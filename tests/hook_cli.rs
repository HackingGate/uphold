//! CLI-level tests for `uphold hook`.
//!
//! The seam this covers has no process to intercept: an agent posts a
//! pull-request body over HTTPS from inside its own process, so the shim's
//! `argv[0]` answer never gets a turn. What replaces it is a harness handing
//! over the pending call as JSON and reading a verdict back, which means the
//! contract under test is not "did a rule fire" -- other suites cover that --
//! but what the HARNESS sees. Everything below therefore drives the binary and
//! asserts on the exit code and the document, because a refusal the harness
//! cannot parse, or one it reads as an error in the hook rather than a verdict
//! on the call, is a refusal that let the body through.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

/// The guard that refuses an authorship marker, declared the way a consuming
/// repository declares it.
const POLICY: &str = "\
[rule.prevent-ai-author]
builtin = \"prevent-ai-author\"
git.hooks = [\"commit-msg\"]
";

/// The shim tables a prose rule needs beside it.
///
/// A rule standing in front of a command is refused at load in a repository
/// that has not put a program in front of that command, which is the design and
/// not a gap -- so a fixture declaring `command.before` writes the tables a
/// consuming repository writes. The hook seam spawns no process and reads no
/// `argv[0]`, and it consults these rules anyway: what an MCP server posts is
/// the body `gh` would have posted.
const SHIMS: &str = "\n[[shim]]
command = \"gh\"
match = [\"pr:create\"]
text_flags = [\"-b\", \"--body\"]

[[shim]]
command = \"git\"
match = [\"push:*\"]
scope = \"always\"
";

/// One prose rule, declared the way a repository declares its own.
const PROSE_POLICY: &str = "\
[rule.no-empty-hedge-here]
message = \"State the claim, or state what is unknown about it.\"
prose_regexp = '(?i)\\barguably\\b'
files.include = [\".\"]
command.before = [\"gh\", \"git push\"]
";

/// The bundled set, inherited the way a repository inherits it.
const PROSE_SET: &str = "[inherit]\nsets = [\"prose-shapes\"]\n";

fn workspace(name: &str, policy: Option<&str>) -> PathBuf {
    let root = support::scratch(name);
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    if let Some(policy) = policy {
        std::fs::create_dir_all(root.join("policy")).unwrap();
        std::fs::write(root.join("policy/principles.toml"), policy).unwrap();
    }
    root
}

/// `HOME` is set on every run, never inherited, for the reason `text_cli` gives:
/// the identity needles are read from the environment the check runs in, and a
/// test that let the real one through would assert on this machine.
fn hook(root: &Path, harness: &str, stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["hook", harness])
        .current_dir(root)
        .env_remove("UPHOLD_ALLOW")
        .env("HOME", "/home/example-user")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Err(error) = child.stdin.as_mut().unwrap().write_all(stdin.as_bytes()) {
        // The binary may answer and exit before it reads its input; that is its
        // verdict, not a failure to deliver the event.
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe, "{error}");
    }
    child.wait_with_output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn event(tool: &str, body: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "session_id": "test-session",
        "turn_id": "test-turn",
        "tool_use_id": "test-call",
        "tool_name": tool,
        "tool_input": {"body": body},
    })
    .to_string()
}

// -- what the harness reads ------------------------------------------------

/// The refusal has to arrive as a document, on stdout, at exit 0.
///
/// This is the inversion the module doc explains and the one thing about this
/// seam that is easy to get wrong: everywhere else in this binary 1 means
/// refused, and here exit 1 is read as the hook itself having failed, which
/// lets the call proceed. A regression here does not look like a
/// refusal that stopped working. It looks like a complaint on a published body.
#[test]
fn a_refusal_is_a_document_on_stdout_at_exit_zero() {
    for harness in ["claude-code", "codex"] {
        let root = workspace("hook-deny", Some(POLICY));
        let output = hook(
            &root,
            harness,
            &event(
                "mcp__github__create_pull_request",
                "Co-Authored-By: Claude <noreply@anthropic.com>",
            ),
        );

        assert_eq!(code(&output), 0, "{}", stderr(&output));
        let document: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
        assert_eq!(
            document
                .pointer("/hookSpecificOutput/permissionDecision")
                .and_then(Value::as_str),
            Some("deny"),
            "{}",
            stdout(&output)
        );
        assert_eq!(
            document
                .pointer("/hookSpecificOutput/hookEventName")
                .and_then(Value::as_str),
            Some("PreToolUse"),
        );
        let reason = document
            .pointer("/hookSpecificOutput/permissionDecisionReason")
            .and_then(Value::as_str)
            .unwrap();
        assert!(reason.contains("prevent-ai-author"), "{reason}");
        // The tool is named because the operator has several in flight and the
        // report is the only place they learn which one was stopped.
        assert!(
            reason.contains("mcp__github__create_pull_request"),
            "{reason}"
        );
    }
}

/// A clean call says nothing at all.
///
/// Not a courtesy. This fires on every matched tool call in a session rather
/// than once per commit, and a gate that narrates its passes is the gate whose
/// output gets filtered and then whose matcher gets deleted.
#[test]
fn a_clean_call_is_silent() {
    for harness in ["claude-code", "codex"] {
        let root = workspace("hook-clean", Some(POLICY));
        let output = hook(
            &root,
            harness,
            &event("mcp__github__create_issue", "an ordinary body"),
        );
        assert_eq!(code(&output), 0);
        assert_eq!(stdout(&output), "");
    }
}

// -- the prose rules reach this seam ---------------------------------------

/// A `prose_regexp` rule standing in front of a command refuses here too.
///
/// The rule names `gh`, and this seam is what an agent uses INSTEAD of `gh`: it
/// posts the body over HTTPS from inside its own process, where there is no
/// `argv[0]` for the shim to read. A sentence shape refused when `gh pr create`
/// publishes it and allowed when an MCP server publishes it would be the same
/// rule with two answers, and the seam that has to hold is this one -- an agent
/// publishes more often than a person does.
#[test]
fn a_prose_rule_refuses_what_a_tool_call_was_about_to_publish() {
    let root = workspace("hook-prose", Some(&format!("{PROSE_POLICY}{SHIMS}")));
    let output = hook(
        &root,
        "claude-code",
        &event(
            "mcp__github__create_pull_request",
            "This change is arguably an improvement.",
        ),
    );

    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let document: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(
        document
            .pointer("/hookSpecificOutput/permissionDecision")
            .and_then(Value::as_str),
        Some("deny"),
        "{}",
        stdout(&output)
    );
    let reason = document
        .pointer("/hookSpecificOutput/permissionDecisionReason")
        .and_then(Value::as_str)
        .unwrap();
    assert!(reason.contains("no-empty-hedge-here"), "{reason}");
    // The sentence, unwrapped, so the agent is told which one to fix rather
    // than only that something was wrong.
    assert!(
        reason.contains("This change is arguably an improvement."),
        "{reason}"
    );
}

/// And the bundled set does, which is the half that was dark.
///
/// `prose-shapes` declares `command.before = ["gh", "git push"]` on every rule
/// in it -- the whole set is written for text a forge publishes. A repository
/// that inherits it and installs the hook has said it wants these shapes
/// refused wherever they are published, and a set that covered the terminal and
/// not the agent would cover the caller that publishes less.
#[test]
fn a_bundled_prose_shapes_rule_refuses_through_the_hook() {
    let root = workspace("hook-prose-set", Some(&format!("{PROSE_SET}{SHIMS}")));
    let output = hook(
        &root,
        "claude-code",
        &event(
            "mcp__github__create_pull_request",
            "In what follows we describe the change.",
        ),
    );

    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let document: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(
        document
            .pointer("/hookSpecificOutput/permissionDecision")
            .and_then(Value::as_str),
        Some("deny"),
        "{}",
        stdout(&output)
    );
    let reason = document
        .pointer("/hookSpecificOutput/permissionDecisionReason")
        .and_then(Value::as_str)
        .unwrap();
    assert!(reason.contains("no-announcing-sentence"), "{reason}");
}

/// A prose rule scoped only by `files.*` is left out, here as everywhere.
///
/// The other half of the same decision. A rule that names no command is scoped
/// to particular paths and file types, and a tool call has no path -- firing it
/// here would be the guesswork `text` refuses for the pattern rules generally.
#[test]
fn a_prose_rule_naming_no_command_is_not_asked_about_a_tool_call() {
    let root = workspace(
        "hook-prose-unscoped",
        Some(
            "[rule.no-empty-hedge-here]\n\
             message = \"State the claim.\"\n\
             prose_regexp = '(?i)\\barguably\\b'\n\
             files.include = [\".\"]\n",
        ),
    );
    let output = hook(
        &root,
        "claude-code",
        &event(
            "mcp__github__create_pull_request",
            "This change is arguably an improvement.",
        ),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert_eq!(stdout(&output), "", "{}", stderr(&output));
}

// -- the case this seam is usually in --------------------------------------

/// No policy where the call was made, and the host-identity rules still run.
///
/// A tool call is made from wherever the session was started, which is
/// frequently a superproject, a scratch directory, or a checkout with no policy
/// of its own. Standing down there would leave the seam absent in exactly the
/// places nobody thought to configure it, which is how identity gets published.
#[test]
fn without_a_policy_the_identity_rules_still_refuse() {
    for harness in ["claude-code", "codex"] {
        let root = workspace("hook-no-policy", None);
        let output = hook(
            &root,
            harness,
            &event("mcp__github__create_issue", "see /home/example-user/notes"),
        );

        assert_eq!(code(&output), 0, "{}", stderr(&output));
        let document: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
        assert_eq!(
            document
                .pointer("/hookSpecificOutput/permissionDecision")
                .and_then(Value::as_str),
            Some("deny")
        );
    }
}

/// ... and says so, because partial coverage reported as a pass is the failure
/// `explicit-unknown` names.
#[test]
fn without_a_policy_the_reduced_coverage_is_stated() {
    let root = workspace("hook-no-policy-said", None);
    let output = hook(
        &root,
        "claude-code",
        &event("mcp__github__create_issue", "an ordinary body"),
    );
    assert_eq!(code(&output), 0);
    assert_eq!(
        stdout(&output),
        "",
        "a clean call is still silent to the harness"
    );
    assert!(
        stderr(&output).contains("the guards did not run"),
        "{}",
        stderr(&output)
    );
}

// -- what it refuses to guess at -------------------------------------------

/// A harness the table does not describe is named, not approximated.
///
/// Exit 2 rather than 0: the call was not examined, and a seam that waves
/// through what it could not read is the one failure mode this whole binary is
/// about.
#[test]
fn an_unknown_harness_is_refused_and_names_the_known_ones() {
    let root = workspace("hook-unknown", Some(POLICY));
    let output = hook(&root, "some-other-agent", &event("x", "body"));
    assert_eq!(code(&output), 2);
    assert!(
        stderr(&output).contains("claude-code|codex"),
        "{}",
        stderr(&output)
    );
    assert_eq!(stdout(&output), "");
}

/// An event that is not JSON is exit 2 for the same reason, and it is also what
/// a harness that changed its schema looks like from here.
#[test]
fn a_malformed_event_is_could_not_look_and_not_a_pass() {
    for harness in ["claude-code", "codex"] {
        let root = workspace("hook-malformed", Some(POLICY));
        let output = hook(&root, harness, "{not json");
        assert_eq!(code(&output), 2);
        assert!(
            stderr(&output).contains("would mean"),
            "{}",
            stderr(&output)
        );
    }
}

/// An event with no subject at all is could-not-look, not a clean call.
///
/// The malformed case one level down, and the one that does not announce
/// itself: the JSON parses, the run exits, and nothing was read. It is what a
/// harness renaming its field looks like from here, and reporting it as a pass
/// would leave the seam silently switched off at the version it changed.
#[test]
fn an_event_with_no_subject_is_could_not_look_and_not_a_pass() {
    for harness in ["claude-code", "codex"] {
        let root = workspace("hook-no-subject", Some(POLICY));
        let output = hook(
            &root,
            harness,
            r#"{"tool_name":"mcp__github__create_pull_request","toolInput":{"body":"renamed"}}"#,
        );
        assert_eq!(code(&output), 2, "{}", stderr(&output));
        assert!(
            stderr(&output).contains("/tool_input"),
            "the report names the pointer that found nothing: {}",
            stderr(&output)
        );
        assert_eq!(stdout(&output), "");
    }
}

/// A subject that is present and is not an object is still read.
///
/// The distinction the case above turns on is found-versus-not, never the shape
/// the harness chose. A bare string where an object was expected is text, and
/// text is what every rule at this seam judges.
#[test]
fn a_subject_that_is_a_bare_string_is_read_as_text() {
    let root = workspace("hook-string-subject", Some(POLICY));
    let output = hook(
        &root,
        "claude-code",
        r#"{"tool_name":"mcp__forge__publish","tool_input":"Generated with Claude Code"}"#,
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let document: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(
        document
            .pointer("/hookSpecificOutput/permissionDecision")
            .and_then(Value::as_str),
        Some("deny"),
        "{}",
        stdout(&output)
    );
}

/// A call with no label is checked exactly as thoroughly.
///
/// The label decides a word in the report and nothing else, so an event missing
/// it is a report that reads slightly worse rather than a call that goes
/// unread. Refusing here would be a gate firing on work it had no finding
/// about.
#[test]
fn an_event_with_no_label_is_still_checked() {
    let root = workspace("hook-no-label", Some(POLICY));
    let output = hook(
        &root,
        "claude-code",
        r#"{"tool_input":{"body":"Generated with Claude Code"}}"#,
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let document: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(
        document
            .pointer("/hookSpecificOutput/permissionDecision")
            .and_then(Value::as_str),
        Some("deny"),
        "{}",
        stdout(&output)
    );
}

// -- the field names are not a list ----------------------------------------

/// The offending string is found wherever the server chose to put it.
///
/// A table of field names per tool is a table missing the one a new server
/// added, silently and in the green direction. This asserts the property that
/// replaces it: a body nested under a name nothing here has ever heard of is
/// still read.
#[test]
fn a_string_under_an_unknown_field_name_is_still_read() {
    let root = workspace("hook-unknown-field", Some(POLICY));
    let event = serde_json::json!({
        "tool_name": "mcp__forge__publish",
        "tool_input": {"draft": {"sections": [{"prose": "Generated with Claude Code"}]}}
    })
    .to_string();

    let output = hook(&root, "claude-code", &event);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let document: Value = serde_json::from_str(stdout(&output).trim()).unwrap();
    assert_eq!(
        document
            .pointer("/hookSpecificOutput/permissionDecision")
            .and_then(Value::as_str),
        Some("deny"),
        "{}",
        stdout(&output)
    );
}

/// A call carrying no argument text is allowed when no rule refuses its tool.
#[test]
fn a_call_with_no_strings_is_allowed_when_its_tool_is_allowed() {
    let root = workspace("hook-no-strings", Some(POLICY));
    let output = hook(
        &root,
        "claude-code",
        r#"{"tool_name":"mcp__forge__count","tool_input":{"limit":10,"all":true}}"#,
    );
    assert_eq!(code(&output), 0);
    assert_eq!(stdout(&output), "");
}

/// A policy that does not load is exit 2 on a string-free call too (#236).
///
/// The subject's strings are what the rules judge, and the policy is what says
/// which rules there are. A call carrying only numbers and flags used to return
/// before the policy was read, so a broken configuration passed every such call
/// at exit 0 and announced itself only on the calls that published text.
#[test]
fn a_call_with_no_strings_under_a_broken_policy_is_could_not_look() {
    for harness in ["claude-code", "codex"] {
        let root = workspace(
            "hook-no-strings-broken-policy",
            Some("[rule.no-example-needle\nmessage = \"unterminated table header\"\n"),
        );
        let output = hook(
            &root,
            harness,
            r#"{"tool_name":"mcp__forge__count","tool_input":{"limit":10,"all":true}}"#,
        );
        assert_eq!(code(&output), 2, "{}", stderr(&output));
        assert_eq!(stdout(&output), "");
    }
}

/// No policy found is not a policy that failed to load: it loads as empty, and
/// a string-free call made there is still clean.
#[test]
fn a_call_with_no_strings_and_no_policy_is_allowed() {
    let root = workspace("hook-no-strings-no-policy", None);
    let output = hook(
        &root,
        "claude-code",
        r#"{"tool_name":"mcp__forge__count","tool_input":{"limit":10,"all":true}}"#,
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert_eq!(stdout(&output), "");
}

/// The reason a refusal gives, for the tests that read it.
fn reason(output: &Output) -> String {
    let document: Value = serde_json::from_str(stdout(output).trim()).unwrap();
    document
        .pointer("/hookSpecificOutput/permissionDecisionReason")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned()
}

/// A rule's refusal carries its message, not only its id.
///
/// The reader here is the agent that made the call, and the message is what
/// says what to do instead -- the same text the shim and `--text` print.
#[test]
fn a_rule_refusal_carries_the_rules_message() {
    let root = workspace("hook-message", Some(&format!("{PROSE_POLICY}{SHIMS}")));
    let output = hook(
        &root,
        "claude-code",
        &event("mcp__github__create_issue", "It is arguably fine."),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let reason = reason(&output);
    assert!(
        reason.contains("State the claim, or state what is unknown about it."),
        "{reason}"
    );
}

/// A `regexp` rule standing in front of `gh`, refusing a release by name at the
/// shim and, through `seams`, at the hook.
const RELEASE_POLICY: &str = "\
[[shim]]
command = \"gh\"
match = [\"release:create\"]
argv_subject = true

[rule.no-release-by-hand]
message = \"Cut a release from the release workflow.\"
regexp = '^release create|__create_release$'
subjects = [\"argv\", \"tool\"]
seams = [\"shim\", \"hook\"]
command.before = [\"gh\"]
command.scope = \"always\"
";

/// The rule the shim enforces is enforced when the same publish goes through an
/// MCP server, where it names the hook in `seams`. The tool name is the
/// subject, so the refusal is by what the call is rather than by what it says.
#[test]
fn a_regexp_rule_naming_the_hook_refuses_the_tool_call_by_its_name() {
    for harness in ["claude-code", "codex"] {
        let root = workspace("hook-regexp-seams", Some(RELEASE_POLICY));
        let refused = hook(
            &root,
            harness,
            &event("mcp__github__create_release", "v1.2.0"),
        );
        assert_eq!(code(&refused), 0, "{}", stderr(&refused));
        let reason = reason(&refused);
        assert!(reason.contains("no-release-by-hand"), "{reason}");
        assert!(
            reason.contains("Cut a release from the release workflow."),
            "{reason}"
        );

        // A body that only mentions the command is text, and the rule asks about
        // the tool: a pull request describing a release is not a release.
        let clean = hook(
            &root,
            harness,
            &event(
                "mcp__github__create_pull_request",
                "Stop running gh release create by hand.",
            ),
        );
        assert_eq!(code(&clean), 0, "{}", stderr(&clean));
        assert_eq!(stdout(&clean), "", "{}", stdout(&clean));
    }
}

/// Tool names remain subjects when the argument tree contains no strings.
#[test]
fn string_free_calls_still_judge_the_tool_without_inventing_argument_text() {
    let policy = format!(
        "{RELEASE_POLICY}\n\
         [rule.require-argument-text]\n\
         message = \"Supply nonempty text.\"\n\
         require_regexp = '.'\n\
         files.exclude = [\"policy/**\"]\n\
         subjects = [\"text\"]\n\
         seams = [\"hook\"]\n\
         command.before = [\"gh\"]\n"
    );
    for harness in ["claude-code", "codex"] {
        let root = workspace("hook-string-free-tool", Some(&policy));
        for input in [
            serde_json::json!({}),
            serde_json::json!({"id": 7, "draft": false}),
            serde_json::json!({"nested": [null, 7, {}]}),
            Value::Null,
        ] {
            for tool in ["mcp__github__create_release", "mcp__github__get_release"] {
                let event = serde_json::json!({"tool_name": tool, "tool_input": input});
                let output = hook(&root, harness, &event.to_string());
                assert_eq!(code(&output), 0, "{}", stderr(&output));
                if tool == "mcp__github__create_release" {
                    let explanation = reason(&output);
                    assert!(explanation.contains("no-release-by-hand"), "{explanation}");
                    assert!(
                        !explanation.contains("require-argument-text"),
                        "{explanation}"
                    );
                    let response: Value = serde_json::from_str(&stdout(&output)).unwrap();
                    assert_eq!(
                        response.pointer("/hookSpecificOutput/permissionDecision"),
                        Some(&Value::String("deny".to_owned()))
                    );
                } else {
                    assert_eq!(stdout(&output), "", "{}", stderr(&output));
                }
            }
        }
        // An explicitly supplied empty string is still a text subject. On a
        // write: the default `[[hook]]` table passes the GitHub reads unjudged.
        let output = hook(&root, harness, &event("mcp__github__update_issue", ""));
        assert!(reason(&output).contains("require-argument-text"));
    }
}

/// Without `seams`, a `regexp` rule stays where it ran before the field
/// existed: at the shim, and not over every tool call.
#[test]
fn a_regexp_rule_that_does_not_name_the_hook_is_not_asked_there() {
    let policy = RELEASE_POLICY.replace("seams = [\"shim\", \"hook\"]\n", "");
    let root = workspace("hook-regexp-default", Some(&policy));
    let output = hook(
        &root,
        "claude-code",
        &event("mcp__github__create_release", "v1.2.0"),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert_eq!(stdout(&output), "", "{}", stdout(&output));
}

// -- a title argument is judged as a title ---------------------------------

/// The invisible-character and lookalike guard, declared the way a repository
/// declares it.
const UNICODE_POLICY: &str = "\
[rule.prevent-unusual-unicode]
builtin = \"prevent-unusual-unicode\"
git.hooks = [\"commit-msg\"]
";

/// A Latin word with a Cyrillic small a (U+0430) in it: a lookalike in a
/// subject, and an ordinary letter in prose.
const DISGUISED: &str = "Fix the p\u{0430}rser";

fn unicode_call(root_name: &str, tool: &str, input: &Value) -> Output {
    let root = workspace(root_name, Some(UNICODE_POLICY));
    let event = serde_json::json!({"tool_name": tool, "tool_input": input}).to_string();
    hook(&root, "claude-code", &event)
}

fn refused_as_lookalike(output: &Output) {
    assert_eq!(code(output), 0, "{}", stderr(output));
    let reason = reason(output);
    assert!(reason.contains("prevent-unusual-unicode"), "{reason}");
    assert!(reason.contains("CYRILLIC SMALL LETTER A"), "{reason}");
}

/// A merge's `commit_title` is the commit subject the forge writes, and the
/// shim judges `gh pr merge --subject` and `gh api -f commit_title=` as one. The
/// same title handed to an MCP server gets the same lookalike pass.
#[test]
fn a_commit_title_argument_is_judged_as_a_subject() {
    let output = unicode_call(
        "hook-commit-title",
        "mcp__github__merge_pull_request",
        &serde_json::json!({"pullNumber": 7, "commit_title": DISGUISED}),
    );
    refused_as_lookalike(&output);
}

/// A finding names the key the subject was found under, so the reader is
/// pointed at `commit_title` or `squash_commit_message` and not at a "title"
/// the call never carried.
#[test]
fn a_finding_names_the_key_it_was_found_under() {
    for (name, key) in [
        ("hook-key-commit-title", "commit_title"),
        ("hook-key-subject", "subject"),
        ("hook-key-squash-message", "squash_commit_message"),
    ] {
        let output = unicode_call(
            name,
            "mcp__forge__merge",
            &serde_json::json!({ key: DISGUISED }),
        );
        refused_as_lookalike(&output);
        let reason = reason(&output);
        assert!(
            reason.contains(&format!("mcp__forge__merge {key}")),
            "{key}: {reason}"
        );
    }
}

/// A pull request's `title` is the subject a squash merge makes of it.
#[test]
fn a_title_argument_is_judged_as_a_subject() {
    let output = unicode_call(
        "hook-title",
        "mcp__github__create_pull_request",
        &serde_json::json!({"title": DISGUISED, "body": "An ordinary body."}),
    );
    refused_as_lookalike(&output);
}

/// A whole-message argument is a subject on its first line and prose below.
#[test]
fn a_merge_message_argument_is_a_subject_then_a_body() {
    let refused = unicode_call(
        "hook-merge-message-subject",
        "mcp__gitlab__merge_merge_request",
        &serde_json::json!({"squash_commit_message": format!("{DISGUISED}\n\nAn ordinary body.")}),
    );
    refused_as_lookalike(&refused);

    let passed = unicode_call(
        "hook-merge-message-body",
        "mcp__gitlab__merge_merge_request",
        &serde_json::json!({"squash_commit_message": format!("Fix the parser\n\n{DISGUISED}")}),
    );
    assert_eq!(code(&passed), 0, "{}", stderr(&passed));
    assert_eq!(stdout(&passed), "", "{}", stdout(&passed));
}

/// The same word in a body is prose, where a lookalike letter is not a hazard.
#[test]
fn the_same_word_in_a_body_is_prose() {
    let output = unicode_call(
        "hook-body-prose",
        "mcp__github__create_pull_request",
        &serde_json::json!({"title": "Fix the parser", "body": DISGUISED}),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert_eq!(stdout(&output), "", "{}", stdout(&output));
}

/// A key not on the list stays prose: the list can add a check, never remove
/// one, and a key it lacks is judged the way every string was before it.
#[test]
fn an_unknown_key_stays_prose() {
    let output = unicode_call(
        "hook-unknown-key-prose",
        "mcp__forge__publish",
        &serde_json::json!({"headline_text": DISGUISED}),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert_eq!(stdout(&output), "", "{}", stdout(&output));
}

/// A character that draws nothing is refused under any key, title or not.
#[test]
fn an_invisible_character_is_refused_under_any_key() {
    for (name, key) in [
        ("hook-invisible-body", "body"),
        ("hook-invisible-title", "title"),
        ("hook-invisible-unknown", "headline_text"),
    ] {
        let output = unicode_call(
            name,
            "mcp__github__create_pull_request",
            &serde_json::json!({ key: "Fix the\u{202E}parser" }),
        );
        assert_eq!(code(&output), 0, "{}", stderr(&output));
        let reason = reason(&output);
        assert!(
            reason.contains("prevent-unusual-unicode"),
            "{key}: {reason}"
        );
        assert!(reason.contains("U+202E"), "{key}: {reason}");
    }
}

// -- one refusal per rule, and title-scoped patterns -----------------------

/// A rule that fires on a title and on a body is one finding about one call,
/// and its block is printed once, naming both parts.
#[test]
fn a_rule_firing_on_two_parts_of_a_call_prints_one_block_naming_both() {
    let root = workspace("hook-merged-verdicts", Some(POLICY));
    let marker = "Co-Authored-By: Claude <noreply@anthropic.com>";
    let event = serde_json::json!({
        "tool_name": "mcp__github__create_pull_request",
        "tool_input": {"title": marker, "body": marker},
    })
    .to_string();
    let output = hook(&root, "claude-code", &event);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let reason = reason(&output);
    assert_eq!(
        reason.matches("guard refused: prevent-ai-author").count(),
        1,
        "{reason}"
    );
    assert!(
        reason.contains("mcp__github__create_pull_request title"),
        "{reason}"
    );
    assert!(
        reason.contains("mcp__github__create_pull_request carries"),
        "{reason}"
    );
    // The rule's advice is one paragraph both parts share, and it reads once.
    assert_eq!(reason.matches("Remove the marker").count(), 1, "{reason}");
}

const TITLE_POLICY: &str = "\
[rule.no-draft-title]
message = \"Name the change, not its state.\"
regexp = '^Draft'
subjects = [\"title\"]
seams = [\"hook\"]
command.before = [\"gh\"]
command.scope = \"always\"
";

/// A `regexp` rule scoped to `title` sees a tool call's title and nothing else.
#[test]
fn a_title_scoped_regexp_rule_refuses_a_title_and_passes_a_body() {
    let root = workspace("hook-title-regexp", Some(TITLE_POLICY));
    let call = |input: Value| {
        let event =
            serde_json::json!({"tool_name": "mcp__github__create_pull_request", "tool_input": input})
                .to_string();
        hook(&root, "claude-code", &event)
    };

    let refused = call(serde_json::json!({"title": "Draft: parser", "body": "ordinary"}));
    assert_eq!(code(&refused), 0, "{}", stderr(&refused));
    let reason = reason(&refused);
    assert!(reason.contains("no-draft-title"), "{reason}");
    assert!(
        reason.contains("(in mcp__github__create_pull_request title)"),
        "{reason}"
    );

    let passed = call(serde_json::json!({"title": "Fix the parser", "body": "Draft: parser"}));
    assert_eq!(code(&passed), 0, "{}", stderr(&passed));
    assert_eq!(stdout(&passed), "", "{}", stdout(&passed));
}

// -- a commit message under `message` is a known limit ---------------------

/// The GitHub MCP file-commit tools take the commit message under `message`,
/// a key too generic to read as a subject without knowing the tool. Pinned as
/// it behaves: prose, so a lookalike passes and an invisible character is
/// refused. See "Known limit" in the reference.
#[test]
fn a_message_key_is_prose_so_a_lookalike_passes_and_an_invisible_character_does_not() {
    let passed = unicode_call(
        "hook-message-lookalike",
        "mcp__github__create_or_update_file",
        &serde_json::json!({"path": "a.txt", "message": DISGUISED}),
    );
    assert_eq!(code(&passed), 0, "{}", stderr(&passed));
    assert_eq!(stdout(&passed), "", "{}", stdout(&passed));

    let refused = unicode_call(
        "hook-message-invisible",
        "mcp__github__create_or_update_file",
        &serde_json::json!({"path": "a.txt", "message": "Fix the\u{200B}parser"}),
    );
    assert_eq!(code(&refused), 0, "{}", stderr(&refused));
    let reason = reason(&refused);
    assert!(reason.contains("prevent-unusual-unicode"), "{reason}");
    assert!(reason.contains("U+200B"), "{reason}");
}

// -- UPHOLD_JUNIT: what a call decided, as one JUnit document ---------------

/// [`hook`], with `args` after `hook` and `UPHOLD_JUNIT` set to `junit` when
/// given.
fn hook_recorded(root: &Path, args: &[&str], stdin: &str, junit: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
    command
        .arg("hook")
        .args(args)
        .current_dir(root)
        .env_remove("UPHOLD_ALLOW")
        .env_remove("UPHOLD_JUNIT")
        .env("HOME", "/home/example-user")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(junit) = junit {
        command.env("UPHOLD_JUNIT", junit);
    }
    let mut child = command.spawn().unwrap();
    if let Err(error) = child.stdin.as_mut().unwrap().write_all(stdin.as_bytes()) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe, "{error}");
    }
    child.wait_with_output().unwrap()
}

/// Every call writes its own document into the directory, refused or not:
/// a seam that wrote only on a refusal would make an absent file mean "passed
/// or never ran". Each rule the call consulted is a testcase under the
/// `uphold hook <harness>` suite, its subject is the tool's name, and the body
/// it judged is in no file.
#[test]
fn every_call_writes_one_document_naming_each_rule_and_never_the_body() {
    let root = workspace(
        "hook-junit",
        Some(&format!("{POLICY}\n{PROSE_POLICY}{SHIMS}")),
    );
    let evidence = root.join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    let tool = "mcp__github__create_pull_request";

    let refused = hook_recorded(
        &root,
        &["claude-code"],
        &event(tool, "Arguably fine.\n\nGenerated with Claude Code"),
        Some(&evidence),
    );
    assert_eq!(code(&refused), 0, "{}", stderr(&refused));
    assert!(stdout(&refused).contains("deny"), "{}", stdout(&refused));
    let clean = hook_recorded(
        &root,
        &["claude-code"],
        &event(tool, "An ordinary change."),
        Some(&evidence),
    );
    assert_eq!(code(&clean), 0, "{}", stderr(&clean));
    assert!(stdout(&clean).is_empty(), "{}", stdout(&clean));

    let files = support::junit::files_in(&evidence);
    assert_eq!(files.len(), 2, "{files:?}");
    for path in &files {
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("uphold-hook-claude-code-"), "{name}");
    }
    let (first, text) = support::junit::suite(files.first().unwrap());
    assert_eq!(first.name.as_str(), "uphold hook claude-code");
    assert_eq!(support::junit::package(&first), Some("uphold"));
    let ai = support::junit::case(&first, "prevent-ai-author");
    assert_eq!(
        support::junit::state(ai),
        ("failure", Some("prevent-ai-author refused"))
    );
    assert_eq!(
        support::junit::property(ai, "builtin"),
        Some("prevent-ai-author")
    );
    let hedge = support::junit::case(&first, "no-empty-hedge-here");
    assert_eq!(
        support::junit::state(hedge),
        ("failure", Some("no-empty-hedge-here refused"))
    );
    // A prose rule names no built-in.
    assert_eq!(support::junit::property(hedge, "builtin"), None);
    let identity = support::junit::case(&first, "no-running-os-identity-metadata");
    assert_eq!(support::junit::state(identity), ("pass", None));
    for case in &first.test_cases {
        assert_eq!(support::junit::properties(case, "subject"), [tool]);
        assert_eq!(support::junit::property(case, "seam"), Some("hook"));
    }
    assert!(!text.contains("Arguably"), "{text}");
    assert!(!text.contains("Generated"), "{text}");

    let (second, _) = support::junit::suite(files.last().unwrap());
    assert_eq!((second.tests, second.failures), (3, 0), "{second:?}");
}

/// The hook runs once per publishing call, so one file would keep only the
/// last; a value naming anything but an existing directory is exit 2, named,
/// before the call is judged.
#[test]
fn a_value_that_is_not_a_directory_is_refused_naming_it() {
    let root = workspace("hook-junit-file", Some(POLICY));
    let file = root.join("hook.xml");
    let output = hook_recorded(
        &root,
        &["claude-code"],
        &event("publish", "Generated with Claude Code"),
        Some(&file),
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains(&format!("UPHOLD_JUNIT={}", file.display())),
        "{}",
        stderr(&output)
    );
    assert!(stdout(&output).is_empty(), "{}", stdout(&output));
    assert!(!file.exists());

    let flagged = hook_recorded(
        &root,
        &["claude-code", "--junit", "hook.xml"],
        &event("publish", "Generated with Claude Code"),
        None,
    );
    assert_eq!(code(&flagged), 2, "{}", stderr(&flagged));
    assert!(
        stderr(&flagged).contains("--junit="),
        "{}",
        stderr(&flagged)
    );
    assert!(!file.exists());
}

/// `--junit DIR` is the spelling for the harness's settings file, before or
/// after the harness name, and a relative value is the directory the hook
/// runs in.
#[test]
fn the_flag_names_the_directory_on_either_side_of_the_harness() {
    let root = workspace("hook-junit-flag", Some(POLICY));
    std::fs::create_dir_all(root.join("evidence")).unwrap();
    for args in [
        ["--junit", "evidence", "codex"],
        ["codex", "--junit", "evidence"],
    ] {
        let output = hook_recorded(&root, &args, &event("publish", "plain"), None);
        assert_eq!(code(&output), 0, "{args:?}: {}", stderr(&output));
    }
    let files = support::junit::files_in(&root.join("evidence"));
    assert_eq!(files.len(), 2, "{files:?}");
    let (suite, _) = support::junit::suite(files.first().unwrap());
    assert_eq!(suite.name.as_str(), "uphold hook codex");
}

// -- the end of a turn ---------------------------------------------------------

/// A gate that is green while the file `red` is absent: argv, no shell, and a
/// program every test machine has.
const STOP_POLICY: &str = "[stop]\nrun = [[\"test\", \"!\", \"-e\", \"red\"]]\n";

/// A repository with a `[stop]` gate. A git repository, because the baseline
/// lives under the worktree's git dir.
fn gated(name: &str, policy: &str) -> PathBuf {
    let root = workspace(name, Some(policy));
    support::git(&root, &["init", "-q"]);
    root
}

/// Run the hook with the fixture's own git, never the one a commit hook running
/// this suite exported.
fn turn(root: &Path, stdin: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
    command
        .args(["hook", "claude-code"])
        .current_dir(root)
        .env_remove("UPHOLD_ALLOW")
        .env("HOME", "/home/example-user")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    support::without_git_environment(&mut command);
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin.as_bytes())
        .ok();
    child.wait_with_output().unwrap()
}

fn moment(name: &str, session: &str) -> String {
    serde_json::json!({
        "hook_event_name": name,
        "session_id": session,
        "cwd": "/unused",
        "stop_hook_active": false,
    })
    .to_string()
}

fn decision(output: &Output) -> Value {
    serde_json::from_str(stdout(output).trim()).unwrap()
}

/// The point of the seam: green when the session started, red when it ends.
#[test]
fn a_command_this_session_turned_red_blocks_the_end_of_the_turn() {
    let root = gated("stop-new-red", STOP_POLICY);
    let started = turn(&root, &moment("SessionStart", "s-new"));
    assert_eq!(code(&started), 0, "{}", stderr(&started));
    // Claude Code adds SessionStart stdout to the conversation.
    assert_eq!(stdout(&started), "");
    std::fs::write(root.join("red"), "").unwrap();
    let stopped = turn(&root, &moment("Stop", "s-new"));
    assert_eq!(code(&stopped), 0, "{}", stderr(&stopped));
    let document = decision(&stopped);
    assert_eq!(document.get("decision"), Some(&Value::from("block")));
    let reason = document.get("reason").and_then(Value::as_str).unwrap();
    assert!(reason.contains("`test ! -e red` exited 1"), "{reason}");
    assert!(document.get("systemMessage").is_none(), "{document}");
}

/// An agent sent back once that says it cannot fix the gate has followed the
/// reason. Blocking it again spends the harness's cap on a turn that is over.
#[test]
fn a_stop_that_follows_a_block_ends_the_turn_and_tells_the_person() {
    let root = gated("stop-sent-back", STOP_POLICY);
    turn(&root, &moment("SessionStart", "s-back"));
    std::fs::write(root.join("red"), "").unwrap();
    let again = serde_json::json!({
        "hook_event_name": "Stop",
        "session_id": "s-back",
        "stop_hook_active": true,
    });
    let stopped = turn(&root, &again.to_string());
    assert_eq!(code(&stopped), 0, "{}", stderr(&stopped));
    let document = decision(&stopped);
    assert!(document.get("decision").is_none(), "{document}");
    let message = document
        .get("systemMessage")
        .and_then(Value::as_str)
        .unwrap();
    assert!(
        message.contains("still red after the agent was sent back once"),
        "{message}"
    );
    assert!(message.contains("`test ! -e red`"), "{message}");
}

/// A gate that cannot start blocks once. It does not hold every later turn.
#[test]
fn a_gate_that_cannot_start_does_not_block_a_stop_that_follows_a_block() {
    let root = gated(
        "stop-unstartable-again",
        "[stop]\nrun = [[\"uphold-no-such-program\"]]\n",
    );
    let again = serde_json::json!({
        "hook_event_name": "Stop",
        "session_id": "s-unstartable-again",
        "stop_hook_active": true,
    });
    let stopped = turn(&root, &again.to_string());
    assert_eq!(code(&stopped), 0, "{}", stderr(&stopped));
    let document = decision(&stopped);
    let message = document
        .get("systemMessage")
        .and_then(Value::as_str)
        .unwrap();
    assert!(message.contains("could not be started"), "{message}");
}

/// The baseline runs while the agent works. A tree that moved under it cannot
/// say what was red before the session, so it is not compared against.
#[test]
fn a_baseline_whose_tree_changed_while_it_ran_is_not_trusted() {
    let root = gated(
        "stop-moved-tree",
        "[stop]\nrun = [[\"touch\", \"written-during-baseline\"], [\"test\", \"!\", \"-e\", \"red\"]]\n",
    );
    std::fs::write(root.join("red"), "").unwrap();
    let started = turn(&root, &moment("SessionStart", "s-moved"));
    assert_eq!(code(&started), 0, "{}", stderr(&started));
    let stopped = turn(&root, &moment("Stop", "s-moved"));
    let document = decision(&stopped);
    assert_eq!(document.get("decision"), Some(&Value::from("block")));
    let reason = document.get("reason").and_then(Value::as_str).unwrap();
    assert!(
        reason.contains("the tree changed while the SessionStart baseline ran"),
        "{reason}"
    );
}

/// Claude Code fires `SessionStart` again on resume and compaction, under the
/// same id. The second one must not re-baseline the session's own red.
#[test]
fn a_repeated_session_start_keeps_the_first_baseline() {
    let root = gated("stop-resumed", STOP_POLICY);
    turn(&root, &moment("SessionStart", "s-resumed"));
    std::fs::write(root.join("red"), "").unwrap();
    let resumed = turn(&root, &moment("SessionStart", "s-resumed"));
    assert_eq!(code(&resumed), 0, "{}", stderr(&resumed));
    let stopped = turn(&root, &moment("Stop", "s-resumed"));
    assert_eq!(
        decision(&stopped).get("decision"),
        Some(&Value::from("block"))
    );
}

/// A `SessionStart` that was killed leaves its marker. Stop does not wait the
/// whole bound again for a run that is not coming.
#[test]
fn a_stale_pending_marker_is_not_waited_on() {
    let root = gated("stop-stale-pending", STOP_POLICY);
    std::fs::write(root.join("red"), "").unwrap();
    let directory = root.join(".git/uphold/stop");
    std::fs::create_dir_all(&directory).unwrap();
    let marker = directory.join("s-stale.pending");
    std::fs::write(&marker, "").unwrap();
    let aged = Command::new("touch")
        .args(["-t", "202001010000"])
        .arg(&marker)
        .status()
        .unwrap();
    assert!(aged.success());
    let started = std::time::Instant::now();
    let stopped = turn(&root, &moment("Stop", "s-stale"));
    assert!(started.elapsed() < std::time::Duration::from_secs(30));
    let reason = decision(&stopped)
        .get("reason")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    assert!(reason.contains("did not finish within"), "{reason}");
}

/// Outside a git repository there is nowhere to keep a baseline. That is a
/// missing baseline, which still honours the one-block rule.
#[test]
fn outside_a_git_repository_the_baseline_is_missing_not_fatal() {
    let root = workspace("stop-no-git", Some(STOP_POLICY));
    std::fs::write(root.join("red"), "").unwrap();
    let again = serde_json::json!({
        "hook_event_name": "Stop",
        "session_id": "s-no-git",
        "stop_hook_active": true,
    });
    let stopped = turn(&root, &again.to_string());
    assert_eq!(code(&stopped), 0, "{}", stderr(&stopped));
    let document = decision(&stopped);
    assert!(document.get("decision").is_none(), "{document}");
    assert!(document.get("systemMessage").is_some_and(Value::is_string));
}

#[test]
fn a_green_gate_lets_the_turn_end_silently() {
    let root = gated("stop-green", STOP_POLICY);
    turn(&root, &moment("SessionStart", "s-green"));
    let stopped = turn(&root, &moment("Stop", "s-green"));
    assert_eq!(code(&stopped), 0, "{}", stderr(&stopped));
    assert_eq!(stdout(&stopped), "");
}

/// Red the session found is named to the person, and does not hold the agent.
#[test]
fn a_command_already_red_at_session_start_is_reported_and_does_not_block() {
    let root = gated("stop-old-red", STOP_POLICY);
    std::fs::write(root.join("red"), "").unwrap();
    turn(&root, &moment("SessionStart", "s-old"));
    let stopped = turn(&root, &moment("Stop", "s-old"));
    assert_eq!(code(&stopped), 0, "{}", stderr(&stopped));
    let document = decision(&stopped);
    assert!(document.get("decision").is_none(), "{document}");
    let message = document
        .get("systemMessage")
        .and_then(Value::as_str)
        .unwrap();
    assert!(message.contains("`test ! -e red`"), "{message}");
}

/// Without a baseline nothing separates found red from caused red, so it
/// blocks, and says the comparison was missing.
#[test]
fn with_no_baseline_every_red_command_blocks_and_says_why() {
    let root = gated("stop-no-baseline", STOP_POLICY);
    std::fs::write(root.join("red"), "").unwrap();
    let stopped = turn(&root, &moment("Stop", "s-none"));
    let document = decision(&stopped);
    assert_eq!(document.get("decision"), Some(&Value::from("block")));
    let reason = document.get("reason").and_then(Value::as_str).unwrap();
    assert!(
        reason.contains("No baseline to compare against"),
        "{reason}"
    );
    assert!(
        reason.contains("configure the SessionStart hook"),
        "{reason}"
    );
}

/// A first turn can end before a slow gate's first run has. Stop waits for
/// the baseline rather than racing it.
#[test]
fn stop_waits_for_a_baseline_that_is_still_being_written() {
    let root = gated("stop-pending", STOP_POLICY);
    std::fs::write(root.join("red"), "").unwrap();
    let directory = root.join(".git/uphold/stop");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("s-wait.pending"), "").unwrap();
    let writer = {
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let baseline = r#"{"ran":[["test","!","-e","red"]],"red":[["test","!","-e","red"]]}"#;
            // Renamed into place, as `SessionStart` writes it. Written in
            // place instead, the file exists empty for an instant, and a Stop
            // polling for it can read that instant as an unreadable baseline.
            // The partial file's name is not the baseline's, so no poll opens it.
            let partial = directory.join("s-wait.json.partial");
            std::fs::write(&partial, baseline).unwrap();
            std::fs::rename(&partial, directory.join("s-wait.json")).unwrap();
            std::fs::remove_file(directory.join("s-wait.pending")).unwrap();
        })
    };
    let stopped = turn(&root, &moment("Stop", "s-wait"));
    writer.join().unwrap();
    let document = decision(&stopped);
    assert!(document.get("decision").is_none(), "{document}");
    assert!(
        document.get("systemMessage").is_some_and(Value::is_string),
        "{document}"
    );
}

/// The harness supplies the id that becomes a file name.
#[test]
fn a_session_id_that_could_name_another_path_is_not_used_as_one() {
    let root = gated("stop-unsafe-id", STOP_POLICY);
    let started = turn(&root, &moment("SessionStart", "../escaped"));
    assert_eq!(code(&started), 2, "{}", stderr(&started));
    assert!(stderr(&started).contains("is not used as a file name"));
    assert!(!root.join(".git/uphold/escaped.json").exists());
    assert!(!root.join(".git/uphold/stop").exists());

    std::fs::write(root.join("red"), "").unwrap();
    let stopped = turn(&root, &moment("Stop", "../escaped"));
    let document = decision(&stopped);
    assert_eq!(document.get("decision"), Some(&Value::from("block")));
    assert!(
        document
            .get("reason")
            .and_then(Value::as_str)
            .unwrap()
            .contains("is not used as a file name")
    );
}

#[test]
fn a_policy_without_a_stop_gate_says_nothing_was_checked() {
    let root = gated("stop-undeclared", POLICY);
    let stopped = turn(&root, &moment("Stop", "s-undeclared"));
    assert_eq!(code(&stopped), 0, "{}", stderr(&stopped));
    assert_eq!(stdout(&stopped), "");
    assert!(stderr(&stopped).contains("declares no `[stop] run`"));
}

/// A gate that cannot run is not a gate that passed. Exit 2 at Stop sends
/// stderr to the agent, so this fails closed.
#[test]
fn a_command_that_cannot_start_is_could_not_look() {
    let root = gated(
        "stop-unstartable",
        "[stop]\nrun = [[\"uphold-no-such-program\"]]\n",
    );
    let stopped = turn(&root, &moment("Stop", "s-unstartable"));
    assert_eq!(code(&stopped), 2, "{}", stderr(&stopped));
    assert!(stderr(&stopped).contains("could not be started"));
}

#[test]
fn an_entry_naming_no_program_is_refused_at_load() {
    let root = gated("stop-empty-argv", "[stop]\nrun = [[]]\n");
    let stopped = turn(&root, &moment("Stop", "s-empty"));
    assert_eq!(code(&stopped), 2, "{}", stderr(&stopped));
    assert!(stderr(&stopped).contains("names no program"));
}

/// What a repository's tree has to pass is not a fact another file can know.
#[test]
fn a_stop_gate_in_an_inherited_file_is_refused() {
    let root = gated(
        "stop-inherited",
        "[inherit]\npaths = [\"policy/shared.toml\"]\n",
    );
    std::fs::write(root.join("policy/shared.toml"), STOP_POLICY).unwrap();
    let stopped = turn(&root, &moment("Stop", "s-inherited"));
    assert_eq!(code(&stopped), 2, "{}", stderr(&stopped));
    assert!(stderr(&stopped).contains("`[stop]` names the commands"));
}

// -- where the call publishes ----------------------------------------------

/// A repository taking the publishing checkers, with the shim tables
/// `published-text` requires, and the GitHub `[[hook]]` table arriving from
/// the set. `example-org` is the private owner the names guard watches for.
const PUBLISHING_POLICY: &str = r#"
owner = "example-user"
private_owners_file = "xdg:principles/private-owners"

[inherit]
sets = ["published-text"]

[[shim]]
command = "gh"
match = ["pr:create"]
text_flags = ["-b", "--body"]
target_flags = ["-R", "--repo"]
target = "forge-repo"
scope = "public-target"

[[shim]]
command = "git"
match = ["push:*"]
"#;

/// A `gh` that knows two repositories under `example-org`, both private, and
/// calls everything under `example-user` public. Every question it is asked
/// is appended to `gh.asked`, so a test can say no forge was asked at all. A
/// visibility question is answered only when it names github.com: asked
/// without `--hostname`, `gh` answers for whatever `GH_HOST` says.
fn forge_stub(root: &Path) {
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let gh = bin.join("gh");
    std::fs::write(
        &gh,
        "#!/bin/sh\n\
         printf '%s\\n' \"$*\" >> \"$(dirname \"$0\")/../gh.asked\"\n\
         case \"$*\" in\n\
         'api repos/example-org/'*' --jq .visibility --hostname github.com') echo private ;;\n\
         'api repos/example-user/'*' --jq .visibility --hostname github.com') echo public ;;\n\
         'api repos/example-org/'*' --jq '*) \
         printf 'private\\texample-org/%s\\n' \"${2##*/}\" ;;\n\
         *) echo \"gh asked: $*\" >&2; exit 1 ;;\n\
         esac\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&gh).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(&gh, permissions).unwrap();
}

/// [`hook`] with the stub forge first on PATH, and `GH_HOST` unset.
fn hook_with_forge(root: &Path, stdin: &str) -> Output {
    hook_with_forge_at(root, stdin, None)
}

/// [`hook_with_forge`] with `GH_HOST` set to `host`, where one is given.
fn hook_with_forge_at(root: &Path, stdin: &str, host: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
    command.env_remove("GH_HOST");
    if let Some(host) = host {
        command.env("GH_HOST", host);
    }
    let mut child = command
        .args(["hook", "claude-code"])
        .current_dir(root)
        .env_remove("UPHOLD_ALLOW")
        .env("HOME", "/home/example-user")
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env(
            "PATH",
            format!(
                "{}:{}",
                root.join("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Err(error) = child.stdin.as_mut().unwrap().write_all(stdin.as_bytes()) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe, "{error}");
    }
    child.wait_with_output().unwrap()
}

fn call(tool: &str, input: &Value) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": input,
    })
    .to_string()
}

fn publishing(name: &str, policy: &str) -> PathBuf {
    let root = workspace(name, Some(policy));
    forge_stub(&root);
    std::fs::create_dir_all(root.join("config/principles")).unwrap();
    std::fs::write(
        root.join("config/principles/private-owners"),
        "example-org\n",
    )
    .unwrap();
    root
}

/// A read publishes nothing, so a private name in it is nobody's business --
/// and the forge is not asked about it either.
#[test]
fn a_read_naming_a_private_repository_passes_unjudged() {
    let root = publishing("hook-read", PUBLISHING_POLICY);
    let output = hook_with_forge(
        &root,
        &call(
            "mcp__github__get_file_contents",
            &serde_json::json!({
                "owner": "example-org",
                "repo": "private-repo",
                "path": "notes/example-org/other-private.md",
            }),
        ),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert_eq!(stdout(&output), "", "{}", stderr(&output));
    assert!(!root.join("gh.asked").exists());
}

#[test]
fn a_write_into_a_public_repository_naming_a_private_one_is_refused() {
    let root = publishing("hook-public-write", PUBLISHING_POLICY);
    let output = hook_with_forge(
        &root,
        &call(
            "mcp__github__create_issue",
            &serde_json::json!({
                "owner": "example-user",
                "repo": "public-widget",
                "title": "A question",
                "body": "Refs example-org/other-private#1",
            }),
        ),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        reason(&output).contains("no-published-private-repo-names [set: published-text]"),
        "{}",
        stdout(&output)
    );
}

/// `public-target` stands the private-name check down where the destination
/// is private, as the `gh` table does for `gh issue create`.
#[test]
fn a_write_into_a_private_repository_naming_another_passes() {
    let root = publishing("hook-private-write", PUBLISHING_POLICY);
    let output = hook_with_forge(
        &root,
        &call(
            "mcp__github__create_issue",
            &serde_json::json!({
                "owner": "example-org",
                "repo": "private-repo",
                "title": "A question",
                "body": "Refs example-org/other-private#1",
            }),
        ),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert_eq!(stdout(&output), "", "{}", stderr(&output));
    let asked = std::fs::read_to_string(root.join("gh.asked")).unwrap();
    assert!(
        asked.contains("api repos/example-org/private-repo --jq .visibility --hostname github.com"),
        "{asked}"
    );
}

/// The repository's own commit-message guard is not a rule any table scopes,
/// so it judges a tool call as it judges the same body through `gh`: against
/// this repository's declared visibility, wherever the text is going.
#[test]
fn a_guard_no_table_scopes_still_judges_a_write_into_a_private_repository() {
    let policy = PUBLISHING_POLICY.replace(
        "sets = [\"published-text\"]",
        "sets = [\"private-names\", \"published-text\"]",
    );
    let root = publishing(
        "hook-private-write-guarded",
        &format!("visibility = \"public\"\n{policy}"),
    );
    let output = hook_with_forge(
        &root,
        &call(
            "mcp__github__create_issue",
            &serde_json::json!({
                "owner": "example-org",
                "repo": "private-repo",
                "body": "Refs example-org/other-private#1",
            }),
        ),
    );
    let reason = reason(&output);
    assert!(
        reason.contains("no-private-repo-names [set: private-names]"),
        "{}",
        stderr(&output)
    );
    assert!(
        !reason.contains("no-published-private-repo-names"),
        "{reason}"
    );
}

/// Host identity is scoped `always`, so a private destination does not stand
/// it down.
#[test]
fn host_identity_is_refused_at_a_private_destination() {
    let root = publishing("hook-private-identity", PUBLISHING_POLICY);
    let output = hook_with_forge(
        &root,
        &call(
            "mcp__github__create_issue",
            &serde_json::json!({
                "owner": "example-org",
                "repo": "private-repo",
                "body": "The log is in /home/example-user/notes.txt",
            }),
        ),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        reason(&output).contains("/home/example-user"),
        "{}",
        stdout(&output)
    );
}

/// A call no table names has no destination, so a rule whose scope needs one
/// could not be asked, and `unresolved` refuses by default.
#[test]
fn a_call_no_table_names_is_refused_as_unresolved() {
    let root = publishing("hook-no-table", PUBLISHING_POLICY);
    let output = hook_with_forge(
        &root,
        &call(
            "mcp__slack__post_message",
            &serde_json::json!({"channel": "general", "text": "An ordinary sentence."}),
        ),
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert_eq!(stdout(&output), "");
    assert!(
        stderr(&output).contains("no `[[hook]]` table names mcp__slack__post_message"),
        "{}",
        stderr(&output)
    );
}

/// A table naming no destination, with `unresolved = "run"`: the call goes
/// ahead with the destination-scoped checks stood down, and says so.
#[test]
fn unresolved_run_lets_the_call_through_and_says_it_is_not_a_pass() {
    let policy = format!(
        "{PUBLISHING_POLICY}\n[[hook]]\ntools = '^mcp__slack__'\nscope = \"public-target\"\nunresolved = \"run\"\n"
    );
    let root = publishing("hook-unresolved-run", &policy);
    let output = hook_with_forge(
        &root,
        &call(
            "mcp__slack__post_message",
            &serde_json::json!({"text": "Refs example-org/other-private#1"}),
        ),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert_eq!(stdout(&output), "", "{}", stderr(&output));
    assert!(
        stderr(&output).contains("This is not a pass"),
        "{}",
        stderr(&output)
    );
}

/// A call the table names that carries no destination where the table points
/// is unresolved, and is not asked about some other repository instead.
#[test]
fn a_named_call_without_its_destination_is_refused_as_unresolved() {
    let root = publishing("hook-no-destination", PUBLISHING_POLICY);
    let output = hook_with_forge(
        &root,
        &call(
            "mcp__github__create_gist",
            &serde_json::json!({"filename": "a.md", "content": "An ordinary sentence."}),
        ),
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no string at \"/owner\""),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_table_with_half_a_destination_is_refused_at_load() {
    let policy = format!(
        "{PUBLISHING_POLICY}\n[[hook]]\ntools = '^mcp__forge__'\ntarget = \"forge-repo\"\nowner = \"/owner\"\n"
    );
    let root = publishing("hook-half-destination", &policy);
    let output = hook_with_forge(&root, &call("mcp__forge__write", &serde_json::json!({})));
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("without all of"),
        "{}",
        stderr(&output)
    );
}

/// Only `.rules` is merged from an inherited file, so a table there would
/// vanish and leave its calls judged as no table's. Refused instead.
#[test]
fn a_table_in_an_inherited_file_is_refused() {
    let root = publishing(
        "hook-inherited-table",
        "[inherit]\npaths = [\"policy/shared.toml\"]\n",
    );
    std::fs::write(
        root.join("policy/shared.toml"),
        "[[hook]]\ntools = '^mcp__forge__'\n",
    )
    .unwrap();
    let output = hook_with_forge(&root, &call("mcp__forge__write", &serde_json::json!({})));
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("an inherited file's tables are not adopted"),
        "{}",
        stderr(&output)
    );
}

/// A github.com destination is asked of github.com, whatever `GH_HOST` names:
/// an enterprise repository of the same name is a stranger, and its answer
/// would stand the private-name check down for the public one.
#[test]
fn a_github_destination_is_asked_of_github_com_under_an_enterprise_gh_host() {
    let root = publishing("hook-enterprise-host", PUBLISHING_POLICY);
    let output = hook_with_forge_at(
        &root,
        &call(
            "mcp__github__create_issue",
            &serde_json::json!({
                "owner": "example-user",
                "repo": "public-widget",
                "body": "Refs example-org/other-private#1",
            }),
        ),
        Some("github.example.com"),
    );
    assert!(
        reason(&output).contains("no-published-private-repo-names"),
        "{}",
        stderr(&output)
    );
    let asked = std::fs::read_to_string(root.join("gh.asked")).unwrap();
    assert!(
        asked.contains(
            "api repos/example-user/public-widget --jq .visibility --hostname github.com"
        ),
        "{asked}"
    );
}

/// `public-registry` reads an npm command line, which no tool call has, so the
/// hook cannot answer it and refuses, naming the rule and the way out. The
/// policy still loads: the scope is right at the shim, and every other seam
/// is not broken for the hook's sake.
#[test]
fn a_public_registry_rule_is_unresolved_at_the_hook_and_loads_elsewhere() {
    let policy = r#"
[rule.registry-prose]
message = "State the claim."
prose_regexp = '(?i)\barguably\b'
files.include = ["."]
command.before = ["npm"]
command.scope = "public-registry"

[[shim]]
command = "npm"
match = ["publish"]
"#;
    let body = serde_json::json!({"body": "An ordinary sentence."});
    let root = publishing("hook-public-registry", policy);
    let output = hook_with_forge(&root, &call("mcp__github__create_issue", &body));
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains(r#"seams = ["shim"]"#)
            && stderr(&output).contains("\"registry-prose\""),
        "{}",
        stderr(&output)
    );
    let scanned = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["scan", "--text", "-"])
        .current_dir(&root)
        .env("HOME", "/home/example-user")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(code(&scanned), 0, "{}", stderr(&scanned));
    let fixed = publishing(
        "hook-public-registry-shim-only",
        &policy.replace("command.scope", "seams = [\"shim\"]\ncommand.scope"),
    );
    let passed = hook_with_forge(&fixed, &call("mcp__github__create_issue", &body));
    assert_eq!(code(&passed), 0, "{}", stderr(&passed));
    assert_eq!(stdout(&passed), "", "{}", stderr(&passed));
    // The other way out the refusal names: `unresolved = "run"` on a table
    // for these calls, which the load accepts because this rule's scope is
    // one the hook cannot answer.
    let run = publishing(
        "hook-public-registry-run",
        &format!("{policy}\n[[hook]]\ntools = '^mcp__github__'\nunresolved = \"run\"\n"),
    );
    let ran = hook_with_forge(&run, &call("mcp__github__create_issue", &body));
    assert_eq!(code(&ran), 0, "{}", stderr(&ran));
    assert_eq!(stdout(&ran), "", "{}", stderr(&ran));
    assert!(
        stderr(&ran).contains("This is not a pass"),
        "{}",
        stderr(&ran)
    );
}

/// A GitLab destination names no host, and `glab` asked without one answers
/// for whichever instance it is configured for, so the table refuses it.
#[test]
fn a_gitlab_destination_is_refused_at_load() {
    let policy = format!(
        "{PUBLISHING_POLICY}\n[[hook]]\ntools = '^mcp__gitlab__'\ntarget = \"forge-repo\"\nforge = \"gitlab\"\nowner = \"/owner\"\nrepo = \"/repo\"\nscope = \"public-target\"\n"
    );
    let root = publishing("hook-gitlab-destination", &policy);
    let output = hook_with_forge(
        &root,
        &call("mcp__gitlab__create_issue", &serde_json::json!({})),
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("unknown variant `gitlab`"),
        "{}",
        stderr(&output)
    );
}

/// A repository's own table naming a command it shims nothing for would be
/// judged under defaults nobody wrote, so it is refused at load.
#[test]
fn a_table_naming_an_undeclared_shim_is_refused_at_load() {
    let policy =
        format!("{PUBLISHING_POLICY}\n[[hook]]\ntools = '^mcp__forge__'\nshim = \"glab\"\n");
    let root = publishing("hook-undeclared-shim", &policy);
    let output = hook_with_forge(&root, &call("mcp__forge__write", &serde_json::json!({})));
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no `[[shim]]` here stands in front of \"glab\""),
        "{}",
        stderr(&output)
    );
}

/// A read the table skips is judged by nothing, and its record says so rule
/// by rule: an absent document would read as a call the hook never saw.
#[test]
fn a_skipped_read_writes_a_record_of_rules_set_aside() {
    let root = workspace(
        "hook-junit-skipped",
        Some(&format!("{POLICY}\n{PROSE_POLICY}{SHIMS}")),
    );
    let evidence = root.join("evidence");
    std::fs::create_dir_all(&evidence).unwrap();
    let tool = "mcp__github__get_file_contents";
    let output = hook_recorded(
        &root,
        &["claude-code"],
        &event(tool, "Arguably fine.\n\nGenerated with Claude Code"),
        Some(&evidence),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert_eq!(stdout(&output), "", "{}", stdout(&output));
    let files = support::junit::files_in(&evidence);
    assert_eq!(files.len(), 1, "{files:?}");
    let (suite, _) = support::junit::suite(files.first().unwrap());
    for id in [
        "prevent-ai-author",
        "no-empty-hedge-here",
        "no-running-os-identity-metadata",
    ] {
        let case = support::junit::case(&suite, id);
        assert_eq!(support::junit::state(case).0, "skipped", "{id}");
        assert_eq!(support::junit::properties(case, "subject"), [tool]);
    }
    assert_eq!((suite.tests, suite.failures), (3, 0), "{suite:?}");
}

/// A tool call has no remote, so `git-remote` is not a `[[hook]]` target: the
/// load refuses it, naming the two that are.
#[test]
fn a_git_remote_target_is_refused_at_load() {
    let policy = format!(
        "{PUBLISHING_POLICY}\n[[hook]]\ntools = '^mcp__forge__'\ntarget = \"git-remote\"\n"
    );
    let root = publishing("hook-git-remote", &policy);
    let output = hook_with_forge(&root, &call("mcp__forge__write", &serde_json::json!({})));
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("unknown variant `git-remote`, expected `forge-repo` or `none`"),
        "{}",
        stderr(&output)
    );
}

/// A read publishes no text, and a rule about what the call is still runs on
/// it: a repository refusing a tool by its name keeps refusing it when the
/// compiled-in table lists that tool as a read, and with no scope of its own
/// the rule takes `gh`'s, which a read never has to ask a forge about.
#[test]
fn a_tool_name_rule_still_refuses_a_skipped_read() {
    let policy = "\
[[shim]]
command = \"gh\"
match = [\"search:code\"]
argv_subject = true
scope = \"public-target\"

[rule.no-code-search]
message = \"Search the local checkout instead.\"
regexp = '^search code|__search_code$'
subjects = [\"argv\", \"tool\"]
seams = [\"shim\", \"hook\"]
command.before = [\"gh\"]
";
    let root = publishing("hook-tool-rule-on-read", policy);
    let output = hook_with_forge(
        &root,
        &call(
            "mcp__github__search_code",
            &serde_json::json!({"query": "anything"}),
        ),
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        reason(&output).contains("no-code-search"),
        "{}",
        stderr(&output)
    );
    assert!(!root.join("gh.asked").exists());
}

/// A server set to publish to GitHub Enterprise is not one the compiled-in
/// table describes. The repository's own table for its tools, naming no
/// destination, leaves every check that needs one unresolved: refused, and
/// never asked of a github.com repository that shares the name.
#[test]
fn an_enterprise_servers_own_table_refuses_rather_than_ask_github_com() {
    let policy = format!(
        "{PUBLISHING_POLICY}\n[[hook]]\ntools = '^mcp__github__'\nskip = [\"get_file_contents\"]\nscope = \"public-target\"\n"
    );
    let root = publishing("hook-enterprise-server", &policy);
    let output = hook_with_forge(
        &root,
        &call(
            "mcp__github__create_issue",
            &serde_json::json!({
                "owner": "example-user",
                "repo": "public-widget",
                "body": "An ordinary sentence.",
            }),
        ),
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("names no destination"),
        "{}",
        stderr(&output)
    );
    assert!(!root.join("gh.asked").exists());
}
