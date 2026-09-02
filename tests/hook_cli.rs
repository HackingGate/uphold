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
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
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
    serde_json::json!({"tool_name": tool, "tool_input": {"body": body}}).to_string()
}

// -- what the harness reads ------------------------------------------------

/// The refusal has to arrive as a document, on stdout, at exit 0.
///
/// This is the inversion the module doc explains and the one thing about this
/// seam that is easy to get wrong: everywhere else in this binary 1 means
/// refused, and here a non-zero status is read as the hook itself having
/// failed, which lets the call proceed. A regression here does not look like a
/// refusal that stopped working. It looks like a complaint on a published body.
#[test]
fn a_refusal_is_a_document_on_stdout_at_exit_zero() {
    let root = workspace("hook-deny", Some(POLICY));
    let output = hook(
        &root,
        "claude-code",
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

/// A clean call says nothing at all.
///
/// Not a courtesy. This fires on every matched tool call in a session rather
/// than once per commit, and a gate that narrates its passes is the gate whose
/// output gets filtered and then whose matcher gets deleted.
#[test]
fn a_clean_call_is_silent() {
    let root = workspace("hook-clean", Some(POLICY));
    let output = hook(
        &root,
        "claude-code",
        &event("mcp__github__create_issue", "an ordinary body"),
    );
    assert_eq!(code(&output), 0);
    assert_eq!(stdout(&output), "");
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
    let root = workspace("hook-no-policy", None);
    let output = hook(
        &root,
        "claude-code",
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
        stderr(&output).contains("claude-code"),
        "{}",
        stderr(&output)
    );
    assert_eq!(stdout(&output), "");
}

/// An event that is not JSON is exit 2 for the same reason, and it is also what
/// a harness that changed its schema looks like from here.
#[test]
fn a_malformed_event_is_could_not_look_and_not_a_pass() {
    let root = workspace("hook-malformed", Some(POLICY));
    let output = hook(&root, "claude-code", "{not json");
    assert_eq!(code(&output), 2);
    assert!(
        stderr(&output).contains("would mean"),
        "{}",
        stderr(&output)
    );
}

/// An event with no subject at all is could-not-look, not a clean call.
///
/// The malformed case one level down, and the one that does not announce
/// itself: the JSON parses, the run exits, and nothing was read. It is what a
/// harness renaming its field looks like from here, and reporting it as a pass
/// would leave the seam silently switched off at the version it changed.
#[test]
fn an_event_with_no_subject_is_could_not_look_and_not_a_pass() {
    let root = workspace("hook-no-subject", Some(POLICY));
    let output = hook(
        &root,
        "claude-code",
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

/// A call carrying no text at all publishes nothing there is a rule about.
#[test]
fn a_call_with_no_strings_is_allowed_without_looking_further() {
    let root = workspace("hook-no-strings", Some(POLICY));
    let output = hook(
        &root,
        "claude-code",
        r#"{"tool_name":"mcp__forge__count","tool_input":{"limit":10,"all":true}}"#,
    );
    assert_eq!(code(&output), 0);
    assert_eq!(stdout(&output), "");
}
