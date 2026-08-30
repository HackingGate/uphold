//! CLI-level tests for `uphold shim`.
//!
//! Every case drives a real invocation and lets it exec through to a stub
//! command on PATH, because "checked and then ran the command" is the contract
//! -- a shim that refuses correctly and never execs has broken the command it
//! was standing in front of.

#![expect(
    clippy::let_underscore_must_use,
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// A shim whose scope is `always`, so the tests do not need a forge.
const POLICY: &str = r#"
[rule.no-published-markers]
message = "remove the marker"
exec = "uphold guard --text -"

# The shim under test, and only it. Naming the command here is what the
# scoping is: a checker used to be consulted by every declared shim, so this
# fixture would have exercised the rule even if the shim below were for a
# different command entirely.
[rule.no-published-markers.command]
before = ["faux"]

[rule.prevent-ai-author]
builtin = "prevent-ai-author"

[rule.prevent-ai-author.git]
hooks = ["commit-msg"]

[[shim]]
command = "faux"
match = ["pr:create", "issue:*"]
text_flags = ["-t", "--title", "-b", "--body"]
file_flags = ["-F", "--body-file"]
skip_flags = ["--fill"]
web_flags = ["-w", "--web"]
editor_env = "FAUX_EDITOR"
scope = "always"
"#;

fn workspace(policy: &str) -> PathBuf {
    let root = support::scratch("shim-cli");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    std::fs::create_dir_all(root.join("bin")).unwrap();
    std::fs::write(root.join("policy/principles.toml"), policy).unwrap();

    // The checkers in this policy are the binary consulting itself, which is
    // the point of them -- the rule that judges a commit message and the rule
    // that judges a pull-request body are the same rule. So it has to be on
    // PATH under its own name, which the multicall entry then dispatches
    // normally.
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), root.join("bin/uphold")).unwrap();

    // The real command, which must be reached when nothing refuses.
    let stub = root.join("bin/faux");
    std::fs::write(&stub, "#!/bin/sh\necho \"faux ran: $*\"\n").unwrap();
    let mut permissions = std::fs::metadata(&stub).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(&stub, permissions).unwrap();

    Command::new(support::real_git())
        .args(["init", "-q", "-b", "main"])
        .current_dir(&root)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    root
}

fn shim(root: &Path, args: &[&str]) -> Output {
    let path = format!(
        "{}:{}",
        root.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .arg("shim")
        .args(args)
        .current_dir(root)
        .env("PATH", path)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_clean_invocation_is_checked_and_then_actually_runs() {
    // The half that is easy to lose. A shim that refuses correctly and never
    // execs has broken the command it was standing in front of.
    let root = workspace(POLICY);
    let output = shim(&root, &["faux", "pr", "create", "-t", "An ordinary title"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"), "{}", stdout(&output));
}

#[test]
fn a_marker_in_a_title_is_refused_and_the_command_never_runs() {
    let root = workspace(POLICY);
    let output = shim(
        &root,
        &["faux", "pr", "create", "-t", "Generated with Claude Code"],
    );
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("faux ran:"),
        "{}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("Nothing was published"),
        "{}",
        stderr(&output)
    );
}

/// A policy where one verb's grammar differs from the table's, which is the
/// case `[[shim.verbs]]` exists for. `-c` is bare on `pr:review` and takes a
/// value on `issue:close`, exactly as it is on the real `gh`.
const PER_VERB_POLICY: &str = r#"
[rule.no-published-markers]
message = "remove the marker"
exec = "uphold guard --text -"

[rule.no-published-markers.command]
before = ["faux"]

# The text-capable guard `uphold guard --text -` actually runs. Without it the
# checker consults an empty list and every subject passes, which would make
# these tests green over a shim that read nothing.
[rule.prevent-ai-author]
builtin = "prevent-ai-author"

[rule.prevent-ai-author.git]
hooks = ["commit-msg"]

[[shim]]
command = "faux"
match = ["pr:review", "issue:close"]
text_flags = ["-b", "--body"]
scope = "always"

  [[shim.verbs]]
  match = ["issue:close"]
  text_flags = ["-c", "--comment"]
"#;

#[test]
fn a_verbs_table_gives_one_verb_its_own_flag_vocabulary() {
    // The gap this closes: `faux issue close --comment` published text through
    // a vocabulary that did not name `--comment`, so nothing read it.
    let root = workspace(PER_VERB_POLICY);
    let output = shim(
        &root,
        &[
            "faux",
            "issue",
            "close",
            "1",
            "--comment",
            "Generated with Claude Code",
        ],
    );
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("faux ran:"),
        "{}",
        stdout(&output)
    );

    // And it is the flag being read rather than the verb being refused
    // wholesale: an ordinary comment goes through.
    let clean = shim(
        &root,
        &["faux", "issue", "close", "1", "--comment", "ordinary"],
    );
    assert_eq!(code(&clean), 0, "{}", stderr(&clean));
    assert!(stdout(&clean).contains("faux ran:"), "{}", stdout(&clean));
}

#[test]
fn a_verb_vocabulary_does_not_leak_onto_the_verbs_that_did_not_ask() {
    // The reason the lists REPLACE rather than union. On the real `gh`, `-c` is
    // a boolean on `pr review` -- "Comment on a pull request". If the entry's
    // `-c` reached this verb too, `-c` would swallow `-b` as its value and the
    // body it is publishing would go unread: a false negative introduced into
    // the seam that exists to prevent one.
    let root = workspace(PER_VERB_POLICY);
    let output = shim(
        &root,
        &[
            "faux",
            "pr",
            "review",
            "1",
            "-c",
            "-b",
            "Generated with Claude Code",
        ],
    );
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("faux ran:"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn an_entrys_vocabulary_replaces_the_tables_rather_than_adding_to_it() {
    // `allowed_scripts` already settled this for the same reason: what is
    // declared beside the narrower thing is the WHOLE truth for it. A union
    // would mean a vocabulary nobody wrote -- here, `issue close --body`, which
    // the real `gh` does not have. Reading a flag the command does not accept
    // is not harmless: it is the shim claiming to have checked a subject that
    // was never published.
    let root = workspace(PER_VERB_POLICY);
    let output = shim(
        &root,
        &[
            "faux",
            "issue",
            "close",
            "1",
            "--body",
            "Generated with Claude Code",
        ],
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"), "{}", stdout(&output));
}

#[test]
fn a_verb_the_entries_do_not_name_keeps_the_tables_own_vocabulary() {
    // Every shim written before entries existed is this case.
    let root = workspace(PER_VERB_POLICY);
    let output = shim(
        &root,
        &[
            "faux",
            "pr",
            "review",
            "1",
            "--body",
            "Generated with Claude Code",
        ],
    );
    assert_eq!(code(&output), 1, "{}", stderr(&output));

    let clean = shim(&root, &["faux", "pr", "review", "1", "--body", "ordinary"]);
    assert_eq!(code(&clean), 0, "{}", stderr(&clean));
}

#[test]
fn an_unnamed_subcommand_is_not_this_shims_business() {
    // Named rather than pattern-matched. `pr checkout` publishes nothing.
    let root = workspace(POLICY);
    let output = shim(
        &root,
        &["faux", "pr", "checkout", "-t", "Generated with Claude Code"],
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"));
}

#[test]
fn a_flag_is_read_in_both_spellings() {
    let root = workspace(POLICY);
    for form in [
        vec![
            "faux",
            "issue",
            "create",
            "--body=Generated with Claude Code",
        ],
        vec![
            "faux",
            "issue",
            "create",
            "--body",
            "Generated with Claude Code",
        ],
    ] {
        let output = shim(&root, &form);
        assert_eq!(code(&output), 1, "{form:?}: {}", stderr(&output));
    }
}

#[test]
fn a_body_file_is_read_and_a_skip_flag_is_not() {
    let root = workspace(POLICY);
    std::fs::write(root.join("body.md"), "Generated with Claude Code\n").unwrap();
    let output = shim(&root, &["faux", "pr", "create", "-F", "body.md"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));

    // `--fill` takes the body from commit messages, which commit-msg already
    // guarded on the way in.
    let output = shim(&root, &["faux", "pr", "create", "--fill"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_body_composed_in_an_editor_makes_the_editor_the_checkpoint() {
    // This case used to be the one thing a shim admitted it could not see: no
    // body in argv, no `--web`, and a command about to open an editor, so there
    // was nothing to hand a checker and the shim said so and execed. Saying so
    // leaves the text unchecked and tells somebody who did nothing wrong to do
    // it differently, so the shim now installs itself in the command's own
    // editor variable and reads the file back when the editor closes.
    //
    // The assertion is on what is HANDED to the command, because that is what
    // decides whether the checkpoint exists: the stub prints its environment,
    // and the shim's declared `editor_env` has to be pointing at this binary by
    // the time the command runs. `tests/shim_handoff_cli.rs` drives the whole
    // round trip with a real editor; this holds the near end of it.
    let root = workspace(POLICY);
    let stub = root.join("bin/faux");
    std::fs::write(
        &stub,
        "#!/bin/sh\necho \"faux ran: $*\"\necho \"editor: $FAUX_EDITOR\"\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&stub).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(&stub, permissions).unwrap();

    let output = shim(&root, &["faux", "pr", "create"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        // `--as-editor` is the word that routes the re-entry. It was an
        // environment variable, which every descendant of the checking pass
        // inherited -- see `an_editor_pass_does_not_re_enter_the_git_it_runs`.
        stdout(&output).contains("editor: ") && stdout(&output).contains("shim --as-editor 'faux'"),
        "the command was handed no checkpoint to open: {}",
        stdout(&output)
    );
    // And it says which checkpoint it is, rather than reporting a pass over
    // text nothing has read yet.
    assert!(
        stderr(&output).contains("the editor is the checkpoint"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn the_bypass_names_the_checker_it_switched_off() {
    let root = workspace(POLICY);
    let path = format!(
        "{}:{}",
        root.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args([
            "shim",
            "faux",
            "pr",
            "create",
            "-t",
            "Generated with Claude Code",
        ])
        .current_dir(&root)
        .env("PATH", path)
        .env("UPHOLD_ALLOW", "no-published-markers")
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"));
}

/// Asked BY NAME for a shim this repository does not have, and told so.
///
/// The other half of this pair lets the same reading through, and the two are
/// not in tension: what differs is what was asked. `uphold shim unknown ...` is
/// a question typed with an answer in mind, and nothing is standing in front of
/// anything, so the caller hears it rather than watching a typo run.
#[test]
fn a_command_no_shim_declares_is_refused_rather_than_silently_passed_through() {
    let root = workspace(POLICY);
    let output = shim(&root, &["unknown-command", "publish"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no shim declares"),
        "{}",
        stderr(&output)
    );
}

/// A link is on PATH for the whole machine; a `[[shim]]` is a line in one
/// repository's policy.
///
/// So the undeclared case is the ordinary one, not the exception: every
/// directory outside a participating repository reaches it, and so does every
/// participating repository that declares a shim for some OTHER command. While
/// that answer was an error, installing the link as the documentation describes
/// made the command exit 2 nearly everywhere it was typed -- and what gets
/// installed after that is nothing, which loses the seam in the repositories
/// that did declare it.
#[test]
fn a_command_this_policy_does_not_declare_still_runs_when_the_link_is_the_command() {
    let root = workspace(POLICY);
    // The real command, behind a link named for it. Two directories, because one
    // cannot hold two files of the same name -- and the link has to come first.
    std::fs::create_dir_all(root.join("front")).unwrap();
    let stub = root.join("bin/undeclared");
    std::fs::write(&stub, "#!/bin/sh\necho \"undeclared ran: $*\"\n").unwrap();
    let mut permissions = std::fs::metadata(&stub).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(&stub, permissions).unwrap();
    let link = root.join("front/undeclared");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), &link).unwrap();

    let path = format!(
        "{}:{}:{}",
        root.join("front").display(),
        root.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(&link)
        .args(["publish", "--now"])
        .current_dir(&root)
        .env("PATH", path)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stdout(&output).contains("undeclared ran: publish --now"),
        "{}{}",
        stdout(&output),
        stderr(&output)
    );
}

/// No policy where the command was typed is not a repository refusing; it is a
/// directory that declares nothing.
///
/// `/tmp`, somebody else's checkout, a shell that never enters a participating
/// repository -- a machine-wide link meets these far more often than it meets a
/// declaration. Refusing here protects nothing and breaks the command
/// everywhere.
#[test]
fn a_directory_with_no_policy_at_all_does_not_break_the_command() {
    let root = workspace(POLICY);
    // Outside `root`, deliberately: a subdirectory of it would find the policy
    // by walking up, which is the case this test is not about.
    let elsewhere = support::run_root().join(format!(
        "shim-no-policy-{}",
        root.file_name().unwrap().to_string_lossy()
    ));
    let _ = std::fs::remove_dir_all(&elsewhere);
    std::fs::create_dir_all(&elsewhere).unwrap();

    // Named for the stub, so PATH resolution finds the link first and the real
    // command second, exactly as an install puts them.
    std::fs::create_dir_all(root.join("front")).unwrap();
    let front = root.join("front/faux");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), &front).unwrap();

    let path = format!(
        "{}:{}:{}",
        root.join("front").display(),
        root.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(&front)
        .args(["pr", "create", "-t", "anything"])
        .current_dir(&elsewhere)
        .env("PATH", path)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stdout(&output).contains("faux ran:"),
        "{}{}",
        stdout(&output),
        stderr(&output)
    );
}

#[test]
fn a_checker_that_could_not_look_is_not_a_pass() {
    // Exit 2 is the third answer, and folding it into either of the others is
    // the failure `explicit-unknown` names.
    let root = workspace(
        r#"
[rule.cannot-look]
message = "x"
exec = "exit 2"

[rule.cannot-look.command]
before = ["faux"]

[[shim]]
command = "faux"
match = ["pr:create"]
text_flags = ["-t"]
scope = "always"
"#,
    );
    let output = shim(&root, &["faux", "pr", "create", "-t", "anything"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(!stdout(&output).contains("faux ran:"));
}

#[test]
fn the_binary_run_under_a_commands_name_is_that_commands_shim() {
    // The multicall entry, which is what ends the installer: there is nothing
    // to install but a link, and nothing to find but this binary.
    let root = workspace(POLICY);
    let link = root.join("bin/faux-link");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), &link).unwrap();

    let mut policy = std::fs::read_to_string(root.join("policy/principles.toml")).unwrap();
    policy = policy.replace("command = \"faux\"", "command = \"faux-link\"");
    policy = policy.replace("before = [\"faux\"]", "before = [\"faux-link\"]");
    std::fs::write(root.join("policy/principles.toml"), policy).unwrap();

    let path = format!(
        "{}:{}",
        root.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(&link)
        .args(["pr", "create", "-t", "Generated with Claude Code"])
        .current_dir(&root)
        .env("PATH", path)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap();
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("Nothing was published"),
        "{}",
        stderr(&output)
    );
}

/// argv is bytes, and a shim that stands in front of `git` will be handed some.
///
/// `std::env::args()` PANICS on an argument that is not UTF-8 -- exit 101, out
/// of a binary whose whole promise is three exit codes and transparency. A file
/// named in latin-1 is an ordinary argument to `git add`, and this binary is
/// installed exactly where such a name gets typed. So the bytes go through
/// untouched where there is nothing to check, and where there IS something to
/// check the shim says it could not read them rather than checking a lossy copy.
#[test]
fn an_argument_that_is_not_text_reaches_the_command_it_was_typed_for() {
    use std::os::unix::ffi::OsStringExt;

    let root = workspace(POLICY);
    let path = format!(
        "{}:{}",
        root.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    // `caf\xe9`, which is a perfectly good file name and is not UTF-8.
    let latin1 = std::ffi::OsString::from_vec(b"caf\xe9.txt".to_vec());

    // `repo clone` is not in this shim's `match` list, so there is nothing to
    // check and nothing to stop: the command must run.
    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["shim", "faux", "repo", "clone"])
        .arg(&latin1)
        .current_dir(&root)
        .env("PATH", &path)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stdout(&output).contains("faux ran: repo clone"),
        "{}",
        stdout(&output)
    );

    // `pr create` is, so the same bytes are now part of an invocation whose text
    // is checked. Exit 2: nothing was found and nothing was cleared.
    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["shim", "faux", "pr", "create", "-t"])
        .arg(&latin1)
        .current_dir(&root)
        .env("PATH", &path)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap();
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("is not UTF-8 text"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stdout(&output).contains("faux ran:"),
        "{}",
        stdout(&output)
    );
}

/// A text-capable built-in standing in front of a command, with no `exec`
/// checker anywhere and no git hook.
///
/// The seam some guards belong at and could not name. `no-private-repo-names`
/// reads a commit message at every git hook, which refuses the issue citations
/// a repository's own prose is full of -- so a repository that wants it over a
/// pull-request body and NOWHERE else had no field to say it in, and three
/// wrote `command.before` on the built-in independently while the loader
/// refused all three.
const BUILTIN_CHECKER: &str = r#"
[[shim]]
command = "faux"
match = ["pr:create"]
text_flags = ["-t", "--title", "-b", "--body"]
scope = "always"

[rule.no-private-repo-names]
builtin = "no-private-repo-names"
visibility = "public"
private_owners = ["acme-private"]

[rule.no-private-repo-names.command]
before = ["faux"]
"#;

#[test]
fn a_text_capable_builtin_refuses_the_body_it_stands_in_front_of() {
    let root = workspace(BUILTIN_CHECKER);
    let output = shim(
        &root,
        &[
            "faux",
            "pr",
            "create",
            "-b",
            "this fixes acme-private/thing",
        ],
    );
    assert_eq!(code(&output), 1, "{}", stdout(&output));
    assert!(
        stderr(&output).contains("acme-private"),
        "{}",
        stderr(&output)
    );
    // Refused means not published: the real command must not have run.
    assert!(!stdout(&output).contains("faux ran"), "{}", stdout(&output));
}

#[test]
fn a_clean_body_reaches_the_real_command_through_a_builtin_checker() {
    let root = workspace(BUILTIN_CHECKER);
    let output = shim(&root, &["faux", "pr", "create", "-b", "an ordinary change"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran"), "{}", stdout(&output));
}

/// A `git` shim as the shipped policy declares it, with git's own global
/// grammar written nowhere in it.
const GIT_POLICY: &str = r#"
[rule.no-published-markers]
message = "remove the marker"
exec = "uphold guard --text -"

[rule.no-published-markers.command]
before = ["git"]

[rule.prevent-ai-author]
builtin = "prevent-ai-author"

[rule.prevent-ai-author.git]
hooks = ["commit-msg"]

[[shim]]
command = "git"
match = ["push:*"]
text_flags = ["-m"]
scope = "always"
"#;

/// A stub for a command the workspace does not install by default.
fn stub(root: &Path, name: &str, script: &str) {
    let path = root.join("bin").join(name);
    std::fs::write(&path, script).unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(&path, permissions).unwrap();
}

#[test]
fn a_git_global_option_before_the_subcommand_does_not_switch_the_shim_off() {
    // A `[[shim]]` table names the flags whose values it publishes; nothing in
    // one says what `git -c` does, and no repository should have to write git's
    // grammar into its policy to be guarded. Skipping only the table's flags,
    // `git -c user.name=x push ...` reads `user.name=x` as the verb -- no
    // `match` entry contains that, so a push to a public forge exec'd
    // unexamined, silently and with an exit code of 0.
    let root = workspace(GIT_POLICY);
    stub(&root, "git", "#!/bin/sh\necho \"git ran: $*\"\n");
    for form in [
        vec![
            "git",
            "-c",
            "user.name=x",
            "push",
            "-m",
            "Generated with Claude Code",
        ],
        vec![
            "git",
            "-C",
            "/somewhere/else",
            "push",
            "-m",
            "Generated with Claude Code",
        ],
        vec![
            "git",
            "--git-dir",
            "/elsewhere/.git",
            "push",
            "-m",
            "Generated with Claude Code",
        ],
    ] {
        let output = shim(&root, &form);
        assert_eq!(code(&output), 1, "{form:?}: {}", stderr(&output));
        assert!(!stdout(&output).contains("git ran:"), "{form:?}");
    }

    // And the half a looser matcher would lose: `-c` takes the word after it,
    // so `status` there is a value and not a subcommand this shim checks. Read
    // as a decision rather than as an ambiguity -- knowing git's grammar is
    // what keeps every `git -c ... status` on the machine quiet.
    let output = shim(&root, &["git", "-c", "user.name=push", "status"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("git ran:"), "{}", stdout(&output));
    assert!(
        !stderr(&output).contains("This is not a pass."),
        "{}",
        stderr(&output)
    );
}

/// A `git` shim that reads its subjects out of the positions, as the shipped
/// policy declares it.
const GIT_REFS_POLICY: &str = r#"
[rule.no-published-branch-name]
message = "that name goes onto a public forge in the ref list"
exec = 'if grep -q acme; then echo "the name names a private owner" >&2; exit 1; fi'

[rule.no-published-branch-name.command]
before = ["git"]

[[shim]]
command = "git"
match = ["push:*"]
scope = "always"
collect = "git-refs"
"#;

/// A `git` that reports a push instead of making one, and is the real git for
/// everything else -- the shim reads `HEAD` through it.
fn forwarding_git(root: &Path) {
    stub(
        root,
        "git",
        &format!(
            "#!/bin/sh\nfor word in \"$@\"; do\n  [ \"$word\" = push ] && {{ echo \"git ran: $*\"; exit 0; }}\ndone\nexec {} \"$@\"\n",
            support::real_git().display()
        ),
    );
}

#[test]
fn a_global_option_does_not_shift_which_word_the_branch_is() {
    // The matcher learned git's global grammar and the collector did not.
    // `git -c user.name=x push origin topic` was MATCHED -- that is what
    // `VALUE_OPTIONS` bought -- and then collected by argv index: `user.name=x`
    // read as the remote, `push` as the name being published, and the branch
    // that actually goes out checked nowhere. The bare form is worse: a word
    // WAS collected, so the fallback that reads the branch off `HEAD` did not
    // run, and `git -c ... push` published a branch name through nothing.
    let root = workspace(GIT_REFS_POLICY);
    forwarding_git(&root);
    Command::new(support::real_git())
        .args(["symbolic-ref", "HEAD", "refs/heads/fix/acme-outage"])
        .current_dir(&root)
        .status()
        .unwrap();

    for form in [
        vec!["git", "push", "origin", "fix/acme-outage"],
        vec![
            "git",
            "-c",
            "user.name=x",
            "push",
            "origin",
            "fix/acme-outage",
        ],
        vec![
            "git",
            "-C",
            "elsewhere",
            "push",
            "origin",
            "fix/acme-outage",
        ],
        vec![
            "git",
            "--git-dir",
            "elsewhere/.git",
            "push",
            "origin",
            "fix/acme-outage",
        ],
        // The name appears nowhere in argv, so the subject comes off `HEAD`.
        vec!["git", "-c", "user.name=x", "push"],
    ] {
        let output = shim(&root, &form);
        assert_eq!(code(&output), 1, "{form:?}: {}", stderr(&output));
        assert!(!stdout(&output).contains("git ran:"), "{form:?}");
    }

    // And the other half: a name nothing refuses still reaches the command,
    // past the same option.
    let output = shim(
        &root,
        &["git", "-c", "user.name=x", "push", "origin", "fix/ordinary"],
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("git ran:"), "{}", stdout(&output));
}

#[test]
fn an_option_nothing_can_classify_is_said_out_loud_rather_than_passed_in_silence() {
    // TWO options nothing can classify, which is what leaves the subcommand
    // genuinely undetermined: `words` applies `unknown_takes_value` uniformly,
    // so two of them have four readings and exactly two are tried. Running the
    // command anyway is deliberate -- the link is on PATH for the whole
    // machine, and refusing every command that grows an option would make the
    // guard the reason work stops -- but running it in silence is the shape of
    // failure this tool refuses.
    let root = workspace(POLICY);
    let output = shim(
        &root,
        &["faux", "--fic-a", "x", "--fic-b", "y", "repo", "clone"],
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"), "{}", stdout(&output));
    assert!(
        stderr(&output).contains("This is not a pass."),
        "{}",
        stderr(&output)
    );

    // And ONE is not a doubt, because the two readings are then the whole
    // space and both were asked. Said at this level as well as in the unit
    // test, because this line is the one a person actually sees: before #56 a
    // git shim declaring `push:*` printed the refusal over `git show --stat
    // HEAD`, `git commit -F -` and seven more of sixteen ordinary invocations,
    // and stayed quiet on `git push`.
    let output = shim(&root, &["faux", "--fictional", "value", "repo", "clone"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"), "{}", stdout(&output));
    assert!(
        !stderr(&output).contains("This is not a pass."),
        "{}",
        stderr(&output)
    );
}

/// A shim that names this invocation, and a checker that names another one.
///
/// The load refuses a `[[shim]]` whose command no rule names at all. This is
/// the same reading one invocation later: `faux pr create` is checked, and
/// `faux issue create` -- which the same `match` list names -- is collected,
/// consulted by nobody, and exec'd.
const NARROWED_CHECKER: &str = r#"
[rule.no-published-markers]
message = "remove the marker"
exec = "uphold guard --text -"

[rule.no-published-markers.command]
before = ["faux pr create"]

[[shim]]
command = "faux"
match = ["pr:create", "issue:*"]
text_flags = ["-t", "--title", "-b", "--body"]
scope = "always"
"#;

#[test]
fn an_invocation_no_checker_stands_in_front_of_is_not_a_pass() {
    let root = workspace(NARROWED_CHECKER);

    // The invocation a rule does name is checked, and runs.
    let output = shim(&root, &["faux", "pr", "create", "-t", "An ordinary title"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"), "{}", stdout(&output));

    // The one it does not is exit 2 and no command at all. A body collected and
    // consulted by nobody exits 0 otherwise, which is indistinguishable from a
    // body every checker approved.
    let output = shim(
        &root,
        &["faux", "issue", "create", "-t", "An ordinary title"],
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("faux ran:"),
        "{}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("nothing would have been checked"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_builtin_checker_satisfies_the_shim_that_would_otherwise_check_nothing() {
    // The load refuses a shim no checker names, because a command collected and
    // consulted by nothing runs anyway -- an invocation that passed because
    // nothing looked at it. A built-in is a checker, and counting only `exec`
    // rules refused a policy whose shim WAS checked, by a guard rather than a
    // script.
    let root = workspace(BUILTIN_CHECKER);
    let output = shim(&root, &["faux", "--version"]);
    assert_eq!(code(&output), 0, "{}{}", stdout(&output), stderr(&output));
}

#[test]
fn a_policy_that_cannot_be_read_refuses_the_command_and_names_the_way_out() {
    // The trap this closes: with an unparseable policy, the shim refused every
    // invocation of the command it stands in front of -- including the `git
    // checkout` that would put the file back. The refusal is right. Being
    // unable to repair the declaration without knowing the real binary's path
    // is not.
    let root = workspace("this is not toml [[[\n");

    let refused = shim(&root, &["faux", "pr", "create", "-t", "a title"]);
    assert_eq!(code(&refused), 2, "{}", stderr(&refused));
    let text = stderr(&refused);
    assert!(text.contains("did not run"), "{text}");
    assert!(text.contains("UPHOLD_ALLOW=all"), "{text}");

    // And the way out works, says so, and is not silent about it: a bypass that
    // became habit has to be visible in a shell history and a CI log.
    let allowed = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["shim", "faux", "pr", "create", "-t", "a title"])
        .current_dir(&root)
        .env(
            "PATH",
            format!(
                "{}:{}",
                root.join("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("UPHOLD_ALLOW", "all")
        .output()
        .unwrap();
    assert_eq!(allowed.status.code().unwrap(), 0, "{}", stderr(&allowed));
    assert!(
        String::from_utf8_lossy(&allowed.stdout).contains("faux ran"),
        "the real command did not run"
    );
    assert!(
        stderr(&allowed).contains("ran unchecked"),
        "{}",
        stderr(&allowed)
    );
}

#[test]
fn an_empty_allow_variable_switches_nothing_off() {
    // `UPHOLD_ALLOW=` is a variable somebody exported and then cleared. Read as
    // a list it is one empty field, and an early version of the whole-invocation
    // bypass answered yes to it -- which would have switched the seam off in
    // every shell that had ever set the variable.
    let root = workspace("this is not toml [[[\n");

    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["shim", "faux", "pr", "create", "-t", "a title"])
        .current_dir(&root)
        .env(
            "PATH",
            format!(
                "{}:{}",
                root.join("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("UPHOLD_ALLOW", "")
        .output()
        .unwrap();
    assert_eq!(output.status.code().unwrap(), 2, "{}", stderr(&output));
}

// ── the consultations, in-process ────────────────────────────────────

/// The `POLICY` above with the `exec` line replaced by the built-in it was
/// re-invoking this binary for, which is the promotion `published-text` ships.
const BUILTIN_POLICY: &str = r#"
[rule.no-published-markers]
message = "remove the marker"
builtin = "text-guards"

[rule.no-published-markers.command]
before = ["faux"]

[rule.prevent-ai-author]
builtin = "prevent-ai-author"

[rule.prevent-ai-author.git]
hooks = ["commit-msg"]

[[shim]]
command = "faux"
match = ["pr:create"]
text_flags = ["-t", "--title", "-b", "--body"]
scope = "always"
"#;

#[test]
fn a_text_guards_builtin_judges_the_subject_without_a_subprocess() {
    // The `exec` form answered with whatever `uphold` PATH happened to reach,
    // which is not necessarily the binary that asked. The built-in is the same
    // consultation compiled in, so the symlink the exec form needs is removed
    // here on purpose: a subprocess sneaking back in would fail on CI, where
    // no other uphold is installed.
    let root = workspace(BUILTIN_POLICY);
    std::fs::remove_file(root.join("bin/uphold")).unwrap();

    let refused = shim(
        &root,
        &["faux", "pr", "create", "-t", "Generated with Claude Code"],
    );
    assert_eq!(code(&refused), 1, "{}", stderr(&refused));
    assert!(
        !stdout(&refused).contains("faux ran:"),
        "{}",
        stdout(&refused)
    );
    // The fold names the rule that refused, not only the consultation that
    // carried it: a reader has to know which check to argue with.
    assert!(
        stderr(&refused).contains("prevent-ai-author"),
        "{}",
        stderr(&refused)
    );

    let clean = shim(&root, &["faux", "pr", "create", "-t", "An ordinary title"]);
    assert_eq!(code(&clean), 0, "{}", stderr(&clean));
    assert!(stdout(&clean).contains("faux ran:"), "{}", stdout(&clean));
}

// ── per-rule scope: the rule says when it applies ────────────────────

/// A table whose own scope never holds, and one rule that applies anyway.
/// The shape two workspaces hand-rolled an agent hook for: `public-target`
/// tables over an all-private fleet, and two rules that should read every
/// egress regardless.
const WIDER_RULE_POLICY: &str = r#"
[rule.no-published-markers]
message = "remove the marker"
builtin = "text-guards"
command.before = ["faux"]
command.scope = "always"

[rule.prevent-ai-author]
builtin = "prevent-ai-author"

[rule.prevent-ai-author.git]
hooks = ["commit-msg"]

[[shim]]
command = "faux"
match = ["pr:create"]
text_flags = ["-t", "--title", "-b", "--body"]
scope = { command = { command = "exit 1" } }
"#;

#[test]
fn a_rule_scoped_always_applies_where_the_table_stands_down() {
    let root = workspace(WIDER_RULE_POLICY);
    std::fs::remove_file(root.join("bin/uphold")).unwrap();

    let refused = shim(
        &root,
        &["faux", "pr", "create", "-t", "Generated with Claude Code"],
    );
    assert_eq!(code(&refused), 1, "{}", stderr(&refused));
    assert!(
        !stdout(&refused).contains("faux ran:"),
        "{}",
        stdout(&refused)
    );

    let clean = shim(&root, &["faux", "pr", "create", "-t", "An ordinary title"]);
    assert_eq!(code(&clean), 0, "{}", stderr(&clean));
    assert!(stdout(&clean).contains("faux ran:"), "{}", stdout(&clean));
}

/// The other direction: the table applies, one rule's own scope does not, and
/// that rule alone is stood down.
const NARROWER_RULE_POLICY: &str = r#"
[rule.no-published-markers]
message = "remove the marker"
builtin = "text-guards"
command.before = ["faux"]
command.scope = { command = { command = "exit 1" } }

[rule.prevent-ai-author]
builtin = "prevent-ai-author"

[rule.prevent-ai-author.git]
hooks = ["commit-msg"]

[[shim]]
command = "faux"
match = ["pr:create"]
text_flags = ["-t", "--title", "-b", "--body"]
scope = "always"
"#;

#[test]
fn a_rule_whose_own_scope_does_not_hold_is_stood_down_alone() {
    // The policy answered: this check does not apply to this destination.
    // The marker walks through because the ONLY rule for it stood down --
    // which is the declared behaviour, not a gap.
    let root = workspace(NARROWER_RULE_POLICY);
    std::fs::remove_file(root.join("bin/uphold")).unwrap();

    let output = shim(
        &root,
        &["faux", "pr", "create", "-t", "Generated with Claude Code"],
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"), "{}", stdout(&output));
}

// ── prose rules at the command seam ──────────────────────────────────

/// A shape rule over the body a command is about to publish.
///
/// The body reaches the checker as PROSE, which is what a pull-request body is:
/// a wrapped paragraph is unwrapped before the pattern sees it, and a fenced
/// example is an example rather than an instance.
const PROSE_POLICY: &str = r#"
[rule.no-empty-hedge]
message = "state the claim, or state what is unknown about it"
prose_regexp = '(?i)\barguably\b'
command.before = ["faux"]

[[shim]]
command = "faux"
match = ["pr:create"]
title_flags = ["-t", "--title"]
text_flags = ["-b", "--body"]
scope = "always"
"#;

#[test]
fn a_prose_rule_refuses_a_shape_in_the_body_a_command_would_publish() {
    let root = workspace(PROSE_POLICY);
    std::fs::remove_file(root.join("bin/uphold")).unwrap();

    let refused = shim(
        &root,
        &[
            "faux",
            "pr",
            "create",
            "-b",
            "The count is taken once.\n\nArguably it is the one a reader wants.\n",
        ],
    );
    assert_eq!(code(&refused), 1, "{}", stderr(&refused));
    assert!(
        !stdout(&refused).contains("faux ran:"),
        "{}",
        stdout(&refused)
    );
    let text = stderr(&refused);
    assert!(text.contains("no-empty-hedge"), "{text}");
    assert!(text.contains("text subject"), "{text}");

    // A body with no such shape publishes.
    let clean = shim(
        &root,
        &["faux", "pr", "create", "-b", "The count is taken once.\n"],
    );
    assert_eq!(code(&clean), 0, "{}", stderr(&clean));
    assert!(stdout(&clean).contains("faux ran:"), "{}", stdout(&clean));
}

/// The two properties that make this prose and not bytes, at the seam.
///
/// A sentence wrapped by whatever composed the body still matches; a shape
/// quoted inside a fence is an example of the shape and is not one.
#[test]
fn a_wrapped_body_is_read_as_prose_and_a_fenced_example_is_not_an_instance() {
    let root = workspace(PROSE_POLICY);
    std::fs::remove_file(root.join("bin/uphold")).unwrap();

    let wrapped = shim(
        &root,
        &[
            "faux",
            "pr",
            "create",
            "-b",
            "The count is\nArguably wrong.\n",
        ],
    );
    assert_eq!(code(&wrapped), 1, "{}", stderr(&wrapped));

    let fenced = shim(
        &root,
        &[
            "faux",
            "pr",
            "create",
            "-b",
            "The rule refuses this shape:\n\n```\nArguably it is right.\n```\n",
        ],
    );
    assert_eq!(code(&fenced), 0, "{}", stderr(&fenced));
    assert!(stdout(&fenced).contains("faux ran:"), "{}", stdout(&fenced));
}

/// The waiver, which is what makes a refusal over prose acceptable: the rule is
/// wrong about one sentence and the operator says so on the invocation.
#[test]
fn upholds_allow_lets_one_invocation_past_a_prose_rule() {
    let root = workspace(PROSE_POLICY);
    std::fs::remove_file(root.join("bin/uphold")).unwrap();

    let path = format!(
        "{}:{}",
        root.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args([
            "shim",
            "faux",
            "pr",
            "create",
            "-b",
            "Arguably it is right.\n",
        ])
        .current_dir(&root)
        .env("PATH", path)
        .env("UPHOLD_ALLOW", "no-empty-hedge")
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"), "{}", stdout(&output));
}

// ── pattern rules at the command seam, and the title kind ────────────

/// The release-title shape this exists for: a format rule about one subject
/// kind, refusing before anything is published.
const TITLE_POLICY: &str = r#"
[rule.release-title-is-the-tag]
message = "title a release by its tag"
require_regexp = '^v[0-9]+\.[0-9]+\.[0-9]+$'
subjects = ["title"]
command.before = ["faux release create", "faux release edit"]

[[shim]]
command = "faux"
match = ["release:create", "release:edit"]
title_flags = ["-t", "--title"]
text_flags = ["-n", "--notes"]
scope = "always"
"#;

#[test]
fn a_title_format_rule_refuses_the_title_and_only_the_title() {
    let root = workspace(TITLE_POLICY);
    std::fs::remove_file(root.join("bin/uphold")).unwrap();

    // A sentence where the tag should be: refused, naming the rule, the kind
    // and the pattern, and the command never runs.
    let refused = shim(
        &root,
        &[
            "faux",
            "release",
            "edit",
            "v1.9.0",
            "-t",
            "the seams a fleet held by hand",
        ],
    );
    assert_eq!(code(&refused), 1, "{}", stderr(&refused));
    assert!(
        !stdout(&refused).contains("faux ran:"),
        "{}",
        stdout(&refused)
    );
    assert!(
        stderr(&refused).contains("title subject"),
        "{}",
        stderr(&refused)
    );

    // The tag itself passes.
    let clean = shim(
        &root,
        &["faux", "release", "create", "v2.0.0", "-t", "v2.0.0"],
    );
    assert_eq!(code(&clean), 0, "{}", stderr(&clean));
    assert!(stdout(&clean).contains("faux ran:"), "{}", stdout(&clean));

    // And prose in the NOTES is not a title: the `subjects` filter keeps a
    // format rule about one kind away from every other.
    let notes = shim(
        &root,
        &[
            "faux",
            "release",
            "edit",
            "v1.9.0",
            "-n",
            "prose notes, full sentences",
        ],
    );
    assert_eq!(code(&notes), 0, "{}", stderr(&notes));
    assert!(stdout(&notes).contains("faux ran:"), "{}", stdout(&notes));
}

/// An empty title is a published title, and `require_regexp` is asked about it.
///
/// The skip in front of the checker loop is older than the pattern checks --
/// it was written when `exec` was the only kind, where "" is genuinely nothing
/// to hand a program. A `require_regexp` claims the subject MUST look a certain
/// way, so "" is the clearest violation it has, and skipping it made the one
/// rule that would have refused report clean instead: `-t ""` published a
/// release with no title, past a policy whose entire subject was the title.
#[test]
fn an_empty_title_does_not_walk_past_a_require_regexp() {
    let root = workspace(TITLE_POLICY);
    std::fs::remove_file(root.join("bin/uphold")).unwrap();

    let refused = shim(&root, &["faux", "release", "create", "v3.0.0", "-t", ""]);
    assert_eq!(code(&refused), 1, "{}", stderr(&refused));
    assert!(
        !stdout(&refused).contains("faux ran:"),
        "{}",
        stdout(&refused)
    );
    assert!(
        stderr(&refused).contains("title subject"),
        "{}",
        stderr(&refused)
    );

    // Whitespace is the same answer. The subject was given, and what it names
    // satisfies the pattern no better for having a space in it.
    let blank = shim(&root, &["faux", "release", "create", "v3.0.0", "-t", "   "]);
    assert_eq!(code(&blank), 1, "{}", stderr(&blank));

    // Not giving the flag at all is the case that stays untouched: no title
    // subject is collected, so no rule is asked and the command supplies its
    // own default. A rule cannot judge text that was never published.
    let absent = shim(&root, &["faux", "release", "create", "v3.0.0"]);
    assert_eq!(code(&absent), 0, "{}", stderr(&absent));
    assert!(stdout(&absent).contains("faux ran:"), "{}", stdout(&absent));
}

// ── what the shim does with the answers it collected ─────────────────

#[test]
fn a_shim_that_cannot_reach_the_real_command_does_not_exit_zero() {
    // A link is on PATH for the whole machine and outlives the command it
    // stands in front of: uninstall the real one and the link is still there.
    // The walk past ourselves then finds nothing to hand the process to, and
    // exiting 0 would be this shim reporting that a command ran when none did
    // -- the shape it exists to make impossible, arriving out of the
    // transparent half of the code.
    let root = workspace(POLICY);
    std::fs::remove_file(root.join("bin/faux")).unwrap();

    let checked = shim(&root, &["faux", "pr", "create", "-t", "An ordinary title"]);
    assert_eq!(code(&checked), 2, "{}", stderr(&checked));
    assert!(
        stderr(&checked).contains("could not find the real one on PATH"),
        "{}",
        stderr(&checked)
    );

    // And the reading that runs no checker at all lands in the same place,
    // still having said out loud that it could not tell which subcommand this
    // was. A could-not-look line followed by a silent 0 is the pair refused
    // here.
    let unclear = shim(
        &root,
        &["faux", "--fic-a", "x", "--fic-b", "y", "repo", "clone"],
    );
    assert_eq!(code(&unclear), 2, "{}", stderr(&unclear));
    assert!(
        stderr(&unclear).contains("This is not a pass."),
        "{}",
        stderr(&unclear)
    );
}

/// Two checkers over one invocation, so a bypass has something to leave alone.
const TWO_CHECKERS: &str = r#"
[rule.marker-in-the-body]
message = "remove the marker"
regexp = "Claude Code"
command.before = ["faux"]
# A pattern that names itself in the file it is declared in selects that
# file, which the load refuses. The rule is about what a command publishes.
files.exclude = ["policy/**"]

[rule.marker-again]
message = "remove the marker"
regexp = "Claude Code"
command.before = ["faux"]
files.exclude = ["policy/**"]

[[shim]]
command = "faux"
match = ["pr:create"]
text_flags = ["-t", "--title"]
scope = "always"
"#;

#[test]
fn a_bypass_switches_off_the_checker_it_names_and_no_other() {
    // UPHOLD_ALLOW names a rule, and the loop skips that rule. A bypass that
    // switched off the PASS rather than the checker would be an override
    // nobody asked for, granted by whoever typed the first rule's name.
    let root = workspace(TWO_CHECKERS);
    let path = format!(
        "{}:{}",
        root.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args([
            "shim",
            "faux",
            "pr",
            "create",
            "-t",
            "Generated with Claude Code",
        ])
        .current_dir(&root)
        .env("PATH", path)
        .env("UPHOLD_ALLOW", "marker-in-the-body")
        .output()
        .unwrap();
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("faux ran:"),
        "{}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("marker-again"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("marker-in-the-body"),
        "the bypass reached a rule it was not named for: {}",
        stderr(&output)
    );
}

/// One rule that wrote its own scope beside one that did not.
const A_SCOPE_OF_ITS_OWN: &str = r#"
[rule.stood-down]
message = "would refuse anything at all"
regexp = "."
command.before = ["faux"]
command.scope = { command = { command = "exit 1" } }
files.exclude = ["policy/**"]

[rule.marker-in-the-title]
message = "remove the marker"
regexp = "Claude Code"
command.before = ["faux"]
files.exclude = ["policy/**"]

[[shim]]
command = "faux"
match = ["pr:create"]
text_flags = ["-t", "--title"]
scope = "always"
"#;

#[test]
fn a_rule_whose_scope_does_not_hold_does_not_stand_down_the_rule_beside_it() {
    // The scope is answered per rule and memoized per predicate, not decided
    // once for the invocation. `stood-down` would refuse this title -- its
    // pattern matches anything -- so a loop that read the wrong rule's answer
    // shows up here as a refusal naming it.
    let root = workspace(A_SCOPE_OF_ITS_OWN);
    let output = shim(
        &root,
        &["faux", "pr", "create", "-t", "Generated with Claude Code"],
    );
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("marker-in-the-title"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("stood-down"),
        "a rule whose own scope does not hold was consulted anyway: {}",
        stderr(&output)
    );
}

/// A rule about one subject kind, beside one about every kind.
const ONE_KIND_AND_EVERY_KIND: &str = r#"
[rule.release-title-is-the-tag]
message = "title a release by its tag"
require_regexp = '^v[0-9]+\.[0-9]+\.[0-9]+$'
subjects = ["title"]
command.before = ["faux"]

[rule.marker-anywhere]
message = "remove the marker"
regexp = "Claude Code"
command.before = ["faux"]
files.exclude = ["policy/**"]

[[shim]]
command = "faux"
match = ["release:create"]
title_flags = ["-t", "--title"]
text_flags = ["-n", "--notes"]
scope = "always"
"#;

#[test]
fn a_rule_about_one_kind_is_not_asked_about_the_subject_beside_it() {
    // `subjects` narrows every kind of checker the same way. Asked about the
    // notes, a title-shape rule refuses prose that was never a title and was
    // never going to look like a tag -- so the filter is what keeps a format
    // rule from becoming a rule about everything the invocation carries.
    let root = workspace(ONE_KIND_AND_EVERY_KIND);
    let output = shim(
        &root,
        &[
            "faux",
            "release",
            "create",
            "-t",
            "v1.2.3",
            "-n",
            "Generated with Claude Code",
        ],
    );
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("marker-anywhere"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("release-title-is-the-tag"),
        "a title rule was asked about the notes: {}",
        stderr(&output)
    );
}

#[test]
fn an_empty_subject_is_not_handed_to_a_program_and_the_one_beside_it_still_is() {
    // A program handed "" on stdin is being asked to judge text that was never
    // published, so the skip stands for `exec` -- and it must not take the
    // rest of the invocation with it. The body here is a marker, and a walker
    // that stopped at the empty title would publish it.
    let root = workspace(
        r#"
[rule.no-published-markers]
message = "remove the marker"
exec = "uphold guard --text -"

[rule.no-published-markers.command]
before = ["faux"]

[rule.prevent-ai-author]
builtin = "prevent-ai-author"

[rule.prevent-ai-author.git]
hooks = ["commit-msg"]

[[shim]]
command = "faux"
match = ["pr:create"]
title_flags = ["-t"]
text_flags = ["-b"]
scope = "always"
"#,
    );
    let output = shim(
        &root,
        &[
            "faux",
            "pr",
            "create",
            "-t",
            "",
            "-b",
            "Generated with Claude Code",
        ],
    );
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("faux ran:"),
        "{}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("refused a text subject"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("refused a title subject"),
        "an empty title was handed to a program: {}",
        stderr(&output)
    );
}

/// A `git`-shaped shim: positional refs rather than flag values.
const REF_POLICY: &str = r#"
[rule.no-customer-in-a-branch-name]
message = "name a branch for the work, not the customer"
regexp = "acme-outage"
subjects = ["ref"]
command.before = ["faux"]
files.exclude = ["policy/**"]

[[shim]]
command = "faux"
match = ["push:*"]
collect = "git-refs"
scope = "always"
"#;

#[test]
fn a_push_with_no_refspec_still_names_the_branch_it_is_publishing() {
    // With no refspec git pushes the current branch, so the name going out
    // appears nowhere in argv. Collecting only what was typed leaves the one
    // string this shim is standing in front of unread -- and it goes to the
    // ref list, the pull request the forge suggests, and every notification.
    let root = workspace(REF_POLICY);
    Command::new(support::real_git())
        .args(["checkout", "-q", "-b", "fix/acme-outage"])
        .current_dir(&root)
        .stdout(Stdio::null())
        .status()
        .unwrap();

    let refused = shim(&root, &["faux", "push", "origin"]);
    assert_eq!(code(&refused), 1, "{}", stderr(&refused));
    assert!(
        !stdout(&refused).contains("faux ran:"),
        "{}",
        stdout(&refused)
    );
    assert!(
        stderr(&refused).contains("ref subject"),
        "{}",
        stderr(&refused)
    );

    // And a name that was typed is read from the position it was typed in,
    // rather than from the branch this checkout happens to be on.
    let clean = shim(&root, &["faux", "push", "origin", "topic"]);
    assert_eq!(code(&clean), 0, "{}", stderr(&clean));
    assert!(stdout(&clean).contains("faux ran:"), "{}", stdout(&clean));
}

// ── the destination, not the text ────────────────────────────────────

/// A checker that judges WHERE an invocation publishes rather than what.
///
/// Every other policy in this file asks whether the text is safe. This one asks
/// whether the destination is a repository this workspace owns, which nothing
/// at this seam asked until it existed: an invocation carrying blameless prose
/// and `--repo other-owner/their-repo` satisfied every text checker and
/// published to a forge repository this workspace does not own.
///
/// `owner` is the pin, spelled with a neutral placeholder. `scope = "always"`
/// on the table, because whether a destination is yours is a fact about the
/// destination and not about its visibility.
const TARGET_POLICY: &str = r#"
[rule.unowned-forge-target]
builtin = "prevent-unowned-target"
owner = "example-user"
command.before = ["faux"]

[[shim]]
command = "faux"
match = ["issue:create"]
text_flags = ["-b", "--body"]
target_flags = ["-R", "--repo"]
target = "forge-repo"
scope = "always"
"#;

/// `TARGET_POLICY` with extra lines on the rule, or with the pin taken off.
fn target_policy(fields: &str) -> String {
    TARGET_POLICY.replace(
        "owner = \"example-user\"\n",
        &format!("owner = \"example-user\"\n{fields}"),
    )
}

#[test]
fn a_destination_this_workspace_does_not_own_is_refused_and_the_command_never_runs() {
    // The gap this closes. The body is ordinary prose -- no marker, no host
    // name, nothing a text guard would say a word about -- and it was about to
    // be published on somebody else's repository.
    let root = workspace(TARGET_POLICY);
    let output = shim(
        &root,
        &[
            "faux",
            "issue",
            "create",
            "--repo",
            "other-owner/their-repo",
            "-b",
            "An ordinary sentence about an ordinary thing.",
        ],
    );
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("faux ran:"),
        "{}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("other-owner/their-repo"),
        "{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("pinned to example-user"),
        "{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("Nothing was published"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_destination_under_this_workspaces_own_owner_passes_and_the_command_runs() {
    // The half that is easy to lose: a destination guard that refuses
    // everything has broken the command it was standing in front of.
    let root = workspace(TARGET_POLICY);
    let output = shim(
        &root,
        &[
            "faux",
            "issue",
            "create",
            "-R",
            "example-user/widget",
            "-b",
            "An ordinary sentence.",
        ],
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"), "{}", stdout(&output));
}

#[test]
fn allowed_owners_admits_a_named_other_owner() {
    let root = workspace(&target_policy("allowed_owners = [\"other-owner\"]\n"));
    let admitted = shim(
        &root,
        &[
            "faux",
            "issue",
            "create",
            "-R",
            "other-owner/their-repo",
            "-b",
            "An ordinary sentence.",
        ],
    );
    assert_eq!(code(&admitted), 0, "{}", stderr(&admitted));
    assert!(
        stdout(&admitted).contains("faux ran:"),
        "{}",
        stdout(&admitted)
    );

    // The discriminating half: a list that admitted its one entry and
    // everything else would be an allow-list only in name.
    let refused = shim(
        &root,
        &[
            "faux",
            "issue",
            "create",
            "-R",
            "third-owner/their-repo",
            "-b",
            "An ordinary sentence.",
        ],
    );
    assert_eq!(code(&refused), 1, "{}", stderr(&refused));
    assert!(
        !stdout(&refused).contains("faux ran:"),
        "{}",
        stdout(&refused)
    );
}

#[test]
fn allowed_repos_admits_one_repository_without_widening_to_its_owner() {
    // The finer grant. An owner is a blunt unit: allowing one to let a single
    // repository through allows every repository it will ever have.
    let root = workspace(&target_policy(
        "allowed_repos = [\"other-owner/their-repo\"]\n",
    ));
    let admitted = shim(
        &root,
        &[
            "faux",
            "issue",
            "create",
            "-R",
            "other-owner/their-repo",
            "-b",
            "An ordinary sentence.",
        ],
    );
    assert_eq!(code(&admitted), 0, "{}", stderr(&admitted));

    let sibling = shim(
        &root,
        &[
            "faux",
            "issue",
            "create",
            "-R",
            "other-owner/another-repo",
            "-b",
            "An ordinary sentence.",
        ],
    );
    assert_eq!(code(&sibling), 1, "{}", stderr(&sibling));
    assert!(
        !stdout(&sibling).contains("faux ran:"),
        "{}",
        stdout(&sibling)
    );
}

#[test]
fn owner_required_with_nothing_declared_anywhere_is_exit_two_and_not_a_pass() {
    // Neither a refusal nor a pass. Nothing here says who this workspace is and
    // there is no origin to guess from, so the question was never answered --
    // and a run that could not look must not exit 0.
    let policy = TARGET_POLICY.replace("owner = \"example-user\"\n", "owner_required = true\n");
    let root = workspace(&policy);
    let output = shim(
        &root,
        &[
            "faux",
            "issue",
            "create",
            "-R",
            "other-owner/their-repo",
            "-b",
            "An ordinary sentence.",
        ],
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("faux ran:"),
        "{}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("owner_required"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_destination_that_could_not_be_resolved_is_exit_two_and_not_a_pass() {
    // The dangerous direction, and the one an unresolvable target invites: no
    // `--repo` on the command line and no remote to read one off. Reading that
    // as "nothing to refuse" would put the whole gap back, because an
    // invocation whose destination this seam could not read is exactly the one
    // that most needs asking about.
    let root = workspace(TARGET_POLICY);
    let output = shim(
        &root,
        &["faux", "issue", "create", "-b", "An ordinary sentence."],
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("faux ran:"),
        "{}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("could not look"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_target_rule_whose_own_scope_does_not_hold_is_stood_down_alone() {
    // The policy answered: this check does not apply to this invocation. The
    // unowned destination goes through because the ONLY rule for it stood down
    // -- which is the declared behaviour, not a gap, and it is the same reading
    // the text path takes.
    let root = workspace(&target_policy(
        "command.scope = { command = { command = \"exit 1\" } }\n",
    ));
    let output = shim(
        &root,
        &[
            "faux",
            "issue",
            "create",
            "-R",
            "other-owner/their-repo",
            "-b",
            "An ordinary sentence.",
        ],
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"), "{}", stdout(&output));
}
