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

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

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
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "uphold-shim-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
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

    Command::new("git")
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
fn a_body_typed_into_an_editor_is_said_to_be_unchecked_rather_than_passed() {
    // What gets typed there has not been written yet, so there is nothing to
    // hand a checker. A shim that says nothing here reports a pass over text it
    // never saw.
    let root = workspace(POLICY);
    let output = shim(&root, &["faux", "pr", "create"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("composed in an editor"),
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
