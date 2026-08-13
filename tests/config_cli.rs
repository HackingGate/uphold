//! CLI-level tests for the load-time refusals in `config::validate`.
//!
//! The unit tests beside `config::load` call the loader directly, which proves
//! the loader refuses and proves nothing about whether anything reaches the
//! loader. Every refusal here exists to stop a seam from running with nothing
//! checked, so the fact under test is the seam's: `uphold shim` must die on a
//! policy that declares a shim no checker names rather than exec through to the
//! command, and a rule whose only declared place is one no seam reads must stop
//! the binary at whichever entry point loaded it.
//!
//! That is the half a direct call to `load` cannot see. A future entry point
//! that skipped `config::load`, or a `shim_command` that treated a policy error
//! as "nothing to stand in front of this" and exec'd anyway, would leave every
//! unit test green while the command ran unchecked -- which is the exact shape
//! these refusals were written to make impossible.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A repository whose policy is exactly `policy`, with a stub `faux` on PATH.
///
/// The stub is what makes the shim cases falsifiable. A refusal that arrives as
/// a non-zero exit proves little on its own -- the command could have run and
/// failed -- so the stub announces itself on stdout, and "the command did not
/// run" is then something a test can assert rather than assume.
fn workspace(policy: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "uphold-config-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    std::fs::create_dir_all(root.join("bin")).unwrap();
    std::fs::write(root.join("policy/principles.toml"), policy).unwrap();

    // The checker in the accepted policy below is this binary consulting
    // itself, so it has to be on PATH under its own name for the multicall
    // entry to dispatch it.
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), root.join("bin/uphold")).unwrap();

    let stub = root.join("bin/faux");
    std::fs::write(&stub, "#!/bin/sh\necho \"faux ran: $*\"\n").unwrap();
    let mut permissions = std::fs::metadata(&stub).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(&stub, permissions).unwrap();

    // `discover` walks up until a repository root, so the fixture has to be
    // one; otherwise it climbs out of the temporary directory and finds
    // whatever policy the machine running the suite happens to carry.
    Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(&root)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    root
}

fn uphold(root: &Path, args: &[&str]) -> Output {
    let path = format!(
        "{}:{}",
        root.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    Command::new(env!("CARGO_BIN_EXE_uphold"))
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

/// The policy every accepted case here is a variation of: one checker, one
/// shim, each naming the other.
const PAIRED: &str = r#"
[rule.no-published-markers]
message = "remove the marker"
exec = "uphold guard --text -"

[rule.no-published-markers.command]
before = ["faux"]

[[shim]]
command = "faux"
match = ["pr:create"]
text_flags = ["-t", "--title"]
scope = "always"
"#;

/// `command.before` on a check no shim consults, refused by the real binary.
///
/// `shim::run` filters the rules it consults to `exec` checkers and
/// text-capable built-ins, so a built-in that reads a push range and declares
/// `command.before` and nothing else is consulted by nothing and runs nowhere
/// -- and the "nothing says where it runs" refusal is satisfied by the very
/// field that cannot be used, so the check meant to catch a rule with no place
/// is the one this rule walks past.
#[test]
fn a_command_place_no_seam_reads_stops_the_binary() {
    let root = workspace(
        r#"
        [rule.push]
        builtin = "prevent-public-push"

        [rule.push.command]
        before = ["faux"]

        [[shim]]
        command = "faux"
        match = ["pr:create"]
        text_flags = ["-t"]
        scope = "always"
        "#,
    );
    // Asked of an entry point that only loads and prints, so what fails is the
    // load and not a check downstream of it.
    let output = uphold(&root, &["rules", "--effective"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("read by nothing"), "{text}");
    assert!(text.contains("push"), "{text}");
    // The refusal names the seams the rule COULD have declared, so the cure is
    // in the message rather than in a document the reader has to go and find.
    assert!(text.contains("git.hooks"), "{text}");
}

/// The same rule, and the seam it would have run at is silent about it.
///
/// This is the half the loader exists for. `uphold shim` collects the subjects
/// of the invocation, consults the rules that stand in front of the command,
/// finds none -- because the built-in is not one `shim::run` consults -- and
/// execs. Nothing on that path can report the rule, so the only place it can be
/// said is at load, and this asserts the binary says it there instead of
/// running the command.
#[test]
fn the_shim_refuses_rather_than_running_a_command_that_rule_could_not_guard() {
    let root = workspace(
        r#"
        [rule.push]
        builtin = "prevent-public-push"

        [rule.push.command]
        before = ["faux"]

        [[shim]]
        command = "faux"
        match = ["pr:create"]
        text_flags = ["-t"]
        scope = "always"
        "#,
    );
    let output = uphold(&root, &["shim", "faux", "pr", "create", "-t", "A title"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("faux ran:"),
        "the command ran under a policy that could not be loaded: {}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("read by nothing"),
        "{}",
        stderr(&output)
    );
}

/// A `[[shim]]` no checker names, refused before the command it fronts runs.
///
/// The failure it prevents is the worst shape this tool has: the shim collects
/// the pull-request body, iterates an empty list of checkers, refuses nothing
/// and execs -- a publication that passed because nothing looked at it,
/// reported as a pass. So the assertion is not merely that the exit is 2 but
/// that the stub never printed.
#[test]
fn a_shim_named_by_no_checker_never_reaches_the_command() {
    let root = workspace(
        r#"
        [[shim]]
        command = "faux"
        match = ["pr:create"]
        text_flags = ["-t"]
        scope = "always"
        "#,
    );
    let output = uphold(&root, &["shim", "faux", "pr", "create", "-t", "A title"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("faux ran:"),
        "an unchecked invocation reached the command: {}",
        stdout(&output)
    );
    let text = stderr(&output);
    assert!(text.contains("named by no checker"), "{text}");
    assert!(text.contains("faux"), "{text}");
}

/// And the mirror: the shim is the only thing that invokes a checker, so a
/// `command.before` naming a command no `[[shim]]` declares is a rule that runs
/// nowhere -- which reads exactly like a rule that passes.
#[test]
fn a_checker_naming_a_command_no_shim_declares_stops_the_binary() {
    let root = workspace(
        r#"
        [rule.no-published-markers]
        message = "remove the marker"
        exec = "uphold guard --text -"

        [rule.no-published-markers.command]
        before = ["faux", "glab mr create"]

        [[shim]]
        command = "faux"
        match = ["pr:create"]
        text_flags = ["-t"]
        scope = "always"
        "#,
    );
    let output = uphold(&root, &["rules", "--effective"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("glab"), "{text}");
    assert!(text.contains("no `[[shim]]` declares"), "{text}");
}

/// The control, without which every assertion above passes for a policy that
/// simply does not parse.
///
/// A paired checker and shim loads, and the shim runs the command it fronts --
/// the half that is easy to lose, because a loader that refused everything
/// would satisfy each refusal test in this file.
#[test]
fn a_checker_and_the_shim_that_invokes_it_load_and_run() {
    let root = workspace(PAIRED);
    let listed = uphold(&root, &["rules", "--effective"]);
    assert_eq!(code(&listed), 0, "{}", stderr(&listed));
    assert!(
        stdout(&listed).contains("no-published-markers"),
        "{}",
        stdout(&listed)
    );

    let ran = uphold(&root, &["shim", "faux", "pr", "create", "-t", "A title"]);
    assert_eq!(code(&ran), 0, "{}", stderr(&ran));
    assert!(stdout(&ran).contains("faux ran:"), "{}", stdout(&ran));
}
