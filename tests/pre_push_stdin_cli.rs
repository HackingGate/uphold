//! What a pre-push reader does with a stdin that is open and never carries a
//! byte: the socket a coding agent's shell tool hands every command.
//!
//! git starts a pre-push hook with a pipe, so a socket never holds a ref line.
//! Reading one waits for an end of file that does not come, and the command
//! hangs at no CPU until the harness kills it, where the same run with a
//! closed stdin refuses at once. Both commands that read git's ref lines are
//! held to the closed-stdin answer.
#![cfg(unix)]
#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use wait_timeout::ChildExt;

/// Long enough for a debug build on a loaded runner to load a policy and
/// refuse; a reader blocked on the socket never gets there at all.
const DEADLINE: Duration = Duration::from_secs(60);

fn repository() -> PathBuf {
    let root = support::scratch("pre-push-stdin");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    // Git before the policy, as in guard_cli.rs: an installed shim reads the
    // policy of the directory `git init` is typed in.
    support::git(&root, &["init", "-q", "-b", "main"]);
    support::git(&root, &["config", "user.name", "Test"]);
    support::git(&root, &["config", "user.email", "test@example.test"]);
    std::fs::write(
        root.join("policy/principles.toml"),
        "[rule.prevent-unusual-unicode-in-files]\n\
         builtin = \"prevent-unusual-unicode-in-files\"\n\n\
         [rule.prevent-unusual-unicode-in-files.git]\n\
         hooks = [\"pre-push\"]\n",
    )
    .unwrap();
    std::fs::write(root.join("a.txt"), "one\n").unwrap();
    support::git(&root, &["add", "-A"]);
    support::git(&root, &["commit", "-qm", "one", "--no-verify"]);
    root
}

/// Run `uphold ARGS` with a silent socket on stdin, and return its exit code
/// and stderr. The writing end stays open until the child is done, so a child
/// that reads stdin to the end never returns.
fn on_a_silent_socket(root: &Path, args: &[&str]) -> (i32, String) {
    let (held, handed) = UnixStream::pair().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(args)
        .current_dir(root)
        .env_remove("UPHOLD_ALLOW")
        .env_remove("PRE_COMMIT_TO_REF")
        .env_remove("PRE_COMMIT_SOURCE")
        .env_remove("PRE_COMMIT_LOCAL_BRANCH")
        .stdin(Stdio::from(OwnedFd::from(handed)))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let status = child.wait_timeout(DEADLINE).unwrap();
    if status.is_none() {
        child.kill().ok();
    }
    let output = child.wait_with_output().unwrap();
    drop(held);

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        status.is_some(),
        "uphold {} still waiting on a socket after {DEADLINE:?}",
        args.join(" ")
    );
    (output.status.code().unwrap(), stderr)
}

#[test]
fn guard_at_pre_push_refuses_a_silent_socket_instead_of_waiting_on_it() {
    let root = repository();
    let (code, stderr) = on_a_silent_socket(&root, &["guard", "--stage", "pre-push"]);
    // 2: could-not-look, the answer a closed stdin gets.
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("no ref line reached"), "{stderr}");
}

#[test]
fn supply_chain_refuses_a_silent_socket_instead_of_waiting_on_it() {
    let root = repository();
    let (code, stderr) = on_a_silent_socket(&root, &["supply-chain"]);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("no push to scan"), "{stderr}");
}
