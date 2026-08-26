//! CLI-level tests for `uphold hooks --install`.
//!
//! The command writes the four guard-stage hook files into a tracked directory
//! and points `core.hooksPath` at it. What is being preserved is the
//! fail-closed shape: a foreign file is refused rather than replaced, a
//! foreign `core.hooksPath` is refused rather than repointed, and the written
//! pre-push refuses a push it could not check rather than passing it.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn repository() -> PathBuf {
    let root = support::scratch("hooks-install");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    std::fs::write(
        root.join("policy/principles.toml"),
        "[rule.no-shouting]\nregexp = '^SHOUTING'\nmessage = \"quiet\"\nfiles.include = [\".\"]\n",
    )
    .unwrap();
    std::fs::write(
        root.join(".pre-commit-config.yaml"),
        "default_install_hook_types: [pre-commit, commit-msg, pre-merge-commit, pre-push]\nrepos: []\n",
    )
    .unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    root
}

fn git(root: &Path, args: &[&str]) {
    let status = Command::new(support::real_git())
        .args(args)
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

/// A stub runner on PATH, so detection and the delegates have something real.
fn stub_runner(name: &str) -> PathBuf {
    let directory = support::scratch("hooks-install-runner");
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(name);
    std::fs::write(&path, "#!/bin/sh\necho \"runner ran: $*\"\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    directory
}

fn install(root: &Path, extra: &[&str], path_extra: &Path) -> Output {
    let mut path = path_extra.as_os_str().to_owned();
    path.push(":/usr/bin:/bin");
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["hooks", "--install"])
        .args(extra)
        .env("PATH", path)
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn text(output: &Output) -> String {
    let mut all = String::from_utf8_lossy(&output.stdout).into_owned();
    all.push_str(&String::from_utf8_lossy(&output.stderr));
    all
}

fn hooks_path(root: &Path) -> String {
    let output = Command::new(support::real_git())
        .args(["config", "--get", "core.hooksPath"])
        .current_dir(root)
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

#[test]
fn the_four_files_are_written_and_core_hookspath_points_at_them() {
    let root = repository();
    let stub = stub_runner("prek");

    let output = install(&root, &[], &stub);
    assert_eq!(code(&output), 0, "{}", text(&output));
    for stage in ["pre-commit", "commit-msg", "pre-merge-commit", "pre-push"] {
        let file = root.join(".githooks").join(stage);
        assert!(file.is_file(), "{stage} was not written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111, "{stage} is not executable");
        }
    }
    assert_eq!(hooks_path(&root), ".githooks");

    // A second run is a re-install, not an error.
    let again = install(&root, &[], &stub);
    assert_eq!(code(&again), 0, "{}", text(&again));
}

#[test]
fn a_file_somebody_else_wrote_is_refused_rather_than_replaced() {
    let root = repository();
    let stub = stub_runner("prek");
    std::fs::create_dir_all(root.join(".githooks")).unwrap();
    std::fs::write(root.join(".githooks/pre-push"), "#!/bin/sh\nexit 0\n").unwrap();

    let output = install(&root, &[], &stub);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("not this command's call"),
        "{}",
        text(&output)
    );
    // And the file is untouched.
    let kept = std::fs::read_to_string(root.join(".githooks/pre-push")).unwrap();
    assert_eq!(kept, "#!/bin/sh\nexit 0\n");
}

#[test]
fn a_foreign_core_hookspath_is_refused_rather_than_repointed() {
    let root = repository();
    let stub = stub_runner("prek");
    git(&root, &["config", "core.hooksPath", "somewhere/else"]);

    let output = install(&root, &[], &stub);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("somewhere/else"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_hook_type_outside_the_four_is_refused_rather_than_switched_off() {
    let root = repository();
    std::fs::write(
        root.join(".pre-commit-config.yaml"),
        "default_install_hook_types: [pre-commit, post-checkout]\nrepos: []\n",
    )
    .unwrap();
    let stub = stub_runner("prek");

    let output = install(&root, &[], &stub);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(text(&output).contains("post-checkout"), "{}", text(&output));
}

#[test]
fn the_written_pre_push_refuses_when_uphold_is_not_on_path() {
    // The fail-closed half the file exists for: a hook that cannot answer must
    // not answer yes.
    let root = repository();
    let stub = stub_runner("prek");
    let output = install(&root, &[], &stub);
    assert_eq!(code(&output), 0, "{}", text(&output));

    let hook = root.join(".githooks/pre-push");
    let run = Command::new("sh")
        .arg(&hook)
        .args(["origin", "https://github.com/example/repo.git"])
        .current_dir(&root)
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(run.status.code().unwrap(), 2);
    assert!(
        String::from_utf8_lossy(&run.stderr).contains("refused rather than guessed at"),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn the_written_pre_push_runs_the_guard_and_then_the_runner() {
    // Both halves of the file, driven for real: a passing guard hands the same
    // ref lines to the runner; the runner stub records that it was reached.
    let root = repository();
    let stub = stub_runner("prek");
    let output = install(&root, &[], &stub);
    assert_eq!(code(&output), 0, "{}", text(&output));

    // uphold itself on PATH beside the stub runner, under its own name.
    std::fs::write(
        root.join("policy/principles.toml"),
        "[rule.no-shouting]\nregexp = '^SHOUTING'\nmessage = \"quiet\"\nfiles.include = [\".\"]\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), stub.join("uphold")).unwrap();

    let hook = root.join(".githooks/pre-push");
    let mut path = stub.as_os_str().to_owned();
    path.push(":/usr/bin:/bin");
    let run = Command::new("sh")
        .arg(&hook)
        .args(["origin", "https://github.com/example/repo.git"])
        .current_dir(&root)
        .env("PATH", path)
        .env("UPHOLD_ALLOW", "")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(run.status.code().unwrap(), 0, "{said}");
    assert!(said.contains("runner ran:"), "{said}");
}
