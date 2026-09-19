//! A fixture's `git` acts on its scratch directory, whatever the suite was run under.
//!
//! WHAT WENT WRONG. A hook runner exports `GIT_DIR`, `GIT_INDEX_FILE` and
//! friends to the hook it runs, and a pre-push hook that runs this suite hands
//! them to every fixture. `current_dir` does not win against them: the
//! fixtures' `init`, `config user.*`, `add` and `commit` reached the repository
//! whose hook was running -- a fixture commit on top of the one being pushed,
//! and a main checkout left with `core.bare = true`. `support::git_command` is
//! what strips those names, and this file is what makes dropping the strip red.
//!
//! WHY A CHILD PROCESS. The environment is process-wide and the harness runs
//! tests on parallel threads, so a poisoned `GIT_DIR` set in place would reach
//! every fixture in this binary, and setting it is unsafe in this edition
//! besides. A child has an environment of its own: the second test runs this
//! very binary on the first, under a hook runner's variables aimed at a decoy
//! repository, and then reads both repositories. Run alone, the first test is
//! the ordinary smoke test of the helper; under the second, it is the proof.
//!
//! The direct check on `get_envs` is here too, and it is the weaker half: it
//! says the helper asked for the removal, and only the child says git obeyed.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};

/// The test the child process is pointed at, by the name libtest filters on.
const INNER: &str = "a_fixture_commit_lands_in_its_own_root";

/// Where the inner test builds its repository: handed down by the outer test,
/// and a scratch directory of its own otherwise.
const ROOT_VARIABLE: &str = "UPHOLD_FIXTURE_ENV_ROOT";

fn stdout(root: &Path, args: &[&str]) -> String {
    let output = support::git_command(root).args(args).output().unwrap();
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn repository(root: &Path, file: &str, message: &str) {
    std::fs::create_dir_all(root).unwrap();
    support::git(root, &["init", "-q", "-b", "main"]);
    support::git(root, &["config", "user.name", "Test"]);
    support::git(
        root,
        &["config", "user.email", &format!("{message}@example.test")],
    );
    std::fs::write(root.join(file), "planted\n").unwrap();
    support::git(root, &["add", "-A"]);
    support::git(root, &["commit", "-q", "-m", message]);
}

#[test]
fn a_fixture_commit_lands_in_its_own_root() {
    let root = std::env::var_os(ROOT_VARIABLE)
        .map_or_else(|| support::scratch("fixture-env-root"), PathBuf::from);
    repository(&root, "planted.txt", "fixture");

    assert_eq!(stdout(&root, &["log", "--format=%s"]), "fixture");
    assert_eq!(stdout(&root, &["ls-files"]), "planted.txt");
    assert_eq!(
        stdout(&root, &["config", "--get", "user.email"]),
        "fixture@example.test"
    );
}

#[test]
fn the_helper_asks_for_every_name_a_hook_runner_exports_to_be_removed() {
    let command = support::git_command(Path::new("."));
    let removed: Vec<&std::ffi::OsStr> = command
        .get_envs()
        .filter(|(_, value)| value.is_none())
        .map(|(name, _)| name)
        .collect();
    for name in [
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_WORK_TREE",
        "GIT_PREFIX",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG_PARAMETERS",
    ] {
        assert!(
            removed.contains(&std::ffi::OsStr::new(name)),
            "{name} is inherited by a fixture's git; removed: {removed:?}"
        );
    }
}

#[test]
fn a_hook_runners_environment_does_not_reach_a_fixture() {
    let decoy = support::scratch("fixture-env-decoy");
    repository(&decoy, "decoy.txt", "decoy");
    let head = stdout(&decoy, &["rev-parse", "HEAD"]);

    let root = support::scratch("fixture-env-root");
    std::fs::create_dir_all(&root).unwrap();

    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([INNER, "--exact"])
        .env(ROOT_VARIABLE, &root)
        .env("GIT_DIR", decoy.join(".git"))
        .env("GIT_INDEX_FILE", decoy.join(".git").join("index"))
        .env("GIT_WORK_TREE", &decoy)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "the fixture did not build under a hook runner's environment:\n{}\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(
        String::from_utf8_lossy(&child.stdout).contains("1 passed"),
        "the child ran something other than the one test it was pointed at:\n{}",
        String::from_utf8_lossy(&child.stdout)
    );

    // The commit went where the fixture pointed, and nowhere else.
    assert_eq!(stdout(&root, &["log", "--format=%s"]), "fixture");
    assert_eq!(
        stdout(&decoy, &["rev-parse", "HEAD"]),
        head,
        "the decoy gained a commit"
    );
    assert_eq!(stdout(&decoy, &["log", "--format=%s"]), "decoy");
    assert_eq!(
        stdout(&decoy, &["ls-files"]),
        "decoy.txt",
        "the decoy's index was written"
    );
    assert_eq!(
        stdout(&decoy, &["status", "--porcelain"]),
        "",
        "the decoy's working tree or index was touched"
    );
    assert_eq!(
        stdout(&decoy, &["config", "--get", "user.email"]),
        "decoy@example.test",
        "the decoy's config was written"
    );
    assert_eq!(stdout(&decoy, &["config", "--get", "core.bare"]), "false");
}
