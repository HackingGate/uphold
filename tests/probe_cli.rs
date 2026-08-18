//! `uphold probe` -- driven against a runner this test controls.
//!
//! The stub on PATH is the point rather than a shortcut. What is under test is
//! the probe's own reasoning -- plant, run, clean, run, and what each pair of
//! exits MEANS -- and a real runner would make every case depend on a tool
//! installed elsewhere. The stubs here are the three answers a runner can give:
//! refuses what it should, refuses nothing, refuses everything.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// A repository with one declared hook, and a policy so the root is found.
fn repository(probes: &str) -> PathBuf {
    let root = support::scratch("probe-cli");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();

    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.name", "Test"]);
    git(&root, &["config", "user.email", "test@example.test"]);

    std::fs::write(
        root.join("policy/principles.toml"),
        "[rule.no-shouting]\nregexp = 'SHOUTING'\nmessage = \"quiet\"\nfiles.include = [\".\"]\n",
    )
    .unwrap();
    std::fs::write(
        root.join(".pre-commit-config.yaml"),
        "repos:\n  - repo: https://github.com/example/hooks\n    rev: v1.0.0\n    hooks:\n      - id: no-markers\n",
    )
    .unwrap();
    if !probes.is_empty() {
        std::fs::write(root.join("policy/hooks.toml"), probes).unwrap();
    }
    // A commit, because the probe checks out HEAD into a throwaway worktree --
    // which is the whole reason the operator's own tree is never planted in.
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);
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

/// A `prek` on PATH that answers the way this case needs.
///
/// `script` is the body: it is handed the same arguments the real runner is,
/// with the worktree as its working directory.
fn runner(script: &str) -> PathBuf {
    let directory = support::scratch("probe-runner");
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("prek");
    std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    directory
}

fn probe(root: &Path, path_extra: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
    command.arg("probe");
    if path_extra.is_some() {
        command.args(["--runner", "prek"]);
    }
    // The stub FIRST, so a real runner installed on the machine running these
    // tests cannot answer for it -- and the system directories after it,
    // because the probe shells out to `git` for the throwaway worktree and a
    // PATH holding only the stub takes git away too.
    let path = path_extra.map_or_else(
        || std::ffi::OsString::from("/nonexistent"),
        |directory| {
            let mut path = directory.as_os_str().to_owned();
            path.push(":/usr/bin:/bin");
            path
        },
    );
    command
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

const ONE_PROBE: &str = r#"
[[probe]]
id = "no-markers"
path = "sample.txt"
refuses = "MARKER\n"
allows = "clean\n"
"#;

#[test]
fn a_hook_that_refuses_its_fixture_and_accepts_a_clean_one_is_demonstrated() {
    let root = repository(ONE_PROBE);
    // The honest runner: refuses exactly what it is given to refuse.
    let stub = runner("grep -q MARKER sample.txt && exit 1\nexit 0");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains("refuses its fixture, accepts a clean one"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_hook_that_cannot_fail_is_the_finding_this_command_exists_for() {
    // The `gofmt -l` shape: it prints its findings and exits 0, so it reports
    // the same green tick as a hook that keeps finding nothing.
    let root = repository(ONE_PROBE);
    let stub = runner("echo 'found something'\nexit 0");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 1, "{}", text(&output));
    assert!(text(&output).contains("ACCEPTED"), "{}", text(&output));
}

#[test]
fn a_hook_that_refuses_everything_is_a_different_finding() {
    // Its refusal says nothing about what it was given, so a green run of it
    // proves nothing either. Reported apart from a hook that cannot fail
    // because the fix is not the same one.
    let root = repository(ONE_PROBE);
    let stub = runner("exit 1");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 1, "{}", text(&output));
    assert!(
        text(&output).contains("refused the clean fixture as well"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_probe_with_no_clean_fixture_drives_one_verdict_and_says_so() {
    let root = repository(
        "[[probe]]\nid = \"no-markers\"\npath = \"sample.txt\"\nrefuses = \"MARKER\\n\"\n",
    );
    let stub = runner("grep -q MARKER sample.txt && exit 1\nexit 0");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains("nothing here shows it accepts anything"),
        "{}",
        text(&output)
    );
}

#[test]
fn the_denominator_is_printed_beside_the_probes() {
    // "One hook was probed" means one thing beside one declaration and another
    // beside twenty.
    let root = repository(ONE_PROBE);
    std::fs::write(
        root.join(".pre-commit-config.yaml"),
        "repos:\n  - repo: https://github.com/example/hooks\n    rev: v1.0.0\n    hooks:\n      - id: no-markers\n      - id: something-else\n",
    )
    .unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "two", "--no-verify"]);
    let stub = runner("grep -q MARKER sample.txt && exit 1\nexit 0");

    let output = probe(&root, Some(&stub));
    assert!(
        text(&output).contains("1 declared hook(s) have no probe"),
        "{}",
        text(&output)
    );
    assert!(
        text(&output).contains("something-else"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_probe_naming_a_hook_nothing_declares_is_refused() {
    // It would drive nothing while reading as though that hook had been
    // demonstrated, which is the same failure a `disabled_rules` entry naming
    // nothing has.
    let root = repository(
        "[[probe]]\nid = \"a-hook-nobody-declares\"\npath = \"sample.txt\"\nrefuses = \"X\\n\"\n",
    );
    let stub = runner("exit 0");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("would drive nothing"),
        "{}",
        text(&output)
    );
}

#[test]
fn an_empty_fixture_demonstrates_nothing_and_is_refused() {
    let root =
        repository("[[probe]]\nid = \"no-markers\"\npath = \"sample.txt\"\nrefuses = \"   \"\n");
    let stub = runner("exit 0");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("demonstrates nothing"),
        "{}",
        text(&output)
    );
}

#[test]
fn no_runner_on_path_is_could_not_look_and_not_a_pass() {
    // A hook that could not be run has not been shown to refuse anything.
    let root = repository(ONE_PROBE);

    let output = probe(&root, None);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(text(&output).contains("on PATH"), "{}", text(&output));
}

#[test]
fn the_operators_own_tree_is_never_planted_in() {
    // The fixture goes into a throwaway worktree at HEAD. A probe that planted
    // it here would leave one behind the first time it was interrupted -- in a
    // tree whose hooks would then refuse the next commit for a reason nothing
    // in the tree explains.
    let root = repository(ONE_PROBE);
    let stub = runner("grep -q MARKER sample.txt && exit 1\nexit 0");

    let _ = probe(&root, Some(&stub));
    assert!(
        !root.join("sample.txt").exists(),
        "the probe left its fixture in the working tree"
    );
    let status = Command::new(support::real_git())
        .args(["status", "--porcelain"])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&status.stdout).trim().is_empty(),
        "the probe left the working tree dirty: {}",
        String::from_utf8_lossy(&status.stdout)
    );
}

#[test]
fn a_probe_run_from_inside_a_hook_does_not_borrow_that_hooks_index() {
    // Found by running this suite from inside a hook, which is where `probe`
    // is most likely to be used. A hook runner exports `GIT_INDEX_FILE` and
    // `GIT_DIR`, several of them RELATIVE to the repository the hook fired in.
    // Inherited, they point every `git` the probe runs at the wrong index: the
    // worktree could not be created at all, and where it could, the staging
    // would have gone into somebody else's index -- the same accident with none
    // of the noise.
    let root = repository(ONE_PROBE);
    let stub = runner("grep -q MARKER sample.txt && exit 1\nexit 0");

    let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
    let mut path = stub.as_os_str().to_owned();
    path.push(":/usr/bin:/bin");
    let output = command
        .args(["probe", "--runner", "prek"])
        .env("PATH", path)
        // Exactly what a hook runner leaves in the environment, relative
        // spelling and all.
        .env("GIT_INDEX_FILE", ".git/index")
        .env("GIT_DIR", ".git")
        .current_dir(&root)
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert_eq!(
        output.status.code().unwrap(),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_probe_file_carrying_waivers_is_read_by_the_probe_reader_too() {
    // The mirror of the identity test: one file, two features, and each reader
    // has to tolerate the other's table while still refusing a typo in its own.
    let root = repository(
        "[[waive]]\nid = \"no-markers\"\nfindings = [\"absent\"]\nreason = \"the hooks repository cannot pin itself\"\n\n[[probe]]\nid = \"no-markers\"\npath = \"sample.txt\"\nrefuses = \"MARKER\\n\"\nallows = \"clean\\n\"\n",
    );
    let stub = runner("grep -q MARKER sample.txt && exit 1\nexit 0");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains("refuses its fixture, accepts a clean one"),
        "{}",
        text(&output)
    );
}
