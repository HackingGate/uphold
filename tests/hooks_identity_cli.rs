//! `uphold hooks --identity` -- the question no single repository can answer.
//!
//! A forked hook declaration is byte-perfect in every repository that holds it.
//! Nothing inside a tree can report one, which is why these fixtures come in
//! pairs: the finding exists only in the comparison.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// A workspace of repositories, since one repository is not a fixture here.
fn workspace() -> PathBuf {
    let root = support::scratch("identity");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

/// One repository, with a `.pre-commit-config.yaml` and nothing else.
fn repository(workspace: &Path, name: &str, config: &str) -> PathBuf {
    let root = workspace.join(name);
    std::fs::create_dir_all(&root).unwrap();
    let status = Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    std::fs::write(root.join(".pre-commit-config.yaml"), config).unwrap();
    root
}

fn identity(from: &Path, repositories: &[&Path]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
    command.args(["hooks", "--identity"]);
    for repository in repositories {
        command.arg(repository);
    }
    command
        .current_dir(from)
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

const PINNED: &str = "repos:\n  - repo: https://github.com/astral-sh/ruff-pre-commit\n    rev: v0.1.0\n    hooks:\n      - id: ruff-check\n";

#[test]
fn two_repositories_declaring_the_same_hook_the_same_way_agree() {
    let workspace = workspace();
    let one = repository(&workspace, "one", PINNED);
    let two = repository(&workspace, "two", PINNED);

    let output = identity(&workspace, &[&one, &two]);
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains("every declaration agrees"),
        "{}",
        text(&output)
    );
}

#[test]
fn one_id_declared_two_ways_is_a_fork_and_says_which_way_each_wrote_it() {
    let workspace = workspace();
    let one = repository(&workspace, "one", PINNED);
    let two = repository(
        &workspace,
        "two",
        "repos:\n  - repo: https://github.com/astral-sh/ruff-pre-commit\n    rev: v0.1.0\n    hooks:\n      - id: ruff-check\n        args: [--fix]\n",
    );

    let output = identity(&workspace, &[&one, &two]);
    assert_eq!(code(&output), 1, "{}", text(&output));
    let report = text(&output);
    assert!(report.contains("forked: `ruff-check`"), "{report}");
    // The bodies, so the reader does not have to open both files to find out
    // what the difference is.
    assert!(report.contains("--fix"), "{report}");
    assert!(report.contains("one"), "{report}");
    assert!(report.contains("two"), "{report}");
}

#[test]
fn one_id_at_two_revisions_is_a_different_finding_from_a_fork() {
    // Every repository is running the check; they are running different
    // versions of it. Calling that a fork would send the reader to diff two
    // declarations that are identical.
    let workspace = workspace();
    let one = repository(&workspace, "one", PINNED);
    let two = repository(&workspace, "two", &PINNED.replace("v0.1.0", "v0.2.0"));

    let output = identity(&workspace, &[&one, &two]);
    assert_eq!(code(&output), 1, "{}", text(&output));
    let report = text(&output);
    assert!(report.contains("pinned apart: `ruff-check`"), "{report}");
    assert!(report.contains("v0.1.0"), "{report}");
    assert!(report.contains("v0.2.0"), "{report}");
    assert!(!report.contains("forked:"), "{report}");
}

#[test]
fn an_id_one_repository_alone_declares_is_its_own_business() {
    // Reporting every id somebody has and the others do not turns the answer
    // into a list nobody reads, which is the failure this whole tool is about.
    let workspace = workspace();
    let one = repository(&workspace, "one", PINNED);
    let two = repository(
        &workspace,
        "two",
        "repos:\n  - repo: https://github.com/astral-sh/ruff-pre-commit\n    rev: v0.1.0\n    hooks:\n      - id: ruff-check\n      - id: ruff-format\n",
    );

    let output = identity(&workspace, &[&one, &two]);
    let report = text(&output);
    assert!(!report.contains("absent: `ruff-format`"), "{report}");
}

#[test]
fn an_id_most_of_the_set_declares_and_one_lacks_is_reported() {
    let workspace = workspace();
    let one = repository(&workspace, "one", PINNED);
    let two = repository(&workspace, "two", PINNED);
    let three = repository(
        &workspace,
        "three",
        "repos:\n  - repo: https://github.com/astral-sh/ruff-pre-commit\n    rev: v0.1.0\n    hooks:\n      - id: ruff-format\n",
    );

    let output = identity(&workspace, &[&one, &two, &three]);
    assert_eq!(code(&output), 1, "{}", text(&output));
    let report = text(&output);
    assert!(report.contains("absent: `ruff-check`"), "{report}");
    assert!(report.contains("not in three"), "{report}");
}

/// A waiver file in the repository the command is run FROM.
fn waivers(root: &Path, text: &str) {
    std::fs::create_dir_all(root.join("policy")).unwrap();
    std::fs::write(
        root.join("policy/principles.toml"),
        "[rule.x]\nregexp = 'zzz'\nmessage = \"no\"\nfiles.include = [\".\"]\n",
    )
    .unwrap();
    std::fs::write(root.join("policy/hooks.toml"), text).unwrap();
    let status = Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn a_waiver_silences_the_finding_it_names_and_nothing_else() {
    let workspace = workspace();
    let from = workspace.join("from");
    std::fs::create_dir_all(&from).unwrap();
    waivers(
        &from,
        "[[waive]]\nid = \"ruff-check\"\nfindings = [\"forked\"]\nreason = \"two answers about two languages\"\n",
    );
    let one = repository(&workspace, "one", PINNED);
    let two = repository(
        &workspace,
        "two",
        "repos:\n  - repo: https://github.com/astral-sh/ruff-pre-commit\n    rev: v0.2.0\n    hooks:\n      - id: ruff-check\n        args: [--fix]\n",
    );

    let output = identity(&from, &[&one, &two]);
    let report = text(&output);
    assert!(!report.contains("forked:"), "{report}");
    // The revision finding is a different one and was not waived.
    assert!(report.contains("pinned apart"), "{report}");
    assert_eq!(code(&output), 1, "{report}");
}

#[test]
fn a_waiver_that_matches_nothing_is_reported_rather_than_kept() {
    // An exemption that no longer describes the fleet reads as a decision that
    // is doing something while doing nothing, and it will keep reading that way
    // after the divergence it named is gone.
    let workspace = workspace();
    let from = workspace.join("from");
    std::fs::create_dir_all(&from).unwrap();
    waivers(
        &from,
        "[[waive]]\nid = \"a-hook-nobody-has\"\nreason = \"settled last year\"\n",
    );
    let one = repository(&workspace, "one", PINNED);
    let two = repository(&workspace, "two", PINNED);

    let output = identity(&from, &[&one, &two]);
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains("no longer describe this fleet"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_waiver_with_no_reason_is_refused() {
    let workspace = workspace();
    let from = workspace.join("from");
    std::fs::create_dir_all(&from).unwrap();
    waivers(&from, "[[waive]]\nid = \"ruff-check\"\nreason = \"\"\n");
    let one = repository(&workspace, "one", PINNED);
    let two = repository(&workspace, "two", PINNED);

    let output = identity(&from, &[&one, &two]);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("nobody's name on it"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_waiver_naming_a_finding_that_does_not_exist_is_refused() {
    let workspace = workspace();
    let from = workspace.join("from");
    std::fs::create_dir_all(&from).unwrap();
    waivers(
        &from,
        "[[waive]]\nid = \"ruff-check\"\nfindings = [\"drifted\"]\nreason = \"a typo for forked\"\n",
    );
    let one = repository(&workspace, "one", PINNED);
    let two = repository(&workspace, "two", PINNED);

    let output = identity(&from, &[&one, &two]);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("waives nothing"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_directory_that_is_not_a_repository_is_could_not_look() {
    // Not "declares nothing". The second is a measurement, and it is the one
    // that reports a fleet in agreement over a directory nobody read.
    let workspace = workspace();
    let one = repository(&workspace, "one", PINNED);
    let empty = workspace.join("not-a-repo");
    std::fs::create_dir_all(&empty).unwrap();

    let output = identity(&workspace, &[&one, &empty]);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("could not be read"),
        "{}",
        text(&output)
    );
}

#[test]
fn one_repository_is_not_a_comparison() {
    let workspace = workspace();
    let one = repository(&workspace, "one", PINNED);

    let output = identity(&workspace, &[&one]);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(text(&output).contains("at least"), "{}", text(&output));
}

#[test]
fn a_lefthook_command_under_two_hooks_is_two_declarations_not_a_fork() {
    // The same command name under `pre-commit` and under `pre-push` is two
    // declarations. Reading them as one made a repository that declares a guard
    // at five stages report as five repositories disagreeing with each other.
    let workspace = workspace();
    let one = workspace.join("one");
    std::fs::create_dir_all(&one).unwrap();
    let status = Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(&one)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    std::fs::write(
        one.join("lefthook.yml"),
        "pre-commit:\n  commands:\n    guards:\n      run: uphold guard --stage pre-commit\npre-push:\n  commands:\n    guards:\n      run: uphold guard --stage pre-push\n",
    )
    .unwrap();
    let two = repository(&workspace, "two", PINNED);

    let output = identity(&workspace, &[&one, &two]);
    let report = text(&output);
    assert!(!report.contains("forked: `guards`"), "{report}");
}
