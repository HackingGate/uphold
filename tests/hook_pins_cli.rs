//! CLI-level tests for `no-stale-hook-pins`.
//!
//! Driven through the binary rather than through `pins::stale`, because the
//! thing under test in most of these is the EXIT CODE, and the exit code is the
//! one part of a guard a caller reads. A pin nobody could check reported itself
//! on stderr and exited 0 for exactly as long as nothing asserted on the number.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const POLICY: &str = r#"
[rule.no-stale-hook-pins]
builtin = "no-stale-hook-pins"

[rule.no-stale-hook-pins.git]
hooks = ["pre-push", "manual"]
"#;

fn repository() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "uphold-pins-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    std::fs::write(root.join("policy/principles.toml"), POLICY).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.name", "Test"]);
    git(&root, &["config", "user.email", "test@example.test"]);
    root
}

/// A local repository standing in for the upstream, so these need no network
/// and no forge. `git ls-remote` reads a path exactly as it reads a URL.
fn upstream(root: &Path, tags: &[&str]) -> String {
    let upstream = root.join("upstream");
    std::fs::create_dir_all(&upstream).unwrap();
    git(&upstream, &["init", "-q", "-b", "main"]);
    git(&upstream, &["config", "user.name", "Test"]);
    git(&upstream, &["config", "user.email", "test@example.test"]);
    std::fs::write(upstream.join("a.txt"), "x\n").unwrap();
    git(&upstream, &["add", "-A"]);
    git(&upstream, &["commit", "-qm", "one", "--no-verify"]);
    for tag in tags {
        git(&upstream, &["tag", tag]);
    }
    upstream.to_string_lossy().into_owned()
}

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

fn guard(root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["guard", "--stage", "manual"])
        .current_dir(root)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// A pin nobody could check is not a pin that is up to date.
///
/// `remote_refs` returns `Ok(None)` for a remote it could not reach and its
/// comment says that is never a pass -- and then the caller made it one. The
/// pin went into `unchecked`, `unchecked` was printed and dropped, and
/// `guard::run` counted the guard among the ones that passed and exited 0. A
/// network that was down, a token that had expired and a remote that had been
/// renamed all read as a current pin.
#[test]
fn a_pin_whose_remote_cannot_be_reached_is_could_not_look_and_not_a_pass() {
    let root = repository();
    let nowhere = root.join("no-such-upstream");
    write(
        &root,
        ".pre-commit-config.yaml",
        &format!(
            "repos:\n  - repo: {}\n    rev: v1.0.0\n    hooks:\n      - id: x\n",
            nowhere.display()
        ),
    );

    let output = guard(&root);
    let report = text(&output);
    assert_eq!(
        output.status.code().unwrap(),
        2,
        "could not look is exit 2:\n{report}"
    );
    assert!(report.contains("could not be checked"), "{report}");
    assert!(report.contains("Could not look is not a pass"), "{report}");
}

/// The documented lefthook-only install path is not a broken repository.
///
/// `read_pins` opened `root/.pre-commit-config.yaml` unconditionally and
/// `read_to_string` turns ENOENT into a `Fatal`, so this guard exited 2 for
/// every consumer who installed the way the documentation tells them to.
#[test]
fn a_tree_with_no_pre_commit_config_passes_and_says_why() {
    let root = repository();
    let output = guard(&root);
    let report = text(&output);
    assert_eq!(output.status.code().unwrap(), 0, "{report}");
    assert!(report.contains(".pre-commit-config.yaml"), "{report}");
    assert!(report.contains("lefthook-only"), "{report}");
}

/// The one version a lefthook consumer pins, which nothing was reading.
///
/// A `remotes:` entry is a pin in every sense this guard means: it names
/// another repository's hook definitions and a ref to fetch them at. It was
/// invisible here and there is no Dependabot ecosystem for it either, so it was
/// the single pin in a lefthook tree with nobody watching it.
#[test]
fn a_lefthook_remote_is_checked_like_any_other_pin() {
    let root = repository();
    let url = upstream(&root, &["v1.0.0", "v2.0.0"]);
    write(
        &root,
        "lefthook.yml",
        &format!(
            "remotes:\n  - git_url: {url}\n    ref: v1.0.0\n    configs:\n      - lefthook.yml\n"
        ),
    );

    let output = guard(&root);
    let report = text(&output);
    assert_eq!(output.status.code().unwrap(), 1, "{report}");
    assert!(report.contains("v2.0.0 is newer"), "{report}");
    assert!(report.contains("lefthook.yml"), "{report}");
}

/// A pin in `sub/` is a pin a run touches.
///
/// The retired upstream read every `.pre-commit-config.yaml` in the work tree
/// and this read only the root one, so a monorepo with a config per package had
/// exactly one of them checked -- and which one depended on where the file
/// happened to sit.
#[test]
fn a_config_below_the_root_is_checked_too() {
    let root = repository();
    let url = upstream(&root, &["v1.0.0", "v2.0.0"]);
    write(
        &root,
        ".pre-commit-config.yaml",
        &format!("repos:\n  - repo: {url}\n    rev: v2.0.0\n    hooks:\n      - id: x\n"),
    );
    write(
        &root,
        "sub/.pre-commit-config.yaml",
        &format!("repos:\n  - repo: {url}\n    rev: v1.0.0\n    hooks:\n      - id: y\n"),
    );

    let output = guard(&root);
    let report = text(&output);
    assert_eq!(
        output.status.code().unwrap(),
        1,
        "the root config is current and the nested one is not:\n{report}"
    );
    assert!(report.contains("v2.0.0 is newer"), "{report}");
    assert!(
        report.contains("sub/.pre-commit-config.yaml"),
        "the report has to name the file holding the stale pin:\n{report}"
    );
}

/// Zero pins and "this is not a file pins can be read out of" are different
/// answers, and only one of them is something a reader can act on.
#[test]
fn a_config_with_no_repos_key_is_unreadable_rather_than_empty() {
    let root = repository();
    write(
        &root,
        ".pre-commit-config.yaml",
        "default_stages: [commit]\n",
    );

    let output = guard(&root);
    let report = text(&output);
    assert_eq!(output.status.code().unwrap(), 2, "{report}");
    assert!(report.contains("`repos:`"), "{report}");
}

/// The behaviour every change above had to leave alone.
#[test]
fn a_current_pin_still_passes() {
    let root = repository();
    let url = upstream(&root, &["v1.0.0"]);
    write(
        &root,
        ".pre-commit-config.yaml",
        &format!("repos:\n  - repo: {url}\n    rev: v1.0.0\n    hooks:\n      - id: x\n"),
    );
    let output = guard(&root);
    assert_eq!(output.status.code().unwrap(), 0, "{}", text(&output));
}
