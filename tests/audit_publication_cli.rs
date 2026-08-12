//! CLI-level tests for what `uphold audit --for-publication` COVERS.
//!
//! The sibling file, `audit_cli.rs`, tests the judgement: which names count and
//! under whose visibility. These test the other half, which is the half that
//! fails silently -- whether the surfaces a flip republishes were opened at all,
//! and whether this subcommand tells the truth about the ones it could not open.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A fictional owner, deliberately. A fixture that hardcoded the real one would
/// write a private organisation's name into the tree -- a surface a flip
/// republishes -- which is the exact thing the code under test refuses.
///
/// The owners come from a file OUTSIDE the repository, for the reason the audit
/// reports when they do not: a list of names that must not be published cannot
/// live in a file that is about to be published.
fn repository() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let serial = NEXT.fetch_add(1, Ordering::Relaxed);
    let outside = std::env::temp_dir().join(format!(
        "uphold-publication-owners-{}-{serial}.txt",
        std::process::id()
    ));
    std::fs::write(&outside, "PrivateOrg\n").unwrap();

    let root = std::env::temp_dir().join(format!(
        "uphold-publication-{}-{serial}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    std::fs::write(
        root.join("policy/principles.toml"),
        format!(
            r#"
[rule.no-private-repo-names]
builtin = "no-private-repo-names"
visibility = "private"
private_owners_from = "cat {}"

[rule.no-private-repo-names.git]
hooks = ["commit-msg"]
"#,
            outside.display()
        ),
    )
    .unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.name", "Test"]);
    git(&root, &["config", "user.email", "test@example.test"]);
    root
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

/// The fixtures live in a temp directory with no forge, so the conversation half
/// of the audit fails locally and fast. That is not a gap: the surfaces the
/// audit cannot reach are themselves a thing it has to report, and this
/// exercises that path without a network or a logged-in account.
fn audit(root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["audit", "--for-publication"])
        .current_dir(root)
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

/// A name deleted before HEAD is still published by the flip.
///
/// This is the finding the audit exists to trigger a rewrite for, and the scan
/// it was built on could not see it: `git ls-tree -r HEAD` names the tree as it
/// stands, while a visibility flip republishes every REACHABLE object. The blob
/// stays in the commit that added it, the forge serves it by sha forever, and
/// it survives the default-branch rewrite the report asks for.
#[test]
fn a_name_deleted_before_head_is_still_found() {
    let root = repository();
    std::fs::write(root.join("NOTES.md"), "we hit this in PrivateOrg first\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "notes", "--no-verify"]);
    std::fs::remove_file(root.join("NOTES.md")).unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "drop the notes", "--no-verify"]);

    let output = audit(&root);
    let report = text(&output);
    assert_eq!(
        output.status.code().unwrap(),
        1,
        "the blob is gone from HEAD and is still on the forge:\n{report}"
    );
    assert!(report.contains("NOTES.md"), "{report}");
    // Named as a blob, because that is how the reader will have to reach it: the
    // path no longer exists to open.
    assert!(report.contains("(blob "), "{report}");
}

/// One blob, read once, however many commits carry it.
///
/// Deduplicated by sha rather than by path. Keyed the other way, a file
/// untouched for forty commits was read forty times and every finding in it was
/// reported forty times, which is a report nobody finishes.
#[test]
fn an_unchanged_file_is_read_once_and_not_once_per_commit() {
    let root = repository();
    std::fs::write(root.join("KEEP.md"), "PrivateOrg\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);
    for round in ["two", "three", "four"] {
        std::fs::write(root.join("other.txt"), format!("{round}\n")).unwrap();
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-qm", round, "--no-verify"]);
    }

    let report = text(&audit(&root));
    assert_eq!(
        report.matches("KEEP.md").count(),
        1,
        "one blob, one finding:\n{report}"
    );
}

/// The caveat that is true of every run is not a surface this run failed to
/// read.
///
/// Pushed into the unreadable list it made that list non-empty on every run, so
/// this subcommand could never exit 0 and the clean arm was dead code -- while
/// the reference documentation went on describing an exit 0. The caveat still
/// has to be said; it just is not a measurement.
#[test]
fn the_standing_caveat_is_stated_without_being_counted_as_unread() {
    let root = repository();
    std::fs::write(root.join("a.txt"), "nothing to see\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);

    let report = text(&audit(&root));
    assert!(report.contains("standing caveat"), "{report}");
    assert!(report.contains("comment edit history"), "{report}");

    // Everything after the header of the measured list is what this run failed
    // to open. The caveat must not be in it.
    let (_, measured) = report.split_once("could NOT be read:").unwrap();
    assert!(
        !measured.contains("comment edit history"),
        "the standing caveat is being counted as a surface this run failed to \
         read:\n{measured}"
    );
}

/// A forge that could not be reached is still reported, with the reason.
///
/// "Could not be read" with nothing beside it is a line nobody can act on, and
/// the listing is where every conversation surface -- title, body, comments,
/// review bodies, review-thread comments -- is lost at once when it fails.
#[test]
fn a_forge_that_cannot_be_listed_is_named_with_its_reason() {
    let root = repository();
    std::fs::write(root.join("a.txt"), "nothing to see\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);

    let output = audit(&root);
    let report = text(&output);
    assert_eq!(
        output.status.code().unwrap(),
        2,
        "a surface that could not be read is never clean:\n{report}"
    );
    assert!(report.contains("could not be listed"), "{report}");
    assert!(report.contains("not the same as clean"), "{report}");
}

/// A literal owner in the SECOND variant is refused, not merely searched for.
///
/// The three `no-private-repo-names` variants carry different fields, and which
/// one a policy file lists first is not a decision anybody makes. The owner list
/// is taken off all of them; the disclosure refusal read `rules.first()` only.
/// So a name written literally into the second or third variant was handed to
/// the scan as something to look for, in a file the audit then declined to
/// object to -- the audit hunting for a name it had just been given, in the
/// place it was given it.
#[test]
fn a_literal_owner_in_a_later_variant_is_still_refused() {
    let root = repository();
    let policy = root.join("policy/principles.toml");
    let existing = std::fs::read_to_string(&policy).unwrap();
    // Appended, so the variant carrying the literal is deliberately NOT first.
    std::fs::write(
        &policy,
        format!(
            r#"{existing}
[rule.no-private-repo-names-staged]
builtin = "no-private-repo-names-staged"
visibility = "private"
private_owners = ["PrivateOrg"]

[rule.no-private-repo-names-staged.git]
hooks = ["pre-commit"]
"#
        ),
    )
    .unwrap();
    std::fs::write(root.join("a.txt"), "nothing to see\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);

    let output = audit(&root);
    let report = text(&output);
    // The refusal can only have come from the appended variant: the first one
    // carries `private_owners_from` and no literal list at all, so there is
    // nothing there to object to.
    assert!(
        report.contains("private owner(s) literally"),
        "a literal owner outside the first variant was never objected to:\n{report}"
    );
}

/// A `refs/audit/pull/*` ref the forge no longer serves is not audited.
///
/// That destination is written by this subcommand and by nothing else, so a ref
/// left by an earlier run stays until something prunes it -- including after
/// `origin` is repointed at a different repository, which is when every ref
/// under it names a pull request the current forge never had. Read unpruned,
/// those commits are reported as `would be republished`, and the reader's only
/// fix is to delete something that was never published where the report says it
/// was. It is the same defect the branch half was fixed for, on the ref set that
/// half does not cover.
#[test]
fn a_pull_ref_the_forge_no_longer_serves_is_not_audited() {
    let root = repository();
    // A real remote, because the fetch is what prunes: with no origin at all the
    // subcommand reports the surface unreadable and never walks a ref.
    let origin =
        std::env::temp_dir().join(format!("uphold-publication-origin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&origin);
    git(&root, &["init", "-q", "--bare", origin.to_str().unwrap()]);
    git(
        &root,
        &["remote", "add", "origin", origin.to_str().unwrap()],
    );

    std::fs::write(root.join("a.txt"), "nothing to see\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);
    git(&root, &["push", "-q", "origin", "main"]);

    // A commit the remote does not have, parked under the audit's own
    // destination the way a previous run against another forge would leave it.
    std::fs::write(root.join("STALE.md"), "PrivateOrg\n").unwrap();
    git(&root, &["add", "-A"]);
    git(
        &root,
        &[
            "commit",
            "-qm",
            "a pull request on some other forge",
            "--no-verify",
        ],
    );
    let stale = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&root)
        .output()
        .unwrap();
    let stale = String::from_utf8_lossy(&stale.stdout).trim().to_owned();
    git(&root, &["update-ref", "refs/audit/pull/9", &stale]);
    git(&root, &["reset", "-q", "--hard", "HEAD~1"]);

    let output = audit(&root);
    let report = text(&output);
    assert!(
        !report.contains("STALE.md") && !report.contains("some other forge"),
        "a pruned pull ref was still read as a surface this forge serves:\n{report}"
    );
}
