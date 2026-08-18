//! CLI-level tests for `uphold audit --for-publication`.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A fictional owner, deliberately. A fixture that hardcoded the real one would
/// write a private organisation's name into the tree -- a surface a flip
/// republishes -- which is the exact thing the code under test refuses. Caught
/// by running that code over this repository.
///
/// The owners come from a file OUTSIDE the repository, for the reason the audit
/// reports when they do not: a list of names that must not be published cannot
/// live in a file that is about to be published -- and that includes a command
/// string with the name written into it, which travels with the policy exactly
/// as a list would.
fn policy_reading_owners_from(outside: &Path) -> String {
    std::fs::write(outside, "PrivateOrg\n").unwrap();
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
    )
}

/// The same rule with the names written into it, which is right for a
/// repository staying private and is itself a finding for one being published.
const POLICY_WITH_LITERAL_NAMES: &str = r#"
[rule.no-private-repo-names]
builtin = "no-private-repo-names"
visibility = "private"
private_owners = ["PrivateOrg"]

[rule.no-private-repo-names.git]
hooks = ["commit-msg"]
"#;

/// A repository whose private-owner list lives outside it.
fn with_outside_owners() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let outside = support::run_root().join(format!(
        "audit-owners-{}.txt",
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    repository(&policy_reading_owners_from(&outside))
}

fn repository(policy: &str) -> PathBuf {
    let root = support::scratch("audit");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    std::fs::write(root.join("policy/principles.toml"), policy).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.name", "Test"]);
    git(&root, &["config", "user.email", "test@example.test"]);
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

/// The fixtures live in a temp directory with no GitHub remote, so the forge
/// half of the audit fails fast and locally. That is not a gap in the test --
/// the surfaces the audit cannot reach are themselves a thing it has to report,
/// and this exercises that path without a network or a logged-in account.
fn audit(root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["audit", "--for-publication"])
        .current_dir(root)
        .output()
        .unwrap()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn a_name_a_flip_would_republish_is_found_in_the_tree() {
    let root = with_outside_owners();
    std::fs::write(root.join("NOTES.md"), "we hit this in PrivateOrg first\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "notes", "--no-verify"]);

    let output = audit(&root);
    assert_eq!(code(&output), 1, "{}", text(&output));
    let report = text(&output);
    assert!(report.contains("NOTES.md"), "{report}");
    assert!(report.contains("named on its own"), "{report}");
}

#[test]
fn the_audit_judges_under_the_visibility_the_repository_is_about_to_have() {
    // The rule says `visibility = "private"`, which is why the guard does not
    // fire today. The audit is the thing that asks the other question.
    let root = with_outside_owners();
    std::fs::write(root.join("NOTES.md"), "PrivateOrg\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "notes", "--no-verify"]);

    let guarded = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["guard", "--stage", "pre-commit"])
        .current_dir(&root)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap();
    assert_eq!(code(&guarded), 0, "the guard should be out of scope today");

    assert_eq!(code(&audit(&root)), 1, "the audit should not be");
}

#[test]
fn a_surface_that_could_not_be_read_is_never_reported_as_clean() {
    // The whole point of an audit before a flip is that it covers the surfaces
    // the flip republishes. A surface it could not read is not one of them
    // being clean, and a total printed without saying so is a coverage claim
    // nobody measured.
    let root = with_outside_owners();
    std::fs::write(root.join("NOTES.md"), "nothing to see\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "notes", "--no-verify"]);

    let output = audit(&root);
    assert_eq!(code(&output), 2, "{}", text(&output));
    let report = text(&output);
    assert!(report.contains("could NOT be read"), "{report}");
    assert!(report.contains("not the same as clean"), "{report}");
    assert!(report.contains("comment edit history"), "{report}");
}

#[test]
fn a_repository_naming_itself_is_not_a_finding() {
    // Publishing a repository publishes its own name by definition, and a
    // README saying where to clone it from is not a disclosure. Left to the
    // visibility lookup this would fire on every mention: the audit judges as
    // public while the forge still answers private for the repository itself.
    let root = with_outside_owners();
    git(
        &root,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/acme/widget.git",
        ],
    );
    std::fs::write(
        root.join("README.md"),
        "clone https://github.com/acme/widget\n",
    )
    .unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "readme", "--no-verify"]);

    let report = text(&audit(&root));
    assert!(!report.contains("acme/widget is private"), "{report}");
}

#[test]
fn a_literal_list_of_private_owners_is_itself_a_finding() {
    // The list of names that must not be published is a list of private names.
    // In a file the flip would publish, it is the disclosure the rule exists to
    // prevent, arriving through the rule.
    let root = repository(POLICY_WITH_LITERAL_NAMES);
    std::fs::write(root.join("a.txt"), "nothing to see\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);

    let output = audit(&root);
    assert_eq!(code(&output), 1, "{}", text(&output));
    assert!(
        text(&output).contains("private_owners_from"),
        "{}",
        text(&output)
    );
}

#[test]
fn without_a_private_name_rule_the_audit_refuses_to_guess() {
    let root = repository("[rule.no-merge-commit]\nbuiltin = \"no-merge-commit\"\n\n[rule.no-merge-commit.git]\nhooks = [\"pre-commit\"]\n");
    std::fs::write(root.join("a.txt"), "x\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);

    let output = audit(&root);
    assert_eq!(code(&output), 2);
    assert!(
        text(&output).contains("no rule saying what counts as a private name"),
        "{}",
        text(&output)
    );
}

/// The owner list must not depend on which `[[rule]]` comes first.
///
/// Three variants of the guard exist -- message, staged, tracked -- and usually
/// only one carries `private_owners_from`; the others say `visibility` and
/// nothing more. The audit took `rules.first()`, so its entire idea of a private
/// owner rode on the ORDER of two tables in a config file: written one way it
/// found the name, written the other way it found nothing and said the tree was
/// clean.
#[test]
fn the_owner_list_does_not_depend_on_rule_order() {
    let outside = support::run_root().join("audit-owners-order.txt");
    std::fs::write(&outside, "PrivateOrg\n").unwrap();

    // The variant WITHOUT owners written first, which is the losing order.
    let policy = format!(
        r#"
[rule.no-private-repo-names-in-files]
builtin = "no-private-repo-names-in-files"
visibility = "private"

[rule.no-private-repo-names-in-files.git]
hooks = ["manual"]

[rule.no-private-repo-names]
builtin = "no-private-repo-names"
visibility = "private"
private_owners_from = "cat {}"

[rule.no-private-repo-names.git]
hooks = ["commit-msg"]
"#,
        outside.display()
    );

    let root = repository(&policy);
    std::fs::write(root.join("a.md"), "a doc naming PrivateOrg\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "add a doc", "--no-verify"]);

    let output = audit(&root);
    assert!(
        text(&output).contains("PrivateOrg"),
        "the owner was invisible because its rule was written second:\n{}",
        text(&output)
    );
}
