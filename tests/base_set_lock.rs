//! The bundled sets, committed, so a change to one is a change somebody reads.
//!
//! A set ships compiled into the binary. That is the property that makes a set
//! worth having -- a consumer cannot be running a stale copy of one -- and it
//! is also the property that makes it dangerous: a pattern edited here changes
//! what is refused in every repository that inherits the set, and the diff
//! exists in NO consuming tree. Sixty-five repositories learn about it by
//! having a commit refused.
//!
//! `policy/base/sets.lock.json` is that diff, in the one repository that can
//! review it. It is the whole of every bundled set, field for field, and this
//! test refuses a tree where it has drifted from what the binary would install.
//! Regenerate deliberately:
//!
//! ```sh
//! cargo run --quiet -- rules --sets --json > policy/base/sets.lock.json
//! ```
//!
//! The second test is the constraint that has to be real before a bundled set
//! is allowed to carry a guard: a set declares the hook stages it may install,
//! and a rule reaching past that ceiling is refused at load. This asserts the
//! refusal happens rather than trusting that every future set author reads the
//! comment above the field.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn uphold(directory: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(args)
        .current_dir(directory)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn the_committed_lock_is_what_this_binary_would_install() {
    let root = manifest();
    let output = uphold(&root, &["rules", "--sets", "--json"]);
    assert_eq!(
        output.status.code().unwrap(),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let live = String::from_utf8(output.stdout).unwrap();

    let path = root.join("policy/base/sets.lock.json");
    let committed = std::fs::read_to_string(&path).unwrap();

    assert_eq!(
        committed.trim_end(),
        live.trim_end(),
        "policy/base/sets.lock.json has drifted from the bundled sets. A set changing shape \
         with no diff in this repository is the one thing the lock exists to prevent, so read \
         the difference before regenerating it:\n\n  \
         cargo run --quiet -- rules --sets --json > policy/base/sets.lock.json\n"
    );
}

#[test]
fn a_set_may_not_install_a_hook_its_header_does_not_admit() {
    // The constraint stated as a risk to hold in the fleet audit, made
    // mechanical: "a new guard gets a new set name rather than joining an
    // existing one". A set whose header admits no stage cannot acquire a guard
    // at all, and one that admits `manual` cannot quietly acquire a pre-commit
    // gate -- widening the ceiling means editing a line that says so.
    //
    // Driven through `inherit.paths` rather than through a bundled set,
    // because the bundled ones are compiled in and a test cannot add one. The
    // ceiling is checked by the same `parse_bundled` either way; what this
    // asserts is that a header outside a bundled set is refused outright,
    // which is the other half of the same rule.
    let root = support::scratch("set-header");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    std::fs::write(
        root.join("policy/principles.toml"),
        "[set]\nstages = [\"pre-commit\"]\n\n[rule.prevent-ai-author]\nbuiltin = \"prevent-ai-author\"\ngit.hooks = [\"commit-msg\"]\n",
    )
    .unwrap();

    let output = uphold(&root, &["rules", "--effective"]);
    assert_eq!(
        output.status.code().unwrap(),
        2,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("`[set]`"), "{text}");
    assert!(text.contains("not one"), "{text}");
}

#[test]
fn one_sets_json_is_the_same_document_as_the_whole() {
    // `--set NAME --json` and `--sets --json` have to agree, or the per-set
    // form is a second answer to the question the lock answers -- and the two
    // would be free to disagree about the set somebody is actually comparing.
    let root = manifest();
    let one = uphold(&root, &["rules", "--set", "credentials", "--json"]);
    assert_eq!(one.status.code().unwrap(), 0);
    let one = String::from_utf8(one.stdout).unwrap();

    let all = uphold(&root, &["rules", "--sets", "--json"]);
    let all = String::from_utf8(all.stdout).unwrap();

    // The one-set document is a one-element array; find its body in the whole.
    let body = one.trim().trim_start_matches('[').trim_end_matches(']');
    assert!(
        all.contains(body.trim()),
        "the credentials set reads differently on its own than it does in the whole document"
    );
}
