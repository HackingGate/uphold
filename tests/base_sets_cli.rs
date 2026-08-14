//! What a bundled set is, said out loud: provenance, hand-copies, and the two
//! notes a repository never used to hear.
//!
//! Every case here is about a rule whose declaration is somewhere the reader is
//! not looking. A set is compiled into the binary, so `sets = ["..."]` is the
//! whole of what a repository writes down -- which makes "where did this rule
//! come from" a question the tree cannot answer, and every one of these tests
//! is an answer to it.
//!
//! Driven through the CLI for the reason `guard_cli.rs` gives: a test calling
//! the function directly would be choosing the artifact under test.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

fn repository(policy: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "uphold-sets-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();

    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.name", "Test"]);
    git(&root, &["config", "user.email", "test@example.test"]);

    std::fs::write(root.join("policy/principles.toml"), policy).unwrap();
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

fn guard(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .arg("guard")
        .args(args)
        .current_dir(root)
        .env_remove("UPHOLD_ALLOW")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The check itself, under an id of its own -- which is what a repository that
/// does not inherit `process-residue` would have to write, and is the reason
/// dispatch is on the built-in name rather than on the id.
const AUDIT: &str = r#"
[rule.local-set-audit]
builtin = "no-hand-copied-base-rule"

[rule.local-set-audit.git]
hooks = ["manual"]
"#;

/// A transcription of a rule `process-residue` already ships.
const COPIED: &str = r#"
[rule.no-merge-conflict-markers]
message = "conflict markers"
regexp = '^(<<<<<<<|>>>>>>>) '
files.include = ["."]
"#;

#[test]
fn a_hand_copied_rule_is_named_with_its_set_and_what_that_set_would_add() {
    let root = repository(&format!("{AUDIT}{COPIED}"));

    let output = guard(&root, &["--stage", "manual"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("no-merge-conflict-markers"), "{text}");
    assert!(text.contains("process-residue"), "{text}");
    // The coverage delta is the argument for taking the set, so the report has
    // to carry it: a reader deciding whether to inherit cannot weigh the
    // decision from the one id they already wrote out.
    assert!(text.contains("no-hardcoded-home-paths"), "{text}");
}

#[test]
fn an_override_of_a_set_this_policy_inherits_stays_silent() {
    // The documented override, and it is a decision written in the same file
    // as the `[inherit]` line that shows it. Firing here would make the
    // supported way of narrowing an inherited rule the thing this check
    // refuses.
    let root = repository(&format!(
        "[inherit]\nsets = [\"process-residue\"]\n{AUDIT}{COPIED}"
    ));

    let output = guard(&root, &["--stage", "manual"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_rule_no_set_owns_is_nobody_elses_business() {
    let root = repository(&format!(
        "{AUDIT}\n[rule.no-shouting]\nmessage = \"quiet\"\nregexp = 'SHOUT'\nfiles.include = [\".\"]\n"
    ));

    let output = guard(&root, &["--stage", "manual"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_refusal_from_an_inherited_set_names_the_set_it_arrived_from() {
    // The whole reason provenance exists. This repository's policy contains no
    // rule with this id at all -- it is one word in an `[inherit]` line -- so a
    // refusal naming only the id sends the reader looking through their own
    // file for something that was never in it.
    let root = repository(
        "[inherit]\nsets = [\"process-residue\"]\n\n\
         [rule.no-committed-secret-material]\nmessage = \"copied\"\nregexp = 'BEGIN PRIVATE KEY'\nfiles.include = [\".\"]\n",
    );

    let output = guard(&root, &["--stage", "manual"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(
        text.contains("no-hand-copied-base-rule [set: process-residue]"),
        "{text}"
    );
    // And it names the OTHER set: the one the copy came from, which is the one
    // the reader has to inherit.
    assert!(text.contains("credentials"), "{text}");
}

#[test]
fn an_override_that_changes_the_check_is_reported_at_load() {
    // `no-tracked-private-data-paths` is a `path_regexp` in the set. A local
    // rule of the same id checking file CONTENTS instead is a different check
    // wearing the set's name -- and the id resolves, so every claim naming it
    // reconciles green over a rule that is no longer the rule it is named
    // after.
    let root = repository(
        "[inherit]\nsets = [\"process-residue\"]\n\n\
         [rule.no-tracked-private-data-paths]\nmessage = \"mine\"\nregexp = 'private'\nfiles.include = [\".\"]\n",
    );

    let output = guard(&root, &["--stage", "manual"]);
    let text = stderr(&output);
    assert!(text.contains("no-tracked-private-data-paths"), "{text}");
    assert!(text.contains("shadows"), "{text}");
    // A note and not a gate: the tree still passes, because a repository may
    // have a reason for the copy and hearing about it should not be the same
    // event as being stopped.
    assert_eq!(code(&output), 0, "{text}");
}

#[test]
fn a_push_allowed_by_a_derived_owner_says_the_owner_was_derived() {
    // 50 of 65 repositories run this guard with no `owner` pinned, and until
    // now it said so only when refusing -- which is never, for as long as
    // nothing has gone wrong.
    let root = repository(
        "[rule.prevent-public-push]\nbuiltin = \"prevent-public-push\"\n\n\
         [rule.prevent-public-push.git]\nhooks = [\"pre-push\"]\n",
    );
    std::fs::write(root.join("a.txt"), "one\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);
    git(
        &root,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/acme/widget.git",
        ],
    );

    let output = guard(
        &root,
        &[
            "--stage",
            "pre-push",
            "--remote-url",
            "https://github.com/acme/widget.git",
        ],
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("DERIVED FROM ORIGIN"), "{text}");
    assert!(text.contains("owner = \"acme\""), "{text}");
}

#[test]
fn a_push_allowed_by_a_pinned_owner_says_nothing() {
    // A note on every push is a note nobody reads by the time it matters, so
    // the strong mode is silent -- it has nothing to report.
    let root = repository(
        "[rule.prevent-public-push]\nbuiltin = \"prevent-public-push\"\nowner = \"acme\"\n\n\
         [rule.prevent-public-push.git]\nhooks = [\"pre-push\"]\n",
    );
    std::fs::write(root.join("a.txt"), "one\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);

    let output = guard(
        &root,
        &[
            "--stage",
            "pre-push",
            "--remote-url",
            "https://github.com/acme/widget.git",
        ],
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        !stderr(&output).contains("DERIVED FROM ORIGIN"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_push_allowed_by_a_named_repository_says_nothing_about_origin() {
    // `allowed_repos` decided this from a written list, so the derived owner
    // did not answer the question and has nothing to say about it.
    let root = repository(
        "[rule.prevent-public-push]\nbuiltin = \"prevent-public-push\"\nallowed_repos = [\"other/thing\"]\n\n\
         [rule.prevent-public-push.git]\nhooks = [\"pre-push\"]\n",
    );
    std::fs::write(root.join("a.txt"), "one\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);
    git(
        &root,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/acme/widget.git",
        ],
    );

    let output = guard(
        &root,
        &[
            "--stage",
            "pre-push",
            "--remote-url",
            "https://github.com/other/thing.git",
        ],
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        !stderr(&output).contains("DERIVED FROM ORIGIN"),
        "{}",
        stderr(&output)
    );
}
