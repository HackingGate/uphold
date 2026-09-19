//! The `unnamed-removal` set, driven through the binary.
//!
//! Three verdicts over one staged change, because the guard promises three:
//! a removal the message does not name is refused, the same removal named is
//! clean, and a file the parser could not read is exit 2 rather than either.
//! Then the three shapes of message a hook receives that are not the message
//! git records: a name below the scissors line or on a comment line, a merge
//! message over a merged tree, and a deleted file named as a file. Driven
//! through the CLI for the reason `guard_cli.rs` gives: a test calling the
//! predicate directly would be choosing the artifact under test, and the
//! artifact here is what a repository inheriting the set gets.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// A repository inheriting the set, with `before` committed at `path`.
fn committed(path: &str, before: &str) -> PathBuf {
    let root = support::scratch("unnamed-removal");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    support::git(&root, &["init", "-q", "-b", "main"]);
    support::git(&root, &["config", "user.name", "Test"]);
    support::git(&root, &["config", "user.email", "test@example.test"]);
    std::fs::write(
        root.join("policy/principles.toml"),
        "[inherit]\nsets = [\"unnamed-removal\"]\n",
    )
    .unwrap();
    std::fs::write(root.join(path), before).unwrap();
    support::git(&root, &["add", "-A"]);
    support::git(&root, &["commit", "-qm", "before", "--no-verify"]);
    root
}

/// A repository inheriting the set, with `before` committed at `path` and
/// `after` staged over it -- or the path deleted from the index when `after`
/// is `None`.
fn staged(path: &str, before: &str, after: Option<&str>) -> PathBuf {
    let root = committed(path, before);
    match after {
        Some(text) => std::fs::write(root.join(path), text).unwrap(),
        None => std::fs::remove_file(root.join(path)).unwrap(),
    }
    support::git(&root, &["add", "-A"]);
    root
}

fn guard(root: &Path, message: &str) -> Output {
    std::fs::write(root.join("msg.txt"), message).unwrap();
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["guard", "--stage", "commit-msg", "--message", "msg.txt"])
        .current_dir(root)
        .env_remove("UPHOLD_ALLOW")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_removal_the_message_does_not_name_is_refused_and_named_it_is_clean() {
    let root = staged(
        "lib.rs",
        "fn keep() {}\n\nfn drop_me(b: u8) -> u8 {\n    b\n}\n",
        Some("fn keep() {}\n"),
    );

    let refused = guard(&root, "Tidy the module\n");
    assert_eq!(refused.status.code().unwrap(), 1, "{}", stderr(&refused));
    let text = stderr(&refused);
    assert!(
        text.contains("removed-function-named [set: unnamed-removal]"),
        "{text}"
    );
    assert!(text.contains("lib.rs: `drop_me` is removed"), "{text}");
    assert!(text.contains("(seen by tree-sitter)"), "{text}");

    let allowed = guard(&root, "Drop drop_me, which nothing called\n");
    assert_eq!(allowed.status.code().unwrap(), 0, "{}", stderr(&allowed));
    assert!(
        String::from_utf8_lossy(&allowed.stdout).contains("1 guard(s) passed at commit-msg"),
        "{}",
        String::from_utf8_lossy(&allowed.stdout)
    );
}

#[test]
fn a_staged_file_the_parser_could_not_read_is_exit_two_and_not_a_pass() {
    // The measurement ADR 0003 records, as a verdict a repository gets: the
    // staged side has an unterminated string, the grammar recovers a tree
    // with nothing removed in it, and the run says it could not look rather
    // than that the message names everything.
    let root = staged(
        "lib.rs",
        "fn keep() {}\n",
        Some("const S: &str = \"open;\nfn keep() {}\n"),
    );
    let output = guard(&root, "Break the string\n");
    assert_eq!(output.status.code().unwrap(), 2, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(
        text.contains("lib.rs:1 at the index did not parse"),
        "{text}"
    );
    assert!(text.contains("could not be established"), "{text}");
}

#[test]
fn a_file_in_no_linked_language_is_outside_the_claim() {
    // A removed `fn`-shaped line in a document is not a function, and the
    // set says nothing about it.
    let root = staged("notes.md", "fn drop_me() {}\n", Some("gone\n"));
    let output = guard(&root, "Rewrite the notes\n");
    assert_eq!(output.status.code().unwrap(), 0, "{}", stderr(&output));
}

#[test]
fn a_name_below_the_scissors_line_or_on_a_comment_line_is_not_in_the_message() {
    // What `git commit -v` hands the hook: the template names the removal
    // on a `#` line, and the staged diff below the scissors carries the
    // declaration itself. Git records neither, so neither names anything.
    let root = staged(
        "lib.rs",
        "fn keep() {}\n\nfn drop_me(b: u8) -> u8 {\n    b\n}\n",
        Some("fn keep() {}\n"),
    );

    let verbose = "Tidy the module\n\
                   \n\
                   # Please enter the commit message for your changes.\n\
                   #\tmodified:   lib.rs\n\
                   # ------------------------ >8 ------------------------\n\
                   # Do not modify or remove the line above.\n\
                   diff --git a/lib.rs b/lib.rs\n\
                   --- a/lib.rs\n\
                   +++ b/lib.rs\n\
                   @@ -1,5 +1 @@\n\
                   fn keep() {}\n\
                   -\n\
                   -fn drop_me(b: u8) -> u8 {\n\
                   -    b\n\
                   -}\n";
    let below = guard(&root, verbose);
    assert_eq!(below.status.code().unwrap(), 1, "{}", stderr(&below));
    assert!(
        stderr(&below).contains("lib.rs: `drop_me` is removed"),
        "{}",
        stderr(&below)
    );

    let commented = guard(&root, "Tidy the module\n\n# drop_me is gone\n");
    assert_eq!(
        commented.status.code().unwrap(),
        1,
        "{}",
        stderr(&commented)
    );

    // The same words above the scissors and not commented out are the message.
    let written = guard(
        &root,
        "Drop drop_me\n\n# ------------------------ >8 ------------------------\n-fn other() {}\n",
    );
    assert_eq!(written.status.code().unwrap(), 0, "{}", stderr(&written));
}

#[test]
fn a_merge_message_is_not_asked_to_name_what_the_merged_commits_removed() {
    // `git merge` runs `commit-msg` with the merged tree in the index. The
    // removal is recorded in the topic commit, which met this guard at its
    // own `commit-msg`; the merge message names the branch and is clean.
    let root = committed(
        "lib.rs",
        "fn keep() {}\n\nfn drop_me(b: u8) -> u8 {\n    b\n}\n",
    );
    support::git(&root, &["checkout", "-q", "-b", "topic"]);
    std::fs::write(root.join("lib.rs"), "fn keep() {}\n").unwrap();
    support::git(&root, &["add", "-A"]);
    support::git(
        &root,
        &[
            "commit",
            "-qm",
            "Drop drop_me, nothing called it",
            "--no-verify",
        ],
    );
    support::git(&root, &["checkout", "-q", "main"]);
    std::fs::write(root.join("notes.md"), "kept\n").unwrap();
    support::git(&root, &["add", "-A"]);
    support::git(&root, &["commit", "-qm", "A note", "--no-verify"]);
    support::git(&root, &["merge", "-q", "--no-ff", "--no-commit", "topic"]);
    assert!(
        support::git_command(&root)
            .args(["rev-parse", "-q", "--verify", "MERGE_HEAD"])
            .stdout(Stdio::null())
            .status()
            .unwrap()
            .success(),
        "the merge is in progress"
    );

    let merged = guard(&root, "Merge branch 'topic'\n");
    assert_eq!(merged.status.code().unwrap(), 0, "{}", stderr(&merged));
    assert!(
        String::from_utf8_lossy(&merged.stdout).contains("1 guard(s) passed at commit-msg"),
        "{}",
        String::from_utf8_lossy(&merged.stdout)
    );
}

#[test]
fn a_deleted_file_is_named_by_its_name_and_a_kept_file_is_not() {
    let deleted = staged("old.rs", "fn a() {}\nfn b() {}\n", None);
    let by_file = guard(&deleted, "Delete old.rs, nothing read it\n");
    assert_eq!(by_file.status.code().unwrap(), 0, "{}", stderr(&by_file));

    let by_stem = guard(&deleted, "Drop old\n");
    assert_eq!(by_stem.status.code().unwrap(), 0, "{}", stderr(&by_stem));

    // The file stays and one function goes: the file's name names no
    // function, and the message must say which.
    let kept = staged("old.rs", "fn a() {}\nfn b() {}\n", Some("fn a() {}\n"));
    let refused = guard(&kept, "Delete old.rs, nothing read it\n");
    assert_eq!(refused.status.code().unwrap(), 1, "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("old.rs: `b` is removed"),
        "{}",
        stderr(&refused)
    );
}
