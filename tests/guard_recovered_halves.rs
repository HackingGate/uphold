//! The halves of the upstream rules that did not survive the port.
//!
//! Every test here is a case the guard reported as a PASS. Not a wrong finding,
//! not a crash: a green tick over bytes nobody read, which is the one failure
//! this binary exists to make impossible. They are driven through the CLI for
//! the reason `guard_cli.rs` states -- the artifact a guard reads is decided by
//! the stage it is told it is at, and a test calling the function directly
//! would be choosing that artifact itself.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn repository(policy: &str) -> PathBuf {
    let root = support::scratch("halves");
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

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

fn guard(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .arg("guard")
        .args(args)
        .current_dir(root)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn head(root: &Path) -> String {
    let output = Command::new(support::real_git())
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

const ZERO: &str = "0000000000000000000000000000000000000000";

/// A declared private owner needs no network and cannot be contradicted by one,
/// which is what lets these tests judge a real refusal without asking a forge.
const STAGED: &str = r#"
[rule.no-private-repo-names-staged]
builtin = "no-private-repo-names-staged"
visibility = "public"
private_owners = ["acme-private"]

[rule.no-private-repo-names-staged.git]
hooks = ["pre-commit"]
"#;

const TRACKED: &str = r#"
[rule.no-private-repo-names-in-files]
builtin = "no-private-repo-names-in-files"
visibility = "public"
private_owners = ["acme-private"]

[rule.no-private-repo-names-in-files.git]
hooks = ["pre-push", "manual"]
"#;

const IN_FILES: &str = r#"
[rule.prevent-unusual-unicode-in-files]
builtin = "prevent-unusual-unicode-in-files"

[rule.prevent-unusual-unicode-in-files.git]
hooks = ["pre-commit", "pre-merge-commit", "pre-push", "manual"]
"#;

// ── the staged scan ──────────────────────────────────────────────────

#[test]
fn a_staged_finding_names_the_file_it_arrived_in() {
    // Every added line used to be concatenated into one blob labelled "staged
    // changes", so the report named nothing a reader could open -- and the
    // rule's `[rule.files]` scope, which is a question about a PATH, could not
    // be applied to it at all.
    let root = repository(STAGED);
    write(
        &root,
        "docs/note.md",
        "we hit this in acme-private/secret\n",
    );
    git(&root, &["add", "docs/note.md"]);

    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("docs/note.md"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_files_scope_written_on_the_staged_guard_is_obeyed() {
    // Accepted and ignored before this: the scan had no path to apply it to.
    let root = repository(
        "[rule.no-private-repo-names-staged]\n\
         builtin = \"no-private-repo-names-staged\"\n\
         visibility = \"public\"\n\
         private_owners = [\"acme-private\"]\n\
         files.exclude = [\"**/vendor/**\"]\n\n\
         [rule.no-private-repo-names-staged.git]\nhooks = [\"pre-commit\"]\n",
    );
    write(
        &root,
        "vendor/upstream.md",
        "shipped from acme-private/secret\n",
    );
    git(&root, &["add", "vendor/upstream.md"]);
    assert_eq!(code(&guard(&root, &["--stage", "pre-commit"])), 0);

    write(&root, "docs/note.md", "shipped from acme-private/secret\n");
    git(&root, &["add", "docs/note.md"]);
    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
}

#[test]
fn an_external_diff_driver_cannot_blind_the_staged_scan() {
    // `git diff` honours `diff.external` from the repository's config and from
    // the global and system files alike, so somebody's difftastic or delta
    // setup -- made for reading diffs, not for this -- emitted no `+` line at
    // all and the guard reported a pass over a diff it never saw.
    let root = repository(STAGED);
    git(&root, &["config", "diff.external", "true"]);
    write(
        &root,
        "docs/note.md",
        "we hit this in acme-private/secret\n",
    );
    git(&root, &["add", "docs/note.md"]);

    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
}

#[test]
fn a_diff_attribute_cannot_blind_the_staged_scan() {
    // git consults the `diff` ATTRIBUTE before it looks at a byte, so a
    // committed `* -diff` reduces a plain-ASCII file to "Binary files differ"
    // and not one added line reaches the first pass.
    let root = repository(STAGED);
    write(&root, ".gitattributes", "* -diff\n");
    git(&root, &["add", ".gitattributes"]);
    git(&root, &["commit", "-qm", "attributes", "--no-verify"]);

    write(
        &root,
        "docs/note.md",
        "we hit this in acme-private/secret\n",
    );
    git(&root, &["add", "docs/note.md"]);
    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("docs/note.md"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_rename_publishes_a_path_and_adds_no_line() {
    // The whole disclosure is the NAME, and a rename adds no line for any
    // line-based scan to read.
    let root = repository(STAGED);
    write(&root, "notes.md", "nothing to see here\n");
    git(&root, &["add", "notes.md"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);
    git(&root, &["mv", "notes.md", "acme-private-notes.md"]);

    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("the path itself"),
        "{}",
        stderr(&output)
    );
}

// ── the tree-wide scan ───────────────────────────────────────────────

#[test]
fn a_path_names_a_private_repository_with_no_help_from_its_content() {
    let root = repository(TRACKED);
    write(&root, "acme-private/readme.md", "nothing to see here\n");
    git(&root, &["add", "acme-private/readme.md"]);

    let output = guard(&root, &["--stage", "manual"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("the path itself"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn the_messages_a_push_publishes_are_read() {
    // `commit-msg` only fires when `git commit` writes a message. This one was
    // written under `--no-verify`, which is one of six ways to record a message
    // no hook has read -- and everything else at pre-push reads the TREE.
    let root = repository(TRACKED);
    write(&root, "a.txt", "nothing to see here\n");
    git(&root, &["add", "a.txt"]);
    git(
        &root,
        &[
            "commit",
            "-qm",
            "Fix the thing we hit in acme-private/secret",
            "--no-verify",
        ],
    );
    let pushed = head(&root);

    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["guard", "--stage", "pre-push"])
        .current_dir(&root)
        .env_remove("UPHOLD_ALLOW")
        .env("PRE_COMMIT_REMOTE_NAME", "origin")
        .env("PRE_COMMIT_LOCAL_BRANCH", "main")
        .env("PRE_COMMIT_REMOTE_BRANCH", "refs/heads/main")
        .env("PRE_COMMIT_TO_REF", &pushed)
        .env("PRE_COMMIT_FROM_REF", ZERO)
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(stderr(&output).contains("MESSAGE"), "{}", stderr(&output));
}

#[test]
fn a_submodule_does_not_end_the_scan_before_it_starts() {
    // A gitlink's object is another repository's COMMIT, and `git cat-file blob`
    // on it fails. The failure was reported the way any read failure is, so
    // every tree-wide guard exited 2 in any workspace that tracks a submodule --
    // and this workspace is full of them.
    let root = repository(IN_FILES);
    write(&root, "a.txt", "clean\n");
    git(&root, &["add", "a.txt"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);
    let commit = head(&root);
    git(
        &root,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{commit},sub"),
        ],
    );

    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

// ── hidden Unicode ───────────────────────────────────────────────────

#[test]
fn a_filename_is_committed_text_too() {
    let root = repository(IN_FILES);
    write(&root, "docs/re\u{200b}adme.md", "clean\n");
    git(&root, &["add", "-A"]);

    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(stderr(&output).contains("FILE NAME"), "{}", stderr(&output));
    assert!(stderr(&output).contains("U+200B"), "{}", stderr(&output));
}

#[test]
fn a_blob_that_cannot_be_read_as_text_is_never_reported_clean() {
    // Skipped in silence before this: a file nobody read, counted as a file
    // with nothing in it. Exit 2, because nothing was found and nothing was
    // cleared -- the bytes could not be looked at.
    let root = repository(IN_FILES);
    std::fs::write(root.join("mixed.txt"), b"caf\xe9 latin1\n").unwrap();
    git(&root, &["add", "mixed.txt"]);

    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("never examined"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_binary_file_is_still_the_one_honest_skip() {
    let root = repository(IN_FILES);
    std::fs::write(root.join("image.bin"), b"\x89PNG\x00\x1a\x0a\xff\xfe\x01").unwrap();
    git(&root, &["add", "image.bin"]);

    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

// ── text mode ────────────────────────────────────────────────────────

fn scan_text(root: &Path, stdin: &[u8], home: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["scan", "--text", "-"])
        .current_dir(root)
        .env_remove("UPHOLD_ALLOW")
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn text_that_is_not_utf8_is_could_not_look_and_not_a_pass() {
    // `printf 'caf\xe9 latin1\n' | uphold scan --text -` printed "policy checks
    // passed (text)" and exited 0 over bytes that were never the text they were
    // searched as: `from_utf8_lossy` had already replaced the byte that should
    // have stopped the run.
    let root = std::env::temp_dir();
    let output = scan_text(&root, b"caf\xe9 latin1\n", "/srv/example");
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(stderr(&output).contains("not UTF-8"), "{}", stderr(&output));
}

#[test]
fn an_unrelated_literal_rule_does_not_remove_the_identity_fallback() {
    // The test was for the check KIND, so declaring any forbidden-literals rule
    // at all -- about anything at all -- silently deleted the one rule that
    // stops the running host's identity being published.
    let home = "/srv/example-home-4d1f2a";
    let root = repository(
        "[rule.no-default-route-in-text]\n\
         message = \"Do not publish this machine's default route.\"\n\
         forbidden_literals = \"running-default-route\"\n\
         files.include = [\".\"]\n",
    );
    let subject = format!("the log said {home}/work/output.txt\n");
    let output = scan_text(&root, subject.as_bytes(), home);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
}

// ── the message guards at pre-push ───────────────────────────────────

/// The two message guards, pinned at the stage that made them read the wrong
/// file. `no-private-repo-names-in-files` above already reads the pushed range;
/// these two asked `.git/COMMIT_EDITMSG` at every stage, so at pre-push they
/// judged whatever the last `git commit` happened to write.
const PUSHED_MESSAGES: &str = r#"
[rule.prevent-ai-author]
builtin = "prevent-ai-author"

[rule.prevent-ai-author.git]
hooks = ["commit-msg", "pre-push"]

[rule.prevent-unusual-unicode]
builtin = "prevent-unusual-unicode"

[rule.prevent-unusual-unicode.git]
hooks = ["commit-msg", "pre-push"]
"#;

fn pre_push(root: &Path, pushed: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["guard", "--stage", "pre-push"])
        .current_dir(root)
        .env_remove("UPHOLD_ALLOW")
        .env("PRE_COMMIT_REMOTE_NAME", "origin")
        .env("PRE_COMMIT_LOCAL_BRANCH", "main")
        .env("PRE_COMMIT_REMOTE_BRANCH", "refs/heads/main")
        .env("PRE_COMMIT_TO_REF", pushed)
        .env("PRE_COMMIT_FROM_REF", ZERO)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn an_attribution_marker_in_a_pushed_commit_is_refused_at_pre_push() {
    // The whole of the bug in one fixture: the marker is in the commit being
    // pushed, and `.git/COMMIT_EDITMSG` holds a LATER, clean message -- so a
    // guard reading the fallback found nothing and reported "1 guard(s)
    // passed", exit 0, while the marker went to the remote.
    let root = repository(PUSHED_MESSAGES);
    write(&root, "a.txt", "one\n");
    git(&root, &["add", "a.txt"]);
    git(
        &root,
        &[
            "commit",
            "-qm",
            "Add the thing\n\nGenerated with Claude Code\n",
            "--no-verify",
        ],
    );
    write(&root, "b.txt", "two\n");
    git(&root, &["add", "b.txt"]);
    git(
        &root,
        &["commit", "-qm", "Add another thing", "--no-verify"],
    );

    let pushed = head(&root);
    let output = pre_push(&root, &pushed);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("prevent-ai-author"),
        "{}",
        stderr(&output)
    );
    // Named by commit, not by the path of a file it did not read.
    assert!(stderr(&output).contains("MESSAGE"), "{}", stderr(&output));
}

#[test]
fn an_invisible_character_in_a_pushed_commit_is_refused_at_pre_push() {
    let root = repository(PUSHED_MESSAGES);
    write(&root, "a.txt", "one\n");
    git(&root, &["add", "a.txt"]);
    git(
        &root,
        &["commit", "-qm", "Add the\u{200b}thing", "--no-verify"],
    );
    write(&root, "b.txt", "two\n");
    git(&root, &["add", "b.txt"]);
    git(
        &root,
        &["commit", "-qm", "Add another thing", "--no-verify"],
    );

    let pushed = head(&root);
    let output = pre_push(&root, &pushed);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("prevent-unusual-unicode"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_clean_push_still_passes_when_the_last_edited_message_was_not() {
    // The other direction, and the reason the fallback is not merely
    // unnecessary: `.git/COMMIT_EDITMSG` outlives the commit it was written
    // for. Reading it at pre-push refuses a push that publishes nothing wrong.
    let root = repository(PUSHED_MESSAGES);
    write(&root, "a.txt", "one\n");
    git(&root, &["add", "a.txt"]);
    git(&root, &["commit", "-qm", "Add the thing", "--no-verify"]);
    let pushed = head(&root);

    // Left behind by an attempt that was refused and never became a commit.
    let git_dir = root.join(".git");
    std::fs::write(
        git_dir.join("COMMIT_EDITMSG"),
        "Something\n\nGenerated with Claude Code\n",
    )
    .unwrap();

    let output = pre_push(&root, &pushed);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}
