//! CLI-level tests for `uphold guard`.
//!
//! Each builds a real repository and drives the binary the way a hook runner
//! does, because the artifact a guard reads is decided by the stage it is told
//! it is at -- and a test that called the function directly would be choosing
//! that artifact itself, which is the one thing under test.

#![expect(
    clippy::let_underscore_must_use,
    clippy::shadow_unrelated,
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
        "uphold-guard-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    std::fs::write(root.join("policy/principles.toml"), policy).unwrap();

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

const AI_AUTHOR: &str = r#"
[rule.prevent-ai-author]
builtin = "prevent-ai-author"

[rule.prevent-ai-author.git]
hooks = ["commit-msg"]
"#;

#[test]
fn a_noreply_coauthor_trailer_is_refused() {
    let root = repository(AI_AUTHOR);
    write(
        &root,
        "msg.txt",
        "Fix the thing\n\nCo-Authored-By: A <noreply@example.test>\n",
    );
    let output = guard(&root, &["--stage", "commit-msg", "--message", "msg.txt"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("prevent-ai-author"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_ordinary_message_passes() {
    let root = repository(AI_AUTHOR);
    write(
        &root,
        "msg.txt",
        "Fix the thing\n\nCo-Authored-By: A <a@example.test>\n",
    );
    assert_eq!(
        code(&guard(
            &root,
            &["--stage", "commit-msg", "--message", "msg.txt"]
        )),
        0
    );
}

#[test]
fn the_bypass_names_the_guard_it_switched_off() {
    // Five differently-named variables became one. What was switched off is
    // legible in a shell history because the id is in it.
    let root = repository(AI_AUTHOR);
    write(&root, "msg.txt", "x\n\nGenerated with Claude Code\n");
    assert_eq!(
        code(&guard(
            &root,
            &["--stage", "commit-msg", "--message", "msg.txt"]
        )),
        1
    );
    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["guard", "--stage", "commit-msg", "--message", "msg.txt"])
        .current_dir(&root)
        .env("UPHOLD_ALLOW", "prevent-ai-author")
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stderr(&output).contains("bypassed"), "{}", stderr(&output));
}

#[test]
fn a_bypass_for_one_guard_does_not_release_another() {
    let root = repository(AI_AUTHOR);
    write(&root, "msg.txt", "x\n\nGenerated with Claude Code\n");
    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["guard", "--stage", "commit-msg", "--message", "msg.txt"])
        .current_dir(&root)
        .env("UPHOLD_ALLOW", "no-merge-commit")
        .output()
        .unwrap();
    assert_eq!(code(&output), 1, "{}", stderr(&output));
}

#[test]
fn a_guard_is_only_asked_at_a_stage_it_can_observe() {
    // Asked at a stage it cannot see, a guard has not passed -- it has not run.
    // Reporting that as a pass is the failure `explicit-unknown` names.
    let root = repository(AI_AUTHOR);
    write(&root, "msg.txt", "x\n\nGenerated with Claude Code\n");
    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("0 guard(s) passed"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn a_guard_id_that_names_no_guard_is_refused_at_load() {
    let root = repository("[rule.invent-a-guard]\nbuiltin = \"invent-a-guard\"\n\n[rule.invent-a-guard.git]\nhooks = []\n");
    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no built-in is called"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_missing_stage_is_an_error_and_not_a_default() {
    // A guard reads a different artifact at each stage, so a default would make
    // it answer a question nobody asked, and answer it green.
    let root = repository(AI_AUTHOR);
    let output = guard(&root, &[]);
    assert_eq!(code(&output), 2);
    assert!(
        stderr(&output).contains("needs --stage"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn hidden_unicode_is_read_out_of_the_index_and_not_the_working_tree() {
    // A line staged and then edited away is in the commit and not on disk. A
    // guard reading the working tree judges the second and misses the first.
    let root =
        repository("[rule.prevent-unusual-unicode-in-files]\nbuiltin = \"prevent-unusual-unicode-in-files\"\n\n[rule.prevent-unusual-unicode-in-files.git]\nhooks = [\"pre-commit\", \"pre-merge-commit\", \"pre-push\", \"manual\"]\n");
    write(&root, "a.txt", "clean\u{200B}\n");
    git(&root, &["add", "a.txt"]);
    write(&root, "a.txt", "clean\n"); // the working tree is now innocent

    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(stderr(&output).contains("U+200B"), "{}", stderr(&output));
}

#[test]
fn an_allowance_scoped_to_a_path_admits_the_character_only_there() {
    let root = repository(
        "[rule.prevent-unusual-unicode-in-files]\n\
         builtin = \"prevent-unusual-unicode-in-files\"\n\
         allow = [\"U+00A0:captured/**\"]\n\n[rule.prevent-unusual-unicode-in-files.git]\nhooks = [\"pre-commit\"]\n",
    );
    write(&root, "captured/page.html", "a\u{00A0}b\n");
    git(&root, &["add", "-A"]);
    assert_eq!(code(&guard(&root, &["--stage", "pre-commit"])), 0);

    write(&root, "src/main.rs", "let a\u{00A0}= 1;\n");
    git(&root, &["add", "-A"]);
    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("src/main.rs"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_symlinks_blob_is_its_target_path() {
    // Git stores the TARGET PATH as the blob, so a link whose target carries a
    // zero-width space commits one -- while any reader that follows the link
    // scans some other file's bytes and reports on those instead.
    let root =
        repository("[rule.prevent-unusual-unicode-in-files]\nbuiltin = \"prevent-unusual-unicode-in-files\"\n\n[rule.prevent-unusual-unicode-in-files.git]\nhooks = [\"pre-commit\", \"pre-merge-commit\", \"pre-push\", \"manual\"]\n");
    write(&root, "real.txt", "clean\n");
    std::os::unix::fs::symlink("t\u{200B}gt", root.join("link")).unwrap();
    git(&root, &["add", "-A"]);

    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(stderr(&output).contains("link:"), "{}", stderr(&output));
}

#[test]
fn a_merge_in_progress_is_refused_at_pre_commit() {
    let root = repository("[rule.no-merge-commit]\nbuiltin = \"no-merge-commit\"\n\n[rule.no-merge-commit.git]\nhooks = [\"pre-commit\"]\n");
    write(&root, "a.txt", "one\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);
    assert_eq!(code(&guard(&root, &["--stage", "pre-commit"])), 0);

    // A SQUASH_MSG is the squash-merge half of the same guard.
    let git_dir = root.join(".git");
    std::fs::write(git_dir.join("SQUASH_MSG"), "squashed\n").unwrap();
    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(stderr(&output).contains("squash"), "{}", stderr(&output));
}

#[test]
fn a_push_outside_the_allow_list_is_refused_and_says_how_to_allow_it() {
    let root =
        repository("[rule.prevent-public-push]\nbuiltin = \"prevent-public-push\"\nowner = \"acme\"\n\n[rule.prevent-public-push.git]\nhooks = [\"pre-push\"]\n");
    write(&root, "a.txt", "one\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);

    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args([
            "guard",
            "--stage",
            "pre-push",
            "--remote-url",
            "https://github.com/someone-else/thing.git",
        ])
        .current_dir(&root)
        .env_remove("UPHOLD_ALLOW")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("someone-else/thing"), "{text}");
    assert!(text.contains("pinned to acme"), "{text}");
    assert!(text.contains("allowed_repos"), "{text}");
}

#[test]
fn a_push_to_the_pinned_owner_passes() {
    let root =
        repository("[rule.prevent-public-push]\nbuiltin = \"prevent-public-push\"\nowner = \"acme\"\n\n[rule.prevent-public-push.git]\nhooks = [\"pre-push\"]\n");
    write(&root, "a.txt", "one\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);

    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args([
            "guard",
            "--stage",
            "pre-push",
            "--remote-url",
            "https://github.com/acme/widget.git",
        ])
        .current_dir(&root)
        .env_remove("UPHOLD_ALLOW")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn an_unpinned_workspace_says_its_answer_came_from_origin() {
    // The fallback is the weaker mode -- repointing origin moves it, which is
    // the accident the guard exists for -- so it says so rather than passing
    // itself off as the pinned one.
    let root = repository("[rule.prevent-public-push]\nbuiltin = \"prevent-public-push\"\n\n[rule.prevent-public-push.git]\nhooks = [\"pre-push\"]\n");
    write(&root, "a.txt", "one\n");
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

    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args([
            "guard",
            "--stage",
            "pre-push",
            "--remote-url",
            "https://github.com/someone-else/thing.git",
        ])
        .current_dir(&root)
        .env_remove("UPHOLD_ALLOW")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("DERIVED FROM ORIGIN"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_pin_that_names_no_tag_and_a_pin_left_behind_are_both_reported() {
    let root = repository("[rule.no-stale-hook-pins]\nbuiltin = \"no-stale-hook-pins\"\n\n[rule.no-stale-hook-pins.git]\nhooks = [\"pre-push\", \"manual\"]\n");

    // A local repository stands in for the upstream, so the test needs no
    // network and no forge.
    let upstream = root.join("upstream");
    std::fs::create_dir_all(&upstream).unwrap();
    git(&upstream, &["init", "-q", "-b", "main"]);
    git(&upstream, &["config", "user.name", "Test"]);
    git(&upstream, &["config", "user.email", "test@example.test"]);
    std::fs::write(upstream.join("a.txt"), "x\n").unwrap();
    git(&upstream, &["add", "-A"]);
    git(&upstream, &["commit", "-qm", "one", "--no-verify"]);
    git(&upstream, &["tag", "v1.0.0"]);
    git(&upstream, &["tag", "v2.0.0"]);

    let url = upstream.to_string_lossy().into_owned();
    write(
        &root,
        ".pre-commit-config.yaml",
        &format!("repos:\n  - repo: {url}\n    rev: v1.0.0\n    hooks:\n      - id: x\n"),
    );
    let output = guard(&root, &["--stage", "manual"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("v2.0.0 is newer"),
        "{}",
        stderr(&output)
    );

    // The opposite predicate: a rev ahead of every tag has not fallen behind,
    // and the guard that asks only "behind?" reports it as a pass.
    write(
        &root,
        ".pre-commit-config.yaml",
        &format!("repos:\n  - repo: {url}\n    rev: v9.9.9\n    hooks:\n      - id: x\n"),
    );
    let output = guard(&root, &["--stage", "manual"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("names no tag"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_current_pin_passes() {
    let root = repository("[rule.no-stale-hook-pins]\nbuiltin = \"no-stale-hook-pins\"\n\n[rule.no-stale-hook-pins.git]\nhooks = [\"pre-push\", \"manual\"]\n");
    let upstream = root.join("upstream");
    std::fs::create_dir_all(&upstream).unwrap();
    git(&upstream, &["init", "-q", "-b", "main"]);
    git(&upstream, &["config", "user.name", "Test"]);
    git(&upstream, &["config", "user.email", "test@example.test"]);
    std::fs::write(upstream.join("a.txt"), "x\n").unwrap();
    git(&upstream, &["add", "-A"]);
    git(&upstream, &["commit", "-qm", "one", "--no-verify"]);
    git(&upstream, &["tag", "v1.0.0"]);

    let url = upstream.to_string_lossy().into_owned();
    write(
        &root,
        ".pre-commit-config.yaml",
        &format!("repos:\n  - repo: {url}\n    rev: v1.0.0\n    hooks:\n      - id: x\n"),
    );
    assert_eq!(code(&guard(&root, &["--stage", "manual"])), 0);
}

// ── what a runner tells a pre-push guard ─────────────────────────────
//
// git hands a pre-push hook its ref lines on stdin. pre-commit and prek
// consume that stdin themselves and export the same facts as environment
// variables instead, so a guard reading only stdin sees an empty push under
// the two most widely used runners -- and an empty push looked exactly like a
// push introducing nothing.

const IN_FILES: &str = r#"
[rule.prevent-unusual-unicode-in-files]
builtin = "prevent-unusual-unicode-in-files"

[rule.prevent-unusual-unicode-in-files.git]
hooks = ["pre-commit", "pre-merge-commit", "pre-push", "manual"]
"#;

const ZERO: &str = "0000000000000000000000000000000000000000";

fn head(root: &Path) -> String {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A guard that cannot see the push must say so, not scan something else.
#[test]
fn a_pre_push_told_nothing_refuses_rather_than_reading_the_working_tree() {
    let root = repository(IN_FILES);
    write(&root, "a.txt", "one\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);

    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["guard", "--stage", "pre-push"])
        .current_dir(&root)
        .env_remove("UPHOLD_ALLOW")
        .env_remove("PRE_COMMIT_TO_REF")
        .env_remove("PRE_COMMIT_SOURCE")
        .stdin(Stdio::null())
        .output()
        .unwrap();

    // 2, not 1 and not 0: this is could-not-look, which `explicit-unknown`
    // says must be a state of its own.
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(stderr(&output).contains("use_stdin"), "{}", stderr(&output));
}

/// The discriminating case, and the reason this is a correctness fix rather
/// than a convenience: the index holds a file the guard would refuse, and the
/// commit being pushed does not. Reading the runner's environment gives the
/// right answer; reading nothing gave a refusal about a tree nobody was
/// pushing.
#[test]
fn a_pre_push_reads_the_range_the_runner_exported_and_not_the_index() {
    let root = repository(IN_FILES);
    write(&root, "a.txt", "one\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);
    let pushed = head(&root);

    // Staged, never committed, and carrying a zero-width space.
    write(&root, "b.txt", "two\u{200b}\n");
    git(&root, &["add", "-A"]);

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

    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

/// pre-commit's older spellings. A repository pinned to an older pre-commit
/// exports these and nothing else, and a guard that knows only the new names
/// reads that push as empty -- the failure this whole module exists to delete,
/// reintroduced by a version number.
#[test]
fn the_older_pre_commit_variable_names_are_read_too() {
    let root = repository(IN_FILES);
    write(&root, "a.txt", "one\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);
    let pushed = head(&root);

    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["guard", "--stage", "pre-push"])
        .current_dir(&root)
        .env_remove("UPHOLD_ALLOW")
        .env_remove("PRE_COMMIT_TO_REF")
        .env_remove("PRE_COMMIT_FROM_REF")
        .env("PRE_COMMIT_SOURCE", &pushed)
        .env("PRE_COMMIT_ORIGIN", ZERO)
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

/// git's own channel still wins, and still parses. A flag or a ref line typed
/// by a person is a reproduction of one invocation, and a stale environment
/// variable silently replacing it is not one.
#[test]
fn ref_lines_on_stdin_are_still_read_and_still_win() {
    use std::io::Write;

    let root = repository(IN_FILES);
    write(&root, "a.txt", "one\u{200b}\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);
    let pushed = head(&root);

    let mut child = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["guard", "--stage", "pre-push"])
        .current_dir(&root)
        .env_remove("UPHOLD_ALLOW")
        // The environment names a commit with nothing wrong with it; stdin
        // names the one actually being pushed.
        .env("PRE_COMMIT_TO_REF", ZERO)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(
        child.stdin.as_mut().unwrap(),
        "refs/heads/main {pushed} refs/heads/main {ZERO}"
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();

    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("prevent-unusual-unicode-in-files"),
        "{}",
        stderr(&output)
    );
}

/// The first push to a remote with no refs at all.
///
/// pre-commit names both branches here and exports NEITHER sha, because the
/// pair it publishes is a range and there is no ancestor on the remote to start
/// one from. Requiring the sha read that as "no push" -- so the one push that
/// introduces a repository's entire history was the one push nothing scanned.
#[test]
fn a_first_push_names_a_branch_and_no_shas_and_is_still_read() {
    let root = repository(IN_FILES);
    write(&root, "a.txt", "one\u{200b}\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);

    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["guard", "--stage", "pre-push"])
        .current_dir(&root)
        .env_remove("UPHOLD_ALLOW")
        .env_remove("PRE_COMMIT_TO_REF")
        .env_remove("PRE_COMMIT_SOURCE")
        .env_remove("PRE_COMMIT_FROM_REF")
        .env_remove("PRE_COMMIT_ORIGIN")
        .env("PRE_COMMIT_REMOTE_NAME", "origin")
        .env("PRE_COMMIT_LOCAL_BRANCH", "refs/heads/main")
        .env("PRE_COMMIT_REMOTE_BRANCH", "refs/heads/main")
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("prevent-unusual-unicode-in-files"),
        "{}",
        stderr(&output)
    );
}

/// A remote sha this clone does not have is not an empty range.
///
/// The discriminating file is one that a pushed commit ADDS and a later pushed
/// commit DELETES: it is on the remote permanently and in no tip tree, so the
/// range half of the scope is the only thing that reads it. `^<sha>` fails on
/// an object the clone does not hold, and that failure used to be read as "this
/// push introduces nothing" -- so the guard printed `1 guard(s) passed` over a
/// zero-width space it never opened. Anyone else pushing since the last fetch
/// produces this state, as do a rewritten upstream ref and a shallow clone.
#[test]
fn a_remote_sha_this_clone_does_not_have_is_not_an_empty_push() {
    let root = repository(IN_FILES);
    write(&root, "a.txt", "clean\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "base", "--no-verify"]);
    write(&root, "bad.txt", "zero\u{200b}width\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "add", "--no-verify"]);
    git(&root, &["rm", "-q", "bad.txt"]);
    git(&root, &["commit", "-qm", "remove", "--no-verify"]);

    let local = head(&root);
    let unknown = "1111111111111111111111111111111111111111";
    let line = format!("refs/heads/main {local} refs/heads/main {unknown}\n");

    let mut child = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["guard", "--stage", "pre-push", "--remote", "origin"])
        .current_dir(&root)
        .env_remove("UPHOLD_ALLOW")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(line.as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();

    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(stderr(&output).contains("bad.txt"), "{}", stderr(&output));
}

/// A named message file that is not there is not "nothing was forwarded".
///
/// The fallback reads `.git/COMMIT_EDITMSG` -- the PREVIOUS commit's message,
/// which is clean -- so the guard reported a pass over a file it never opened.
/// A typo, a relative `$1` resolved from the wrong directory, or an unset
/// variable in a wrapper all produce it.
#[test]
fn a_named_message_file_that_is_missing_is_not_a_pass() {
    let root = repository(AI_AUTHOR);
    write(&root, "a.txt", "one\n");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "a clean subject", "--no-verify"]);

    let output = guard(
        &root,
        &["--stage", "commit-msg", "--message", "no-such-file.txt"],
    );

    // 2, not 0: could-not-look is its own state.
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no-such-file.txt"),
        "{}",
        stderr(&output)
    );
}

// --- the identity a commit is about to be stamped with ----------------------

const AUTHOR_MISMATCH: &str = r#"
[rule.prevent-author-mismatch]
builtin = "prevent-author-mismatch"

[rule.prevent-author-mismatch.git]
hooks = ["pre-commit"]
"#;

/// The guard reads the GLOBAL identity, so a test has to own one.
///
/// `GIT_CONFIG_GLOBAL` is what git itself offers for this, and it reaches the
/// binary's own `git config --global` through the environment it inherits --
/// which is the same path a developer's real `~/.gitconfig` takes. Writing the
/// fixture anywhere else would test a lookup nothing performs.
///
/// The `GIT_AUTHOR_*` and `GIT_COMMITTER_*` pairs are cleared for the same
/// reason, from the other side. `git var GIT_AUTHOR_IDENT` reads the
/// environment BEFORE the repository's config, and git sets both pairs for
/// every hook it runs -- so this suite, run from a commit hook, asked the
/// binary about whoever was committing and got their identity back instead of
/// the fixture's. It failed under the hook and passed under `cargo test`, which
/// is the shape of a test that does not own its inputs.
fn guard_under_global(root: &Path, args: &[&str], global: &str) -> Output {
    let config = root.join("fixture.gitconfig");
    std::fs::write(&config, global).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
    command
        .arg("guard")
        .args(args)
        .current_dir(root)
        .env_remove("UPHOLD_ALLOW")
        .env("GIT_CONFIG_GLOBAL", &config);
    for name in [
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_AUTHOR_DATE",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
        "GIT_COMMITTER_DATE",
        "EMAIL",
    ] {
        command.env_remove(name);
    }
    command.output().unwrap()
}

#[test]
fn a_repository_identity_that_is_not_the_global_one_is_refused() {
    // The case the guard exists for: a tree whose local `user.email` is not the
    // one the author publishes under, so the commit lands attributed to nobody
    // they recognise -- and a forge keys attribution on the address, so it is
    // the half that decides.
    let root = repository(AUTHOR_MISMATCH);
    let output = guard_under_global(
        &root,
        &["--stage", "pre-commit"],
        "[user]\n\tname = Real Name\n\temail = real@example.test\n",
    );
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("does not match your global one"), "{text}");
    // Both roles are named, and the local identity is quoted back rather than
    // described -- the reader has to be able to see which of the two is wrong.
    assert!(text.contains("author: Test <test@example.test>"), "{text}");
    assert!(
        text.contains("committer: Test <test@example.test>"),
        "{text}"
    );
    // And the remedy is the command, with the expected values already in it.
    assert!(
        text.contains("git config user.email \"real@example.test\""),
        "{text}"
    );
    assert!(
        text.contains("git config user.name  \"Real Name\""),
        "{text}"
    );
}

#[test]
fn the_identity_that_matches_the_global_one_passes() {
    let root = repository(AUTHOR_MISMATCH);
    let output = guard_under_global(
        &root,
        &["--stage", "pre-commit"],
        "[user]\n\tname = Test\n\temail = test@example.test\n",
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_global_identity_with_no_name_compares_only_the_address() {
    // Half a configured identity is enforced as half. Comparing an empty
    // expectation against whatever git resolved would refuse every commit in
    // every repository, and offer `git config user.name ""` as the remedy --
    // which git does not accept either.
    let root = repository(AUTHOR_MISMATCH);
    let matching = guard_under_global(
        &root,
        &["--stage", "pre-commit"],
        "[user]\n\temail = test@example.test\n",
    );
    assert_eq!(code(&matching), 0, "{}", stderr(&matching));

    let wrong = guard_under_global(
        &root,
        &["--stage", "pre-commit"],
        "[user]\n\temail = other@example.test\n",
    );
    assert_eq!(code(&wrong), 1, "{}", stderr(&wrong));
    let text = stderr(&wrong);
    assert!(text.contains("only the address"), "{text}");
    // The remedy names the address and nothing else, because a name was never
    // declared to hold the commit to.
    assert!(!text.contains("git config user.name"), "{text}");
}

#[test]
fn no_global_identity_at_all_says_the_guard_did_not_run() {
    // The fail-open, said out loud. A container or an agent that ran `git init`
    // has no global identity to compare against, which is the very scenario the
    // guard names -- so it reports that it declined rather than passing in a
    // way indistinguishable from a checked, matching identity.
    let root = repository(AUTHOR_MISMATCH);
    let output = guard_under_global(&root, &["--stage", "pre-commit"], "");
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no global `user.email` is configured"),
        "{}",
        stderr(&output)
    );
}
