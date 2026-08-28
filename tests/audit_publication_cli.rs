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

mod support;

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
    let outside = support::run_root().join(format!("publication-owners-{serial}.txt"));
    std::fs::write(&outside, "PrivateOrg\n").unwrap();

    let root = support::run_root().join(format!("publication-{serial}"));
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
    let status = Command::new(support::real_git())
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
    let origin = support::scratch("publication-origin");
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
    let stale = Command::new(support::real_git())
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

/// A forge that retains no pull-request head refs is a fact, not an unread
/// surface.
///
/// The empty log these two produce is identical, and the difference between them
/// is this subcommand's exit code: "the forge retains none" is something the
/// audit established, and "the fetch matched nothing" is a published surface
/// nobody opened. Both went into the unreadable list, so a repository that has
/// never opened a pull request could not reach exit 0 through this path however
/// clean it was -- and a check that always answers "could not look" is one its
/// reader stops reading.
#[test]
fn a_forge_retaining_no_pull_refs_is_not_an_unread_surface() {
    let root = repository();
    // A real remote, because the question is what `ls-remote` says about it: a
    // bare repository with no `refs/pull/*` retains none, which is the fact.
    let origin = support::scratch("publication-no-pulls");
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

    let report = text(&audit(&root));
    assert!(
        !report.contains("refs/pull/*/head fetched no commits"),
        "a forge that retains none was reported as a surface this run failed to \
         read:\n{report}"
    );
    let _ = std::fs::remove_dir_all(&origin);
}

/// The reachable blobs are read by one process, and the run says how far it got.
///
/// This spawned `git cat-file blob <sha>` once per object, with no cap and
/// nothing printed between the first and the last. On a repository whose
/// reachable set runs to five figures that is five figures of process spawns in
/// silence, and from outside a slow audit and a hung one look the same -- so the
/// reader's only move is to kill it, which answers nothing.
#[test]
fn a_large_reachable_set_is_read_in_one_pass_and_reports_progress() {
    let root = repository();
    for index in 0..2100_u32 {
        std::fs::write(
            root.join(format!("blob-{index:05}.txt")),
            format!("blob number {index}\n"),
        )
        .unwrap();
    }
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "many", "--no-verify"]);

    let output = audit(&root);
    let report = text(&output);
    assert!(
        report.contains("reading") && report.contains("reachable object(s)"),
        "a run this size said nothing about what it was doing:\n{report}"
    );
    assert!(
        report.contains("object(s)") && report.contains("read "),
        "the run never said how far it had got:\n{report}"
    );
}

/// A bare repository standing in for the forge, wired up as `origin`.
///
/// The fetch is what prunes and the fetch is what brings the retained pull
/// refs down, so a fixture with no remote at all reports every ref-shaped
/// surface unreadable and never walks one. Nothing here reaches a network: a
/// local bare repository answers `fetch` and `ls-remote` exactly as a forge
/// does for the questions this subcommand asks.
fn origin_for(root: &Path, kind: &str) -> PathBuf {
    let origin = support::scratch(kind);
    let _ = std::fs::remove_dir_all(&origin);
    git(root, &["init", "-q", "--bare", origin.to_str().unwrap()]);
    git(root, &["remote", "add", "origin", origin.to_str().unwrap()]);
    origin
}

/// Run the audit with a stub `gh` ahead of the real one on PATH.
///
/// Every forge surface this subcommand reads goes through `gh`, and on a
/// machine with no logged-in account -- CI included -- every one of those calls
/// fails at the LISTING, which is the one path the rest of this file exercises.
/// So the reads that succeed, and the fields they ask for, were never executed
/// by any test: a title dropped from the `--json` list, a review body never
/// requested, an `api` route pointed at the wrong pull request would each have
/// left the suite green.
///
/// The stub answers the same way the forge does -- keyed on the arguments -- so
/// a test asserting that a name in a title is found FAILS when the code stops
/// asking for the title, rather than passing on a stub that answers everything.
fn audit_with_gh(root: &Path, body: &str) -> Output {
    let bin = root.join("stub-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let gh = bin.join("gh");
    std::fs::write(&gh, format!("#!/bin/sh\n{body}")).unwrap();
    // The real git ahead of whatever the developer's PATH puts there, for the
    // reason `support::real_git` states: a `git` shim is a link to this binary
    // and loads the policy of the tree it is invoked in before running
    // anything, so on a machine with one installed the shim rather than the
    // audit would decide what these fixtures answer.
    //
    // Guarded like the mode bits below it: this helper writes a `#!/bin/sh`
    // stub and is Unix-shaped throughout, and an unguarded `std::os::unix` call
    // would be the one line that stops the suite COMPILING elsewhere rather
    // than merely failing.
    #[cfg(unix)]
    {
        let _ = std::os::unix::fs::symlink(support::real_git(), bin.join("git"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["audit", "--for-publication"])
        .current_dir(root)
        .env(
            "PATH",
            format!(
                "{}:{}",
                bin.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env_remove("UPHOLD_ALLOW")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

/// Exit 0 is reachable from a repository, not only from `verdict(0, 0)`.
///
/// The unit test says the ranking returns clean for a run that read everything
/// and found nothing. It cannot say that a run can get there, and for most of
/// this subcommand's life none could: the standing caveat sat in the measured
/// list, so the clean arm was unreachable code while the reference
/// documentation described the exit 0 nobody could observe. Every other fixture
/// in this file has an unreachable forge and therefore asserts on 1 or 2, which
/// is why the arm stayed unexecuted after it was fixed. A check whose pass
/// nobody has seen is a check that gets switched off the first time it is
/// wrong.
#[test]
fn a_run_that_read_every_surface_and_found_nothing_exits_clean() {
    let root = repository();
    let origin = origin_for(&root, "publication-clean-origin");
    std::fs::write(root.join("a.txt"), "nothing to see\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);
    git(&root, &["push", "-q", "origin", "main"]);

    // A forge with no issues and no pull requests: both listings succeed and
    // come back empty, which is an answer and not a failure to look.
    let output = audit_with_gh(&root, "exit 0\n");
    let report = text(&output);
    assert_eq!(code(&output), 0, "{report}");
    assert!(
        report.contains("every surface a flip would republish was read"),
        "{report}"
    );
    // Still said, on a clean run: the caveat is a permanent property of the
    // tool, and a green exit that stopped mentioning it would read as a claim
    // about the one surface nothing can reach.
    assert!(report.contains("standing caveat"), "{report}");
    assert!(!report.contains("could NOT be read"), "{report}");
    let _ = std::fs::remove_dir_all(&origin);
}

/// A private name in an issue TITLE is found.
///
/// The largest hole this subcommand had: it asked the forge for `body,comments`
/// and printed the conversation as read, over a field it never opened.
/// `-t/--title` is the exact field the `gh` cmd-shim guards on `gh issue
/// create`, so a title is text this repository already refuses to publish
/// knowingly -- and a flip republishes it in the same breath as the body under
/// it.
///
/// The stub answers a title only when the code asks for one, so dropping
/// `title` from the `--json` list fails this test rather than passing it.
#[test]
fn a_private_name_in_an_issue_title_is_found() {
    let root = repository();
    std::fs::write(root.join("a.txt"), "nothing to see\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);

    let output = audit_with_gh(
        &root,
        r#"case "$1 $2" in
  "issue list") echo 4 ;;
  "issue view") case "$5" in *title*) echo 'the PrivateOrg outage' ;; esac ;;
esac
"#,
    );
    let report = text(&output);
    assert_eq!(
        code(&output),
        1,
        "a name in an issue title is republished by the flip:\n{report}"
    );
    assert!(
        report.contains("issue #4 title, body and comments"),
        "{report}"
    );
}

/// Review bodies and review-thread comments are read, and per pull request.
///
/// Both are separate objects from issue comments and arrive on neither `.body`
/// nor `.comments`, so the conversation read that stops at those two reports
/// clean over them. A review body is where the reasoning on a pull request goes
/// -- which is where a private sibling gets named -- and a review comment is
/// pinned to a diff line, which is the context in which somebody quotes a path,
/// a host, or an internal repository.
///
/// The stub answers the `api` route only for the pull request being read, so a
/// route that drifted off `{owner}`, `{repo}` or the number would come back
/// empty and fail this test.
#[test]
fn a_private_name_in_a_review_body_or_a_review_thread_comment_is_found() {
    let root = repository();
    std::fs::write(root.join("a.txt"), "nothing to see\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);

    let output = audit_with_gh(
        &root,
        r#"case "$1" in
  pr) case "$2" in
        list) echo 12 ;;
        view) case "$5" in reviews) echo 'as we did in PrivateOrg' ;; esac ;;
      esac ;;
  api) case "$2" in *"/pulls/12/comments") echo 'see the PrivateOrg mirror' ;; esac ;;
esac
"#,
    );
    let report = text(&output);
    assert_eq!(code(&output), 1, "{report}");
    assert!(report.contains("pr #12 review bodies"), "{report}");
    assert!(report.contains("pr #12 review-thread comments"), "{report}");
}

/// A `gh` that fails without a word still names the call and its exit code.
///
/// "Could not be read" with nothing beside it is a line nobody can act on --
/// not logged in, no such repository and rate limited are three different
/// things to go and do. When `gh` writes nothing at all, its exit code is the
/// only fact there is, and a note that dropped it would leave the reader
/// nothing to distinguish this from the surfaces that were merely empty.
#[test]
fn a_forge_call_that_fails_without_a_word_is_reported_with_its_exit_code() {
    let root = repository();
    std::fs::write(root.join("a.txt"), "nothing to see\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);

    let output = audit_with_gh(&root, "exit 3\n");
    let report = text(&output);
    assert_eq!(
        code(&output),
        2,
        "a surface that could not be read is never clean:\n{report}"
    );
    assert!(report.contains("issues could not be listed"), "{report}");
    assert!(report.contains("exited 3"), "{report}");
}

/// A conversation that was LISTED and then could not be read is named, one by
/// one and by which half of it failed.
///
/// The listing succeeding is the case where the count in the report is right
/// and its coverage is not: the audit knows the issue and the pull request are
/// there, prints `n surface(s) read`, and a reader takes that for the whole
/// conversation. Each of the three reads fails on its own -- a comment thread
/// route is a different API call from the review bodies above it and from the
/// issue view above that -- so a note that named the pull request without
/// saying which half went unread would send its reader to look at the part
/// that was fine.
#[test]
fn a_conversation_that_was_listed_and_then_failed_is_named_read_by_read() {
    let root = repository();
    std::fs::write(root.join("a.txt"), "nothing to see\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);

    // Listing works; every read of what it listed does not -- a token that can
    // see the repository and not its conversations, which is what a
    // fine-grained one without the issues scope does.
    let output = audit_with_gh(
        &root,
        r#"case "$1 $2" in
  "issue list") echo 4 ;;
  "pr list") echo 12 ;;
  *) echo 'HTTP 403: Resource not accessible by personal access token' >&2 ; exit 1 ;;
esac
"#,
    );
    let report = text(&output);
    assert_eq!(
        code(&output),
        2,
        "a conversation that could not be read is never clean:\n{report}"
    );
    assert!(report.contains("issue #4 could not be read"), "{report}");
    assert!(
        report.contains("pr #12 review bodies could not be read"),
        "{report}"
    );
    assert!(
        report.contains("pr #12 review-thread comments could not be read"),
        "{report}"
    );
    // The reason `gh` gave, not the fact that it failed: not logged in, no such
    // repository and rate limited are three different things to go and do.
    assert!(report.contains("Resource not accessible"), "{report}");
}

/// An audit that could not run git refuses rather than reporting a tree it
/// never read.
///
/// A repository with no commits is the smallest version of it: `git rev-list
/// --objects HEAD` has no revision to walk and exits non-zero, and every
/// surface below that read is empty for a reason that has nothing to do with
/// the repository being clean. Swallowed, an empty object walk reads as `0
/// surface(s)` and a clean report -- which is `UNKNOWN -> PASS` on the one
/// subcommand that exists to say what it could not see.
#[test]
fn an_object_walk_that_git_refused_is_not_reported_as_an_empty_tree() {
    let root = repository();
    let output = audit(&root);
    let report = text(&output);
    assert_eq!(code(&output), 2, "{report}");
    assert!(
        report.contains("the audit cannot see what it claims to check"),
        "{report}"
    );
}

/// A commit that exists only on a retained pull-request head ref is read.
///
/// The surface named in the module docstring as the one a rewrite does not
/// touch: a forge keeps `refs/pull/<n>/head` permanently and renders it on the
/// closed pull request, and a clone does not carry it. So the fetch is the only
/// thing standing between the reader and a clean report over a commit message
/// that will still be served, by sha, after the default-branch rewrite this
/// audit exists to trigger.
#[test]
fn a_commit_only_on_a_retained_pull_ref_is_read() {
    let root = repository();
    let origin = origin_for(&root, "publication-retained-origin");
    std::fs::write(root.join("a.txt"), "nothing to see\n").unwrap();
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "one", "--no-verify"]);
    git(&root, &["push", "-q", "origin", "main"]);

    // The name is in the MESSAGE and not in the file, so the finding can only
    // have come from walking the retained ref rather than from the blob.
    std::fs::write(root.join("b.txt"), "an ordinary change\n").unwrap();
    git(&root, &["add", "-A"]);
    git(
        &root,
        &["commit", "-qm", "as PrivateOrg asked", "--no-verify"],
    );
    git(&root, &["push", "-q", "origin", "HEAD:refs/pull/7/head"]);
    // Off every branch, the way a closed pull request's head is: nothing but
    // the forge's retained ref reaches this commit now.
    git(&root, &["reset", "-q", "--hard", "HEAD~1"]);

    let output = audit(&root);
    let report = text(&output);
    assert_eq!(
        code(&output),
        1,
        "a closed pull request's head ref outlives the rewrite:\n{report}"
    );
    assert!(report.contains("retained pull ref"), "{report}");
    let _ = std::fs::remove_dir_all(&origin);
}
