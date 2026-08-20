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

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn repository(policy: &str) -> PathBuf {
    let root = support::scratch("sets");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();

    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.name", "Test"]);
    git(&root, &["config", "user.email", "test@example.test"]);

    std::fs::write(root.join("policy/principles.toml"), policy).unwrap();
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

/// Run a guard with a stub `gh` ahead of the real one on PATH.
///
/// The two failure modes this distinguishes are only distinguishable by what
/// `gh` writes to stderr, so the only honest test drives a `gh` that writes
/// each. A test that called the classifier directly would be asserting on the
/// function rather than on the behaviour a repository gets.
fn guard_with_gh(root: &Path, stderr_line: &str, args: &[&str]) -> Output {
    guard_with_stub_gh(root, &format!("echo '{stderr_line}' >&2\nexit 1\n"), args)
}

/// The same, for a stub that ANSWERS rather than fails.
///
/// The falsifier's whole subject is the difference between a forge saying
/// `public`, a forge saying `private`, and a forge that said neither, so a
/// helper that can only produce the third would leave two of the three states
/// untested. `guard_with_gh` above is this one with its body written for it.
fn guard_with_stub_gh(root: &Path, body: &str, args: &[&str]) -> Output {
    let bin = root.join("stub-bin");
    std::fs::create_dir_all(&bin).unwrap();
    let gh = bin.join("gh");
    std::fs::write(&gh, format!("#!/bin/sh\n{body}")).unwrap();
    // The real git, ahead of whatever the developer's PATH puts there. A `git`
    // shim loads the policy of the tree it is invoked in and fails closed when
    // that policy will not load -- so on a machine with one installed, the shim
    // rather than the guard would decide what `git remote get-url` answers in
    // this fixture, and a guard that reads `origin` would be testing the
    // installed binary instead of this one.
    //
    // Guarded like the mode bits below it: this file writes `#!/bin/sh` stubs
    // and is Unix-shaped throughout, and an unguarded `std::os::unix` call in
    // the middle of it would be the one line that stops the suite COMPILING
    // elsewhere rather than merely failing.
    #[cfg(unix)]
    {
        let _ = std::os::unix::fs::symlink(support::real_git(), bin.join("git"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&gh, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .arg("guard")
        .args(args)
        .current_dir(root)
        .env("PATH", path)
        .env_remove("UPHOLD_ALLOW")
        .stdin(Stdio::null())
        .output()
        .unwrap()
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

/// The check at both stages the bundled set now registers it at: `pre-commit`,
/// where a policy file changes, and `manual`, where the whole sweep is asked
/// for. The two answer different questions and the tests below ask both.
const AUDIT_SHIPPED: &str = r#"
[rule.local-set-audit]
builtin = "no-hand-copied-base-rule"

[rule.local-set-audit.git]
hooks = ["pre-commit", "manual"]
"#;

/// A transcription of a rule `process-residue` already ships.
const COPIED: &str = r#"
[rule.no-merge-conflict-markers]
message = "conflict markers"
regexp = '^(<<<<<<<|>>>>>>>) '
files.include = ["."]
"#;

/// A second one, from a different set, so a test can add one transcription to a
/// policy that already has another and see which of the two is reported.
const COPIED_TOO: &str = r#"
[rule.no-hardcoded-home-paths]
message = "home paths"
regexp = '/home/[a-z]+'
files.include = ["."]
"#;

fn commit_policy(root: &Path, policy: &str) {
    std::fs::write(root.join("policy/principles.toml"), policy).unwrap();
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "policy", "--no-verify"]);
}

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
fn a_transcription_this_change_adds_is_refused_at_pre_commit() {
    // The whole point of the hook. `manual` reported this and nobody ran it:
    // 76 of 77 repositories inherited the set carrying the check and roughly
    // forty carried a transcription it had never once reported.
    let root = repository("");
    commit_policy(&root, &format!("{AUDIT_SHIPPED}{COPIED}"));
    // Committed above, so the copy that is NEW is the second one.
    std::fs::write(
        root.join("policy/principles.toml"),
        format!("{AUDIT_SHIPPED}{COPIED}{COPIED_TOO}"),
    )
    .unwrap();

    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("no-hardcoded-home-paths"), "{text}");
    // And it says nothing about the one that was already there. A refusal that
    // listed both would send the reader looking for a change they did not make.
    assert!(!text.contains("no-merge-conflict-markers"), "{text}");
    assert!(text.contains("this change adds"), "{text}");
}

#[test]
fn a_transcription_already_committed_is_not_refused_at_pre_commit() {
    // The ratchet, and it is what makes the hook installable at all. Arriving
    // as a gate over declarations that already exist would refuse the next
    // commit in roughly forty repositories on the strength of a version bump,
    // with nothing in any of those trees to review.
    let root = repository("");
    commit_policy(&root, &format!("{AUDIT_SHIPPED}{COPIED}"));
    std::fs::write(root.join("a.txt"), "one\n").unwrap();

    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));

    // Still the sweep, though: the copy has not become invisible, it has become
    // something a reader asks about rather than something a commit trips over.
    let swept = guard(&root, &["--stage", "manual"]);
    assert_eq!(code(&swept), 1, "{}", stderr(&swept));
    assert!(
        stderr(&swept).contains("no-merge-conflict-markers"),
        "{}",
        stderr(&swept)
    );
}

#[test]
fn a_policy_file_git_has_never_seen_has_no_baseline_to_be_old_against() {
    // A repository adopting uphold writes its whole policy in one commit, and
    // every id in it is an id being written now. Answering "no baseline, so
    // nothing is new" would let the first commit carry any number of
    // transcriptions past the check that exists to see them.
    let root = repository(&format!("{AUDIT_SHIPPED}{COPIED}"));

    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no-merge-conflict-markers"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_baseline_that_would_not_parse_is_reported_as_one_rather_than_as_an_empty_one() {
    // The commit that REPAIRS a broken policy file. Folding "HEAD would not
    // parse" into "HEAD declared nothing" would report every transcription
    // already in the file as one this change introduced -- a measurement
    // printed over a comparison that never happened, in the one commit whose
    // author is fixing the thing that broke it.
    let root = repository("");
    commit_policy(&root, "this is not toml at all\n[[[\n");
    std::fs::write(
        root.join("policy/principles.toml"),
        format!("{AUDIT_SHIPPED}{COPIED}"),
    )
    .unwrap();

    let output = guard(&root, &["--stage", "pre-commit"]);
    // Still refused: a comparison that could not be made is not one that
    // passed.
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("no-merge-conflict-markers"), "{text}");
    // And it says the comparison did not happen, so "this change adds" is not
    // read as a measurement.
    assert!(text.contains("could not be parsed"), "{text}");
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

// ---------------------------------------------------------------------------
// The guard sets, and the one field that lets a set carry a push guard.
// ---------------------------------------------------------------------------

fn write(root: &Path, relative: &str, contents: &str) {
    std::fs::write(root.join(relative), contents).unwrap();
}

fn commit_one(root: &Path) {
    write(root, "a.txt", "one\n");
    git(root, &["add", "-A"]);
    git(root, &["commit", "-qm", "one", "--no-verify"]);
}

#[test]
fn a_refusal_from_an_inherited_guard_set_names_the_set() {
    // The case set provenance was built for, now that a set can carry a guard:
    // this policy contains no `[rule.prevent-ai-author]` at all, and a reader
    // grepping for the id that refused them would find nothing.
    let root = repository("[inherit]\nsets = [\"commit-message-residue\"]\n");
    write(&root, "msg.txt", "x\n\nGenerated with Claude Code\n");

    let output = guard(&root, &["--stage", "commit-msg", "--message", "msg.txt"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("prevent-ai-author [set: commit-message-residue]"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn unowned_push_refuses_to_guess_who_this_repository_is() {
    // A set carrying `prevent-public-push` with nothing pinned would be
    // deciding, for every repository that inherits it, that origin is who they
    // are -- which is the mode that cannot catch the accident the guard exists
    // for. Exit 2: not a refusal of the push, an answer that it could not be
    // judged.
    let root = repository("[inherit]\nsets = [\"unowned-push\"]\n");
    commit_one(&root);
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
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("owner_required"), "{text}");
    assert!(text.contains("owner = \"acme\""), "{text}");
}

#[test]
fn an_owner_declared_once_for_the_policy_answers_for_an_inherited_rule() {
    // Where the owner goes when the rule is not in this file: the top of the
    // policy, because a rule arriving from a set cannot be handed a parameter
    // and identity was never a property of one rule.
    let root = repository("owner = \"acme\"\n\n[inherit]\nsets = [\"unowned-push\"]\n");
    commit_one(&root);

    let allowed = guard(
        &root,
        &[
            "--stage",
            "pre-push",
            "--remote-url",
            "https://github.com/acme/widget.git",
        ],
    );
    assert_eq!(code(&allowed), 0, "{}", stderr(&allowed));
    // Declared, so it is the strong mode and has nothing to report.
    assert!(!stderr(&allowed).contains("DERIVED FROM ORIGIN"));

    let refused = guard(
        &root,
        &[
            "--stage",
            "pre-push",
            "--remote-url",
            "https://github.com/someone-else/thing.git",
        ],
    );
    assert_eq!(code(&refused), 1, "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("pinned to acme"),
        "{}",
        stderr(&refused)
    );
}

#[test]
fn private_names_refuses_to_guess_whether_this_repository_is_published() {
    // The `unowned-push` shape, transposed to the other fact a set cannot be
    // handed. These guards fire on ONE condition -- is this tree public -- and
    // left to itself the answer comes from the forge, which is unknown with no
    // token, unknown with no network, and stale on the day a repository is
    // flipped. Exit 2: not "this text is wrong", but "nothing here can tell".
    let root = repository("[inherit]\nsets = [\"private-names\"]\n");
    commit_one(&root);
    write(&root, "msg.txt", "a message\n");

    let output = guard(&root, &["--stage", "commit-msg", "--message", "msg.txt"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("visibility_required"), "{text}");
    // And it prints the line to write, because a refusal that names a field
    // without saying where it goes sends the reader to the documentation.
    assert!(text.contains("visibility = \"private\""), "{text}");
}

#[test]
fn a_visibility_declared_once_for_the_policy_answers_for_an_inherited_rule() {
    // Where the answer goes when the rule is not in this file. `private` is a
    // real answer and not an opt-out: it says the condition these guards fire
    // under does not hold here, which is a decision somebody made rather than a
    // question nobody asked.
    let root = repository("visibility = \"private\"\n\n[inherit]\nsets = [\"private-names\"]\n");
    commit_one(&root);
    write(&root, "msg.txt", "a message\n");

    let output = guard(&root, &["--stage", "commit-msg", "--message", "msg.txt"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn an_unreadable_owner_source_is_exit_two_unless_the_policy_said_it_may_be_absent() {
    // The default, first: a rule with no owners refuses nothing, so a source
    // that could not be read must not be folded into "there were none".
    let source = "private_owners_from = \"cat no-such-file-anywhere\"\n";
    let root = repository(&format!(
        "visibility = \"public\"\n{source}\n[inherit]\nsets = [\"private-names\"]\n"
    ));
    commit_one(&root);
    write(&root, "msg.txt", "a message\n");

    let refused = guard(&root, &["--stage", "commit-msg", "--message", "msg.txt"]);
    assert_eq!(code(&refused), 2, "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("private_owners_optional"),
        "{}",
        stderr(&refused)
    );

    // And the declared exemption, for a policy that is cloned onto machines
    // that will not have the source. It proceeds -- and says what it stopped
    // checking, which is the whole difference from a command that swallows its
    // own failure.
    std::fs::write(
        root.join("policy/principles.toml"),
        format!(
            "visibility = \"public\"\n{source}private_owners_optional = true\n\n\
             [inherit]\nsets = [\"private-names\"]\n"
        ),
    )
    .unwrap();

    let allowed = guard(&root, &["--stage", "commit-msg", "--message", "msg.txt"]);
    assert_eq!(code(&allowed), 0, "{}", stderr(&allowed));
    let text = stderr(&allowed);
    assert!(text.contains("NOT checked here"), "{text}");
    assert!(text.contains("named on its own"), "{text}");
}

#[test]
fn permitting_an_absent_owner_source_that_no_rule_reads_is_refused_at_load() {
    // A permission over a source that does not exist reads as though somebody
    // thought about it, and there is nothing for it to permit.
    let root = repository(
        "visibility = \"public\"\nprivate_owners_optional = true\n\n\
         [inherit]\nsets = [\"private-names\"]\n",
    );
    commit_one(&root);

    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("permits a failure that cannot happen"),
        "{}",
        stderr(&output)
    );
}

/// A policy whose private-name guard reads a commit message, with a name the
/// stub `gh` will be asked about. The URL form, because a bare `owner/repo` is
/// only extracted for a declared owner.
const NAMES_AT_COMMIT: &str = "visibility = \"public\"\n\n\
     [rule.no-private-repo-names]\nbuiltin = \"no-private-repo-names\"\n\n\
     [rule.no-private-repo-names.git]\nhooks = [\"commit-msg\"]\n";

#[test]
fn a_forge_that_could_not_be_asked_is_exit_two_and_not_an_inconclusive_finding() {
    // The distinction the whole split exists for. `gh` unauthenticated,
    // rate-limited, or absent means this guard DID NOT RUN -- and folding that
    // into "could not be resolved" made an unauthenticated run print a line per
    // name and then permit the commit, which is a check that did not happen
    // wearing the output of one that did.
    let root = repository(NAMES_AT_COMMIT);
    commit_one(&root);
    write(&root, "msg.txt", "see https://github.com/acme/widget\n");

    let output = guard_with_gh(
        &root,
        "gh: Bad credentials (HTTP 401)",
        &["--stage", "commit-msg", "--message", "msg.txt"],
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("could not be asked"), "{text}");
    assert!(text.contains("did not run"), "{text}");
}

#[test]
fn a_forge_that_answered_no_such_repository_is_a_finding_and_not_exit_two() {
    // The other side, and it is why the split is not just "fail closed". An
    // authenticated `gh` answers 404 for every invented name in a document --
    // `acme/widget` in this repository's own tests and README. Treating that as
    // "the check did not happen" would make a tree full of examples unusable,
    // which is the state `refuse_unknown` exists to let a repository choose.
    let root = repository(NAMES_AT_COMMIT);
    commit_one(&root);
    write(&root, "msg.txt", "see https://github.com/acme/widget\n");

    let output = guard_with_gh(
        &root,
        "gh: Not Found (HTTP 404)",
        &["--stage", "commit-msg", "--message", "msg.txt"],
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("could not be resolved"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn refuse_unknown_governs_the_answer_and_not_the_absence_of_one() {
    // `refuse_unknown` turns the 404 case into a refusal. It must NOT be what
    // decides the unavailable case: that one is exit 2 either way, because a
    // field about what an answer means cannot speak for a run that got none.
    let strict = NAMES_AT_COMMIT.replace(
        "builtin = \"no-private-repo-names\"",
        "builtin = \"no-private-repo-names\"\nrefuse_unknown = true",
    );
    let root = repository(&strict);
    commit_one(&root);
    write(&root, "msg.txt", "see https://github.com/acme/widget\n");

    let answered = guard_with_gh(
        &root,
        "gh: Not Found (HTTP 404)",
        &["--stage", "commit-msg", "--message", "msg.txt"],
    );
    assert_eq!(code(&answered), 1, "{}", stderr(&answered));
    assert!(
        stderr(&answered).contains("refuse_unknown"),
        "{}",
        stderr(&answered)
    );

    let unasked = guard_with_gh(
        &root,
        "gh: Bad credentials (HTTP 401)",
        &["--stage", "commit-msg", "--message", "msg.txt"],
    );
    assert_eq!(code(&unasked), 2, "{}", stderr(&unasked));
}

#[test]
fn a_name_known_to_be_private_survives_a_name_nothing_could_answer_for() {
    // The exit-state ranking this repository documents and proves: 1 when
    // something was found, 2 when nothing was found and something could not be
    // read, 0 only when everything was read and was clean.
    //
    // The unavailable check used to return before the report was built, so a
    // private name the guard had ALREADY caught was discarded -- unprinted,
    // exit 2 -- because some unrelated name in the same text had no answer.
    // The name the guard exists to catch is the one that has to survive.
    let root = repository(
        "visibility = \"public\"\n\n\
         [rule.no-private-repo-names]\nbuiltin = \"no-private-repo-names\"\n\
         private_owners = [\"secretcorp\"]\n\n\
         [rule.no-private-repo-names.git]\nhooks = [\"commit-msg\"]\n",
    );
    commit_one(&root);
    // One name a declared owner settles with no network at all, and one the
    // stub `gh` cannot answer for.
    write(
        &root,
        "msg.txt",
        "see secretcorp/thing and https://github.com/acme/widget\n",
    );

    let output = guard_with_gh(
        &root,
        "gh: Bad credentials (HTTP 401)",
        &["--stage", "commit-msg", "--message", "msg.txt"],
    );
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let text = stderr(&output);
    // The finding, which is the whole point.
    assert!(text.contains("secretcorp/thing"), "{text}");
    // And the unread part, said alongside rather than instead of it.
    assert!(text.contains("could not be asked"), "{text}");
}

#[test]
fn a_source_declared_in_an_inherited_file_satisfies_the_optional_permission() {
    // The check reads the RESOLVED policy. Asked of `file.rules` alone it
    // refused a policy whose source is declared in an `inherit.paths` file,
    // with a sentence saying no source is declared anywhere -- false of exactly
    // the shape it was refusing.
    let root = repository(
        "visibility = \"public\"\nprivate_owners_optional = true\n\n\
         [inherit]\npaths = [\"policy/shared.toml\"]\n",
    );
    std::fs::write(
        root.join("policy/shared.toml"),
        "[rule.no-private-repo-names]\nbuiltin = \"no-private-repo-names\"\n\
         private_owners_from = \"printf 'secretcorp\\n'\"\n\n\
         [rule.no-private-repo-names.git]\nhooks = [\"commit-msg\"]\n",
    )
    .unwrap();
    commit_one(&root);
    write(&root, "msg.txt", "a message\n");

    let output = guard(&root, &["--stage", "commit-msg", "--message", "msg.txt"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_word_that_is_not_a_visibility_is_refused_at_load() {
    // At LOAD, not when a hook fires. A misspelt visibility is a fact about the
    // file, and hearing about it from whichever seam happened to run first is
    // hearing about it months after the line was written -- by which time the
    // guard has been reporting a clean tree the whole way.
    let root = repository("visibility = \"pubic\"\n\n[inherit]\nsets = [\"private-names\"]\n");
    commit_one(&root);

    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("not a visibility"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn naming_the_destinations_is_a_way_of_saying_who_you_are() {
    // `owner_required` is satisfied by an allow-list too. A repository whose
    // pushes legitimately go somewhere other than its own owner -- a fork, a
    // mirror -- has answered the question in the only form the guard needed,
    // and demanding a second declaration of the same fact is ceremony.
    let root = repository(
        "[rule.prevent-public-push]\nbuiltin = \"prevent-public-push\"\nowner_required = true\n\
         allowed_repos = [\"other/thing\"]\n\n[rule.prevent-public-push.git]\nhooks = [\"pre-push\"]\n",
    );
    commit_one(&root);

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
}

#[test]
fn every_guard_set_declares_the_stages_its_rules_install() {
    // The ceiling and the rules have to agree, and nothing else checks that
    // they do for a set that is inside its ceiling: a set admitting
    // `pre-commit` while shipping nothing at `pre-commit` is a permission
    // granted for no reason, and the next rule added to it inherits that
    // permission silently.
    for name in [
        "commit-message-residue",
        "unreviewed-history",
        "invisible-characters",
        "stale-pins",
        "unowned-push",
    ] {
        let root = repository(&format!("[inherit]\nsets = [\"{name}\"]\n"));
        let listed = Command::new(env!("CARGO_BIN_EXE_uphold"))
            .args(["rules", "--set", name])
            .current_dir(&root)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&listed.stdout).into_owned();
        assert!(
            text.contains("may install at:"),
            "{name} declares no stage and it carries guards: {text}"
        );
    }
}

// ---------------------------------------------------------------------------
// A repository fact declared somewhere other than the policy file.
//
// `owner` and `visibility` are declared once per repository, which across one
// fleet means 78 copies of an `owner` line for seven distinct values. Reading
// the value from a command is the shape `private_owners_from` already uses, and
// the cases below are about the thing that makes it safe: it is a DECLARATION
// moved out of the tree, never a lookup of the fact being guarded, so every way
// it can fail to answer is exit 2 rather than the fallback it replaced.
// ---------------------------------------------------------------------------

#[test]
fn an_owner_read_from_a_command_pins_a_push_the_way_a_written_one_does() {
    // The pin, and the half that proves it is a pin: `unowned-push` sets
    // `owner_required`, so a repository the guard considers unpinned exits 2
    // with the line to write. Exit 0 here means the command answered and the
    // answer was treated as the declaration, not as a guess off `origin`.
    let root =
        repository("owner_from = \"printf 'acme\\n'\"\n\n[inherit]\nsets = [\"unowned-push\"]\n");
    commit_one(&root);

    let allowed = guard(
        &root,
        &[
            "--stage",
            "pre-push",
            "--remote-url",
            "https://github.com/acme/widget.git",
        ],
    );
    assert_eq!(code(&allowed), 0, "{}", stderr(&allowed));
    // And it is the pinned mode, not the derived one. The guard says so on the
    // allow path precisely because a derived owner allows everything it should
    // have refused, and never mentions it.
    assert!(
        !stderr(&allowed).contains("DERIVED FROM ORIGIN"),
        "{}",
        stderr(&allowed)
    );

    let refused = guard(
        &root,
        &[
            "--stage",
            "pre-push",
            "--remote-url",
            "https://github.com/someone-else/widget.git",
        ],
    );
    assert_eq!(code(&refused), 1, "{}", stderr(&refused));
}

#[test]
fn an_owner_source_that_failed_is_exit_two_and_not_the_owner_read_off_origin() {
    // The whole reason there is no `owner_optional` beside this. An unreadable
    // private-owner list degrades to a NARROWER check, which can be reported and
    // lived with; an unreadable owner degrades to the owner read off `origin`,
    // which is the tautology `prevent-public-push` exists to refuse. So the
    // failure has to be louder than the fallback, not quieter.
    let root = repository(
        "owner_from = \"cat no-such-file-anywhere\"\n\n[inherit]\nsets = [\"unowned-push\"]\n",
    );
    commit_one(&root);

    let output = guard(
        &root,
        &[
            "--stage",
            "pre-push",
            "--remote-url",
            "https://github.com/someone-else/widget.git",
        ],
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("owner_from"), "{text}");
    // Naming what it would otherwise have fallen back to, because a reader who
    // cannot see the difference between exit 1 and exit 2 here will assume the
    // guard did its job.
    assert!(text.contains("read off `origin`"), "{text}");
}

#[test]
fn a_source_that_answers_more_than_once_is_refused_rather_than_read_partly() {
    // This is one fact about one repository. Taking the first line would pin the
    // repository to whatever the command happened to print first -- which is a
    // decision nobody made, arriving as a silent success.
    let root = repository(
        "owner_from = \"printf 'acme\\nother\\n'\"\n\n[inherit]\nsets = [\"unowned-push\"]\n",
    );
    commit_one(&root);

    let output = guard(
        &root,
        &[
            "--stage",
            "pre-push",
            "--remote-url",
            "https://github.com/acme/widget.git",
        ],
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("more than one value"),
        "{}",
        stderr(&output)
    );
}

/// A trailing blank line is not a second answer.
///
/// Pinned as a test because it reads as an oversight and is the contract: the
/// rule is one VALUE, not one line of output. `cat` gives a trailing blank line
/// back for any file that ends with one, so counting it would make the field
/// refuse the exact shape it exists for -- and the two-answer case beside it is
/// what the count is actually for.
#[test]
fn a_blank_line_after_the_answer_is_not_a_second_answer() {
    let root = repository(
        "owner_from = \"printf 'acme\\n\\n'\"\n\n[inherit]\nsets = [\"unowned-push\"]\n",
    );
    commit_one(&root);

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
}

#[test]
fn a_source_that_answers_nothing_at_all_is_refused_rather_than_read_as_absent() {
    // Exit 0 and no output is the most dangerous shape a source has: the policy
    // file reads as though the repository declared something, and it declared
    // nothing.
    let root = repository("owner_from = \"true\"\n\n[inherit]\nsets = [\"unowned-push\"]\n");
    commit_one(&root);

    let output = guard(
        &root,
        &[
            "--stage",
            "pre-push",
            "--remote-url",
            "https://github.com/acme/widget.git",
        ],
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("printed nothing"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_visibility_read_from_a_command_decides_whether_the_family_runs() {
    // The scope condition of three guards, arriving from outside the tree. Both
    // directions are asserted in one test on purpose: a `private` that stood the
    // family down for the wrong reason -- because the command failed, say --
    // would be indistinguishable from this one without the `public` half beside
    // it, and standing a disclosure guard down quietly is the failure mode.
    let rule = "[rule.no-private-repo-names]\nbuiltin = \"no-private-repo-names\"\n\
                private_owners = [\"secretcorp\"]\n\n\
                [rule.no-private-repo-names.git]\nhooks = [\"commit-msg\"]\n";
    let root = repository(&format!(
        "visibility_from = \"printf 'private\\n'\"\n\n{rule}"
    ));
    commit_one(&root);
    write(&root, "msg.txt", "see secretcorp/thing\n");

    let stood_down = guard(&root, &["--stage", "commit-msg", "--message", "msg.txt"]);
    assert_eq!(code(&stood_down), 0, "{}", stderr(&stood_down));

    std::fs::write(
        root.join("policy/principles.toml"),
        format!("visibility_from = \"printf 'public\\n'\"\n\n{rule}"),
    )
    .unwrap();

    let fired = guard(&root, &["--stage", "commit-msg", "--message", "msg.txt"]);
    assert_eq!(code(&fired), 1, "{}", stderr(&fired));
    assert!(
        stderr(&fired).contains("secretcorp/thing"),
        "{}",
        stderr(&fired)
    );
}

#[test]
fn a_visibility_source_answering_a_word_that_is_not_a_visibility_is_exit_two() {
    // A written `visibility` is held to the three spellings at load. A command's
    // answer cannot be -- there is no answer until it runs -- so it is held to
    // them as it is read, and the refusal names the command rather than the
    // file, because the file is right and the thing it points at is not.
    let root = repository(
        "visibility_from = \"printf 'pubic\\n'\"\n\n[inherit]\nsets = [\"private-names\"]\n",
    );
    commit_one(&root);
    write(&root, "msg.txt", "a message\n");

    let output = guard(&root, &["--stage", "commit-msg", "--message", "msg.txt"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("visibility_from"), "{text}");
    assert!(text.contains("not a visibility"), "{text}");
}

#[test]
fn one_fact_written_down_and_also_read_from_a_command_is_refused_at_load() {
    // Two statements of one fact, free to disagree, with nothing here to notice
    // when they do -- which is the defect the field exists to remove, arriving
    // through the field.
    for (written, source) in [
        ("owner = \"acme\"", "owner_from = \"printf 'acme\\n'\""),
        (
            "visibility = \"public\"",
            "visibility_from = \"printf 'public\\n'\"",
        ),
    ] {
        let root = repository(&format!(
            "{written}\n{source}\n\n[inherit]\nsets = [\"process-residue\"]\n"
        ));
        commit_one(&root);

        let output = guard(&root, &["--stage", "pre-commit"]);
        assert_eq!(code(&output), 2, "{}", stderr(&output));
        assert!(
            stderr(&output).contains("two statements of one fact"),
            "{}",
            stderr(&output)
        );
    }
}

#[test]
fn a_file_this_repository_did_not_write_may_not_carry_a_command_that_speaks_for_it() {
    // The reason `private-names` gives for not shipping `private_owners_from`,
    // and it is not weakened by the command being one line shorter: a command
    // arriving by inheritance runs in every repository that inherits it on the
    // strength of a version bump, with nothing in any of those trees to review.
    //
    // Refused rather than dropped. An inherited `owner` is read by nothing and
    // says nothing about it, which is the "looks declared, enforced by nobody"
    // shape refused everywhere else here; these two are new and start correct.
    let root = repository("[inherit]\npaths = [\"policy/shared.toml\"]\n");
    std::fs::write(
        root.join("policy/shared.toml"),
        "owner_from = \"printf 'acme\\n'\"\n\n\
         [rule.no-shouting]\nregexp = \"SHOUTING\"\nmessage = \"do not shout\"\n",
    )
    .unwrap();
    commit_one(&root);

    let output = guard(&root, &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("owner_from"),
        "{}",
        stderr(&output)
    );
}

// ---------------------------------------------------------------------------
// The declared visibility, checked against the forge that owns the fact.
//
// `stale-visibility` refuses exactly one state -- a policy claiming privacy over
// a repository the forge serves as public -- because that is the only direction
// a probe can establish and it is the direction that leaks. Every other answer
// is either clean or "could not look", and the cases below are mostly about
// keeping those two apart: a rule that read silence as agreement would disarm
// three disclosure guards on any machine with no credentials.
// ---------------------------------------------------------------------------

/// A repository with an `origin` for the falsifier to ask about.
fn repository_with_origin(policy: &str) -> PathBuf {
    let root = repository(policy);
    git(
        &root,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/acme/widget.git",
        ],
    );
    root
}

/// A stub `gh api` answering the way the real one does: the `--jq` template the
/// lookup passes asks for visibility and full name as one tab-separated line.
fn gh_answers(visibility: &str) -> String {
    format!("printf '{visibility}\\tacme/widget\\n'\nexit 0\n")
}

#[test]
fn a_policy_declaring_public_has_no_claim_of_privacy_and_makes_no_request() {
    // The state most repositories are in, and it must cost them nothing. The
    // stub `gh` fails if it is called at all, so exit 0 here is evidence that
    // no request was made rather than evidence that one succeeded.
    let root = repository_with_origin(
        "visibility = \"public\"\n\n[inherit]\nsets = [\"stale-visibility\"]\n",
    );
    commit_one(&root);

    let output = guard_with_gh(
        &root,
        "gh: Bad credentials (HTTP 401)",
        &["--stage", "pre-push"],
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("no request was made"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn a_declared_privacy_the_forge_serves_as_public_is_refused() {
    // The one refusable state, and the whole reason the rule exists: while the
    // policy says `private` the three private-name guards stand down, over a
    // repository everybody can read.
    let root = repository_with_origin(
        "visibility = \"private\"\n\n[inherit]\nsets = [\"stale-visibility\"]\n",
    );
    commit_one(&root);

    let output = guard_with_stub_gh(&root, &gh_answers("public"), &["--stage", "pre-push"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("acme/widget"), "{text}");
    assert!(text.contains("PUBLIC"), "{text}");
    // And it says where the rule came from, which is the only thing a reader
    // grepping the tree for the id would otherwise not find.
    assert!(text.contains("[set: stale-visibility]"), "{text}");
}

#[test]
fn a_forge_that_agrees_the_repository_is_private_is_clean() {
    let root = repository_with_origin(
        "visibility = \"private\"\n\n[inherit]\nsets = [\"stale-visibility\"]\n",
    );
    commit_one(&root);

    let output = guard_with_stub_gh(&root, &gh_answers("private"), &["--stage", "pre-push"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("the forge agrees"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn a_name_the_forge_will_not_show_us_is_never_read_as_agreement() {
    // The case the whole design turns on. A 404 is the ORDINARY answer for a
    // genuinely private repository asked about without credentials -- and it is
    // also the answer for one that was deleted, renamed, or never existed. A
    // rule that read it as "confirmed private" would let an unauthenticated
    // runner confirm any claim at all, which is fail-open on the one family
    // where fail-open is unacceptable.
    for stderr_line in ["gh: Not Found (HTTP 404)", "gh: Bad credentials (HTTP 401)"] {
        let root = repository_with_origin(
            "visibility = \"private\"\n\n[inherit]\nsets = [\"stale-visibility\"]\n",
        );
        commit_one(&root);

        let output = guard_with_gh(&root, stderr_line, &["--stage", "pre-push"]);
        assert_eq!(code(&output), 2, "{stderr_line}: {}", stderr(&output));
        let text = stderr(&output);
        assert!(text.contains("Could not look is not a pass"), "{text}");
        // Named, because a guard that fails on a machine with no credentials
        // and offers no way past it is a guard somebody deletes.
        assert!(text.contains("UPHOLD_ALLOW=no-stale-visibility"), "{text}");
    }
}

#[test]
fn a_repository_that_declares_no_visibility_has_no_claim_for_this_rule_to_check() {
    // Not a pass. The subject of this rule is a declaration, and with none there
    // is nothing to falsify -- which is a different answer from having checked
    // and found nothing wrong.
    let root = repository_with_origin("[inherit]\nsets = [\"stale-visibility\"]\n");
    commit_one(&root);

    let output = guard_with_stub_gh(&root, &gh_answers("public"), &["--stage", "pre-push"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no \nclaim") || stderr(&output).contains("no claim"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn the_visibility_read_from_a_command_is_the_claim_this_rule_checks() {
    // The two halves of #54 meeting: the declaration comes from outside the
    // tree, and it is still a declaration -- checked against the forge exactly
    // as a written one is, and never replaced by what the forge said.
    let root = repository_with_origin(
        "visibility_from = \"printf 'private\\n'\"\n\n[inherit]\nsets = [\"stale-visibility\"]\n",
    );
    commit_one(&root);

    let output = guard_with_stub_gh(&root, &gh_answers("public"), &["--stage", "pre-push"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(stderr(&output).contains("PUBLIC"), "{}", stderr(&output));
}

#[test]
fn the_falsifier_never_runs_at_a_commit() {
    // The stage decision, asserted rather than trusted to the set file. A guard
    // that adds a network round trip to every commit is one somebody comments
    // out, which is the reason `stale-pins` is off `pre-commit` too.
    let root = repository_with_origin(
        "visibility = \"private\"\n\n[inherit]\nsets = [\"stale-visibility\"]\n",
    );
    commit_one(&root);

    let output = guard_with_stub_gh(&root, &gh_answers("public"), &["--stage", "pre-commit"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}
