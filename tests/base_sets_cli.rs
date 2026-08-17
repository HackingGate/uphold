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
