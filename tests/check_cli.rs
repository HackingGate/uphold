//! CLI-level tests for `uphold check`.
//!
//! Ported from `tests/test_uphold_check.py`, where the reconcile lived until
//! the loader took it over. At the CLI and not the function boundary, for the
//! reason the exit-code contract IS the interface: 0 clean, 1 refused, 2 could
//! not look. A test reaching inside would pass on a change to all three.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

fn workspace() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "uphold-check-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(path.join("policy")).unwrap();
    path
}

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

fn check(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .arg("check")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A consumer pinning the ids the fixtures below rely on. One id installs
/// exactly one git stage, so pinning `uphold-scan` and `uphold-guard-push` is
/// evidence about the file scan and about pre-push and about nothing else.
const PRE_COMMIT: &str = "\
repos:
  - repo: https://github.com/HackingGate/uphold
    rev: v2.0.0
    hooks:
      - id: uphold-scan
      - id: uphold-guard-commit-msg
      - id: uphold-guard-push
  - repo: local
    hooks:
      - id: my-own-check
        name: my own check
";

const SCAN_ONLY: &str = "\
repos:
  - repo: https://github.com/HackingGate/uphold
    rev: v2.0.0
    hooks:
      - id: uphold-scan
";

const GUARD_POLICY: &str = "\
[rule.prevent-public-push]
builtin = \"prevent-public-push\"
git.hooks = [\"pre-push\"]
";

// ── the exit-code contract ───────────────────────────────────────────

#[test]
fn a_missing_declaration_is_two_not_zero() {
    let root = workspace();
    write(&root, "policy/principles.toml", GUARD_POLICY);
    let output = check(&root, &[]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("upheld.toml"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_unreadable_declaration_is_two_not_one() {
    let root = workspace();
    write(&root, "policy/principles.toml", GUARD_POLICY);
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]] this is not toml\n",
    );
    assert_eq!(code(&check(&root, &[])), 2);
}

#[test]
fn an_empty_declaration_is_zero() {
    let root = workspace();
    write(&root, "policy/principles.toml", GUARD_POLICY);
    write(&root, "policy/upheld.toml", "# nothing claimed yet\n");
    write(&root, ".pre-commit-config.yaml", PRE_COMMIT);
    let output = check(&root, &[]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_leftover_tier_field_is_two_not_one() {
    // A declaration written for the old schema is unreadable, not false. `tier`
    // said which namespace `rule` resolved in; ignoring one silently
    // reinterprets the claim, and failing it sends the author looking for a
    // rule that is present.
    let root = workspace();
    write(&root, "policy/principles.toml", GUARD_POLICY);
    write(&root, ".pre-commit-config.yaml", PRE_COMMIT);
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"explicit-unknown\"\ntier = \"local\"\nrule = \"my-own-check\"\n",
    );
    let output = check(&root, &[]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("The field is gone"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_declaration_that_is_not_utf8_is_two_and_not_a_crash() {
    let root = workspace();
    write(&root, "policy/principles.toml", GUARD_POLICY);
    std::fs::write(
        root.join("policy/upheld.toml"),
        b"[[enforce]]\nprinciple = \"\xff\"\n",
    )
    .unwrap();
    assert_eq!(code(&check(&root, &[])), 2);
}

#[test]
fn a_policy_file_that_is_not_utf8_is_two_and_not_a_crash() {
    let root = workspace();
    std::fs::write(
        root.join("policy/principles.toml"),
        b"[rule.prevent-public-push]\nmessage = \"\xff\"\n",
    )
    .unwrap();
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"fail-safe-defaults\"\nrule = \"prevent-public-push\"\n",
    );
    assert_eq!(code(&check(&root, &[])), 2);
}

// ── reconciling one claim ────────────────────────────────────────────

#[test]
fn an_installed_guard_reconciles() {
    let root = workspace();
    write(&root, "policy/principles.toml", GUARD_POLICY);
    write(&root, ".pre-commit-config.yaml", PRE_COMMIT);
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"fail-safe-defaults\"\nrule = \"prevent-public-push\"\n",
    );
    let output = check(&root, &[]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stdout(&output).contains("fail-safe-defaults <- prevent-public-push"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_guard_claim_fails_when_the_stage_it_fires_at_is_not_installed() {
    // The whole reason the answer is per-stage and not per-repository. This
    // pins the file scan and no guard id at all, so the pre-push guard runs
    // nowhere -- and a repository-wide "uphold runs here" reconciled it green.
    let root = workspace();
    write(&root, "policy/principles.toml", GUARD_POLICY);
    write(&root, ".pre-commit-config.yaml", SCAN_ONLY);
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"fail-safe-defaults\"\nrule = \"prevent-public-push\"\n",
    );
    let output = check(&root, &[]);
    assert_eq!(code(&output), 1, "{}", stdout(&output));
    assert!(
        stderr(&output).contains("no seam here supplies"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_unknown_principle_is_refused() {
    let root = workspace();
    write(&root, "policy/principles.toml", GUARD_POLICY);
    write(&root, ".pre-commit-config.yaml", PRE_COMMIT);
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"no-such-principle\"\nrule = \"prevent-public-push\"\n",
    );
    let output = check(&root, &[]);
    assert_eq!(code(&output), 1, "{}", stdout(&output));
    assert!(
        stderr(&output).contains("unknown principle id"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_rule_the_policy_disables_is_refused() {
    // `inherit.disabled_rules` is one of the five fields that decide what runs,
    // and the reason the reconcile cannot read `[rule.*]` tables alone.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        "[inherit]\nsets = [\"process-residue\"]\ndisabled_rules = [\"no-task-tracker-references\"]\n",
    );
    write(&root, ".pre-commit-config.yaml", PRE_COMMIT);
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"single-authoritative-source\"\nrule = \"no-task-tracker-references\"\n",
    );
    let output = check(&root, &[]);
    assert_eq!(code(&output), 1, "{}", stdout(&output));
}

#[test]
fn a_rule_from_a_bundled_base_set_is_supplied() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        "[inherit]\nsets = [\"process-residue\"]\n",
    );
    write(&root, ".pre-commit-config.yaml", PRE_COMMIT);
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"single-authoritative-source\"\nrule = \"no-merge-conflict-markers\"\n",
    );
    let output = check(&root, &[]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_rule_inherited_through_inherit_paths_is_supplied() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        "[inherit]\npaths = [\"policy/extra.toml\"]\n",
    );
    write(
        &root,
        "policy/extra.toml",
        "[rule.from-a-path]\nmessage = \"no\"\nregexp = 'nothing-matches-this'\nfiles.include = [\".\"]\n",
    );
    write(&root, ".pre-commit-config.yaml", PRE_COMMIT);
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"single-authoritative-source\"\nrule = \"from-a-path\"\n",
    );
    let output = check(&root, &[]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn inherit_paths_naming_a_file_that_is_not_there_is_two_not_one() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        "[inherit]\npaths = [\"policy/gone.toml\"]\n",
    );
    write(&root, ".pre-commit-config.yaml", PRE_COMMIT);
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"single-authoritative-source\"\nrule = \"no-merge-conflict-markers\"\n",
    );
    assert_eq!(code(&check(&root, &[])), 2);
}

#[test]
fn a_rule_enforced_at_two_seams_reports_both() {
    // A rule that both searches the tree and fires at a hook is the ordinary
    // case, not an ambiguity, and every seam that supplies it is reported.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        "[rule.prevent-unusual-unicode-in-files]\nbuiltin = \"prevent-unusual-unicode-in-files\"\ngit.hooks = [\"pre-push\"]\n",
    );
    write(&root, ".pre-commit-config.yaml", PRE_COMMIT);
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"complete-mediation\"\nrule = \"prevent-unusual-unicode-in-files\"\n",
    );
    let output = check(&root, &[]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("pre-push"), "{}", stdout(&output));
}

#[test]
fn a_claim_on_a_shim_only_rule_is_refused_and_not_credited_to_the_scan() {
    // The seam an empty hook list could not express. `command.before` runs when
    // the shim is on PATH ahead of the real command, which no runner
    // configuration settles -- so it is not the file scan, and reading it as
    // one reconciled this claim green over a rule nothing runs.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        "[[shim]]\ncommand = \"gh\"\nmatch = [\"pr:create\"]\ntext_flags = [\"-b\", \"--body\"]\n\n\
         [rule.no-published-markers]\nmessage = \"do not publish that\"\n\
         exec = \"uphold guard --text -\"\ncommand.before = [\"gh\"]\n",
    );
    write(&root, ".pre-commit-config.yaml", SCAN_ONLY);
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"complete-mediation\"\nrule = \"no-published-markers\"\n",
    );
    let output = check(&root, &[]);
    assert_eq!(code(&output), 1, "{}{}", stdout(&output), stderr(&output));

    let coverage = check(&root, &["--coverage"]);
    assert!(
        stdout(&coverage).contains("stands in front of a command"),
        "{}",
        stdout(&coverage)
    );
}

#[test]
fn the_seam_is_found_by_a_published_id_not_by_one_repositorys_name() {
    // Every published guard id has to make its own stage visible, and the id is
    // the whole of what is matched. The predicate this replaced was a
    // repository NAME, and a consumer does not necessarily write one a matcher
    // would recognise: `scripts/consumer_check.sh` clones this repository to a
    // temporary directory and pins it by path, so the last segment of its
    // `repo:` is `hooks`. Scoping on the url told that consumer the seam
    // supplying every guard was absent.
    for (stage, id) in [
        ("pre-commit", "uphold-guard"),
        ("commit-msg", "uphold-guard-commit-msg"),
        ("pre-merge-commit", "uphold-guard-merge"),
        ("pre-push", "uphold-guard-push"),
    ] {
        let root = workspace();
        write(
            &root,
            "policy/principles.toml",
            &format!(
                "[rule.prevent-unusual-unicode-in-files]\n\
                 builtin = \"prevent-unusual-unicode-in-files\"\n\
                 git.hooks = [\"{stage}\"]\n"
            ),
        );
        write(
            &root,
            ".pre-commit-config.yaml",
            &format!(
                "repos:\n  - repo: /tmp/some-checkout/hooks\n    rev: v1.0.0\n    hooks:\n      - id: {id}\n"
            ),
        );
        write(
            &root,
            "policy/upheld.toml",
            "[[enforce]]\nprinciple = \"complete-mediation\"\nrule = \"prevent-unusual-unicode-in-files\"\n",
        );
        let output = check(&root, &[]);
        assert_eq!(code(&output), 0, "{stage}/{id}: {}", stderr(&output));
    }
}

#[test]
fn a_lefthook_consumer_reconciles_with_no_pre_commit_config() {
    let root = workspace();
    write(&root, "policy/principles.toml", GUARD_POLICY);
    write(
        &root,
        "lefthook.yml",
        "remotes:\n  - git_url: https://github.com/HackingGate/uphold\n    ref: v1.0.0\n    configs:\n      - hooks/lefthook.yml\n",
    );
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"fail-safe-defaults\"\nrule = \"prevent-public-push\"\n",
    );
    let output = check(&root, &[]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_lefthook_remote_by_filesystem_path_is_still_ours() {
    // lefthook takes any git url and most carry no `owner/name`.
    // `scripts/consumer_check.sh` points its consumer at a clone by PATH, and
    // requiring the slug reported that consumer as running no seam at all.
    let root = workspace();
    write(&root, "policy/principles.toml", GUARD_POLICY);
    write(
        &root,
        "lefthook.yml",
        "remotes:\n  - git_url: /srv/example/uphold\n    ref: v1.0.0\n    configs:\n      - hooks/lefthook.yml\n",
    );
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"fail-safe-defaults\"\nrule = \"prevent-public-push\"\n",
    );
    let output = check(&root, &[]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_remote_is_only_ours_when_one_entry_says_both() {
    // Either half alone granted every stage this manifest publishes, because
    // the branch it feeds assumes the remote IS this repository's config. A
    // fork, a mirror, or an unrelated project using the same conventional
    // filename was credited with running every guard here.
    let root = workspace();
    write(&root, "policy/principles.toml", GUARD_POLICY);
    write(
        &root,
        "lefthook.yml",
        "remotes:\n  - git_url: https://github.com/somebody-else/thing\n    configs:\n      - hooks/lefthook.yml\n  \
         - git_url: https://github.com/HackingGate/uphold\n    configs:\n      - some/other.yml\n",
    );
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"fail-safe-defaults\"\nrule = \"prevent-public-push\"\n",
    );
    assert_eq!(code(&check(&root, &[])), 1);
}

#[test]
fn a_lefthook_key_that_is_not_a_command_is_not_a_rule() {
    // `configs:` is the key README.md tells every lefthook consumer to write
    // under `remotes:`, at exactly the indent a command name sits at. A scan
    // keyed on indentation read it as a command, so a claim naming a rule
    // called `configs` reconciled green against a file defining no such thing.
    let root = workspace();
    write(&root, "policy/principles.toml", GUARD_POLICY);
    write(
        &root,
        "lefthook.yml",
        "remotes:\n  - git_url: https://github.com/HackingGate/uphold\n    configs:\n      - hooks/lefthook.yml\n",
    );
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"explicit-unknown\"\nrule = \"configs\"\n",
    );
    assert_eq!(code(&check(&root, &[])), 1);
}

#[test]
fn a_lefthook_command_is_a_rule_a_claim_may_name() {
    let root = workspace();
    write(&root, "policy/principles.toml", GUARD_POLICY);
    write(
        &root,
        "lefthook.yml",
        "pre-commit:\n  commands:\n    my-own-check:\n      run: ./check.sh\n",
    );
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"explicit-unknown\"\nrule = \"my-own-check\"\n",
    );
    let output = check(&root, &[]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn an_uninstalled_hook_is_refused() {
    let root = workspace();
    write(&root, "policy/principles.toml", GUARD_POLICY);
    write(&root, ".pre-commit-config.yaml", PRE_COMMIT);
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"explicit-unknown\"\nrule = \"a-hook-nobody-installed\"\n",
    );
    assert_eq!(code(&check(&root, &[])), 1);
}

// ── coverage ─────────────────────────────────────────────────────────

const COVERAGE_POLICY: &str = "\
[rule.prevent-public-push]
builtin = \"prevent-public-push\"
git.hooks = [\"pre-push\"]

[rule.prevent-ai-author]
builtin = \"prevent-ai-author\"
git.hooks = [\"commit-msg\"]
";

fn coverage_fixture() -> PathBuf {
    let root = workspace();
    write(&root, "policy/principles.toml", COVERAGE_POLICY);
    write(&root, ".pre-commit-config.yaml", PRE_COMMIT);
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"fail-safe-defaults\"\nrule = \"prevent-public-push\"\n",
    );
    root
}

#[test]
fn a_claimed_rule_is_reported_against_its_principle() {
    let root = coverage_fixture();
    let output = check(&root, &["--coverage"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stdout(&output).contains("prevent-public-push -> fail-safe-defaults"),
        "{}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("uphold: 1 of 2"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_rule_no_claim_names_is_reported_as_unclaimed() {
    let root = coverage_fixture();
    let output = check(&root, &["--coverage"]);
    assert!(
        stdout(&output).contains("unclaimed  prevent-ai-author"),
        "{}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("my-own-check"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_false_claim_is_reported_rather_than_refused() {
    let root = workspace();
    write(&root, "policy/principles.toml", COVERAGE_POLICY);
    write(&root, ".pre-commit-config.yaml", PRE_COMMIT);
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"fail-safe-defaults\"\nrule = \"no-such-hook\"\n",
    );
    assert_eq!(code(&check(&root, &[])), 1);

    let coverage = check(&root, &["--coverage"]);
    assert_eq!(code(&coverage), 0, "{}", stderr(&coverage));
    assert!(
        stdout(&coverage).contains("claimed but supplied by nothing here: no-such-hook"),
        "{}",
        stdout(&coverage)
    );
}

#[test]
fn an_orphan_claim_is_not_counted_in_the_number_it_was_reported_under() {
    // `records: N of M` is the one number a reader takes away, and it was
    // computed from the claims rather than from what a seam supplies -- so a
    // declaration whose only claim names a rule nothing runs reported one
    // record as claimed, two lines under the line saying it is supplied by
    // nothing.
    let root = workspace();
    write(&root, "policy/principles.toml", COVERAGE_POLICY);
    write(&root, ".pre-commit-config.yaml", PRE_COMMIT);
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"fail-safe-defaults\"\nrule = \"no-such-hook\"\n",
    );
    let output = check(&root, &["--coverage"]);
    assert!(
        stdout(&output).contains("records: 0 of"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_seam_that_could_not_be_read_is_not_a_seam_running_nothing() {
    // The count is `?`, not 0, and the exit is 2: a hole in the denominator
    // reported as zero reads as coverage that was never measured.
    let root = workspace();
    write(&root, "policy/principles.toml", COVERAGE_POLICY);
    write(
        &root,
        ".pre-commit-config.yaml",
        "this: is not a repos list\n",
    );
    write(
        &root,
        "policy/upheld.toml",
        "[[enforce]]\nprinciple = \"fail-safe-defaults\"\nrule = \"prevent-public-push\"\n",
    );
    let output = check(&root, &["--coverage"]);
    assert_eq!(code(&output), 2, "{}", stdout(&output));
    assert!(
        stdout(&output).contains("local: 0 of ?"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn it_counts_records_against_what_can_be_claimed() {
    let root = coverage_fixture();
    let output = check(&root, &["--coverage"]);
    assert!(
        stdout(&output).contains("claimable records are claimed by a rule here"),
        "{}",
        stdout(&output)
    );
}

// ── this repository ──────────────────────────────────────────────────

#[test]
fn this_repository_reconciles() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = check(root, &[]);
    assert_eq!(code(&output), 0, "{}{}", stdout(&output), stderr(&output));
}

#[test]
fn the_starter_declaration_is_valid_and_enforces_nothing() {
    let root = workspace();
    write(&root, "policy/principles.toml", GUARD_POLICY);
    write(&root, ".pre-commit-config.yaml", PRE_COMMIT);
    let starter = Command::new("python3")
        .args([
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("uphold_check.py")
                .to_str()
                .unwrap(),
            "--init",
        ])
        .output()
        .unwrap();
    assert_eq!(starter.status.code().unwrap(), 0);
    write(&root, "policy/upheld.toml", &stdout(&starter));
    let output = check(&root, &[]);
    assert_eq!(code(&output), 0, "{}{}", stdout(&output), stderr(&output));
}

#[test]
fn the_output_carries_no_record_prose() {
    // A tool holding prose has no condition on which to emit it; see the
    // `enforcement-needs-a-trigger` record. What this prints is the rule that
    // went missing and the file that says so.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let run = check(root, &[]);
    let mut text = stdout(&run);
    text.push_str(&stderr(&run));
    for prose in [
        "Any verification, evaluation, or measurement",
        "review_questions",
        "does not mean",
    ] {
        assert!(
            !text.contains(prose),
            "record prose reached the output: {prose}"
        );
    }
}
