//! `uphold probe` -- driven against a runner this test controls.
//!
//! The stub on PATH is the point rather than a shortcut. What is under test is
//! the probe's own reasoning -- plant, run, clean, run, and what each pair of
//! exits MEANS -- and a real runner would make every case depend on a tool
//! installed elsewhere. The stubs here are the three answers a runner can give:
//! refuses what it should, refuses nothing, refuses everything.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// A repository with one declared hook, and a policy so the root is found.
fn repository(probes: &str) -> PathBuf {
    let root = support::scratch("probe-cli");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();

    support::git(&root, &["init", "-q", "-b", "main"]);
    support::git(&root, &["config", "user.name", "Test"]);
    support::git(&root, &["config", "user.email", "test@example.test"]);

    std::fs::write(
        root.join("policy/principles.toml"),
        "[rule.no-shouting]\nregexp = 'SHOUTING'\nmessage = \"quiet\"\nfiles.include = [\".\"]\n",
    )
    .unwrap();
    std::fs::write(
        root.join(".pre-commit-config.yaml"),
        "repos:\n  - repo: https://github.com/example/hooks\n    rev: v1.0.0\n    hooks:\n      - id: no-markers\n",
    )
    .unwrap();
    if !probes.is_empty() {
        std::fs::write(root.join("policy/hooks.toml"), probes).unwrap();
    }
    // A commit, because the probe checks out HEAD into a throwaway worktree --
    // which is the whole reason the operator's own tree is never planted in.
    support::git(&root, &["add", "-A"]);
    support::git(&root, &["commit", "-qm", "one", "--no-verify"]);
    root
}

/// A `prek` on PATH that answers the way this case needs.
///
/// `script` is the body: it is handed the same arguments the real runner is,
/// with the worktree as its working directory.
fn runner(script: &str) -> PathBuf {
    let directory = support::scratch("probe-runner");
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("prek");
    std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    directory
}

fn probe(root: &Path, path_extra: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
    command.arg("probe");
    if path_extra.is_some() {
        command.args(["--runner", "prek"]);
    }
    // The stub FIRST, so a real runner installed on the machine running these
    // tests cannot answer for it -- and the system directories after it,
    // because the probe shells out to `git` for the throwaway worktree and a
    // PATH holding only the stub takes git away too.
    let path = path_extra.map_or_else(
        || std::ffi::OsString::from("/nonexistent"),
        |directory| {
            let mut path = directory.as_os_str().to_owned();
            path.push(":/usr/bin:/bin");
            path
        },
    );
    command
        .env("PATH", path)
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn text(output: &Output) -> String {
    let mut all = String::from_utf8_lossy(&output.stdout).into_owned();
    all.push_str(&String::from_utf8_lossy(&output.stderr));
    all
}

const ONE_PROBE: &str = r#"
[[probe]]
id = "no-markers"
path = "sample.txt"
refuses = "MARKER\n"
allows = "clean\n"
"#;

#[test]
fn a_hook_that_refuses_its_fixture_and_accepts_a_clean_one_is_demonstrated() {
    let root = repository(ONE_PROBE);
    // The honest runner: refuses exactly what it is given to refuse.
    let stub = runner("grep -q MARKER sample.txt && exit 1\nexit 0");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains("refuses its fixture, accepts a clean one"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_hook_that_cannot_fail_is_the_finding_this_command_exists_for() {
    // The `gofmt -l` shape: it prints its findings and exits 0, so it reports
    // the same green tick as a hook that keeps finding nothing.
    let root = repository(ONE_PROBE);
    let stub = runner("echo 'found something'\nexit 0");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 1, "{}", text(&output));
    assert!(text(&output).contains("ACCEPTED"), "{}", text(&output));
}

#[test]
fn a_hook_that_refuses_everything_is_a_different_finding() {
    // Its refusal says nothing about what it was given, so a green run of it
    // proves nothing either. Reported apart from a hook that cannot fail
    // because the fix is not the same one.
    let root = repository(ONE_PROBE);
    let stub = runner("exit 1");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 1, "{}", text(&output));
    assert!(
        text(&output).contains("refused the clean fixture as well"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_probe_with_no_clean_fixture_drives_one_verdict_and_says_so() {
    let root = repository(
        "[[probe]]\nid = \"no-markers\"\npath = \"sample.txt\"\nrefuses = \"MARKER\\n\"\n",
    );
    let stub = runner("grep -q MARKER sample.txt && exit 1\nexit 0");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains("nothing here shows it accepts anything"),
        "{}",
        text(&output)
    );
}

#[test]
fn the_denominator_is_printed_beside_the_probes() {
    // "One hook was probed" means one thing beside one declaration and another
    // beside twenty.
    let root = repository(ONE_PROBE);
    std::fs::write(
        root.join(".pre-commit-config.yaml"),
        "repos:\n  - repo: https://github.com/example/hooks\n    rev: v1.0.0\n    hooks:\n      - id: no-markers\n      - id: something-else\n",
    )
    .unwrap();
    support::git(&root, &["add", "-A"]);
    support::git(&root, &["commit", "-qm", "two", "--no-verify"]);
    let stub = runner("grep -q MARKER sample.txt && exit 1\nexit 0");

    let output = probe(&root, Some(&stub));
    assert!(
        text(&output).contains("1 declared hook(s) have no probe"),
        "{}",
        text(&output)
    );
    assert!(
        text(&output).contains("something-else"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_probe_naming_a_hook_nothing_declares_is_refused() {
    // It would drive nothing while reading as though that hook had been
    // demonstrated, which is the same failure a `disabled_rules` entry naming
    // nothing has.
    let root = repository(
        "[[probe]]\nid = \"a-hook-nobody-declares\"\npath = \"sample.txt\"\nrefuses = \"X\\n\"\n",
    );
    let stub = runner("exit 0");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("would drive nothing"),
        "{}",
        text(&output)
    );
}

#[test]
fn an_empty_fixture_demonstrates_nothing_and_is_refused() {
    let root =
        repository("[[probe]]\nid = \"no-markers\"\npath = \"sample.txt\"\nrefuses = \"   \"\n");
    let stub = runner("exit 0");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("demonstrates nothing"),
        "{}",
        text(&output)
    );
}

#[test]
fn no_runner_on_path_is_could_not_look_and_not_a_pass() {
    // A hook that could not be run has not been shown to refuse anything.
    let root = repository(ONE_PROBE);

    let output = probe(&root, None);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(text(&output).contains("on PATH"), "{}", text(&output));
}

#[test]
fn the_operators_own_tree_is_never_planted_in() {
    // The fixture goes into a throwaway worktree at HEAD. A probe that planted
    // it here would leave one behind the first time it was interrupted -- in a
    // tree whose hooks would then refuse the next commit for a reason nothing
    // in the tree explains.
    let root = repository(ONE_PROBE);
    let stub = runner("grep -q MARKER sample.txt && exit 1\nexit 0");

    let _ = probe(&root, Some(&stub));
    assert!(
        !root.join("sample.txt").exists(),
        "the probe left its fixture in the working tree"
    );
    let status = support::git_command(&root)
        .args(["status", "--porcelain"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&status.stdout).trim().is_empty(),
        "the probe left the working tree dirty: {}",
        String::from_utf8_lossy(&status.stdout)
    );
}

#[test]
fn a_probe_run_from_inside_a_hook_does_not_borrow_that_hooks_index() {
    // Found by running this suite from inside a hook, which is where `probe`
    // is most likely to be used. A hook runner exports `GIT_INDEX_FILE` and
    // `GIT_DIR`, several of them RELATIVE to the repository the hook fired in.
    // Inherited, they point every `git` the probe runs at the wrong index: the
    // worktree could not be created at all, and where it could, the staging
    // would have gone into somebody else's index -- the same accident with none
    // of the noise.
    let root = repository(ONE_PROBE);
    let stub = runner("grep -q MARKER sample.txt && exit 1\nexit 0");

    let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
    let mut path = stub.as_os_str().to_owned();
    path.push(":/usr/bin:/bin");
    let output = command
        .args(["probe", "--runner", "prek"])
        .env("PATH", path)
        // Exactly what a hook runner leaves in the environment, relative
        // spelling and all.
        .env("GIT_INDEX_FILE", ".git/index")
        .env("GIT_DIR", ".git")
        .current_dir(&root)
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert_eq!(
        output.status.code().unwrap(),
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_probe_file_carrying_waivers_is_read_by_the_probe_reader_too() {
    // The mirror of the identity test: one file, two features, and each reader
    // has to tolerate the other's table while still refusing a typo in its own.
    let root = repository(
        "[[waive]]\nid = \"no-markers\"\nfindings = [\"absent\"]\nreason = \"the hooks repository cannot pin itself\"\n\n[[probe]]\nid = \"no-markers\"\npath = \"sample.txt\"\nrefuses = \"MARKER\\n\"\nallows = \"clean\\n\"\n",
    );
    let stub = runner("grep -q MARKER sample.txt && exit 1\nexit 0");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains("refuses its fixture, accepts a clean one"),
        "{}",
        text(&output)
    );
}

// ── expect: the words a refusal must contain ─────────────────────────

const EXPECTING_PROBE: &str = r#"
[[probe]]
id = "no-markers"
path = "sample.txt"
refuses = "MARKER\n"
allows = "clean\n"
expect = "no-shouting"
"#;

#[test]
fn a_refusal_carrying_the_expected_words_is_demonstrated() {
    let root = repository(EXPECTING_PROBE);
    let stub =
        runner("grep -q MARKER sample.txt && { echo 'refused by no-shouting'; exit 1; }\nexit 0");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains("refuses its fixture, accepts a clean one"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_refusal_without_the_expected_words_is_a_red_from_somewhere_else() {
    // The case `expect` exists for: the planted fixture trips a NEIGHBOURING
    // rule, the rule the probe was written for has silently stopped matching,
    // and without the words the probe reports a demonstrated gate.
    let root = repository(EXPECTING_PROBE);
    let stub = runner(
        "grep -q MARKER sample.txt && { echo 'trailing whitespace fixed'; exit 1; }\nexit 0",
    );

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 1, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("somewhere else"), "{said}");
    // The reader is shown what the refusal DID say, so the next step does not
    // begin with running the probe again.
    assert!(said.contains("trailing whitespace fixed"), "{said}");
}

#[test]
fn an_empty_expect_asserts_nothing_and_is_refused() {
    let root = repository(
        "[[probe]]\nid = \"no-markers\"\npath = \"sample.txt\"\nrefuses = \"MARKER\\n\"\nexpect = \"  \"\n",
    );
    let stub = runner("exit 1");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("empty `expect`"),
        "{}",
        text(&output)
    );
}

// ── timeout: a hook that never answers is unmeasured, not passed ─────

#[test]
fn a_hook_still_running_at_its_deadline_is_unmeasured_and_exit_2() {
    let root = repository(
        "timeout_seconds = 1\n\n[[probe]]\nid = \"no-markers\"\npath = \"sample.txt\"\nrefuses = \"MARKER\\n\"\nallows = \"clean\\n\"\n",
    );
    let stub = runner("sleep 30");

    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(text(&output).contains("never"), "{}", text(&output));
}

#[test]
fn the_timeout_flag_overrides_the_file_for_one_run() {
    // How a suite proves a timeout is a FAILURE rather than a silent pass:
    // the file may declare all the patience in the world, and one run can
    // still take it away.
    let root = repository(
        "timeout_seconds = 600\n\n[[probe]]\nid = \"no-markers\"\npath = \"sample.txt\"\nrefuses = \"MARKER\\n\"\n",
    );
    let stub = runner("sleep 30");

    let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
    command.args(["probe", "--runner", "prek", "--timeout", "1"]);
    let mut path = stub.as_os_str().to_owned();
    path.push(":/usr/bin:/bin");
    let output = command
        .env("PATH", path)
        .current_dir(&root)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(text(&output).contains("never"), "{}", text(&output));
}

// ─── `push = "empty"`: the range the delegate exists for ─────────────────────

/// The probe that pushes nothing, to a destination the policy pins against.
///
/// `refuses` and `allows` are destinations rather than files: an empty range
/// carries no content, so what the pre-push guard judges is where the push is
/// going.
const EMPTY_RANGE_PROBE: &str = r#"
[[probe]]
id = "empty-range"
push = "empty"
refuses = "someone-else/widget"
allows = "acme/widget"
expect = "prevent-public-push"
"#;

/// A repository pinned to `acme`, with `prevent-public-push` at pre-push and
/// a policy that says nothing else -- so the only thing that can refuse a push
/// is the destination guard, and only through the delegate.
///
/// `install` says whether `uphold hooks --install` writes the delegate into
/// the tree before it is committed. Without it git runs `.git/hooks`, which
/// holds nothing, and the push goes through: that is the state every
/// consumer was in before the delegate existed, and it is the state this
/// probe is for.
fn pinned_repository(probes: &str, install: bool, stub: &Path) -> PathBuf {
    let root = support::scratch("probe-push");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    support::git(&root, &["init", "-q", "-b", "main"]);
    support::git(&root, &["config", "user.name", "Test"]);
    support::git(&root, &["config", "user.email", "test@example.test"]);
    std::fs::write(
        root.join("policy/principles.toml"),
        "[rule.prevent-public-push]\nbuiltin = \"prevent-public-push\"\nowner = \"acme\"\n\n\
         [rule.prevent-public-push.git]\nhooks = [\"pre-push\"]\n",
    )
    .unwrap();
    std::fs::write(root.join(".pre-commit-config.yaml"), "repos: []\n").unwrap();
    std::fs::write(root.join("policy/hooks.toml"), probes).unwrap();
    if install {
        let mut path = stub.as_os_str().to_owned();
        path.push(":/usr/bin:/bin");
        let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
            .args(["hooks", "--install"])
            .env("PATH", path)
            .current_dir(&root)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(code(&output), 0, "{}", text(&output));
    }
    support::git(&root, &["add", "-A"]);
    support::git(&root, &["commit", "-qm", "one", "--no-verify"]);
    root
}

/// The stub runner beside `uphold` itself, since the delegate calls both by
/// name and a PATH holding only one of them makes the hook refuse before the
/// guard is reached.
fn runner_beside_uphold(script: &str) -> PathBuf {
    let stub = runner(script);
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), stub.join("uphold")).unwrap();
    stub
}

fn probe_push(root: &Path, stub: &Path) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
    command.args(["probe", "--runner", "prek"]);
    let mut path = stub.as_os_str().to_owned();
    path.push(":/usr/bin:/bin");
    command
        .env("PATH", path)
        .env_remove("UPHOLD_ALLOW")
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn an_empty_range_push_reaches_the_delegate_and_the_guard_it_runs_first() {
    // Nothing is being sent, and the push to the wrong owner is refused by
    // name anyway -- by the delegate, before the runner is reached. Then the
    // same push to the pinned owner goes through, so the refusal was about the
    // destination and not about everything.
    let stub = runner_beside_uphold("exit 0");
    let root = pinned_repository(EMPTY_RANGE_PROBE, true, &stub);

    let output = probe_push(&root, &stub);
    let said = text(&output);
    assert_eq!(code(&output), 0, "{said}");
    assert!(
        said.contains(
            "empty-range (git push of an empty range): refuses its fixture, accepts a clean one"
        ),
        "{said}"
    );
    // Nothing of the probe is left in the operator's tree, and no remote was
    // added to its config.
    let status = support::git_command(&root)
        .args(["status", "--porcelain"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&status.stdout).trim(), "");
    let remotes = support::git_command(&root)
        .args(["remote"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&remotes.stdout).trim(), "");
}

#[test]
fn an_empty_range_push_with_no_delegate_is_accepted_and_that_is_the_finding() {
    // The state every consumer was in before the delegate existed: the range
    // is empty, so nothing on the push path asks the destination guard, and
    // the push to somebody else's repository goes through.
    let stub = runner_beside_uphold("exit 0");
    let root = pinned_repository(EMPTY_RANGE_PROBE, false, &stub);

    let output = probe_push(&root, &stub);
    let said = text(&output);
    assert_eq!(code(&output), 1, "{said}");
    assert!(
        said.contains("empty-range (git push of an empty range): ACCEPTED"),
        "{said}"
    );
}

#[test]
fn an_empty_range_push_refused_for_another_reason_is_not_the_guard_demonstrated() {
    // The delegate refuses when `uphold` is missing from PATH, before the
    // guard is reached, and that is a refusal too -- of every push, for a
    // reason that has nothing to do with where it was going. `expect` is what
    // keeps that red from counting as the destination guard.
    let stub = runner("exit 0");
    let root = pinned_repository(EMPTY_RANGE_PROBE, true, &stub);

    let output = probe_push(&root, &stub);
    let said = text(&output);
    assert_eq!(code(&output), 1, "{said}");
    assert!(said.contains("WITHOUT the words `expect` names"), "{said}");
    assert!(said.contains("uphold is not on PATH"), "{said}");
}

#[test]
fn a_push_probe_with_a_path_or_a_stage_is_refused_at_load() {
    let stub = runner_beside_uphold("exit 0");
    let root = pinned_repository(
        "[[probe]]\nid = \"empty-range\"\npush = \"empty\"\npath = \"x.txt\"\nrefuses = \"someone-else/widget\"\n",
        true,
        &stub,
    );
    let output = probe_push(&root, &stub);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("plants no file"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_push_probe_whose_fixture_is_not_a_destination_is_refused_at_load() {
    let stub = runner_beside_uphold("exit 0");
    let root = pinned_repository(
        "[[probe]]\nid = \"empty-range\"\npush = \"empty\"\nrefuses = \"https://github.com/someone-else/widget\"\n",
        true,
        &stub,
    );
    let output = probe_push(&root, &stub);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("not an `owner/repo`"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_push_of_a_shape_this_command_does_not_drive_is_refused_at_load() {
    let stub = runner_beside_uphold("exit 0");
    let root = pinned_repository(
        "[[probe]]\nid = \"empty-range\"\npush = \"force\"\nrefuses = \"someone-else/widget\"\n",
        true,
        &stub,
    );
    let output = probe_push(&root, &stub);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("the only push this command drives is \"empty\""),
        "{}",
        text(&output)
    );
}

#[test]
fn a_runner_probe_with_no_path_is_refused_at_load() {
    let root = repository("[[probe]]\nid = \"no-markers\"\nrefuses = \"MARKER\\n\"\n");
    let stub = runner("exit 0");
    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(text(&output).contains("has no `path`"), "{}", text(&output));
}
