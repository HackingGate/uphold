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
fn fixture_paths_cannot_escape_the_worktree_or_name_git_metadata() {
    for path in [
        "../escaped.txt",
        "/absolute.txt",
        ".git",
        ".git/config",
        "",
        ".",
    ] {
        let config = ONE_PROBE.replace("sample.txt", path);
        let root = repository(&config);
        let stub = runner("exit 1");
        let output = probe(&root, Some(&stub));
        assert_eq!(code(&output), 2, "{path:?}: {}", text(&output));
        assert!(text(&output).contains("fixture path"), "{}", text(&output));
    }
}

#[cfg(unix)]
#[test]
fn fixture_paths_cannot_follow_a_tracked_symlink() {
    for directory_link in [false, true] {
        let root = repository(ONE_PROBE);
        let outside = support::scratch("probe-outside");
        std::fs::create_dir_all(&outside).unwrap();
        let sentinel = outside.join("sentinel.txt");
        std::fs::write(&sentinel, "keep this\n").unwrap();
        let (link, target, fixture) = if directory_link {
            ("linked", outside.as_path(), "linked/sentinel.txt")
        } else {
            ("sample.txt", sentinel.as_path(), "sample.txt")
        };
        std::os::unix::fs::symlink(target, root.join(link)).unwrap();
        std::fs::write(
            root.join("policy/hooks.toml"),
            ONE_PROBE.replace("sample.txt", fixture),
        )
        .unwrap();
        support::git(&root, &["add", "-A"]);
        support::git(&root, &["commit", "-qm", "symlink fixture", "--no-verify"]);
        let stub = runner("exit 1");

        let output = probe(&root, Some(&stub));
        assert_eq!(code(&output), 2, "{}", text(&output));
        assert!(text(&output).contains("symlink"), "{}", text(&output));
        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "keep this\n");
    }
}

#[test]
fn a_failed_fixture_stage_is_unmeasured() {
    let root = repository(ONE_PROBE);
    let stub = runner(
        "if grep -q MARKER sample.txt; then\n  touch \"$(git rev-parse --git-path index.lock)\"\n  exit 1\nfi\nexit 0",
    );
    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("could not stage"),
        "{}",
        text(&output)
    );
    assert!(text(&output).contains("index.lock"), "{}", text(&output));
}

#[test]
fn an_ignored_fixture_is_staged_for_the_hook() {
    let root = repository(ONE_PROBE);
    std::fs::write(root.join(".gitignore"), "sample.txt\n").unwrap();
    support::git(&root, &["add", ".gitignore"]);
    support::git(&root, &["commit", "-qm", "ignored fixture", "--no-verify"]);
    let stub = runner("git show :sample.txt | grep -q MARKER && exit 1\nexit 0");
    let output = probe(&root, Some(&stub));
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains("accepts a clean one"),
        "{}",
        text(&output)
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

fn claimed_repository(probes: &str) -> PathBuf {
    let root = repository(probes);
    std::fs::write(
        root.join("policy/principles.toml"),
        "allowed_scripts = ['Latin']\n",
    )
    .unwrap();
    std::fs::write(
        root.join("policy/upheld.toml"),
        "[[enforce]]\nprinciple = 'explicit-unknown'\nrule = 'no-markers'\n",
    )
    .unwrap();
    support::git(&root, &["add", "-A"]);
    support::git(&root, &["commit", "-qm", "claim", "--no-verify"]);
    root
}

fn reconciliation(root: &Path, stub: &Path, measure: bool) -> serde_json::Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
    command.args(["check", "--json"]);
    if measure {
        command.arg("--probe");
    }
    let mut path = stub.as_os_str().to_owned();
    path.push(":/usr/bin:/bin");
    let output = command
        .current_dir(root)
        .env("PATH", path)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    // Behavioral reporting is independent of the installation contract.
    assert_eq!(code(&output), 0, "{}", text(&output));
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn installed_hook_with_no_probe_has_explicitly_unmeasured_behavior() {
    let root = claimed_repository("");
    let stub = runner("exit 0");
    let measured = reconciliation(&root, &stub, true);
    assert_eq!(
        measured.pointer("/claims/0/behavior/0/state").unwrap(),
        "unmeasured"
    );
    assert_eq!(
        measured.pointer("/claims/0/behavior/0/outcome").unwrap(),
        "no_matching_probe"
    );
    // Ordinary check needs neither a runner nor a git snapshot.
    std::fs::remove_dir_all(root.join(".git")).unwrap();
    let report = reconciliation(&root, &stub, false);
    let claim = &report.pointer("/claims/0").unwrap();
    assert_eq!(claim["status"], "reconciled");
    assert_eq!(claim.pointer("/behavior/0").unwrap()["state"], "unmeasured");
    assert_eq!(
        claim.pointer("/behavior/0").unwrap()["outcome"],
        "not_requested"
    );
    assert!(claim.pointer("/behavior/0").unwrap()["provenance"].is_null());
}

#[test]
fn combined_report_demonstrates_only_the_matching_hook_with_provenance() {
    let root = claimed_repository(ONE_PROBE);
    let stub = runner("grep -q MARKER sample.txt && exit 1\nexit 0");
    let report = reconciliation(&root, &stub, true);
    let behavior = &report.pointer("/claims/0/behavior/0").unwrap();
    assert_eq!(behavior["state"], "demonstrated");
    assert_eq!(behavior["subject"], "hook");
    assert_eq!(behavior["manager"], "pre-commit");
    let provenance = &behavior["provenance"];
    assert_eq!(provenance["hook"], "no-markers");
    assert_eq!(provenance["stage"], "pre-commit");
    assert_eq!(provenance["source"], ".pre-commit-config.yaml");
    assert_eq!(provenance.pointer("/fixture/refuses").unwrap(), "MARKER\n");
    assert_eq!(provenance.pointer("/fixture/allows").unwrap(), "clean\n");
    assert!(provenance["runner"].as_str().unwrap().ends_with("/prek"));
    let head = support::git_command(&root)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert_eq!(
        provenance["revision"],
        String::from_utf8_lossy(&head.stdout).trim()
    );
    assert!(
        provenance["declaration"]
            .as_str()
            .unwrap()
            .contains("no-markers")
    );
}

#[test]
fn failed_and_partial_controls_never_demonstrate_a_claim_or_change_installation_acceptance() {
    for (script, probes, state, outcome) in [
        (
            "exit 0",
            ONE_PROBE.to_owned(),
            "measured_failure",
            "cannot_fail",
        ),
        (
            "exit 1",
            ONE_PROBE.to_owned(),
            "measured_failure",
            "refuses_everything",
        ),
        (
            "kill -TERM $$",
            ONE_PROBE.to_owned(),
            "measured_failure",
            "unread",
        ),
        (
            "sleep 2",
            format!("timeout_seconds = 1\n{ONE_PROBE}"),
            "unmeasured",
            "timeout",
        ),
        (
            "exit 1",
            ONE_PROBE.replace("allows = \"clean\\n\"", ""),
            "unmeasured",
            "missing_clean_control",
        ),
    ] {
        let root = claimed_repository(&probes);
        let stub = runner(script);
        let report = reconciliation(&root, &stub, true);
        let behavior = &report.pointer("/claims/0/behavior/0").unwrap();
        assert_eq!(behavior["state"], state, "{report}");
        assert_eq!(behavior["outcome"], outcome, "{report}");
        assert_eq!(report.pointer("/claims/0").unwrap()["status"], "reconciled");
    }
}

#[test]
fn changed_rules_fixtures_and_revisions_cannot_reuse_demonstration() {
    let root = claimed_repository(ONE_PROBE);
    let stub = runner("grep -q MARKER sample.txt && exit 1\nexit 0");
    let first = reconciliation(&root, &stub, true);
    let old_revision = first
        .pointer("/claims/0/behavior/0/provenance/revision")
        .unwrap()
        .clone();
    for relative in [".pre-commit-config.yaml", "policy/hooks.toml"] {
        let contents = std::fs::read_to_string(root.join(relative)).unwrap();
        std::fs::write(root.join(relative), format!("{contents}\n# changed\n")).unwrap();
        let report = reconciliation(&root, &stub, true);
        assert_eq!(
            report.pointer("/claims/0/behavior/0").unwrap()["state"],
            "unmeasured"
        );
        assert!(
            report.pointer("/claims/0/behavior/0").unwrap()["detail"]
                .as_str()
                .unwrap()
                .contains("clean committed tree")
        );
        std::fs::write(root.join(relative), contents).unwrap();
    }
    std::fs::write(
        root.join("policy/hooks.toml"),
        ONE_PROBE.replace("MARKER", "OTHER"),
    )
    .unwrap();
    support::git(&root, &["add", "-A"]);
    support::git(&root, &["commit", "-qm", "changed fixture", "--no-verify"]);
    let changed = reconciliation(&root, &stub, true);
    let behavior = &changed.pointer("/claims/0/behavior/0").unwrap();
    assert_eq!(behavior["state"], "measured_failure");
    assert_eq!(behavior["outcome"], "cannot_fail");
    assert_ne!(
        behavior.pointer("/provenance/revision").unwrap(),
        &old_revision
    );
    assert_eq!(
        behavior.pointer("/provenance/fixture/refuses").unwrap(),
        "OTHER\n"
    );
}

#[test]
fn mutation_between_controls_is_unread_instead_of_demonstrated() {
    let root = claimed_repository(ONE_PROBE);
    let stub = runner(
        "echo '# changed by hook' >> .pre-commit-config.yaml\ngrep -q MARKER sample.txt && exit 1\nexit 0",
    );
    let report = reconciliation(&root, &stub, true);
    let behavior = &report.pointer("/claims/0/behavior/0").unwrap();
    assert_eq!(behavior["state"], "measured_failure");
    assert_eq!(behavior["outcome"], "unread");
    assert!(
        behavior["detail"]
            .as_str()
            .unwrap()
            .contains("changed the probe snapshot")
    );
}

#[test]
fn same_id_in_another_manager_does_not_inherit_a_demonstration() {
    let root = claimed_repository(ONE_PROBE);
    std::fs::write(
        root.join("lefthook.yml"),
        "pre-commit:\n  commands:\n    no-markers:\n      run: echo unrelated\n",
    )
    .unwrap();
    support::git(&root, &["add", "-A"]);
    support::git(&root, &["commit", "-qm", "second manager", "--no-verify"]);
    let stub = runner("grep -q MARKER sample.txt && exit 1\nexit 0");
    let report = reconciliation(&root, &stub, true);
    let measurements = report
        .pointer("/claims/0/behavior")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(measurements.len(), 2, "{report}");
    assert!(
        measurements
            .iter()
            .any(|item| item["manager"] == "pre-commit" && item["state"] == "demonstrated")
    );
    assert!(
        measurements
            .iter()
            .any(|item| item["manager"] == "lefthook" && item["state"] == "unmeasured")
    );
}

#[test]
fn a_push_probe_label_cannot_certify_a_runner_hook() {
    let root = claimed_repository(
        "[[probe]]\nid = 'no-markers'\npush = 'empty'\nrefuses = 'other/repo'\nallows = 'example/repo'\n",
    );
    let stub = runner("exit 1");
    let report = reconciliation(&root, &stub, true);
    let evidence = report.pointer("/claims/0/behavior/0").unwrap();
    assert_eq!(evidence["state"], "unmeasured");
    assert_eq!(evidence["outcome"], "no_matching_probe");
}

#[test]
fn a_wrapper_hook_does_not_certify_an_engine_rule_with_the_same_name() {
    let root = claimed_repository(ONE_PROBE);
    std::fs::write(root.join("policy/principles.toml"), "[rule.no-markers]\nregexp = 'MARKER'\nmessage = 'marker'\nfiles.include = ['sample.txt']\n").unwrap();
    let config = std::fs::read_to_string(root.join(".pre-commit-config.yaml")).unwrap();
    std::fs::write(root.join(".pre-commit-config.yaml"), format!("{config}  - repo: https://github.com/HackingGate/uphold\n    rev: v1.0.0\n    hooks:\n      - id: uphold-scan\n")).unwrap();
    support::git(&root, &["add", "-A"]);
    support::git(&root, &["commit", "-qm", "engine supplier", "--no-verify"]);
    let stub = runner("grep -q MARKER sample.txt && exit 1\nexit 0");
    let report = reconciliation(&root, &stub, true);
    let evidence = report
        .pointer("/claims/0/behavior")
        .unwrap()
        .as_array()
        .unwrap();
    assert!(
        evidence
            .iter()
            .any(|item| item["subject"] == "hook" && item["state"] == "demonstrated"),
        "{report}"
    );
    assert!(
        evidence
            .iter()
            .any(|item| item["subject"] == "rule" && item["state"] == "unmeasured"),
        "{report}"
    );
}

#[test]
fn a_revision_changed_during_the_probe_invalidates_all_demonstrations() {
    let root = claimed_repository(ONE_PROBE);
    // Synthetic local fixture commits are the test subject; this never changes
    // the checkout running the suite.
    let script = format!(
        "git -C '{}' -c core.hooksPath=/dev/null commit --allow-empty -qm advanced\ngrep -q MARKER sample.txt && exit 1\nexit 0",
        root.display()
    );
    let stub = runner(&script);
    let report = reconciliation(&root, &stub, true);
    let evidence = report.pointer("/claims/0/behavior/0").unwrap();
    assert_eq!(evidence["state"], "unmeasured");
    assert!(
        evidence["detail"]
            .as_str()
            .unwrap()
            .contains("revision changed")
    );
}

#[test]
fn human_reconciliation_names_behavior_separately_from_installation() {
    let root = claimed_repository("");
    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .arg("check")
        .current_dir(&root)
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(text(&output).contains("enforced by a hook installed here"));
    assert!(text(&output).contains("behavior  no-markers: unmeasured"));
}

#[test]
fn committing_a_changed_probe_snapshot_cannot_hide_mutation_between_controls() {
    let root = claimed_repository(ONE_PROBE);
    let stub = runner(
        "echo '# changed by hook' >> .pre-commit-config.yaml\ngit add -A\ngit -c core.hooksPath=/dev/null commit -qm changed\ngrep -q MARKER sample.txt && exit 1\nexit 0",
    );
    let report = reconciliation(&root, &stub, true);
    let evidence = report.pointer("/claims/0/behavior/0").unwrap();
    assert_eq!(evidence["state"], "measured_failure");
    assert_eq!(evidence["outcome"], "unread");
    assert!(
        evidence["detail"]
            .as_str()
            .unwrap()
            .contains("changed the probe revision")
    );
}
