//! CLI-level tests for `uphold hooks --install`.
//!
//! The command writes the four guard-stage hook files into a tracked directory
//! and points `core.hooksPath` at it. What is being preserved is the
//! fail-closed shape: a foreign file is refused rather than replaced, a
//! foreign `core.hooksPath` is refused rather than repointed, and the written
//! pre-push refuses a push it could not check rather than passing it.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn repository() -> PathBuf {
    let root = support::scratch("hooks-install");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    std::fs::write(
        root.join("policy/principles.toml"),
        "[rule.no-shouting]\nregexp = '^SHOUTING'\nmessage = \"quiet\"\nfiles.include = [\".\"]\n",
    )
    .unwrap();
    std::fs::write(
        root.join(".pre-commit-config.yaml"),
        "default_install_hook_types: [pre-commit, commit-msg, pre-merge-commit, pre-push]\nrepos: []\n",
    )
    .unwrap();
    support::git(&root, &["init", "-q", "-b", "main"]);
    root
}

/// A stub runner on PATH, so detection and the delegates have something real.
fn stub_runner(name: &str) -> PathBuf {
    let directory = support::scratch("hooks-install-runner");
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join(name);
    std::fs::write(&path, "#!/bin/sh\necho \"runner ran: $*\"\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    directory
}

fn install(root: &Path, extra: &[&str], path_extra: &Path) -> Output {
    let mut path = path_extra.as_os_str().to_owned();
    path.push(":/usr/bin:/bin");
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["hooks", "--install"])
        .args(extra)
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

fn hooks_path(root: &Path) -> String {
    let output = support::git_command(root)
        .args(["config", "--get", "core.hooksPath"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

#[test]
fn the_four_files_are_written_and_core_hookspath_points_at_them() {
    let root = repository();
    let stub = stub_runner("prek");

    let output = install(&root, &[], &stub);
    assert_eq!(code(&output), 0, "{}", text(&output));
    for stage in ["pre-commit", "commit-msg", "pre-merge-commit", "pre-push"] {
        let file = root.join(".githooks").join(stage);
        assert!(file.is_file(), "{stage} was not written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111, "{stage} is not executable");
        }
    }
    assert_eq!(hooks_path(&root), ".githooks");

    // A second run is a re-install, not an error.
    let again = install(&root, &[], &stub);
    assert_eq!(code(&again), 0, "{}", text(&again));
}

#[test]
fn a_file_somebody_else_wrote_is_refused_rather_than_replaced() {
    let root = repository();
    let stub = stub_runner("prek");
    std::fs::create_dir_all(root.join(".githooks")).unwrap();
    std::fs::write(root.join(".githooks/pre-push"), "#!/bin/sh\nexit 0\n").unwrap();

    let output = install(&root, &[], &stub);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("not this command's call"),
        "{}",
        text(&output)
    );
    // And the file is untouched.
    let kept = std::fs::read_to_string(root.join(".githooks/pre-push")).unwrap();
    assert_eq!(kept, "#!/bin/sh\nexit 0\n");
}

#[test]
fn a_foreign_core_hookspath_is_refused_rather_than_repointed() {
    let root = repository();
    let stub = stub_runner("prek");
    support::git(&root, &["config", "core.hooksPath", "somewhere/else"]);

    let output = install(&root, &[], &stub);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("somewhere/else"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_hook_type_outside_the_four_is_refused_rather_than_switched_off() {
    let root = repository();
    std::fs::write(
        root.join(".pre-commit-config.yaml"),
        "default_install_hook_types: [pre-commit, post-checkout]\nrepos: []\n",
    )
    .unwrap();
    let stub = stub_runner("prek");

    let output = install(&root, &[], &stub);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(text(&output).contains("post-checkout"), "{}", text(&output));
}

#[test]
fn the_written_pre_push_refuses_when_uphold_is_not_on_path() {
    // The fail-closed half the file exists for: a hook that cannot answer must
    // not answer yes.
    let root = repository();
    let stub = stub_runner("prek");
    let output = install(&root, &[], &stub);
    assert_eq!(code(&output), 0, "{}", text(&output));

    let hook = root.join(".githooks/pre-push");
    let run = Command::new("sh")
        .arg(&hook)
        .args(["origin", "https://github.com/example/repo.git"])
        .current_dir(&root)
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(run.status.code().unwrap(), 2);
    assert!(
        String::from_utf8_lossy(&run.stderr).contains("refused rather than guessed at"),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn the_written_pre_push_runs_the_guard_and_then_the_runner() {
    // Both halves of the file, driven for real: a passing guard hands the same
    // ref lines to the runner; the runner stub records that it was reached.
    let root = repository();
    let stub = stub_runner("prek");
    let output = install(&root, &[], &stub);
    assert_eq!(code(&output), 0, "{}", text(&output));

    // uphold itself on PATH beside the stub runner, under its own name.
    std::fs::write(
        root.join("policy/principles.toml"),
        "[rule.no-shouting]\nregexp = '^SHOUTING'\nmessage = \"quiet\"\nfiles.include = [\".\"]\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), stub.join("uphold")).unwrap();

    let hook = root.join(".githooks/pre-push");
    let mut path = stub.as_os_str().to_owned();
    path.push(":/usr/bin:/bin");
    let run = Command::new("sh")
        .arg(&hook)
        .args(["origin", "https://github.com/example/repo.git"])
        .current_dir(&root)
        .env("PATH", path)
        .env("UPHOLD_ALLOW", "")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(run.status.code().unwrap(), 0, "{said}");
    assert!(said.contains("runner ran:"), "{said}");
}

/// One fleet's hand-written `pre-push`, as it was carried before this command
/// existed: the same lines this binary writes, wrapped at a different word on
/// the last command and under a comment three times the length. The text is
/// here verbatim because it is the text `--adopt` is for, and a paraphrase of
/// it would prove adoption of a file nobody has.
const HAND_WRITTEN: &str = r#"#!/bin/sh
#
# The push-destination guard, run by git itself, BEFORE anything downstream gets
# to decide that this push is uninteresting.
#
# `core.hooksPath` points git at this directory, so this file is the pre-push
# hook git runs; the shim `prek install` generates under the repository's own
# `hooks/` directory is no longer reached by git and is invoked from the bottom
# of this file instead. That inversion is the entire point of the file, and it
# is here because of one measurement rather than a preference.
#
# WHAT WAS MEASURED, 2026-08-16, prek 0.3.13, on one machine. prek computes the
# pushed range as `<local sha> --not --remotes` and, when that range comes back
# empty, it skips the WHOLE pre-push stage -- including hooks that carry
# `always_run: true`, which is the key whose entire job is to mean "run whether
# or not anything matched".
#
# So declaring `uphold guard --stage pre-push` as a `local` hook and letting
# prek run it is not a seam. It is a seam that is open in exactly the case the
# guard exists for, which is worse than no seam because it reads as wired.
#
# THE DESTINATION COMES OFF ARGV, WHICH IS WHERE GIT PUTS IT. `$1` is the remote
# name and `$2` is the URL this push is going to.

set -e

hook_dir="$(cd "$(dirname "$0")" && pwd)"
remote_name="$1"
remote_url="$2"

# git hands the ref lines to the hook on stdin, and both the guard and prek want
# them. There is only one stdin, so it is read once here and replayed to each.
ref_lines="$(cat)"

# A checkout where `uphold` is not on PATH is a checkout where this hook cannot
# answer the question it exists to answer, and answering it by exiting 0 is
# precisely the failure this file was written to remove. Refuse instead.
if ! command -v uphold >/dev/null 2>&1; then
	echo "pre-push: uphold is not on PATH, so the push destination was not" >&2
	echo "checked and this push is refused rather than guessed at." >&2
	exit 2
fi

printf '%s\n' "$ref_lines" | uphold guard --stage pre-push \
	--remote "$remote_name" --remote-url "$remote_url"

# Everything else this repository runs at pre-push, handed the same argv and the
# same ref lines. `hook-impl` is what the generated shim calls, so calling it
# here directly means `prek install` is not what wires the pre-push stage and a
# rerun of `prek install` cannot quietly take this file's place.
if ! command -v prek >/dev/null 2>&1; then
	echo "pre-push: prek is not on PATH, so the pre-push hooks that" >&2
	echo ".pre-commit-config.yaml declares did not run." >&2
	exit 2
fi

printf '%s\n' "$ref_lines" | prek hook-impl --hook-dir "$hook_dir" \
	--script-version 4 --hook-type=pre-push -- "$@"
"#;

const MARKER: &str = "Written by `uphold hooks --install`";

#[test]
fn a_hand_written_copy_with_the_same_lines_is_adopted() {
    let root = repository();
    let stub = stub_runner("prek");
    std::fs::create_dir_all(root.join(".githooks")).unwrap();
    std::fs::write(root.join(".githooks/pre-push"), HAND_WRITTEN).unwrap();

    let output = install(&root, &["--adopt"], &stub);
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains("adopted pre-push"),
        "{}",
        text(&output)
    );
    let now = std::fs::read_to_string(root.join(".githooks/pre-push")).unwrap();
    assert!(now.contains(MARKER), "{now}");
    // The lines that run are the ones that ran before; only the comments and
    // the wrapping moved.
    assert!(now.contains("uphold guard --stage pre-push"), "{now}");
    assert!(now.contains("--script-version 4"), "{now}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(root.join(".githooks/pre-push"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111);
    }
    assert_eq!(hooks_path(&root), ".githooks");
    // And from here on it is an ordinary install.
    let again = install(&root, &[], &stub);
    assert_eq!(code(&again), 0, "{}", text(&again));
}

#[test]
fn a_hand_written_copy_that_does_something_else_is_refused_with_the_difference() {
    // The `uphold`-not-on-PATH branch exiting 0 is the exact failure the file
    // exists to remove, and it is one character away from the text this
    // command writes. That is a decision somebody made, and `--adopt` does not
    // overrule it -- it shows it.
    let root = repository();
    let stub = stub_runner("prek");
    std::fs::create_dir_all(root.join(".githooks")).unwrap();
    let drifted =
        HAND_WRITTEN.replace("guessed at.\" >&2\n\texit 2", "guessed at.\" >&2\n\texit 0");
    assert_ne!(drifted, HAND_WRITTEN);
    std::fs::write(root.join(".githooks/pre-push"), &drifted).unwrap();

    let output = install(&root, &["--adopt"], &stub);
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("--- .githooks/pre-push"), "{said}");
    assert!(
        said.contains("+++ what `uphold hooks --install` writes"),
        "{said}"
    );
    assert!(said.contains("-exit 0"), "{said}");
    assert!(said.contains("+exit 2"), "{said}");
    // A wrapped line that only wraps differently is not in the diff.
    assert!(!said.contains("-printf"), "{said}");
    let kept = std::fs::read_to_string(root.join(".githooks/pre-push")).unwrap();
    assert_eq!(kept, drifted);
}

/// A hand-written delegate for `stage` that spells the hook directory inline
/// on the exec line, where this binary binds `hook_dir` on the line before.
fn inline_delegate(stage: &str) -> String {
    format!(
        "#!/bin/sh\n# hand-written\nset -e\n\
         exec prek hook-impl --hook-dir \"$(cd \"$(dirname \"$0\")\" && pwd)\" \
         --script-version 4 --hook-type={stage} -- \"$@\"\n"
    )
}

#[test]
fn a_directory_of_hand_written_copies_with_the_hook_dir_inline_is_adopted() {
    let root = repository();
    let stub = stub_runner("prek");
    std::fs::create_dir_all(root.join(".githooks")).unwrap();
    for stage in ["pre-commit", "commit-msg", "pre-merge-commit"] {
        std::fs::write(root.join(".githooks").join(stage), inline_delegate(stage)).unwrap();
    }
    std::fs::write(root.join(".githooks/pre-push"), HAND_WRITTEN).unwrap();

    let output = install(&root, &["--adopt"], &stub);
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains("adopted pre-commit, commit-msg, pre-merge-commit, pre-push"),
        "{}",
        text(&output)
    );
    for stage in ["pre-commit", "commit-msg", "pre-merge-commit", "pre-push"] {
        let now = std::fs::read_to_string(root.join(".githooks").join(stage)).unwrap();
        assert!(now.contains(MARKER), "{stage}: {now}");
    }
    assert_eq!(hooks_path(&root), ".githooks");
}

#[test]
fn one_copy_that_does_something_else_is_named_and_nothing_is_written() {
    // pre-commit matches and commit-msg calls pre-commit where this directory
    // runs prek. Adopting pre-commit on the way to refusing commit-msg is the
    // half-marked directory this command must not leave.
    let root = repository();
    let stub = stub_runner("prek");
    std::fs::create_dir_all(root.join(".githooks")).unwrap();
    let matching = inline_delegate("pre-commit");
    let differing = inline_delegate("commit-msg").replace("exec prek", "exec pre-commit");
    std::fs::write(root.join(".githooks/pre-commit"), &matching).unwrap();
    std::fs::write(root.join(".githooks/commit-msg"), &differing).unwrap();

    let output = install(&root, &["--adopt"], &stub);
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(
        said.contains("not a copy to adopt: .githooks/commit-msg."),
        "{said}"
    );
    assert!(said.contains("--- .githooks/commit-msg"), "{said}");
    assert!(!said.contains("--- .githooks/pre-commit"), "{said}");
    assert!(said.contains("Nothing was written"), "{said}");
    assert!(said.contains("The lines of pre-commit are"), "{said}");
    assert_eq!(
        std::fs::read_to_string(root.join(".githooks/pre-commit")).unwrap(),
        matching
    );
    assert_eq!(
        std::fs::read_to_string(root.join(".githooks/commit-msg")).unwrap(),
        differing
    );
    assert!(!root.join(".githooks/pre-merge-commit").exists());
    assert!(!root.join(".githooks/pre-push").exists());
    assert_eq!(hooks_path(&root), "");
}

#[test]
fn every_copy_that_does_something_else_is_named() {
    let root = repository();
    let stub = stub_runner("prek");
    std::fs::create_dir_all(root.join(".githooks")).unwrap();
    for stage in ["pre-commit", "pre-merge-commit"] {
        std::fs::write(
            root.join(".githooks").join(stage),
            inline_delegate(stage).replace("set -e\n", ""),
        )
        .unwrap();
    }

    let output = install(&root, &["--adopt"], &stub);
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(
        said.contains("not a copy to adopt: .githooks/pre-commit, .githooks/pre-merge-commit."),
        "{said}"
    );
    assert!(said.contains("+set -e"), "{said}");
}

#[test]
fn without_adopt_a_hand_written_copy_is_still_refused_and_told_about_adopt() {
    let root = repository();
    let stub = stub_runner("prek");
    std::fs::create_dir_all(root.join(".githooks")).unwrap();
    std::fs::write(root.join(".githooks/pre-push"), HAND_WRITTEN).unwrap();

    let output = install(&root, &[], &stub);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("not this command's call"),
        "{}",
        text(&output)
    );
    assert!(text(&output).contains("--adopt"), "{}", text(&output));
    let kept = std::fs::read_to_string(root.join(".githooks/pre-push")).unwrap();
    assert_eq!(kept, HAND_WRITTEN);
}

#[test]
fn check_reports_the_directory_and_writes_nothing() {
    let root = repository();
    let stub = stub_runner("prek");
    std::fs::create_dir_all(root.join(".githooks")).unwrap();
    std::fs::write(root.join(".githooks/pre-push"), HAND_WRITTEN).unwrap();

    // An unmarked copy with the right lines, three files absent, and no
    // core.hooksPath: not as an install would leave it, and said so.
    let before = install(&root, &["--check"], &stub);
    assert_eq!(code(&before), 1, "{}", text(&before));
    let said = text(&before);
    assert!(said.contains("pre-push: written by hand"), "{said}");
    assert!(
        said.contains("`hooks --install --adopt` takes it over"),
        "{said}"
    );
    assert!(said.contains("pre-commit: absent"), "{said}");
    assert!(said.contains("core.hooksPath is unset"), "{said}");
    assert!(said.contains("nothing was written"), "{said}");
    assert_eq!(
        std::fs::read_to_string(root.join(".githooks/pre-push")).unwrap(),
        HAND_WRITTEN
    );
    assert!(!root.join(".githooks/pre-commit").exists());
    assert_eq!(hooks_path(&root), "");

    let adopted = install(&root, &["--adopt"], &stub);
    assert_eq!(code(&adopted), 0, "{}", text(&adopted));
    let after = install(&root, &["--check"], &stub);
    assert_eq!(code(&after), 0, "{}", text(&after));
    assert!(
        text(&after).contains("the hooks git runs are the ones this binary writes"),
        "{}",
        text(&after)
    );

    // A marked file from an older binary, or edited since: the difference is
    // shown, and a rerun of the install is what fixes it.
    let installed = std::fs::read_to_string(root.join(".githooks/pre-push")).unwrap();
    std::fs::write(
        root.join(".githooks/pre-push"),
        installed.replace("exit 2", "exit 0"),
    )
    .unwrap();
    let drifted = install(&root, &["--check"], &stub);
    assert_eq!(code(&drifted), 1, "{}", text(&drifted));
    assert!(
        text(&drifted).contains("NOT the text this binary writes: an older install"),
        "{}",
        text(&drifted)
    );
    assert!(text(&drifted).contains("+exit 2"), "{}", text(&drifted));
}

#[test]
fn adopt_and_check_together_are_a_usage_error() {
    let root = repository();
    let stub = stub_runner("prek");
    let output = install(&root, &["--adopt", "--check"], &stub);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(text(&output).contains("usage:"), "{}", text(&output));
}
