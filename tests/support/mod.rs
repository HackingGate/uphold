//! Where a fixture lives, and who removes it.
//!
//! Every CLI test here builds a real repository, and until this module existed
//! each one built it directly under the system temporary directory and removed
//! it only on the way IN -- `remove_dir_all` before `create_dir_all`, which
//! defends against a name colliding and frees nothing. The names carry a process
//! id precisely so that they do not collide, so nothing was ever freed.
//!
//! Observed before the fix: one working session left enough directories under
//! `/tmp` to fill the tmpfs they share. It is not a slow leak -- a mutation run
//! repeats the whole suite once per mutant, so a great many suites is an
//! ordinary afternoon -- and what it broke was a `cargo mutants` run, which
//! died on `No space left on device` and reported as "unviable" the mutants it
//! could not evaluate. A tool reporting a measurement it could not make is the
//! shape this repository exists to refuse, and the test suite caused it.
//!
//! So a fixture lives under `<temp>/uphold-tests/<pid>/`, and the first fixture
//! in a run SWEEPS every sibling whose process is gone. What a run leaves behind
//! is bounded by that run rather than by the history of the machine, and a
//! suite that is killed -- which a mutation run does on purpose, on a timeout --
//! is cleaned by the next one rather than never.
//!
//! A `Drop` guard was the other option and it is not enough on its own: it does
//! nothing for a test that panics its process or a suite that is killed. The two
//! compose, and the sweep is the half that cannot be skipped.

#![allow(
    dead_code,
    unreachable_pub,
    reason = "a shared test module is compiled into each test binary that includes it, and each uses the part of it that it needs"
)]
#![expect(
    clippy::expect_used,
    reason = "a fixture reports by panicking; there is no caller to hand a Result to"
)]

pub mod syntax;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Once;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The directory this run's fixtures live under.
pub fn run_root() -> PathBuf {
    static SWEPT: Once = Once::new();
    let all = std::env::temp_dir().join("uphold-tests");
    SWEPT.call_once(|| sweep(&all));
    let mine = all.join(std::process::id().to_string());
    let _ = std::fs::create_dir_all(&mine);
    mine
}

/// A fresh fixture directory, named for what it is for.
///
/// The name still carries a counter, because a test that names its fixture
/// after itself and runs twice in one binary would otherwise reuse the
/// directory it just filled.
pub fn scratch(kind: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = run_root().join(format!("{kind}-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&path);
    path
}

/// Remove what earlier runs left, and nothing that a live one is using.
///
/// A directory is named for the process that made it, so "is that process still
/// running" is the whole test. `/proc/<pid>` is that question on Linux, where
/// this suite runs; anywhere else the sweep declines rather than guessing, since
/// deleting a live run's fixtures would make one suite fail inside another.
fn sweep(all: &Path) {
    if !Path::new("/proc").is_dir() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(all) else {
        return;
    };
    let ours = std::process::id().to_string();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == ours || name.parse::<u32>().is_err() {
            continue;
        }
        if Path::new("/proc").join(name).exists() {
            continue;
        }
        let _ = std::fs::remove_dir_all(entry.path());
    }
}

/// The real `git`, not the shim standing in front of it.
///
/// `Command::new("git")` resolves through `PATH`, and on a machine where
/// `uphold shim --install` has been run the first `git` on `PATH` is a symlink
/// to this very binary. Every fixture-setup call in this suite then runs the
/// shim, which loads the repository's policy before running anything and
/// refuses when it cannot.
///
/// That is the shim being RIGHT, and it is why the failure is confusing: the
/// tests it breaks are the ones whose fixture is a policy that deliberately
/// does not load, so `git add -A` inside such a tree is precisely the
/// invocation `uphold` exists to refuse. Measured at v1.4.0 and every version
/// before it: three tests in `base_sets_cli.rs` fail on a developer machine and
/// pass in CI, because the runner has no shims installed. Green where a
/// regression would be caught and red only for whoever is developing the tool
/// is the shape that gets a test deleted.
///
/// So the fixtures say which `git` they mean. A candidate is skipped when it
/// resolves to a file named `uphold`, which is what `--install` creates: links
/// named after each command, all pointing at this binary.
///
/// The limit, stated rather than discovered: a shim installed under a binary
/// with some other file name is not recognised, and neither is a wrapper script
/// that is not a link. `--install` makes links to this binary and nothing else,
/// so what is covered is what the tool does; what is not covered is somebody
/// having built their own front-end, and that person is not surprised by this.
///
/// Falling back to the bare name when nothing else is found is deliberate: an
/// absent `git` should fail the way it always did, naming git, rather than
/// naming a helper the reader has to go and understand first.
pub fn real_git() -> PathBuf {
    static RESOLVED: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    RESOLVED.get_or_init(resolve_git).clone()
}

fn resolve_git() -> PathBuf {
    let Some(path) = std::env::var_os("PATH") else {
        return PathBuf::from("git");
    };
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join("git");
        if !candidate.is_file() {
            continue;
        }
        // The canonical target, not the link. A shim is a symlink whose target
        // is this binary, and its own file name is `git` like any other.
        let Ok(target) = std::fs::canonicalize(&candidate) else {
            continue;
        };
        if target.file_stem().is_some_and(|stem| stem == "uphold") {
            continue;
        }
        return candidate;
    }
    PathBuf::from("git")
}

/// What a hook runner exports that would send a fixture's `git` elsewhere.
///
/// The same list `detached` in `src/probe.rs` strips, and the two are copies
/// rather than one item because this crate is a binary: an integration test
/// links nothing from `src/`, and the one thing it could share would have to be
/// a public item of a library that does not exist. Whoever adds a name to one
/// list adds it to the other; `structural_git_env.rs` reads the other list off
/// the helper's body, so this is the one a reader has to remember.
const GIT_ENVIRONMENT: [&str; 8] = [
    "GIT_DIR",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_WORK_TREE",
    "GIT_PREFIX",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG_PARAMETERS",
];

/// A `git` that acts on `root` and on nothing else, however it was started.
///
/// `current_dir` is not what git reads first. A hook runner exports `GIT_DIR`
/// and `GIT_INDEX_FILE` to the hook it runs, and a suite run from inside that
/// hook -- a pre-push that runs the tests, say -- hands them to every fixture.
/// The fixture's `init --bare`, `config user.*`, `add` and `commit` then reach
/// the repository whose hook is running, not the scratch directory it was
/// pointed at: a fixture commit on top of the commit being pushed, and a main
/// checkout whose config says `core.bare = true`.
///
/// Stripped rather than overridden, for the reason `probe::detached` gives:
/// the list of what git reads from an environment is git's, and an override
/// answers only for the names somebody remembered.
pub fn git_command(root: &Path) -> Command {
    let mut command = Command::new(real_git());
    command.current_dir(root);
    for name in GIT_ENVIRONMENT {
        command.env_remove(name);
    }
    command
}

/// Run `git args` in `root`, and fail the test if git did.
///
/// stderr is kept for the failure message rather than dropped: a helper that
/// swallowed it reported a missing committer identity as `git ["commit", ...]
/// failed`, which is the one fact a reader already has -- and the cause was one
/// config line away in a message nobody could see.
pub fn git(root: &Path, args: &[&str]) {
    let output = git_command(root)
        .args(args)
        .stdout(Stdio::null())
        .output()
        .expect("git could not be started");
    assert!(
        output.status.success(),
        "git {args:?} in {} failed:\n{}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}
