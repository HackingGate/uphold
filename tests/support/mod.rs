//! Where a fixture lives, and who removes it.
//!
//! Every CLI test here builds a real repository, and until this module existed
//! each one built it directly under the system temporary directory and removed
//! it only on the way IN -- `remove_dir_all` before `create_dir_all`, which
//! defends against a name colliding and frees nothing. The names carry a process
//! id precisely so that they do not collide, so nothing was ever freed.
//!
//! Measured before the fix: one working session left 84,992 directories under
//! `/tmp`, occupying the whole of the tmpfs they share. It is not a slow leak
//! -- a mutation run repeats the whole suite once per mutant, so a hundred
//! suites is an ordinary afternoon -- and what it broke was a `cargo mutants`
//! run, which died on `No space left on device` and reported 158 mutants
//! "unviable". A tool reporting a measurement it could not make is the shape
//! this repository exists to refuse, and the test suite caused it.
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

pub mod syntax;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Once;

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
fn sweep(all: &std::path::Path) {
    if !std::path::Path::new("/proc").is_dir() {
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
        if std::path::Path::new("/proc").join(name).exists() {
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
