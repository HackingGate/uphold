//! Where a fixture lives, and who removes it.
//!
//! Every CLI test here builds a real repository, and until this module existed
//! each one built it directly under the system temporary directory and removed
//! it only on the way IN -- `remove_dir_all` before `create_dir_all`, which
//! defends against a name colliding and frees nothing. The names carry a process
//! id precisely so that they do not collide, so nothing was ever freed.
//!
//! Measured before the fix: one working session left 84,992 directories under
//! `/tmp`, occupying 15 GB of a 16 GB tmpfs. It is not a slow leak -- a mutation
//! run repeats the whole suite once per mutant, so a hundred suites is an
//! ordinary afternoon -- and what it broke was a `cargo mutants` run, which died
//! on `No space left on device` and reported 158 of 162 mutants "unviable". A
//! tool reporting a measurement it could not make is the shape this repository
//! exists to refuse, and the test suite caused it.
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
