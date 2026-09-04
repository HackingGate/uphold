//! Where a unit test's fixture lives, and who removes it.
//!
//! The same answer `tests/support` gives the CLI tests, for the tests inside
//! this crate: a fixture goes under `<temp>/uphold-tests/<pid>/`, and the first
//! one in a run sweeps every sibling whose process is gone.
//!
//! It exists because the old shape -- a directory named for the process, cleared
//! on the way IN and never on the way out -- freed nothing by construction: the
//! name carries the pid precisely so it cannot collide with a live run, so
//! `remove_dir_all` before `create_dir_all` never had anything to remove.
//! Observed before the fix, one working session left enough of them under
//! `/tmp` to fill the tmpfs they share, killing a `cargo mutants` run with
//! `No space left on device` -- which the run then reported as mutants it
//! found "unviable", a measurement it had not made.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Once;

/// The directory this test run's fixtures live under.
pub(crate) fn run_root() -> PathBuf {
    static SWEPT: Once = Once::new();
    let all = std::env::temp_dir().join("uphold-tests");
    SWEPT.call_once(|| sweep(&all));
    let mine = all.join(std::process::id().to_string());
    drop(std::fs::create_dir_all(&mine));
    mine
}

/// A fresh fixture directory, named for what it is for.
pub(crate) fn scratch(kind: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = run_root().join(format!("{kind}-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
    drop(std::fs::remove_dir_all(&path));
    path
}

/// Remove what earlier runs left, and nothing a live one is using.
///
/// A directory is named for the process that made it, so "is that process still
/// running" is the whole test, and `/proc/<pid>` is that question here. Where
/// there is no `/proc` the sweep declines rather than guessing: deleting a live
/// run's fixtures would make one suite fail inside another.
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
        drop(std::fs::remove_dir_all(entry.path()));
    }
}
