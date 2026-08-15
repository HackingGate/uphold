//! Two failure kinds, kept apart because they exit differently.
//!
//! A policy violation is the tool working: something in the tree broke a rule,
//! and the run exits 1. An infrastructure error is the tool NOT working: a
//! policy file that will not parse, a source that names nothing, a search that
//! died. That exits 2, and the distinction is load-bearing -- a caller that
//! folded them together would read "could not look" as "looked and found
//! nothing", which is the `explicit-unknown` failure on this tool's own output.

use std::fmt;
use std::io;
use std::path::Path;

/// Something that stopped the run rather than something the run found.
#[derive(Debug)]
pub(crate) struct Fatal {
    message: String,
}

impl Fatal {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// An error that a reader can only act on once they know which file it came
    /// from. `toml` reports a line and column and no path; a bare
    /// "expected a table" names nothing a reader can open.
    pub(crate) fn at(path: &Path, message: impl fmt::Display) -> Self {
        Self::new(format!("{}: {message}", path.display()))
    }
}

impl fmt::Display for Fatal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Fatal {}

impl From<io::Error> for Fatal {
    fn from(error: io::Error) -> Self {
        Self::new(error.to_string())
    }
}

pub(crate) type Result<T> = std::result::Result<T, Fatal>;

/// Read a file, naming it in the error. `fs::read_to_string` reports the reason
/// and not the path, so the same "No such file or directory" arrives from every
/// call site indistinguishably.
pub(crate) fn read_to_string(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|error| Fatal::at(path, error))
}

/// The exit code convention, in one place because three callers share it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exit {
    Clean = 0,
    Violations = 1,
    Broken = 2,
}

impl Exit {
    pub(crate) const fn code(self) -> i32 {
        self as i32
    }
}

/// The exit code a run owes its reader, from what it found and what it could
/// not read.
///
/// One function because it is one decision, and it was written out three times:
/// in `audit --for-publication`, in `scan`, and in the coverage half of `check`.
/// Three transcriptions of a ranking is three places for the ranking to drift,
/// and the drift is silent -- every one of them still returns a valid `Exit`.
///
/// The ranking: a violation outranks a surface this run could not read, because
/// something WAS found and that is the answer the reader has to act on first.
/// The unread surfaces are printed either way, so nothing is hidden by the
/// ranking; only the code is decided by it.
///
/// What must never happen is the third arm being reached with either count
/// non-zero, which is `UNKNOWN -> PASS`, the failure this repository keeps
/// finding one seam at a time. `#[cfg(kani)] mod proofs` states that as a
/// property over every pair of counts rather than over the four this module's
/// tests can name.
pub(crate) const fn verdict(found: usize, could_not_look: usize) -> Exit {
    if found > 0 {
        Exit::Violations
    } else if could_not_look > 0 {
        Exit::Broken
    } else {
        Exit::Clean
    }
}

/// The exit-state invariants, over every pair of counts.
///
/// `cargo kani --harness <name>`, and see CONTRIBUTING for what it costs. This
/// is the manual tier: the proofs run in about a second each, and the toolchain
/// they need is half a gigabyte that no commit should wait for.
///
/// A unit test names four input pairs out of 2^128. These say the same thing
/// about all of them, which is worth having for exactly one function in this
/// crate -- the one where an unknown becomes a number a caller acts on.
#[cfg(kani)]
mod proofs {
    use super::{verdict, Exit};

    /// `could not look -> exit != 0`.
    #[kani::proof]
    fn a_run_that_could_not_look_never_exits_clean() {
        let could_not_look: usize = kani::any();
        kani::assume(could_not_look > 0);
        assert!(verdict(kani::any(), could_not_look).code() != 0);
    }

    /// `violation -> exit == 1`, whatever else the run could not read.
    #[kani::proof]
    fn a_violation_outranks_a_surface_that_could_not_be_read() {
        let found: usize = kani::any();
        kani::assume(found > 0);
        assert!(verdict(found, kani::any()) as i32 == Exit::Violations as i32);
    }

    /// Clean is reachable, and reachable from nothing else. The second half is
    /// the one that matters; the first is here because a verdict function that
    /// could never return clean is the defect this one was extracted after.
    #[kani::proof]
    fn clean_means_read_everything_and_found_nothing() {
        let found: usize = kani::any();
        let could_not_look: usize = kani::any();
        let clean = verdict(found, could_not_look) as i32 == Exit::Clean as i32;
        assert!(clean == (found == 0 && could_not_look == 0));
    }

    /// Every answer is one of the three codes this tool promises. A fourth
    /// would be a code no caller has a branch for.
    #[kani::proof]
    fn the_only_codes_are_the_three_that_are_documented() {
        let code = verdict(kani::any(), kani::any()).code();
        assert!(code == 0 || code == 1 || code == 2);
    }
}
