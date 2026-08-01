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
