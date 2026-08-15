//! Where every line this binary prints goes, and what it does when it cannot.
//!
//! `println!` unwraps the write and PANICS when it fails, and Rust ignores
//! `SIGPIPE` at startup, so the write returns `EPIPE` rather than the process
//! being killed the way a shell expects. `uphold rules --effective | head -2`
//! therefore exited **101**, which is not one of the three codes this tool
//! promises, out of a binary installed in front of `git`, `gh` and `npm`. The
//! run had already decided its verdict by then; what failed was writing the tail
//! of a report to a reader that had gone away, and a crash loses the verdict and
//! names `stdio.rs` at a reader who can act on neither.
//!
//! Two answers, because the two failures are not the same thing:
//!
//! * **The reader went away.** Nothing is wrong with the run and nothing more
//!   will be read, so the rest of the output is dropped and the exit code stays
//!   the verdict the run reached. `head` closing a pipe is a reader's decision,
//!   not a check that could not be made.
//! * **The write failed for any other reason** -- a full disk under a redirected
//!   report, a file this process may no longer write. There the output really
//!   did not arrive, nothing downstream has the report, and that is exit `2` by
//!   the rule that governs every other could-not-look in this tool. The first
//!   such error is kept and `main` reads it on the way out.
//!
//! Reached through the `println!`, `print!` and `eprintln!` in `main.rs`, which
//! shadow the ones in the prelude. A helper function beside them would have been
//! a rule 114 call sites had to remember and the next line of code could
//! silently break: the macro cannot be forgotten, because it is what the
//! habitual spelling already expands to.

use std::io::{ErrorKind, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

/// Which stream, and therefore which reader can have gone away independently of
/// the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stream {
    Out,
    Err,
}

/// A reader that has gone. Per stream: `uphold scan | head` closes stdout and
/// leaves a terminal on stderr, and a run that stopped reporting refusals there
/// because a pager exited would be this tool losing the only output that matters.
static OUT_GONE: AtomicBool = AtomicBool::new(false);
static ERR_GONE: AtomicBool = AtomicBool::new(false);

/// The first write that failed for a reason that was NOT a reader going away.
///
/// The first, and not the last: the later ones are the same disk. What a reader
/// needs is the error that started it, and `main` turns having one at all into
/// exit 2.
static UNWRITTEN: Mutex<Option<String>> = Mutex::new(None);

/// What a write to a closed or broken stream means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Nobody is reading. Stop writing to this stream and change nothing else.
    Gone,
    /// The bytes did not arrive and this is not the reader's doing.
    Unwritten,
}

/// Which of the two an `io::Error` is.
///
/// A function of its own because it is the whole of the decision, and the only
/// part of this module a test can drive without a real pipe and a real full
/// disk.
const fn verdict(kind: ErrorKind) -> Verdict {
    match kind {
        // `BrokenPipe` is the write to a pipe nobody holds open. `WouldBlock`
        // and the rest are not this, and folding them in would silently drop a
        // report on a stream that was still there.
        ErrorKind::BrokenPipe => Verdict::Gone,
        _ => Verdict::Unwritten,
    }
}

/// One line, and the newline that ends it.
pub(crate) fn line(stream: Stream, body: &str) {
    deliver(stream, body, true);
}

/// Exactly these bytes, with nothing added.
pub(crate) fn text(stream: Stream, body: &str) {
    deliver(stream, body, false);
}

fn gone_flag(stream: Stream) -> &'static AtomicBool {
    match stream {
        Stream::Out => &OUT_GONE,
        Stream::Err => &ERR_GONE,
    }
}

fn deliver(stream: Stream, body: &str, newline: bool) {
    let gone = gone_flag(stream);
    // Asked before the write rather than after the failure: once a reader has
    // gone every subsequent line is another failed syscall, and a report with
    // thousands of findings would make thousands of them.
    if gone.load(Ordering::Relaxed) {
        return;
    }
    let result = match stream {
        Stream::Out => put(&mut std::io::stdout().lock(), body, newline),
        Stream::Err => put(&mut std::io::stderr().lock(), body, newline),
    };
    let Err(error) = result else {
        return;
    };
    match verdict(error.kind()) {
        Verdict::Gone => gone.store(true, Ordering::Relaxed),
        Verdict::Unwritten => {
            if let Ok(mut held) = UNWRITTEN.lock() {
                held.get_or_insert_with(|| error.to_string());
            }
        }
    }
}

fn put(handle: &mut impl Write, body: &str, newline: bool) -> std::io::Result<()> {
    handle.write_all(body.as_bytes())?;
    if newline {
        handle.write_all(b"\n")?;
    }
    Ok(())
}

/// The write that did not arrive, if one did not.
///
/// `main` asks on the way out. A run whose findings never reached the file they
/// were redirected to has not reported them, and exiting 0 over that is the
/// could-not-look-reported-as-a-pass this whole tool is about -- with this
/// tool's own name on it.
pub(crate) fn unwritten() -> Option<String> {
    UNWRITTEN.lock().ok().and_then(|held| held.clone())
}

#[cfg(test)]
mod tests {
    use super::{put, verdict, Verdict};
    use std::io::ErrorKind;

    /// The one decision this module makes, and the direction each way costs
    /// something: a broken pipe read as unwritten turns `| head` into exit 2,
    /// and anything else read as a broken pipe drops a report on a stream that
    /// was still there and says nothing.
    #[test]
    fn only_a_reader_that_went_away_is_a_reader_that_went_away() {
        assert_eq!(verdict(ErrorKind::BrokenPipe), Verdict::Gone);
        for other in [
            ErrorKind::PermissionDenied,
            ErrorKind::WriteZero,
            ErrorKind::Interrupted,
            ErrorKind::Other,
        ] {
            assert_eq!(verdict(other), Verdict::Unwritten, "{other:?}");
        }
    }

    #[test]
    fn a_line_carries_its_newline_and_text_carries_nothing() {
        let mut written: Vec<u8> = Vec::new();
        put(&mut written, "a", true).unwrap();
        put(&mut written, "b", false).unwrap();
        assert_eq!(written, b"a\nb");
    }
}
