//! The git calls the guards share.
//!
//! Every one of these reports the failure rather than swallowing it. A guard
//! that cannot ask git what it is about to do has not established that the act
//! is safe; it has established nothing, and returning an empty answer would
//! make that look like a pass.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Fatal, Result};

/// Run git, returning stdout. `Ok(None)` where git itself said no -- a ref that
/// does not exist, a config key that is unset -- which is an answer.
pub(crate) fn try_run(root: &Path, args: &[&str]) -> Result<Option<String>> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| Fatal::new(format!("git {}: {error}", args.join(" "))))?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
}

pub(crate) fn run(root: &Path, args: &[&str]) -> Result<String> {
    try_run(root, args)?.ok_or_else(|| {
        Fatal::new(format!(
            "git {} failed; the guard cannot see what it is being asked about",
            args.join(" ")
        ))
    })
}

/// Which of these objects git says are blobs, asked once rather than once each.
///
/// The two pipes move at the same time, on two threads, and that is not a style
/// preference. `--batch-check` answers each object as it reads it, at roughly
/// fifty bytes an answer, so it fills its stdout pipe -- 64 KiB on Linux --
/// somewhere near the thirteen-hundredth object and stops reading stdin. A
/// parent that writes the whole list first is then blocked on a full stdin pipe
/// while the child is blocked on a stdout pipe nobody is draining, and neither
/// ever moves again: no output, no exit code, the push simply stops. Every
/// repository these callers are meant for is far past that count, so writing
/// first is not a rare hang, it is the ordinary case.
///
/// This lived twice, and the third caller is why it lives here instead: the
/// audit and the selection pass each grew their own writer thread while the
/// pre-push guard kept the version that hangs. One copy is the only shape in
/// which that cannot happen again.
pub(crate) fn blob_shas(root: &Path, shas: &[String]) -> Result<BTreeSet<String>> {
    use std::io::{Read, Write};
    use std::process::Stdio;

    let mut blobs = BTreeSet::new();
    if shas.is_empty() {
        return Ok(blobs);
    }

    let mut child = Command::new("git")
        .args(["cat-file", "--batch-check=%(objectname) %(objecttype)"])
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| Fatal::new(format!("git cat-file: {error}")))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Fatal::new("git cat-file: no stdin"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| Fatal::new("git cat-file: no stdout"))?;

    let mut answered: Vec<u8> = Vec::new();
    let written = std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            for sha in shas {
                writeln!(stdin, "{sha}")?;
            }
            // Dropped here, and closing stdin is what tells `--batch-check` the
            // list is finished. Without it the child waits for more input that
            // is never coming and the read below never sees end of file.
            drop(stdin);
            Ok::<(), std::io::Error>(())
        });
        let drained = stdout.read_to_end(&mut answered);
        // The writer's own error outranks the drain's: a child that died early
        // shows up here as a broken pipe, and the drain merely stops.
        writer.join().map_or_else(
            |_| {
                Err(std::io::Error::other(
                    "git cat-file: writer thread panicked",
                ))
            },
            |result| result.and_then(|()| drained.map(|_| ())),
        )
    });
    written.map_err(|error| Fatal::new(format!("git cat-file: {error}")))?;

    let status = child
        .wait()
        .map_err(|error| Fatal::new(format!("git cat-file: {error}")))?;
    // Reported rather than swallowed: no stdout means no known kinds, every
    // caller's filter then keeps nothing, and a set of objects that could not be
    // identified would read as a set with no blobs in it.
    //
    // A missing object is not this case. `--batch-check` writes "<sha> missing"
    // and still exits 0, so a non-zero status means git itself could not run.
    if !status.success() {
        return Err(Fatal::new(format!(
            "git cat-file --batch-check exited {}: cannot tell which of {} object(s) \
             are blobs, and reporting none of them would read as nothing to check",
            status.code().unwrap_or(-1),
            shas.len()
        )));
    }

    let text = String::from_utf8_lossy(&answered);
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if let [name, "blob", ..] = fields.as_slice() {
            blobs.insert((*name).to_owned());
        }
    }
    Ok(blobs)
}

/// The bytes of every named object, from ONE `git cat-file --batch`.
///
/// The audit read its blobs one `git cat-file blob <sha>` at a time, with no cap
/// and nothing printed between the first object and the last. On a repository
/// whose reachable set runs to five figures that is five figures of process
/// spawns, and the run is silent for all of them: a slow audit and a hung audit
/// look identical from outside, so the reader's only available move is to kill
/// it and not find out which it was. One process answers the whole list, and
/// `visit` is called as each object arrives, so the caller can say how far it
/// has got.
///
/// Streamed rather than collected, because these are every blob a repository
/// ever reached and holding them twice is holding a repository twice. The
/// caller keeps what it needs from each and this function keeps one.
///
/// The two pipes move at the same time, on two threads, for the reason
/// `blob_shas` states at length: a parent that writes the whole list before
/// reading a byte back deadlocks against a child that has stopped reading stdin
/// because nobody is draining its stdout. `--batch` is worse than
/// `--batch-check` here, not better -- it answers with whole file contents
/// rather than fifty bytes -- so a full pipe arrives sooner.
///
/// Returns the objects git could not produce. A missing object is an answer,
/// not a failure: `--batch` writes "<oid> missing" and exits 0, and a shallow or
/// partial clone is the ordinary way to arrive here. It is the caller's to
/// report, and reporting it is what keeps "the audit did not read this" out of
/// the same bucket as "the audit read this and found nothing".
pub(crate) fn each_blob<F>(
    root: &Path,
    shas: &[String],
    mut visit: F,
) -> Result<Vec<(String, String)>>
where
    F: FnMut(&str, &[u8]),
{
    use std::io::Write;
    use std::process::Stdio;

    let mut absent = Vec::new();
    if shas.is_empty() {
        return Ok(absent);
    }
    let asked = shas.len();

    let mut child = Command::new("git")
        .args(["cat-file", "--batch"])
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| Fatal::new(format!("git cat-file --batch: {error}")))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Fatal::new("git cat-file --batch: no stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Fatal::new("git cat-file --batch: no stdout"))?;

    let read = std::thread::scope(|scope| {
        let writer = scope.spawn(move || {
            for sha in shas {
                writeln!(stdin, "{sha}")?;
            }
            // Closing stdin is what tells `--batch` the list is finished; see
            // `blob_shas`, where the same drop is the difference between an end
            // of file and a wait for input that is never coming.
            drop(stdin);
            Ok::<(), std::io::Error>(())
        });
        let drained = drain_batch(stdout, &mut absent, &mut visit);
        // The writer's error outranks the reader's, for `blob_shas`'s reason: a
        // child that died early reaches the writer as a broken pipe and reaches
        // the reader as a short read, and only the first of those says why.
        writer.join().map_or_else(
            |_| {
                Err(std::io::Error::other(
                    "git cat-file --batch: writer thread panicked",
                ))
            },
            |result| result.and(drained),
        )
    });
    read.map_err(|error| Fatal::new(format!("git cat-file --batch: {error}")))?;

    let status = child
        .wait()
        .map_err(|error| Fatal::new(format!("git cat-file --batch: {error}")))?;
    // Refused rather than swallowed, exactly as in `blob_shas`: a non-zero exit
    // means git itself could not run, and the objects not yet answered for would
    // otherwise read as objects with nothing in them.
    if !status.success() {
        return Err(Fatal::new(format!(
            "git cat-file --batch exited {}: the contents of one or more of {asked} object(s) \
             were never read, and reporting them as empty would read as nothing to check",
            status.code().unwrap_or(-1)
        )));
    }
    Ok(absent)
}

/// One `--batch` record at a time: a header line, then exactly the bytes it
/// says, then the newline git writes after them.
///
/// By size rather than by line, because a blob is not text. A reader that split
/// this stream on newlines would take the first line of a file for the header of
/// the next object, and a file holding a NUL or a lone CR would be read as a
/// different object entirely.
fn drain_batch<R, F>(
    stdout: R,
    absent: &mut Vec<(String, String)>,
    visit: &mut F,
) -> std::result::Result<(), std::io::Error>
where
    R: std::io::Read,
    F: FnMut(&str, &[u8]),
{
    use std::io::{BufRead, BufReader, Read};

    let mut reader = BufReader::new(stdout);
    let mut header = Vec::new();
    loop {
        header.clear();
        if reader.read_until(b'\n', &mut header)? == 0 {
            return Ok(());
        }
        let line = String::from_utf8_lossy(&header).trim_end().to_owned();
        let mut fields = line.split_whitespace();
        let (Some(oid), Some(kind)) = (fields.next(), fields.next()) else {
            continue;
        };
        // "missing", "ambiguous", and any other one-word verdict git grows: what
        // they share is that no content follows, so the only correct move is to
        // name the object and read the next header.
        let Some(size) = fields.next().and_then(|size| size.parse::<usize>().ok()) else {
            absent.push((oid.to_owned(), kind.to_owned()));
            continue;
        };
        let mut body = vec![0_u8; size];
        reader.read_exact(&mut body)?;
        // The newline git writes after every object, which is not part of it.
        let mut terminator = [0_u8; 1];
        reader.read_exact(&mut terminator)?;
        if kind == "blob" {
            visit(oid, &body);
        }
    }
}

/// NUL-separated output, for the paths git will not quote.
pub(crate) fn run_z(root: &Path, args: &[&str]) -> Result<Vec<String>> {
    Ok(run(root, args)?
        .split('\0')
        .filter(|field| !field.is_empty())
        .map(str::to_owned)
        .collect())
}

pub(crate) fn dir(root: &Path) -> Result<PathBuf> {
    let raw = run(root, &["rev-parse", "--git-dir"])?;
    let trimmed = raw.trim();
    let path = PathBuf::from(trimmed);
    Ok(if path.is_absolute() {
        path
    } else {
        root.join(path)
    })
}

pub(crate) fn config_global(key: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["config", "--global", key])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!value.is_empty()).then_some(value)
}

/// `Name <address>`, split.
pub(crate) fn split_ident(ident: &str) -> (String, String) {
    let name = ident.split(" <").next().unwrap_or("").trim().to_owned();
    let email = ident
        .split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .map(|(address, _)| address.trim().to_owned())
        .unwrap_or_default();
    (name, email)
}

/// The remote url for a name, or the name itself when it already is one.
pub(crate) fn remote_url(root: &Path, remote: &str) -> Option<String> {
    if remote.contains("://") || remote.contains('@') {
        return Some(remote.to_owned());
    }
    try_run(root, &["remote", "get-url", remote])
        .ok()
        .flatten()
        .map(|url| url.trim().to_owned())
        .filter(|url| !url.is_empty())
}

/// `owner/repo` from any spelling of a forge url.
pub(crate) fn owner_repo(url: &str) -> Option<(String, String)> {
    let trimmed = url.trim().trim_end_matches('/');
    let without_git = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    // scp-like (`git@host:owner/repo`) and url forms both end in owner/repo.
    let tail = without_git
        .rsplit_once(':')
        .map(|(_, tail)| tail)
        .filter(|tail| !tail.starts_with("//") && tail.contains('/'))
        .unwrap_or(without_git);
    let mut parts = tail.rsplit('/');
    let repo = parts.next()?.to_owned();
    let owner = parts.next()?.to_owned();
    if owner.is_empty() || repo.is_empty() || owner.contains("://") {
        return None;
    }
    Some((owner, repo))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_and_repo_come_out_of_every_url_spelling() {
        for url in [
            "https://github.com/acme/widget.git",
            "https://github.com/acme/widget",
            "git@github.com:acme/widget.git",
            "ssh://git@github.com/acme/widget.git",
            "https://github.com/acme/widget/",
        ] {
            assert_eq!(
                owner_repo(url),
                Some(("acme".to_owned(), "widget".to_owned())),
                "{url}"
            );
        }
    }

    #[test]
    fn an_ident_splits_into_its_two_halves() {
        assert_eq!(
            split_ident("Ada Lovelace <ada@example.test> 1700000000 +0000"),
            ("Ada Lovelace".to_owned(), "ada@example.test".to_owned())
        );
    }

    #[test]
    fn several_thousand_objects_are_asked_about_without_deadlocking() {
        // The proof for the pipe. `--batch-check` answers each object as it
        // reads it, at roughly fifty bytes an answer, so 4000 objects is 160 KiB
        // of stdin and 200 KiB back -- several times over the 64 KiB a pipe
        // holds in each direction. A caller that wrote the whole list before
        // reading a byte stopped somewhere past the fifteen-hundredth and never
        // came back, which is what `guard::scope::keep_blobs` did to every push
        // of a range this size.
        //
        // On a thread with a deadline, because a test that proves a deadlock is
        // gone has to FAIL when it is not, and a test that hangs reports nothing
        // at all -- it stops the suite with no failing test named.
        let root = std::env::temp_dir().join(format!("uphold-git-batch-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(&root).unwrap();
        for args in [
            &["init", "-q", "-b", "main"][..],
            &["config", "user.name", "Test"][..],
            &["config", "user.email", "test@example.test"][..],
        ] {
            let status = Command::new("git")
                .args(args)
                .current_dir(&root)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        }

        // Written and staged in one `git add`, because the point of the test is
        // the pipe and not the fixture: 4000 `hash-object` processes cost a
        // minute of suite time to produce the same 4000 shas.
        for index in 0..4000_u32 {
            std::fs::write(
                root.join(format!("blob-{index:05}.txt")),
                format!("blob number {index}\n"),
            )
            .unwrap();
        }
        let status = Command::new("git")
            .args(["add", "-A", "."])
            .current_dir(&root)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git add failed");
        let staged = run(&root, &["ls-files", "-s"]).unwrap();
        let shas: Vec<String> = staged
            .lines()
            .filter_map(|line| line.split_whitespace().nth(1).map(str::to_owned))
            .collect();
        assert_eq!(shas.len(), 4000, "the fixture did not stage");

        let (sender, receiver) = std::sync::mpsc::channel();
        let asked = root.clone();
        let listed = shas.clone();
        std::thread::spawn(move || {
            sender.send(blob_shas(&asked, &listed)).ok();
        });
        let blobs = receiver
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("`git cat-file --batch-check` did not answer: the pipes deadlocked")
            .unwrap();

        assert_eq!(blobs.len(), shas.len());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn an_empty_list_asks_git_nothing() {
        assert!(blob_shas(&std::env::temp_dir(), &[]).unwrap().is_empty());
        assert!(each_blob(&std::env::temp_dir(), &[], |_, _| ())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_batch_read_returns_whole_blobs_and_names_the_ones_git_has_not_got() {
        // The content is the point: `--batch` writes a header line, then exactly
        // the bytes it announced, then a newline of its own. A reader that split
        // this stream on newlines would take the second line of this file for
        // the header of the next object -- so the fixture holds a newline, a
        // NUL, and something that looks exactly like a header.
        let root = std::env::temp_dir().join(format!("uphold-git-read-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(&root).unwrap();
        for args in [
            &["init", "-q", "-b", "main"][..],
            &["config", "user.name", "Test"][..],
            &["config", "user.email", "test@example.test"][..],
        ] {
            let status = Command::new("git")
                .args(args)
                .current_dir(&root)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        }
        let awkward: Vec<u8> = b"first line\n0123456789abcdef blob 12\n\0trailing".to_vec();
        std::fs::write(root.join("awkward.bin"), &awkward).unwrap();
        std::fs::write(root.join("plain.txt"), "plain\n").unwrap();
        let status = Command::new("git")
            .args(["add", "-A", "."])
            .current_dir(&root)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git add failed");

        let staged = run(&root, &["ls-files", "-s"]).unwrap();
        let mut shas: Vec<String> = staged
            .lines()
            .filter_map(|line| line.split_whitespace().nth(1).map(str::to_owned))
            .collect();
        assert_eq!(shas.len(), 2, "the fixture did not stage");
        // An object this repository has never held, which `--batch` answers for
        // by name and still exits 0. A shallow or partial clone is the ordinary
        // way to meet one, and it is not a blob that was read and found clean.
        let absent_sha = String::from("0123456789012345678901234567890123456789");
        shas.push(absent_sha.clone());

        let mut read: Vec<(String, Vec<u8>)> = Vec::new();
        let absent = each_blob(&root, &shas, |sha, bytes| {
            read.push((sha.to_owned(), bytes.to_vec()));
        })
        .unwrap();

        assert_eq!(read.len(), 2, "{read:?}");
        assert!(
            read.iter().any(|(_, bytes)| bytes == &awkward),
            "a blob holding a newline and a NUL did not come back whole"
        );
        assert_eq!(absent.len(), 1);
        assert_eq!(absent[0].0, absent_sha);
        std::fs::remove_dir_all(&root).ok();
    }
}
