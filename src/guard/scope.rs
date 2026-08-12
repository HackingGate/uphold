//! Which bytes is this operation actually introducing?
//!
//! Two guards scan a whole repository rather than a diff, and each used to
//! answer this for itself out of the WORKING TREE. Both answers were wrong, in
//! the same direction, for three different reasons, and every one of them ends
//! with a green tick over bytes nobody looked at:
//!
//! * At pre-commit the working tree is not what is being committed. A line
//!   staged and then edited away is in the commit and not on disk; a line typed
//!   and never staged is on disk and not in the commit.
//! * At pre-push the working tree is not what is being pushed. Commit a private
//!   name on a branch, check out another, push the branch: the file is not even
//!   on disk, and the guard registered at pre-push exactly to catch a name that
//!   got in without passing a hook reads a clean tree and prints Passed.
//! * A symlink's content is not the file it points at. Git stores the TARGET
//!   PATH as the blob, so a link whose target carries a zero-width space commits
//!   one -- while any reader that follows the link scans some other file's bytes.
//!
//! Two guards asking one question two ways is two rules that agree until they
//! do not, so the question is answered ONCE, here.
//!
//! **The index, unless a push says otherwise.**
//!
//! The index is the tree the next commit will have, which makes it right at
//! pre-commit and at pre-merge-commit (git has already merged into it by the
//! time the hook runs). At the manual stage, in a checkout CI has just made, the
//! index is HEAD -- so one answer covers that stage too.
//!
//! A push is the one operation with no index at all: what becomes shared is a
//! COMMIT, and the working tree beside it may be on a different branch entirely.
//! There the artifact is the commit being pushed -- its whole tree PLUS every
//! blob the pushed RANGE introduces. Neither half is a superset of the other:
//!
//! * THE TIP'S TREE catches what arrived BEFORE this range: a name committed
//!   under `--no-verify` last month and carried forward by every commit since.
//!   No diff over this push names it, because to this push it is not new.
//! * THE RANGE catches what passed THROUGH it. A blob added in one pushed commit
//!   and removed in the next is in the remote's history permanently, is in no
//!   tip tree, and was read by nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use globset::Glob;

use super::Stage;
use crate::config::Rule;
use crate::error::{Fatal, Result};
use crate::git;

/// One `[rule.files]` glob, given ripgrep's meaning.
///
/// A glob with no slash matches a BASENAME anywhere in the tree -- `*.md` means
/// every markdown file, not only the ones beside the config. globset does not
/// assume that, and `*` does not cross a `/`, so the pattern has to say it.
fn path_glob(pattern: &str) -> Result<globset::GlobMatcher> {
    let anchored = if pattern.contains('/') {
        pattern.to_owned()
    } else {
        format!("**/{pattern}")
    };
    Ok(Glob::new(&anchored)
        .map_err(|error| Fatal::new(format!("{pattern:?} is not a path glob: {error}")))?
        .compile_matcher())
}

/// Whether a blob is in scope for this rule, by `[rule.files]`.
///
/// A built-in's `[rule.files]` is optional and deliberately NOT refused when
/// written, because which artifact a built-in reads is its own business. Both
/// blob-reading guards then read every blob regardless, so an `exclude` would
/// parse, validate, and do nothing. Config that is accepted and then ignored is
/// the failure this repository exists to make loud, and it was in the guards
/// that report it about everyone else.
///
/// Here rather than in either guard for the reason this module exists: two
/// guards answering one question two ways is two rules that agree until they do
/// not.
///
/// `glob` selects when present; `exclude` always removes. An absent
/// `[rule.files]` selects everything, which is what every rule that never
/// mentioned files has always got.
pub(crate) fn in_file_scope(rule: &Rule, path: &str) -> Result<bool> {
    if !rule.reads_files() {
        return Ok(true);
    }
    let files = rule.files();
    // `include` names directory roots, and it was the one field of the three
    // this function did not read -- so a guard scoped with `include` read the
    // whole tree while its author had written down a smaller one. That is the
    // same defect this function exists to fix, one field over. A root selects
    // everything under it, which is what it means to the scan's walker.
    if let Some(include) = &files.include {
        let roots: Vec<&String> = include.iter().filter(|spec| spec.as_str() != ".").collect();
        if !roots.is_empty()
            && !roots.iter().any(|spec| {
                let prefix = spec.trim_end_matches('/');
                path == prefix || path.starts_with(&format!("{prefix}/"))
            })
        {
            return Ok(false);
        }
    }
    if !files.glob.is_empty() {
        let mut selected = false;
        for pattern in &files.glob {
            if path_glob(pattern)?.is_match(path) {
                selected = true;
                break;
            }
        }
        if !selected {
            return Ok(false);
        }
    }
    for pattern in &files.exclude {
        if path_glob(pattern)?.is_match(path) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// One entry the operation is introducing: the path it arrived under, the
/// object sitting at it, and the MODE git recorded beside the two.
///
/// The mode is carried rather than inferred, because inferring it means finding
/// out by trying to read. A gitlink -- mode 160000, one line per submodule in
/// every index in this workspace -- names ANOTHER repository's commit, and
/// `git cat-file blob <commit-oid>` fails on it. `read` reported that failure
/// the way it reports any other, so a tree with a submodule in it aborted both
/// tree-wide guards with exit 2 and neither of them ever finished a scan here.
///
/// The entry is still enumerated, and deliberately: its PATH is this
/// repository's own committed text whatever the object at it turns out to be.
/// What the mode decides is whether there are BYTES here to read, which is what
/// `has_content` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Blob {
    pub path: String,
    pub sha: String,
    /// git's six-digit mode, or empty for an object `rev-list` named -- that
    /// listing gives an object and a path it once appeared at, and no mode.
    pub mode: String,
}

/// A submodule: another repository's commit, recorded at a path in this one.
const GITLINK: &str = "160000";

impl Blob {
    /// Whether this repository holds bytes at this entry.
    ///
    /// False for exactly one thing, and it is not a judgement about the file:
    /// a submodule's commit belongs to a repository with its own object
    /// database and its own hooks. There is nothing here to read, and nothing
    /// hidden by not reading it -- the path above is this repository's and is
    /// scanned by the callers either way.
    pub(crate) fn has_content(&self) -> bool {
        self.mode != GITLINK
    }
}

const ZERO: &str = "0000000000000000000000000000000000000000";

/// Every blob this operation introduces, deduplicated by (path, sha).
pub(crate) fn blobs(
    root: &Path,
    stage: Stage,
    push_refs: &str,
    push_source: crate::runner::Source,
    remote: Option<&str>,
) -> Result<Vec<Blob>> {
    let mut found: BTreeMap<(String, String), Blob> = BTreeMap::new();

    if stage == Stage::PrePush {
        // Nobody said what this push is. Before this was a state, it was the
        // same value as "a push introducing nothing", and the fall-through
        // below scanned the INDEX -- at pre-push quite likely a different
        // branch than the one being sent -- and reported on it as the push.
        // Under pre-commit and prek that was not an edge case: neither
        // forwards git's stdin, so it was every push.
        if push_source == crate::runner::Source::Absent {
            return Err(Fatal::new(
                "pre-push: no ref line reached this guard, on stdin or from the runner, \
                 so what is being pushed is unknown -- refusing to scan the working tree \
                 instead.\n\n\
                 Under lefthook, the pre-push job needs `use_stdin: true`; without it \
                 lefthook runs the command under a pseudo-TTY and git's ref lines never \
                 arrive.\n\
                 Under pre-commit or prek this is exported for you; a run driven by hand \
                 needs `--remote NAME` and the ref lines on stdin, or the manual stage, \
                 which reads the tree on purpose.",
            ));
        }
        for line in push_refs.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [_, local_sha, _, remote_sha, ..] = fields.as_slice() else {
                continue;
            };
            // An all-zero local sha is a deletion. Nothing is being introduced.
            if local_sha.chars().all(|character| character == '0') {
                continue;
            }
            for blob in tree_blobs(root, local_sha)? {
                found.insert((blob.path.clone(), blob.sha.clone()), blob);
            }
            for blob in range_blobs(root, local_sha, remote_sha, remote)? {
                found.insert((blob.path.clone(), blob.sha.clone()), blob);
            }
        }
        // A push line the hook could not parse is not an empty push. Falling
        // through to the index here would scan the local branch instead of the
        // one being sent, and report on it as though it were.
        if found.is_empty() && !push_refs.trim().is_empty() {
            return Err(Fatal::new(
                "pre-push: no ref line could be read from stdin; refusing to scan the \
                 working tree instead of what is being pushed",
            ));
        }
        return Ok(found.into_values().collect());
    }

    for blob in index_blobs(root)? {
        found.insert((blob.path.clone(), blob.sha.clone()), blob);
    }
    Ok(found.into_values().collect())
}

/// `<mode> <sha> <stage>\t<path>`, NUL-separated.
fn index_blobs(root: &Path) -> Result<Vec<Blob>> {
    let records = git::run_z(root, &["ls-files", "-s", "-z"])?;
    if records.is_empty() {
        // HEAD is the last resort, for a repository with no index to read: a
        // bare clone, or a scan pointed at a rev by hand.
        if git::try_run(root, &["rev-parse", "-q", "--verify", "HEAD"])?.is_some() {
            return tree_blobs(root, "HEAD");
        }
        return Ok(Vec::new());
    }
    let mut blobs = Vec::new();
    for record in records {
        let Some((meta, path)) = record.split_once('\t') else {
            continue;
        };
        let fields: Vec<&str> = meta.split_whitespace().collect();
        let [mode, sha, _, ..] = fields.as_slice() else {
            continue;
        };
        // Mode 120000 is a symlink, and its blob is the TARGET PATH. Kept, for
        // the reason in the module docstring: that path is committed bytes.
        // Mode 160000 is a gitlink, whose object is not in this repository at
        // all -- kept too, for its path, and marked by the mode so that nobody
        // downstream asks git for bytes that are somebody else's.
        blobs.push(Blob {
            path: path.to_owned(),
            sha: (*sha).to_owned(),
            mode: (*mode).to_owned(),
        });
    }
    Ok(blobs)
}

fn tree_blobs(root: &Path, rev: &str) -> Result<Vec<Blob>> {
    let records = git::run_z(root, &["ls-tree", "-r", "-z", rev])?;
    let mut blobs = Vec::new();
    for record in records {
        let Some((meta, path)) = record.split_once('\t') else {
            continue;
        };
        let fields: Vec<&str> = meta.split_whitespace().collect();
        // `blob` and `commit` alike. A commit here is a gitlink, and it is kept
        // for the same reason the index keeps one: the path it sits at is this
        // repository's committed text even though the object is not this
        // repository's to read. `-r` lists nothing else, and a kind this reader
        // does not know is dropped rather than guessed at.
        let [mode, "blob" | "commit", sha, ..] = fields.as_slice() else {
            continue;
        };
        blobs.push(Blob {
            path: path.to_owned(),
            sha: (*sha).to_owned(),
            mode: (*mode).to_owned(),
        });
    }
    Ok(blobs)
}

/// WHICH commits one pushed ref publishes, as arguments for `rev-list` and for
/// `log`.
///
/// One answer, because two readers working the range out separately are two
/// ranges that agree until they do not -- and the two readers here are the
/// blobs the push introduces and the MESSAGES it publishes, which have to be
/// the same push or the report is about two different acts.
///
/// A remote sha this clone does not have is NOT an empty range, and it used to
/// become one: `^<sha>` fails on an unknown object, and the failure was read as
/// "this push introduces nothing", so the whole range half of the scope
/// disappeared without a word. It is not a rare state -- anyone else pushing
/// since the last fetch produces it, as do a rewritten upstream ref and a
/// shallow clone. So the sha is RESOLVED first, and a range that cannot be
/// anchored falls back to subtracting what is already known to be on a remote.
/// Over-subtracting is the safe direction: those commits are reachable from a
/// ref that was itself pushed under a hook.
fn range_of(root: &Path, local_sha: &str, remote_sha: &str) -> Result<Vec<String>> {
    let new_branch = remote_sha.chars().all(|character| character == '0') || remote_sha == ZERO;
    let anchored = !new_branch
        && git::try_run(
            root,
            &[
                "rev-parse",
                "-q",
                "--verify",
                &format!("{remote_sha}^{{commit}}"),
            ],
        )?
        .is_some();
    Ok(if anchored {
        vec![local_sha.to_owned(), format!("^{remote_sha}")]
    } else {
        vec![
            local_sha.to_owned(),
            String::from("--not"),
            String::from("--remotes"),
        ]
    })
}

/// Every blob the pushed range introduces, including ones later deleted.
fn range_blobs(
    root: &Path,
    local_sha: &str,
    remote_sha: &str,
    remote: Option<&str>,
) -> Result<Vec<Blob>> {
    let range = range_of(root, local_sha, remote_sha)?;
    let mut argv: Vec<&str> = vec!["rev-list", "--objects"];
    argv.extend(range.iter().map(String::as_str));
    let listed = match git::try_run(root, &argv)? {
        Some(listed) => Some(listed),
        // The whole history reachable from the tip, which is what is left when
        // nothing can be subtracted from it. Reading too much is the safe
        // direction; reading nothing is the one this guard exists to refuse.
        None => git::try_run(root, &["rev-list", "--objects", local_sha])?,
    };
    // Neither the range nor the fallback could be listed. Returning no blobs
    // here reports a push nobody read as a push with nothing in it.
    let Some(listed) = listed else {
        return Err(Fatal::new(format!(
            "pre-push: could not list the objects {local_sha} introduces over \
             {remote_sha}, and could not list them against the remote-tracking refs \
             either -- refusing to report an unread push as an empty one.\n\n\
             A `git fetch {}` usually supplies the missing object.",
            remote.unwrap_or("<remote>")
        )));
    };

    // `rev-list --objects` lists commits, trees and blobs alike; only the ones
    // with a path beside them can be blobs, and `cat-file --batch-check` says
    // which of those actually are.
    let mut candidates: Vec<Blob> = Vec::new();
    for line in listed.lines() {
        let Some((sha, path)) = line.split_once(' ') else {
            continue;
        };
        if path.is_empty() {
            continue;
        }
        candidates.push(Blob {
            path: path.to_owned(),
            sha: sha.to_owned(),
            // No mode: this listing names an object and a path it appeared at,
            // and `keep_blobs` below settles the only question the mode would
            // have answered here -- whether there are bytes to read.
            mode: String::new(),
        });
    }
    keep_blobs(root, candidates)
}

/// The messages of the commits this push publishes.
///
/// Empty at every other stage, and that is the answer rather than a shrug: an
/// index is a commit that does not exist yet, and its message is what the
/// commit-msg guards read at the moment it is written.
///
/// This half exists because `commit-msg` only fires when `git commit` writes a
/// message. `git commit-tree`, a rebase, a cherry-pick, `git am`, `--no-verify`
/// and a fast-forward carrying somebody else's commit in from a hookless clone
/// all record a message that no hook ever read -- and until this, everything at
/// pre-push read the TREE. A subject line naming a private repository reached a
/// remote with every hook green and no override of any kind.
pub(crate) fn pushed_messages(
    root: &Path,
    stage: Stage,
    push_refs: &str,
    push_source: crate::runner::Source,
) -> Result<Vec<(String, String)>> {
    if stage != Stage::PrePush {
        return Ok(Vec::new());
    }
    if push_source == crate::runner::Source::Absent {
        // The same refusal `blobs` makes, and for the same reason: without a
        // ref line there is no range, and a range nobody named is not an empty
        // one. `blobs` says it at length; a caller reaches this only by asking
        // for the messages without asking for the blobs.
        return Err(Fatal::new(
            "pre-push: no ref line reached this guard, so which commits are being \
             published is unknown -- refusing to report their messages as read",
        ));
    }

    let mut messages: Vec<(String, String)> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for line in push_refs.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [_, local_sha, _, remote_sha, ..] = fields.as_slice() else {
            continue;
        };
        // A deletion publishes no commit and so no message.
        if local_sha.chars().all(|character| character == '0') {
            continue;
        }
        let range = range_of(root, local_sha, remote_sha)?;
        // `%B` is the raw body -- subject and body exactly as stored, with
        // nothing stripped, because git has already stripped the `#` comment
        // lines by the time a message is in a commit. The sha travels with it
        // so a finding can name the commit rather than only quote the text, and
        // `-z` separates the records because a message holds newlines and blank
        // lines by construction.
        let mut argv: Vec<&str> = vec!["log", "-z", "--format=%H%x09%B"];
        argv.extend(range.iter().map(String::as_str));
        // Not `try_run`: a range that cannot be read is a set of messages
        // nobody looked at, and an empty list of them would read as a push that
        // published nothing to say.
        let listed = git::run(root, &argv)?;
        for record in listed.split('\0').filter(|field| !field.is_empty()) {
            let Some((sha, body)) = record.split_once('\t') else {
                continue;
            };
            if seen.insert(sha.to_owned()) {
                messages.push((sha.to_owned(), body.to_owned()));
            }
        }
    }
    Ok(messages)
}

fn keep_blobs(root: &Path, candidates: Vec<Blob>) -> Result<Vec<Blob>> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    if candidates.is_empty() {
        return Ok(candidates);
    }

    let mut child = Command::new("git")
        .args(["cat-file", "--batch-check=%(objectname) %(objecttype)"])
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| Fatal::new(format!("git cat-file: {error}")))?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| Fatal::new("git cat-file: no stdin"))?;
        for candidate in &candidates {
            writeln!(stdin, "{}", candidate.sha)
                .map_err(|error| Fatal::new(format!("git cat-file: {error}")))?;
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| Fatal::new(format!("git cat-file: {error}")))?;
    // The status was never read here, and the failure was silent in the worst
    // direction: no stdout means no known kinds, and the filter below then drops
    // EVERY candidate and returns an empty list -- a push whose blobs could not
    // be identified, reported as a push with no blobs in it. `read` a few lines
    // down has always checked this; only this function did not.
    //
    // A missing object is not this case. `--batch-check` writes "<sha> missing"
    // and still exits 0, so a non-zero status means git itself could not run.
    if !output.status.success() {
        return Err(Fatal::new(format!(
            "git cat-file --batch-check exited {}: cannot tell which of {} object(s) \
             are blobs, and reporting none of them would read as a clean push",
            output.status.code().unwrap_or(-1),
            candidates.len()
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);

    let mut kinds: BTreeMap<&str, &str> = BTreeMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if let [name, kind, ..] = fields.as_slice() {
            kinds.insert(name, kind);
        }
    }
    Ok(candidates
        .into_iter()
        .filter(|candidate| kinds.get(candidate.sha.as_str()) == Some(&"blob"))
        .collect())
}

/// The bytes of one blob. Read through git rather than off disk, because the
/// blob is the artifact and the file beside it may differ or not exist.
pub(crate) fn read(root: &Path, blob: &Blob) -> Result<Vec<u8>> {
    if !blob.has_content() {
        // A caller that got here skipped `has_content`, and the object is
        // another repository's commit. Said as a refusal rather than as a git
        // failure, because the two mean different things: this one is a bug in
        // the caller, and the git failure it used to produce was read as "this
        // tree cannot be scanned" and ended the run at exit 2.
        return Err(Fatal::new(format!(
            "{}: a gitlink has no blob in this repository -- its content belongs to \
             the submodule, which carries its own guards",
            blob.path
        )));
    }
    read_object(root, &blob.sha, &blob.path)
}

/// The bytes of one object, named by oid rather than by an enumerated entry.
///
/// The staged-blob reader needs this: what it holds is a path and the oid the
/// INDEX has at it, which is not one of the entries any scope enumerated.
pub(crate) fn read_object(root: &Path, sha: &str, path: &str) -> Result<Vec<u8>> {
    let output = std::process::Command::new("git")
        .args(["cat-file", "blob", sha])
        .current_dir(root)
        .output()
        .map_err(|error| Fatal::new(format!("git cat-file blob {sha}: {error}")))?;
    if !output.status.success() {
        return Err(Fatal::new(format!(
            "git cat-file blob {sha} ({path}) failed"
        )));
    }
    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Through the real deserializer, so a test cannot assert about a shape the
    /// config would have refused.
    fn rule_with_files(files_table: &str) -> Rule {
        let text = format!(
            "builtin = \"no-private-repo-names-in-files\"\n\
             visibility = \"private\"\n{files_table}"
        );
        // The id is the section header in a policy file and has no spelling in
        // a bare rule body, so it is set the way `parse` sets it.
        let mut rule: Rule = toml::from_str(&text).expect("a rule the config would accept");
        rule.id = String::from("no-private-repo-names-in-files");
        rule
    }

    #[test]
    fn a_rule_that_never_mentions_files_reads_every_one() {
        let rule = rule_with_files("");
        assert!(in_file_scope(&rule, "tests/guard_cli.rs").unwrap());
        assert!(in_file_scope(&rule, "README.md").unwrap());
    }

    #[test]
    fn an_exclude_written_on_a_builtin_is_obeyed() {
        // It was accepted and ignored: `[rule.files]` is optional on a builtin
        // and not refused, so this exclude parsed, validated, and did nothing --
        // in BOTH guards that read blobs.
        let rule = rule_with_files("[files]\nexclude = [\"**/tests/**\"]\n");
        assert!(!in_file_scope(&rule, "tests/guard_cli.rs").unwrap());
        assert!(in_file_scope(&rule, "src/guard/names.rs").unwrap());
    }

    #[test]
    fn an_include_root_bounds_a_guard_the_way_it_bounds_the_scan() {
        // The field this function did not read. A guard scoped to `src` used to
        // read the whole tree, which is the same defect it was written to fix.
        let rule = rule_with_files("[files]\ninclude = [\"src\"]\n");
        assert!(in_file_scope(&rule, "src/main.rs").unwrap());
        assert!(in_file_scope(&rule, "src/guard/names.rs").unwrap());
        assert!(!in_file_scope(&rule, "tests/guard_cli.rs").unwrap());
        assert!(!in_file_scope(&rule, "README.md").unwrap());
        // Not a prefix match on the string: `srcery/` is not under `src/`.
        assert!(!in_file_scope(&rule, "srcery/a.rs").unwrap());
    }

    #[test]
    fn the_repository_root_bounds_nothing() {
        let rule = rule_with_files("[files]\ninclude = [\".\"]\n");
        assert!(in_file_scope(&rule, "anywhere/at/all.rs").unwrap());
    }

    fn entry(path: &str, mode: &str) -> Blob {
        Blob {
            path: path.to_owned(),
            sha: String::from("0123456789abcdef0123456789abcdef01234567"),
            mode: mode.to_owned(),
        }
    }

    #[test]
    fn a_gitlink_is_enumerated_and_never_read() {
        // The live one: this workspace tracks submodules, and every tree-wide
        // guard exited 2 over the first of them because a gitlink was handed
        // downstream as a blob and `git cat-file blob <commit-oid>` fails.
        // Enumerated all the same -- the PATH is this repository's committed
        // text whatever the object at it belongs to.
        assert!(!entry("sub", "160000").has_content());
        assert!(entry("src/main.rs", "100644").has_content());
        assert!(entry("run.sh", "100755").has_content());
        // A symlink's blob IS its target path, which is committed text and is
        // read like any other blob.
        assert!(entry("link", "120000").has_content());
        // An object `rev-list` named carries no mode, and `keep_blobs` has
        // already settled that it is a blob.
        assert!(entry("gone.txt", "").has_content());
    }

    #[test]
    fn a_glob_without_a_slash_matches_a_basename_anywhere() {
        // ripgrep's meaning, which is what every other `glob` in this config
        // already gets. `*.md` is "every markdown file", not "the ones at the
        // root".
        let rule = rule_with_files("[files]\nglob = [\"*.md\"]\n");
        assert!(in_file_scope(&rule, "docs/deep/nested.md").unwrap());
        assert!(in_file_scope(&rule, "README.md").unwrap());
        assert!(!in_file_scope(&rule, "src/main.rs").unwrap());
    }
}
