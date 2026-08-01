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

use std::collections::BTreeMap;
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

/// One blob the operation is introducing, and the path it arrived under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Blob {
    pub path: String,
    pub sha: String,
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
        let [_, sha, _, ..] = fields.as_slice() else {
            continue;
        };
        // Mode 120000 is a symlink, and its blob is the TARGET PATH. Kept, for
        // the reason in the module docstring: that path is committed bytes.
        blobs.push(Blob {
            path: path.to_owned(),
            sha: (*sha).to_owned(),
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
        let [_, "blob", sha, ..] = fields.as_slice() else {
            continue;
        };
        blobs.push(Blob {
            path: path.to_owned(),
            sha: (*sha).to_owned(),
        });
    }
    Ok(blobs)
}

/// Every blob the pushed range introduces, including ones later deleted.
fn range_blobs(
    root: &Path,
    local_sha: &str,
    remote_sha: &str,
    remote: Option<&str>,
) -> Result<Vec<Blob>> {
    let new_branch = remote_sha.chars().all(|character| character == '0') || remote_sha == ZERO;
    let listed = if new_branch {
        // Nothing on the remote to subtract, so subtract everything already
        // known to be there. `--not --all` over-subtracts if the branch shares
        // commits with another local branch, which is the safe direction: those
        // commits are reachable from a ref that was itself pushed under a hook.
        git::try_run(
            root,
            &["rev-list", "--objects", local_sha, "--not", "--remotes"],
        )?
        .or(git::try_run(root, &["rev-list", "--objects", local_sha])?)
    } else {
        // A remote sha this clone does not have is NOT an empty range, and it
        // used to become one: `^<sha>` fails on an unknown object, and the
        // failure was read as "this push introduces nothing", so the whole
        // range half of the scope disappeared without a word. It is not a rare
        // state -- anyone else pushing since the last fetch produces it, as do
        // a rewritten upstream ref and a shallow clone -- and the half it drops
        // is the one that catches a blob added in one pushed commit and removed
        // in the next, which is on the remote permanently and in no tip tree.
        //
        // So fall back the way the new-branch arm does: subtract what is known
        // to be on a remote already. Over-subtracting is the safe direction for
        // the same stated reason -- those commits are reachable from a ref that
        // was itself pushed under a hook.
        match git::try_run(
            root,
            &[
                "rev-list",
                "--objects",
                local_sha,
                &format!("^{remote_sha}"),
            ],
        )? {
            Some(listed) => Some(listed),
            None => git::try_run(
                root,
                &["rev-list", "--objects", local_sha, "--not", "--remotes"],
            )?,
        }
    };
    let _ = remote;
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
        });
    }
    keep_blobs(root, candidates)
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
    let output = std::process::Command::new("git")
        .args(["cat-file", "blob", &blob.sha])
        .current_dir(root)
        .output()
        .map_err(|error| Fatal::new(format!("git cat-file blob {}: {error}", blob.sha)))?;
    if !output.status.success() {
        return Err(Fatal::new(format!(
            "git cat-file blob {} ({}) failed",
            blob.sha, blob.path
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
