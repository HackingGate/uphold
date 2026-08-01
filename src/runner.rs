//! What the hook runner said, when git did not say it.
//!
//! git hands a pre-push hook two arguments -- remote name and remote URL -- and
//! one line per ref on stdin: `<local-ref> <local-sha> <remote-ref>
//! <remote-sha>`. That is the whole contract, and a guard reading it is reading
//! what is actually being sent.
//!
//! Only one of the three runners this tool supports keeps that contract intact.
//! lefthook does, once the job says `use_stdin: true` -- without it lefthook
//! runs the command under a pseudo-TTY whose stdin never closes, so a reader
//! hangs rather than seeing nothing. pre-commit and prek do NOT: they consume
//! git's stdin themselves and re-publish it as environment variables, one
//! invocation per ref.
//!
//! That difference is not cosmetic. A pre-push guard that reads only stdin sees
//! an empty push under the two most widely used runners, and an empty push and
//! a push of nothing are indistinguishable at that point -- so the tree-scanning
//! guards fell through to the INDEX, which at pre-push is quite likely a
//! different branch entirely, and reported on it as though it were the push.
//! A green tick about the wrong tree.
//!
//! So the ref lines are reconstructed from the environment when git's own
//! channel is empty, in git's format, so that exactly one parser downstream
//! reads exactly one shape. When neither channel says anything the answer is
//! `Absent`, which is a third state and not an empty push: `explicit-unknown`
//! is the record that a check which could not evaluate must say so.

use std::io::{IsTerminal, Read};
use std::path::Path;

/// git's all-zero object id: "this ref does not exist on the remote yet".
const ZERO: &str = "0000000000000000000000000000000000000000";

/// Where the push context came from, which is the difference between a push
/// this tool read and a push it could not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// git's own stdin, forwarded intact.
    Git,
    /// A runner's environment variables, reassembled into git's format.
    Runner,
    /// Neither. Not an empty push.
    Absent,
}

/// The push a pre-push guard is being asked about.
pub(crate) struct Push {
    /// Ref lines in git's pre-push format, whatever channel they arrived on.
    pub refs: String,
    pub remote_name: Option<String>,
    pub remote_url: Option<String>,
    pub source: Source,
}

/// A variable that is set and not empty. An empty one is not an answer, and
/// treating it as one is how a blank `PRE_COMMIT_TO_REF` becomes a ref line
/// naming no commit.
fn variable(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// The first of these that is set, because two runners spell the same fact
/// differently and a repository may be running either.
fn first(names: &[&str]) -> Option<String> {
    names.iter().copied().find_map(variable)
}

/// git wants a full ref. pre-commit exports a branch name, prek sometimes a
/// full ref, and `HEAD` is legal in both.
fn as_ref_name(value: &str) -> String {
    if value.starts_with("refs/") || value == "HEAD" {
        return value.to_owned();
    }
    format!("refs/heads/{value}")
}

/// Rebuild git's ref line from what pre-commit and prek export.
///
/// `PRE_COMMIT_SOURCE` and `PRE_COMMIT_ORIGIN` are pre-commit's older names for
/// the same two shas. Both spellings are read because a repository pinned to an
/// older pre-commit exports the old pair and nothing else, and a guard that
/// only knows the new names reads that push as empty.
///
/// A missing remote sha is the all-zero id rather than a missing field: git
/// spells "the remote does not have this ref" that way, and a new branch is the
/// ordinary case, not a broken environment.
fn from_environment(root: &Path) -> Option<(String, Option<String>, Option<String>)> {
    let named_branch = variable("PRE_COMMIT_LOCAL_BRANCH");
    let local_ref = named_branch
        .as_deref()
        .map_or_else(|| String::from("HEAD"), as_ref_name);
    let remote_ref = variable("PRE_COMMIT_REMOTE_BRANCH")
        .map_or_else(|| local_ref.clone(), |branch| as_ref_name(&branch));

    // The first push to a remote that has no refs at all. pre-commit names both
    // branches and both remote fields here and exports NEITHER sha, because the
    // pair it publishes is a range and there is no ancestor on the remote to
    // start one from. Read as "no push", which is what requiring the sha did,
    // that is the case with the most to lose: a repository's entire history
    // arriving on a remote for the first time, with every tree-scanning guard
    // skipped for the one push that introduces everything.
    //
    // The branch is enough. Resolving it here produces the same line git would
    // have written on stdin -- local sha from the ref, remote sha all-zero,
    // which is exactly how git spells a branch the remote does not have.
    //
    // The branch has to have been NAMED for this: resolving HEAD when no runner
    // said anything would invent a push out of whatever is checked out, which is
    // the same fabrication as scanning the index and harder to notice.
    let local_sha = if let Some(sha) = first(&["PRE_COMMIT_TO_REF", "PRE_COMMIT_SOURCE"]) {
        sha
    } else {
        named_branch.as_ref()?;
        crate::git::try_run(root, &["rev-parse", "--verify", "--quiet", &local_ref])
            .ok()
            .flatten()
            .map(|sha| sha.trim().to_owned())
            .filter(|sha| !sha.is_empty())?
    };
    let remote_sha =
        first(&["PRE_COMMIT_FROM_REF", "PRE_COMMIT_ORIGIN"]).unwrap_or_else(|| ZERO.to_owned());
    Some((
        format!("{local_ref} {local_sha} {remote_ref} {remote_sha}\n"),
        variable("PRE_COMMIT_REMOTE_NAME"),
        variable("PRE_COMMIT_REMOTE_URL"),
    ))
}

/// Read git's stdin, unless there is no stdin to read.
///
/// The terminal check is what keeps `uphold guard --stage pre-push`, typed
/// by a person to see what it says, from sitting there forever waiting for a
/// ref line that is never coming. Under a real hook stdin is a pipe and this is
/// false.
fn from_stdin() -> std::io::Result<String> {
    let input = std::io::stdin();
    if input.is_terminal() {
        return Ok(String::new());
    }
    let mut buffer = String::new();
    input.lock().read_to_string(&mut buffer)?;
    Ok(buffer)
}

/// The push context, from git if git supplied one and from the runner if not.
///
/// Command-line flags win over both. They are how a person reproduces one
/// invocation by hand, and a value typed on the command line that a stale
/// environment variable could silently replace is not a reproduction.
pub(crate) fn push(
    root: &Path,
    remote_name: Option<String>,
    remote_url: Option<String>,
) -> std::io::Result<Push> {
    let refs = from_stdin()?;
    if !refs.trim().is_empty() {
        return Ok(Push {
            refs,
            remote_name,
            remote_url,
            source: Source::Git,
        });
    }

    if let Some((environment_refs, environment_name, environment_url)) = from_environment(root) {
        return Ok(Push {
            refs: environment_refs,
            remote_name: remote_name.or(environment_name),
            remote_url: remote_url.or(environment_url),
            source: Source::Runner,
        });
    }

    Ok(Push {
        refs: String::new(),
        remote_name,
        remote_url,
        source: Source::Absent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_branch_name_becomes_a_ref_and_a_ref_is_left_alone() {
        assert_eq!(as_ref_name("main"), "refs/heads/main");
        assert_eq!(as_ref_name("refs/heads/main"), "refs/heads/main");
        assert_eq!(as_ref_name("refs/tags/v1"), "refs/tags/v1");
        // git itself writes HEAD in the local-ref field for a detached push.
        assert_eq!(as_ref_name("HEAD"), "HEAD");
    }

    /// The reassembled line has to parse the way git's own line parses, because
    /// one parser downstream reads both. Four whitespace-separated fields, and
    /// the shas in positions 1 and 3.
    #[test]
    fn a_reassembled_line_has_gits_four_fields_in_gits_order() {
        let line = format!(
            "{} {} {} {}\n",
            as_ref_name("topic"),
            "aaaa",
            as_ref_name("topic"),
            ZERO
        );
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[1], "aaaa");
        assert_eq!(fields[3], ZERO);
    }

    #[test]
    fn a_missing_remote_sha_is_the_zero_id_and_not_a_missing_field() {
        // A new branch is the ordinary case. Dropping the field instead would
        // make the line unparseable and turn every first push into an error.
        assert_eq!(ZERO.len(), 40);
        assert!(ZERO.chars().all(|character| character == '0'));
    }
}
