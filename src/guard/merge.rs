//! Merges made locally rather than through a forge.

use std::path::Path;

use super::{Refusal, Request};
use crate::error::Result;
use crate::git;

/// Whether the commit being made is finishing a merge: `MERGE_HEAD` names the
/// other parent from `git merge` until the merge commit is written.
pub(crate) fn in_progress(root: &Path) -> Result<bool> {
    Ok(git::try_run(root, &["rev-parse", "-q", "--verify", "MERGE_HEAD"])?.is_some())
}

/// Refuse a commit that is finishing a merge or a squash merge.
pub(crate) fn no_merge_commit(request: &Request<'_>) -> Result<Option<Refusal>> {
    let git_dir = git::dir(request.root)?;

    if in_progress(request.root)? {
        return Ok(Some(Refusal {
            id: request.rule.id.clone(),
            report: String::from(
                "A merge is in progress and local merges are disabled.\n\n\
                 Run `git merge --abort`, then merge through your forge's PR/MR workflow.",
            ),
        }));
    }

    if git_dir.join("SQUASH_MSG").is_file() {
        return Ok(Some(Refusal {
            id: request.rule.id.clone(),
            report: String::from(
                "A squash merge is in progress and local squash merges are disabled.\n\n\
                 Run `git reset --hard HEAD`, then merge through your forge's PR/MR workflow.",
            ),
        }));
    }

    Ok(None)
}

/// Refuse the merge that would make a merge commit.
///
/// A FAST-FORWARD merge is not covered and cannot be: git creates no commit for
/// one and runs no `pre-merge-commit` hook, so there is no moment to refuse at.
/// Whatever a fast-forward brings in is judged at the next commit or push, by
/// the guards that read the whole tree the operation is introducing.
pub(crate) fn no_local_merge(request: &Request<'_>) -> Result<Option<Refusal>> {
    Ok(Some(Refusal {
        id: request.rule.id.clone(),
        report: String::from(
            "Local merges are disabled.\n\n\
             Merge through your forge's PR/MR workflow (`gh pr merge`, `glab mr merge`).",
        ),
    }))
}
