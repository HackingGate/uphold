//! Where a push is allowed to go.

use std::fmt::Write as _;

use super::{Refusal, Request};
use crate::error::Result;
use crate::git;

/// The owner this workspace belongs to, and whether that was PINNED or guessed.
///
/// Deriving it from `origin` is tautological for the one remote most likely to
/// be wrong: repointing origin at a public upstream -- the exact accident this
/// guard exists to prevent -- also repoints the allow-list, so the push is
/// permitted and the guard exits 0. A pinned constant cannot be moved by the
/// mistake it guards.
///
/// `owner` on the rule is that pin, and it is stronger than the environment
/// variable it replaces for the same reason `.git-guards-owner` was: it is
/// committed, and changing it is a diff somebody reviews.
///
/// Falling back to origin still guards a repository that has declared nothing.
/// That fallback is the weaker mode, and it SAYS so at the point of refusal
/// rather than passing itself off as the pinned one.
fn workspace_owner(request: &Request<'_>) -> (Option<String>, bool) {
    if let Some(owner) = request.rule.owner.as_deref() {
        return (Some(owner.to_owned()), true);
    }
    let derived = git::remote_url(request.root, "origin")
        .and_then(|url| git::owner_repo(&url))
        .map(|(owner, _)| owner);
    (derived, false)
}

/// Where this push is actually going.
fn destination(request: &Request<'_>) -> Option<(String, String)> {
    let url = request
        .remote_url
        .map(str::to_owned)
        .or_else(|| {
            request
                .remote_name
                .and_then(|name| git::remote_url(request.root, name))
        })
        .or_else(|| git::remote_url(request.root, "origin"))?;
    git::owner_repo(&url)
}

pub(crate) fn prevent_public_push(request: &Request<'_>) -> Result<Option<Refusal>> {
    let Some((owner, repo)) = destination(request) else {
        // A push whose destination could not be read is not a push to an
        // allowed destination.
        return Ok(Some(Refusal {
            id: request.rule.id.clone(),
            report: String::from(
                "could not work out where this push is going, so it cannot be checked \
                 against the allow-list.",
            ),
        }));
    };
    let name = format!("{owner}/{repo}");

    let (workspace, pinned) = workspace_owner(request);

    // An owner is a blunt unit: allowing one to let a single repository through
    // allows every repository it will ever have. `allowed_repos` is the finer
    // grant, and the two are checked together.
    let mut allowed_owners: Vec<String> = request.rule.allowed_owners().to_vec();
    if allowed_owners.is_empty() {
        if let Some(workspace) = workspace.as_deref() {
            allowed_owners.push(workspace.to_owned());
        }
    }

    let by_owner = allowed_owners
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&owner));
    let by_repo = request
        .rule
        .allowed_repos()
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&name));

    if by_owner || by_repo {
        // The allow path says which mode allowed it, and it only says so where
        // the answer rested on the derived owner.
        //
        // The refusal has always named the weaker mode; the pass never did, so
        // a repository running the tautological version of this guard heard
        // nothing for as long as nothing went wrong -- which is exactly as long
        // as the note is worth reading. Measured across the fleet: 50 of 65
        // repositories pin no `owner`.
        //
        // Scoped to `!pinned && !by_repo` on purpose. A pinned owner is the
        // strong mode and has nothing to report, and an `allowed_repos` hit
        // decided the question from a written list whatever origin says -- a
        // note on either would be a line on every push, and a line on every
        // push is a line nobody reads by the time it matters.
        if !pinned && !by_repo {
            if let Some(workspace) = workspace.as_deref() {
                eprintln!(
                    "uphold guard: {} allowed this push to {name}, judged against {workspace} \
                     -- DERIVED FROM ORIGIN, not pinned. Repointing origin at a public \
                     upstream moves this answer with it, which is the accident this guard \
                     exists for. Pin it with `owner = \"{workspace}\"` on the rule.",
                    request.rule.id
                );
            }
        }
        return Ok(None);
    }

    let mut report = format!("this push would go to {name}, which is not on the allow-list.\n\n");
    match workspace.as_deref() {
        Some(workspace) if pinned => {
            writeln!(report, "This workspace is pinned to {workspace}.").ok();
        }
        Some(workspace) => {
            writeln!(
                report,
                "This workspace was taken to be {workspace}, DERIVED FROM ORIGIN and not \
                 pinned. Repointing origin moves this answer, which is the accident this \
                 guard exists for -- set `owner` on the rule to pin it."
            )
            .ok();
        }
        None => {
            report.push_str(
                "This workspace has no origin this guard can read and no `owner` on the \
                 rule, so it had nothing to judge against.\n",
            );
        }
    }
    write!(
        report,
        "\nAllow it by adding to the rule:\n  allowed_repos = [\"{name}\"]\n\
         or, more bluntly, allowed_owners = [\"{owner}\"]"
    )
    .ok();

    Ok(Some(Refusal {
        id: request.rule.id.clone(),
        report,
    }))
}
