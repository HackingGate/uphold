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
/// The policy's `owner_from` is the same pin held one level out, for a
/// workspace that would otherwise write the same line into every policy it
/// holds. It is still a DECLARATION -- read from a file the mistake this guard
/// catches does not touch -- and not a second way of asking the remote.
///
/// Falling back to origin still guards a repository that has declared nothing.
/// That fallback is the weaker mode, and it SAYS so at the point of refusal
/// rather than passing itself off as the pinned one.
fn workspace_owner(request: &Request<'_>) -> Result<(Option<String>, bool)> {
    if let Some(owner) = request.rule.owner.as_deref() {
        return Ok((Some(owner.to_owned()), true));
    }
    // The policy's own `owner`, which is the pin a rule arriving from a bundled
    // set can still reach: a set cannot be handed a parameter without writing
    // the rule out again, and identity is a property of the repository rather
    // than of any one rule in it.
    if let Some(owner) = request.policy.declared_owner(request.root)? {
        return Ok((Some(owner), true));
    }
    let derived = git::remote_url(request.root, "origin")
        .and_then(|url| git::owner_repo(&url))
        .map(|(owner, _)| owner);
    Ok((derived, false))
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

    let (workspace, pinned) = workspace_owner(request)?;

    // A rule that says it will not guess, in a repository that has not said
    // who it is. Fatal rather than a refusal, because the two are different
    // answers: a refusal says "this push is wrong", and this says "nothing
    // here can tell whether it is". Exit 2 is that answer everywhere else in
    // this binary.
    //
    // The allow-list is checked FIRST, so an explicit `allowed_owners` or
    // `allowed_repos` still settles the question -- a repository that has
    // written down where its pushes may go has answered, in the only form the
    // guard needed, and demanding a second declaration of the same fact would
    // be ceremony.
    if request.rule.owner_required.unwrap_or(false)
        && !pinned
        && request.rule.allowed_owners().is_empty()
        && request.rule.allowed_repos().is_empty()
    {
        return Err(crate::error::Fatal::new(format!(
            "rule {:?}: `owner_required` is set and nothing here says who this repository \
             belongs to, so the only owner available is the one read off `origin` -- which \
             is the remote this guard exists to catch being wrong. Declare it once, at the \
             top of the policy file:\n\n  owner = \"{}\"\n\nor name the destinations \
             directly with `allowed_owners` / `allowed_repos` on the rule.",
            request.rule.id,
            workspace.as_deref().unwrap_or("your-org")
        )));
    }

    // An owner is a blunt unit: allowing one to let a single repository through
    // allows every repository it will ever have. `allowed_repos` is the finer
    // grant, and the two are checked together.
    //
    // A written `allowed_owners` JOINS the pinned owner rather than standing in
    // for it. The pin says who this repository is, and naming a fork it also
    // pushes to does not stop it being that: replacing the pin refused a push
    // to the workspace's own owner under a refusal whose next line still read
    // "This workspace is pinned to acme", so the decision and the explanation
    // disagreed and only one of them could be right.
    //
    // The DERIVED owner stays the fallback for an empty list and joins nothing.
    // Origin is the remote this guard exists to catch being wrong, so a rule
    // that wrote its destinations down is answered from what it wrote; folding
    // origin in beside the list would put that tautology back on every rule
    // carrying one.
    let mut allowed_owners: Vec<String> = request.rule.allowed_owners().to_vec();
    if pinned || allowed_owners.is_empty() {
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
                     exists for. Pin it with `owner = \"{workspace}\"` at the top of the \
                     policy file, which is a place an inherited rule can reach.",
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
