//! Whether the visibility a policy DECLARES is still the one the forge serves.
//!
//! `visibility` is written into a policy file and read by three guards as the
//! condition they fire under. The forge owns the fact; the file holds a copy;
//! nothing reconciles the two, so a repository flipped from private to public
//! goes on being judged by a file that says `private` forever. Measured across
//! one fleet: 78 policies declare a visibility and nothing anywhere would notice
//! if one of them stopped being true.
//!
//! THIS IS A FALSIFIER AND NOT A RESOLVER, which is the whole design.
//!
//! No probe can prove a repository is PRIVATE. A 404 is private, deleted,
//! renamed, mistyped, or a token that was never presented, and a public index
//! by construction lists only public repositories. Every probe can DISPROVE it,
//! and that is the direction that leaks: the repository is actually public, the
//! policy says `private`, and the three `private-names` guards stand down. So
//! this rule refuses one direction and reads nothing back into the declaration.
//!
//! The declaration stays the input. If a failed lookup could flip the guards to
//! `private`, an offline laptop would silently disarm a disclosure guard, which
//! is fail-open on the one rule family where fail-open is unacceptable. Could
//! not look is exit 2 here, never a downgrade to "confirmed private".
//!
//! WHERE IT RUNS. `pre-push` and `manual`, exactly as `no-stale-hook-pins` is,
//! and for the identical reason written there: a guard that adds a network round
//! trip to every commit is one somebody comments out. No commit pays for this.

use std::collections::BTreeMap;

use super::names::{lookup, Visibility};
use super::{Refusal, Request};
use crate::config::visibility_is_public;
use crate::error::{Fatal, Result};
use crate::git;

/// Refuse a declared privacy the forge has stopped serving.
///
/// `Ok(None)` for the two clean states -- a policy declaring `public`, which has
/// no claim of privacy to disprove, and a forge that agrees the repository is
/// private. `Ok(Some(_))` for the one refusable state. Everything else is
/// `Err`, because a claim that could not be checked has never been a claim that
/// passed.
pub(crate) fn no_stale_visibility(request: &Request<'_>) -> Result<Option<Refusal>> {
    let id = &request.rule.id;

    // The declaration is the subject. A rule that checks a claim against the
    // world needs a claim, and with none there is nothing to falsify -- so this
    // says so rather than passing, which would be a check that looked like it
    // ran and examined nothing.
    let declared = match request.rule.visibility() {
        Some(word) => word.to_owned(),
        None => match request.policy.declared_visibility(request.root)? {
            Some(word) => word,
            None => {
                return Err(Fatal::new(format!(
                    "{id}: nothing here declares this repository's visibility, so there is no \
                     claim for this rule to check. Declare it once, at the top of the policy \
                     file:\n\n  visibility = \"private\"    # or \"public\", or \"internal\"\n\n\
                     or point `visibility_from` at a command that prints one word."
                )))
            }
        },
    };
    let Some(declared_public) = visibility_is_public(&declared) else {
        return Err(Fatal::new(format!(
            "{id}: visibility {declared:?} is not a visibility"
        )));
    };

    // Declared public: there is nothing here to falsify. The direction that
    // leaks is a declaration of `private` over a repository that is public, and
    // a policy already saying `public` has the private-name family at its
    // strictest. Said out loud rather than returned silently, because a rule
    // that reports nothing is indistinguishable from one that did not run.
    if declared_public {
        println!(
            "{id}: declared {declared:?}, so there is no claim of privacy to disprove and no \
             request was made."
        );
        return Ok(None);
    }

    let Some(url) = git::remote_url(request.root, "origin") else {
        return Err(Fatal::new(format!(
            "{id}: this repository has no `origin` remote, so there is no name to ask the \
             forge about and the declared {declared:?} was checked against nothing.\n\n\
             Could not look is not a pass. Bypass this run deliberately with \
             UPHOLD_ALLOW={id}."
        )));
    };
    let Some((owner, repo)) = git::owner_repo(&url) else {
        return Err(Fatal::new(format!(
            "{id}: could not read an owner and a repository out of the `origin` URL {url:?}, \
             so the declared {declared:?} was checked against nothing.\n\nCould not look is \
             not a pass. Bypass this run deliberately with UPHOLD_ALLOW={id}."
        )));
    };

    // The same lookup the private-name family uses, and deliberately not a
    // second one. Two mechanisms answering one question are two answers free to
    // disagree, and this one depends on the distinction that mechanism already
    // draws: `gh` separates "the forge will not show us this" from "the forge
    // would not talk to us", which is exactly the line between a fact and an
    // absent check here.
    let mut cache = BTreeMap::new();
    match lookup(&mut cache, &owner, &repo).visibility {
        Visibility::Public => Ok(Some(Refusal {
            id: id.clone(),
            report: format!(
                "the policy declares visibility {declared:?}, and the forge serves \
                 {owner}/{repo} as PUBLIC.\n\nThe declaration is what the private-name \
                 guards read as the condition they fire under, so while it says \
                 {declared:?} they stand down -- over a repository everybody can read. \
                 Change the declared visibility to \"public\" and let them run, or change \
                 the repository back."
            ),
        })),
        Visibility::Private => {
            println!("{id}: declared {declared:?}, and the forge agrees.");
            Ok(None)
        }
        // Neither of these disproves the declaration and neither confirms it.
        // `Unknown` is the forge answering that it will show us no repository by
        // this name, which for a repository declared private is the ordinary
        // answer to an unauthenticated request -- and it is also the answer for
        // one that was deleted or renamed. `Unavailable` is no answer at all.
        // Both are the check not happening, and a check that did not happen has
        // never been a pass anywhere in this binary.
        Visibility::Unknown | Visibility::Unavailable => Err(Fatal::new(format!(
            "{id}: the forge did not say whether {owner}/{repo} is public, so the declared \
             {declared:?} was not checked. A 404 is a private repository, a deleted one, a \
             renamed one, and a request that carried no credentials -- this rule can \
             disprove a claim of privacy and can never confirm one, so it does not read \
             silence as agreement.\n\nCould not look is not a pass. Authenticate `gh`, or \
             bypass this run deliberately with UPHOLD_ALLOW={id}."
        ))),
    }
}
