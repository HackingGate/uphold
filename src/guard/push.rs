//! Where a push is allowed to go -- and, at the command seam, whether a
//! destination is a repository this workspace owns at all.
//!
//! The two questions are one question. A push to somewhere off the allow-list
//! and a `--repo other-owner/their-repo` on a forge CLI are the same act
//! arriving by two roads, and for a while only the first road had a gate: the
//! shim asked whether the TEXT was safe to publish and never whether the
//! DESTINATION was ours, so an agent published clean prose to a forge
//! repository this workspace does not own and every check reported a pass.
//! Nothing was wrong with the text; the wrong thing was where it went.
//!
//! So the decision lives here once, in [`unowned`], and both seams reach it.
//! Complete Mediation is the principle being obeyed rather than a preference:
//! a second copy of this body, worded for the second seam, would be two rules
//! answering one question, and the day they disagree is the day one of them is
//! the hole.

use std::fmt::Write as _;
use std::path::Path;

use super::{Refusal, Request};
use crate::config::{Policy, Rule};
use crate::error::Result;
use crate::git;

/// Which seam is asking, for the two phrases that differ between them.
///
/// The DECISION does not vary: who this workspace is, whether the destination
/// is on its allow-list, and what to say when nothing declared an owner. Only
/// the act being described does -- a push leaves, a command publishes -- and a
/// refusal that called a `gh issue create` a push would be describing something
/// that did not happen. So the wording is a parameter and the body is not
/// copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Seam {
    /// `pre-push`: the range git is about to send, judged by the git hook.
    Push,
    /// A `[[shim]]`: the repository a command was told to publish to.
    Command,
}

impl Seam {
    /// How a refusal opens, before the destination's name.
    const fn would(self) -> &'static str {
        match self {
            Self::Push => "this push would go to",
            Self::Command => "this command would publish to",
        }
    }

    /// How the derived-owner note on the ALLOW path names what it let through.
    const fn allowed(self) -> &'static str {
        match self {
            Self::Push => "allowed this push to",
            Self::Command => "allowed this publication to",
        }
    }

    /// Which seam printed the note, so a reader knows where to look for it.
    const fn tool(self) -> &'static str {
        match self {
            Self::Push => "uphold guard",
            Self::Command => "uphold shim",
        }
    }
}

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
///
/// Takes the three things it reads rather than a `Request`, because a `Request`
/// is what a GIT HOOK was handed and the command seam has no push range, no
/// stage and no remote to build one from. Narrowing the parameters is what let
/// the one body serve both.
fn workspace_owner(root: &Path, policy: &Policy, rule: &Rule) -> Result<(Option<String>, bool)> {
    if let Some(owner) = rule.owner.as_deref() {
        return Ok((Some(owner.to_owned()), true));
    }
    // The policy's own `owner`, which is the pin a rule arriving from a bundled
    // set can still reach: a set cannot be handed a parameter without writing
    // the rule out again, and identity is a property of the repository rather
    // than of any one rule in it.
    if let Some(owner) = policy.declared_owner(root)? {
        return Ok((Some(owner), true));
    }
    let derived = git::remote_url(root, "origin")
        .and_then(|url| git::owner_repo(&url))
        .map(|(owner, _)| owner);
    Ok((derived, false))
}

/// Whether one destination is off the list of destinations this workspace may
/// publish to -- the one statement of that question in this binary.
///
/// `Ok(None)` is "this destination is ours, or allowed"; `Ok(Some(_))` is a
/// refusal carrying the whole report; `Err` is the third answer -- nothing here
/// could tell, which is exit 2 and never a pass.
///
/// Both seams call this and neither reimplements it. What a caller supplies is
/// the destination it resolved, in the form both roads already have it in:
/// `git::owner_repo` parses a remote url at the hook and a `--repo` value at
/// the shim, and one parser means the two cannot disagree about what `owner`
/// means.
pub(crate) fn unowned(
    root: &Path,
    policy: &Policy,
    rule: &Rule,
    destination: (&str, &str),
    seam: Seam,
) -> Result<Option<Refusal>> {
    let (owner, repo) = destination;
    let name = format!("{owner}/{repo}");

    let (workspace, pinned) = workspace_owner(root, policy, rule)?;

    // A rule that says it will not guess, in a repository that has not said
    // who it is. Fatal rather than a refusal, because the two are different
    // answers: a refusal says "this destination is wrong", and this says
    // "nothing here can tell whether it is". Exit 2 is that answer everywhere
    // else in this binary.
    //
    // The allow-list is checked FIRST, so an explicit `allowed_owners` or
    // `allowed_repos` still settles the question -- a repository that has
    // written down where its publications may go has answered, in the only form
    // the guard needed, and demanding a second declaration of the same fact
    // would be ceremony.
    if rule.owner_required.unwrap_or(false)
        && !pinned
        && rule.allowed_owners().is_empty()
        && rule.allowed_repos().is_empty()
    {
        return Err(crate::error::Fatal::new(format!(
            "rule {:?}: `owner_required` is set and nothing here says who this repository \
             belongs to, so the only owner available is the one read off `origin` -- which \
             is the remote this guard exists to catch being wrong. Declare it once, at the \
             top of the policy file:\n\n  owner = \"{}\"\n\nor name the destinations \
             directly with `allowed_owners` / `allowed_repos` on the rule.",
            rule.id,
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
    let mut allowed_owners: Vec<String> = rule.allowed_owners().to_vec();
    if pinned || allowed_owners.is_empty() {
        if let Some(workspace) = workspace.as_deref() {
            allowed_owners.push(workspace.to_owned());
        }
    }

    let by_owner = allowed_owners
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(owner));
    let by_repo = rule
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
                    "{}: {} {} {name}, judged against {workspace} \
                     -- DERIVED FROM ORIGIN, not pinned. Repointing origin at a public \
                     upstream moves this answer with it, which is the accident this guard \
                     exists for. Pin it with `owner = \"{workspace}\"` at the top of the \
                     policy file, which is a place an inherited rule can reach.",
                    seam.tool(),
                    rule.id,
                    seam.allowed()
                );
            }
        }
        return Ok(None);
    }

    let mut report = format!(
        "{} {name}, which is not on the allow-list.\n\n",
        seam.would()
    );
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
        id: rule.id.clone(),
        report,
    }))
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

/// The git-hook seam: resolve where the push is going, then ask [`unowned`].
///
/// Thin on purpose. Everything this used to decide for itself is now the shared
/// predicate, so the answer a push gets and the answer a `gh` invocation gets
/// come out of the same lines.
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
    unowned(
        request.root,
        request.policy,
        request.rule,
        (&owner, &repo),
        Seam::Push,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One policy holding one rule, loaded the way the binary loads one.
    ///
    /// Built through `config::load` rather than by hand, because the fields
    /// this predicate reads are the fields a policy AUTHOR writes -- a struct
    /// assembled in the test could hold a combination the loader refuses, and
    /// the test would then be about a state no repository can reach.
    ///
    /// Every case gets its own directory. The suite runs in parallel threads of
    /// one process, so a path keyed on the process id is the same path for all
    /// of them.
    fn verdict(
        name: &str,
        body: &str,
        destination: (&str, &str),
        seam: Seam,
    ) -> Result<Option<Refusal>> {
        let root = crate::fixture::scratch(name);
        std::fs::create_dir_all(root.join("policy")).unwrap();
        let path = root.join("policy/principles.toml");
        std::fs::write(
            &path,
            format!(
                "[rule.destination]\nbuiltin = \"prevent-public-push\"\n{body}\n\
                 [rule.destination.git]\nhooks = [\"pre-push\"]\n"
            ),
        )
        .unwrap();
        let policy = crate::config::load(&root, &path).unwrap();
        let rule = policy
            .rules
            .iter()
            .find(|rule| rule.id == "destination")
            .expect("the fixture rule did not survive the load");
        unowned(&root, &policy, rule, destination, seam)
    }

    fn report(answer: Result<Option<Refusal>>) -> String {
        answer
            .expect("the predicate could not look")
            .expect("an unowned destination was allowed")
            .report
    }

    #[test]
    fn a_destination_under_the_pinned_owner_is_owned() {
        let answer = verdict(
            "push-owned",
            "owner = \"acme\"\n",
            ("acme", "widget"),
            Seam::Command,
        );
        assert!(matches!(answer, Ok(None)), "the workspace's own owner");
    }

    #[test]
    fn a_destination_under_another_owner_is_not() {
        // The gap this predicate closes at the command seam: the text is fine
        // and the destination is somebody else's.
        let text = report(verdict(
            "push-unowned",
            "owner = \"acme\"\n",
            ("other-owner", "their-repo"),
            Seam::Command,
        ));
        assert!(text.contains("other-owner/their-repo"), "{text}");
        assert!(text.contains("pinned to acme"), "{text}");
    }

    /// One body, two seams: only the act being described differs.
    ///
    /// The discriminating half is the second assertion. A second copy of the
    /// decision, worded for the second seam, would pass the first one too --
    /// right up until the day the copies disagree, which is what having one
    /// body makes unrepresentable.
    #[test]
    fn the_two_seams_differ_in_the_act_they_name_and_in_nothing_else() {
        let push = report(verdict(
            "push-seam-push",
            "owner = \"acme\"\n",
            ("other-owner", "their-repo"),
            Seam::Push,
        ));
        let command = report(verdict(
            "push-seam-command",
            "owner = \"acme\"\n",
            ("other-owner", "their-repo"),
            Seam::Command,
        ));
        assert!(push.starts_with("this push would go to"), "{push}");
        assert!(
            command.starts_with("this command would publish to"),
            "{command}"
        );
        // Everything from the destination's name onward is the decision and
        // its explanation, which do not vary by seam. Only the clause in front
        // of it -- the act being described -- does.
        let tail = |report: &str| {
            report
                .split_once("other-owner/their-repo")
                .map(|(_, tail)| tail.to_owned())
                .unwrap_or_default()
        };
        assert_eq!(tail(&push), tail(&command));
    }

    #[test]
    fn allowed_repos_admits_one_repository_and_not_its_owner() {
        let admitted = verdict(
            "push-allowed-repo",
            "owner = \"acme\"\nallowed_repos = [\"other-owner/their-repo\"]\n",
            ("other-owner", "their-repo"),
            Seam::Command,
        );
        assert!(matches!(admitted, Ok(None)), "the named repository");

        let sibling = verdict(
            "push-allowed-repo-sibling",
            "owner = \"acme\"\nallowed_repos = [\"other-owner/their-repo\"]\n",
            ("other-owner", "another-repo"),
            Seam::Command,
        );
        assert!(
            matches!(sibling, Ok(Some(_))),
            "the grant widened to the owner"
        );
    }

    #[test]
    fn owner_required_with_nothing_declared_is_the_third_answer() {
        // Not a refusal and not a pass. Nothing here could tell whose the
        // destination is, and a run that could not look must not exit 0.
        let message = verdict(
            "push-owner-required",
            "owner_required = true\n",
            ("other-owner", "their-repo"),
            Seam::Command,
        )
        .err()
        .map(|error| error.to_string())
        .unwrap_or_default();
        assert!(message.contains("owner_required"), "{message:?}");
    }
}
