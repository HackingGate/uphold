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
//!
//! The allow-list is asked first and the forge second. A workspace pinned to
//! one organisation refused a `gh issue create` on a public repository the
//! operator owns, and had no way to say so: a bundled rule takes no parameter,
//! so the only lever left was `UPHOLD_ALLOW`, which switches the guard off rather
//! than answering it. Ownership is a fact the forge holds and a repointed
//! remote cannot move, which is what keeps this from being the tautology the
//! pin exists to refuse -- and it is reached only for a destination already off
//! the list, so nothing that was going to pass waits on somebody's service.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use super::{Refusal, Request};
use crate::config::{Policy, Rule};
use crate::error::Result;
use crate::git;
use crate::shim::Forge;

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
    if let Some(owner) = rule.owner() {
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

/// What the forge said about who owns one destination.
///
/// A third state rather than a boolean, for the reason `names::Visibility`
/// keeps `Unavailable` apart from `Unknown`: "the forge says you do not
/// administer this" and "the forge was not asked" are different answers, and
/// folding them together would make a machine with no `gh` on it report every
/// destination as somebody else's -- or, worse the other way round, let a check
/// that never ran stand in for one that passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Owned {
    /// The authenticated identity IS the destination's owner, or administers it.
    Yes,
    /// The forge answered, and neither is true.
    No,
    /// No answer: no `gh` on PATH, no credentials, no network, or output that
    /// is neither a yes nor a no. Carries the first line of what `gh` said, so
    /// the reader is told which of those it was.
    CouldNotAsk(String),
}

/// The first line of what a failed `gh` wrote, which is the part worth printing.
fn first_line(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text.lines().next().unwrap_or_default().trim().to_owned();
    if line.is_empty() {
        String::from("it said nothing")
    } else {
        line
    }
}

/// Ask the forge whether the operator owns this destination, once per run.
///
/// Only ever reached for a destination the allow-list has already refused, so
/// the pin stays the first and cheap answer and an ordinary invocation pays no
/// round trip. Two questions, stopping at the first yes: the authenticated
/// login IS the owner, or the token administers the repository. Ownership is a
/// forge fact and cannot be moved by editing a remote, which is what lets it
/// stand beside the pin rather than under the tautology the pin exists to
/// refuse.
///
/// Spawned through [`crate::shim::inner_tool`] and never `Command::new`: the
/// `gh` on PATH is this binary, and an unmarked probe re-enters the shim it is
/// standing behind.
pub(crate) fn forge_owns(cache: &mut BTreeMap<String, Owned>, owner: &str, repo: &str) -> Owned {
    let key = format!("{owner}/{repo}");
    if let Some(known) = cache.get(&key) {
        return known.clone();
    }
    let answer = ask_forge(owner, &key);
    cache.insert(key, answer.clone());
    answer
}

/// The two requests, without the cache in front of them.
fn ask_forge(owner: &str, key: &str) -> Owned {
    let login = match crate::shim::inner_tool("gh")
        .args(["api", "user", "--jq", ".login"])
        .output()
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        Ok(output) => return Owned::CouldNotAsk(first_line(&output.stderr)),
        Err(error) => return Owned::CouldNotAsk(format!("gh could not be run ({error})")),
    };
    if login.is_empty() {
        return Owned::CouldNotAsk(String::from("`gh api user` printed no login"));
    }
    // GitHub logins are case-insensitive, and a pin written in the case the
    // profile page shows is the same account as one written in the case a url
    // carries.
    if login.eq_ignore_ascii_case(owner) {
        return Owned::Yes;
    }
    match crate::shim::inner_tool("gh")
        .args(["api", &format!("repos/{key}"), "--jq", ".permissions.admin"])
        .output()
    {
        Ok(output) if output.status.success() => {
            match String::from_utf8_lossy(&output.stdout).trim() {
                "true" => Owned::Yes,
                "false" => Owned::No,
                // `gh api` writes the API's error body to stdout, and a
                // `permissions` block that is not there answers `null`. Neither
                // is a no about ownership.
                other => Owned::CouldNotAsk(format!(
                    "`gh api repos/{key}` answered {other:?}, which is neither true nor false"
                )),
            }
        }
        // A 404 here is a definite no, and only because the request above
        // succeeded: the client works and is authenticated, and a forge that
        // will not show this repository to that identity is not a forge saying
        // the identity administers it. Every other failure -- 401, 403, a rate
        // limit, 5xx -- is the check not happening.
        Ok(output) if String::from_utf8_lossy(&output.stderr).contains("(HTTP 404)") => Owned::No,
        Ok(output) => Owned::CouldNotAsk(first_line(&output.stderr)),
        Err(error) => Owned::CouldNotAsk(format!("gh could not be run ({error})")),
    }
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
///
/// `forge` is which forge that destination is on, as the CALLER already knows
/// it -- the command's own name at the shim, the remote's host at the hook --
/// rather than a second parse here. It decides only whether there is a client
/// that can be asked: `Some(Forge::GitHub)` reaches [`forge_owns`] for a
/// destination the allow-list refused, and everything else keeps the answer the
/// allow-list gave. `asked` is that question's memo, so one invocation asks at
/// most once per destination however many rules judge it.
pub(crate) fn unowned(
    root: &Path,
    policy: &Policy,
    rule: &Rule,
    destination: (&str, &str),
    forge: Option<Forge>,
    asked: &mut BTreeMap<String, Owned>,
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
    if rule.owner_required()
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

    // Off the list, which used to end it. The list is a DECLARATION, and a
    // workspace inheriting a bundled rule cannot write a parameter onto it: an
    // operator who owns two forges had no lever short of UPHOLD_ALLOW, which
    // switches the whole guard off rather than answering it. So the forge is
    // asked second, and only here -- ownership is a fact it holds and the
    // mistake this guard catches, a repointed remote, cannot move it.
    //
    // `None` is the question not being put at all: a GitLab destination, or a
    // host neither client answers for, gets exactly the answer it got before
    // this branch existed rather than an invented one.
    let verdict = match forge {
        Some(Forge::GitHub) => Some(forge_owns(asked, owner, repo)),
        Some(Forge::GitLab) | None => None,
    };
    if verdict == Some(Owned::Yes) {
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

    match verdict {
        // Asked and answered. The line is the difference between a reader
        // going to look for a mis-typed owner and one who knows the forge was
        // consulted and disagreed too.
        Some(Owned::No) => {
            write!(
                report,
                "\n\nThe forge was asked as well: the identity `gh` is authenticated as is \
                 neither {owner} nor an administrator of {name}."
            )
            .ok();
        }
        // Asked and not answered. Not a refusal, because nothing here found
        // the destination wrong; not a pass, because nothing here found it
        // right either. Exit 2 is that third answer everywhere in this binary,
        // and a question that could not be asked has never been a pass.
        Some(Owned::CouldNotAsk(why)) => {
            return Err(crate::error::Fatal::new(format!(
                "rule {:?}: {report}\n\nThe forge could not be asked whether you own {name}, \
                 so the allow-list is the only answer there is and it is not a whole one: \
                 {why}. Could not look is not a pass. Authenticate `gh`, or name the \
                 destination on the rule, or bypass this run deliberately with \
                 UPHOLD_ALLOW={}.",
                rule.id, rule.id
            )));
        }
        Some(Owned::Yes) | None => {}
    }

    Ok(Some(Refusal {
        id: rule.id.clone(),
        report,
    }))
}

/// Where this push is actually going, and which forge that is.
///
/// The forge comes off the url this function already read. The host is in it,
/// and reading it here is what lets [`unowned`] know whether there is a client
/// that can be asked about the destination -- the same question the shim
/// answers from the command's own name.
fn destination(request: &Request<'_>) -> Option<(String, String, Option<Forge>)> {
    let url = request
        .remote_url
        .map(str::to_owned)
        .or_else(|| {
            request
                .remote_name
                .and_then(|name| git::remote_url(request.root, name))
        })
        .or_else(|| git::remote_url(request.root, "origin"))?;
    let (owner, repo) = git::owner_repo(&url)?;
    Some((owner, repo, Forge::of_url(&url)))
}

/// The git-hook seam: resolve where the push is going, then ask [`unowned`].
///
/// Thin on purpose. Everything this used to decide for itself is now the shared
/// predicate, so the answer a push gets and the answer a `gh` invocation gets
/// come out of the same lines.
pub(crate) fn prevent_public_push(request: &Request<'_>) -> Result<Option<Refusal>> {
    let Some((owner, repo, forge)) = destination(request) else {
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
    // One push, one destination, so the memo is made here and dies here. The
    // shim's loop is the seam where several rules judge the same destination,
    // and it holds its own.
    let mut asked = BTreeMap::new();
    unowned(
        request.root,
        request.policy,
        request.rule,
        (&owner, &repo),
        forge,
        &mut asked,
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
    ///
    /// The forge is `None` throughout, which is a destination on a host no
    /// client answers for -- the case whose behaviour is exactly what it was
    /// before the forge branch existed, so these cases keep testing the
    /// allow-list and its report and nothing else. The forge branch is asked
    /// about where it can be driven honestly: `tests/guard_cli.rs` and
    /// `tests/shim_cli.rs` run the binary with a stub `gh` on a PATH they set
    /// for the child. A unit test cannot do that -- these run as threads of one
    /// process, and `set_var("PATH")` in one of them is a change to every other
    /// thread's environment.
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
        unowned(
            &root,
            &policy,
            rule,
            destination,
            None,
            &mut BTreeMap::new(),
            seam,
        )
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
