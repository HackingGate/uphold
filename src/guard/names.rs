//! A private repository's name written into a public one.
//!
//! A public repository's history is permanent and indexable. A private
//! repository named there discloses that it exists, who owns it, and often what
//! it does -- and unlike a pull-request description, a commit message cannot be
//! corrected afterwards without rewriting published history.
//!
//! It happens by accident, not by carelessness: you fix a shared tool in a
//! public repository BECAUSE of something you hit in a private one, and paste
//! the real error output into the message.
//!
//! Three modes, because git is not the only way a private name reaches a public
//! place and it is not the way it usually does. `in_message` judges a commit
//! message. `in_staged` judges what a commit ADDS, which is the right unit at
//! commit time and blind by construction to a line already there. `in_tracked`
//! closes that half: a name that arrived under `--no-verify`, through a merge,
//! or in a checkout where no hook was installed is never looked at again
//! otherwise.
//!
//! What a name is written INTO is not only file content, and each of these
//! reads every carrier it can reach:
//!
//! * the bytes of a blob, and a symlink's blob IS its target path;
//! * the PATH itself, for every kind of entry -- `docs/why-acme-secret-broke.md`
//!   discloses a repository in every listing and every search of the history
//!   without one line of its content saying anything at all, and a gitlink has
//!   nothing else to disclose;
//! * the messages a push publishes, because `commit-msg` fires only when
//!   `git commit` writes one. `git commit-tree`, a rebase, a cherry-pick,
//!   `git am`, `--no-verify` and a fast import each record a message no hook
//!   has read, and everything else at pre-push reads the tree.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use regex::Regex;

use super::scope;
use super::{Refusal, Request, Stage};
use crate::config::{Policy, Rule};
use crate::error::{Fatal, Result};
use crate::git;

/// A repository name, with what a sentence put on the end taken off.
///
/// The character class has to allow a dot, because repository names contain
/// them -- and a name at the end of a sentence then swallows the full stop, so
/// the lookup asks the forge about `widget.` and gets no answer. It reported
/// that rather than passing (an unresolved name is never a clean one), which is
/// how this was found, but "could not resolve" is the wrong answer to a
/// question that has one. A forge name cannot end in a dot.
fn clean_repo(name: &str) -> String {
    name.trim_end_matches('.')
        .trim_end_matches(".git")
        .trim_end_matches('.')
        .to_owned()
}

/// Shared with `guard::visibility`, which asks the same forge the same question
/// about this repository's own name. One mechanism rather than two: two ways of
/// asking whether a repository is public are two answers free to disagree, and
/// the falsifier's exit-state ranking rests on the distinction drawn below
/// between an answer and no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Visibility {
    Public,
    Private,
    /// The forge ANSWERED, and no repository it will show us has this name.
    ///
    /// A real finding, and an ambiguous one: an invented name in a document
    /// reads exactly like a private repository the token cannot see. Which of
    /// those it is, is what `refuse_unknown` decides.
    Unknown,
    /// The forge was not asked, or could not answer: no `gh` on PATH, no
    /// credentials, a rate limit, a network that is not there.
    ///
    /// Separate from `Unknown` because it is not a fact about the NAME at all,
    /// it is the absence of a check. Folding the two together made an
    /// unauthenticated `gh` report every name as unresolved and then permit the
    /// commit -- a guard that did not run, wearing the output of one that ran
    /// and found something inconclusive.
    Unavailable,
}

/// What the forge said about one name: how visible, and what it is really called.
///
/// The second half is not decoration. A forge answers a renamed repository's OLD
/// name by redirecting to the current one, so a lookup of a name this repository
/// used to have succeeds and reports the visibility of THIS repository -- and
/// every mention of the old name then reads as a finding against itself. The
/// canonical name is how that is told apart from a genuine sibling: same
/// repository, not a leak. `None` when there was no answer to be canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Resolved {
    pub visibility: Visibility,
    pub canonical: Option<String>,
}

/// Any `host.tld/owner/repo` or its scp-like `host.tld:owner/repo`, with the
/// host kept.
///
/// The host used to be matched and then dropped, which is what made a
/// bibliography look like a list of repositories: `doi.org/10.1109/PROC.1975.9939`
/// and `apache.org/licenses/LICENSE-2.0` are `host.tld/a/b`, so both became
/// names, and both were then asked of GitHub. Keeping the host is what lets the
/// caller ask the forge the name actually came from.
static URL: OnceLock<Regex> = OnceLock::new();

fn url_pattern() -> &'static Regex {
    URL.get_or_init(|| {
        crate::engine::literal_pattern(
            r"(?i)\b([A-Za-z0-9.-]+\.[A-Za-z]{2,})[:/]([A-Za-z0-9][A-Za-z0-9._-]*)/([A-Za-z0-9][A-Za-z0-9._-]*)",
        )
    })
}

/// Whether `gh` can answer for a name written against this host.
///
/// Only GitHub, and only exactly GitHub. A GitHub Enterprise host is a
/// DIFFERENT forge that happens to share the software: asking github.com about
/// `acme/widget` seen on `github.acme.com` answers about someone else's
/// repository, and a public answer there passes a private repository here.
fn is_github_host(host: &str) -> bool {
    matches!(
        host.to_lowercase().as_str(),
        "github.com" | "www.github.com" | "raw.githubusercontent.com"
    )
}

/// The hosts a policy has said carry no repository this guard must resolve.
///
/// The field this replaces was a list of six forge hostnames written into the
/// binary, and it decided the answer for every host in the world by leaving the
/// rest out: a name on gitlab.com was reported, and a name on
/// `github.acme.com` or on any other forge nobody had thought of produced
/// NOTHING -- no finding, no report, no exit code. A silent third answer, in a
/// guard whose whole subject is that "could not look" and "looked and found
/// nothing" are different sentences.
///
/// So the polarity is the other way round now. Every `host.tld/owner/repo` this
/// tool cannot ask about is could-not-look, and what a declaration quiets is
/// the host, not the name: a bibliography is `doi.org/10.1109/PROC.1975.9939`
/// and `apache.org/licenses/LICENSE-2.0`, which are that shape and are not
/// repositories at all. Which hosts a repository's own documents cite is a fact
/// about that repository, so it is policy and lives in the policy file --
/// `parameterize-do-not-enumerate`, which the hand list was the standing
/// violation of.
///
/// Globs rather than literal hostnames because globs are the selection language
/// this config already speaks: `*.sr.ht` is one line where the enumeration
/// needed a special case.
pub(crate) struct ForeignHosts {
    matcher: Option<globset::GlobSet>,
}

impl ForeignHosts {
    /// Compile the declared host globs, refusing one that will not parse.
    ///
    /// Refused rather than skipped, because a glob nobody could compile is a
    /// host nobody quieted, and the run that drops it looks exactly like the
    /// run where the declaration worked.
    pub(crate) fn new(patterns: &[String]) -> Result<Self> {
        if patterns.is_empty() {
            return Ok(Self { matcher: None });
        }
        let mut builder = globset::GlobSetBuilder::new();
        for pattern in patterns {
            let glob = globset::Glob::new(&pattern.to_lowercase()).map_err(|error| {
                Fatal::new(format!("foreign_hosts: {pattern:?} is not a glob: {error}"))
            })?;
            builder.add(glob);
        }
        let matcher = builder
            .build()
            .map_err(|error| Fatal::new(format!("foreign_hosts: {error}")))?;
        Ok(Self {
            matcher: Some(matcher),
        })
    }

    fn quiets(&self, host: &str) -> bool {
        self.matcher
            .as_ref()
            .is_some_and(|matcher| matcher.is_match(host.to_lowercase()))
    }
}

/// Repositories named on a host `gh` cannot be asked about.
///
/// The host travels with the name here, and it is not decoration: `acme/widget`
/// on `github.acme.com` is a different repository from `acme/widget` on
/// github.com, and a reader told only the second half cannot tell which one the
/// line is about.
fn unanswerable_names(text: &str, quiet: &ForeignHosts) -> BTreeSet<(String, String, String)> {
    let mut found = BTreeSet::new();
    for capture in url_pattern().captures_iter(text) {
        let host = capture[1].to_lowercase();
        if is_github_host(&host) || quiet.quiets(&host) {
            continue;
        }
        let repo = clean_repo(&capture[3]);
        if repo.is_empty() {
            continue;
        }
        found.insert((host, capture[2].to_string(), repo));
    }
    found
}

/// Every `owner/repo` this text could be naming ON GITHUB.
///
/// Two forms. A GitHub URL needs `github.com/owner/repo`, or its scp-like
/// spelling `github.com:owner/repo` -- two segments after the host, which cannot
/// be confused with an ordinary relative path. A bare `owner/repo` is only a
/// candidate when the owner is one the rule declared private -- otherwise every
/// relative path in every document would be a name to look up.
///
/// The host has to match, not merely exist. Every URL in a citation list is
/// `host.tld/two/segments`, and treating the shape alone as a name turned a
/// bibliography into twenty-five lookups against a forge none of them came from.
/// A private repository on another forge is still reachable here: declare its
/// owner in `private_owners`, which is matched in the bare form and needs no
/// network.
fn candidates(text: &str, owners: &OwnerMatchers) -> BTreeSet<(String, String)> {
    let mut found: BTreeSet<(String, String)> = BTreeSet::new();
    for capture in url_pattern().captures_iter(text) {
        if !is_github_host(&capture[1]) {
            continue;
        }
        let owner = capture[2].to_string();
        let repo = clean_repo(&capture[3]);
        if repo.is_empty() {
            continue;
        }
        found.insert((owner, repo));
    }

    for (owner, matcher) in &owners.named {
        for capture in matcher.captures_iter(text) {
            found.insert((owner.clone(), clean_repo(&capture[1])));
        }
    }
    for (owner, matcher) in &owners.bare {
        if matcher.is_match(text) {
            found.insert((owner.clone(), String::new()));
        }
    }
    found
}

/// The patterns that depend only on the OWNER, compiled once per judgement.
///
/// Built here rather than inside `candidates` because `candidates` is asked
/// about one source at a time, and the staged scan now hands it one ADDED LINE
/// at a time: a pattern built inside the search is rebuilt once per line per
/// declared owner. The tree-wide scan was already rebuilding it twice per blob,
/// which is thousands of compilations of a pattern that cannot vary with the
/// text it is run against.
struct OwnerMatchers {
    /// `owner/repo`, anchored at each owner this rule looks for.
    named: Vec<(String, Regex)>,
    /// A DECLARED private owner written on its own, with no repository after it.
    bare: Vec<(String, Regex)>,
}

impl OwnerMatchers {
    /// Compiled here, and REFUSED here where one will not compile.
    ///
    /// Both arms used to be `let Ok(matcher) = ... else { continue; }`, which
    /// accepted a declared owner, dropped it, and ran the guard without it: the
    /// operator's list said one thing and the search did another, with nothing
    /// printed either way. An owner is escaped before it becomes a pattern, so
    /// a failure here is a name no regex can hold rather than a typo in a
    /// regex -- and either way it is a declaration this run cannot honour,
    /// which is a config error and not a silent narrowing.
    fn new(private_owners: &[String], own_owner: Option<&str>) -> Result<Self> {
        // The repository's OWN owner, treated as though it had been declared.
        //
        // `acme/widget` written with no host is the spelling a README uses for
        // a sibling -- "now maintained in acme/widget" -- and the URL forms in
        // `candidates` all miss it. It is not caught for owners in general
        // because a bare `owner/repo` is indistinguishable from a relative
        // path, and every path in every document would become a lookup. It is
        // caught for THIS owner because a segment equal to the login that owns
        // the repository, followed by a name, is a sibling reference and not a
        // directory: nobody writes `acme/main.rs`.
        //
        // Found by trying to write the deprecation note that would close #29
        // and watching the guard pass it.
        let mut owners: Vec<String> = private_owners.to_vec();
        if let Some(own_owner) = own_owner {
            if !owners
                .iter()
                .any(|owner| owner.eq_ignore_ascii_case(own_owner))
            {
                owners.push(own_owner.to_owned());
            }
        }

        let mut named: Vec<(String, Regex)> = Vec::new();
        let mut bare: Vec<(String, Regex)> = Vec::new();
        for owner in owners {
            // Anchored at the owner so a declared-private owner is found in the
            // bare form too. Escaped, because an owner may legitimately contain
            // a dot and an unescaped one would match any character.
            let pattern = format!(
                r"(?i)\b{}/([A-Za-z0-9][A-Za-z0-9._-]*)",
                regex::escape(&owner)
            );
            let matcher = Regex::new(&pattern).map_err(|error| {
                Fatal::new(format!(
                    "private owner {owner:?}: no pattern can be built for that name ({error})"
                ))
            })?;

            // The owner ON ITS OWN, with no repository after it. Every form
            // above needs an `owner/repo`, and this is the one that got past a
            // hand audit: a sentence naming a private organisation discloses
            // that it exists and who owns it without ever naming one of its
            // repositories. Only for a DECLARED owner -- a bare word is not
            // otherwise a name, and treating any capitalised token as one would
            // fire on ordinary prose. The repository's own owner is
            // deliberately not in this half: its name is published by the
            // repository existing.
            if private_owners.contains(&owner) {
                let alone = Regex::new(&format!(r"(?i)\b{}\b", regex::escape(&owner))).map_err(
                    |error| {
                        Fatal::new(format!(
                            "private owner {owner:?}: no pattern can be built for that name \
                             on its own ({error})"
                        ))
                    },
                )?;
                bare.push((owner.clone(), alone));
            }
            named.push((owner, matcher));
        }
        Ok(Self { named, bare })
    }
}

/// Ask the forge, once per name per run.
///
/// `gh api` writes the API's ERROR BODY to stdout, so a failed lookup that is
/// read as an answer produces a visibility of whatever the error happened to
/// say. Only a successful exit is an answer here; everything else is Unknown,
/// and Unknown is reported rather than passed over.
///
/// Both fields come back from one request. `full_name` is what the forge
/// redirected to, which is the only way to notice that the name asked about and
/// the repository doing the asking are the same repository under two names.
pub(crate) fn lookup(cache: &mut BTreeMap<String, Resolved>, owner: &str, repo: &str) -> Resolved {
    let key = format!("{owner}/{repo}");
    if let Some(known) = cache.get(&key) {
        return known.clone();
    }
    let resolved = match crate::shim::inner_tool("gh")
        .args([
            "api",
            &format!("repos/{key}"),
            "--jq",
            "[.visibility, .full_name] | @tsv",
        ])
        .output()
    {
        Ok(output) if output.status.success() => {
            let answer = String::from_utf8_lossy(&output.stdout);
            let mut fields = answer.trim().split('\t');
            let visibility = match fields.next().unwrap_or("").trim().to_lowercase().as_str() {
                // `internal` is deliberately NOT counted as public. It is
                // visible to an organisation and to nobody else, which is the
                // property this guard is about.
                "public" => Visibility::Public,
                "private" | "internal" => Visibility::Private,
                _ => Visibility::Unknown,
            };
            let canonical = fields
                .next()
                .map(|name| name.trim().to_lowercase())
                .filter(|name| !name.is_empty());
            Resolved {
                visibility,
                canonical,
            }
        }
        // The forge said no. WHICH no it said is the whole question, and it is
        // in stderr: `gh` writes `gh: Not Found (HTTP 404)` for a name it will
        // not show us, and `gh: Bad credentials (HTTP 401)` for a client it
        // will not talk to. Only the first is a fact about the name.
        //
        // Anything else -- 401, 403 and a rate limit, 5xx, a status line that
        // is not there, or no `gh` at all -- is the check not happening, and
        // reporting that as an inconclusive finding is how an unauthenticated
        // run passed every name in the tree.
        Ok(output) => Resolved {
            visibility: if String::from_utf8_lossy(&output.stderr).contains("(HTTP 404)") {
                Visibility::Unknown
            } else {
                Visibility::Unavailable
            },
            canonical: None,
        },
        Err(_) => Resolved {
            visibility: Visibility::Unavailable,
            canonical: None,
        },
    };
    cache.insert(key, resolved.clone());
    resolved
}

/// Whether the repository being written INTO is public.
///
/// This is the scope condition, and it is also the gap #14 exists for: it asks
/// whether the target is public NOW. Content written into a private repository
/// is correctly allowed at write time, and nothing re-examines that decision
/// when the repository later goes public.
fn target_is_public(root: &Path, policy: &Policy, rule: &Rule) -> Result<Option<bool>> {
    if let Some(declared) = rule.visibility() {
        return crate::config::visibility_is_public(declared)
            .map(Some)
            .ok_or_else(|| {
                Fatal::new(format!(
                    "rule {:?}: visibility {declared:?} is not a visibility",
                    rule.id
                ))
            });
    }
    // The policy's own `visibility`, which is the declaration a rule arriving
    // from a bundled set can still reach: a set cannot be handed a parameter
    // without writing the rule out again, and whether this repository is
    // published was never a property of one rule in it. Held to the three
    // spellings before it reaches this line -- a written one at load, a
    // `visibility_from` answer as it is read -- so a word that is not a
    // visibility never gets this far.
    if let Some(declared) = policy.declared_visibility(root)? {
        return Ok(crate::config::visibility_is_public(&declared));
    }
    let Some(url) = git::remote_url(root, "origin") else {
        return Ok(None);
    };
    let Some((owner, repo)) = git::owner_repo(&url) else {
        return Ok(None);
    };
    let mut cache = BTreeMap::new();
    Ok(match lookup(&mut cache, &owner, &repo).visibility {
        Visibility::Public => Some(true),
        Visibility::Private => Some(false),
        // Both are "no answer" to the caller, which turns into the refusal that
        // names `visibility`. The caller cannot act on the difference here --
        // either way this repository has not said what it is, and that is the
        // thing to fix.
        Visibility::Unknown | Visibility::Unavailable => None,
    })
}

struct Verdict {
    refused: Vec<String>,
    unresolved: Vec<String>,
    /// Names the forge was never able to answer for. Not findings: evidence
    /// that the check did not run.
    unavailable: Vec<String>,
}

/// The owner half of the repository doing the judging.
fn own_owner(root: &Path) -> Option<String> {
    let url = git::remote_url(root, "origin")?;
    git::owner_repo(&url).map(|(owner, _)| owner)
}

/// The repository doing the judging, as `owner/repo`.
///
/// Its own name is never a leak: publishing a repository publishes its name by
/// definition, and a README that says where to clone it from is not a
/// disclosure. Skipped explicitly rather than left to the visibility lookup,
/// because the audit judges under the visibility the repository is ABOUT to
/// have while the forge still reports the one it has -- so the lookup answers
/// `private` for the very repository being published, and every mention of it
/// in its own tree reads as a finding.
fn own_name(root: &Path) -> Option<String> {
    let url = git::remote_url(root, "origin")?;
    let (owner, repo) = git::owner_repo(&url)?;
    Some(format!("{owner}/{repo}").to_lowercase())
}

/// Every declared private owner: the literal list, plus whatever the command
/// produced.
pub(crate) fn declared_owners(root: &Path, policy: &Policy, rule: &Rule) -> Result<Vec<String>> {
    let mut owners = rule.private_owners().to_vec();
    // The rule's own source first, then the policy's. Same precedence as
    // `visibility` and for the same reason: the policy-level declaration is
    // what a rule arriving from a set can reach, and a rule that names its own
    // source is saying something narrower on purpose.
    if let Some(command) = rule
        .private_owners_from()
        .or(policy.private_owners_from.as_deref())
    {
        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(root)
            .output()
            .map_err(|error| Fatal::new(format!("{}: private_owners_from: {error}", rule.id)))?;
        if !output.status.success() {
            // Not silently empty. A source that failed produced no owners, and
            // a rule with no owners refuses nothing -- reporting a clean tree
            // because the list could not be read.
            //
            // `private_owners_optional` is the one way out, and it is a
            // DECLARATION rather than a fallback: it exists because a policy in
            // a repository other people clone names a source that resolves on
            // one machine, and the choice there is between refusing every
            // clone's first commit and losing the check silently. Neither is
            // acceptable, so the third answer is losing it OUT LOUD.
            if !policy.private_owners_optional {
                return Err(Fatal::new(format!(
                    "{}: private_owners_from exited {}: {}\n\nA source that failed produced \
                     no owners, and a rule with no owners refuses nothing. If this source is \
                     expected to be absent on some machines -- because this policy is \
                     cloned -- say so with `private_owners_optional = true` at the top of \
                     the policy file, and the failure becomes a reported gap instead of \
                     this.",
                    rule.id,
                    output.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            // Exactly what stopped being checked, because "degraded" without a
            // list of what degraded is a sentence a reader skips. The two forms
            // named here are the ones that need a DECLARED owner: every other
            // form reaches the forge on its own.
            eprintln!(
                "uphold: {}: the private-owner source produced nothing ({} exited {}), and \
                 `private_owners_optional` allows that. Names in URL form, and names under \
                 this repository's own owner, are still checked. NOT checked here: a bare \
                 `owner/repo` under an owner nothing declared, and a private organisation \
                 named on its own.",
                rule.id,
                command,
                output.status.code().unwrap_or(-1)
            );
        }
        owners.extend(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(str::to_owned),
        );
    }
    Ok(owners)
}

/// Whether a resolved name turned out to be the repository doing the judging.
///
/// The caller already compared what was WRITTEN against the current name, which
/// catches the ordinary case without a request. This catches the one that check
/// cannot see: a name this repository used to have. The forge answers an old
/// name by redirecting to the current one, so the lookup succeeds and reports
/// THIS repository's visibility -- private, while it is being audited for
/// publication -- and every mention of the old name in its own pull requests and
/// issues reads as a finding against itself.
///
/// Publishing a repository publishes every name it has answered to. A former
/// name is no more a disclosure than the current one.
fn is_ourselves(resolved: &Resolved, ours: Option<&str>) -> bool {
    match (resolved.canonical.as_deref(), ours) {
        (Some(canonical), Some(ours)) => canonical == ours,
        // No canonical name means there was no answer, and an unresolved name
        // is never quietly treated as our own.
        _ => false,
    }
}

/// `watched` is the set of owners whose names on an unaskable host are
/// could-not-look rather than merely unresolved: the private owners this policy
/// declares, plus the owner it says this workspace is. Kept apart from `owners`
/// because that list also drives the bare-owner search, where the workspace's
/// own name is deliberately not a finding.
fn judge(
    root: &Path,
    rule: &Rule,
    owners: &[String],
    watched: &BTreeSet<String>,
    quiet: &ForeignHosts,
    sources: &[(String, String)],
) -> Result<Verdict> {
    let ours = own_name(root);
    let our_owner = own_owner(root);
    let public: BTreeSet<String> = rule
        .public_repos()
        .iter()
        .map(|name| name.to_lowercase())
        .collect();
    let private_owners: BTreeSet<String> =
        owners.iter().map(|owner| owner.to_lowercase()).collect();

    let mut cache: BTreeMap<String, Resolved> = BTreeMap::new();
    let mut refused = Vec::new();
    let mut unresolved = Vec::new();
    let mut unavailable = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let matchers = OwnerMatchers::new(owners, our_owner.as_deref())?;

    for (where_found, text) in sources {
        for (owner, repo) in candidates(text, &matchers) {
            let bare_owner = repo.is_empty();
            let name = if bare_owner {
                owner.clone()
            } else {
                format!("{owner}/{repo}")
            };
            if !seen.insert(format!("{where_found}\u{0}{name}")) {
                continue;
            }
            if public.contains(&name.to_lowercase())
                || ours.as_deref() == Some(name.to_lowercase().as_str())
            {
                continue;
            }
            // A declared-private owner needs no network and cannot be
            // contradicted by one: it is the operator saying so.
            let resolved = if private_owners.contains(&owner.to_lowercase()) {
                Resolved {
                    visibility: Visibility::Private,
                    canonical: None,
                }
            } else {
                lookup(&mut cache, &owner, &repo)
            };
            if is_ourselves(&resolved, ours.as_deref()) {
                continue;
            }
            match resolved.visibility {
                Visibility::Private if bare_owner => refused.push(format!(
                    "{where_found}: {name} is a private organisation, named on its own"
                )),
                Visibility::Private => refused.push(format!("{where_found}: {name} is private")),
                Visibility::Unknown => {
                    unresolved.push(format!("{where_found}: {name} could not be resolved"));
                }
                Visibility::Unavailable => {
                    unavailable.push(format!("{where_found}: {name}"));
                }
                Visibility::Public => {}
            }
        }

        // Named on a host this tool cannot ask, which is two different
        // sentences depending on WHOSE name it is.
        //
        // Under a declared owner it is could-not-look: the operator has said
        // that owner's repositories are private, `gh` cannot say whether this
        // one is, and a name this rule exists to keep off a public target
        // cannot be reported clean on silence. That is the `unavailable`
        // bucket, exit 2, where a `gh` that could not be reached lands.
        //
        // Under any other owner it is the inconclusive answer it always was.
        // Every `host.tld/a/b` in a document has this shape -- a DOI, a licence
        // URL, an encyclopaedia article -- and treating all of them as
        // could-not-look makes the fix "enumerate every host you cite" in every
        // consuming repository, which is `parameterize-do-not-enumerate` with
        // the enumeration moved out of the binary and into eighty policy files.
        // Reported on the way past, and refused only where the repository has
        // said with `refuse_unknown` that an unresolved name is not acceptable.
        for (host, owner, repo) in unanswerable_names(text, quiet) {
            let name = format!("{owner}/{repo}");
            if public.contains(&name.to_lowercase()) {
                continue;
            }
            if !seen.insert(format!("{where_found}\u{0}{host}/{name}")) {
                continue;
            }
            if watched.contains(&owner.to_lowercase()) {
                unavailable.push(format!(
                    "{where_found}: {host}/{name} (a declared owner, on a host `gh` cannot \
                     be asked about)"
                ));
            } else {
                unresolved.push(format!(
                    "{where_found}: {host}/{name} is on a host this tool cannot query"
                ));
            }
        }
    }
    Ok(Verdict {
        refused,
        unresolved,
        unavailable,
    })
}

/// The judgement, over what was read AND what could not be.
///
/// `unread` is the second list because the two halves of could-not-look arrive
/// from different places and must not be able to cancel each other out: a text
/// whose bytes no charset would decode is as much a gap as a name the forge
/// would not answer for, and both are outranked by a name that WAS found. Every
/// caller that opens a blob hands its failures here rather than skipping them,
/// which is the difference between "this file is clean" and "nobody read it".
fn decide(
    request: &Request<'_>,
    sources: &[(String, String)],
    unread: &[String],
) -> Result<Option<Refusal>> {
    // A rule that says it will not guess, in a repository that has not said
    // whether it is published. Asked BEFORE the lookup rather than after it
    // fails, because the lookup succeeding is the worse case: it answers from
    // the forge's view of a visibility that is about to change, and the answer
    // it gives on the day of the change is the one that decides whether the
    // whole family runs at all.
    if request.rule.visibility_required()
        && request.rule.visibility().is_none()
        && request.policy.declared_visibility(request.root)?.is_none()
    {
        return Err(Fatal::new(format!(
            "rule {:?}: `visibility_required` is set and nothing here says whether this \
             repository is published, so the only answer available is the forge's -- which \
             is unknown with no token, unknown with no network, and stale on the one day it \
             matters. Declare it once, at the top of the policy file:\n\n  visibility = \
             \"private\"    # or \"public\", or \"internal\"\n\nor point `visibility_from` \
             at a command that prints one word. The guards in this family fire only on a \
             public tree, so the word decides whether they run here at all.",
            request.rule.id
        )));
    }
    let Some(public) = target_is_public(request.root, request.policy, request.rule)? else {
        // Not a pass. The guard could not establish the one condition it fires
        // under, and saying nothing would look exactly like saying clean.
        return Err(Fatal::new(format!(
            "{}: could not determine this repository's visibility. Set `visibility` at the \
             top of the policy file, on the rule, or as a `visibility_from` command, to say \
             what it is.",
            request.rule.id
        )));
    };
    if !public {
        return Ok(None);
    }

    let owners = declared_owners(request.root, request.policy, request.rule)?;
    // The hosts this policy has declared are not forges it needs an answer
    // about. The rule's own list first and the policy's second, the same
    // precedence `private_owners_from` and `visibility` have and for the same
    // reason: a rule arriving from a bundled set cannot be handed a parameter,
    // so the policy is where a repository writes the fact once.
    let quiet = ForeignHosts::new(
        request
            .rule
            .foreign_hosts()
            .unwrap_or(&request.policy.foreign_hosts),
    )?;
    // The owners a name on an unaskable host is could-not-look for. The
    // declared private ones, and the owner this workspace says it is -- a
    // repository of ours on a forge we cannot query is the case where silence
    // is least affordable, and it is the one form a private-owner list often
    // leaves out because nobody thinks of their own login as private.
    //
    // The policy's `owner` and not the rule's: `owner` is a parameter of the
    // push guards and is refused on a rule in this family, so the top of the
    // policy file is the only place this family can read it from.
    let mut watched: BTreeSet<String> = owners.iter().map(|owner| owner.to_lowercase()).collect();
    if let Some(owner) = request.policy.declared_owner(request.root)? {
        watched.insert(owner.to_lowercase());
    }
    let verdict = judge(
        request.root,
        request.rule,
        &owners,
        &watched,
        &quiet,
        sources,
    )?;

    // The forge could not be asked about some names, so for THOSE this guard
    // did not run. Exit 2 and not a refusal, and NOT governed by
    // `refuse_unknown`: that field decides what an ANSWER of "no repository by
    // that name" means, and there was no answer. Folding this into the
    // inconclusive pile is how an unauthenticated `gh` used to pass every name
    // in a tree while printing a line about each.
    //
    // Built here and DECIDED at the bottom, because a finding outranks it. The
    // exit-state ranking this repository documents and proves is: 1 when
    // something was found, 2 when nothing was found and something could not be
    // read, 0 only when the whole selection was read and was clean. Returning
    // early here inverted that -- a private name the guard had already caught
    // was discarded, unprinted, because some unrelated name in the same text
    // had no answer. The name the guard exists to catch is the one that must
    // survive.
    let mut gaps: Vec<String> = Vec::new();
    if !verdict.unavailable.is_empty() {
        gaps.push(format!(
            "{}: the forge could not be asked about {} name(s), so their visibility is \
             unestablished and this guard did not run over them:\n{}\n\n`gh` must be \
             installed and authenticated for this rule -- `gh auth status` says which. A \
             rate limit, a missing token and no network all land here, and so does a name \
             under a DECLARED owner written against a host `gh` cannot be asked about: if \
             that host carries no repository this rule needs resolved, name it in \
             `foreign_hosts`. Names it ANSWERED for are judged normally; this is the \
             absence of an answer, which is exit 2 rather than a refusal because nothing \
             here is known to be wrong.",
            request.rule.id,
            verdict.unavailable.len(),
            verdict.unavailable.join("\n")
        ));
    }
    if !unread.is_empty() {
        gaps.push(format!(
            "{}: {} of the texts this operation carries could not be read, so no name in \
             them was looked for:\n{}\n\nDeclare the file not text in .gitattributes, or \
             exclude it from this rule. A file nobody could decode is not a file with \
             nothing in it.",
            request.rule.id,
            unread.len(),
            unread.join("\n")
        ));
    }
    let unavailable = (!gaps.is_empty()).then(|| Fatal::new(gaps.join("\n\n")));

    let mut report = String::new();
    if !verdict.refused.is_empty() {
        report.push_str(&verdict.refused.join("\n"));
    }
    if !verdict.unresolved.is_empty() {
        if request.rule.refuse_unknown() {
            if !report.is_empty() {
                report.push('\n');
            }
            report.push_str(&verdict.unresolved.join("\n"));
            report.push_str("\n\nRefused because the rule sets `refuse_unknown`.");
        } else {
            // Reported on the way past even when it does not refuse: a name the
            // forge could not answer for is not a name that is fine.
            eprintln!(
                "{}: {} name(s) could not be resolved:\n{}",
                request.rule.id,
                verdict.unresolved.len(),
                verdict.unresolved.join("\n")
            );
        }
    }
    if report.is_empty() {
        // Nothing was found, and something could not be read. Exit 2.
        return unavailable.map_or(Ok(None), Err);
    }
    // Something WAS found, so the refusal is the answer and the unread part is
    // said alongside it rather than instead of it. A reader who is shown only
    // the exit code still sees the name; a reader who is shown only the names
    // still learns that the list is incomplete.
    if let Some(gap) = unavailable {
        eprintln!("{gap}");
    }
    Ok(Some(Refusal {
        id: request.rule.id.clone(),
        report: format!(
            "{report}\n\nA public repository's history is permanent and indexable. Use a \
             neutral description instead of the name."
        ),
    }))
}

pub(crate) fn in_message(request: &Request<'_>) -> Result<Option<Refusal>> {
    // The same trap `message::message_text` documents: a named file that is not
    // there fell through to `.git/COMMIT_EDITMSG`, so the guard read the
    // PREVIOUS commit's message and passed over one it never opened.
    if let Some(named) = request.message_file {
        if !named.is_file() {
            return Err(Fatal::new(format!(
                "{}: {} was named as the commit-message file and is not a file. \
                 Refusing to fall back to the previous commit's message and report \
                 a pass over a file that was never opened",
                request.rule.id,
                named.display()
            )));
        }
    }
    let path = match request.message_file {
        Some(path) => path.to_path_buf(),
        None => git::dir(request.root)?.join("COMMIT_EDITMSG"),
    };
    let text = scope::read_message(&request.rule.id, &path)?;
    decide(request, &[(String::from("commit message"), text)], &[])
}

/// Git's own answer to "was this path diffed as text", per `--numstat`.
///
/// `-` for both counts is git saying it did not, and it is the only signal
/// there is: it means the binary heuristic and the `diff` ATTRIBUTE alike,
/// which is exactly why the blob has to be consulted next.
struct Staged {
    path: String,
    added: bool,
    as_text: bool,
}

/// Every path the index changes, with git's verdict on each.
///
/// `--numstat -z` rather than the headers of the diff itself, because `-z`
/// prints a path verbatim -- no quoting, no escaping -- and a path read out of
/// a `+++ b/...` header is a path this reader would have to unquote correctly
/// to attribute a finding to the right file.
///
/// `--no-ext-diff` and `--no-textconv` for the reason `added_lines` sets out at
/// length. git counts these itself and does not put them through a diff driver,
/// so on the git in front of me the flags change nothing here -- they are
/// written anyway so that the three `git diff` calls in this file cannot be
/// read as three different decisions about whose config gets a say. The one
/// that was missing them was blind, and it looked exactly like its twins until
/// somebody put them side by side.
fn staged_paths(root: &Path) -> Result<Vec<Staged>> {
    let records = git::run_z(
        root,
        &[
            "-c",
            "core.quotepath=false",
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--numstat",
            "-z",
        ],
    )?;
    let mut staged = Vec::new();
    let mut records = records.into_iter();
    while let Some(record) = records.next() {
        let mut fields = record.split('\t');
        let added = fields.next().unwrap_or_default().to_owned();
        let deleted = fields.next().unwrap_or_default().to_owned();
        let path = fields.next().unwrap_or_default().to_owned();
        // A rename or a copy: `-z` spells it as this record with an empty path
        // and then the source and the destination, each its own record.
        let path = if path.is_empty() {
            let Some(_source) = records.next() else { break };
            let Some(destination) = records.next() else {
                break;
            };
            destination
        } else {
            path
        };
        let as_text = added != "-" || deleted != "-";
        staged.push(Staged {
            path,
            added: added != "0",
            as_text,
        });
    }
    Ok(staged)
}

/// Which line of the NEW file a hunk opens at, from the `+c,d` half of its
/// `@@ -a,b +c,d @@` header.
///
/// The count is optional and `-U0` is where that shows: a one-line hunk is
/// spelled `@@ -7 +7 @@`, with no comma anywhere in it, so a reader that split
/// on one found no number and every finding in the commit lost its line.
fn hunk_start(header: &str) -> Option<usize> {
    header
        .split_once('+')?
        .1
        .split(|character: char| character == ',' || character.is_whitespace())
        .next()
        .filter(|number| !number.is_empty())
        .and_then(|number| number.parse().ok())
}

/// The lines one staged path ADDS, each with the line it will be at.
///
/// Read hunk by hunk rather than by keeping every line that starts with `+` and
/// excepting `+++`. That exception cannot tell a header from content: an added
/// line whose own first two characters are `++` is spelled `+++...` in the diff
/// exactly like the `+++ b/path` above it, so every such line was dropped from
/// the scan -- `++ github.com/acme/secret` in a changelog was a name this guard
/// never looked at. Inside a hunk a leading `+` is always the marker, and the
/// file header cannot appear inside one.
///
/// It is also the only place the LINE NUMBER exists. A finding that names the
/// file and not the line is one a reader has to go searching for, and the
/// sibling guard over the same text has named both since it was written.
///
/// Every flag here closes a way this diff was reported as empty over a file
/// that was not:
///
/// * `--no-ext-diff` and `--no-textconv`, because `git diff` honours
///   `diff.external` and a per-path `textconv` from the repository's config AND
///   from the global and system files. A difftastic or delta setup -- somebody
///   else's, on their own machine, made for reading diffs and not for this --
///   emits `EXTERNAL a.txt ...` and not one `+` line, and the guard reported a
///   pass over a diff it never saw.
/// * `--no-color`, one step down from the same class: `color.diff = always` in
///   a personal config wraps every line in escape sequences, and `+` stops
///   being the first byte of an added line.
/// * `core.quotepath=false`, so a non-ASCII path is spelled here the way every
///   other listing in this file spells it.
/// * `--text` on the second pass, which is what makes a `diff` attribute stop
///   deciding whether the bytes get read.
fn added_lines(root: &Path, path: &str, force_text: bool) -> Result<Vec<(Option<usize>, String)>> {
    let mut argv: Vec<&str> = vec![
        "-c",
        "core.quotepath=false",
        "diff",
        "--cached",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "-U0",
    ];
    if force_text {
        argv.push("--text");
    }
    let spec = format!(":(literal){path}");
    argv.push("--");
    argv.push(&spec);
    let diff = git::run(root, &argv)?;

    let mut added: Vec<(Option<usize>, String)> = Vec::new();
    let mut in_hunk = false;
    // `None` inside a hunk means a header this reader could not parse. The line
    // is still SCANNED -- it is only reported without a number. A guard that
    // dropped the line because it could not number it would be answering "where
    // is it" by deciding there is nothing there.
    let mut line: Option<usize> = None;
    for record in diff.lines() {
        if let Some(header) = record.strip_prefix("@@") {
            in_hunk = true;
            line = hunk_start(header);
            continue;
        }
        // One path per call, so this is belt and braces -- but the counter has
        // to be wrong before a finding can name the wrong line, and starting it
        // over at each file is what makes that impossible.
        if record.starts_with("diff --git ") {
            in_hunk = false;
            line = None;
            continue;
        }
        if !in_hunk {
            // The preamble: the mode and index lines, `--- /dev/null`,
            // `+++ b/path`, and "Binary files a/x and b/x differ" -- which is
            // the whole of the output for a path the first pass cannot read,
            // and the reason there is a second one.
            continue;
        }
        if let Some(text) = record.strip_prefix('+') {
            added.push((line, text.to_owned()));
            line = line.map(|number| number.saturating_add(1));
        } else if record.starts_with(' ') {
            // Context, which `-U0` does not ask for. Counted all the same,
            // because what the numbers here mean must not depend on a
            // `diff.context` in somebody's personal config being overridden.
            line = line.map(|number| number.saturating_add(1));
        }
        // A `-` line is text the commit removes and does not carry, and
        // `\ No newline at end of file` is a note about the line above it.
        // Neither is a line of the new file, and neither moves the counter.
    }
    Ok(added)
}

/// Where a finding was found: the path, and the line when the diff said which.
///
/// Dropped rather than guessed at when a hunk header could not be read. A wrong
/// line number sends a reader to the wrong place and is worse than none, and the
/// line was scanned either way.
fn located(path: &str, line: Option<usize>) -> String {
    line.map_or_else(|| path.to_owned(), |number| format!("{path}:{number}"))
}

/// The paths this commit INTRODUCES, whatever is inside them.
///
/// A path is committed text: `docs/why-acme-secret-broke.md` names a private
/// repository in every listing, every diff and every search of the history,
/// and no line of its content has to say anything at all. Added and renamed
/// only -- a path that was already there is the tree-wide guard's business,
/// and reporting it at every commit that touches the file would be a wall
/// somebody bypasses by reflex rather than a finding they act on.
///
/// Spelled with the same flags as its two neighbours, for the reason
/// `staged_paths` gives: whose config gets a say in what this guard can see is
/// one decision, and three call sites that answer it three ways is the fork
/// this tool exists to catch.
fn introduced_paths(root: &Path) -> Result<Vec<String>> {
    git::run_z(
        root,
        &[
            "-c",
            "core.quotepath=false",
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--name-only",
            "--diff-filter=ACR",
            "-z",
        ],
    )
}

/// The lines this commit ADDS, and the paths it introduces.
///
/// One source per ADDED LINE rather than one blob for the whole commit: the
/// rule's `[rule.files]` scope is a question about a PATH, so a single blob
/// labelled "staged changes" could not be scoped at all -- and the finding it
/// produced named neither the file it came from nor anything a reader could
/// open. A path answers the scope; the line is what a reader opens.
pub(crate) fn in_staged(request: &Request<'_>) -> Result<Option<Refusal>> {
    let mut sources: Vec<(String, String)> = Vec::new();
    let mut unread: Vec<String> = Vec::new();

    for path in introduced_paths(request.root)? {
        if !scope::in_file_scope(request.rule, &path)? {
            continue;
        }
        sources.push((format!("{path} (the path itself)"), path));
    }

    for staged in staged_paths(request.root)? {
        if !scope::in_file_scope(request.rule, &staged.path)? {
            continue;
        }
        if staged.as_text {
            if staged.added {
                for (line, text) in added_lines(request.root, &staged.path, false)? {
                    sources.push((located(&staged.path, line), text));
                }
            }
            continue;
        }

        // The second pass, for the paths git would not diff as text.
        //
        // `git diff` consults the `diff` ATTRIBUTE before it looks at a single
        // byte. A committed `*.log -diff`, `* -diff` or `*.csv binary` -- two
        // lines, in this very commit if you like -- reduces a plain-ASCII file
        // to "Binary files a/x and b/x differ", so not one of its added lines
        // reached the first pass and this guard exited 0 with nothing printed.
        // The attribute is a claim about how to RENDER a change; whether there
        // is readable text in there is a question about the blob, and this asks
        // it of the blob.
        let Some(oid) = git::try_run(
            request.root,
            &[
                "rev-parse",
                "--verify",
                "--quiet",
                &format!(":{}", staged.path),
            ],
        )?
        else {
            // Not in the index at all: the change is a deletion, and a deletion
            // adds no line to any commit.
            continue;
        };
        let oid = oid.trim();
        if oid.is_empty() {
            continue;
        }
        // Not a skip. git named this path as changed and then would not show
        // it, so failing to read the object is could-not-look -- the one thing
        // this guard must never report as a clean commit.
        let bytes = scope::read_object(request.root, oid, &staged.path)?;
        // What the bytes turned out to be, asked of the content this time and
        // through the one decoder. A NUL test alone stood here, which is git's
        // binary test and is also true of every UTF-16 file ever committed: a
        // staged UTF-16 document naming a private repository was skipped as an
        // image, with nothing printed.
        if std::str::from_utf8(&bytes).is_ok() {
            // Valid UTF-8, so the diff git prints is text a reader can be
            // pointed at line by line.
            for (line, text) in added_lines(request.root, &staged.path, true)? {
                sources.push((located(&staged.path, line), text));
            }
            continue;
        }
        match scope::decode(&bytes) {
            // Text, but not in this diff's encoding: `git diff --text` hands
            // back the same bytes it would not render, and a line number read
            // off them points nowhere. The whole decoded blob is judged
            // instead -- wider than the diff on purpose, because what is lost
            // is the line and what is kept is the name.
            scope::Decoded::Text(text) => sources.push((staged.path.clone(), text)),
            // No lines for a name to be written on.
            scope::Decoded::Binary => {}
            scope::Decoded::Unreadable(why) => {
                unread.push(format!("{}: {why}", staged.path));
            }
        }
    }

    decide(request, &sources, &unread)
}

/// Every blob the operation is introducing, every path it arrives under, and --
/// at a push -- every commit message it publishes.
///
/// Four of the five things the upstream scanned; the fifth is the symlink
/// target, which arrives here already, because a symlink's blob IS its target
/// path and `scope` hands that blob over like any other.
pub(crate) fn in_tracked(request: &Request<'_>) -> Result<Option<Refusal>> {
    let blobs = scope::blobs(
        request.root,
        request.stage,
        request.push_refs,
        request.push_source,
        request.remote_name,
    )?;
    let mut sources = Vec::with_capacity(blobs.len() * 2);
    let mut unread: Vec<String> = Vec::new();
    for blob in &blobs {
        if !scope::in_file_scope(request.rule, &blob.path)? {
            continue;
        }
        // THE PATH ITSELF, for every kind of entry, because it is the one thing
        // every entry has. A gitlink has no blob in this repository at all and
        // its path is the whole of what it publishes -- and a path the pushed
        // range introduced and the tip no longer holds published that name just
        // as permanently as one that survived.
        sources.push((
            format!("{} (the path itself)", blob.path),
            blob.path.clone(),
        ));
        if !blob.has_content() {
            continue;
        }
        let bytes = scope::read(request.root, blob)?;
        // Through the one decoder rather than `String::from_utf8_lossy`, which
        // is what stood here: a UTF-16 file arrived as replacement characters
        // with NULs between them, `github.com/acme/secret` inside it matched
        // nothing, and the blob was reported as read. The sibling guard over
        // the same blobs had been decoding properly since it was written, so
        // the two disagreed about whether a file had text in it at all.
        match scope::decode(&bytes) {
            scope::Decoded::Text(text) => sources.push((blob.path.clone(), text)),
            // The one honest skip: no lines for a name to be written on.
            scope::Decoded::Binary => {}
            scope::Decoded::Unreadable(why) => {
                unread.push(format!("{}: {why}", blob.path));
            }
        }
    }

    // The messages of the commits this push publishes. `commit-msg` fires only
    // when `git commit` writes a message -- not for `git commit-tree`, a
    // rebase, a cherry-pick, `git am`, `--no-verify` or a fast import -- and
    // everything else at pre-push reads the TREE, so a subject line naming a
    // private repository reached a remote with every hook green. It costs no
    // network beyond the name lookups this guard already makes.
    for (sha, body) in scope::pushed_messages(
        request.root,
        request.stage,
        request.push_refs,
        request.push_source,
    )? {
        let short: String = sha.chars().take(12).collect();
        sources.push((format!("commit {short} (its MESSAGE)"), body));
    }

    decide(request, &sources, &unread)
}

/// Text mode, for what never becomes a commit: a pull-request body typed into a
/// CLI, an issue title, a release note. Each of those goes straight to a public
/// API without passing a single hook, and the rule for all of them is this one.
pub(crate) fn in_text(
    root: &Path,
    policy: &Policy,
    rule: &Rule,
    label: &str,
    text: &str,
) -> Result<Option<Refusal>> {
    let request = Request {
        root,
        rule,
        policy,
        stage: Stage::Manual,
        message_file: None,
        push_refs: "",
        push_source: crate::runner::Source::Absent,
        remote_name: None,
        remote_url: None,
    };
    decide(&request, &[(label.to_owned(), text.to_owned())], &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The owner patterns are compiled once per judgement now, so a test that
    /// asks what a text names builds them the way `judge` does.
    fn named(
        text: &str,
        private_owners: &[String],
        own_owner: Option<&str>,
    ) -> BTreeSet<(String, String)> {
        candidates(
            text,
            &OwnerMatchers::new(private_owners, own_owner).expect("an owner a pattern can hold"),
        )
    }

    fn resolved(visibility: Visibility, canonical: Option<&str>) -> Resolved {
        Resolved {
            visibility,
            canonical: canonical.map(str::to_owned),
        }
    }

    #[test]
    fn a_name_this_repository_used_to_have_is_not_a_finding() {
        // The audit reported nine of these against itself: every pull request
        // and issue that named the repository before it was renamed. The forge
        // redirects the old name to the new one, so the lookup succeeded and
        // answered `private` -- which is this repository's own visibility while
        // it is being audited for publication, not a sibling's.
        let us = resolved(Visibility::Private, Some("acme/ours"));
        assert!(is_ourselves(&us, Some("acme/ours")));
    }

    #[test]
    fn a_genuine_private_sibling_is_still_a_finding() {
        let sibling = resolved(Visibility::Private, Some("acme/other-thing"));
        assert!(!is_ourselves(&sibling, Some("acme/ours")));
    }

    #[test]
    fn an_unresolved_name_is_not_assumed_to_be_our_own() {
        // The dangerous direction. Treating "no answer" as "that was us" turns
        // every name the forge could not reach into a pass.
        let no_answer = resolved(Visibility::Unknown, None);
        assert!(!is_ourselves(&no_answer, Some("acme/ours")));
    }

    #[test]
    fn a_repository_with_no_origin_claims_no_name_as_its_own() {
        let anything = resolved(Visibility::Private, Some("acme/ours"));
        assert!(!is_ourselves(&anything, None));
    }

    #[test]
    fn a_citation_is_not_a_repository_name() {
        // Every one of these is `host.tld/two/segments`, which is why matching
        // the shape and dropping the host turned a bibliography into lookups.
        for citation in [
            "https://doi.org/10.1109/PROC.1975.9939",
            "http://www.apache.org/licenses/LICENSE-2.0",
            "https://en.wikipedia.org/wiki/Anti-pattern",
            "https://sre.google/sre-book/monitoring-distributed-systems",
            "https://datatracker.ietf.org/rfc/rfc9110",
        ] {
            assert!(
                named(citation, &[], None).is_empty(),
                "{citation} was read as a repository name"
            );
        }
    }

    #[test]
    fn an_enterprise_host_is_not_asked_of_github() {
        // The dangerous direction: `github.acme.com/acme/widget` is a different
        // forge. Asking github.com about it answers about somebody else's
        // repository, and a public answer there passes a private one here.
        assert!(named("https://github.acme.com/acme/widget", &[], None).is_empty());
    }

    #[test]
    fn a_host_gh_cannot_answer_for_is_reported_rather_than_dropped() {
        // Extracted whatever the host is, so `judge` can decide which of the
        // two things it is: a declared owner's repository on a forge nobody can
        // ask about, or a citation. Both were dropped in silence for every host
        // outside a six-entry list, the self-hosted one included -- which is
        // the likeliest place of all for a private repository to be.
        let quiet = ForeignHosts::new(&[]).unwrap();
        let found = unanswerable_names("moved to https://gitlab.com/acme/secret", &quiet);
        assert!(
            found.contains(&(
                "gitlab.com".to_owned(),
                "acme".to_owned(),
                "secret".to_owned()
            )),
            "{found:?}"
        );
        let enterprise = unanswerable_names("https://github.acme.com/acme/widget", &quiet);
        assert_eq!(enterprise.len(), 1, "{enterprise:?}");
    }

    #[test]
    fn a_declared_host_stops_a_name_being_extracted_at_all() {
        // What `foreign_hosts` is for: a host that carries no repository this
        // rule needs an answer about, said by the policy rather than known by
        // the binary. It quiets both halves -- the declared owner's could-not-
        // look and the citation's report -- because the host is not a forge.
        let text = "https://doi.org/10.1109/PROC.1975.9939 and https://www.apache.org/l/L-2.0";
        assert_eq!(
            unanswerable_names(text, &ForeignHosts::new(&[]).unwrap()).len(),
            2
        );
        let quiet = ForeignHosts::new(&["doi.org".to_owned(), "*.apache.org".to_owned()]).unwrap();
        assert!(unanswerable_names(text, &quiet).is_empty());
    }

    #[test]
    fn a_host_glob_that_will_not_compile_is_refused_rather_than_dropped() {
        assert!(ForeignHosts::new(&["doi.org".to_owned()]).is_ok());
        assert!(ForeignHosts::new(&["{".to_owned()]).is_err());
    }

    #[test]
    fn a_raw_content_url_is_still_a_github_name() {
        let found = named(
            "https://raw.githubusercontent.com/acme/widget/main/README.md",
            &[],
            None,
        );
        assert!(found.contains(&("acme".to_owned(), "widget".to_owned())));
    }

    #[test]
    fn a_forge_url_is_a_candidate() {
        let found = named("see https://github.com/acme/widget for details", &[], None);
        assert!(found.contains(&("acme".to_owned(), "widget".to_owned())));
    }

    #[test]
    fn a_sentence_full_stop_is_not_part_of_the_name() {
        let found = named("moved to acme/widget.", &[], Some("acme"));
        assert!(
            found.contains(&("acme".to_owned(), "widget".to_owned())),
            "{found:?}"
        );
    }

    #[test]
    fn a_dot_git_suffix_is_not_part_of_the_name() {
        let found = named("git@github.com:acme/widget.git", &[], None);
        assert!(found.contains(&("acme".to_owned(), "widget".to_owned())));
    }

    #[test]
    fn a_bare_path_is_not_a_candidate_unless_its_owner_was_declared() {
        // Otherwise every relative path in every document is a lookup.
        assert!(named("see src/main.rs", &[], None).is_empty());
        let declared = vec!["src".to_owned()];
        assert!(named("see src/main.rs", &declared, None)
            .contains(&("src".to_owned(), "main.rs".to_owned())));
    }

    #[test]
    fn a_sibling_named_without_a_host_is_a_candidate_for_this_owner() {
        // `acme/widget` with no host is what a README writes -- "now maintained
        // in acme/widget" -- and every URL form misses it. Found by trying to
        // write a deprecation note and watching the guard pass it.
        let found = named("now maintained in acme/widget", &[], Some("acme"));
        assert!(found.contains(&("acme".to_owned(), "widget".to_owned())));
    }

    #[test]
    fn another_owners_bare_path_is_still_not_a_candidate() {
        // A bare `owner/repo` is indistinguishable from a relative path, so
        // this stays off for owners in general: every path in every document
        // would otherwise become a forge lookup.
        let found = named("see src/main.rs", &[], Some("acme"));
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn the_repositorys_own_owner_alone_is_not_a_finding() {
        // Its name is published by the repository existing. Only a DECLARED
        // private owner is caught on its own.
        let found = named("maintained by acme", &[], Some("acme"));
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_declared_owner_with_a_dot_is_escaped_not_interpreted() {
        let declared = vec!["acme.corp".to_owned()];
        let found = named("acme.corp/thing and acmeXcorp/other", &declared, None);
        assert!(found.contains(&("acme.corp".to_owned(), "thing".to_owned())));
        assert!(!found
            .iter()
            .any(|(owner, _)| owner.eq_ignore_ascii_case("acmeXcorp")));
    }

    #[test]
    fn a_hunk_with_no_count_still_says_which_line_it_opens_at() {
        // `-U0` spells a one-line hunk without a comma anywhere in it, and it is
        // the spelling the staged scan asks for -- so a reader that needed the
        // comma numbered nothing this guard ever sees.
        assert_eq!(hunk_start(" -7 +7 @@ fn f()"), Some(7));
        assert_eq!(hunk_start(" -0,0 +1,3 @@"), Some(1));
        assert_eq!(hunk_start(" -1 +0,0 @@"), Some(0));
        // Nothing to read rather than a number invented from one: a wrong line
        // sends a reader to the wrong place.
        assert_eq!(hunk_start(" not a hunk header"), None);
    }

    #[test]
    fn a_finding_with_no_line_still_names_the_file() {
        // The line is dropped when a header could not be parsed, and the finding
        // is not -- the line was scanned either way.
        assert_eq!(located("docs/note.md", Some(12)), "docs/note.md:12");
        assert_eq!(located("docs/note.md", None), "docs/note.md");
    }
}
