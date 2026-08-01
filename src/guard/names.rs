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
//! message. `in_staged` judges the lines a commit ADDS, which is the right unit
//! at commit time and blind by construction to a line already there.
//! `in_tracked` closes that half: a name that arrived under `--no-verify`,
//! through a merge, or in a checkout where no hook was installed is never looked
//! at again otherwise.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use regex::Regex;

use super::scope;
use super::{Refusal, Request, Stage};
use crate::config::Rule;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Visibility {
    Public,
    Private,
    Unknown,
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
struct Resolved {
    visibility: Visibility,
    canonical: Option<String>,
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

/// A forge this tool cannot query, but which hosts repositories that can be
/// private.
///
/// Kept apart from an arbitrary host because the two deserve different answers.
/// A name on one of these is a repository whose visibility is genuinely unknown,
/// and unknown is reported. A name on `doi.org` is not a repository at all.
fn is_foreign_forge_host(host: &str) -> bool {
    let host = host.to_lowercase();
    ["gitlab.com", "bitbucket.org", "codeberg.org", "gitea.com"].contains(&host.as_str())
        || host.ends_with(".sr.ht")
        || host == "git.sr.ht"
}

/// Repositories named on a forge whose visibility `gh` cannot answer for.
///
/// Reported as unresolved rather than dropped: the tool cannot tell whether
/// `gitlab.com/acme/secret` is private, and silence would read as clean.
fn foreign_forge_names(text: &str) -> BTreeSet<(String, String)> {
    let mut found = BTreeSet::new();
    for capture in url_pattern().captures_iter(text) {
        if !is_foreign_forge_host(&capture[1]) {
            continue;
        }
        let repo = clean_repo(&capture[3]);
        if repo.is_empty() {
            continue;
        }
        found.insert((capture[2].to_string(), repo));
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
fn candidates(
    text: &str,
    private_owners: &[String],
    own_owner: Option<&str>,
) -> BTreeSet<(String, String)> {
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

    // The repository's OWN owner, treated as though it had been declared.
    //
    // `acme/widget` written with no host is the spelling a README uses for a
    // sibling -- "now maintained in acme/widget" -- and the URL forms above all
    // miss it. It is not caught for owners in general because a bare
    // `owner/repo` is indistinguishable from a relative path, and every path in
    // every document would become a lookup. It is caught for THIS owner because
    // a segment equal to the login that owns the repository, followed by a
    // name, is a sibling reference and not a directory: nobody writes
    // `acme/main.rs`.
    //
    // Found by trying to write the deprecation note that would close #29 and
    // watching the guard pass it.
    let mut owners: Vec<String> = private_owners.to_vec();
    if let Some(own_owner) = own_owner {
        if !owners
            .iter()
            .any(|owner| owner.eq_ignore_ascii_case(own_owner))
        {
            owners.push(own_owner.to_owned());
        }
    }

    for owner in &owners {
        // Anchored at the owner so a declared-private owner is found in the
        // bare form too. Escaped, because an owner may legitimately contain a
        // dot and an unescaped one would match any character.
        let pattern = format!(
            r"(?i)\b{}/([A-Za-z0-9][A-Za-z0-9._-]*)",
            regex::escape(owner)
        );
        let Ok(matcher) = Regex::new(&pattern) else {
            continue;
        };
        for capture in matcher.captures_iter(text) {
            found.insert((owner.clone(), clean_repo(&capture[1])));
        }

        // The owner ON ITS OWN, with no repository after it. Every form above
        // needs an `owner/repo`, and this is the one that got past a hand
        // audit: a sentence naming a private organisation discloses that it
        // exists and who owns it without ever naming one of its repositories.
        // Only for a DECLARED owner -- a bare word is not otherwise a name, and
        // treating any capitalised token as one would fire on ordinary prose.
        // The repository's own owner is deliberately not in this half: its
        // name is published by the repository existing.
        if !private_owners.iter().any(|declared| declared == owner) {
            continue;
        }
        let bare = format!(r"(?i)\b{}\b", regex::escape(owner));
        if let Ok(bare_matcher) = Regex::new(&bare) {
            if bare_matcher.is_match(text) {
                found.insert((owner.clone(), String::new()));
            }
        }
    }
    found
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
fn lookup(cache: &mut BTreeMap<String, Resolved>, owner: &str, repo: &str) -> Resolved {
    let key = format!("{owner}/{repo}");
    if let Some(known) = cache.get(&key) {
        return known.clone();
    }
    let resolved = match Command::new("gh")
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
        _ => Resolved {
            visibility: Visibility::Unknown,
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
fn target_is_public(root: &Path, rule: &Rule) -> Result<Option<bool>> {
    if let Some(declared) = rule.visibility.as_deref() {
        return match declared.to_lowercase().as_str() {
            "public" => Ok(Some(true)),
            "private" | "internal" => Ok(Some(false)),
            other => Err(Fatal::new(format!(
                "rule {:?}: visibility {other:?} is not a visibility",
                rule.id
            ))),
        };
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
        Visibility::Unknown => None,
    })
}

struct Verdict {
    refused: Vec<String>,
    unresolved: Vec<String>,
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
pub(crate) fn declared_owners(root: &Path, rule: &Rule) -> Result<Vec<String>> {
    let mut owners = rule.private_owners().to_vec();
    if let Some(command) = rule.private_owners_from.as_deref() {
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
            return Err(Fatal::new(format!(
                "{}: private_owners_from exited {}: {}",
                rule.id,
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
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

fn judge(root: &Path, rule: &Rule, owners: &[String], sources: &[(String, String)]) -> Verdict {
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
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for (where_found, text) in sources {
        for (owner, repo) in candidates(text, owners, our_owner.as_deref()) {
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
                Visibility::Public => {}
            }
        }

        // Named on a forge this tool cannot query. Not refused -- it may well be
        // public -- but not passed over either.
        for (owner, repo) in foreign_forge_names(text) {
            let name = format!("{owner}/{repo}");
            if public.contains(&name.to_lowercase()) {
                continue;
            }
            if seen.insert(format!("{where_found}\u{0}{name}")) {
                unresolved.push(format!(
                    "{where_found}: {name} is on a forge this tool cannot query"
                ));
            }
        }
    }
    Verdict {
        refused,
        unresolved,
    }
}

fn decide(request: &Request<'_>, sources: &[(String, String)]) -> Result<Option<Refusal>> {
    let Some(public) = target_is_public(request.root, request.rule)? else {
        // Not a pass. The guard could not establish the one condition it fires
        // under, and saying nothing would look exactly like saying clean.
        return Err(Fatal::new(format!(
            "{}: could not determine this repository's visibility. Set `visibility` on \
             the rule to say what it is.",
            request.rule.id
        )));
    };
    if !public {
        return Ok(None);
    }

    let owners = declared_owners(request.root, request.rule)?;
    let verdict = judge(request.root, request.rule, &owners, sources);
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
        return Ok(None);
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
    let bytes = std::fs::read(&path).map_err(|error| Fatal::at(&path, error))?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    decide(request, &[(String::from("commit message"), text)])
}

/// The lines this commit ADDS.
pub(crate) fn in_staged(request: &Request<'_>) -> Result<Option<Refusal>> {
    let diff = git::run(request.root, &["diff", "--cached", "--unified=0"])?;
    let added: String = diff
        .lines()
        .filter(|line| line.starts_with('+') && !line.starts_with("+++"))
        .collect::<Vec<&str>>()
        .join("\n");
    decide(request, &[(String::from("staged changes"), added)])
}

/// Every blob the operation is introducing.
pub(crate) fn in_tracked(request: &Request<'_>) -> Result<Option<Refusal>> {
    let blobs = scope::blobs(
        request.root,
        request.stage,
        request.push_refs,
        request.push_source,
        request.remote_name,
    )?;
    let mut sources = Vec::with_capacity(blobs.len());
    for blob in &blobs {
        if !scope::in_file_scope(request.rule, &blob.path)? {
            continue;
        }
        let bytes = scope::read(request.root, blob)?;
        sources.push((
            blob.path.clone(),
            String::from_utf8_lossy(&bytes).into_owned(),
        ));
    }
    decide(request, &sources)
}

/// Text mode, for what never becomes a commit: a pull-request body typed into a
/// CLI, an issue title, a release note. Each of those goes straight to a public
/// API without passing a single hook, and the rule for all of them is this one.
pub(crate) fn in_text(
    root: &Path,
    rule: &Rule,
    label: &str,
    text: &str,
) -> Result<Option<Refusal>> {
    let request = Request {
        root,
        rule,
        stage: Stage::Manual,
        message_file: None,
        push_refs: "",
        push_source: crate::runner::Source::Absent,
        remote_name: None,
        remote_url: None,
    };
    decide(&request, &[(label.to_owned(), text.to_owned())])
}

#[cfg(test)]
mod tests {
    use super::*;

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
                candidates(citation, &[], None).is_empty(),
                "{citation} was read as a repository name"
            );
        }
    }

    #[test]
    fn an_enterprise_host_is_not_asked_of_github() {
        // The dangerous direction: `github.acme.com/acme/widget` is a different
        // forge. Asking github.com about it answers about somebody else's
        // repository, and a public answer there passes a private one here.
        assert!(candidates("https://github.acme.com/acme/widget", &[], None).is_empty());
    }

    #[test]
    fn another_forge_is_reported_rather_than_dropped() {
        // Cannot be resolved with `gh`, and may well be private. Silence would
        // read as clean.
        let found = foreign_forge_names("moved to https://gitlab.com/acme/secret");
        assert!(
            found.contains(&("acme".to_owned(), "secret".to_owned())),
            "{found:?}"
        );
        assert!(foreign_forge_names("https://doi.org/10.1109/PROC.1975.9939").is_empty());
    }

    #[test]
    fn a_raw_content_url_is_still_a_github_name() {
        let found = candidates(
            "https://raw.githubusercontent.com/acme/widget/main/README.md",
            &[],
            None,
        );
        assert!(found.contains(&("acme".to_owned(), "widget".to_owned())));
    }

    #[test]
    fn a_forge_url_is_a_candidate() {
        let found = candidates("see https://github.com/acme/widget for details", &[], None);
        assert!(found.contains(&("acme".to_owned(), "widget".to_owned())));
    }

    #[test]
    fn a_sentence_full_stop_is_not_part_of_the_name() {
        let found = candidates("moved to acme/widget.", &[], Some("acme"));
        assert!(
            found.contains(&("acme".to_owned(), "widget".to_owned())),
            "{found:?}"
        );
    }

    #[test]
    fn a_dot_git_suffix_is_not_part_of_the_name() {
        let found = candidates("git@github.com:acme/widget.git", &[], None);
        assert!(found.contains(&("acme".to_owned(), "widget".to_owned())));
    }

    #[test]
    fn a_bare_path_is_not_a_candidate_unless_its_owner_was_declared() {
        // Otherwise every relative path in every document is a lookup.
        assert!(candidates("see src/main.rs", &[], None).is_empty());
        let declared = vec!["src".to_owned()];
        assert!(candidates("see src/main.rs", &declared, None)
            .contains(&("src".to_owned(), "main.rs".to_owned())));
    }

    #[test]
    fn a_sibling_named_without_a_host_is_a_candidate_for_this_owner() {
        // `acme/widget` with no host is what a README writes -- "now maintained
        // in acme/widget" -- and every URL form misses it. Found by trying to
        // write a deprecation note and watching the guard pass it.
        let found = candidates("now maintained in acme/widget", &[], Some("acme"));
        assert!(found.contains(&("acme".to_owned(), "widget".to_owned())));
    }

    #[test]
    fn another_owners_bare_path_is_still_not_a_candidate() {
        // A bare `owner/repo` is indistinguishable from a relative path, so
        // this stays off for owners in general: every path in every document
        // would otherwise become a forge lookup.
        let found = candidates("see src/main.rs", &[], Some("acme"));
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn the_repositorys_own_owner_alone_is_not_a_finding() {
        // Its name is published by the repository existing. Only a DECLARED
        // private owner is caught on its own.
        let found = candidates("maintained by acme", &[], Some("acme"));
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_declared_owner_with_a_dot_is_escaped_not_interpreted() {
        let declared = vec!["acme.corp".to_owned()];
        let found = candidates("acme.corp/thing and acmeXcorp/other", &declared, None);
        assert!(found.contains(&("acme.corp".to_owned(), "thing".to_owned())));
        assert!(!found
            .iter()
            .any(|(owner, _)| owner.eq_ignore_ascii_case("acmeXcorp")));
    }
}
