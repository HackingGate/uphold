//! Reconcile `policy/upheld.toml` against the rules this repository runs.
//!
//! A claim is that a named rule is what enforces a named principle HERE:
//!
//! ```toml
//! [[enforce]]
//! principle = "explicit-unknown"
//! rule = "catalog-tests"
//! ```
//!
//! It is falsifiable from this repository's own configuration -- the rule is
//! resolved and its seam is installed, or it is not -- and that is the only
//! thing checked. When it is false, the principle stopped being enforced while
//! the declaration went on saying it was.
//!
//! This lived in `uphold_check.py`, where answering it meant re-implementing
//! `config::load`: the bundled sets, `inherit.paths`, `inherit.disabled_rules`,
//! and a repository's own rule shadowing an inherited id. Five interacting
//! fields, read twice, by two programs free to disagree -- and they did, about
//! the seam a hookless rule runs at, which credited a checker standing in front
//! of `gh` to the file scan and reconciled a claim on it green in a repository
//! where nothing ran it. The loader answers now, and this asks.
//!
//! What stayed in Python is what never reads the policy: `--explain`,
//! `--list`, `--review`. Those read the catalog and render prose, so they
//! cannot disagree with the engine about which rules run.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

use crate::catalog;
use crate::config::Policy;
use crate::error::{Exit, Fatal, Result};

const DECLARATION: &str = "policy/upheld.toml";

/// `owner/name` -- the form a consumer's runner configuration writes down.
///
/// From `package.repository` at COMPILE time. The Python read the manifest off
/// disk beside itself, which works only in a checkout of this repository and is
/// a second copy of a value cargo already holds. This one cannot drift from the
/// crate it is compiled into.
fn upstream_slug() -> Option<(&'static str, &'static str)> {
    slug_of(env!("CARGO_PKG_REPOSITORY"))
}

/// The parse, taking the url as an argument so it can be asked about one.
///
/// Split out because a mutation run said so: the whole function read a
/// compile-time constant, so every mutation of the emptiness test survived --
/// there was no input a test could hand it, and therefore no test. What the
/// test now pins is the answer for a url that names no owner or no repository,
/// which is the case that decides whether a consumer's configuration is read as
/// pinning this repository at all.
fn slug_of(url: &str) -> Option<(&str, &str)> {
    let url = url.trim_end_matches('/').trim_end_matches(".git");
    let (rest, name) = url.rsplit_once('/')?;
    let owner = rest.rsplit('/').next()?;
    (!owner.is_empty() && !name.is_empty()).then_some((owner, name))
}

/// Is this url NOT identifiably somebody else's?
///
/// The question is deliberately that way round. lefthook takes any git url, and
/// most cannot answer "does this name us" at all: a consumer may clone from a
/// filesystem path, a mirror, or a bare directory whose name says nothing.
/// `scripts/consumer_check.sh` clones to a neutral `$WORK/hooks` on purpose, so
/// the url it writes carries neither the owner nor the repository name.
/// Demanding the slug there demands evidence the format does not carry, and
/// answering "no seam here supplies it" is answering exit 1 -- the claim is
/// FALSE -- about a repository whose only fault is cloning from a path.
///
/// So a remote is rejected only when it spells a forge `owner/name` and that
/// pair is not ours. Anything without a host is a path, and a path is
/// unidentifiable rather than foreign.
///
/// The load-bearing half is elsewhere and untouched: the remote and
/// `hooks/lefthook.yml` must appear in the SAME entry, so a fork pinning its own
/// config, or an unrelated project pulling a file that happens to share the
/// conventional name, is still not credited with running every guard here.
fn names_this_repository(url: &str) -> bool {
    let trimmed = url.trim().trim_end_matches('/').trim_end_matches(".git");
    let Some((owner, name)) = upstream_slug() else {
        return false;
    };
    // A host, in either spelling git accepts: `scheme://host/owner/name` and
    // `user@host:owner/name`. Without one there is no owner to compare.
    let after_host = if let Some((_, rest)) = trimmed.split_once("://") {
        rest.split_once('/').map(|(_, path)| path)
    } else if let Some((_, rest)) = trimmed.split_once('@') {
        rest.split_once(':').map(|(_, path)| path)
    } else {
        return true;
    };
    let Some(path) = after_host else {
        return true;
    };
    let mut segments = path.rsplit('/');
    let (Some(last), Some(before)) = (segments.next(), segments.next()) else {
        // A host and one segment names no owner, so it identifies nobody.
        return true;
    };
    before == owner && last == name
}

/// One `[[enforce]]` entry, as written.
#[derive(Debug, Deserialize)]
struct Claim {
    principle: Option<String>,
    rule: Option<String>,
    /// Refused rather than ignored. `tier` said which namespace `rule` resolved
    /// in, back when the seams were separate repositories. Ignoring a leftover
    /// one silently reinterprets the claim; failing it as a false claim sends
    /// the author looking for a rule that is present.
    #[serde(default)]
    tier: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Declaration {
    #[serde(default)]
    enforce: Vec<Claim>,
}

/// Which seams of `uphold` this repository installs.
///
/// Two answers and not one. A repository-wide "uphold runs here" let every rule
/// in the policy resolve against it, so one that pinned `uphold-scan` and no
/// guard id reconciled a claim on a `pre-push` guard whose stage nothing
/// installed. What is returned is what was installed: the file scan, and the
/// set of git stages some pinned id actually runs.
///
/// Both runners are read and unioned rather than the first one winning. A
/// repository may drive the fast stages from pre-commit and the slow ones from
/// lefthook, and either file alone understates it.
#[derive(Debug, Default)]
pub(crate) struct Installed {
    pub scan: bool,
    pub stages: BTreeSet<String>,
    /// How it was established, so a reconcile that passes does not pass for a
    /// reason the reader cannot see.
    pub how: Vec<String>,
    /// Seams that could not be read. Never counted as absent: a rule missing
    /// from what could be read is not a missing rule, which is exit 2 and not
    /// exit 1. See the `explicit-unknown` record.
    pub unreadable: Vec<String>,
    /// The `local` tier: every hook id installed here from any repository, plus
    /// every lefthook command name. A claim may name a formatter, a linter, or
    /// a hook this repository wrote, and those are rules that fire here.
    pub local: BTreeSet<String>,
}

impl Installed {
    fn nothing(&self) -> bool {
        !self.scan && self.stages.is_empty()
    }
}

/// The published ids, and which stage each one installs.
///
/// Read off this binary's own manifest at compile time rather than listed here.
/// A list here would be a literal describing a constant there, which is the
/// shape of the defect `_rule_stages` carries a paragraph about: the list was
/// short by one id and a claim on the rule it named reported enforcing nothing.
const MANIFEST: &str = include_str!("../.pre-commit-hooks.yaml");

#[derive(Debug, Deserialize)]
struct PublishedHook {
    id: String,
    #[serde(default)]
    entry: String,
    #[serde(default)]
    stages: Vec<String>,
}

/// `(ids that run the scan, stage -> the id that installs it)`.
fn published() -> Result<(BTreeSet<String>, BTreeMap<String, String>)> {
    let hooks: Vec<PublishedHook> = serde_yaml_ng::from_str(MANIFEST)
        .map_err(|error| Fatal::new(format!(".pre-commit-hooks.yaml: {error}")))?;

    let mut scans = BTreeSet::new();
    let mut guards = BTreeMap::new();
    for hook in hooks {
        let entry = hook.entry.split_whitespace().collect::<Vec<_>>();
        match entry.as_slice() {
            // `uphold scan` over the tree. `--text` reads a message on stdin
            // and establishes nothing about the tree, so it is not the scan
            // seam a content rule runs at.
            [_, "scan", rest @ ..] if !rest.contains(&"--text") => {
                scans.insert(hook.id);
            }
            [_, "guard", ..] => {
                for stage in hook.stages {
                    guards.entry(stage).or_insert_with(|| hook.id.clone());
                }
            }
            _ => {}
        }
    }
    Ok((scans, guards))
}

#[derive(Debug, Deserialize)]
struct PreCommitConfig {
    #[serde(default)]
    repos: Option<Vec<PreCommitRepo>>,
}

#[derive(Debug, Deserialize)]
struct PreCommitRepo {
    // No `repo:` field. Which repository an id came from is deliberately not
    // consulted -- see `pinned_ids`. `repo: local` entries are read the same
    // way as any other, because a local hook is a rule that fires here and a
    // claim may name it.
    #[serde(default)]
    hooks: Vec<PinnedHook>,
}

#[derive(Debug, Deserialize)]
struct PinnedHook {
    #[serde(default)]
    id: String,
}

/// Every hook id a pre-commit config installs, from any repository.
///
/// By ID and not by repository url, which is the whole of what
/// `published_seams` is for. The predicate this replaced was a repository name,
/// and a consumer does not necessarily write one a matcher would recognise:
/// `scripts/consumer_check.sh` clones this repository to a temporary directory
/// and pins it by PATH, so the last segment of its `repo:` is `hooks`. Scoping
/// on the url told that consumer the seam supplying every guard was absent.
///
/// An id is specific enough on its own. `uphold-guard-push` is this binary's
/// name for this binary's stage, and the manifest is where the list comes from
/// so a new id cannot be published there and forgotten here.
///
/// The same set answers the `local` tier: a claim may name a formatter, a
/// linter, or a hook this repository wrote, and those are rules that fire here.
fn pinned_ids(root: &Path) -> Result<Option<BTreeSet<String>>> {
    let path = root.join(".pre-commit-config.yaml");
    if !path.is_file() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path).map_err(|error| Fatal::at(&path, error))?;
    let config: PreCommitConfig =
        serde_yaml_ng::from_str(&text).map_err(|error| Fatal::at(&path, error))?;
    let Some(repos) = config.repos else {
        return Err(Fatal::at(
            &path,
            "has no top-level `repos:` key, so which hooks it installs cannot be read. \
             Reporting no hooks would be an empty answer where the honest one is \
             could-not-look",
        ));
    };
    let mut every = BTreeSet::new();
    for entry in repos {
        for hook in entry.hooks {
            every.insert(hook.id);
        }
    }
    Ok(Some(every))
}

#[derive(Debug, Deserialize)]
struct LefthookConfig {
    #[serde(default)]
    remotes: Vec<LefthookRemote>,
    #[serde(flatten)]
    stages: BTreeMap<String, serde_yaml_ng::Value>,
}

#[derive(Debug, Deserialize)]
struct LefthookRemote {
    #[serde(default)]
    git_url: String,
    #[serde(default)]
    configs: Vec<String>,
}

/// The git stages a lefthook config drives the binary at, directly.
///
/// Parsed rather than line-scanned. The Python read this with a regex over
/// indentation and a stack of enclosing keys, which accepted `configs:` -- the
/// key under `remotes:` that README.md tells every consumer to write -- as a
/// command name, so a claim naming a rule called `configs` reconciled green
/// against a file defining no such thing. A parser cannot make that mistake.
fn lefthook_seams(root: &Path, guards: &BTreeMap<String, String>) -> Result<Installed> {
    let mut found = Installed::default();
    let path = root.join("lefthook.yml");
    if !path.is_file() {
        return Ok(found);
    }
    let text = std::fs::read_to_string(&path).map_err(|error| Fatal::at(&path, error))?;
    let config: LefthookConfig =
        serde_yaml_ng::from_str(&text).map_err(|error| Fatal::at(&path, error))?;

    let mut direct = false;
    for (stage, body) in &config.stages {
        // Only a name git knows is a stage; `remotes`, `colors` and the rest of
        // lefthook's top-level keys are not.
        if !guards.contains_key(stage.as_str()) {
            continue;
        }
        for run in runs_in(body) {
            let words: Vec<&str> = run.split_whitespace().collect();
            // The subcommand, and the word before it. Matched on the
            // SUBCOMMAND and not the executable: this repository runs its own
            // binary out of the tree with `cargo run -- scan`, a consumer runs
            // `uphold scan` from PATH, and a third by absolute path. All three
            // are the same seam, and a pattern anchored on the program name
            // recognised only the middle one.
            let Some((before, subcommand)) = words.windows(2).find_map(|pair| match pair {
                [before, word @ ("scan" | "guard")] => Some((*before, *word)),
                _ => None,
            }) else {
                continue;
            };
            if !(before.ends_with("uphold") || before == "--") {
                continue;
            }
            direct = true;
            if subcommand == "scan" && !words.contains(&"--text") {
                found.scan = true;
            } else if subcommand == "guard" {
                found.stages.insert(stage.clone());
            }
        }
    }
    if direct {
        found.how.push(String::from("lefthook.yml runs the binary"));
    }

    let commands = lefthook_commands(&config, guards);
    if !commands.is_empty() {
        found.how.push(format!(
            "lefthook.yml defines {} command(s)",
            commands.len()
        ));
    }
    found.local = commands;

    // BOTH halves, in the SAME entry. Checked separately, either alone was
    // enough: a remote whose url merely resembled this repository, or one
    // pulling a file that happens to be called `hooks/lefthook.yml` out of
    // somebody else's. Either match granted every stage this manifest
    // publishes, because the branch it feeds assumes the remote IS this
    // repository's config -- so a fork, a mirror, or an unrelated project
    // following the same conventional filename was credited with running every
    // guard here.
    if config.remotes.iter().any(|remote| {
        names_this_repository(&remote.git_url)
            && remote
                .configs
                .iter()
                .any(|named| named.trim() == "hooks/lefthook.yml")
    }) {
        // The remote config is this repository's `hooks/lefthook.yml`, which
        // wires every stage the manifest publishes. Including it is the one
        // form that needs no per-stage reading.
        found.scan = true;
        found.stages.extend(guards.keys().cloned());
        found.how.push(String::from(
            "lefthook.yml includes this repository as a remote",
        ));
    }
    Ok(found)
}

/// The command names a lefthook config defines, and nothing else.
///
/// A command is a key under a stage's `commands:` mapping. The Python matched
/// on indentation with a stack of enclosing keys, which accepted `configs:` --
/// the key under `remotes:` that README.md tells every consumer to write
/// verbatim -- as a command named `configs`, so a claim naming that rule
/// reconciled green against a file that defines no such thing. Reading the
/// mapping cannot make that mistake, because `configs` is not under a stage.
fn lefthook_commands(
    config: &LefthookConfig,
    guards: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for (stage, body) in &config.stages {
        if !guards.contains_key(stage.as_str()) {
            continue;
        }
        let Some(commands) = body.get("commands").and_then(|value| value.as_mapping()) else {
            continue;
        };
        for key in commands.keys() {
            if let Some(name) = key.as_str() {
                names.insert(name.to_owned());
            }
        }
    }
    names
}

/// Every `run:` string under a lefthook stage, at any nesting.
fn runs_in(value: &serde_yaml_ng::Value) -> Vec<String> {
    let mut found = Vec::new();
    match value {
        serde_yaml_ng::Value::Mapping(mapping) => {
            for (key, nested) in mapping {
                if key.as_str() == Some("run") {
                    if let Some(text) = nested.as_str() {
                        found.push(text.to_owned());
                    }
                } else {
                    found.extend(runs_in(nested));
                }
            }
        }
        serde_yaml_ng::Value::Sequence(items) => {
            for item in items {
                found.extend(runs_in(item));
            }
        }
        _ => {}
    }
    found
}

pub(crate) fn installed(root: &Path) -> Result<Installed> {
    let (scans, guards) = published()?;
    let mut found = Installed::default();

    match pinned_ids(root) {
        Ok(Some(ids)) => {
            found.scan = ids.iter().any(|id| scans.contains(id));
            for (stage, hook) in &guards {
                if ids.contains(hook) {
                    found.stages.insert(stage.clone());
                }
            }
            let mut named: Vec<String> = ids
                .iter()
                .filter(|id| scans.contains(*id) || guards.values().any(|hook| hook == *id))
                .cloned()
                .collect();
            named.sort_unstable();
            found.local.extend(ids);
            if !named.is_empty() {
                found
                    .how
                    .push(format!(".pre-commit-config.yaml pins {}", named.join(", ")));
            }
        }
        Ok(None) => {}
        // Present and unreadable is not absent. A config this cannot parse is
        // exactly where the missing seam might be.
        Err(error) => found.unreadable.push(error.to_string()),
    }

    match lefthook_seams(root, &guards) {
        Ok(lefthook) => {
            found.scan = found.scan || lefthook.scan;
            found.stages.extend(lefthook.stages);
            found.how.extend(lefthook.how);
            found.local.extend(lefthook.local);
        }
        Err(error) => found.unreadable.push(error.to_string()),
    }

    if found.nothing() && found.how.is_empty() {
        found.how.push(String::from(
            "no runner configuration here runs `uphold scan` or `uphold guard`",
        ));
    }
    Ok(found)
}

/// Which seams supply each resolved rule, and what could not be established.
///
/// `Rule::seams` is the loader's answer to where a rule runs; this asks whether
/// that place is installed here. A `shim` rule is the one seam no runner
/// configuration can settle -- whether the shim is on PATH ahead of the real
/// command is not written in any file this reads -- so it is reported as
/// unestablished rather than credited to whichever seam happens to be on.
pub(crate) fn suppliers(policy: &Policy, installed: &Installed) -> Supply {
    let mut supplied: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut unestablished: Vec<String> = Vec::new();

    for name in &installed.local {
        supplied
            .entry(name.clone())
            .or_default()
            .push(String::from("a hook installed here"));
    }

    for rule in &policy.rules {
        let mut by: Vec<String> = Vec::new();
        for seam in rule.seams() {
            match seam {
                "scan" if installed.scan => by.push(String::from("uphold scan")),
                "scan" => unestablished.push(format!("{} (file scan)", rule.id)),
                "guard" => {
                    let live: Vec<&str> = rule
                        .hooks()
                        .iter()
                        .filter(|hook| installed.stages.contains(*hook))
                        .map(String::as_str)
                        .collect();
                    if live.is_empty() {
                        unestablished.push(format!("{} ({})", rule.id, rule.hooks().join(", ")));
                    } else {
                        by.push(format!("uphold guard at {}", live.join(", ")));
                    }
                }
                "shim" => {
                    unestablished.push(format!("{} (stands in front of a command)", rule.id));
                }
                _ => {}
            }
        }
        if !by.is_empty() {
            supplied.entry(rule.id.clone()).or_default().extend(by);
        }
    }
    Supply {
        supplied,
        unestablished,
    }
}

pub(crate) struct Supply {
    pub supplied: BTreeMap<String, Vec<String>>,
    pub unestablished: Vec<String>,
}

/// `uphold check`, and `uphold check --coverage`.
pub(crate) fn run(root: &Path, policy: &Policy, coverage: bool) -> Result<Exit> {
    let path = root.join(DECLARATION);
    if !path.is_file() {
        return Err(Fatal::new(format!(
            "{DECLARATION} not found under {}. Create one with: \
             uphold_check.py --init > {DECLARATION}",
            root.display()
        )));
    }
    let text = std::fs::read_to_string(&path).map_err(|error| Fatal::at(&path, error))?;
    let declaration: Declaration =
        toml::from_str(&text).map_err(|error| Fatal::at(&path, error))?;

    let installed = installed(root)?;
    let supply = suppliers(policy, &installed);

    if coverage {
        return report_coverage(policy, &declaration, &installed, &supply);
    }

    let mut failures: Vec<String> = Vec::new();
    let mut evidence: Vec<String> = Vec::new();

    for (index, claim) in declaration.enforce.iter().enumerate() {
        let at = format!("enforce[{index}]");
        if claim.tier.is_some() {
            return Err(Fatal::at(
                &path,
                format!(
                    "{at} carries a `tier`. The field is gone: a rule id resolves across \
                     every seam at once, so a claim naming one no longer has to say which. \
                     Drop the line."
                ),
            ));
        }
        let (Some(principle), Some(rule)) = (claim.principle.as_deref(), claim.rule.as_deref())
        else {
            return Err(Fatal::at(
                &path,
                format!("{at}: `principle` and `rule` are both required"),
            ));
        };
        if principle.trim().is_empty() || rule.trim().is_empty() {
            return Err(Fatal::at(
                &path,
                format!("{at}: `principle` and `rule` must not be blank"),
            ));
        }

        let Some(record) = catalog::get(principle)? else {
            failures.push(format!(
                "{at}: {}",
                catalog::unknown(principle, catalog::ids()?.len())
            ));
            continue;
        };
        if record.deprecated() {
            failures.push(format!(
                "{at}: {principle:?} is deprecated; the catalog keeps it for redirects only"
            ));
            continue;
        }
        if record.refuses_automation() {
            failures.push(format!(
                "{at}: the {principle:?} record says enforcement.automatable = \"no\"; \
                 no rule can be claimed to enforce it"
            ));
            continue;
        }

        if let Some(by) = supply.supplied.get(rule) {
            evidence.push(format!(
                "{principle} <- {rule}  enforced by {}",
                by.join(", ")
            ));
            continue;
        }

        if !installed.unreadable.is_empty() {
            // A rule absent from what could be read is not an absent rule. The
            // configuration that could not be inspected is exactly where it
            // might be, so this is could-not-look and not a false claim.
            return Err(Fatal::new(format!(
                "{at}: no rule {rule:?} in what could be read, and {} \
                 could not be read; cannot tell whether the claim holds",
                installed.unreadable.join("; ")
            )));
        }

        failures.push(format!(
            "{at}: {principle:?} claims {rule:?}, which no seam here supplies"
        ));
    }

    if !failures.is_empty() {
        eprintln!("enforcement claims refused ({DECLARATION}):");
        for failure in &failures {
            eprintln!("- {failure}");
        }
        return Ok(Exit::Violations);
    }

    println!("reconciled {} enforcement claims:", evidence.len());
    for line in &evidence {
        println!("  {line}");
    }
    for note in &installed.how {
        println!("  note  {note}");
    }
    Ok(Exit::Clean)
}

/// The denominator the reconcile cannot see: rules that run and claim nothing.
///
/// It reports and does not refuse. A mode that failed a build over an unclaimed
/// rule would be paid for in claims written to silence it, and deciding which
/// principle a rule serves is a judgment. Exit 2 only where something could not
/// be read, because a coverage number computed over a seam nobody could inspect
/// means less than it looks like it means.
fn report_coverage(
    policy: &Policy,
    declaration: &Declaration,
    installed: &Installed,
    supply: &Supply,
) -> Result<Exit> {
    let mut claims: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for claim in &declaration.enforce {
        if let (Some(principle), Some(rule)) = (claim.principle.as_deref(), claim.rule.as_deref()) {
            claims.entry(rule).or_default().push(principle);
        }
    }

    let mut lines: Vec<String> = Vec::new();

    // The engine's own rules, and how many of them a claim names.
    let mut carrying = 0_usize;
    let mut unclaimed: Vec<&str> = Vec::new();
    for rule in &policy.rules {
        if !supply.supplied.contains_key(&rule.id) {
            continue;
        }
        match claims.get(rule.id.as_str()) {
            Some(principles) => {
                carrying += 1;
                for principle in principles {
                    lines.push(format!("  {} -> {principle}", rule.id));
                }
            }
            None => unclaimed.push(&rule.id),
        }
    }
    let supplied = carrying + unclaimed.len();
    println!("uphold: {carrying} of {supplied} rules carry a principle");
    for line in &lines {
        println!("{line}");
    }
    for rule in &unclaimed {
        println!("  unclaimed  {rule}");
    }

    // The local tier: hooks and commands this repository installs, which a
    // claim may name and the engine does not own. `?` and not 0 where it could
    // not be read -- a hole reported as zero reads as coverage nobody measured.
    if installed.unreadable.is_empty() {
        let claimed_local = installed
            .local
            .iter()
            .filter(|name| claims.contains_key(name.as_str()))
            .count();
        println!(
            "local: {claimed_local} of {} rules carry a principle",
            installed.local.len()
        );
        for name in &installed.local {
            if !claims.contains_key(name.as_str()) {
                println!("  unclaimed  {name}");
            }
        }
    } else {
        println!("local: 0 of ? rules carry a principle");
        for note in &installed.unreadable {
            println!("  could not look  {note}");
        }
    }

    for note in &installed.how {
        println!("  note  {note}");
    }

    // Claims naming a rule nothing here supplies. Reported, not refused --
    // `uphold check` is where that is a failure.
    let orphans: Vec<&str> = claims
        .keys()
        .filter(|rule| !supply.supplied.contains_key(**rule))
        .copied()
        .collect();
    if !orphans.is_empty() {
        println!(
            "  claimed but supplied by nothing here: {}",
            orphans.join(", ")
        );
    }
    if !supply.unestablished.is_empty() {
        println!(
            "  declared, but no runner configuration here installs the seam it fires at: {}",
            supply.unestablished.join(", ")
        );
    }

    // The one number a reader takes away, computed from what a seam SUPPLIES
    // and not from what the declaration says. Counting the claims instead
    // reported a record as claimed by a rule here two lines under the line
    // saying that rule is supplied by nothing.
    let claimable = catalog::claimable_ids()?;
    let held: BTreeSet<&str> = declaration
        .enforce
        .iter()
        .filter(|claim| {
            claim
                .rule
                .as_deref()
                .is_some_and(|rule| supply.supplied.contains_key(rule))
        })
        .filter_map(|claim| claim.principle.as_deref())
        .collect();
    let counted = claimable.iter().filter(|id| held.contains(**id)).count();
    println!(
        "records: {counted} of {} claimable records are claimed by a rule here",
        claimable.len()
    );

    if installed.unreadable.is_empty() {
        Ok(Exit::Clean)
    } else {
        Ok(Exit::Broken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_naming_no_owner_or_no_repository_resolves_to_neither() {
        assert_eq!(
            slug_of("https://github.com/HackingGate/uphold.git"),
            Some(("HackingGate", "uphold"))
        );
        assert_eq!(
            slug_of("https://github.com/HackingGate/uphold/"),
            Some(("HackingGate", "uphold"))
        );
        // Half a slug is not a slug, and it takes BOTH of these to say so:
        // under `||` each of them resolves, and a consumer configuration would
        // be read as pinning a repository one half of whose name was never
        // established.
        assert_eq!(slug_of("/uphold"), None, "no owner");
        assert_eq!(slug_of("HackingGate/.git"), None, "no repository");
        // Nothing that could be a slug at all.
        assert_eq!(slug_of("uphold"), None);
    }

    #[test]
    fn a_text_scan_is_not_the_seam_a_content_rule_runs_at() {
        // `uphold scan --text` reads a message on stdin and establishes nothing
        // about the tree, so a repository that pins only that hook has not
        // installed the file scan -- and a claim on a content rule there is a
        // claim nothing supplies.
        let (scans, guards) = published().unwrap();
        assert!(scans.contains("uphold-scan"));
        assert!(!scans.contains("uphold-scan-text"));
        assert!(guards
            .values()
            .any(|hook| hook == "uphold-guard-commit-msg"));
    }

    #[test]
    fn a_lefthook_text_scan_is_not_the_file_scan_either() {
        // The same distinction as above, in the other reader, and it needs its
        // own test for the reason the two readers exist: `uphold scan --text`
        // judges a message on stdin and establishes nothing about the tree.
        // Counting it as the scan seam would reconcile a claim on a content
        // rule in a repository where no content rule runs.
        let root = std::env::temp_dir().join(format!(
            "uphold-check-lefthook-{}-{}",
            std::process::id(),
            line!()
        ));
        drop(std::fs::remove_dir_all(&root));
        std::fs::create_dir_all(&root).unwrap();

        // The real stage table: `lefthook_seams` only reads a top-level key
        // git knows as a hook, and an empty table here would make this test
        // pass by looking at nothing.
        let (_, guards) = published().unwrap();
        std::fs::write(
            root.join("lefthook.yml"),
            "commit-msg:\n  commands:\n    message:\n      run: uphold scan --text {1}\n",
        )
        .unwrap();
        assert!(
            !lefthook_seams(&root, &guards).unwrap().scan,
            "a --text scan is not the file scan"
        );

        std::fs::write(
            root.join("lefthook.yml"),
            "pre-commit:\n  commands:\n    policy:\n      run: uphold scan\n",
        )
        .unwrap();
        let found = lefthook_seams(&root, &guards).unwrap();
        assert!(found.scan, "a plain scan is the file scan");
        // And the evidence line says how it was established. A reconcile that
        // passes should not pass for a reason the reader cannot see, so the
        // note counting the commands is part of the answer rather than
        // decoration -- inverted, it appears over a config that defines none
        // and disappears over one that does.
        let note = found.how.join(" ");
        assert!(note.contains("lefthook.yml defines 1 command(s)"), "{note}");

        std::fs::write(root.join("lefthook.yml"), "colors: false\n").unwrap();
        let bare = lefthook_seams(&root, &guards).unwrap();
        assert!(!bare.how.join(" ").contains("defines"), "{:?}", bare.how);
        drop(std::fs::remove_dir_all(&root));
    }

    #[test]
    fn a_run_line_nested_under_a_sequence_is_still_a_run_line() {
        // lefthook nests freely, and a `run:` under a list is a `run:`. Losing
        // the sequence arm would make a config read as declaring nothing --
        // which reconciles as "no seam here supplies it" over a repository
        // whose hooks are installed and running.
        let config: serde_yaml_ng::Value = serde_yaml_ng::from_str(
            "commands:\n  - first:\n      run: uphold scan\n  - second:\n      run: uphold guard --stage pre-commit\n",
        )
        .unwrap();
        let runs = runs_in(&config);
        assert_eq!(runs.len(), 2, "{runs:?}");
        assert!(runs.iter().any(|run| run.contains("scan")), "{runs:?}");
        assert!(runs.iter().any(|run| run.contains("guard")), "{runs:?}");
    }

    #[test]
    fn the_note_names_every_published_id_this_tree_pins() {
        // A reconcile that passes should not pass for a reason the reader
        // cannot see, so the note lists what was found. Under `&&` it lists
        // only ids that are a scan AND a guard, which is none of them, and the
        // note disappears while the answer stays green.
        let root = std::env::temp_dir().join(format!(
            "uphold-check-note-{}-{}",
            std::process::id(),
            line!()
        ));
        drop(std::fs::remove_dir_all(&root));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join(".pre-commit-config.yaml"),
            "repos:\n  - repo: https://github.com/HackingGate/uphold\n    rev: v1.1.1\n    hooks:\n      - id: uphold-scan\n      - id: uphold-guard-commit-msg\n  - repo: https://github.com/pre-commit/pre-commit-hooks\n    rev: v6.0.0\n    hooks:\n      - id: trailing-whitespace\n",
        )
        .unwrap();

        let found = installed(&root).unwrap();
        let note = found.how.join(" ");
        assert!(note.contains("uphold-scan"), "{note}");
        assert!(note.contains("uphold-guard-commit-msg"), "{note}");
        // And nothing else. The note is evidence about THIS binary's seams, so
        // a hook from anywhere else does not belong in it -- and naming
        // everything pinned would make the line say nothing, which is the
        // failure mode of a report that grows to cover its own uncertainty.
        assert!(!note.contains("trailing-whitespace"), "{note}");
        assert!(found.scan, "the scan hook is pinned here");
        // `local` is the other half and it IS everything pinned: a claim may
        // name a formatter or a linter, and those are rules that fire here.
        assert!(found.local.contains("trailing-whitespace"));
        // A tree that pins hooks -- any hooks -- has a runner configuration,
        // so it must not also be told there is none. Both halves decide that:
        // nothing of ours is installed AND nothing was found to say how.
        assert!(
            !found
                .how
                .iter()
                .any(|line| line.contains("no runner configuration here")),
            "{:?}",
            found.how
        );
        drop(std::fs::remove_dir_all(&root));

        // And the other side of it: a tree with no configuration at all hears
        // exactly that, which is the answer that keeps "nothing is installed"
        // apart from "everything passed".
        let bare = std::env::temp_dir().join(format!(
            "uphold-check-bare-{}-{}",
            std::process::id(),
            line!()
        ));
        drop(std::fs::remove_dir_all(&bare));
        std::fs::create_dir_all(&bare).unwrap();
        let empty = installed(&bare).unwrap();
        assert!(empty.nothing());
        // And the case between the two, which is what makes this an AND: a
        // tree that runs hooks, none of them ours. Nothing of this binary's is
        // installed -- so `nothing()` is true -- and the report already says
        // what WAS found, so adding "no runner configuration here" on top of
        // it would contradict the line above it.
        std::fs::write(
            bare.join("lefthook.yml"),
            "pre-commit:\n  commands:\n    fmt:\n      run: cargo fmt --check\n",
        )
        .unwrap();
        let others = installed(&bare).unwrap();
        assert!(others.nothing(), "none of ours is installed");
        assert!(
            !others
                .how
                .iter()
                .any(|line| line.contains("no runner configuration here")),
            "{:?}",
            others.how
        );
        assert!(
            others.how.iter().any(|line| line.contains("defines")),
            "{:?}",
            others.how
        );
        assert!(
            empty
                .how
                .iter()
                .any(|line| line.contains("no runner configuration here")),
            "{:?}",
            empty.how
        );
        drop(std::fs::remove_dir_all(&bare));
    }

    #[test]
    fn a_content_rule_in_a_tree_that_runs_no_scan_is_not_supplied_by_one() {
        // The `UNKNOWN -> PASS` shape, at the seam that decides it. A
        // repository can declare every content rule in the catalog and install
        // no scan, and the honest answer is that nothing supplies them --
        // reported as unestablished rather than credited to a seam that is not
        // there.
        let mut rule = crate::config::Rule::synthetic("no-shouting", crate::config::Check::Regexp);
        rule.regexp = Some(String::from("SHOUTING"));
        rule.files = Some(crate::config::Files::default());
        let policy = Policy {
            rules: vec![rule],
            ..Policy::default()
        };

        let absent = suppliers(&policy, &Installed::default());
        assert!(
            !absent.supplied.contains_key("no-shouting"),
            "{:?}",
            absent.supplied
        );
        assert!(
            absent
                .unestablished
                .iter()
                .any(|note| note.contains("no-shouting")),
            "{:?}",
            absent.unestablished
        );

        let present = suppliers(
            &policy,
            &Installed {
                scan: true,
                ..Installed::default()
            },
        );
        assert_eq!(
            present.supplied.get("no-shouting").map(Vec::as_slice),
            Some(["uphold scan".to_owned()].as_slice())
        );
    }

    #[test]
    fn nothing_installed_and_something_installed_are_different_answers() {
        // Every mutation of `Installed::nothing` survived a mutation run,
        // which is another way of saying nothing asked it anything. It decides
        // whether a reconcile says "no runner configuration here runs `uphold
        // scan` or `uphold guard`" -- the note a repository sees when its hooks
        // are not installed at all, which is the one state that looks exactly
        // like a clean reconcile from the outside.
        let mut installed = Installed::default();
        assert!(installed.nothing());

        installed.scan = true;
        assert!(!installed.nothing());

        let mut staged = Installed::default();
        staged.stages.insert(String::from("pre-push"));
        assert!(!staged.nothing());
    }
}
