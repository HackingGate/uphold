//! `uphold hooks --identity` -- do a set of repositories declare the same hooks?
//!
//! Every other check here reads ONE repository. This one reads several, because
//! the question has no answer inside any of them: a hook declaration that has
//! forked is byte-perfect in each repository that holds it, and only the
//! comparison shows that the copies stopped agreeing. Nothing in a tree can
//! report a fork, which is why a fork is invisible to every other check this
//! binary has.
//!
//! Three findings, and they are three different failures:
//!
//! * **forked** -- one id, two declarations. Some repositories run a hook with
//!   `args:` the others do not have, or a different `entry:` under a name that
//!   claims to be the same check. A claim naming that id means one thing in one
//!   repository and another next door, and `uphold check` reconciles both green.
//! * **pinned apart** -- one id, one upstream, two revs. Every repository is
//!   running the check; they are running different versions of it, and the
//!   older one is missing whatever the newer one learned.
//! * **absent** -- an id most of the set declares and one does not. Not a
//!   defect on its own, which is why it is reported with the count and can be
//!   waived: a repository with no Go in it has no business declaring `gofmt`.
//!
//! WAIVERS, and why they carry a reason. `policy/hooks.toml` in the repository
//! this runs from holds them. A waiver with no reason is a check switched off
//! with nobody's name on it, so it is refused at load rather than accepted --
//! and a waiver that matches nothing is reported, because an exemption that no
//! longer describes the fleet reads as a decision that is doing something while
//! doing nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Exit, Fatal, Result};
use crate::pins::{declarations, Declaration, Manager};

const WAIVERS: &str = "policy/hooks.toml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Waivers {
    #[serde(default, rename = "waive")]
    waivers: Vec<Waiver>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Waiver {
    /// The hook id this is about.
    id: String,
    /// Why. Required: see the module note.
    reason: String,
    /// Which repositories, by the name this command calls them. Absent means
    /// every repository in the comparison.
    #[serde(default)]
    repos: Vec<String>,
    /// Which finding is waived: `forked`, `pinned-apart`, `absent`. Absent
    /// means all three, which is the blunt form and is why the field exists.
    #[serde(default)]
    findings: Vec<String>,
}

/// The three findings, named once.
///
/// A match arm over a string would have let a waiver name a finding that does
/// not exist and silently waive nothing -- an exemption that reads as switching
/// a check off while doing nothing at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Finding {
    Forked,
    PinnedApart,
    Absent,
}

impl Finding {
    const ALL: [Self; 3] = [Self::Forked, Self::PinnedApart, Self::Absent];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Forked => "forked",
            Self::PinnedApart => "pinned-apart",
            Self::Absent => "absent",
        }
    }
}

/// What makes two declarations the same declaration: one id, in one manager,
/// under one hook where the format puts the hook outside the entry.
type Where<'a> = (&'a str, Manager, Option<&'a str>);

/// One repository in the comparison: what to call it, and what it declares.
struct Read {
    name: String,
    path: PathBuf,
    declarations: Vec<Declaration>,
}

/// `uphold hooks --identity <path>...`
pub(crate) fn identity(root: &Path, paths: &[PathBuf]) -> Result<Exit> {
    if paths.len() < 2 {
        return Err(Fatal::new(
            "hooks --identity compares repositories against each other, so it needs at least \
             two. One repository's declarations are `uphold rules --effective`",
        ));
    }
    let waivers = waivers(root)?;

    let mut reads: Vec<Read> = Vec::new();
    for path in paths {
        // A path that is not a repository is could-not-look and not "declares
        // nothing": the second is a measurement, and it is the one that would
        // report a fleet in agreement over a directory nobody read.
        if !path.join(".git").exists() {
            return Err(Fatal::at(
                path,
                "is not a git repository, so what it declares could not be read. A directory \
                 that declares nothing and one that could not be read are different answers",
            ));
        }
        let name = name_of(path);
        // The same repository twice agrees with itself, and a comparison that
        // agrees because it looked at one thing twice is the shape of answer
        // this tool exists to refuse.
        if let Some(seen) = reads.iter().find(|read| read.name == name) {
            return Err(Fatal::new(format!(
                "{} and {} are both called {:?}. Two repositories under one name cannot be \
                 told apart in a report, and the same repository twice agrees with itself",
                seen.path.display(),
                path.display(),
                name
            )));
        }
        reads.push(Read {
            name,
            path: path.clone(),
            declarations: declarations(path)?,
        });
    }

    let mut used: BTreeSet<usize> = BTreeSet::new();
    let mut findings: Vec<String> = Vec::new();

    // Every id anybody declares, and who declares it -- keyed by MANAGER as
    // well as by id. The same id in a `.pre-commit-config.yaml` and in a
    // `lefthook.yml` is one check written twice in two formats, which is what
    // supporting both runners means; comparing the two as one declaration makes
    // every repository that does it report itself as forked from itself.
    let mut everywhere: BTreeMap<Where<'_>, Vec<(&Read, &Declaration)>> = BTreeMap::new();
    for read in &reads {
        for declaration in &read.declarations {
            everywhere
                .entry((
                    declaration.id.as_str(),
                    declaration.manager,
                    declaration.stage.as_deref(),
                ))
                .or_default()
                .push((read, declaration));
        }
    }

    // Which repositories declare an id at all, in either manager. The absent
    // finding is about the CHECK rather than about the file it is written in.
    let mut anywhere: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for read in &reads {
        for declaration in &read.declarations {
            anywhere
                .entry(declaration.id.as_str())
                .or_default()
                .insert(read.name.as_str());
        }
    }

    for ((id, manager, stage), holders) in &everywhere {
        // -- forked -------------------------------------------------------
        let mut bodies: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for (read, declaration) in holders {
            bodies
                .entry(declaration.body.as_str())
                .or_default()
                .push(read.name.as_str());
        }
        if bodies.len() > 1
            && !waived(
                &waivers,
                id,
                Finding::Forked,
                &holders_named(holders),
                &mut used,
            )
        {
            let repositories: BTreeSet<&str> = holders_named(holders).into_iter().collect();
            let at = stage.map_or_else(String::new, |stage| format!(", at {stage}"));
            let mut report = format!(
                "forked: `{id}` is declared {} different ways across {} repositories ({}{at})",
                bodies.len(),
                repositories.len(),
                manager.as_str()
            );
            for (body, who) in &bodies {
                write!(report, "\n  {}:\n", who.join(", ")).ok();
                for line in body.lines() {
                    writeln!(report, "    {line}").ok();
                }
            }
            findings.push(report.trim_end().to_owned());
        }

        // -- pinned apart --------------------------------------------------
        let mut revs: BTreeMap<(&str, &str), Vec<&str>> = BTreeMap::new();
        for (read, declaration) in holders {
            if let (Some(from), Some(rev)) =
                (declaration.from.as_deref(), declaration.rev.as_deref())
            {
                revs.entry((from, rev))
                    .or_default()
                    .push(read.name.as_str());
            }
        }
        let upstreams: BTreeSet<&str> = revs.keys().map(|(from, _)| *from).collect();
        // One upstream, more than one rev. Two upstreams is not this finding:
        // repositories running an id from different sources are not running
        // two versions of one hook, they are running two hooks that share a
        // name, and that is the forked finding above.
        if upstreams.len() == 1
            && revs.len() > 1
            && !waived(
                &waivers,
                id,
                Finding::PinnedApart,
                &holders_named(holders),
                &mut used,
            )
        {
            let mut report = format!("pinned apart: `{id}` runs at different revisions");
            for ((from, rev), who) in &revs {
                write!(report, "\n  {rev} ({from}) in {}", who.join(", ")).ok();
            }
            findings.push(report);
        }
    }

    // -- absent ------------------------------------------------------------
    //
    // Reported per ID rather than per manager, and only where MOST of the set
    // declares it. "This repository has a hook the others do not" is the normal
    // state of a fleet -- a repository with no Go in it has no business
    // declaring `gofmt` -- and reporting every such id turns the answer into a
    // list nobody reads, which is the failure this whole tool is about. A
    // majority is the weakest statement of "the set says this belongs here"
    // that needs no second file to hold it; anything below it is one
    // repository's own business, and anything a majority holds and one lacks is
    // worth a sentence. `policy/hooks.toml` waives the rest.
    for (id, holders) in &anywhere {
        if holders.len() * 2 <= reads.len() {
            continue;
        }
        let missing: Vec<&str> = reads
            .iter()
            .filter(|read| !holders.contains(read.name.as_str()))
            .map(|read| read.name.as_str())
            .collect();
        if !missing.is_empty() && !waived(&waivers, id, Finding::Absent, &missing, &mut used) {
            findings.push(format!(
                "absent: `{id}` is declared in {} of {} repositories, and not in {}",
                holders.len(),
                reads.len(),
                missing.join(", ")
            ));
        }
    }

    println!(
        "read {} repositories, {} distinct hook id(s)",
        reads.len(),
        anywhere.len()
    );
    for read in &reads {
        println!(
            "  {}: {} declaration(s)",
            read.name,
            read.declarations.len()
        );
    }

    // A waiver that matched nothing, reported for the reason a stale
    // `disabled_rules` entry is: it reads as a decision that is doing something
    // and it is doing nothing, and it will keep reading that way after the
    // divergence it named is gone.
    let mut stale: Vec<String> = Vec::new();
    for (index, waiver) in waivers.iter().enumerate() {
        if !used.contains(&index) {
            stale.push(format!(
                "  {WAIVERS}: the waiver for `{}` matched no finding -- {}",
                waiver.id, waiver.reason
            ));
        }
    }
    if !stale.is_empty() {
        println!("waivers that no longer describe this fleet:");
        for line in &stale {
            println!("{line}");
        }
    }

    if findings.is_empty() {
        println!("every declaration agrees across every repository read");
        return Ok(Exit::Clean);
    }
    for finding in &findings {
        eprintln!("{finding}");
        eprintln!();
    }
    eprintln!(
        "{} divergence(s). A hook that has forked is byte-perfect in each repository that \
         holds it, so nothing inside any of them can report this.",
        findings.len()
    );
    Ok(Exit::Violations)
}

fn holders_named<'a>(holders: &[(&'a Read, &'a Declaration)]) -> Vec<&'a str> {
    holders.iter().map(|(read, _)| read.name.as_str()).collect()
}

/// What to call a repository in the report.
///
/// The directory name, which is what the operator typed and what they will look
/// for afterwards. Not the remote, which several of these may share, and not
/// the path, which makes every line as long as the deepest checkout.
///
/// Canonicalized first, or the repository somebody ran this from is called `.`
/// in every line of a report about six repositories.
fn name_of(path: &Path) -> String {
    let resolved = path.canonicalize();
    let named = resolved.as_deref().unwrap_or(path);
    named.file_name().map_or_else(
        || named.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    )
}

fn waivers(root: &Path) -> Result<Vec<Waiver>> {
    let path = root.join(WAIVERS);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = crate::error::read_to_string(&path)?;
    let parsed: Waivers = toml::from_str(&text).map_err(|error| Fatal::at(&path, error))?;
    for waiver in &parsed.waivers {
        if waiver.reason.trim().is_empty() {
            return Err(Fatal::at(
                &path,
                format!(
                    "the waiver for `{}` has an empty `reason`. A waiver with no reason is a \
                     check switched off with nobody's name on it",
                    waiver.id
                ),
            ));
        }
        for finding in &waiver.findings {
            if !Finding::ALL.iter().any(|kind| kind.as_str() == finding) {
                return Err(Fatal::at(
                    &path,
                    format!(
                        "the waiver for `{}` names the finding {finding:?}, which is not one \
                         of {}. A waiver naming a finding that does not exist waives nothing \
                         while reading as though it does",
                        waiver.id,
                        Finding::ALL
                            .iter()
                            .map(|kind| kind.as_str())
                            .collect::<Vec<&str>>()
                            .join(", ")
                    ),
                ));
            }
        }
    }
    Ok(parsed.waivers)
}

/// Is this finding waived, and by which waiver?
///
/// Records the waiver that answered, so a waiver nothing matched can be
/// reported afterwards.
fn waived(
    waivers: &[Waiver],
    id: &str,
    finding: Finding,
    repos: &[&str],
    used: &mut BTreeSet<usize>,
) -> bool {
    let mut answered = false;
    for (index, waiver) in waivers.iter().enumerate() {
        if waiver.id != id {
            continue;
        }
        if !waiver.findings.is_empty()
            && !waiver
                .findings
                .iter()
                .any(|named| named == finding.as_str())
        {
            continue;
        }
        // A waiver naming repositories covers the finding only when every
        // repository the finding is about is named. Half a divergence waived is
        // a divergence, and reporting it as waived would hide the half nobody
        // decided about.
        if !waiver.repos.is_empty()
            && !repos
                .iter()
                .all(|repo| waiver.repos.iter().any(|named| named == repo))
        {
            continue;
        }
        used.insert(index);
        answered = true;
    }
    answered
}
