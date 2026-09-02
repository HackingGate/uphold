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
    /// The fixtures `uphold probe` reads. Named here so that one file can hold
    /// both without either reader refusing the other's table.
    ///
    /// `deny_unknown_fields` is the reason this field has to exist rather than
    /// being ignored: it is what catches `waivee` and a misplaced `reason`, and
    /// it cannot tell a typo from a sibling feature's table unless the sibling
    /// is named. `probe`'s reader already names `waive` for the same reason;
    /// only this direction was missing, so adding the first `[[probe]]` to this
    /// repository's own `policy/hooks.toml` made `hooks --identity` exit 2 on
    /// it.
    #[serde(default, rename = "probe")]
    _probes: Vec<toml::Value>,
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

// ─── `uphold hooks --install`: the hooks git actually runs ───────────────────

/// The four hook files this command writes, and the line that marks them as
/// its own. A file without the marker was written by somebody, and somebody's
/// file is looked at and refused, never replaced.
const MARKER: &str = "Written by `uphold hooks --install`; the next install overwrites this file.";

const STAGES: [&str; 4] = ["pre-commit", "commit-msg", "pre-merge-commit", "pre-push"];

/// `uphold hooks --install [--runner prek|pre-commit] [--dir DIR]`
///
/// Writes the four guard-stage hook files into a TRACKED directory and points
/// `core.hooksPath` at it, so the hook git runs is reviewable in a diff and a
/// rerun of the runner's own `install` cannot quietly take its place.
///
/// The file that earns the inversion is `pre-push`. prek computes the pushed
/// range as `<local sha> --not --remotes` and, when that range comes back
/// empty, skips the whole pre-push stage -- `always_run: true` included.
/// Measured 2026-08-16, prek 0.3.13: a throwaway repository whose only
/// pre-push hook was a `local` entry with `always_run: true` ran it for a
/// range of one commit and skipped it, silently, for a range of none. An
/// empty range is the dangerous case, not the boring one: repointing `origin`
/// at somebody else's remote is a URL edit, not a commit, so the push that
/// publishes the entire history to the wrong place hands the runner a range
/// of zero commits. The pre-push file written here runs
/// `uphold guard --stage pre-push` unconditionally, BEFORE anything
/// downstream decides the push is uninteresting, and only then delegates.
///
/// One fleet carried this file by hand, byte-identical in ten trees, plus a
/// script whose whole job was to notice when a copy drifted. The other three
/// files are delegates: `core.hooksPath` makes git look for EVERY hook in the
/// named directory, so a directory holding only `pre-push` would silently
/// switch the other stages off -- the same defect the pre-push file closes.
pub(crate) fn install(root: &Path, runner: Option<&str>, directory: &str) -> Result<Exit> {
    let runner = match runner {
        Some("prek") => "prek",
        Some("pre-commit") => "pre-commit",
        Some("lefthook") => {
            return Err(Fatal::new(
                "lefthook installs and owns its own git hooks (`lefthook install`), and a \
                 `core.hooksPath` written here would displace them. This command wires prek \
                 and pre-commit",
            ))
        }
        Some(other) => {
            return Err(Fatal::new(format!(
                "unknown runner {other:?}; this writes hooks that delegate to prek or \
                 pre-commit"
            )))
        }
        // Which of the two is detected from PATH, not from the config: both
        // read the same .pre-commit-config.yaml, and the one that is installed
        // is the one the delegate must call.
        None => {
            if crate::probe::on_path("prek") {
                "prek"
            } else if crate::probe::on_path("pre-commit") {
                "pre-commit"
            } else {
                return Err(Fatal::new(
                    "neither prek nor pre-commit is on PATH, so a delegate written now \
                     could not be run. Install one, or name one with --runner",
                ));
            }
        }
    };

    let config = root.join(".pre-commit-config.yaml");
    if !config.is_file() {
        return Err(Fatal::new(
            "no .pre-commit-config.yaml here, so there is nothing for the written hooks \
             to delegate to",
        ));
    }
    // A hook type outside the four written here would be silently switched
    // off: `core.hooksPath` makes git look in one directory for every hook,
    // and a type with no file there is a hook that no longer fires.
    let text = crate::error::read_to_string(&config)?;
    let parsed: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&text).map_err(|error| Fatal::at(&config, error))?;
    if let Some(declared) = parsed
        .get("default_install_hook_types")
        .and_then(serde_yaml_ng::Value::as_sequence)
    {
        for declared_type in declared {
            let name = declared_type.as_str().unwrap_or_default();
            if !STAGES.contains(&name) {
                return Err(Fatal::new(format!(
                    "default_install_hook_types names {name:?}, and this command writes \
                     only {}. With core.hooksPath set, a hook type with no file in the \
                     directory is a hook git no longer runs -- which would switch \
                     {name:?} off while reading as an install that worked",
                    STAGES.join(", ")
                )));
            }
        }
    }

    // Somebody else's core.hooksPath is somebody else's decision. Equal is a
    // re-install; different is a question this command must not answer.
    let existing = git_config(root, "core.hooksPath")?;
    if let Some(existing) = existing.as_deref() {
        if existing != directory {
            return Err(Fatal::new(format!(
                "core.hooksPath is already {existing:?}, and overwriting it would take \
                 the hooks that directory holds out of git's path. Point --dir at it, or \
                 unset it first"
            )));
        }
    }

    let hooks_dir = root.join(directory);
    std::fs::create_dir_all(&hooks_dir).map_err(|error| Fatal::at(&hooks_dir, error))?;
    for stage in STAGES {
        let path = hooks_dir.join(stage);
        if path.exists() {
            let current = crate::error::read_to_string(&path)?;
            if !current.contains(MARKER) {
                return Err(Fatal::at(
                    &path,
                    "this file was not written by `uphold hooks --install`, and replacing \
                     a hook somebody wrote is not this command's call. Move it aside, or \
                     fold what it does into the runner's own config",
                ));
            }
        }
        let body = if stage == "pre-push" {
            pre_push_hook(runner, directory)
        } else {
            delegate_hook(runner, stage)
        };
        std::fs::write(&path, body).map_err(|error| Fatal::at(&path, error))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .map_err(|error| Fatal::at(&path, error))?;
        }
    }

    if existing.is_none() {
        let output = crate::shim::inner_tool("git")
            .args(["config", "core.hooksPath", directory])
            .current_dir(root)
            .output()
            .map_err(|error| Fatal::new(format!("could not run git config: {error}")))?;
        if !output.status.success() {
            return Err(Fatal::new(format!(
                "git config core.hooksPath failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
    }

    println!(
        "wrote {} into {directory}/ and pointed core.hooksPath at it.\n\
         Commit the directory: the hook git runs is now a tracked file, and a rerun of \
         `{runner} install` cannot take its place.",
        STAGES.join(", ")
    );
    Ok(Exit::Clean)
}

fn git_config(root: &Path, key: &str) -> Result<Option<String>> {
    let output = crate::shim::inner_tool("git")
        .args(["config", "--get", key])
        .current_dir(root)
        .output()
        .map_err(|error| Fatal::new(format!("could not run git config: {error}")))?;
    if !output.status.success() {
        return Ok(None);
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Ok((!value.is_empty()).then_some(value))
}

/// The arguments `hook-impl` takes, which differ between the two runners.
///
/// prek's generated shim passes `--script-version 4`; a prek that changes that
/// contract refuses this invocation with a usage error, which fails the hook
/// CLOSED -- a commit stopped by a version skew is recoverable, a stage that
/// silently stopped running is not.
fn impl_args(runner: &str) -> &'static str {
    match runner {
        "prek" => "--hook-dir \"$hook_dir\" --script-version 4",
        _ => "--config=.pre-commit-config.yaml --hook-dir \"$hook_dir\"",
    }
}

fn delegate_hook(runner: &str, stage: &str) -> String {
    format!(
        "#!/bin/sh\n\
         # {MARKER}\n\
         #\n\
         # A delegate, and the reason it exists is the pre-push file beside it.\n\
         # `core.hooksPath` points git at this directory, so git looks for EVERY hook\n\
         # here and nowhere else: a directory holding only `pre-push` would silently\n\
         # switch this stage off. `hook-impl` is what the shim `{runner} install`\n\
         # generates calls, so calling it from a tracked file means the hook git runs\n\
         # is reviewable in a diff, and nothing here depends on `{runner} install`\n\
         # having been run.\n\
         \n\
         set -e\n\
         \n\
         hook_dir=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\n\
         exec {runner} hook-impl {args} --hook-type={stage} -- \"$@\"\n",
        args = impl_args(runner),
    )
}

fn pre_push_hook(runner: &str, directory: &str) -> String {
    format!(
        "#!/bin/sh\n\
         # {MARKER}\n\
         #\n\
         # The push-destination guard, run by git itself, BEFORE anything downstream\n\
         # gets to decide that this push is uninteresting.\n\
         #\n\
         # Measured 2026-08-16, prek 0.3.13: prek computes the pushed range as\n\
         # `<local sha> --not --remotes` and, when that range comes back empty, skips\n\
         # the WHOLE pre-push stage -- `always_run: true` included. An empty range is\n\
         # the dangerous case, not the boring one: repointing `origin` at somebody\n\
         # else's remote is a URL edit, not a commit, so the push that publishes the\n\
         # entire history hands the runner a range of zero commits. The guard below\n\
         # runs first, unconditionally, and reads the destination off argv -- which is\n\
         # where git puts it, and which asking `git config` would answer with the very\n\
         # thing that was just changed.\n\
         \n\
         set -e\n\
         \n\
         hook_dir=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\n\
         remote_name=\"$1\"\n\
         remote_url=\"$2\"\n\
         \n\
         # git hands the ref lines to the hook on stdin, and both the guard and the\n\
         # runner want them. There is only one stdin, so it is read once and replayed.\n\
         ref_lines=\"$(cat)\"\n\
         \n\
         # A checkout where `uphold` is not on PATH is one where this hook cannot\n\
         # answer the question it exists to answer, and exiting 0 there is precisely\n\
         # the failure this file removes. {directory} is on no PATH by accident.\n\
         if ! command -v uphold >/dev/null 2>&1; then\n\
         \techo \"pre-push: uphold is not on PATH, so the push destination was not\" >&2\n\
         \techo \"checked and this push is refused rather than guessed at.\" >&2\n\
         \texit 2\n\
         fi\n\
         \n\
         printf '%s\\n' \"$ref_lines\" | uphold guard --stage pre-push \\\n\
         \t--remote \"$remote_name\" --remote-url \"$remote_url\"\n\
         \n\
         # Everything else this repository runs at pre-push, handed the same argv and\n\
         # the same ref lines.\n\
         if ! command -v {runner} >/dev/null 2>&1; then\n\
         \techo \"pre-push: {runner} is not on PATH, so the pre-push hooks that\" >&2\n\
         \techo \".pre-commit-config.yaml declares did not run.\" >&2\n\
         \texit 2\n\
         fi\n\
         \n\
         printf '%s\\n' \"$ref_lines\" | {runner} hook-impl {args} \\\n\
         \t--hook-type=pre-push -- \"$@\"\n",
        args = impl_args(runner),
    )
}
