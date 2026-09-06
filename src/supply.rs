//! `uphold supply-chain` -- origin, advisories, typosquats and workflow
//! security, in one run.
//!
//! Five external scanners, orchestrated: osv-scanner (known vulnerabilities
//! and reported-malicious packages), zizmor (workflow security), cargo-deny
//! (origin, advisories, bans, licenses), cargo-vet (has anyone looked at this
//! dependency) and guarddog (publisher identity and typosquats -- the half OSV
//! cannot reach, scoring an UNKNOWN package on how closely its name shadows a
//! popular one).
//!
//! It exists because seven repositories in one workspace carried this
//! orchestration as a ~100-line shell task, near-identical, and the copies had
//! already diverged: one grew a failure-output dump the others lack, so the
//! same red printed a reason on one machine and a bare FAILED on the rest.
//! The orchestration is one decision; seven transcriptions of it are seven
//! places for the next fix to miss.
//!
//! What this binary adds over the shell it replaces is the third answer. The
//! shell spelled "the scanner refused" and "the scanner is not installed" the
//! same way, exit 1 via `command not found`; here a tool that is not on PATH
//! is COULD NOT LOOK -- reported by name, never a pass, and exit 2 through the
//! one verdict ranking this crate has, so a machine missing a scanner blocks
//! exactly as loudly while saying what to install.
//!
//! What it deliberately does NOT do: parse any scanner's findings. Each tool's
//! exit code decides, its output is shown when it refuses, and the one filter
//! applied (cargo-deny's headline lines) drops classes that describe the
//! config rather than a dependency. A wrapper that re-judged findings would be
//! a second opinion nobody asked for, drifting from the tool it wraps. The one
//! thing read out of a scanner's OUTPUT is guarddog's own admission that a rule
//! did not run, which is not a finding and is the opposite of one.
//!
//! What the run looks at is a RANGE, not a tree. Every scanner here reaches the
//! network, and a push that changes no lockfile, manifest or workflow was
//! paying for all five: the whole-tree form is now `--all`, and the pre-push
//! form scans what the push actually changed. The range comes from the same
//! `runner::Source` the pre-push guard reads, so there is one reader of what a
//! push is; no range and no flag is exit 2 rather than a fall-through to the
//! working tree, for the reason the guard refuses an absent source.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{verdict, Exit, Fatal, Result};

/// The zizmor policy run where the repository has none of its own.
const ZIZMOR_DEFAULT: &str = include_str!("../policy/zizmor.default.yml");

/// Directory names never descended into. The same list every copy of the
/// shell task carried: build output, vendored trees and upstream imports are
/// somebody else's manifests, and scanning them reports somebody else's
/// backlog.
const PRUNE: [&str; 5] = ["target", "node_modules", ".git", "vendor", "upstream"];

/// What one section established.
enum Section {
    /// Ran and found nothing to refuse.
    Clean,
    /// Ran and refused; the reason was already printed.
    Failed,
    /// Could not run -- a missing tool, an enumeration that errored. Never a
    /// pass, and never spelled like a refusal.
    CouldNotLook(String),
    /// Nothing here for this section to read. Said out loud, because "no
    /// manifests found" and "checked and clean" must never look the same.
    Nothing(String),
}

/// One section: its banner, and the function that runs it.
type SectionRun = (&'static str, fn(&Path, &Scope) -> Result<Section>);

/// The file names a scanner here reads. Everything else in a diff -- source,
/// documentation, a test fixture -- changes nothing any of these five tools
/// would answer differently, so a range holding only those is a range with
/// nothing to scan rather than a range nobody scanned.
const MANIFEST_NAMES: [&str; 6] = [
    "Cargo.toml",
    "Cargo.lock",
    "uv.lock",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
];

/// The subset osv-scanner is handed by path. A manifest without a lock beside
/// it resolves to nothing pinned, and `-L` on one is a scan of a wish list.
const LOCK_NAMES: [&str; 3] = ["Cargo.lock", "uv.lock", "package-lock.json"];

/// What this run was asked to look at.
///
/// `Changed` carries paths relative to the root, submodule members included and
/// prefixed by their submodule path, because that is how every section names
/// what it read.
pub(crate) enum Scope {
    /// Every manifest in the tree -- `--all`, and what this command did before
    /// there was a range.
    Whole,
    /// What one range changed, filtered to the names above.
    Changed(Vec<PathBuf>),
}

/// `uphold supply-chain`
pub(crate) fn run(root: &Path, scope: &Scope) -> Result<Exit> {
    if let Scope::Changed(paths) = scope {
        if paths.is_empty() {
            println!(
                "supply chain: nothing in this range that a scanner reads -- no lockfile, \
                 manifest or workflow changed"
            );
            return Ok(Exit::Clean);
        }
    }
    let mut failed = 0_usize;
    let mut unread = 0_usize;
    let sections: [SectionRun; 5] = [
        (
            "OSV -- known vulnerabilities and reported-malicious packages",
            osv,
        ),
        ("zizmor -- workflow security", zizmor),
        ("cargo-deny -- origin, advisories, bans, licenses", deny),
        ("cargo-vet -- has anyone looked at this dependency", vet),
        ("guarddog -- publisher identity and typosquats", guarddog),
    ];
    for (title, section) in sections {
        println!("\n== {title}");
        match section(root, scope)? {
            Section::Clean => {}
            Section::Failed => {
                failed += 1;
                println!("   FAILED");
            }
            Section::CouldNotLook(reason) => {
                unread += 1;
                eprintln!("   NOT CHECKED: {reason}");
            }
            Section::Nothing(reason) => println!("   {reason}"),
        }
    }
    println!();
    let exit = verdict(failed, unread);
    match exit {
        Exit::Clean => println!("supply chain: all checks passed"),
        Exit::Violations => println!("supply chain: FAILED -- see the sections marked above"),
        Exit::Broken => println!(
            "supply chain: {unread} check(s) could not look, which is not a pass -- see the \
             sections marked NOT CHECKED"
        ),
    }
    Ok(exit)
}

fn on_path(tool: &str) -> Option<String> {
    if crate::probe::on_path(tool) {
        None
    } else {
        Some(format!("{tool} is not on PATH, so this was not checked"))
    }
}

/// Run one tool, show what it said when it refused, answer by exit code.
///
/// A tool that died on a signal answered nothing, and nothing is could-not-
/// look rather than either verdict.
fn tool(root: &Path, program: &str, args: &[&str]) -> Result<Section> {
    if let Some(reason) = on_path(program) {
        return Ok(Section::CouldNotLook(reason));
    }
    let output = Command::new(program)
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| Fatal::new(format!("could not run {program}: {error}")))?;
    let Some(code) = output.status.code() else {
        return Ok(Section::CouldNotLook(format!(
            "{program} was killed and gave no verdict"
        )));
    };
    if code == 0 {
        return Ok(Section::Clean);
    }
    for line in String::from_utf8_lossy(&output.stdout)
        .lines()
        .chain(String::from_utf8_lossy(&output.stderr).lines())
    {
        println!("   {line}");
    }
    Ok(Section::Failed)
}

/// Every file of one name under the root, with the prune list applied.
///
/// "It failed" is kept distinct from "it found nothing": an unreadable
/// directory poisons the enumeration rather than shrinking it, because a scan
/// that looked at part of a tree and reported on all of it is the shape this
/// repository exists to refuse.
fn find_named(root: &Path, name: &str) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let walk = ignore::WalkBuilder::new(root)
        .standard_filters(false)
        .filter_entry(|entry| {
            entry
                .file_name()
                .to_str()
                .is_none_or(|file| !PRUNE.contains(&file))
        })
        .build();
    for entry in walk {
        let entry = entry.map_err(|error| {
            Fatal::new(format!(
                "could not enumerate the tree looking for {name}: {error}. A scan that \
                 looked at part of the tree must not report on all of it"
            ))
        })?;
        if entry.file_name().to_str() == Some(name)
            && entry.file_type().is_some_and(|kind| kind.is_file())
        {
            found.push(entry.into_path());
        }
    }
    found.sort();
    Ok(found)
}

/// Is this a path one of the five scanners would read?
///
/// The two halves are the whole filter: a manifest or lock by name at any
/// depth, and any file under a `.github/workflows` directory. A path that is
/// neither changes nothing any scanner here would answer differently.
fn interesting(path: &Path) -> bool {
    let named = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| MANIFEST_NAMES.contains(&name));
    named || is_workflow(path)
}

/// A file inside a `.github/workflows` directory, at any depth.
fn is_workflow(path: &Path) -> bool {
    let parts: Vec<&std::ffi::OsStr> = path.iter().collect();
    parts.windows(3).any(|window| {
        window.first() == Some(&".github".as_ref()) && window.get(1) == Some(&"workflows".as_ref())
    })
}

/// The scope of one or more ranges, submodule pointers expanded.
///
/// A range whose start is the all-zero id is a branch the remote does not have,
/// and there is no ancestor to diff against: that widens to every manifest and
/// says so, because the alternative is scanning nothing for the one push that
/// introduces everything.
pub(crate) fn scope_for_ranges(root: &Path, ranges: &[(String, String)]) -> Result<Scope> {
    let mut changed = BTreeSet::new();
    for (from, to) in ranges {
        // A deleted ref pushes no content. Nothing arrives, so nothing is
        // scanned; the range would not even parse.
        if is_zero(to) {
            continue;
        }
        if is_zero(from) {
            println!(
                "   a branch the remote does not have: no ancestor to diff against, so every \
                 manifest is in scope"
            );
            return Ok(Scope::Whole);
        }
        collect_range(root, Path::new(""), from, to, &mut changed)?;
    }
    Ok(Scope::Changed(changed.into_iter().collect()))
}

/// The same, from git's pre-push ref lines.
///
/// The line is `<local-ref> <local-sha> <remote-ref> <remote-sha>`, and the
/// range being pushed runs from the remote's sha to the local one. Parsed here
/// rather than anywhere new because `runner` already reassembles a runner's
/// environment INTO that shape, so both channels reach one parser.
pub(crate) fn scope_for_push(root: &Path, refs: &str) -> Result<Scope> {
    let mut ranges = Vec::new();
    for line in refs.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if let [_local_ref, local_sha, _remote_ref, remote_sha] = fields[..] {
            ranges.push(((*remote_sha).to_owned(), (*local_sha).to_owned()));
        }
    }
    scope_for_ranges(root, &ranges)
}

/// git's all-zero object id, in either of the lengths git writes it in.
fn is_zero(sha: &str) -> bool {
    !sha.is_empty() && sha.chars().all(|character| character == '0')
}

/// What one range changed under `prefix`, recursing through submodule pointers.
fn collect_range(
    root: &Path,
    prefix: &Path,
    from: &str,
    to: &str,
    out: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    let directory = root.join(prefix);
    let range = format!("{from}..{to}");
    for line in crate::git::run(
        &directory,
        &["diff", "--name-only", "--diff-filter=ACMR", &range],
    )?
    .lines()
    {
        let path = prefix.join(line);
        if interesting(&path) {
            out.insert(path);
        }
    }

    // A gitlink is a pointer, and the pointer is the only thing the
    // superproject's diff shows. `--raw` is where the two shas it moved between
    // are written down; without them a bumped submodule reads as one changed
    // file called `sub`, which no scanner reads, and a member's new lockfile is
    // never looked at.
    for line in crate::git::run(&directory, &["diff", "--raw", &range])?.lines() {
        let Some((meta, path)) = line.split_once('\t') else {
            continue;
        };
        let fields: Vec<&str> = meta.split_whitespace().collect();
        let [source_mode, destination_mode, old, new, ..] = fields[..] else {
            continue;
        };
        if source_mode != ":160000" && destination_mode != "160000" {
            continue;
        }
        let submodule = prefix.join(path);
        expand_gitlink(root, &submodule, old, new, out)?;
    }
    Ok(())
}

/// One moved submodule pointer, read inside the submodule.
///
/// Three answers, and the difference between them is the point. The store has
/// both commits: diff them, and the members' own manifests are in scope. The
/// store has neither or only one -- a shallow clone, a fetch nobody ran -- and
/// the range cannot be read, so every manifest under it is, which is the
/// widening a scan must take when it cannot narrow. Not checked out at all is
/// neither: there is no tree to widen INTO, and reporting on a submodule whose
/// files are absent is the "looked at part of it, reported on all of it" shape
/// this crate exists to refuse.
fn expand_gitlink(
    root: &Path,
    submodule: &Path,
    old: &str,
    new: &str,
    out: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    let directory = root.join(submodule);
    if directory.join(".git").symlink_metadata().is_err() {
        return Err(Fatal::new(format!(
            "the submodule {} moved in this range and is not checked out, so its manifests \
             cannot be read. Run `git submodule update --init {}`, or scan the whole tree \
             with `uphold supply-chain --all`",
            submodule.display(),
            submodule.display()
        )));
    }
    let has = |sha: &str| -> Result<bool> {
        if is_zero(sha) {
            return Ok(false);
        }
        Ok(crate::git::try_run(
            &directory,
            &["cat-file", "-e", &format!("{sha}^{{commit}}")],
        )?
        .is_some())
    };
    if has(old)? && has(new)? {
        return collect_range(root, submodule, old, new, out);
    }
    println!(
        "   {} moved to a commit its object store does not have, so every manifest under it \
         is in scope",
        submodule.display()
    );
    widen_into(root, submodule, out)
}

/// Every manifest and workflow file under one directory, as root-relative paths.
fn widen_into(root: &Path, prefix: &Path, out: &mut BTreeSet<PathBuf>) -> Result<()> {
    let directory = root.join(prefix);
    let walk = ignore::WalkBuilder::new(&directory)
        .standard_filters(false)
        .filter_entry(|entry| {
            entry
                .file_name()
                .to_str()
                .is_none_or(|file| !PRUNE.contains(&file))
        })
        .build();
    for entry in walk {
        let entry = entry.map_err(|error| {
            Fatal::new(format!(
                "could not enumerate {} for the manifests in scope: {error}. A scan that \
                 looked at part of the tree must not report on all of it",
                prefix.display()
            ))
        })?;
        if !entry.file_type().is_some_and(|kind| kind.is_file()) {
            continue;
        }
        let Ok(relative) = entry.path().strip_prefix(root) else {
            continue;
        };
        if interesting(relative) {
            out.insert(relative.to_path_buf());
        }
    }
    Ok(())
}

/// The changed paths carrying one of these names, as absolute paths.
fn selected(root: &Path, paths: &[PathBuf], names: &[&str]) -> Vec<PathBuf> {
    paths
        .iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| names.contains(&name))
        })
        .map(|path| root.join(path))
        .collect()
}

/// The directories those paths sit in, each named once.
fn directories_of(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = paths
        .iter()
        .filter_map(|path| path.parent().map(Path::to_path_buf))
        .collect();
    found.sort();
    found.dedup();
    found
}

fn osv(root: &Path, scope: &Scope) -> Result<Section> {
    if let Scope::Changed(paths) = scope {
        let locks = selected(root, paths, &LOCK_NAMES);
        if locks.is_empty() {
            return Ok(Section::Nothing(String::from("no lockfile in this range")));
        }
        // By path, and no exclude globs: the globs exist to keep a tree walk out
        // of somebody else's vendored manifests, and there is no walk here --
        // every path was named by the diff.
        let mut args = vec![
            String::from("scan"),
            String::from("source"),
            String::from("--allow-no-lockfiles"),
        ];
        for lock in &locks {
            args.push(String::from("-L"));
            args.push(lock.display().to_string());
        }
        println!("   {} lockfile(s) in this range", locks.len());
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        return tool(root, "osv-scanner", &borrowed);
    }
    tool(
        root,
        "osv-scanner",
        &[
            "scan",
            "source",
            "-r",
            "--allow-no-lockfiles",
            // Glob form, not a bare directory name: a bare name is matched
            // against a full path, so `upstream` several levels down was
            // silently not excluded by it.
            "--experimental-exclude",
            "g:**/target/**",
            "--experimental-exclude",
            "g:**/node_modules/**",
            "--experimental-exclude",
            "g:**/vendor/**",
            "--experimental-exclude",
            "g:**/upstream/**",
            ".",
        ],
    )
}

fn zizmor(root: &Path, scope: &Scope) -> Result<Section> {
    let (workflows, unit) = match scope {
        Scope::Whole => (find_workflow_dirs(root)?, "workflow directories"),
        // The changed files themselves, not their directory: zizmor reports per
        // workflow, and handing it the directory would print the whole
        // directory's backlog for one edited file.
        Scope::Changed(paths) => (
            paths
                .iter()
                .filter(|path| is_workflow(path))
                .map(|path| root.join(path))
                .collect(),
            "workflow file(s) in this range",
        ),
    };
    if workflows.is_empty() {
        return Ok(Section::Nothing(String::from(match scope {
            Scope::Whole => "no workflows here",
            Scope::Changed(_) => "no workflow changed in this range",
        })));
    }
    if let Some(reason) = on_path("zizmor") {
        return Ok(Section::CouldNotLook(reason));
    }
    println!("   {} {unit}", workflows.len());
    // `--config` named explicitly: zizmor resolves it relative to a single
    // input path and finds none when handed several, then silently falls back
    // to its hash-pin default and invents a backlog. The repository's own
    // zizmor.yml wins; the bundled default answers where there is none, which
    // retires the byte-identical copy six repositories carried.
    let own = root.join("zizmor.yml");
    let (config, _kept): (PathBuf, Option<tempfile_guard::TempFile>) = if own.is_file() {
        (own, None)
    } else {
        let written = tempfile_guard::TempFile::containing(ZIZMOR_DEFAULT)?;
        (written.path.clone(), Some(written))
    };
    let mut args: Vec<String> = vec![
        String::from("--config"),
        config.display().to_string(),
        String::from("--persona=regular"),
        String::from("--no-progress"),
    ];
    args.extend(workflows.iter().map(|path| path.display().to_string()));
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    tool(root, "zizmor", &borrowed)
}

fn find_workflow_dirs(root: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let walk = ignore::WalkBuilder::new(root)
        .standard_filters(false)
        .filter_entry(|entry| {
            entry
                .file_name()
                .to_str()
                .is_none_or(|file| !PRUNE.contains(&file))
        })
        .build();
    for entry in walk {
        let entry = entry.map_err(|error| {
            Fatal::new(format!("could not enumerate workflow directories: {error}"))
        })?;
        if entry.file_type().is_some_and(|kind| kind.is_dir())
            && entry.path().ends_with(".github/workflows")
        {
            found.push(entry.into_path());
        }
    }
    found.sort();
    Ok(found)
}

fn deny(root: &Path, scope: &Scope) -> Result<Section> {
    let config = root.join("deny.toml");
    if !config.is_file() {
        return Ok(Section::Nothing(String::from(
            "no deny.toml at the root (write one to opt in)",
        )));
    }
    if let Some(reason) = on_path("cargo") {
        return Ok(Section::CouldNotLook(reason));
    }
    let manifests = match scope {
        Scope::Whole => find_named(root, "Cargo.toml")?,
        // A lock maps to the manifest beside it: cargo-deny is pointed at a
        // manifest, and a `Cargo.lock` that moved is exactly the dependency
        // change this section exists to read.
        Scope::Changed(paths) => {
            let mut found: Vec<PathBuf> =
                directories_of(&selected(root, paths, &["Cargo.toml", "Cargo.lock"]))
                    .into_iter()
                    .map(|directory| directory.join("Cargo.toml"))
                    .filter(|manifest| manifest.is_file())
                    .collect();
            found.sort();
            found
        }
    };
    let mut checked = 0_usize;
    let mut refused = false;
    for manifest in manifests {
        // Only crate and workspace roots. A member's Cargo.toml is checked
        // through its workspace, and handing it to cargo-deny alone repeats
        // the workspace's findings once per member.
        let text = std::fs::read_to_string(&manifest).unwrap_or_default();
        if !text
            .lines()
            .any(|line| line == "[workspace]" || line == "[package]")
        {
            continue;
        }
        checked += 1;
        let output = Command::new("cargo")
            .args(["deny", "--config"])
            .arg(&config)
            .arg("--manifest-path")
            .arg(&manifest)
            .args(["--all-features", "check"])
            .current_dir(root)
            .output()
            .map_err(|error| Fatal::new(format!("could not run cargo deny: {error}")))?;
        if output.status.success() {
            continue;
        }
        if output.status.code() == Some(127) || output.status.code().is_none() {
            return Ok(Section::CouldNotLook(String::from(
                "cargo deny could not run (is cargo-deny installed?)",
            )));
        }
        refused = true;
        // HEADLINES ONLY, and the exit code decides. Grepping for `warning[`
        // once reported cargo-deny's own informational warnings as failures,
        // and keeping every indented detail line printed four lines of ASCII
        // art per unused allow-list entry. The four classes dropped describe
        // deny.toml rather than a dependency.
        for line in String::from_utf8_lossy(&output.stdout)
            .lines()
            .chain(String::from_utf8_lossy(&output.stderr).lines())
        {
            let headline = line.starts_with("error[") || line.starts_with("warning[");
            let config_noise = [
                "license-not-encountered",
                "unmatched-organization",
                "unmatched-source",
                "advisory-not-detected",
            ]
            .iter()
            .any(|class| line.contains(class));
            if headline && !config_noise {
                println!("   {}: {line}", manifest.display());
            }
        }
        println!("   FAILED: cargo-deny: {}", manifest.display());
    }
    println!("   {checked} crate(s) checked");
    if refused {
        return Ok(Section::Failed);
    }
    if checked == 0 {
        return Ok(Section::Nothing(String::from(match scope {
            Scope::Whole => "a deny.toml and no crate to hold to it",
            Scope::Changed(_) => "no crate manifest or lock moved in this range",
        })));
    }
    Ok(Section::Clean)
}

fn vet(root: &Path, scope: &Scope) -> Result<Section> {
    // Conditional on the store existing: a vet store carries an exemption for
    // every dependency present the day it was created, and creating one
    // automatically in every member would produce stores nobody owns.
    // `cargo vet init` is how a crate opts in.
    if !root.join("supply-chain").is_dir() {
        return Ok(Section::Nothing(String::from(
            "no supply-chain/ store here (cargo vet init to opt in)",
        )));
    }
    // The store answers one question -- has anyone looked at these dependencies
    // -- and the answer can only change when the resolved set does. That is a
    // `Cargo.lock` moving; a manifest edit that did not relock changed nothing
    // vet reads.
    if let Scope::Changed(paths) = scope {
        if selected(root, paths, &["Cargo.lock"]).is_empty() {
            return Ok(Section::Nothing(String::from(
                "no Cargo.lock moved in this range",
            )));
        }
    }
    tool(root, "cargo", &["vet", "--locked"])
}

/// Metadata rules only: the source-code rules download every release, which
/// is a different job for a different schedule.
const GUARDDOG_RULES: [&str; 10] = [
    "-r",
    "typosquatting",
    "-r",
    "deceptive_author",
    "-r",
    "unclaimed_maintainer_email_domain",
    "-r",
    "potentially_compromised_email_domain",
    "-r",
    "metadata_mismatch",
];

/// guarddog's own report that a rule did not run.
///
/// It prints "Some rules failed to run while scanning <package>:" and a bullet
/// per rule, then EXITS 0 -- the two email-domain rules time out routinely, and
/// an orchestrator reading only the exit code files that under "clean". A rule
/// that timed out is a question nobody answered, which is the could-not-look
/// verdict and not the pass. The one line returned names the packages and how
/// many rules, because "guarddog was inconclusive" with no subject is a red
/// nobody can act on.
fn rules_that_did_not_run(output: &str) -> Option<String> {
    let mark = "failed to run rule";
    let scanning = "rules failed to run while scanning ";
    let mut rules = 0_usize;
    let mut packages: Vec<String> = Vec::new();
    for line in output.lines() {
        if let Some((_, tail)) = line.split_once(scanning) {
            let package = tail.trim().trim_end_matches(':').trim();
            if !package.is_empty() && !packages.iter().any(|held| held == package) {
                packages.push(package.to_owned());
            }
        }
        if line.contains(mark) {
            rules += 1;
        }
    }
    if rules == 0 {
        return None;
    }
    let named = if packages.is_empty() {
        String::from("a package it did not name")
    } else if packages.len() > 3 {
        format!(
            "{} and {} more",
            packages
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<String>>()
                .join(", "),
            packages.len() - 3
        )
    } else {
        packages.join(", ")
    };
    Some(format!(
        "guarddog left {rules} rule(s) unrun on {named}, and still exited 0 -- a rule that \
         did not run answered nothing"
    ))
}

fn guarddog(root: &Path, scope: &Scope) -> Result<Section> {
    let (python, npm) = match scope {
        Scope::Whole => (
            find_named(root, "uv.lock")?,
            find_named(root, "package.json")?,
        ),
        // A directory, not a file: guarddog is run with the working directory
        // set to the manifest's own, and `pyproject.toml` moving is a dependency
        // change whether or not the lock moved with it.
        Scope::Changed(paths) => (
            directories_of(&selected(root, paths, &["uv.lock", "pyproject.toml"]))
                .into_iter()
                .map(|directory| directory.join("uv.lock"))
                .collect(),
            selected(root, paths, &["package.json"]),
        ),
    };
    if python.is_empty() && npm.is_empty() {
        return Ok(Section::Nothing(String::from(match scope {
            Scope::Whole => "no Python or npm manifests here",
            Scope::Changed(_) => "no Python or npm manifest moved in this range",
        })));
    }
    if let Some(reason) = on_path("guarddog") {
        return Ok(Section::CouldNotLook(reason));
    }
    let mut refused = false;
    let mut unrun: Option<String> = None;
    let mut checked = 0_usize;
    for lock in python {
        let directory = lock.parent().unwrap_or(root);
        checked += 1;
        if on_path("uv").is_some() {
            return Ok(Section::CouldNotLook(String::from(
                "uv is not on PATH, so the Python manifests were not exported for guarddog",
            )));
        }
        let exported = Command::new("uv")
            .args([
                "export",
                "--no-hashes",
                "--no-dev",
                "--format",
                "requirements-txt",
            ])
            .current_dir(directory)
            .output()
            .map_err(|error| Fatal::new(format!("could not run uv export: {error}")))?;
        if !exported.status.success() {
            println!(
                "   FAILED: guarddog: uv export failed in {}",
                directory.display()
            );
            refused = true;
            continue;
        }
        let requirements =
            tempfile_guard::TempFile::containing(&String::from_utf8_lossy(&exported.stdout))?;
        let status = Command::new("guarddog")
            .args(["pypi", "verify"])
            .arg(&requirements.path)
            .args(GUARDDOG_RULES)
            .current_dir(directory)
            .output()
            .map_err(|error| Fatal::new(format!("could not run guarddog: {error}")))?;
        unrun = unrun.or_else(|| rules_that_did_not_run(&String::from_utf8_lossy(&status.stdout)));
        if !status.status.success() {
            println!("   FAILED: guarddog pypi: {}", directory.display());
            refused = true;
        }
    }
    for manifest in npm {
        let directory = manifest.parent().unwrap_or(root);
        checked += 1;
        let status = Command::new("guarddog")
            .args(["npm", "verify", "package.json"])
            .args(GUARDDOG_RULES)
            .current_dir(directory)
            .output()
            .map_err(|error| Fatal::new(format!("could not run guarddog: {error}")))?;
        unrun = unrun.or_else(|| rules_that_did_not_run(&String::from_utf8_lossy(&status.stdout)));
        if !status.status.success() {
            println!("   FAILED: guarddog npm: {}", directory.display());
            refused = true;
        }
    }
    println!("   {checked} Python/npm manifest(s) checked");
    // A finding outranks an unrun rule, which is this crate's own ranking: a
    // refusal is something somebody looked at and objected to. The unrun rules
    // are printed either way, so the red that does appear says what was
    // still not asked.
    if let Some(ref reason) = unrun {
        println!("   {reason}");
    }
    if refused {
        return Ok(Section::Failed);
    }
    if let Some(reason) = unrun {
        return Ok(Section::CouldNotLook(reason));
    }
    Ok(Section::Clean)
}

/// A file that exists for one child process and is removed on the way out.
///
/// Hand-rolled rather than a crate, because this is the only place the binary
/// needs one and the contract is four lines: named, filled, handed to one
/// command, gone.
mod tempfile_guard {
    use std::path::PathBuf;

    use crate::error::{Fatal, Result};

    pub(super) struct TempFile {
        pub path: PathBuf,
    }

    impl TempFile {
        pub(super) fn containing(text: &str) -> Result<Self> {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "uphold-supply-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&path, text).map_err(|error| Fatal::at(&path, error))?;
            Ok(Self { path })
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            drop(std::fs::remove_file(&self.path));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{find_named, find_workflow_dirs, PRUNE};

    /// Paths under the fixture, as strings, so a failure names what was found.
    fn relative(root: &std::path::Path, found: &[std::path::PathBuf]) -> Vec<String> {
        found
            .iter()
            .map(|path| {
                path.strip_prefix(root)
                    .unwrap_or(path)
                    .display()
                    .to_string()
            })
            .collect()
    }

    /// The prune list decides what the run reports on, not how fast it is.
    ///
    /// A `Cargo.toml` under `vendor/` or `upstream/` is somebody else's
    /// manifest, and scanning it makes every run report a backlog nobody in
    /// this tree can act on. The same five names were carried by all seven
    /// copies of the shell task this replaces. `deep/vendor` is here because
    /// the name is matched at every level: the equivalent osv-scanner argument
    /// had to be spelled as a glob for exactly that reason, and a filter that
    /// only pruned at the root would leave this test the one thing that noticed.
    #[test]
    fn the_prune_list_keeps_vendored_and_generated_trees_out_of_the_enumeration() {
        let root = crate::fixture::scratch("supply-prune");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("Cargo.toml"), "[package]\n").unwrap();
        for directory in ["member", "deep/vendor"].iter().chain(PRUNE.iter()) {
            std::fs::create_dir_all(root.join(directory)).unwrap();
            std::fs::write(root.join(directory).join("Cargo.toml"), "[package]\n").unwrap();
        }

        assert_eq!(
            relative(&root, &find_named(&root, "Cargo.toml").unwrap()),
            ["Cargo.toml", "member/Cargo.toml"]
        );
    }

    /// A workflow directory is found wherever it sits, and never inside a
    /// pruned tree.
    ///
    /// zizmor is handed every directory at once, so one missed submodule is a
    /// workflow nobody ever scanned -- and one vendored copy is a finding
    /// nobody can fix. Both halves are the same enumeration.
    #[test]
    fn workflow_directories_are_found_at_any_depth_and_not_inside_a_pruned_tree() {
        let root = crate::fixture::scratch("supply-workflows");
        for directory in [".github/workflows", "sub/.github/workflows"] {
            std::fs::create_dir_all(root.join(directory)).unwrap();
        }
        std::fs::create_dir_all(root.join("vendor/.github/workflows")).unwrap();

        assert_eq!(
            relative(&root, &find_workflow_dirs(&root).unwrap()),
            [".github/workflows", "sub/.github/workflows"]
        );
    }

    /// A directory that cannot be read poisons the enumeration.
    ///
    /// The failure this refuses is the one the whole crate exists to refuse: an
    /// unreadable directory that merely SHRINKS the result gives a scan that
    /// looked at part of the tree and reported on all of it -- a clean run over
    /// manifests nobody read. It has to be an error, so the section is COULD
    /// NOT LOOK and the run exits 2.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_directory_fails_the_enumeration_rather_than_shrinking_it() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = crate::fixture::scratch("supply-unreadable");
        std::fs::create_dir_all(root.join("open")).unwrap();
        std::fs::write(root.join("open/Cargo.toml"), "[package]\n").unwrap();
        let locked = root.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        // Root reads everything, so on a machine where the fixture is readable
        // there is nothing here to prove; say so rather than assert a false
        // negative.
        let unreadable = std::fs::read_dir(&locked).is_err();
        let named = find_named(&root, "Cargo.toml");
        let workflows = find_workflow_dirs(&root);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();

        if !unreadable {
            return;
        }
        let named = named.unwrap_err().to_string();
        assert!(
            named.contains("could not enumerate the tree looking for Cargo.toml"),
            "{named}"
        );
        assert!(named.contains("must not report on all of it"), "{named}");
        let workflows = workflows.unwrap_err().to_string();
        assert!(
            workflows.contains("could not enumerate workflow directories"),
            "{workflows}"
        );
    }
}
