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
//! a second opinion nobody asked for, drifting from the tool it wraps.

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
type SectionRun = (&'static str, fn(&Path) -> Result<Section>);

/// `uphold supply-chain`
pub(crate) fn run(root: &Path) -> Result<Exit> {
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
        match section(root)? {
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

fn osv(root: &Path) -> Result<Section> {
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

fn zizmor(root: &Path) -> Result<Section> {
    let workflows = find_workflow_dirs(root)?;
    if workflows.is_empty() {
        return Ok(Section::Nothing(String::from("no workflows here")));
    }
    if let Some(reason) = on_path("zizmor") {
        return Ok(Section::CouldNotLook(reason));
    }
    println!("   {} workflow directories", workflows.len());
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

fn deny(root: &Path) -> Result<Section> {
    let config = root.join("deny.toml");
    if !config.is_file() {
        return Ok(Section::Nothing(String::from(
            "no deny.toml at the root (write one to opt in)",
        )));
    }
    if let Some(reason) = on_path("cargo") {
        return Ok(Section::CouldNotLook(reason));
    }
    let manifests = find_named(root, "Cargo.toml")?;
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
        return Ok(Section::Nothing(String::from(
            "a deny.toml and no crate to hold to it",
        )));
    }
    Ok(Section::Clean)
}

fn vet(root: &Path) -> Result<Section> {
    // Conditional on the store existing: a vet store carries an exemption for
    // every dependency present the day it was created, and creating one
    // automatically in every member would produce stores nobody owns.
    // `cargo vet init` is how a crate opts in.
    if !root.join("supply-chain").is_dir() {
        return Ok(Section::Nothing(String::from(
            "no supply-chain/ store here (cargo vet init to opt in)",
        )));
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

fn guarddog(root: &Path) -> Result<Section> {
    let python = find_named(root, "uv.lock")?;
    let npm = find_named(root, "package.json")?;
    if python.is_empty() && npm.is_empty() {
        return Ok(Section::Nothing(String::from(
            "no Python or npm manifests here",
        )));
    }
    if let Some(reason) = on_path("guarddog") {
        return Ok(Section::CouldNotLook(reason));
    }
    let mut refused = false;
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
        if !status.status.success() {
            println!("   FAILED: guarddog npm: {}", directory.display());
            refused = true;
        }
    }
    println!("   {checked} Python/npm manifest(s) checked");
    if refused {
        Ok(Section::Failed)
    } else {
        Ok(Section::Clean)
    }
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
