//! `uphold supply-chain` -- origin, advisories, typosquats, workflow security
//! and committed secrets, in one run.
//!
//! Five external scanners over dependencies and workflows, orchestrated:
//! osv-scanner (known vulnerabilities and reported-malicious packages), zizmor
//! (workflow security), cargo-deny (origin, advisories, bans, licenses),
//! cargo-vet (has anyone looked at this dependency) and guarddog (publisher
//! identity and typosquats -- the half OSV cannot reach, scoring an UNKNOWN
//! package on how closely its name shadows a popular one).
//!
//! A sixth, gitleaks, reads commits rather than manifests, and owns secret
//! shapes: the token formats, entropy thresholds and allowlists the
//! `credentials` set's regexes approximated by hand. It runs only where the
//! policy inherits that set, and it is the one scanner here pinned to a
//! version, for the reason given at `GITLEAKS_VERSION`.
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
//! What it deliberately does NOT do: re-judge any scanner's findings. A tool's
//! verdict is its own, its output is shown when it refuses, and the one filter
//! applied (cargo-deny's headline lines) drops classes that describe the
//! config rather than a dependency. A wrapper that re-judged findings would be
//! a second opinion nobody asked for, drifting from the tool it wraps.
//!
//! ONE SCANNER'S FINDINGS ARE READ ANYWAY, and the exception is guarddog.
//! `guarddog verify` exits 0 whether it found three high-severity risks or
//! none, in both ecosystems, so for as long as this section answered by exit
//! code it called every guarddog finding clean -- a false negative on the one
//! scanner here that looks for malware. Its `--exit-non-zero-on-finding` flag
//! is not the remedy: it counts `issues`, which includes capability matches
//! guarddog itself scores 0.0 and labels `no_risks_detected`. So guarddog is
//! run with `--output-format json` and its own `risks` list is counted. The
//! count is reported, never recomputed; the choice is to parse it or to run it
//! for nothing. One named exception: a `metadata_mismatch` risk whose every
//! difference is a known npm rewrite or a verified `PyPI` optional extra is
//! printed as tolerated rather than counted.
//!
//! guarddog is also not handed what it cannot look up. A `uv export` spells a
//! git source, a direct URL and a path as a PEP 508 direct reference, and
//! guarddog asks `PyPI` for each by name and gets a 404. `references` sorts the
//! export first: a git source under the owner the policy declares is checked
//! against its own remote, and every other direct reference outside the tree
//! is refused by name rather than skipped.
//!
//! What IS read out of a scanner's output is the opposite of a finding: its
//! own admission that it did not look. Four of the five need it, because four
//! of the five cannot say so in their exit code. guarddog reports rules that
//! timed out and still exits 0; cargo-vet answers 255 both for an unvetted
//! dependency and for a store it could not open; cargo-deny's exit 1 is a
//! matched advisory or a database it could not fetch; and zizmor, handed one
//! unparseable workflow among good ones, skips it and exits 0. None of those
//! is a judgement about a dependency being re-judged here. Each is the record
//! that a question went unasked, which is this command's third verdict and the
//! reason it exists.
//!
//! THOSE READERS HAVE A FLOOR. Each was written by running one release of its
//! scanner, and a release old enough to print something else turns the
//! could-not-look it matches into whichever verdict the unmatched text falls
//! through to. So each scanner is asked its version before it runs, and one
//! older than its `Floor` -- or one whose version cannot be read -- is
//! could-not-look, the same shape as not on PATH. A floor, not a pin: the host
//! still supplies the scanner, and gitleaks alone is pinned, for its own reason.
//!
//! WHAT NOTHING HERE READS IS SAID OUT LOUD TOO. zizmor parses GitHub Actions
//! and nothing else, so a pipeline defined for any other vendor is read by no
//! scanner here -- an asymmetry of tooling, not preference: Actions is the CI
//! system somebody wrote a scanner for, and the defects are the same file to
//! file. The run prints those files rather than leaving the gap implicit in a
//! section list nobody enumerates.
//!
//! IT IS DECLARED RATHER THAN FILLED because the only candidate fails open.
//! checkov, the one scanner found that reads a CircleCI config, logs a YAML
//! parse error at debug level and exits 0, so a config it could not read comes
//! back indistinguishable from a clean one -- this command's third verdict
//! imported as a silent pass. Named here, not run.
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

use crate::config::{Policy, Waiver};
use crate::error::{Exit, Fatal, Result, verdict};

mod pypi;
mod references;

/// The zizmor policy run where the repository has none of its own.
const ZIZMOR_DEFAULT: &str = include_str!("../policy/zizmor.default.yml");

/// Directory names never descended into. The same list every copy of the
/// shell task carried: build output, vendored trees and upstream imports are
/// somebody else's manifests, and scanning them reports somebody else's
/// backlog.
const PRUNE: [&str; 5] = ["target", "node_modules", ".git", "vendor", "upstream"];

/// CI configuration no scanner here reads, by directory -- the whole of one
/// is pipeline definition. Named so the run can say the files went unscanned;
/// there is no scanner to point at them.
const UNSCANNED_CI_DIRS: [&str; 1] = [".circleci"];

/// The same by file name, for the vendors that put one pipeline in one file.
///
/// A list, not a pattern: `*.yml` at a repository root is a config file for
/// anything, and the declaration on files no CI runner reads is noise.
const UNSCANNED_CI_FILES: [&str; 4] = [
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    "azure-pipelines.yml",
    "Jenkinsfile",
];

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
type SectionRun<'a> = (&'static str, &'a dyn Fn(&Path, &Scope) -> Result<Section>);

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
    /// What the ranges changed, filtered to the names above, and the ranges
    /// themselves as `(from, to)` commit pairs. gitleaks reads commits rather
    /// than files, so it is handed the second; every other section reads the
    /// first.
    Changed(Vec<PathBuf>, Vec<(String, String)>),
}

/// The bundled set whose inheritance turns the gitleaks section on.
///
/// Gated on the set rather than run everywhere because a missing scanner is
/// exit 2: a repository that never asked for credential scanning would
/// otherwise have every push refused on a machine without gitleaks, on the
/// strength of an uphold bump.
pub(crate) const SECRETS_SET: &str = "credentials";

/// `uphold supply-chain`. `secrets` is whether the policy inherits
/// [`SECRETS_SET`].
///
/// `policy` is read by the guarddog section alone: its `[[supply_chain.waive]]`
/// entries, and the declared owner that decides which git dependencies are
/// first party. `nested` is read by that section too, and for the waivers
/// alone: see [`NestedPolicy`].
pub(crate) fn run(
    root: &Path,
    scope: &Scope,
    secrets: bool,
    policy: &Policy,
    nested: NestedPolicy<'_>,
) -> Result<Exit> {
    let manifests_moved = !matches!(scope, Scope::Changed(paths, _) if paths.is_empty());
    if !manifests_moved && !secrets {
        println!(
            "supply chain: nothing in this range that a scanner reads -- no lockfile, \
                 manifest or workflow changed"
        );
        return Ok(Exit::Clean);
    }
    let mut failed = 0_usize;
    let mut unread = 0_usize;
    let guarded = |at: &Path, over: &Scope| guarddog(at, over, policy, nested);
    let mut sections: Vec<SectionRun<'_>> = Vec::new();
    if manifests_moved {
        let dependencies: [SectionRun<'_>; 5] = [
            (
                "OSV -- known vulnerabilities and reported-malicious packages",
                &osv,
            ),
            ("zizmor -- workflow security", &zizmor),
            ("cargo-deny -- origin, advisories, bans, licenses", &deny),
            ("cargo-vet -- has anyone looked at this dependency", &vet),
            ("guarddog -- publisher identity and typosquats", &guarded),
        ];
        sections.extend(dependencies);
    } else {
        println!(
            "supply chain: no lockfile, manifest or workflow changed in this range, so only \
             gitleaks has anything to read"
        );
    }
    sections.push((
        "gitleaks -- committed secrets",
        if secrets {
            &gitleaks
        } else {
            &gitleaks_not_asked
        },
    ));
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

/// `uphold supply-chain --staged`: gitleaks alone, over the staged diff.
///
/// The pre-commit half of the secret scan. The range scan catches a secret at
/// pre-push, which is after it is in local history; a commit carrying one has
/// to be rewritten out, not just edited. gitleaks reads no network, so the
/// reason the other five sections stay off the commit path -- a round trip on
/// every commit -- is not a reason here, and they are not run: a commit moves
/// no pushed range, and their sweep is the push's job.
///
/// Gated on [`SECRETS_SET`] for the reason the range scan is: a missing
/// gitleaks is exit 2, and a policy that never asked for secret scanning must
/// not have every commit refused on a machine without it.
pub(crate) fn run_staged(root: &Path, secrets: bool) -> Result<Exit> {
    println!("== gitleaks -- secrets in the staged diff");
    let section = if !secrets {
        gitleaks_not_asked(root, &Scope::Whole)?
    } else if let Some(reason) = on_path("gitleaks").or_else(gitleaks_version_mismatch) {
        Section::CouldNotLook(reason)
    } else {
        gitleaks_passes(
            root,
            vec![(
                String::from("the staged diff"),
                Some(String::from("--staged")),
            )],
        )?
    };
    let exit = match section {
        Section::Clean => verdict(0, 0),
        Section::Nothing(reason) => {
            println!("   {reason}");
            verdict(0, 0)
        }
        Section::Failed => {
            println!("   FAILED");
            verdict(1, 0)
        }
        Section::CouldNotLook(reason) => {
            eprintln!("   NOT CHECKED: {reason}");
            verdict(0, 1)
        }
    };
    match exit {
        Exit::Clean => println!("secrets: the staged diff passed"),
        Exit::Violations => println!("secrets: FAILED -- unstage or remove what is marked above"),
        Exit::Broken => println!(
            "secrets: the staged diff could not be scanned, which is not a pass -- see NOT \
             CHECKED above"
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

/// A `major.minor.patch` release number, ordered the way releases are.
///
/// Hand-parsed rather than a semver crate: the only question asked of it is
/// "at least this", and a pre-release or build suffix is dropped rather than
/// ranked, so `1.30.0-rc1` counts as `1.30.0`. No scanner here ships one on
/// the channels a host installs from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Version(u64, u64, u64);

impl std::fmt::Display for Version {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// The first `major.minor.patch` in what a tool printed for `--version`.
///
/// The FIRST, because osv-scanner prints its own version and then the
/// osv-scalibr library's on the next line, and the second is not the tool's.
/// A word is one number only if all three parts are digits: `cargo-deny`, the
/// word before the version, is not one, and neither is a two-part `3.2`.
fn parse_version(said: &str) -> Option<Version> {
    said.split_whitespace().find_map(|word| {
        let word = word.strip_prefix('v').unwrap_or(word);
        let release = word.split(['-', '+']).next()?;
        let mut parts = release.split('.');
        let mut number = || -> Option<u64> {
            let part = parts.next()?;
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            part.parse().ok()
        };
        let version = Version(number()?, number()?, number()?);
        parts.next().is_none().then_some(version)
    })
}

/// The oldest release of one scanner whose output this binary's reader of it
/// was measured against.
///
/// A floor, not a pin. The readers below match a scanner's exit codes and the
/// text it prints when it did not look; a release old enough to print
/// something else turns that could-not-look into whichever verdict the
/// unmatched text falls through to. A newer one may reword too, but that is a
/// release nobody here has measured yet, not one known to predate the reader.
/// Each floor sits beside the reader that depends on it, so raising one is the
/// same diff as changing the text the reader matches.
struct Floor {
    /// The name the refusal uses.
    tool: &'static str,
    /// The program that prints its version...
    program: &'static str,
    /// ...and what it is handed to print it.
    args: &'static [&'static str],
    /// The oldest release accepted.
    oldest: Version,
}

impl Floor {
    /// The version command as the reader would type it.
    fn asked(&self) -> String {
        std::iter::once(self.program)
            .chain(self.args.iter().copied())
            .collect::<Vec<&str>>()
            .join(" ")
    }
}

/// Why this scanner is not one to run, or `None` when it is.
///
/// Missing from PATH, a version it would not print, one this could not read,
/// and one older than the floor are each could-not-look: in every case the
/// reader downstream would be matching text nobody knows the shape of.
fn ready(floor: &Floor) -> Option<String> {
    if let Some(reason) = on_path(floor.program) {
        return Some(reason);
    }
    let asked = floor.asked();
    let tool = floor.tool;
    let output = match Command::new(floor.program).args(floor.args).output() {
        Ok(output) => output,
        Err(error) => {
            return Some(format!(
                "could not run `{asked}` to learn which {tool} this is: {error}, so this \
                 was not checked"
            ));
        }
    };
    let said = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        return Some(format!(
            "`{asked}` did not answer (is {tool} installed?), so which {tool} this is is \
             unknown and this was not checked: {}",
            first_said(&String::from_utf8_lossy(&output.stderr))
        ));
    }
    against_floor(floor, &said)
}

/// What a scanner's `--version` answer says about running it: `None` when the
/// version is at or above the floor, the reason otherwise.
fn against_floor(floor: &Floor, said: &str) -> Option<String> {
    let asked = floor.asked();
    let tool = floor.tool;
    let oldest = floor.oldest;
    let Some(found) = parse_version(said) else {
        return Some(format!(
            "`{asked}` printed no version this could read ({:?}), so this was not checked; \
             this uphold reads {tool} {oldest} or later",
            first_said(said)
        ));
    };
    if found < oldest {
        return Some(format!(
            "{tool} {found} is older than {oldest}, the oldest this uphold reads, so this \
             was not checked; upgrade {tool} to {oldest} or later"
        ));
    }
    None
}

/// Run one tool, show what it said when it refused, and read its answer.
///
/// A tool that died on a signal answered nothing, and nothing is could-not-
/// look rather than either verdict.
///
/// A NON-ZERO EXIT IS NOT ALWAYS A VERDICT. Some tools answer the same code
/// for "your tree is out of step" and for "I could not start" -- cargo-vet
/// answers 255 for both -- and mapping every non-zero code to a refusal files
/// the second under the first, which is the failure this command exists to
/// refuse, one layer down. The reader is handed stdout and stderr and names
/// the could-not-look when it sees one. A tool whose exit code already
/// separates the two passes a reader that never fires.
fn tool_read(
    root: &Path,
    program: &str,
    args: &[&str],
    unread: impl Fn(i32, &str, &str) -> Option<String>,
) -> Result<Section> {
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
    let out = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    // THE READER IS ASKED BEFORE THE ZERO IS BELIEVED. A tool that skipped an
    // input it could not parse and exited 0 anyway -- zizmor, handed one bad
    // workflow among good ones -- is the same could-not-look as one that
    // refused to start, and a reader consulted only on failure would never see
    // it. The exit code is passed in because for some tools it is the whole
    // answer and for others it is the ambiguous part.
    let unread = unread(code, &out, &err);
    if unread.is_none() && code == 0 {
        return Ok(Section::Clean);
    }
    for line in out.lines().chain(err.lines()) {
        println!("   {line}");
    }
    if let Some(reason) = unread {
        return Ok(Section::CouldNotLook(reason));
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

/// Is this a path this run has anything to say about?
///
/// Two halves are what a scanner would read: a manifest or lock by name at any
/// depth, and any file under a `.github/workflows` directory. The third is the
/// opposite -- CI configuration nothing reads -- and it is here BECAUSE
/// nothing reads it: a push changing only a `.gitlab-ci.yml` would otherwise
/// leave an empty range, and be told there was nothing here a scanner reads
/// over the one file class whose being unread is worth saying out loud.
/// Nothing downstream is handed it: every section selects its own inputs by
/// name or by `is_workflow`.
fn interesting(path: &Path) -> bool {
    let named = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| MANIFEST_NAMES.contains(&name));
    named || is_workflow(path) || is_unscanned_ci(path)
}

/// A file inside a `.github/workflows` directory, at any depth.
fn is_workflow(path: &Path) -> bool {
    let parts: Vec<&std::ffi::OsStr> = path.iter().collect();
    parts.windows(3).any(|window| {
        window.first() == Some(&".github".as_ref()) && window.get(1) == Some(&"workflows".as_ref())
    })
}

/// A CI configuration file no scanner in this set reads.
///
/// Mirrors `is_workflow`: anything under a listed directory at any depth, and
/// a listed name at any depth. The directory itself is not one -- a directory
/// is not a file anybody could have scanned.
fn is_unscanned_ci(path: &Path) -> bool {
    let parts: Vec<&std::ffi::OsStr> = path.iter().collect();
    let Some((last, ancestors)) = parts.split_last() else {
        return false;
    };
    let named = last
        .to_str()
        .is_some_and(|name| UNSCANNED_CI_FILES.contains(&name));
    let under = ancestors.iter().any(|part| {
        part.to_str()
            .is_some_and(|name| UNSCANNED_CI_DIRS.contains(&name))
    });
    named || under
}

/// Every unscanned CI file in scope, as root-relative paths.
///
/// The walk poisons on an unreadable directory like every other enumeration
/// here: a declaration naming two of three files understates the gap.
fn unscanned_ci(root: &Path, scope: &Scope) -> Result<Vec<PathBuf>> {
    if let Scope::Changed(paths, _) = scope {
        return Ok(paths
            .iter()
            .filter(|path| is_unscanned_ci(path))
            .cloned()
            .collect());
    }
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
                "could not enumerate the tree looking for CI configuration: {error}. A run \
                 that says which files went unscanned must not miss one"
            ))
        })?;
        if !entry.file_type().is_some_and(|kind| kind.is_file()) {
            continue;
        }
        let Ok(relative) = entry.path().strip_prefix(root) else {
            continue;
        };
        if is_unscanned_ci(relative) {
            found.push(relative.to_path_buf());
        }
    }
    found.sort();
    Ok(found)
}

/// Say which CI configuration nobody looked at, before zizmor says what it did.
///
/// A statement, not a verdict: neither count in `run` moves, because nothing
/// failed and nothing was prevented from looking. What it refuses is the
/// silence -- five green sections over an unread pipeline read like six.
fn declare_unscanned_ci(root: &Path, scope: &Scope) -> Result<()> {
    for path in unscanned_ci(root, scope)? {
        println!(
            "   {} is CI configuration no scanner here reads -- a declared gap, \
             not a scanner that failed",
            path.display()
        );
    }
    Ok(())
}

/// The scope of one or more ranges, submodule pointers expanded.
///
/// A range whose start is the all-zero id is a branch the remote does not have,
/// and there is no ancestor to diff against: that widens to every manifest and
/// says so, because the alternative is scanning nothing for the one push that
/// introduces everything.
pub(crate) fn scope_for_ranges(root: &Path, ranges: &[(String, String)]) -> Result<Scope> {
    let mut changed = BTreeSet::new();
    let mut read = Vec::new();
    for (from, to) in ranges {
        // A deleted ref pushes no content. Nothing arrives, so nothing is
        // scanned; the range would not even parse.
        if is_zero(to) {
            continue;
        }
        if is_zero(from) {
            println!(
                "   a branch the remote does not have: no ancestor to diff against, so every \
                 manifest and every commit is in scope"
            );
            return Ok(Scope::Whole);
        }
        // Collected only once the diff below has parsed it: a revision git
        // cannot resolve fails there, before any scanner is handed it.
        collect_range(root, Path::new(""), from, to, &mut changed)?;
        read.push((from.clone(), to.clone()));
    }
    Ok(Scope::Changed(changed.into_iter().collect(), read))
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
    // A non-empty prefix is a submodule: a repository of its own, which the
    // hooked repository's environment would answer for instead.
    let ask = |args: &[&str]| {
        if prefix.as_os_str().is_empty() {
            crate::git::run(&directory, args)
        } else {
            crate::git::run_elsewhere(&directory, args)
        }
    };
    for line in ask(&["diff", "--name-only", "--diff-filter=ACMR", &range])?.lines() {
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
    for line in ask(&["diff", "--raw", &range])?.lines() {
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
    if !crate::git::is_checked_out(&directory) {
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
        Ok(crate::git::try_run_elsewhere(
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
    if let Scope::Changed(paths, _) = scope {
        let locks = selected(root, paths, &LOCK_NAMES);
        if locks.is_empty() {
            return Ok(Section::Nothing(String::from("no lockfile in this range")));
        }
        if let Some(reason) = ready(&OSV_FLOOR) {
            return Ok(Section::CouldNotLook(reason));
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
        return tool_read(root, "osv-scanner", &borrowed, osv_could_not_look);
    }
    if let Some(reason) = ready(&OSV_FLOOR) {
        return Ok(Section::CouldNotLook(reason));
    }
    tool_read(
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
        osv_could_not_look,
    )
}

fn zizmor(root: &Path, scope: &Scope) -> Result<Section> {
    // This section's edge is the gap: what zizmor parses bounds what the whole
    // set covers. Before its early returns, so a missing zizmor and a tree
    // with no Actions workflow are still told.
    declare_unscanned_ci(root, scope)?;
    let (workflows, unit) = match scope {
        Scope::Whole => (find_workflow_dirs(root)?, "workflow directories"),
        // The changed files themselves, not their directory: zizmor reports per
        // workflow, and handing it the directory would print the whole
        // directory's backlog for one edited file.
        Scope::Changed(paths, _) => (
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
            Scope::Changed(..) => "no workflow changed in this range",
        })));
    }
    if let Some(reason) = ready(&ZIZMOR_FLOOR) {
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
    tool_read(root, "zizmor", &borrowed, zizmor_could_not_look)
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
    if let Some(reason) = ready(&DENY_FLOOR) {
        return Ok(Section::CouldNotLook(reason));
    }
    let manifests = match scope {
        Scope::Whole => find_named(root, "Cargo.toml")?,
        // A lock maps to the manifest beside it: cargo-deny is pointed at a
        // manifest, and a `Cargo.lock` that moved is exactly the dependency
        // change this section exists to read.
        Scope::Changed(paths, _) => {
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
        // EXIT 1 IS TWO DIFFERENT FACTS. cargo-deny's code is a bitmask over
        // which check refused -- 1 advisories, 2 bans, 4 licenses, 8 sources --
        // so a matched RUSTSEC advisory and a run that never started share the
        // 1. What separates them is the stream: a run that reached its checks
        // prints the per-check summary (`advisories FAILED`, `bans ok`) on
        // STDOUT whatever the verdict, and one that could not -- an
        // unparseable lock, a manifest it could not read, an advisory database
        // it could not fetch -- leaves stdout empty and puts `[ERROR]` on
        // stderr. Reading the code alone reports a database nobody could
        // download as a vulnerability in this tree.
        let said = String::from_utf8_lossy(&output.stdout);
        if said.trim().is_empty() {
            return Ok(Section::CouldNotLook(format!(
                "cargo-deny reached no check on {}, so nothing here was judged: {}",
                manifest.display(),
                first_said(&String::from_utf8_lossy(&output.stderr))
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
            Scope::Changed(..) => "no crate manifest or lock moved in this range",
        })));
    }
    Ok(Section::Clean)
}

/// cargo-vet's floor: the stdout-versus-stderr split below was measured by
/// running cargo-vet 0.10.2 against a store it could not open and a tree with
/// an unvetted dependency.
const VET_FLOOR: Floor = Floor {
    tool: "cargo-vet",
    program: "cargo",
    args: &["vet", "--version"],
    oldest: Version(0, 10, 2),
};

/// cargo-deny's floor: the exit-bitmask and empty-stdout reading in `deny` was
/// measured against cargo-deny 0.20.2, and the four config-only
/// headline classes it drops were read off that release's output.
const DENY_FLOOR: Floor = Floor {
    tool: "cargo-deny",
    program: "cargo",
    args: &["deny", "--version"],
    oldest: Version(0, 20, 2),
};

/// cargo-vet's could-not-look, which shares exit 255 with its finding.
///
/// cargo-vet answers 255 for two facts. Dependencies carrying no audit are a
/// finding, and print "Vetting Failed!" on STDOUT with stderr empty. A run
/// that could not start -- a store that does not parse, a `Cargo.lock` that
/// `--locked` refuses, a `cargo metadata` that failed -- prints its diagnostic
/// on STDERR with stdout empty. The exit code confuses them and the stream
/// does not.
///
/// THE TEST IS THE STREAM, NOT THE WORDING. Matching the sentence cargo-vet
/// prints when it fails would make this section turn a finding into could-not-
/// look the first time upstream rewords it, and a discriminator that decays
/// silently on somebody else's release is worse than the exit code it
/// replaces. Anything on stdout means the tool got far enough to report on the
/// tree, whatever it called the result; a non-zero exit that reported nothing
/// judged no dependency, and that is the third verdict.
fn vet_could_not_look(code: i32, stdout: &str, stderr: &str) -> Option<String> {
    if code == 0 || !stdout.trim().is_empty() {
        return None;
    }
    Some(format!(
        "cargo-vet exited without reporting on a single dependency, so nothing \
         here was vetted: {}",
        first_said(stderr)
    ))
}

/// The first thing a tool said, so a could-not-look names something.
///
/// "The scanner was inconclusive" with no subject is a red nobody can act on,
/// which is the same argument the guarddog reason is built on.
fn first_said(text: &str) -> &str {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("it printed nothing at all")
}

/// osv-scanner's floor: exits 127 and 128 below were measured against
/// osv-scanner 2.5.1, the release the flags `osv` passes were run on.
const OSV_FLOOR: Floor = Floor {
    tool: "osv-scanner",
    program: "osv-scanner",
    args: &["--version"],
    oldest: Version(2, 5, 1),
};

/// osv-scanner's could-not-look, which its own exit code names.
///
/// `0` is clean and `1` is a vulnerability; every higher code is the scanner
/// declining to answer. `127` covers a path it could not resolve, a lockfile
/// it could not parse, a config it could not read and a query it could not
/// send. `128` is "no package sources found", which is NOT a clean tree: this
/// section hands osv-scanner lockfiles by name, so inputs that yielded no
/// package mean the named files were never read.
fn osv_could_not_look(code: i32, _stdout: &str, stderr: &str) -> Option<String> {
    if matches!(code, 0 | 1) {
        return None;
    }
    Some(format!(
        "osv-scanner exited {code} without a verdict, so no lockfile here was \
         checked: {}",
        first_said(stderr)
    ))
}

/// zizmor's floor: the `failed to parse input:` line and the 11-14 severity
/// codes below were measured against zizmor 1.30.0.
const ZIZMOR_FLOOR: Floor = Floor {
    tool: "zizmor",
    program: "zizmor",
    args: &["--version"],
    oldest: Version(1, 30, 0),
};

/// zizmor's could-not-look, which hides in two places and one of them is zero.
///
/// The verdict codes are `11` through `14`, one per severity present, so any
/// other non-zero code is a run that audited nothing.
///
/// THE ZERO IS THE DANGEROUS ONE. Handed a workflow it cannot parse ALONGSIDE
/// workflows it can, zizmor skips the bad one, audits the rest, and exits 0
/// with "No findings to report. Good job!" on stdout. The only witness is a
/// `failed to parse input:` line on stderr. Its SARIF reports
/// `executionSuccessful: true` in exactly that case, so the structured output
/// is worse than useless here. This section hands zizmor a LIST of workflow
/// files, which is precisely the shape that triggers it.
fn zizmor_could_not_look(code: i32, _stdout: &str, stderr: &str) -> Option<String> {
    const SKIPPED: &str = "failed to parse input:";
    let skipped = stderr.matches(SKIPPED).count();
    if skipped > 0 {
        return Some(format!(
            "zizmor could not parse {skipped} of the workflow(s) it was handed \
             and audited the rest, so those were never read"
        ));
    }
    if matches!(code, 0 | 11..=14) {
        return None;
    }
    Some(format!(
        "zizmor exited {code} without auditing anything: {}",
        first_said(stderr)
    ))
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
    if let Scope::Changed(paths, _) = scope
        && selected(root, paths, &["Cargo.lock"]).is_empty()
    {
        return Ok(Section::Nothing(String::from(
            "no Cargo.lock moved in this range",
        )));
    }
    if let Some(reason) = ready(&VET_FLOOR) {
        return Ok(Section::CouldNotLook(reason));
    }
    tool_read(root, "cargo", &["vet", "--locked"], vet_could_not_look)
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

/// The closed list of metadata normalizations supported by the report reader.
/// `OptionalExtras` additionally requires release evidence from [`pypi`].
///
/// The rule compares the registry's manifest for a release with the
/// `package.json` inside its tarball. `npm publish` normalizes the manifest it
/// uploads and leaves the tarball's file as written, so some differences are
/// npm's own and recur on every release of a package, where a version-keyed
/// waiver needs a new row each time. These are the normalize steps of
/// `@npmcli/package-json`, and only these two are accepted:
///
/// - `DefaultStart`, npm's `serverjs` step: a package with `server.js` at its
///   root and no `scripts.start` is published with `"start": "node server.js"`.
///   guarddog prints the absent tarball side as `None`, which is also how a
///   literal `"None"` prints; either way the registry side is npm's default.
///   The report does not list the tarball's files, so `server.js` itself is
///   not confirmed.
/// - `BinPrefixStripped`, npm's `scriptpath` step: one leading
///   `./node_modules/.bin/` or `node_modules/.bin/` is removed from each
///   script. The same text anywhere else in the value is not removed by npm
///   and is not accepted here.
///
/// A risk is tolerated only where every difference its description lists is
/// one of these. Any other field, any other script difference, or a line that
/// does not read as exactly one difference leaves the risk counted as before,
/// and a waiver still applies to it. Not on the list: `"install": "node-gyp
/// rebuild"`, which npm adds where `binding.gyp` exists; an install script runs
/// at install time, which `start` does not, so it joins only with a case and a
/// test. `PyPI` optional extras use separate release evidence in [`pypi`],
/// because the report itself drops the markers that identify an extra.
#[derive(Clone, Copy)]
enum Normalization {
    DefaultStart,
    BinPrefixStripped,
    OptionalExtras,
}

/// Every normalization tolerated, in the order a difference is tried against
/// them.
const PUBLISH_NORMALIZATIONS: [Normalization; 3] = [
    Normalization::DefaultStart,
    Normalization::BinPrefixStripped,
    Normalization::OptionalExtras,
];

impl Normalization {
    /// What a `tolerated:` line calls it.
    const fn name(self) -> &'static str {
        match self {
            Self::DefaultStart => "npm default start script",
            Self::BinPrefixStripped => "npm strips a leading node_modules/.bin/",
            Self::OptionalExtras => "PyPI optional extras verified against release requires_dist",
        }
    }

    /// Whether npm's publish turns the tarball's `scripts.<key>` into the
    /// registry's, both as guarddog printed them.
    fn accepts(self, key: &str, registry: &str, tarball: &str) -> bool {
        match self {
            Self::DefaultStart => {
                key == "start" && registry == "node server.js" && tarball == "None"
            }
            Self::BinPrefixStripped => ["./node_modules/.bin/", "node_modules/.bin/"]
                .iter()
                .any(|prefix| tarball.strip_prefix(prefix) == Some(registry)),
            Self::OptionalExtras => false,
        }
    }
}

/// The normalization behind each difference an npm `metadata_mismatch`
/// description lists, described, or `None` where any difference is not one of
/// [`PUBLISH_NORMALIZATIONS`] or any line cannot be read as one difference.
///
/// guarddog 3.2.0's `describe_diff` prints a header, a `<field>: ` line per
/// differing field, and under `scripts` one
/// `  <key>: Manifest("<registry>"), package.json("<tarball>") ` line per
/// differing key, in an order that is not stable. It escapes nothing, so a
/// line in which either marker appears more than once is ambiguous and is not
/// read, and a value spanning lines leaves a line that is not a difference.
/// Only `scripts` can hold a tolerated difference, so any other field refuses.
fn tolerated(description: &str) -> Option<Vec<String>> {
    const OPEN: &str = ": Manifest(\"";
    const BETWEEN: &str = "\"), package.json(\"";
    let mut lines = description.lines().map(str::trim_end);
    if lines.next()? != "Difference between manifest and package.json found:"
        || lines.next()? != "scripts:"
    {
        return None;
    }
    let mut accepted = Vec::new();
    for line in lines {
        let entry = line.strip_prefix("  ")?;
        if entry.matches(OPEN).count() != 1 || entry.matches(BETWEEN).count() != 1 {
            return None;
        }
        let (key, rest) = entry.split_once(OPEN)?;
        let (registry, tarball) = rest.strip_suffix("\")")?.split_once(BETWEEN)?;
        let normalization = PUBLISH_NORMALIZATIONS
            .into_iter()
            .find(|normalization| normalization.accepts(key, registry, tarball))?;
        accepted.push(format!(
            "{} (scripts.{key} = \"{registry}\")",
            normalization.name()
        ));
    }
    (!accepted.is_empty()).then_some(accepted)
}

/// A second source is consulted only for the exact `PyPI` report shape it can
/// explain. Unavailable or mismatched evidence leaves the scanner's finding
/// intact, so optional normalization never makes the scan depend on a pass.
fn tolerated_metadata(
    ecosystem: &str,
    name: &str,
    version: &str,
    description: &str,
    metadata: &mut impl FnMut(&str, &str) -> std::result::Result<serde_json::Value, String>,
) -> Option<Vec<String>> {
    match ecosystem {
        "npm" => tolerated(description),
        "pypi" => {
            let differences = pypi::differences(description)?;
            match metadata(name, version) {
                Ok(release) => pypi::confirms(&release, name, version, &differences)
                    .map(|accepted| vec![accepted]),
                Err(reason) => {
                    println!(
                        "   retained: metadata_mismatch on pypi:{name}@{version} -- \
                         could not verify optional extras: {reason}"
                    );
                    None
                }
            }
        }
        _ => None,
    }
}

/// guarddog's floor: the "rules failed to run while scanning" text, the JSON
/// report's `errors` / `results` / `risks` keys and exit 0 on a finding were
/// all measured against guarddog 3.2.0.
const GUARDDOG_FLOOR: Floor = Floor {
    tool: "guarddog",
    program: "guarddog",
    args: &["--version"],
    oldest: Version(3, 2, 0),
};

/// The directory guarddog unpacks what it downloads under:
/// `$XDG_CACHE_HOME/uphold/guarddog`, else `$HOME/.cache/uphold/guarddog`, or
/// `None` where neither names an absolute directory.
///
/// GUARDDOG'S `metadata_mismatch` VERDICT ON A PYPI WHEEL DEPENDS ON THE
/// FILESYSTEM IT UNPACKS ON. guarddog 3.2.0 extracts the release into a fresh
/// `tempfile.TemporaryDirectory()` and takes the first `os.listdir` entry that
/// starts with the package name as the package's root. A wheel such as pandas
/// 3.0.3 holds two, `pandas/` (which carries a `pyproject.toml`) and
/// `pandas-3.0.3.dist-info/` (which carries none), and the order the two are
/// listed in is the filesystem's: tmpfs lists the newest first, btrfs in
/// creation order, ext4 in the order of a hash seeded per filesystem. One
/// order reaches the manifest and reports a mismatch; the other reaches none
/// and reports nothing. Inheriting the caller's `TMPDIR` made that the
/// verdict's input, so one lock passed or failed with where `TMPDIR` pointed.
///
/// The defect is guarddog's, and nothing outside its process reorders a
/// listing. What is fixed here is the input: guarddog is handed this directory
/// as `TMPDIR`, so the caller's `TMPDIR` no longer decides, and one host gives
/// one verdict. Two hosts whose cache directories sit on different filesystems
/// can still disagree, which is why the stale-waiver notice for a `pypi`
/// `metadata_mismatch` waiver does not advise removing it.
///
/// A relative `XDG_CACHE_HOME` is ignored, as the specification says: guarddog
/// runs in the manifest's directory, so a relative one would unpack downloads
/// into the tree being checked. The environment is a parameter so a test can
/// hand in one of its own.
fn guarddog_unpacks_under(env: impl Fn(&str) -> Option<PathBuf>) -> Option<PathBuf> {
    let absolute = |name: &str| env(name).filter(|path| path.is_absolute());
    absolute("XDG_CACHE_HOME")
        .or_else(|| absolute("HOME").map(|home| home.join(".cache")))
        .map(|cache| cache.join("uphold").join("guarddog"))
}

/// [`guarddog_unpacks_under`] on this machine, created; `None`, with the line
/// saying why, where there is none or it could not be made. guarddog then
/// inherits `TMPDIR` as before, and the run says its verdict may move with it.
fn guarddog_unpack_directory() -> Option<PathBuf> {
    let fallback = "guarddog unpacks under TMPDIR, so its metadata_mismatch verdict may \
                    differ with the filesystem TMPDIR is on";
    let Some(directory) = guarddog_unpacks_under(|name| std::env::var_os(name).map(PathBuf::from))
    else {
        println!("   {fallback}: neither XDG_CACHE_HOME nor HOME names an absolute directory");
        return None;
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    match builder.create(&directory) {
        Ok(()) => Some(directory),
        Err(error) => {
            println!(
                "   {fallback}: {} could not be created: {error}",
                directory.display()
            );
            None
        }
    }
}

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

/// What one `guarddog verify` run established.
enum Read {
    /// guarddog objected to something, with any missing coverage described.
    Risks(String, Option<String>),
    /// guarddog did not answer, described.
    Unread(String),
    /// guarddog ran and objected to nothing.
    Clean,
}

/// Read one `guarddog verify` run out of its report rather than its exit code.
///
/// GUARDDOG CANNOT SAY "I FOUND SOMETHING" IN ITS EXIT CODE. `verify` answers
/// 0 whether it found three high-severity risks or none, in both ecosystems,
/// so a section reading the code called every finding clean. That is the one
/// direction this crate must never get wrong, and it was wrong here.
///
/// `--exit-non-zero-on-finding` is not the fix. It keys off `issues`, which
/// counts capability matches -- `six` scores `issues: 2` with `risks: []` and
/// guarddog's own label `no_risks_detected` -- so the flag turns a package its
/// own report calls clean into a hard failure, trading a false negative for a
/// false positive.
///
/// So this is the one scanner whose FINDINGS are read here, against the rule
/// the module header sets, and the reason is that the alternative is running
/// it for nothing. `risks` is guarddog's own list of what it objected to and
/// nothing is re-judged: the count is reported, not recomputed.
///
/// A risk covered by [`tolerated_metadata`] is
/// printed as tolerated, naming each, and is not held against the run.
///
/// A risk a waiver covers is printed as waived, with the waiver's reason, and
/// is not held against the run; the index of each root waiver that matched is
/// recorded in the ledger, with every package a report named, so the section
/// can report the waivers that did not. A nested repository's waiver is named
/// on its line by that repository's policy file, so whose decision let the
/// risk through is on the line that says it was let through.
#[expect(
    clippy::too_many_arguments,
    reason = "scan inputs and subprocess output meet at this reader"
)]
fn guarddog_read(
    at: &str,
    ecosystem: &str,
    expected: &BTreeSet<String>,
    waivers: &Waivers<'_>,
    ledger: &mut Ledger,
    code: Option<i32>,
    stdout: &str,
    stderr: &str,
    metadata: &mut impl FnMut(&str, &str) -> std::result::Result<serde_json::Value, String>,
) -> Read {
    // Its own admission first, because it survives whatever the report is.
    if let Some(reason) = rules_that_did_not_run(stdout).or_else(|| rules_that_did_not_run(stderr))
    {
        return Read::Unread(reason);
    }
    if code != Some(0) {
        return Read::Unread(format!(
            "guarddog gave no report at {at}: {}",
            first_said(stderr)
        ));
    }
    let Ok(serde_json::Value::Array(entries)) = serde_json::from_str::<serde_json::Value>(stdout)
    else {
        return Read::Unread(format!(
            "guarddog printed no report this could read at {at}"
        ));
    };
    // Where the input could not be read, even an empty expected set cannot
    // establish coverage. Known inputs are reconciled below, including `[]`.
    if entries.is_empty() && expected.is_empty() {
        return Read::Unread(format!("guarddog reported on no dependency at all at {at}"));
    }
    let mut objected: Vec<String> = Vec::new();
    let mut observed = BTreeSet::new();
    for entry in &entries {
        let name = entry
            .get("dependency")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("a dependency it did not name");
        observed.insert(if ecosystem == "pypi" {
            references::normalise(name)
        } else {
            name.to_owned()
        });
        let Some(result) = entry.get("result") else {
            return Read::Unread(format!("guarddog said nothing about {name} at {at}"));
        };
        let scanned = result
            .get("errors")
            .and_then(serde_json::Value::as_object)
            .is_some_and(serde_json::Map::is_empty);
        if !scanned || result.get("results").is_none() {
            return Read::Unread(format!(
                "guarddog could not scan {name} at {at}: {}",
                result.get("errors").map_or_else(
                    || String::from("it reported no result for it"),
                    ToString::to_string
                )
            ));
        }
        let Some(results) = result.get("results").and_then(serde_json::Value::as_object) else {
            return Read::Unread(format!(
                "guarddog gave an incomplete report for {name} at {at}: `results` is not an object"
            ));
        };
        let Some(reported_risks) = result.get("risks").and_then(serde_json::Value::as_array) else {
            return Read::Unread(format!(
                "guarddog gave an incomplete report for {name} at {at}: `risks` is not an array"
            ));
        };
        // The version guarddog resolved, which for npm is the release a range
        // in `package.json` picked and not the range itself.
        let version = result
            .get("package_version")
            .or_else(|| entry.get("version"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        ledger
            .seen
            .insert((ecosystem.to_owned(), (*name).to_owned()));
        let mut risks = 0_usize;
        for risk in reported_risks {
            // The rule that raised it, as a waiver names it; `name` is the
            // risk's own id, for a risk no single rule raised.
            let rule = risk
                .get("threat_rule")
                .or_else(|| risk.get("capability_rule"))
                .and_then(serde_json::Value::as_str)
                .or_else(|| risk.get("name").and_then(serde_json::Value::as_str))
                .unwrap_or("");
            // Known metadata normalizations, named on the line that lets
            // them through. The risk and the underlying result must describe
            // the same difference; anything else keeps the risk counted.
            if rule == "metadata_mismatch"
                && let Some(description) = risk
                    .get("threat_description")
                    .and_then(serde_json::Value::as_str)
                && results
                    .get("metadata_mismatch")
                    .and_then(serde_json::Value::as_str)
                    == Some(description)
                && let Some(accepted) =
                    tolerated_metadata(ecosystem, name, version, description, metadata)
            {
                println!(
                    "   tolerated: {rule} on {ecosystem}:{name}@{version} at {at} -- {}",
                    accepted.join("; ")
                );
                continue;
            }
            // The nested repository's own waiver first, because it is the
            // owner's decision about its own dependency; a root row that also
            // covers the risk is then a copy of it, and is recorded as one so
            // the stale report can say it may go.
            let own = waivers.nested.and_then(|nested| {
                nested
                    .waive
                    .iter()
                    .find(|waiver| waiver.covers(ecosystem, name, version, rule))
                    .map(|waiver| (nested.source.as_str(), waiver.reason.as_str()))
            });
            let root = waivers
                .root
                .iter()
                .position(|waiver| waiver.covers(ecosystem, name, version, rule));
            match (own, root) {
                (Some((source, reason)), copy) => {
                    if let Some(index) = copy {
                        ledger
                            .duplicated
                            .entry(index)
                            .or_insert_with(|| source.to_owned());
                    }
                    println!(
                        "   waived ({source}): {rule} on {ecosystem}:{name}@{version} at {at} \
                         -- {reason}"
                    );
                }
                (None, Some(index)) => {
                    ledger.matched.insert(index);
                    let reason = waivers
                        .root
                        .get(index)
                        .map_or("", |covering| covering.reason.as_str());
                    println!(
                        "   waived: {rule} on {ecosystem}:{name}@{version} at {at} -- {reason}"
                    );
                }
                (None, None) => risks += 1,
            }
        }
        if risks > 0 {
            let at_version = if version.is_empty() {
                String::new()
            } else {
                format!("@{version}")
            };
            objected.push(format!("{name}{at_version} ({risks} risk(s))"));
        }
    }
    let missing: Vec<&str> = expected.difference(&observed).map(String::as_str).collect();
    let unread = (!missing.is_empty()).then(|| {
        format!(
            "guarddog omitted {} at {at}: no report for submitted {ecosystem} dependency(s)",
            missing.join(", ")
        )
    });
    if !objected.is_empty() {
        Read::Risks(
            format!("{at}: guarddog objected to {}", objected.join(", ")),
            unread,
        )
    } else if let Some(reason) = unread {
        Read::Unread(reason)
    } else {
        Read::Clean
    }
}

/// How the guarddog section finds the policy of a repository nested inside the
/// scan root: handed a directory under the root, it answers that directory's
/// own policy file and the policy loaded from it where the directory is a
/// repository root carrying one, and `None` everywhere else.
///
/// Handed in rather than written here because which file `uphold` loads at a
/// directory is the command's discovery, not this section's: a second walk
/// written here would be a second answer to "whose policy is this", free to
/// disagree with the one every other entry point gives -- over
/// `policy/principles.toml` against `policy/rg-policy.toml`, over where a
/// repository begins, and over `[inherit]`. A load that fails is an error and
/// never `None`: a policy that would not load has said nothing about which
/// findings its owner accepted, and reading it as "no waivers" would refuse on
/// a guess, or worse, if the run ever read it the other way, pass on one.
pub(crate) type NestedPolicy<'a> = &'a dyn Fn(&Path) -> Result<Option<(PathBuf, Policy)>>;

/// A nested repository's own waivers, as the guarddog section reads them.
struct Nested {
    /// Its policy file, relative to the scan root, which is how every line
    /// that applies one of its waivers names whose decision it was.
    source: String,
    /// Its `[[supply_chain.waive]]` rows.
    waive: Vec<Waiver>,
}

/// The waivers one manifest is judged against.
///
/// Two owners and no more. The scan root's rows cover every manifest in the
/// tree, as they always have: the root's policy is the one the run was started
/// under. A nested repository's rows cover only the manifests in that
/// repository's tree, because they are that repository's decisions about its
/// own dependencies -- the superproject's manifests and a sibling's are
/// somebody else's, and a submodule able to waive them would be a repository
/// excusing a tree it does not own, under the superproject's name.
#[derive(Default)]
struct Waivers<'a> {
    /// The scan root's own.
    root: &'a [Waiver],
    /// The nearest enclosing nested repository's, where it has a policy.
    nested: Option<&'a Nested>,
}

/// What the nested-repository walk found, by directory, so a repository with
/// many manifests is loaded once. An error is kept as said, because the same
/// repository is the same refusal for each of its manifests.
type NestedFound =
    std::collections::BTreeMap<PathBuf, std::result::Result<Option<std::rc::Rc<Nested>>, String>>;

/// The nested repository whose waivers also cover a manifest in `directory`:
/// the nearest directory between it and `root` -- `directory` itself included,
/// `root` excluded -- that `nested` answers a policy for.
///
/// Nearest, because a repository's policy speaks for its own tree, and the
/// innermost repository holding the manifest is the one whose dependency it
/// is. A repository with no policy of its own is passed over rather than
/// stopped at, for the reason `uphold` run there refuses to borrow one: it has
/// made no decision, so the next repository out, which does carry it in its
/// tree, is the one that has.
///
/// The walk is `directory`'s own ancestors and nothing else, which is the
/// whole of the boundary: the root's own manifests have no nested repository
/// above them, and a sibling submodule is never an ancestor.
fn nested_waivers(
    root: &Path,
    directory: &Path,
    nested: NestedPolicy<'_>,
    found: &mut NestedFound,
) -> std::result::Result<Option<std::rc::Rc<Nested>>, String> {
    for ancestor in directory
        .ancestors()
        .take_while(|ancestor| *ancestor != root && ancestor.starts_with(root))
    {
        let answer = found
            .entry(ancestor.to_path_buf())
            .or_insert_with(|| load_nested(root, directory, ancestor, nested));
        if !matches!(answer, Ok(None)) {
            return answer.clone();
        }
    }
    Ok(None)
}

/// One directory's answer for [`nested_waivers`], `directory` being the
/// manifest's, which the refusal names.
fn load_nested(
    root: &Path,
    directory: &Path,
    ancestor: &Path,
    nested: NestedPolicy<'_>,
) -> std::result::Result<Option<std::rc::Rc<Nested>>, String> {
    match nested(ancestor) {
        Ok(Some((path, policy))) => Ok(Some(std::rc::Rc::new(Nested {
            source: path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string(),
            waive: policy.supply_chain.waive,
        }))),
        Ok(None) => Ok(None),
        Err(error) => Err(format!(
            "the guarddog findings at {} were not judged: {} is a repository with a policy of \
             its own, which decides the waivers for its manifests, and that policy did not \
             load: {error}",
            directory.display(),
            ancestor.display()
        )),
    }
}

/// What the guarddog reports of one run said about the waivers.
#[derive(Default)]
struct Ledger {
    /// The scan root's waivers, by index, that covered a risk.
    matched: BTreeSet<usize>,
    /// The scan root's waivers, by index, that would have covered a risk a
    /// nested repository's own waiver covered first, with that repository's
    /// policy file: the copies superprojects made before nested waivers were
    /// read, which the stale report names so they can go.
    duplicated: std::collections::BTreeMap<usize, String>,
    /// Every `(ecosystem, package)` a report named.
    seen: BTreeSet<(String, String)>,
    /// The ecosystems a report was read for at all.
    read: BTreeSet<&'static str>,
}

/// Who is first party here, as the policy declares it.
fn first_party_of<'a>(policy: &'a Policy, root: &Path) -> references::FirstParty<'a> {
    references::FirstParty {
        owner: policy
            .declared_owner(root)
            .map_err(|error| error.to_string()),
        host: policy
            .supply_chain
            .forge_host
            .as_deref()
            .unwrap_or(references::DEFAULT_FORGE_HOST),
    }
}

/// The npm locks that may say what a manifest in `directory` resolved, nearest
/// first: its own, then each directory up to `root`, where a workspace keeps
/// the one lock for every member.
fn npm_locks(directory: &Path, root: &Path) -> Vec<String> {
    directory
        .ancestors()
        .take_while(|ancestor| ancestor.starts_with(root))
        .flat_map(|ancestor| ["bun.lock", "package-lock.json"].map(|name| ancestor.join(name)))
        .filter_map(|lock| std::fs::read_to_string(lock).ok())
        .collect()
}

fn guarddog(
    root: &Path,
    scope: &Scope,
    policy: &Policy,
    nested: NestedPolicy<'_>,
) -> Result<Section> {
    let waivers = policy.supply_chain.waive.as_slice();
    let mut found = NestedFound::new();
    let (python, npm) = match scope {
        Scope::Whole => (
            find_named(root, "uv.lock")?,
            find_named(root, "package.json")?,
        ),
        // A directory, not a file: guarddog is run with the working directory
        // set to the manifest's own, and `pyproject.toml` moving is a dependency
        // change whether or not the lock moved with it.
        Scope::Changed(paths, _) => (
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
            Scope::Changed(..) => "no Python or npm manifest moved in this range",
        })));
    }
    if let Some(reason) = ready(&GUARDDOG_FLOOR) {
        return Ok(Section::CouldNotLook(reason));
    }
    // Handed to every guarddog run as `TMPDIR`; see `guarddog_unpacks_under`.
    let unpack = guarddog_unpack_directory();
    let unpacks = || unpack.as_deref().map(|directory| ("TMPDIR", directory));
    let mut refused = false;
    let mut unrun: Option<String> = None;
    let mut checked = 0_usize;
    let mut ledger = Ledger::default();
    // Asked only where a git source needs it: `owner_from` is a command, and a
    // repository with no git dependency has no reason to run it.
    let mut first_party: Option<references::FirstParty<'_>> = None;
    let mut remotes = std::collections::BTreeMap::new();
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
        let at = directory.display().to_string();
        // Before guarddog is asked: a manifest whose owner's policy did not
        // load has findings nothing here can tell from the accepted ones.
        let owner = match nested_waivers(root, directory, nested, &mut found) {
            Ok(owner) => owner,
            Err(said) => {
                unrun = unrun.or(Some(said));
                continue;
            }
        };
        let sorted = references::sort(
            &String::from_utf8_lossy(&exported.stdout),
            directory,
            root,
            std::fs::read_to_string(&lock).ok().as_deref(),
        );
        for said in &sorted.refused {
            println!("   FAILED: guarddog pypi: {at}: {said}");
            refused = true;
        }
        for pin in &sorted.git {
            let deciding = first_party.get_or_insert_with(|| first_party_of(policy, root));
            match references::check(pin, deciding, directory, &mut remotes) {
                references::Checked::Holds(said) => println!("   first party: {said}"),
                references::Checked::Refused(said) => {
                    println!("   FAILED: guarddog pypi: {at}: {said}");
                    refused = true;
                }
                references::Checked::Unread(said) => unrun = unrun.or(Some(said)),
            }
        }
        // Nothing an index resolves is nothing to look up, and guarddog handed
        // an empty list answers `[]`, which reads as a network failure.
        if sorted.indexed == 0 {
            println!(
                "   {at}: no dependency here resolves from an index, so guarddog was not asked"
            );
            continue;
        }
        let requirements = tempfile_guard::TempFile::containing(&sorted.kept)?;
        let status = Command::new("guarddog")
            .args(["pypi", "verify", "--output-format", "json"])
            .arg(&requirements.path)
            .args(GUARDDOG_RULES)
            .envs(unpacks())
            .current_dir(directory)
            .output()
            .map_err(|error| Fatal::new(format!("could not run guarddog: {error}")))?;
        match guarddog_read(
            &at,
            "pypi",
            &sorted.expected,
            &Waivers {
                root: waivers,
                nested: owner.as_deref(),
            },
            &mut ledger,
            status.status.code(),
            &String::from_utf8_lossy(&status.stdout),
            &String::from_utf8_lossy(&status.stderr),
            &mut pypi::fetch,
        ) {
            Read::Clean => {
                ledger.read.insert("pypi");
            }
            Read::Risks(said, unread) => {
                if unread.is_none() {
                    ledger.read.insert("pypi");
                }
                unrun = unrun.or(unread);
                println!("   FAILED: guarddog pypi: {said}");
                refused = true;
            }
            Read::Unread(said) => unrun = unrun.or(Some(said)),
        }
    }
    // guarddog reads `devDependencies` as well only under this setting, and
    // compares it as Python's `.lower() == "true"`.
    let include_dev = std::env::var("GUARDDOG_NPM_INCLUDE_DEV_DEPENDENCIES")
        .is_ok_and(|value| value.eq_ignore_ascii_case("true"));
    for manifest in npm {
        let directory = manifest.parent().unwrap_or(root);
        checked += 1;
        let at = directory.display().to_string();
        // Before guarddog is asked: a manifest whose owner's policy did not
        // load has findings nothing here can tell from the accepted ones.
        let owner = match nested_waivers(root, directory, nested, &mut found) {
            Ok(owner) => owner,
            Err(said) => {
                unrun = unrun.or(Some(said));
                continue;
            }
        };
        let sorted = std::fs::read_to_string(&manifest)
            .map(|text| references::sort_npm(&text, &npm_locks(directory, root), include_dev))
            .unwrap_or_default();
        for said in &sorted.refused {
            println!("   FAILED: guarddog npm: {at}: {said}");
            refused = true;
        }
        for pin in &sorted.git {
            let deciding = first_party.get_or_insert_with(|| first_party_of(policy, root));
            match references::check(pin, deciding, directory, &mut remotes) {
                references::Checked::Holds(said) => println!("   first party: {said}"),
                references::Checked::Refused(said) => {
                    println!("   FAILED: guarddog npm: {at}: {said}");
                    refused = true;
                }
                references::Checked::Unread(said) => unrun = unrun.or(Some(said)),
            }
        }
        // Nothing npm resolves among what guarddog reads -- no `dependencies`,
        // only `devDependencies` where it does not read them, or only git
        // dependencies -- is nothing to look up, and guarddog would
        // answer `[]`, which reads as a network failure. A manifest that did not
        // parse still goes to guarddog, for it to say so.
        if sorted.read && sorted.indexed == 0 {
            println!("   {at}: no dependency here resolves from npm, so guarddog was not asked");
            continue;
        }
        // The manifest itself where nothing came out of it; otherwise what is
        // left.
        let rewritten = sorted
            .kept
            .as_deref()
            .map(tempfile_guard::TempFile::containing)
            .transpose()?;
        let status = Command::new("guarddog")
            .args(["npm", "verify", "--output-format", "json"])
            .arg(
                rewritten
                    .as_ref()
                    .map_or_else(|| Path::new("package.json"), |file| file.path.as_path()),
            )
            .args(GUARDDOG_RULES)
            .envs(unpacks())
            .current_dir(directory)
            .output()
            .map_err(|error| Fatal::new(format!("could not run guarddog: {error}")))?;
        match guarddog_read(
            &at,
            "npm",
            &sorted.expected,
            &Waivers {
                root: waivers,
                nested: owner.as_deref(),
            },
            &mut ledger,
            status.status.code(),
            &String::from_utf8_lossy(&status.stdout),
            &String::from_utf8_lossy(&status.stderr),
            &mut pypi::fetch,
        ) {
            Read::Clean => {
                ledger.read.insert("npm");
            }
            Read::Risks(said, unread) => {
                if unread.is_none() {
                    ledger.read.insert("npm");
                }
                unrun = unrun.or(unread);
                println!("   FAILED: guarddog npm: {said}");
                refused = true;
            }
            Read::Unread(said) => unrun = unrun.or(Some(said)),
        }
    }
    println!("   {checked} Python/npm manifest(s) checked");
    report_unmatched(waivers, &ledger, scope);
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

/// A waiver that matched nothing, where the run could have matched it, is
/// one whose version moved or whose finding went away. "Could have" is the
/// package appearing in a report, or, over the whole tree, its ecosystem
/// being read at all -- a range scan reads only the manifests that moved,
/// and a waiver about one that did not is not stale for it. Reported and
/// not refused: the push it would have excused is not less safe for it,
/// and the line that names it is the prompt to delete it.
///
/// The scan root's waivers only. A nested repository's row that matched
/// nothing here is reported by that repository's own scan, which is the
/// one that can act on it -- the row is in its policy, and a superproject
/// that printed it too would be a second reporter of one fact, naming a
/// file the superproject does not write. A root row that matched only
/// where the nested repository's own row already covered the risk is a
/// copy of that row, and is named as one.
fn report_unmatched(waivers: &[Waiver], ledger: &Ledger, scope: &Scope) {
    for (index, waiver) in waivers.iter().enumerate() {
        let Some((ecosystem, name, _)) = waiver.parts() else {
            continue;
        };
        if !ledger.matched.contains(&index)
            && let Some(source) = ledger.duplicated.get(&index)
        {
            println!(
                "   waiver repeats {source}: {} on {} -- the repository that owns the manifest \
                 waives it in its own policy, so this copy can be removed",
                waiver.check, waiver.package
            );
            continue;
        }
        let could = ledger
            .seen
            .contains(&(ecosystem.to_owned(), name.to_owned()))
            || (matches!(scope, Scope::Whole) && ledger.read.contains(ecosystem));
        if could && !ledger.matched.contains(&index) {
            // Except where whether the finding appears is the host's: a pypi
            // `metadata_mismatch` reaches the release's manifest on some
            // filesystems and not others (`guarddog_unpacks_under`), so its
            // absence here is not its absence everywhere.
            let advice = if ecosystem == "pypi" && waiver.check == "metadata_mismatch" {
                "guarddog reads a pypi release's manifest for this check on some \
                 filesystems and not others, so another host may still need it"
            } else {
                "remove it if the version moved or the finding is gone"
            };
            println!(
                "   waiver matched nothing in this run: {} on {} -- {advice}",
                waiver.check, waiver.package
            );
        }
    }
}

/// The gitleaks release this binary is tested against.
///
/// Pinned here, unlike the other five scanners, because gitleaks' verdict is
/// the rule list compiled into it: two machines on two versions are two gates
/// over the same commit. The other five answer from databases that move under
/// any version, so a pin would buy them nothing. The README's install line
/// and docs/REFERENCE.md name this version too, and a unit test below holds
/// the three together.
const GITLEAKS_VERSION: &str = "8.30.1";

/// The gitleaks configuration run where the repository has none of its own.
const GITLEAKS_DEFAULT: &str = include_str!("../policy/gitleaks.default.toml");

/// The exit code gitleaks is told to answer when it found something.
///
/// gitleaks answers `1` for "leaks found" and also for a partial scan whose
/// git subprocess failed half way, so its default leaves a refusal and a scan
/// that did not finish spelled alike. `--exit-code` moves the finding to a
/// code of its own; `2` is a Go runtime panic and `126` an unknown flag, so
/// neither is used.
const GITLEAKS_FOUND: i32 = 3;

/// Stands in for the gitleaks section in a policy that does not inherit
/// [`SECRETS_SET`]. Said out loud, for the reason every section says why it
/// read nothing.
fn gitleaks_not_asked(_root: &Path, _scope: &Scope) -> Result<Section> {
    Ok(Section::Nothing(format!(
        "the policy does not inherit the `{SECRETS_SET}` set, which is what asks for this"
    )))
}

/// gitleaks over the commits in scope: each pushed range, or every commit
/// under `--all` and for a branch the remote does not have.
///
/// Commits and not the working tree, because the working tree holds ignored
/// files -- a populated `.env` among them -- that no commit carries, and a
/// push refused for a file that never leaves the machine is the false positive
/// this scanner was adopted to stop producing.
fn gitleaks(root: &Path, scope: &Scope) -> Result<Section> {
    if let Some(reason) = on_path("gitleaks") {
        return Ok(Section::CouldNotLook(reason));
    }
    if let Some(reason) = gitleaks_version_mismatch() {
        return Ok(Section::CouldNotLook(reason));
    }
    let passes: Vec<(String, Option<String>)> = match scope {
        Scope::Whole => vec![(String::from("every commit"), None)],
        Scope::Changed(_, ranges) => ranges
            .iter()
            .map(|(from, to)| {
                let opts = format!("{from}..{to}");
                (opts.clone(), Some(format!("--log-opts={opts}")))
            })
            .collect(),
    };
    if passes.is_empty() {
        return Ok(Section::Nothing(String::from(
            "no commit arrives in this range",
        )));
    }
    gitleaks_passes(root, passes)
}

/// `gitleaks git` once per pass, each pass being what to print for it and the
/// one argument that says what it reads: a `--log-opts` range, `--staged`, or
/// none for every commit. The caller has already checked the version.
fn gitleaks_passes(root: &Path, passes: Vec<(String, Option<String>)>) -> Result<Section> {
    // `--config` named explicitly, as zizmor's is: it outranks the
    // GITLEAKS_CONFIG variables gitleaks otherwise reads, so a variable left
    // in one shell cannot make that machine's gate differ from every other.
    let own = root.join(".gitleaks.toml");
    let (config, _kept): (PathBuf, Option<tempfile_guard::TempFile>) = if own.is_file() {
        (own, None)
    } else {
        let written = tempfile_guard::TempFile::containing(GITLEAKS_DEFAULT)?;
        (written.path.clone(), Some(written))
    };
    let mut worst = Section::Clean;
    for (label, selector) in passes {
        let mut args: Vec<String> = vec![
            String::from("git"),
            String::from("--no-banner"),
            String::from("--no-color"),
            String::from("--redact"),
            String::from("--verbose"),
            format!("--exit-code={GITLEAKS_FOUND}"),
            String::from("--config"),
            config.display().to_string(),
        ];
        println!("   {label}");
        args.extend(selector);
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let answer = tool_read(root, "gitleaks", &borrowed, gitleaks_could_not_look)?;
        if matches!(answer, Section::Failed) {
            println!(
                "   remove the secret from the commit, or put an accepted finding's \
                 fingerprint in .gitleaksignore"
            );
        }
        // The same ranking `verdict` applies across sections: a finding is
        // what the reader acts on first, and every answer was printed.
        worst = match (worst, answer) {
            (Section::Failed, _) | (_, Section::Failed) => Section::Failed,
            (reason @ Section::CouldNotLook(_), _) | (_, reason @ Section::CouldNotLook(_)) => {
                reason
            }
            _ => Section::Clean,
        };
    }
    Ok(worst)
}

/// Why the gitleaks on PATH is not the pinned one, or `None` when it is.
fn gitleaks_version_mismatch() -> Option<String> {
    let install = format!(
        "install {GITLEAKS_VERSION} (mise: \"aqua:gitleaks/gitleaks\" = \"{GITLEAKS_VERSION}\")"
    );
    let output = match Command::new("gitleaks").arg("version").output() {
        Ok(output) => output,
        Err(error) => return Some(format!("could not run gitleaks version: {error}")),
    };
    let said = String::from_utf8_lossy(&output.stdout);
    let said = said.trim();
    if !output.status.success() {
        return Some(format!(
            "`gitleaks version` did not answer, so which rule list would run is unknown; \
             {install}"
        ));
    }
    if said.strip_prefix('v').unwrap_or(said) == GITLEAKS_VERSION {
        return None;
    }
    Some(format!(
        "gitleaks on PATH says {said:?} and this uphold is pinned to {GITLEAKS_VERSION}; \
         another version is another rule list, so this was not checked. {install}"
    ))
}

/// gitleaks' could-not-look, which its own exit code names once the finding
/// has been moved off `1`: anything but `0` and [`GITLEAKS_FOUND`] is a scan
/// that did not finish, the partial scan included.
fn gitleaks_could_not_look(code: i32, _stdout: &str, stderr: &str) -> Option<String> {
    if matches!(code, 0 | GITLEAKS_FOUND) {
        return None;
    }
    Some(format!(
        "gitleaks exited {code} without a verdict, so the range was not fully read: {}",
        first_said(stderr)
    ))
}

/// A file that exists for one child process and is removed on the way out.
///
/// Hand-rolled rather than a crate, because this is the only place the binary
/// needs one and the contract is short: named, filled, handed to one command,
/// gone. The part of it a crate would have done unasked is that the name lives
/// in a temporary directory everyone on the machine can write to, so that part
/// is spelled out in `TempFile::containing`.
mod tempfile_guard {
    use std::io::{ErrorKind, Write as _};
    use std::path::{Path, PathBuf};

    use crate::error::{Fatal, Result};

    /// How many names are drawn before a taken one stops reading as bad luck
    /// and starts reading as somebody else writing into the directory.
    const ATTEMPTS: usize = 16;

    pub(super) struct TempFile {
        pub path: PathBuf,
    }

    impl TempFile {
        /// A new file in the temporary directory holding `text`.
        ///
        /// The name was the process id and a counter, which anyone on the
        /// machine can work out, and the file was filled with `fs::write`,
        /// which opens whatever already sits at the path: a link planted there
        /// first was followed, and its target truncated and overwritten with a
        /// scanner's configuration, at whatever mode the umask left -- usually
        /// world-readable. Now the file is created with `create_new`, which
        /// refuses any path that exists, a dangling link included, and on unix
        /// it is created readable by its owner alone. That refusal is what
        /// keeps a planted file from being adopted; the clock in the name only
        /// makes a planted one rarer, and a name that is taken is a reason to
        /// draw another, a bounded number of times, and never to open it.
        pub(super) fn containing(text: &str) -> Result<Self> {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let directory = std::env::temp_dir();
            let names = std::iter::repeat_with(|| {
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |since| since.as_nanos());
                directory.join(format!(
                    "uphold-supply-{}-{stamp}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ))
            });
            Self::first_free(&directory, names, text)
        }

        /// The first of `names` that did not exist, created and filled.
        ///
        /// Apart from `containing` so a test can choose the names, and so
        /// plant something on them first.
        pub(super) fn first_free(
            directory: &Path,
            names: impl IntoIterator<Item = PathBuf>,
            text: &str,
        ) -> Result<Self> {
            for path in names.into_iter().take(ATTEMPTS) {
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
                match options.open(&path) {
                    Ok(mut file) => {
                        // Owned before it is filled, so a write that fails
                        // still removes the file on the way out.
                        let made = Self { path };
                        file.write_all(text.as_bytes())
                            .map_err(|error| Fatal::at(&made.path, error))?;
                        return Ok(made);
                    }
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(Fatal::at(&path, error)),
                }
            }
            Err(Fatal::at(
                directory,
                format!(
                    "{ATTEMPTS} temporary file names in a row were already taken, so something \
                     else is writing here and none of them was opened. Point TMPDIR at a \
                     directory only you can write to"
                ),
            ))
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
    use super::{
        BTreeSet, Ledger, Nested, NestedFound, NestedPolicy, Read, Waivers, guarddog_read,
        nested_waivers, tolerated,
    };
    use super::{
        DENY_FLOOR, Floor, GITLEAKS_DEFAULT, GITLEAKS_FOUND, GITLEAKS_VERSION, GUARDDOG_FLOOR,
        OSV_FLOOR, PRUNE, Scope, VET_FLOOR, Version, ZIZMOR_FLOOR, against_floor, find_named,
        find_workflow_dirs, gitleaks_could_not_look, guarddog_unpacks_under, interesting,
        parse_version, unscanned_ci,
    };
    use crate::config::{Policy, Waiver};

    /// guarddog 3.2.0's reports, recorded against the public registries with
    /// only the unpack path rewritten: react-dom 19.2.0, whose registry
    /// manifest carries npm's default `start`, swagger-ui-express 5.0.1, whose
    /// `test` lost its leading `./node_modules/.bin/` at publish, and pandas
    /// 3.0.3 on a host where the rule reached its `pyproject.toml`.
    const REACT_DOM: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/guarddog/npm-react-dom-19.2.0.json"
    ));
    const SWAGGER_UI_EXPRESS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/guarddog/npm-swagger-ui-express-5.0.1.json"
    ));
    const PANDAS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/guarddog/pypi-pandas-3.0.3.json"
    ));

    /// `report` with its one risk's description replaced, as guarddog would
    /// print it for a release that differed in that way.
    fn describing(report: &str, description: &str) -> String {
        let mut value: serde_json::Value = serde_json::from_str(report).unwrap();
        value[0]["result"]["risks"][0]["threat_description"] = serde_json::Value::from(description);
        value.to_string()
    }

    /// Whether `report`, read as one run with no waivers, holds a finding, or
    /// what was said where it did not read at all.
    fn objected(ecosystem: &str, report: &str) -> Result<bool, String> {
        let read = guarddog_read(
            "web",
            ecosystem,
            &BTreeSet::new(),
            &Waivers::default(),
            &mut Ledger::default(),
            Some(0),
            report,
            "",
            &mut |_, _| Err(String::from("no registry evidence in this fixture")),
        );
        match read {
            Read::Risks(..) => Ok(true),
            Read::Clean => Ok(false),
            Read::Unread(said) => Err(said),
        }
    }

    const HEADER: &str = "Difference between manifest and package.json found: \n";
    const START: &str = "  start: Manifest(\"node server.js\"), package.json(\"None\") \n";

    /// Each publish-time normalization on its own is tolerated, in the report
    /// guarddog printed for a real release, and named.
    #[test]
    fn a_mismatch_that_is_only_npms_publish_rewrite_is_tolerated_and_named() {
        assert_eq!(objected("npm", REACT_DOM), Ok(false));
        assert_eq!(objected("npm", SWAGGER_UI_EXPRESS), Ok(false));
        assert_eq!(
            tolerated(&format!("{HEADER}scripts: \n{START}")),
            Some(vec![String::from(
                "npm default start script (scripts.start = \"node server.js\")"
            )])
        );
        assert_eq!(
            tolerated(&format!(
                "{HEADER}scripts: \n  test: Manifest(\"mocha t\"), \
                 package.json(\"node_modules/.bin/mocha t\") \n"
            )),
            Some(vec![String::from(
                "npm strips a leading node_modules/.bin/ (scripts.test = \"mocha t\")"
            )])
        );
    }

    /// Guarddog repeats the mismatch in `results` and on its risk. A risk's
    /// description alone cannot excuse a different underlying result.
    #[test]
    fn npm_tolerance_requires_the_result_and_risk_to_agree() {
        let mut report: serde_json::Value = serde_json::from_str(REACT_DOM).unwrap();
        report[0]["result"]["results"]["metadata_mismatch"] = serde_json::Value::from(format!(
            "{HEADER}scripts: \n  postinstall: Manifest(\"node evil.js\"), \
                 package.json(\"None\") \n"
        ));
        assert_eq!(objected("npm", &report.to_string()), Ok(true));

        report[0]["result"]["results"]
            .as_object_mut()
            .unwrap()
            .remove("metadata_mismatch");
        assert_eq!(objected("npm", &report.to_string()), Ok(true));
    }

    /// A normalization alongside any other difference is still a finding: the
    /// tolerance is for a risk that is nothing but npm's rewrites.
    #[test]
    fn a_normalization_beside_any_other_difference_is_still_a_finding() {
        for description in [
            // A second script that differs.
            format!(
                "{HEADER}scripts: \n{START}  postinstall: Manifest(\"node x.js\"), \
                 package.json(\"None\") \n"
            ),
            // A dependency that differs, which describe_diff prints first.
            format!(
                "{HEADER}dependencies: \n  left-pad: Manifest(\"1.0.0\"), \
                 package.json(\"None\") \nscripts: \n{START}"
            ),
            // A `main` that differs, printed after `scripts`.
            format!(
                "{HEADER}scripts: \n{START}main: \n  Manifest:\n    index.js\n  \
                 package.json:\n    evil.js\n"
            ),
            // A `start` npm did not write.
            format!(
                "{HEADER}scripts: \n  start: Manifest(\"node evil.js\"), \
                 package.json(\"None\") \n"
            ),
            // The default `start` where the tarball has one of its own.
            format!(
                "{HEADER}scripts: \n  start: Manifest(\"node server.js\"), \
                 package.json(\"node other.js\") \n"
            ),
            // The default under another key.
            format!(
                "{HEADER}scripts: \n  postinstall: Manifest(\"node server.js\"), \
                 package.json(\"None\") \n"
            ),
        ] {
            assert_eq!(tolerated(&description), None, "{description}");
            assert_eq!(
                objected("npm", &describing(REACT_DOM, &description)),
                Ok(true),
                "{description}"
            );
        }
    }

    /// `./node_modules/.bin/` is stripped by npm only at the start of a
    /// script, once; the same text anywhere else, or a script that differs in
    /// more than that prefix, is a finding.
    #[test]
    fn a_bin_prefix_removed_anywhere_but_the_start_is_still_a_finding() {
        for (registry, tarball) in [
            ("nyc mocha t", "nyc ./node_modules/.bin/mocha t"),
            ("mocha t", "./node_modules/.bin/mocha t && curl x | sh"),
            ("mocha t", "../node_modules/.bin/mocha t"),
            ("mocha t", "./node_modules/.bin/mocha  t"),
            ("./node_modules/.bin/mocha t", "mocha t"),
        ] {
            let description = format!(
                "{HEADER}scripts: \n  test: Manifest(\"{registry}\"), \
                 package.json(\"{tarball}\") \n"
            );
            assert_eq!(tolerated(&description), None, "{description}");
            assert_eq!(
                objected("npm", &describing(SWAGGER_UI_EXPRESS, &description)),
                Ok(true),
                "{description}"
            );
        }
    }

    /// A description this cannot read line by line as single differences is a
    /// finding, because its values are not escaped and a line that splits two
    /// ways could hide a difference behind a tolerated one.
    #[test]
    fn a_description_line_that_does_not_read_as_one_difference_is_still_a_finding() {
        for description in [
            String::new(),
            String::from("start script differs"),
            format!("{HEADER}scripts: \n"),
            format!("{HEADER}scripts: \n{START}something guarddog never prints\n"),
            // A value that spans lines.
            format!(
                "{HEADER}scripts: \n  test: Manifest(\"mocha\nt\"), \
                 package.json(\"./node_modules/.bin/mocha\nt\") \n"
            ),
            // A marker inside a value, so the line splits more than one way.
            format!(
                "{HEADER}scripts: \n  start: Manifest(\"node server.js\"), \
                 package.json(\"None\"), package.json(\"x\") \n"
            ),
            format!(
                "{HEADER}scripts: \n  start: Manifest(\"a: Manifest(\"node server.js\"), \
                 package.json(\"None\") \n"
            ),
            // A key holding the marker: the script `start: Manifest("Z` is
            // `curl x | sh` in the registry, and split at the first marker it
            // would read as `start` losing a `.bin` prefix.
            format!(
                "{HEADER}scripts: \n  start: Manifest(\"Z: Manifest(\"curl x | sh\"), \
                 package.json(\"./node_modules/.bin/Z: Manifest(\"curl x | sh\") \n"
            ),
        ] {
            assert_eq!(tolerated(&description), None, "{description:?}");
            assert_eq!(
                objected("npm", &describing(REACT_DOM, &description)),
                Ok(true),
                "{description:?}"
            );
        }
        // A risk with no description at all.
        let mut bare: serde_json::Value = serde_json::from_str(REACT_DOM).unwrap();
        bare[0]["result"]["risks"][0]
            .as_object_mut()
            .unwrap()
            .remove("threat_description");
        assert_eq!(objected("npm", &bare.to_string()), Ok(true));
    }

    /// Without release evidence, the dropped `extra ==` markers cannot be
    /// recovered from the report. An npm-shaped `PyPI` report also stays a finding.
    #[test]
    fn pypi_metadata_mismatch_is_not_tolerated() {
        assert_eq!(objected("pypi", PANDAS), Ok(true));
        let npm_shaped = describing(PANDAS, &format!("{HEADER}scripts: \n{START}"));
        assert_eq!(objected("pypi", &npm_shaped), Ok(true));
    }

    #[test]
    fn pypi_extras_need_release_evidence_and_agreeing_reports() {
        let mut report: serde_json::Value = serde_json::from_str(PANDAS).unwrap();
        let description = "Dependency mismatch between PyPI metadata and pyproject.toml:\n  In PyPI metadata but NOT in pyproject.toml: pyarrow\n";
        report[0]["result"]["results"]["metadata_mismatch"] = description.into();
        report[0]["result"]["risks"][0]["threat_description"] = description.into();
        for (requirements, clean) in [
            (vec!["pyarrow>=13; extra == 'parquet'"], true),
            (vec!["pyarrow>=13"], false),
            (vec!["pyarrow; extra == 'parquet'", "pyarrow"], false),
        ] {
            let read = guarddog_read(
                "project",
                "pypi",
                &BTreeSet::from([String::from("pandas")]),
                &Waivers::default(),
                &mut Ledger::default(),
                Some(0),
                &report.to_string(),
                "",
                &mut |name, version| {
                    assert_eq!((name, version), ("pandas", "3.0.3"));
                    Ok(serde_json::json!({"info": {
                        "name": name, "version": version, "requires_dist": requirements,
                    }}))
                },
            );
            assert_eq!(matches!(read, Read::Clean), clean);
        }
        report[0]["result"]["results"]["metadata_mismatch"] = "different evidence".into();
        let mut fetched = false;
        let read = guarddog_read(
            "project",
            "pypi",
            &BTreeSet::new(),
            &Waivers::default(),
            &mut Ledger::default(),
            Some(0),
            &report.to_string(),
            "",
            &mut |_, _| {
                fetched = true;
                Err(String::from("unexpected lookup"))
            },
        );
        assert!(matches!(read, Read::Risks(..)));
        assert!(!fetched);
    }

    #[test]
    fn verified_pypi_extras_leave_unrelated_risks_counted() {
        let mut report: serde_json::Value = serde_json::from_str(PANDAS).unwrap();
        for other_risk in [false, true] {
            if other_risk {
                report[0]["result"]["risks"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({"threat_rule": "typosquatting"}));
            }
            let read = guarddog_read(
                "project",
                "pypi",
                &BTreeSet::from([String::from("pandas")]),
                &Waivers::default(),
                &mut Ledger::default(),
                Some(0),
                &report.to_string(),
                "",
                &mut |_, _| {
                    Ok(serde_json::from_str(include_str!(
                        "../tests/fixtures/guarddog/pypi-pandas-3.0.3-metadata.json"
                    ))
                    .unwrap())
                },
            );
            assert_eq!(matches!(read, Read::Risks(..)), other_risk);
            assert_eq!(matches!(read, Read::Clean), !other_risk);
        }
    }

    // ── a nested repository's own waivers ──

    /// A waiver as a policy file would carry it.
    fn waiver(package: &str, check: &str, reason: &str) -> Waiver {
        Waiver {
            scanner: String::from("guarddog"),
            package: String::from(package),
            check: String::from(check),
            reason: String::from(reason),
        }
    }

    /// A scan root that exists only as a path: the walk is lexical, and every
    /// question it asks of the disk goes through the loader.
    const SUPER: &str = "/srv/example/superproject";

    /// A loader standing in for `uphold`'s discovery: a policy carrying one
    /// `typosquatting` waiver on `npm:left-pad@1.3.0` at each directory in
    /// `owners`, a load that fails at each in `broken`, and nothing elsewhere.
    /// Every directory it is asked about is recorded, so a test can assert
    /// where the walk went as well as what it found.
    fn loader<'a>(
        owners: &'a [&'a str],
        broken: &'a [&'a str],
        asked: &'a std::cell::RefCell<Vec<std::path::PathBuf>>,
    ) -> impl Fn(&std::path::Path) -> crate::error::Result<Option<(std::path::PathBuf, Policy)>> + 'a
    {
        move |directory| {
            asked.borrow_mut().push(directory.to_path_buf());
            let relative = directory.strip_prefix(SUPER).unwrap_or(directory);
            let path = directory.join("policy/principles.toml");
            if broken.iter().any(|at| std::path::Path::new(at) == relative) {
                return Err(crate::error::Fatal::at(&path, "is not valid TOML"));
            }
            if !owners.iter().any(|at| std::path::Path::new(at) == relative) {
                return Ok(None);
            }
            let mut policy = Policy::default();
            policy.supply_chain.waive = vec![waiver(
                "npm:left-pad@1.3.0",
                "typosquatting",
                &format!("judged by {}", relative.display()),
            )];
            Ok(Some((path, policy)))
        }
    }

    /// The policy file whose waivers `nested_waivers` gave a manifest in
    /// `directory`, or `None` where it gave only the root's.
    fn owner_of(directory: &str, nested: NestedPolicy<'_>) -> Result<Option<String>, String> {
        let root = std::path::Path::new(SUPER);
        nested_waivers(root, &root.join(directory), nested, &mut NestedFound::new())
            .map(|found| found.map(|owner| owner.source.clone()))
    }

    /// The boundary, in both directions. A nested repository's waivers reach
    /// the manifests in its own tree and none outside it: not the scan root's
    /// own, not a sibling's, and not a directory whose name merely begins with
    /// the repository's -- `std::path::Path::starts_with` is by component, and this is
    /// the case that would break if it were ever done on text.
    #[test]
    fn a_nested_repositorys_waivers_reach_its_own_tree_and_nothing_outside_it() {
        let asked = std::cell::RefCell::new(Vec::new());
        let nested = loader(&["leaf"], &[], &asked);
        for (directory, expected) in [
            ("leaf", Some("leaf/policy/principles.toml")),
            ("leaf/web", Some("leaf/policy/principles.toml")),
            ("leaf/packages/ui", Some("leaf/policy/principles.toml")),
            ("web", None),
            ("", None),
            ("sibling", None),
            ("sibling/web", None),
            ("leaf-two/web", None),
        ] {
            assert_eq!(
                owner_of(directory, &nested),
                Ok(expected.map(String::from)),
                "{directory:?}"
            );
        }
        // The root is never asked: its policy is the one the run was started
        // under, and answering it again as a "nested" one would print the
        // root's own rows under a second name.
        assert!(
            asked
                .borrow()
                .iter()
                .all(|at| at != std::path::Path::new(SUPER)),
            "{:?}",
            asked.borrow()
        );
    }

    /// The nearest repository with a policy decides, and a repository without
    /// one is passed over rather than stopped at, so the next one out -- which
    /// carries it in its own tree -- is the one whose rows apply.
    #[test]
    fn the_nearest_enclosing_repository_with_a_policy_is_the_one_whose_waivers_apply() {
        let asked = std::cell::RefCell::new(Vec::new());
        let nested = loader(&["outer", "outer/inner"], &[], &asked);
        for (directory, expected) in [
            ("outer/inner/web", "outer/inner/policy/principles.toml"),
            ("outer/web", "outer/policy/principles.toml"),
            // `outer/bare` stands for a repository root with no policy: the
            // loader answers `None` there as `uphold`'s discovery does.
            ("outer/bare/web", "outer/policy/principles.toml"),
        ] {
            assert_eq!(
                owner_of(directory, &nested),
                Ok(Some(String::from(expected))),
                "{directory:?}"
            );
        }
    }

    /// A nested policy that will not load is an error naming the manifest and
    /// the repository, never "no waivers": the findings it would have judged
    /// cannot be told apart from the ones it accepted.
    #[test]
    fn a_nested_policy_that_will_not_load_is_an_error_and_never_no_waivers() {
        let asked = std::cell::RefCell::new(Vec::new());
        let nested = loader(&["leaf"], &["leaf/inner"], &asked);
        let said = owner_of("leaf/inner/web", &nested).unwrap_err();
        assert!(
            said.contains("/srv/example/superproject/leaf/inner/web"),
            "{said}"
        );
        assert!(said.contains("did not load"), "{said}");
        assert!(said.contains("is not valid TOML"), "{said}");
        // A sibling of the broken repository is judged as before.
        assert_eq!(
            owner_of("leaf/web", &nested),
            Ok(Some(String::from("leaf/policy/principles.toml")))
        );
    }

    /// A report naming one `typosquatting` risk on `left-pad` at `version`.
    fn typosquat(version: &str) -> String {
        serde_json::json!([{
            "dependency": "left-pad",
            "result": {
                "errors": {}, "issues": 1, "results": {}, "package_version": version,
                "risks": [{"name": "typosquatting", "threat_rule": "typosquatting"}],
            },
        }])
        .to_string()
    }

    /// `guarddog_read` over [`typosquat`] at `version`, against the root's
    /// `root` and the nested repository's `nested`, and what it recorded.
    fn judged(version: &str, root: &[Waiver], nested: Option<&Nested>) -> (Read, Ledger) {
        let mut ledger = Ledger::default();
        let read = guarddog_read(
            "leaf/web",
            "npm",
            &BTreeSet::from([String::from("left-pad")]),
            &Waivers { root, nested },
            &mut ledger,
            Some(0),
            &typosquat(version),
            "",
            &mut |_, _| Err(String::from("no registry evidence in this fixture")),
        );
        (read, ledger)
    }

    /// The nested repository's own row covers the risk, and a root row that
    /// also covers it is recorded as its copy rather than as a match, so the
    /// stale report can say the copy may go.
    #[test]
    fn a_nested_waiver_covers_first_and_a_root_row_for_the_same_risk_is_its_copy() {
        let leaf = Nested {
            source: String::from("leaf/policy/principles.toml"),
            waive: vec![waiver("npm:left-pad@1.3.0", "typosquatting", "the leaf's")],
        };
        let root = [waiver("npm:left-pad@1.3.0", "typosquatting", "the copy")];
        let (both, copied) = judged("1.3.0", &root, Some(&leaf));
        assert!(matches!(both, Read::Clean));
        assert!(copied.matched.is_empty(), "{:?}", copied.matched);
        assert_eq!(
            copied.duplicated.get(&0).map(String::as_str),
            Some("leaf/policy/principles.toml")
        );

        // Keyed on the version as a root row is: the next release is read
        // fresh, whoever wrote the row.
        let (next, fresh) = judged("1.3.1", &[], Some(&leaf));
        assert!(matches!(next, Read::Risks(..)));
        assert!(fresh.duplicated.is_empty());

        // And with no nested repository, the root's row is the match it was.
        let (alone, rooted) = judged("1.3.0", &root, None);
        assert!(matches!(alone, Read::Clean));
        assert_eq!(rooted.matched, BTreeSet::from([0]));
        assert!(rooted.duplicated.is_empty());
    }

    /// guarddog unpacks under the cache directory, whatever `TMPDIR` says: the
    /// order its `metadata_mismatch` rule lists an unpacked wheel in is that
    /// filesystem's, so `TMPDIR` would otherwise be the verdict's input.
    #[test]
    fn guarddog_unpacks_under_the_cache_directory_and_never_under_tmpdir() {
        let under = |xdg: Option<&str>, home: Option<&str>| {
            guarddog_unpacks_under(|name| match name {
                "XDG_CACHE_HOME" => xdg.map(std::path::PathBuf::from),
                "HOME" => home.map(std::path::PathBuf::from),
                "TMPDIR" => Some(std::path::PathBuf::from("/tmp/elsewhere")),
                _ => None,
            })
        };
        assert_eq!(
            under(Some("/x/cache"), Some("/srv/example/user")).as_deref(),
            Some(std::path::Path::new("/x/cache/uphold/guarddog"))
        );
        // Empty and relative are both "not set": a relative one would unpack
        // downloads into the manifest's directory, which guarddog runs in.
        for xdg in [None, Some(""), Some("cache")] {
            assert_eq!(
                under(xdg, Some("/srv/example/user")).as_deref(),
                Some(std::path::Path::new(
                    "/srv/example/user/.cache/uphold/guarddog"
                )),
                "{xdg:?}"
            );
        }
        assert_eq!(under(None, None), None);
        assert_eq!(under(Some("cache"), Some("home")), None);
    }

    /// Every floor, for the tests that hold them all to one rule.
    const FLOORS: [&Floor; 5] = [
        &OSV_FLOOR,
        &ZIZMOR_FLOOR,
        &DENY_FLOOR,
        &VET_FLOOR,
        &GUARDDOG_FLOOR,
    ];

    /// What each scanner printed for its version command on the host the
    /// readers were measured on, byte for byte, paired with the floor it
    /// answers. osv-scanner's is the multi-line one: its own version first,
    /// then the osv-scalibr library's, which is not the tool's.
    const REAL_ANSWERS: [(&Floor, &str, Version); 5] = [
        (
            &OSV_FLOOR,
            "osv-scanner version: 2.5.1\nosv-scalibr version: 0.5.2\ncommit: n/a\nbuilt at: n/a\n",
            Version(2, 5, 1),
        ),
        (&ZIZMOR_FLOOR, "zizmor 1.30.0\n", Version(1, 30, 0)),
        (&DENY_FLOOR, "cargo-deny 0.20.2\n", Version(0, 20, 2)),
        (&VET_FLOOR, "cargo-vet 0.10.2\n", Version(0, 10, 2)),
        (&GUARDDOG_FLOOR, "3.2.0\n", Version(3, 2, 0)),
    ];

    #[test]
    fn each_scanners_real_version_answer_parses_to_its_own_release() {
        for (floor, said, want) in REAL_ANSWERS {
            assert_eq!(parse_version(said), Some(want), "{}: {said:?}", floor.tool);
            // And the release the readers were measured on is not refused.
            assert_eq!(against_floor(floor, said), None, "{}", floor.tool);
        }
    }

    /// The floors ARE the versions in the fixtures above: a floor raised
    /// without re-measuring the reader, or a reader re-measured without
    /// raising its floor, fails here rather than on somebody's push.
    #[test]
    fn each_floor_is_the_release_its_reader_was_measured_against() {
        for (floor, _, measured) in REAL_ANSWERS {
            assert_eq!(floor.oldest, measured, "{}", floor.tool);
        }
    }

    #[test]
    fn versions_compare_as_numbers_not_as_text() {
        assert!(parse_version("zizmor 1.100.0") > parse_version("zizmor 1.30.0"));
        assert_eq!(parse_version("v2.5.1"), Some(Version(2, 5, 1)));
        assert_eq!(parse_version("zizmor 1.30.0-rc1"), Some(Version(1, 30, 0)));
        assert_eq!(
            parse_version("guarddog 3.2.0+local"),
            Some(Version(3, 2, 0))
        );
        // Newer on every axis passes.
        for said in ["zizmor 1.30.1", "zizmor 1.31.0", "zizmor 2.0.0"] {
            assert_eq!(against_floor(&ZIZMOR_FLOOR, said), None, "{said}");
        }
    }

    /// Older than the floor is could-not-look, and the reason names the tool,
    /// the version found and the floor -- the three facts a reader needs to
    /// know what to install.
    #[test]
    fn a_release_below_the_floor_is_refused_naming_the_tool_what_was_found_and_the_floor() {
        for (floor, said) in [
            (&ZIZMOR_FLOOR, "zizmor 1.29.9"),
            (
                &OSV_FLOOR,
                "osv-scanner version: 1.9.2\nosv-scalibr version: 9.9.9",
            ),
            (&DENY_FLOOR, "cargo-deny 0.19.0"),
            (&VET_FLOOR, "cargo-vet 0.10.1"),
            (&GUARDDOG_FLOOR, "2.9.0"),
        ] {
            let reason = against_floor(floor, said).unwrap_or_default();
            let found = parse_version(said).unwrap().to_string();
            assert!(reason.contains(floor.tool), "{reason}");
            assert!(reason.contains(&found), "{reason}");
            assert!(reason.contains(&floor.oldest.to_string()), "{reason}");
            assert!(reason.contains("was not checked"), "{reason}");
        }
    }

    /// A version nobody can read is not a pass: the reader downstream would be
    /// matching text of a shape nobody knows.
    #[test]
    fn a_version_answer_this_cannot_read_is_refused_rather_than_trusted() {
        for said in [
            "",
            "guarddog",
            "3.2",
            "zizmor 1.x.0",
            "zizmor 1.30.0.1",
            "cargo-deny dev",
        ] {
            for floor in FLOORS {
                let reason = against_floor(floor, said).unwrap_or_default();
                assert!(reason.contains("printed no version"), "{said:?}: {reason}");
                assert!(reason.contains(&floor.oldest.to_string()), "{reason}");
            }
        }
    }

    #[test]
    fn the_documentation_names_every_scanner_floor() {
        for floor in FLOORS {
            let row = format!("| {} | `{}` |", floor.tool, floor.oldest);
            assert!(
                include_str!("../docs/REFERENCE.md").contains(&row),
                "docs/REFERENCE.md does not carry `{row}`, so a consumer reading it installs \
                 a {} this binary may refuse",
                floor.tool
            );
        }
    }

    /// The CI recipe installs every scanner a section reads, and the gitleaks
    /// this binary is pinned to: a recipe missing one is a scheduled job that
    /// exits 2 every week.
    #[test]
    fn the_ci_recipe_installs_every_scanner() {
        let reference = include_str!("../docs/REFERENCE.md");
        let start = reference.find("### A scheduled sweep in CI").unwrap_or(0);
        let recipe = reference
            .get(start..)
            .and_then(|rest| rest.split("```yaml").next())
            .unwrap_or_default();
        for floor in FLOORS {
            assert!(
                recipe.contains(&format!("{}\" = ", floor.tool)),
                "the CI recipe in docs/REFERENCE.md installs no {}",
                floor.tool
            );
        }
        let gitleaks = format!("\"aqua:gitleaks/gitleaks\" = \"{GITLEAKS_VERSION}\"");
        assert!(recipe.contains(&gitleaks), "{recipe}");
    }

    #[test]
    fn the_documentation_names_the_pinned_gitleaks() {
        let line = format!("\"aqua:gitleaks/gitleaks\" = \"{GITLEAKS_VERSION}\"");
        assert!(
            include_str!("../README.md").contains(&line),
            "README.md does not carry `{line}`, so a consumer following it installs a \
             gitleaks this binary refuses"
        );
        let named = format!("`{GITLEAKS_VERSION}`");
        assert!(
            include_str!("../docs/REFERENCE.md").contains(&named),
            "docs/REFERENCE.md does not name {named} as the pinned gitleaks"
        );
    }

    #[test]
    fn the_default_gitleaks_config_extends_upstream_and_declares_no_rule() {
        assert!(GITLEAKS_DEFAULT.contains("useDefault = true"));
        assert!(!GITLEAKS_DEFAULT.contains("[[rules]]"));
    }

    #[test]
    fn gitleaks_exit_1_is_a_scan_that_did_not_finish() {
        assert!(gitleaks_could_not_look(0, "", "").is_none());
        assert!(gitleaks_could_not_look(GITLEAKS_FOUND, "", "").is_none());
        assert!(gitleaks_could_not_look(1, "", "partial scan completed").is_some());
        assert!(gitleaks_could_not_look(126, "", "unknown flag").is_some());
    }

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

    /// CI configuration nothing scans is in scope, BECAUSE nothing scans it.
    ///
    /// Read as a list of what the five tools open, a pipeline definition
    /// belongs out of it. It is in for what the run prints when the range is
    /// empty: "nothing in this range that a scanner reads" is true of that
    /// file in a way the sentence does not mean and the reader would not hear.
    #[test]
    fn ci_configuration_no_scanner_reads_is_in_scope_so_the_run_can_say_so() {
        use std::path::Path;

        for path in [
            ".circleci/config.yml",
            ".circleci/scripts/deploy.sh",
            "sub/.circleci/config.yml",
            ".gitlab-ci.yml",
            "Jenkinsfile",
        ] {
            assert!(interesting(Path::new(path)), "{path}");
        }
        // A config file at a root is a config file for anything. Calling every
        // one of them unscanned CI would put the declaration on files no CI
        // runner ever reads, and a declaration nobody believes is noise.
        for path in ["deny.toml", "config.yml", "docs/config.yml", ".circleci"] {
            assert!(!interesting(Path::new(path)), "{path}");
        }
    }

    /// The declaration names every unscanned file, at any depth, and no
    /// vendored one.
    ///
    /// A missed submodule is a pipeline the run said nothing about, which is
    /// the silence the declaration exists to break; a vendored copy is a file
    /// nobody in this tree could scan even if a scanner existed.
    #[test]
    fn unscanned_ci_configuration_is_found_at_any_depth_and_not_inside_a_pruned_tree() {
        let root = crate::fixture::scratch("supply-unscanned-ci");
        for directory in [".circleci", "sub/.circleci", "vendor/.circleci"] {
            std::fs::create_dir_all(root.join(directory)).unwrap();
            std::fs::write(root.join(directory).join("config.yml"), "jobs:\n").unwrap();
        }
        std::fs::write(root.join(".gitlab-ci.yml"), "stages:\n").unwrap();
        std::fs::create_dir_all(root.join(".github/workflows")).unwrap();
        std::fs::write(root.join(".github/workflows/ci.yml"), "on: push\n").unwrap();

        let found = unscanned_ci(&root, &Scope::Whole).unwrap();
        assert_eq!(
            found
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<String>>(),
            [
                ".circleci/config.yml",
                ".gitlab-ci.yml",
                "sub/.circleci/config.yml"
            ]
        );
    }

    /// A directory that cannot be read poisons the enumeration.
    ///
    /// The failure this refuses is the one the whole crate exists to refuse: an
    /// unreadable directory that merely SHRINKS the result gives a scan that
    /// looked at part of the tree and reported on all of it -- a clean run over
    /// manifests nobody read. It has to be an error, so the section is COULD
    /// NOT LOOK and the run exits 2. The unscanned-CI walk is held to the same
    /// rule: a declaration that missed a file understates the gap.
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
        let ci = unscanned_ci(&root, &Scope::Whole);
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
        let ci = ci.unwrap_err().to_string();
        assert!(
            ci.contains("could not enumerate the tree looking for CI configuration"),
            "{ci}"
        );
        assert!(ci.contains("must not miss one"), "{ci}");
    }

    /// What `fs::write` did to a path somebody reached first: followed the
    /// link and overwrote its target, or truncated the file sitting there. A
    /// taken name is now passed over and the next one is used.
    #[cfg(unix)]
    #[test]
    fn a_temporary_file_never_opens_a_path_somebody_reached_first() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = crate::fixture::scratch("supply-tempfile");
        std::fs::create_dir_all(&root).unwrap();
        let planted = root.join("planted");
        std::fs::write(&planted, "planted\n").unwrap();
        let victim = root.join("victim");
        std::fs::write(&victim, "victim\n").unwrap();
        let linked = root.join("linked");
        std::os::unix::fs::symlink(&victim, &linked).unwrap();
        // A link to nothing is a path that exists as far as `create_new` is
        // concerned, and following it would create the file it points at.
        let dangling = root.join("dangling");
        let nowhere = root.join("nowhere");
        std::os::unix::fs::symlink(&nowhere, &dangling).unwrap();
        let free = root.join("free");

        let made = super::tempfile_guard::TempFile::first_free(
            &root,
            [planted.clone(), linked, dangling, free.clone()],
            "scanner configuration\n",
        )
        .unwrap();
        assert_eq!(made.path, free);
        assert_eq!(std::fs::read_to_string(&planted).unwrap(), "planted\n");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "victim\n");
        assert!(!nowhere.exists(), "a dangling link was followed");
        assert_eq!(
            std::fs::read_to_string(&free).unwrap(),
            "scanner configuration\n"
        );
        let bits = std::fs::metadata(&free).unwrap().permissions().mode();
        assert_eq!(bits & 0o777, 0o600, "mode {bits:o}");
        drop(made);
        assert!(!free.exists(), "the file outlived the guard");
    }

    /// Every name taken is somebody writing into the directory, and is said
    /// so rather than drawn from forever or settled by opening one of them.
    #[test]
    fn a_temporary_directory_with_every_name_taken_is_refused() {
        let root = crate::fixture::scratch("supply-tempfile-taken");
        std::fs::create_dir_all(&root).unwrap();
        let taken = root.join("taken");
        std::fs::write(&taken, "taken\n").unwrap();
        let error = super::tempfile_guard::TempFile::first_free(
            &root,
            std::iter::repeat(taken.clone()),
            "scanner configuration\n",
        )
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("already taken"), "{error}");
        assert_eq!(std::fs::read_to_string(&taken).unwrap(), "taken\n");
    }

    /// The path the scanners are actually handed, made the way they get it.
    #[test]
    fn a_temporary_file_holds_what_it_was_given_and_goes_with_its_guard() {
        let made = super::tempfile_guard::TempFile::containing("a config\n").unwrap();
        let path = made.path.clone();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "a config\n");
        drop(made);
        assert!(!path.exists(), "the file outlived the guard");
    }
}
