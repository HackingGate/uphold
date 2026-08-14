//! `uphold probe` -- can each declared hook actually refuse?
//!
//! A hook that cannot fail is indistinguishable, in every report anybody reads,
//! from a hook that keeps finding nothing. Both are a green tick, run after run,
//! for as long as nobody plants something the hook is supposed to catch. The
//! case this was written for is not hypothetical: a `gofmt` entry declared as
//! `gofmt -l .` can never exit non-zero, because `gofmt -l` PRINTS its findings
//! and exits 0. Two repositories in the fleet that produced this command had one.
//!
//! So the probe drives each hook to both verdicts, in a throwaway worktree:
//!
//! 1. plant a fixture the hook must refuse, run the hook ALONE, expect non-zero;
//! 2. put a clean fixture in the same place, run it again, expect zero.
//!
//! Isolation is what makes step 1 an answer about the hook rather than about the
//! stage: the runner is asked for that hook id and nothing else, so a non-zero
//! exit is that hook refusing and not a neighbour.
//!
//! WHERE THE FIXTURES COME FROM, and why they are not generated. uphold knows
//! what its own rules match and knows nothing at all about `gofmt`, `ruff` or a
//! hook somebody wrote this morning -- and the hooks worth probing are exactly
//! the ones it knows nothing about. A fixture is therefore written down, once,
//! by whoever declared the hook, in `policy/hooks.toml`. That is also the only
//! form in which the fixture is reviewable, which matters more than the typing
//! it saves.
//!
//! WHAT IT RUNS. The repository's own hooks, which is what was asked for, and
//! which means arbitrary programs the repository already trusts enough to run on
//! every commit. It happens in a `git worktree` at HEAD, never in the tree the
//! operator is standing in: a probe that planted a fixture in the working tree
//! would leave one behind the first time it was interrupted.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::error::{read_to_string, Exit, Fatal, Result};
use crate::pins::{declarations, Manager};

const PROBES: &str = "policy/hooks.toml";

#[derive(Debug, Default, Deserialize)]
struct ProbeFile {
    #[serde(default, rename = "probe")]
    probes: Vec<Probe>,
    /// The waivers `hooks --identity` reads. Named here so this file can hold
    /// both without `deny_unknown_fields` refusing the other one's table.
    #[serde(default, rename = "waive")]
    _waivers: Vec<toml::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    /// The hook id to drive, as the runner knows it.
    id: String,
    /// Where the fixture goes. Repository-relative, and it decides as much as
    /// the content does: a hook scoped to `*.go` says nothing about a file
    /// called `fixture.txt`.
    path: String,
    /// What this hook must refuse.
    refuses: String,
    /// What it must accept. Absent means only one verdict is driven, which the
    /// report says rather than passing off as both.
    #[serde(default)]
    allows: Option<String>,
    /// The stage to run the hook at. Absent means `pre-commit`, which is where
    /// most hooks live and is what every runner defaults to.
    #[serde(default)]
    stage: Option<String>,
}

/// What driving one hook to both verdicts found.
enum Verdict {
    /// Refused the fixture and accepted the clean tree. A demonstrated gate.
    Demonstrated,
    /// Refused the fixture, and no clean fixture was written to check the
    /// other direction.
    RefusedOnly,
    /// Accepted what it is supposed to refuse. The failure this exists for.
    CannotFail,
    /// Refused the clean fixture too, so it refuses everything and the refusal
    /// says nothing about what it was given.
    RefusesEverything,
}

/// `uphold probe`
pub(crate) fn run(root: &Path, runner: Option<&str>) -> Result<Exit> {
    let probes = probes(root)?;
    let runner = runner.map_or_else(|| detect(root), Runner::named)?;

    // Only the ids the CHOSEN runner can be asked for. A repository carrying
    // both managers declares each check twice, and asking prek for a lefthook
    // command name gets "no such hook" -- which this would otherwise read as a
    // hook that cannot fail.
    let declared: BTreeSet<String> = declarations(root)?
        .into_iter()
        .filter(|declaration| declaration.manager == runner.manager())
        .map(|declaration| declaration.id)
        .collect();

    // A probe naming a hook this repository does not declare drives nothing,
    // and reads as coverage while providing none -- the same failure a
    // `disabled_rules` entry naming nothing has.
    for probe in &probes {
        if !declared.contains(&probe.id) {
            return Err(Fatal::at(
                &root.join(PROBES),
                format!(
                    "the probe for `{}` names a hook no {} configuration here declares, so it \
                     would drive nothing while reading as though this hook had been \
                     demonstrated",
                    probe.id,
                    runner.manager().as_str()
                ),
            ));
        }
    }

    if probes.is_empty() {
        println!(
            "no `[[probe]]` in {PROBES}, so no hook here has been driven to a refusal. \
             {} hook(s) are declared, and a gate whose rejection path is never demonstrated \
             is not demonstrated to be a gate.",
            declared.len()
        );
        return Ok(Exit::Clean);
    }

    let worktree = Worktree::at(root)?;
    let mut results: Vec<(String, Verdict)> = Vec::new();
    for probe in &probes {
        results.push((probe.id.clone(), drive(&worktree, runner, probe)?));
    }
    drop(worktree);

    println!("{} hook(s) driven with {}", results.len(), runner.command());
    let mut failed = 0_usize;
    for (id, verdict) in &results {
        match verdict {
            Verdict::Demonstrated => println!("  {id}: refuses its fixture, accepts a clean one"),
            Verdict::RefusedOnly => println!(
                "  {id}: refuses its fixture. No `allows` fixture, so nothing here shows it \
                 accepts anything"
            ),
            Verdict::CannotFail => {
                failed += 1;
                eprintln!(
                    "  {id}: ACCEPTED what it is declared to refuse. A hook that cannot fail \
                     reports the same green tick as one that keeps finding nothing"
                );
            }
            Verdict::RefusesEverything => {
                failed += 1;
                eprintln!(
                    "  {id}: refused the clean fixture as well, so its refusal says nothing \
                     about what it was given"
                );
            }
        }
    }

    // The denominator, always. "Two hooks were probed" means one thing beside
    // two declarations and another beside twenty.
    let unprobed: Vec<&String> = declared
        .iter()
        .filter(|id| !probes.iter().any(|probe| probe.id == **id))
        .collect();
    if !unprobed.is_empty() {
        println!(
            "{} declared hook(s) have no probe, so nothing here shows they can refuse: {}",
            unprobed.len(),
            unprobed
                .iter()
                .map(|id| id.as_str())
                .collect::<Vec<&str>>()
                .join(", ")
        );
    }

    if failed > 0 {
        return Ok(Exit::Violations);
    }
    Ok(Exit::Clean)
}

/// Plant, run, clean, run.
fn drive(worktree: &Worktree, runner: Runner, probe: &Probe) -> Result<Verdict> {
    let stage = probe.stage.as_deref().unwrap_or("pre-commit");

    worktree.plant(&probe.path, &probe.refuses)?;
    let refused = runner.exit(worktree.path(), &probe.id, &probe.path, stage)?;
    if refused == 0 {
        worktree.remove(&probe.path)?;
        return Ok(Verdict::CannotFail);
    }

    let Some(allows) = probe.allows.as_deref() else {
        worktree.remove(&probe.path)?;
        return Ok(Verdict::RefusedOnly);
    };
    worktree.plant(&probe.path, allows)?;
    let accepted = runner.exit(worktree.path(), &probe.id, &probe.path, stage)?;
    worktree.remove(&probe.path)?;
    if accepted == 0 {
        Ok(Verdict::Demonstrated)
    } else {
        Ok(Verdict::RefusesEverything)
    }
}

/// Which runner drives the hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Runner {
    Prek,
    PreCommit,
    Lefthook,
}

impl Runner {
    fn named(name: &str) -> Result<Self> {
        match name {
            "prek" => Ok(Self::Prek),
            "pre-commit" => Ok(Self::PreCommit),
            "lefthook" => Ok(Self::Lefthook),
            other => Err(Fatal::new(format!(
                "unknown runner {other:?}; this drives prek, pre-commit or lefthook"
            ))),
        }
    }

    const fn command(self) -> &'static str {
        match self {
            Self::Prek => "prek",
            Self::PreCommit => "pre-commit",
            Self::Lefthook => "lefthook",
        }
    }

    const fn manager(self) -> Manager {
        match self {
            Self::Prek | Self::PreCommit => Manager::PreCommit,
            Self::Lefthook => Manager::Lefthook,
        }
    }

    /// Run one hook, alone, and return its exit code.
    ///
    /// Alone is the whole point: asked for one id, a non-zero exit is that
    /// hook refusing rather than a neighbour at the same stage, so nothing here
    /// has to parse a report to find out who spoke.
    fn exit(self, directory: &Path, id: &str, file: &str, stage: &str) -> Result<i32> {
        let mut command = detached(self.command(), directory);
        match self {
            // Two spellings of one flag, and there is no third answer: prek
            // took `--stage` where pre-commit has `--hook-stage`, and a probe
            // that guessed wrong would run the hook at a stage it does not
            // declare and report that it cannot fail.
            Self::Prek => {
                command.args(["run", id, "--stage", stage, "--files", file]);
            }
            Self::PreCommit => {
                command.args(["run", id, "--hook-stage", stage, "--files", file]);
            }
            Self::Lefthook => {
                command.args(["run", stage, "--commands", id, "--force"]);
            }
        }
        let output = command
            .output()
            .map_err(|error| Fatal::new(format!("could not run {}: {error}", self.command())))?;
        // A runner that died on a signal answered nothing. Reporting that as a
        // refusal would credit the hook with a verdict it never gave.
        output.status.code().ok_or_else(|| {
            Fatal::new(format!(
                "{} was killed while running `{id}`, so this hook gave no verdict",
                self.command()
            ))
        })
    }
}

/// Which runner this repository is configured for, and installed here.
///
/// Both halves, because either alone is a wrong answer: a repository with a
/// `lefthook.yml` and no lefthook on PATH cannot be probed, and a machine with
/// three runners installed says nothing about which one this repository uses.
fn detect(root: &Path) -> Result<Runner> {
    let mut configured: Vec<Runner> = Vec::new();
    if root.join(".pre-commit-config.yaml").is_file() {
        configured.push(Runner::Prek);
        configured.push(Runner::PreCommit);
    }
    if [
        "lefthook.yml",
        "lefthook.yaml",
        ".lefthook.yml",
        ".lefthook.yaml",
    ]
    .iter()
    .any(|name| root.join(name).is_file())
    {
        configured.push(Runner::Lefthook);
    }
    if configured.is_empty() {
        return Err(Fatal::new(
            "no hook configuration here, so there is nothing to drive. A repository with no \
             hooks and one whose hooks could not be run are different answers",
        ));
    }
    for runner in &configured {
        if which(runner.command()).is_some() {
            return Ok(*runner);
        }
    }
    Err(Fatal::new(format!(
        "this repository is configured for {}, and none of them is on PATH. A hook that \
         could not be run has not been shown to refuse anything",
        configured
            .iter()
            .map(|runner| runner.command())
            .collect::<Vec<&str>>()
            .join(" or ")
    )))
}

fn which(command: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(command))
        .find(|candidate| candidate.is_file())
}

/// A command with git's own environment taken away.
///
/// Found by running the test suite from inside a hook, which is where this
/// command is most likely to be used: a hook runner exports `GIT_INDEX_FILE`,
/// `GIT_DIR` and friends, several of them RELATIVE to the repository the hook
/// fired in. Inherited, they point every `git` this module runs -- and the hook
/// runner it drives -- at the wrong index, so the worktree could not be created
/// at all. Where it could, the staging would have been written into somebody
/// else's index, which is the same class of accident with none of the noise.
///
/// Stripped rather than overridden: the list of things git puts in an
/// environment is git's, and an override answers only for the names somebody
/// remembered.
fn detached(program: &str, directory: &Path) -> Command {
    let mut command = Command::new(program);
    command.current_dir(directory);
    for name in [
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_WORK_TREE",
        "GIT_PREFIX",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG_PARAMETERS",
    ] {
        command.env_remove(name);
    }
    command
}

/// A throwaway checkout of HEAD, removed when this goes out of scope.
///
/// Never the operator's own tree. A probe plants a file that a hook is meant to
/// refuse, and doing that where somebody is working leaves a planted fixture
/// behind the first time the run is interrupted -- in a tree whose hooks would
/// then refuse their next commit, for a reason nothing in the tree explains.
struct Worktree {
    root: PathBuf,
    path: PathBuf,
}

impl Worktree {
    fn at(root: &Path) -> Result<Self> {
        let path = std::env::temp_dir().join(format!("uphold-probe-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&path));
        let output = detached("git", root)
            .args(["worktree", "add", "--detach", "--quiet"])
            .arg(&path)
            .arg("HEAD")
            .output()
            .map_err(|error| Fatal::new(format!("could not add a worktree: {error}")))?;
        if !output.status.success() {
            return Err(Fatal::new(format!(
                "could not check out a throwaway worktree to probe in: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(Self {
            root: root.to_path_buf(),
            path,
        })
    }

    const fn path(&self) -> &PathBuf {
        &self.path
    }

    fn plant(&self, relative: &str, contents: &str) -> Result<()> {
        let file = self.path.join(relative);
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent).map_err(|error| Fatal::at(parent, error))?;
        }
        std::fs::write(&file, contents).map_err(|error| Fatal::at(&file, error))?;
        self.stage()
    }

    fn remove(&self, relative: &str) -> Result<()> {
        let file = self.path.join(relative);
        if file.exists() {
            std::fs::remove_file(&file).map_err(|error| Fatal::at(&file, error))?;
        }
        self.stage()
    }

    /// Staged, because that is the set lefthook runs over and the state
    /// pre-commit expects to be given.
    fn stage(&self) -> Result<()> {
        detached("git", &self.path)
            .args(["add", "-A"])
            .output()
            .map_err(|error| Fatal::new(format!("could not stage the fixture: {error}")))?;
        Ok(())
    }
}

impl Drop for Worktree {
    fn drop(&mut self) {
        // Both, and neither is checked: this runs while unwinding as well as
        // on the ordinary path, and a probe that panicked while reporting a
        // finding must not also panic on the way out and bury it.
        drop(
            detached("git", &self.root)
                .args(["worktree", "remove", "--force"])
                .arg(&self.path)
                .output(),
        );
        drop(std::fs::remove_dir_all(&self.path));
    }
}

fn probes(root: &Path) -> Result<Vec<Probe>> {
    let path = root.join(PROBES);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = read_to_string(&path)?;
    let parsed: ProbeFile = toml::from_str(&text).map_err(|error| Fatal::at(&path, error))?;
    for probe in &parsed.probes {
        if probe.refuses.trim().is_empty() {
            return Err(Fatal::at(
                &path,
                format!(
                    "the probe for `{}` has an empty `refuses`. An empty fixture demonstrates \
                     nothing, and a hook that accepted it would be reported as unable to fail",
                    probe.id
                ),
            ));
        }
    }
    Ok(parsed.probes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_runner_is_named_by_the_command_it_runs() {
        // The mapping is read in two directions -- a name from the command line
        // and a manager from the runner -- and a runner whose command and
        // manager disagreed would drive a lefthook config with prek.
        for (name, manager) in [
            ("prek", Manager::PreCommit),
            ("pre-commit", Manager::PreCommit),
            ("lefthook", Manager::Lefthook),
        ] {
            let runner = Runner::named(name).unwrap();
            assert_eq!(runner.command(), name);
            assert_eq!(runner.manager(), manager);
        }
        assert!(Runner::named("husky").is_err());
    }
}
