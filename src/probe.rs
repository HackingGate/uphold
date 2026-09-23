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
//!
//! THE ONE PROBE THAT IS NOT A RUNNER RUN. `push = "empty"` drives `git push`
//! itself, of a range with nothing in it, through whatever hooks git runs. The
//! pre-push delegate `hooks --install` writes exists for that range -- prek
//! skips its whole pre-push stage over it -- and a `<runner> run <id>` can
//! never reach the case, because the runner is the thing being stepped
//! around. The fixture for such a probe is a DESTINATION rather than a file:
//! an empty range carries no content for a hook to object to, so what a
//! pre-push guard judges is where the push is going, and `refuses` and
//! `allows` name one destination each.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::error::{Exit, Fatal, Result, read_to_string};
use crate::pins::{Manager, declarations};

const PROBES: &str = "policy/hooks.toml";

#[derive(Debug, Default, Deserialize)]
struct ProbeFile {
    #[serde(default, rename = "probe")]
    probes: Vec<Probe>,
    /// How long one hook run may take before it is called unmeasured, for
    /// every probe that does not carry its own. See [`Probe::timeout_seconds`].
    #[serde(default)]
    timeout_seconds: Option<u64>,
    /// The waivers `hooks --identity` reads. Named here so this file can hold
    /// both without `deny_unknown_fields` refusing the other one's table.
    #[serde(default, rename = "waive")]
    _waivers: Vec<toml::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    /// The hook id to drive, as the runner knows it. For a `push` probe, the
    /// name the report calls it by: what is driven is git's pre-push hook,
    /// which no runner's configuration declares.
    id: String,
    /// Where the fixture goes. Repository-relative, and it decides as much as
    /// the content does: a hook scoped to `*.go` says nothing about a file
    /// called `fixture.txt`. Required for a runner probe, refused for a `push`
    /// one, whose fixture is a destination and not a file.
    #[serde(default)]
    path: Option<String>,
    /// What this hook must refuse: file contents, or for a `push` probe the
    /// `owner/repo` of a destination.
    refuses: String,
    /// What it must accept. Absent means only one verdict is driven, which the
    /// report says rather than passing off as both.
    #[serde(default)]
    allows: Option<String>,
    /// `"empty"`: drive `git push` of an empty range to a throwaway bare
    /// remote already at the tip, through the hooks git runs, instead of
    /// `<runner> run <id>`. The only value, and a string rather than a bool
    /// so that a second shape of push can be named without a second field.
    #[serde(default)]
    push: Option<String>,
    /// The stage to run the hook at. Absent means `pre-commit`, which is where
    /// most hooks live and is what every runner defaults to.
    #[serde(default)]
    stage: Option<String>,
    /// Words the refusal must contain -- a rule id, a finding's own text.
    ///
    /// Without it a probe passes on a red that came from somewhere else: the
    /// planted fixture trips a NEIGHBOURING rule in the same hook, the hook it
    /// was written for silently stops matching, and the probe goes on
    /// reporting a demonstrated gate. Running the hook alone narrows the
    /// refusal to the hook; only the words narrow it to the rule. Measured
    /// before this existed, in the fleet that asked for it: a fixture written
    /// for a home-path rule was red under an unrelated whitespace fixer, and
    /// nothing said so.
    #[serde(default)]
    expect: Option<String>,
    /// How long one run may take before the hook is called UNMEASURED --
    /// exit 2, never a refusal and never a pass.
    ///
    /// A declared value rather than a constant compiled in here, because where
    /// it sits is an operator's call about the machines this runs on: long
    /// enough that a hook pulling a container image on a cold runner is not
    /// called a timeout, short enough that a hook which has wedged is not
    /// waited on all afternoon. Absent means the file-level default, and with
    /// neither the run waits, which is what it always did.
    #[serde(default)]
    timeout_seconds: Option<u64>,
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
    /// Refused, without the words the probe says the refusal must contain --
    /// a red that came from somewhere else, reported with what it did say.
    RefusedForAnotherReason { said: String },
    /// Still running when its time ran out. Not a refusal and not a pass: the
    /// hook was never measured, and the exit code says so.
    Unmeasured { after: u64 },
}

/// `uphold probe`
pub(crate) fn run(root: &Path, runner: Option<&str>, timeout: Option<u64>) -> Result<Exit> {
    let (probes, file_timeout) = probes(root)?;
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
    // `disabled_rules` entry naming nothing has. A push probe names no hook:
    // git's own pre-push is what it drives, and whether that reaches anything
    // is the verdict rather than a precondition.
    for probe in &probes {
        if probe.push.is_none() && !declared.contains(&probe.id) {
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
        // The nearest declaration wins: the flag is one operator's answer for
        // one run, the probe's own field is about one hook, the file's is
        // about the machines this repository runs on. With none of the three
        // the run waits, which is what it always did.
        let patience = timeout.or(probe.timeout_seconds).or(file_timeout);
        // Said in the report line, because the verdict words below are about
        // "its fixture", and for this probe the fixture is where a push went.
        let label = if probe.push.is_some() {
            format!("{} (git push of an empty range)", probe.id)
        } else {
            probe.id.clone()
        };
        results.push((label, drive(&worktree, runner, probe, patience)?));
    }
    drop(worktree);

    println!("{} hook(s) driven with {}", results.len(), runner.command());
    let mut failed = 0_usize;
    let mut unmeasured = 0_usize;
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
            Verdict::RefusedForAnotherReason { said } => {
                failed += 1;
                eprintln!(
                    "  {id}: refused its fixture WITHOUT the words `expect` names, so the red \
                     came from somewhere else and says nothing about the rule this probe is \
                     for. It said:\n{said}"
                );
            }
            Verdict::Unmeasured { after } => {
                unmeasured += 1;
                eprintln!(
                    "  {id}: still running after {after}s, so it was killed and never \
                     measured. Not a refusal and not a pass -- raise `timeout_seconds` if \
                     this machine is simply slow"
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

    // A violation outranks an unmeasured hook, and an unmeasured hook is
    // never a pass -- the same ranking every other command here answers with,
    // asked of the one function that owns it.
    Ok(crate::error::verdict(failed, unmeasured))
}

/// Plant, run, clean, run -- or, for a push probe, push to the destination
/// that must be refused and then to the one that must be allowed.
///
/// One verdict logic for both shapes. The push probe differs only in what a
/// fixture IS and what runs over it, and a second copy of the six verdicts
/// worded for a push would be two readings of the same pair of exit codes.
fn drive(
    worktree: &Worktree,
    runner: Runner,
    probe: &Probe,
    patience: Option<u64>,
) -> Result<Verdict> {
    let stage = probe.stage.as_deref().unwrap_or("pre-commit");
    let run = |fixture: &str| -> Result<Ran> {
        if probe.push.is_some() {
            return worktree.push_empty_range(fixture, patience);
        }
        // Validated at load, which is where a probe of this shape without a
        // path is refused.
        let path = probe.path.as_deref().unwrap_or_default();
        worktree.plant(path, fixture)?;
        let ran = runner.drive(worktree.path(), &probe.id, path, stage, patience);
        worktree.remove(path)?;
        ran
    };

    let refused = run(&probe.refuses)?;
    let Ran::Finished { code, output } = refused else {
        return Ok(Verdict::Unmeasured {
            after: patience.unwrap_or_default(),
        });
    };
    if code == 0 {
        return Ok(Verdict::CannotFail);
    }
    if let Some(expected) = probe.expect.as_deref()
        && !output.contains(expected)
    {
        // The tail rather than the head: runners print their banner first
        // and the finding last, and a reader shown only the banner would
        // have to run the probe again to learn what actually spoke.
        let tail: Vec<&str> = output.lines().rev().take(12).collect();
        let mut said = String::new();
        for line in tail.into_iter().rev() {
            said.push_str("    ");
            said.push_str(line);
            said.push('\n');
        }
        return Ok(Verdict::RefusedForAnotherReason { said });
    }

    let Some(allows) = probe.allows.as_deref() else {
        return Ok(Verdict::RefusedOnly);
    };
    let Ran::Finished { code: clean, .. } = run(allows)? else {
        return Ok(Verdict::Unmeasured {
            after: patience.unwrap_or_default(),
        });
    };
    if clean == 0 {
        Ok(Verdict::Demonstrated)
    } else {
        Ok(Verdict::RefusesEverything)
    }
}

/// One hook run's outcome: a verdict with its words, or no verdict at all.
enum Ran {
    Finished { code: i32, output: String },
    TimedOut,
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

    /// Run one hook, alone, and return its exit code with everything it said.
    ///
    /// Alone is the whole point: asked for one id, a non-zero exit is that
    /// hook refusing rather than a neighbour at the same stage. The words come
    /// back too, because `expect` narrows a refusal to the RULE the probe is
    /// about, and only the output holds the rule's name.
    fn drive(
        self,
        directory: &Path,
        id: &str,
        file: &str,
        stage: &str,
        patience: Option<u64>,
    ) -> Result<Ran> {
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
        let outcome = bounded(command, patience)
            .map_err(|error| Fatal::new(format!("could not run {}: {error}", self.command())))?;
        match outcome {
            Bounded::TimedOut => Ok(Ran::TimedOut),
            // A runner that died on a signal answered nothing. Reporting that
            // as a refusal would credit the hook with a verdict it never gave.
            Bounded::Exited { code: None, .. } => Err(Fatal::new(format!(
                "{} was killed while running `{id}`, so this hook gave no verdict",
                self.command()
            ))),
            Bounded::Exited {
                code: Some(code),
                output,
            } => Ok(Ran::Finished { code, output }),
        }
    }
}

/// What running a command under a deadline produced.
enum Bounded {
    Exited { code: Option<i32>, output: String },
    TimedOut,
}

/// Run one command to completion or to its deadline, whichever comes first.
///
/// The streams are drained on their own threads for the reason `shim::consult`
/// gives about its pipes: a hook that writes more than a bufferful blocks on a
/// pipe nobody empties, and a run that deadlocked would be reported as a
/// timeout -- a diagnosis about the hook for a failure that was here.
///
/// The wait is a poll rather than a blocking `wait`, because a blocking wait
/// has no deadline; fifty milliseconds is far below the run time of any hook
/// runner and far above the cost of `try_wait`.
fn bounded(mut command: Command, patience: Option<u64>) -> std::io::Result<Bounded> {
    use std::io::Read as _;
    use std::process::Stdio;

    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let mut child = command.spawn()?;

    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let readers = (
        std::thread::spawn(move || {
            let mut collected = Vec::new();
            if let Some(pipe) = stdout.as_mut() {
                drop(pipe.read_to_end(&mut collected));
            }
            collected
        }),
        std::thread::spawn(move || {
            let mut collected = Vec::new();
            if let Some(pipe) = stderr.as_mut() {
                drop(pipe.read_to_end(&mut collected));
            }
            collected
        }),
    );

    let deadline =
        patience.map(|seconds| std::time::Instant::now() + std::time::Duration::from_secs(seconds));
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            // Killed and then reaped, so a timed-out hook does not linger as a
            // zombie under a long report. The readers are NOT joined on this
            // path: a grandchild the kill did not reach can hold the pipe open
            // for as long as it likes, a join would wait on it for exactly the
            // time the deadline existed to bound, and an unmeasured verdict
            // has no use for the words. The threads end when the pipe closes,
            // or with this process.
            drop(child.kill());
            drop(child.wait());
            return Ok(Bounded::TimedOut);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };

    let mut output = readers.0.join().unwrap_or_default();
    output.extend(readers.1.join().unwrap_or_default());
    let output = String::from_utf8_lossy(&output).into_owned();
    Ok(Bounded::Exited {
        code: status.code(),
        output,
    })
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

/// Whether a command is reachable on PATH, for callers outside this module.
pub(crate) fn on_path(command: &str) -> bool {
    which(command).is_some()
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
/// The names are `git::REPOSITORY_ENVIRONMENT`, the one list this module and
/// the submodule reads in `supply` both strip: two copies of it would be two
/// answers to "what does git export", and the one nobody updated would be the
/// one a hook ran.
pub(crate) fn detached(program: &str, directory: &Path) -> Command {
    let mut command = Command::new(program);
    command.current_dir(directory);
    for name in crate::git::REPOSITORY_ENVIRONMENT {
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

    /// Where the throwaway remotes go: beside the worktree, removed with it.
    fn remotes(&self) -> PathBuf {
        self.path
            .with_file_name(format!("uphold-probe-{}-remotes", std::process::id()))
    }

    /// `git push` of an empty range to `owner/repo`, through the hooks git
    /// runs, and what that push said.
    ///
    /// The remote is a bare repository made here and brought to the
    /// worktree's tip with a push that skips the hooks, so the push that is
    /// measured has nothing to send. git still runs the pre-push hook for it,
    /// with the remote's name and url on argv and no ref line on stdin, which
    /// is the case the delegate `hooks --install` writes exists for.
    ///
    /// The destination's directory is `<owner>/<repo>.git`, so the url git
    /// hands the hook parses to the same `owner/repo` the guard would read off
    /// a forge url -- through the one parser both use. The remote is named on
    /// the command line with `-c`, never added to the repository's config:
    /// worktrees share it, and a remote left behind by an interrupted probe
    /// would be the operator's to find.
    fn push_empty_range(&self, destination: &str, patience: Option<u64>) -> Result<Ran> {
        const REMOTE: &str = "uphold-probe";
        let bare = self.remotes().join(format!("{destination}.git"));
        drop(std::fs::remove_dir_all(&bare));
        std::fs::create_dir_all(&bare).map_err(|error| Fatal::at(&bare, error))?;
        let made = detached("git", &bare)
            .args(["init", "--bare", "--quiet"])
            .output()
            .map_err(|error| Fatal::new(format!("could not make a bare remote: {error}")))?;
        if !made.status.success() {
            return Err(Fatal::at(
                &bare,
                format!(
                    "could not make a bare remote to push to: {}",
                    String::from_utf8_lossy(&made.stderr).trim()
                ),
            ));
        }
        let seeded = detached("git", &self.path)
            .args(["push", "--quiet", "--no-verify"])
            .arg(&bare)
            .arg("HEAD:refs/heads/probe")
            .output()
            .map_err(|error| Fatal::new(format!("could not seed the bare remote: {error}")))?;
        if !seeded.status.success() {
            return Err(Fatal::at(
                &bare,
                format!(
                    "could not bring the bare remote to the tip, so no push to it would \
                     have an empty range: {}",
                    String::from_utf8_lossy(&seeded.stderr).trim()
                ),
            ));
        }

        let mut command = detached("git", &self.path);
        command
            .arg("-c")
            .arg(format!("remote.{REMOTE}.url={}", bare.display()))
            .args(["push", REMOTE, "HEAD:refs/heads/probe"]);
        match bounded(command, patience)
            .map_err(|error| Fatal::new(format!("could not run git push: {error}")))?
        {
            Bounded::TimedOut => Ok(Ran::TimedOut),
            Bounded::Exited { code: None, .. } => Err(Fatal::new(format!(
                "git push to {destination} was killed, so the hooks it runs gave no verdict"
            ))),
            Bounded::Exited {
                code: Some(code),
                output,
            } => Ok(Ran::Finished { code, output }),
        }
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
        drop(std::fs::remove_dir_all(self.remotes()));
    }
}

fn probes(root: &Path) -> Result<(Vec<Probe>, Option<u64>)> {
    let path = root.join(PROBES);
    if !path.is_file() {
        return Ok((Vec::new(), None));
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
        // The same argument as an empty `refuses`, from the other side: an
        // empty `expect` is contained by every refusal, so it asserts nothing
        // while reading as though the rule had been named.
        if probe
            .expect
            .as_deref()
            .is_some_and(|expected| expected.trim().is_empty())
        {
            return Err(Fatal::at(
                &path,
                format!(
                    "the probe for `{}` has an empty `expect`. Every refusal contains the \
                     empty string, so it would assert nothing while reading as though the \
                     refusal had been pinned to a rule",
                    probe.id
                ),
            ));
        }
        if probe.timeout_seconds == Some(0) {
            return Err(Fatal::at(
                &path,
                format!(
                    "the probe for `{}` declares `timeout_seconds = 0`, under which no hook \
                     can ever be measured",
                    probe.id
                ),
            ));
        }
        match probe.push.as_deref() {
            None => {
                if probe.path.is_none() {
                    return Err(Fatal::at(
                        &path,
                        format!(
                            "the probe for `{}` has no `path`, so there is nowhere to plant \
                             its fixture",
                            probe.id
                        ),
                    ));
                }
            }
            Some("empty") => {
                // The fields a push probe has no use for are refused rather
                // than ignored: a `path` beside `push` reads as a file the
                // push will carry, and an empty range carries none.
                if probe.path.is_some() || probe.stage.is_some() {
                    return Err(Fatal::at(
                        &path,
                        format!(
                            "the probe for `{}` has `push = \"empty\"` beside `path` or \
                             `stage`. An empty-range push plants no file and runs at \
                             pre-push by definition, so neither field can mean anything \
                             here",
                            probe.id
                        ),
                    ));
                }
                for (field, value) in [
                    ("refuses", Some(probe.refuses.as_str())),
                    ("allows", probe.allows.as_deref()),
                ] {
                    if let Some(value) = value
                        && !is_destination(value)
                    {
                        return Err(Fatal::at(
                            &path,
                            format!(
                                "the probe for `{}` has `{field} = {value:?}`, which is not \
                                 an `owner/repo`. A push probe's fixture is where the push \
                                 goes: one owner, one slash, one repository, no host",
                                probe.id
                            ),
                        ));
                    }
                }
            }
            Some(other) => {
                return Err(Fatal::at(
                    &path,
                    format!(
                        "the probe for `{}` has `push = {other:?}`, and the only push this \
                         command drives is \"empty\": a range with nothing in it",
                        probe.id
                    ),
                ));
            }
        }
    }
    if parsed.timeout_seconds == Some(0) {
        return Err(Fatal::at(
            &path,
            "`timeout_seconds = 0` at the top of this file, under which no hook can ever \
             be measured",
        ));
    }
    Ok((parsed.probes, parsed.timeout_seconds))
}

/// `owner/repo`, as a push probe's fixture: the two path segments a bare
/// remote is made under, and nothing a path could not hold or a url parser
/// would read as a host.
fn is_destination(value: &str) -> bool {
    let segments: Vec<&str> = value.split('/').collect();
    segments.len() == 2
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && *segment != "."
                && *segment != ".."
                && segment
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_destination_is_one_owner_one_slash_one_repository() {
        for good in ["acme/widget", "someone-else/their.repo", "a_b/c-d"] {
            assert!(is_destination(good), "{good}");
        }
        // No host, no path walk, no url: the value names a directory the
        // remote is made under and the guard parses back.
        for bad in [
            "widget",
            "acme/",
            "/widget",
            "acme/widget/extra",
            "../acme/widget",
            "acme/..",
            "github.com/acme/widget",
            "https://github.com/acme/widget",
            "acme/wid get",
        ] {
            assert!(!is_destination(bad), "{bad}");
        }
    }

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
