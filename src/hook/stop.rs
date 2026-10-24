//! `uphold hook` at the end of a turn: an agent may not stop with the gate red
//! because of something it did.
//!
//! The pre-call seam in the parent module judges what an agent is about to
//! publish. This one judges the claim an agent makes when it stops -- "done" --
//! against the commands the repository names in `[stop] run`. A refusal at
//! commit or push arrives later, often in another session than the one that
//! broke the tree; here it arrives while the session that broke it still holds
//! the context to fix it.
//!
//! ## Red before the session is not this session's red
//!
//! A gate that was already failing when the session started would block every
//! turn in that repository, and the cheapest response to a check that fires on
//! work it did not cause is turning it off (`psychological-acceptability`). So
//! `SessionStart` runs the same commands once and records which failed, and
//! `Stop` blocks only on a command that fails now and did not then. A command
//! that was already red is named to the person in `systemMessage`, and the turn
//! ends.
//!
//! `SessionStart` is configured `async`, so the agent is already working while
//! the baseline runs, and a slow gate can read a file after the agent changed
//! it -- recording the session's own red as red it found. So the tree is
//! fingerprinted before and after the run, and a baseline whose tree moved
//! underneath it is discarded: with no baseline every red command blocks,
//! which fails toward the gate rather than away from it.
//!
//! The baseline lives under the worktree's git dir, keyed by `session_id`. The
//! harness supplies that id, so it is held to a closed character set before it
//! becomes a path: an id that could name `../` is an id that could make this
//! hook read or write a file nobody chose.
//!
//! ## One block per attempt to stop
//!
//! The reason tells the agent to fix what it broke, or to say plainly that it
//! cannot. An agent that does the second and is blocked again has been given
//! an instruction it has already followed, and Claude Code's own cap -- eight
//! consecutive continuations, reset by a tool call -- spends eight more turns
//! before it ends one. So when `stop_hook_active` says this stop follows a
//! block, a gate still red goes to the person in `systemMessage` and the turn
//! ends. The agent gets one chance to fix it; the person always hears it was
//! not fixed.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::config::Policy;
use crate::error::{Exit, Fatal, Result};
use crate::git;

/// How long `Stop` waits for a `SessionStart` baseline that is still running.
/// A first turn can end before a slow gate's first run has finished, and
/// racing it would block on red the session found rather than caused.
const WAIT_FOR_BASELINE: Duration = Duration::from_secs(300);

const POLL: Duration = Duration::from_millis(500);

/// Lines of a failing command's output carried in the reason. The end is where
/// a test runner or a linter puts its verdict.
const TAIL_LINES: usize = 40;

/// What `SessionStart` found, written once per session.
#[derive(Serialize, Deserialize)]
struct Baseline {
    /// Every command that ran, so a command added to `[stop] run` mid-session
    /// reads as unrecorded rather than as having passed.
    ran: Vec<Vec<String>>,
    /// The ones that failed.
    red: Vec<Vec<String>>,
    /// Why this run cannot be compared against, where it cannot: the tree
    /// changed while it ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unusable: Option<String>,
}

struct Outcome {
    argv: Vec<String>,
    code: Option<i32>,
    output: String,
}

impl Outcome {
    fn passed(&self) -> bool {
        self.code == Some(0)
    }

    fn shown(&self) -> String {
        self.argv.join(" ")
    }
}

/// The harness's session id, if it is one this hook may turn into a path.
fn session_id(event: &Value) -> std::result::Result<&str, String> {
    let id = event
        .pointer("/session_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "the event carries no session_id".to_owned())?;
    let safe = !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'));
    if safe {
        Ok(id)
    } else {
        Err(format!(
            "the event's session_id {id:?} is not 1 to 128 of A-Z, a-z, 0-9, '-' and '_', so it \
             is not used as a file name"
        ))
    }
}

fn baseline_dir(root: &Path) -> Result<PathBuf> {
    Ok(git::dir(root)?.join("uphold").join("stop"))
}

/// What the tree looks like to a gate: HEAD, and the size and modification
/// time of every path git reports as changed or untracked. Any edit to a file
/// moves its time, and a commit moves HEAD or the status list, so two equal
/// fingerprints mean nothing the gate reads moved in between -- ignored paths
/// aside, which is where builds put what they write.
fn fingerprint(root: &Path) -> Result<String> {
    let mut seen =
        git::try_run(root, &["rev-parse", "-q", "--verify", "HEAD"])?.unwrap_or_default();
    let entries = git::run_z(
        root,
        &[
            "--no-optional-locks",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ],
    )?;
    for entry in entries {
        let path = entry.get(3..).unwrap_or(&entry);
        let stamp = std::fs::symlink_metadata(root.join(path)).map_or_else(
            |_| "missing".to_owned(),
            |metadata| {
                let modified = metadata
                    .modified()
                    .ok()
                    .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                    .map_or(0, |since| since.as_nanos());
                format!("{} {modified}", metadata.len())
            },
        );
        write!(seen, "\n{entry}\0{stamp}").ok();
    }
    Ok(seen)
}

fn run_gate(root: &Path, commands: &[Vec<String>]) -> Result<Vec<Outcome>> {
    commands
        .iter()
        .map(|argv| {
            let (program, arguments) = argv
                .split_first()
                .ok_or_else(|| Fatal::new("`[stop] run` holds an empty command"))?;
            let output = Command::new(program)
                .args(arguments)
                .current_dir(root)
                .stdin(Stdio::null())
                .output()
                .map_err(|error| {
                    Fatal::new(format!(
                        "`[stop] run` names `{}`, which could not be started: {error}",
                        argv.join(" ")
                    ))
                })?;
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            Ok(Outcome {
                argv: argv.clone(),
                code: output.status.code(),
                output: text,
            })
        })
        .collect()
}

/// Record which `[stop]` commands fail as the session starts.
///
/// Prints nothing on stdout: Claude Code adds a `SessionStart` hook's stdout to
/// the conversation, and a baseline is not something the agent should read.
pub(super) fn session_start(event: &Value, root: &Path, policy: &Policy) -> Result<Exit> {
    let id = session_id(event).map_err(Fatal::new)?;
    if policy.stop.run.is_empty() {
        return Ok(Exit::Clean);
    }
    let directory = baseline_dir(root)?;
    std::fs::create_dir_all(&directory)?;
    let pending = directory.join(format!("{id}.pending"));
    std::fs::write(&pending, b"")?;
    let written = fingerprint(root).and_then(|before| {
        let outcomes = run_gate(root, &policy.stop.run)?;
        let unusable = (fingerprint(root)? != before).then(|| {
            "the tree changed while the SessionStart baseline ran, so it cannot say what was \
             red before this session"
                .to_owned()
        });
        let baseline = Baseline {
            ran: outcomes
                .iter()
                .map(|outcome| outcome.argv.clone())
                .collect(),
            red: outcomes
                .iter()
                .filter(|outcome| !outcome.passed())
                .map(|outcome| outcome.argv.clone())
                .collect(),
            unusable,
        };
        let document = serde_json::to_vec(&baseline)
            .map_err(|error| Fatal::new(format!("the baseline is not writable: {error}")))?;
        // Renamed into place, so `Stop` never reads half a file.
        let partial = directory.join(format!("{id}.json.partial"));
        std::fs::write(&partial, document)?;
        std::fs::rename(&partial, directory.join(format!("{id}.json")))?;
        Ok(())
    });
    std::fs::remove_file(&pending).ok();
    written.map(|()| Exit::Clean)
}

/// The baseline for this session, or why there is none.
fn baseline(event: &Value, root: &Path) -> Result<std::result::Result<Baseline, String>> {
    let id = match session_id(event) {
        Ok(id) => id,
        Err(why) => return Ok(Err(why)),
    };
    let directory = baseline_dir(root)?;
    let recorded = directory.join(format!("{id}.json"));
    let pending = directory.join(format!("{id}.pending"));
    let started = Instant::now();
    while !recorded.is_file() && pending.is_file() && started.elapsed() < WAIT_FOR_BASELINE {
        std::thread::sleep(POLL);
    }
    if !recorded.is_file() {
        return Ok(Err(if pending.is_file() {
            format!(
                "the SessionStart baseline was still running after {}s",
                WAIT_FOR_BASELINE.as_secs()
            )
        } else {
            "no SessionStart baseline was recorded for this session; configure the \
             SessionStart hook beside the Stop hook"
                .to_owned()
        }));
    }
    let text = std::fs::read(&recorded)?;
    let read: Baseline = match serde_json::from_slice(&text) {
        Ok(read) => read,
        Err(error) => {
            return Ok(Err(format!(
                "the baseline at {} is unreadable ({error})",
                recorded.display()
            )));
        }
    };
    Ok(match read.unusable {
        Some(why) => Err(why),
        None => Ok(read),
    })
}

fn tail(output: &str) -> String {
    let lines: Vec<&str> = output.trim_end().lines().collect();
    let skip = lines.len().saturating_sub(TAIL_LINES);
    lines.into_iter().skip(skip).collect::<Vec<_>>().join("\n")
}

/// Refuse the end of a turn that leaves a command red that was green when the
/// session started.
pub(super) fn stop(event: &Value, root: &Path, policy: &Policy) -> Result<Exit> {
    if policy.stop.run.is_empty() {
        eprintln!(
            "uphold hook: this policy declares no `[stop] run`, so the end of this turn was not \
             checked. That is no gate, not a passing one."
        );
        return Ok(Exit::Clean);
    }
    let sent_back = event
        .pointer("/stop_hook_active")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let known = baseline(event, root)?;
    let outcomes = match run_gate(root, &policy.stop.run) {
        Ok(outcomes) => outcomes,
        // A gate that cannot run blocks the first stop, which fails closed. It
        // blocks no second one: the agent was sent back once, and a missing
        // program is not something every further turn can fix.
        Err(error) if sent_back => {
            let message = format!(
                "uphold: the [stop] gate could not run after the agent was sent back once, so \
                 the turn ends unchecked: {error}"
            );
            eprintln!("{message}");
            println!("{}", serde_json::json!({ "systemMessage": message }));
            return Ok(Exit::Clean);
        }
        Err(error) => return Err(error),
    };
    let (preexisting, blocking): (Vec<&Outcome>, Vec<&Outcome>) = outcomes
        .iter()
        .filter(|outcome| !outcome.passed())
        .partition(|outcome| {
            known.as_ref().is_ok_and(|baseline| {
                baseline.ran.contains(&outcome.argv) && baseline.red.contains(&outcome.argv)
            })
        });

    let mut document = Map::new();
    let mut told: Vec<String> = Vec::new();
    if !blocking.is_empty() && sent_back {
        let names: Vec<String> = blocking
            .iter()
            .map(|outcome| format!("`{}`", outcome.shown()))
            .collect();
        told.push(format!(
            "uphold: the [stop] gate is still red after the agent was sent back once, so the turn \
             ends with it red: {}",
            names.join(", ")
        ));
    } else if !blocking.is_empty() {
        let mut reason = String::from(
            "uphold: the repository's [stop] gate is red, and these commands were not failing \
             when this session started:\n\n",
        );
        if let Err(why) = &known {
            writeln!(reason, "(No baseline to compare against: {why}.)\n").ok();
        }
        for outcome in &blocking {
            let code = outcome.code.map_or_else(
                || "was killed by a signal".to_owned(),
                |code| format!("exited {code}"),
            );
            writeln!(
                reason,
                "`{}` {code}:\n{}\n",
                outcome.shown(),
                tail(&outcome.output)
            )
            .ok();
        }
        reason.push_str(
            "Fix what this session broke before ending the turn. If it cannot be fixed here, say \
             so plainly in the reply. This is the only block: the next stop ends the turn, and a \
             gate still red is reported to the person.",
        );
        eprintln!("{reason}");
        document.insert("decision".to_owned(), Value::from("block"));
        document.insert("reason".to_owned(), Value::from(reason));
    }
    if !preexisting.is_empty() {
        let names: Vec<String> = preexisting
            .iter()
            .map(|outcome| format!("`{}`", outcome.shown()))
            .collect();
        told.push(format!(
            "uphold: these [stop] commands were already failing when this session started, so \
             they did not block: {}",
            names.join(", ")
        ));
    }
    if !told.is_empty() {
        let message = told.join("\n");
        eprintln!("{message}");
        document.insert("systemMessage".to_owned(), Value::from(message));
    }
    if !document.is_empty() {
        println!("{}", Value::Object(document));
    }
    Ok(Exit::Clean)
}
