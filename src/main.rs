//! `uphold` -- one binary for the catalog and the rules that enforce it.
//!
//! Subcommands arrive as the tiers fold in. `scan` is the content-policy engine
//! that used to be a Python script shelling out to `rg`.

#![expect(
    clippy::redundant_pub_crate,
    reason = "Conflicts with the unreachable_pub lint, which is denied crate-wide"
)]
// A unit test asserts on the outcome. A panic in the fixture that sets one up
// IS the failure report, and there is no caller above it to hand a Result to --
// so the panic bans that hold for the binary are lifted for `cfg(test)` only,
// and only here, rather than per module.
#![cfg_attr(
    test,
    expect(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        reason = "a test's fixtures report by panicking"
    )
)]

// Defined BEFORE the modules, which is not style: a `macro_rules!` is in scope
// for what follows it in source order, modules included, and one written after
// this list would shadow the prelude's in `main.rs` alone while every other file
// went on panicking.
//
// Shadowing rather than a helper function beside them. `println!` unwraps its
// write and panics -- exit 101, on a closed pipe, out of a binary whose whole
// contract is three exit codes -- and a helper is a rule that 114 call sites
// have to remember and that the next line of code can silently break. What
// cannot be forgotten is the spelling everybody already types. See `out`, which
// is where the two failures are told apart.
/// `println!` that reports rather than panics when the write fails.
macro_rules! println {
    () => { $crate::out::line($crate::out::Stream::Out, "") };
    ($($argument:tt)*) => {
        $crate::out::line($crate::out::Stream::Out, &format!($($argument)*))
    };
}

/// `print!` that reports rather than panics when the write fails.
macro_rules! print {
    ($($argument:tt)*) => {
        $crate::out::text($crate::out::Stream::Out, &format!($($argument)*))
    };
}

/// `eprintln!` that reports rather than panics when the write fails.
macro_rules! eprintln {
    () => { $crate::out::line($crate::out::Stream::Err, "") };
    ($($argument:tt)*) => {
        $crate::out::line($crate::out::Stream::Err, &format!($($argument)*))
    };
}

/// `eprint!` that reports rather than panics when the write fails.
///
/// Nothing in this crate spells it today, and it is here so that the day
/// something does, it is this one. The expectation below is what says so out
/// loud: the first use turns the attribute into an unfulfilled expectation and
/// the build stops, pointing at a line whose fix is to delete it.
#[expect(
    unused_macros,
    reason = "the prelude's eprint! panics; this one exists so a first use does not reach it"
)]
macro_rules! eprint {
    ($($argument:tt)*) => {
        $crate::out::text($crate::out::Stream::Err, &format!($($argument)*))
    };
}

mod audit;
mod catalog;
mod check;
mod comments;
mod config;
mod engine;
mod error;
#[cfg(test)]
mod fixture;
mod git;
mod guard;
mod hooks;
mod install;
mod out;
mod pins;
mod probe;
mod report;
mod runner;
mod scan;
mod selection;
mod shim;
mod sources;
mod text;

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::error::{verdict, Exit, Fatal, Result};

const USAGE: &str = "\
usage:
  uphold scan [--policy PATH]        run the content policy over this repository
  uphold scan --text [FILE|-]        run the host-identity rules over text
  uphold guard --stage STAGE         run the guards that fire at STAGE
  uphold guard --text [FILE|-]       run the text-capable guards over text
  uphold check                       reconcile policy/upheld.toml against what runs
  uphold check --coverage            which rules run here and carry no principle
  uphold audit --for-publication     what a private->public flip would republish
  uphold hooks --identity DIR...     do these repositories declare the same hooks
  uphold probe [--runner NAME]       can each declared hook actually refuse
  uphold rules --set NAME [--json]   what a bundled rule set refuses, rule by rule
  uphold rules --sets --json         every bundled set, field for field, so two
                                     versions of this binary can be diffed
  uphold rules --effective [--json]  every rule this repository resolves to, and
                                     the git hooks each one fires at
  uphold shim <command> [args...]     check what a command would publish, then run it
  uphold shim --install [COMMAND...]  link this binary under each command's name
  uphold shim --status                what is linked, and whether PATH reaches it
  uphold shim --uninstall             take back the links this tool made
  uphold shim --hook bash|zsh|fish    those links on PATH only inside a policy tree
  uphold shim --path                  the PATH a shell should have, standing here
  uphold --version

Invoked under a command's own name -- a link called `gh` on PATH ahead of the
real one -- the binary runs that command's shim directly. That is what a
multicall binary is for: argv[0] decides, and there is nothing to install but a
link. `--install` makes those links in one directory (`~/.local/uphold/shims` by
default, `--dir` names another) so the whole seam is one PATH entry to add,
inspect or drop. What the shim then DOES is per repository already: no policy
where the command was typed and it execs the real one and says nothing.

STAGE is one of commit-msg, pre-commit, pre-merge-commit, pre-push, manual.
`--message FILE` forwards the commit message. At pre-push the ref lines come
from git on stdin, or from what pre-commit and prek export in their place --
neither forwards git's stdin, so both channels are read and a push that reached
neither is refused rather than guessed at. Under lefthook the pre-push job needs
`use_stdin: true`.

exit codes:
  0  every check passed
  1  one or more policy violations
  2  the check could not be made (bad policy, missing source, unreadable file)

UPHOLD_ALLOW=<id>,<id> bypasses named guards for one invocation.
";

/// The policy file, newest name first.
///
/// `rg-policy.toml` is still read because a repository's policy file is not
/// this tool's to rename on its behalf: the file is checked in, referenced in
/// documentation, and a hard cut would break every consumer on the day the
/// binary shipped rather than on the day they chose.
const POLICY_NAMES: [&str; 2] = ["principles.toml", "rg-policy.toml"];

/// Whether this directory is where a repository begins.
///
/// `.git` is a directory in an ordinary clone and a FILE in a linked worktree
/// and in a submodule, so the question is whether the name is there at all and
/// never what kind of thing it is. `symlink_metadata` rather than
/// `Path::exists` because a `.git` that cannot be followed is still a boundary:
/// reading it as absent would resume the climb into the enclosing superproject,
/// which is the one thing the boundary exists to stop.
fn is_repository_root(directory: &Path) -> bool {
    directory.join(".git").symlink_metadata().is_ok()
}

/// Walk up from the working directory until a policy file appears, stopping at
/// the repository boundary.
///
/// The stop is the whole of the difference between a policy and somebody else's
/// policy. Without it, a repository with no policy of its own kept climbing,
/// loaded the enclosing superproject's, and adopted the SUPERPROJECT'S
/// directory as root -- so the run scanned another tree and the report named
/// files that are not in the repository the command was run in, under this
/// repository's name. Nine repositories in the workspace this was found in have
/// no policy and sit inside superprojects that do, so every one of them was
/// being reported on by proxy.
fn discover(start: &Path) -> Option<(PathBuf, PathBuf)> {
    let mut candidate = start.to_path_buf();
    loop {
        for name in POLICY_NAMES {
            let policy = candidate.join("policy").join(name);
            if policy.is_file() {
                return Some((candidate.clone(), policy));
            }
        }
        // Asked AFTER the lookup: a repository root carrying its own policy is
        // the ordinary case, and it has to be found rather than stopped at.
        if is_repository_root(&candidate) || !candidate.pop() {
            return None;
        }
    }
}

/// The refusal every entry point shares when no policy is within reach.
///
/// It says "in this repository" because that is now the whole of what was
/// looked at. The alternative is not a pass and never was: a repository with no
/// policy has nothing to check against, and borrowing a parent's was a report
/// about a different tree.
fn no_policy_here(working: &Path) -> Fatal {
    Fatal::new(format!(
        "no policy in this repository (looked for policy/{} from {} up to the \
         repository root). A repository's policy is its own -- an enclosing \
         superproject's is not borrowed, because a report naming files outside \
         this repository is a report about something else",
        POLICY_NAMES.join(" or policy/"),
        working.display()
    ))
}

/// The root that an explicitly named policy file is the policy for.
///
/// `--policy PATH` used to take the file's grandparent and check nothing, which
/// is the root only when the file really is at `<root>/policy/<name>.toml`:
/// `uphold scan --policy principles.toml` made the root the repository's
/// PARENT, and a policy one directory below `/` made it `/`. The default
/// include of `["."]` then walks whatever that came out as. So the layout
/// `discover` looks for is asserted here rather than assumed, and a root that
/// cannot be established is exit 2 -- scanning the wrong tree and reporting on
/// it is worse than saying the layout was not understood.
fn root_of(policy: &Path) -> Result<PathBuf> {
    let directory = policy.parent();
    let inside_policy_directory = directory
        .and_then(Path::file_name)
        .is_some_and(|name| name == "policy");
    match directory.and_then(Path::parent) {
        Some(root) if inside_policy_directory => Ok(root.to_path_buf()),
        _ => Err(Fatal::at(
            policy,
            "a policy file says which tree it is about by where it sits, and this one \
             is not at <root>/policy/<name>.toml, so there is no root to scan. Move it \
             under a `policy` directory, or drop --policy and let `uphold scan` find \
             the one belonging to the repository you are standing in",
        )),
    }
}

/// The text of an argument that has to be text to mean anything.
///
/// argv on Unix is arbitrary bytes: a file named in latin-1 is a perfectly good
/// argument, and `std::env::args()` PANICS on one -- exit 101, which is not one
/// of the three codes this tool promises, out of a binary designed to stand in
/// front of `git`, `gh` and `npm` and be handed exactly such paths. So argv is
/// read as `OsString` and only the names that are compared against literals
/// here -- an option, a subcommand, a rule-set name, the command a shim stands
/// in front of -- are converted, each with this. A name that is not UTF-8 names
/// nothing this binary has, and saying so is exit 2.
fn text_of(argument: &OsStr) -> Result<&str> {
    argument.to_str().ok_or_else(|| {
        Fatal::new(format!(
            "the argument {:?} is not valid UTF-8, and an option name, a subcommand \
             name and a command name are all read as text",
            argument.to_string_lossy()
        ))
    })
}

fn run() -> Result<Exit> {
    // argv[0] first. Invoked through a link named for a command it shims, the
    // binary IS that shim -- which is what ends `install.sh` and the
    // sibling-checkout coupling: there is nothing to install but a link, and
    // nothing to find but this binary.
    let mut argv = std::env::args_os();
    let program = argv.next().unwrap_or_default();
    let arguments: Vec<OsString> = argv.collect();
    if let Some(name) = Path::new(&program)
        .file_name()
        .filter(|name| !name.is_empty() && name.to_str() != Some("uphold"))
    {
        return shim_command(text_of(name)?, &arguments, shim::Invoked::AsTheCommand);
    }

    let Some((first, rest)) = arguments.split_first() else {
        print!("{USAGE}");
        return Ok(Exit::Clean);
    };

    match text_of(first)? {
        // The url `package.repository` holds, for the OSCAL export's property
        // namespace. Asked of the binary because the binary is where that value
        // is compiled in; a second copy read off `Cargo.toml` is a copy that
        // drifts, and it can only be read in a checkout of this repository.
        "--upstream" => {
            println!("{}", env!("CARGO_PKG_REPOSITORY"));
            Ok(Exit::Clean)
        }
        "--version" | "-V" => {
            println!("uphold {}", env!("CARGO_PKG_VERSION"));
            Ok(Exit::Clean)
        }
        "--help" | "-h" => {
            print!("{USAGE}");
            Ok(Exit::Clean)
        }
        "scan" => scan_command(rest),
        "guard" => guard_command(rest),
        "audit" => audit_command(rest),
        "check" => match rest {
            [] => check_command(false),
            [flag] if flag == "--coverage" => check_command(true),
            _ => Err(Fatal::new(format!(
                "usage: uphold check [--coverage]\n\n{USAGE}"
            ))),
        },
        "hooks" => match rest {
            [flag, paths @ ..] if flag == "--identity" && !paths.is_empty() => {
                let mut directories = Vec::new();
                for path in paths {
                    directories.push(PathBuf::from(path));
                }
                let working = std::env::current_dir()?;
                // The waivers belong to the repository the operator is standing
                // in, not to any repository being compared: a fleet-wide
                // exemption written inside one of the repositories it exempts
                // is a repository excusing itself.
                let root = discover(&working).map_or(working, |(root, _)| root);
                hooks::identity(&root, &directories)
            }
            _ => Err(Fatal::new(format!(
                "usage: uphold hooks --identity DIR [DIR...]\n\n{USAGE}"
            ))),
        },
        "probe" => {
            let runner = match rest {
                [] => None,
                [flag, name] if flag == "--runner" => Some(text_of(name)?),
                _ => {
                    return Err(Fatal::new(format!(
                        "usage: uphold probe [--runner prek|pre-commit|lefthook]\n\n{USAGE}"
                    )))
                }
            };
            let working = std::env::current_dir()?;
            let (root, _) = discover(&working).ok_or_else(|| no_policy_here(&working))?;
            probe::run(&root, runner)
        }
        "rules" => match rest {
            [flag, name] if flag == "--set" => rules_command(text_of(name)?),
            [flag, name, format] if flag == "--set" && format == "--json" => {
                set_json_command(Some(text_of(name)?))
            }
            [flag, format] if flag == "--sets" && format == "--json" => set_json_command(None),
            [flag] if flag == "--effective" => effective_rules_command(false),
            [flag, format] if flag == "--effective" && format == "--json" => {
                effective_rules_command(true)
            }
            _ => Err(Fatal::new(format!(
                "usage: uphold rules --set NAME [--json] | uphold rules --sets --json | \
                 uphold rules --effective [--json]\n\n{USAGE}"
            ))),
        },
        "shim" => shim_or_links(rest),
        other => Err(Fatal::new(format!(
            "unknown subcommand {other:?}\n\n{USAGE}"
        ))),
    }
}

/// Reconcile the declaration against the rules this repository resolves to.
///
/// The loader runs first and its answer is what the reconcile reads, which is
/// the whole point of moving this in: `uphold_check.py` re-implemented
/// `config::load` to answer the same question and was free to disagree with it.
fn check_command(coverage: bool) -> Result<Exit> {
    let working = std::env::current_dir()?;
    let (root, policy_path) = discover(&working).ok_or_else(|| no_policy_here(&working))?;
    let policy = config::load(&root, &policy_path)?;
    check::run(&root, &policy, coverage)
}

fn scan_command(arguments: &[OsString]) -> Result<Exit> {
    let mut explicit_policy: Option<PathBuf> = None;
    let mut text_source: Option<String> = None;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        match text_of(argument)? {
            "--policy" => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| Fatal::new("--policy needs a path"))?;
                // A path keeps its bytes. Only the flag NAME above had to be
                // text, and a policy file whose name is not UTF-8 opens exactly
                // as well as one whose name is.
                explicit_policy = Some(PathBuf::from(value));
            }
            "--text" => {
                index += 1;
                // This one is a path or `-`, and what reads it takes text, so
                // it converts here -- as a sentence and exit 2, never a panic.
                text_source = Some(match arguments.get(index) {
                    Some(value) => text_of(value)?.to_owned(),
                    None => String::from("-"),
                });
            }
            other => return Err(Fatal::new(format!("unknown option {other:?}\n\n{USAGE}"))),
        }
        index += 1;
    }

    let working = std::env::current_dir()?;
    let found = match &explicit_policy {
        Some(path) => {
            let policy = path
                .canonicalize()
                .map_err(|error| Fatal::at(path, error))?;
            let root = root_of(&policy)?;
            Some((root, policy))
        }
        None => discover(&working),
    };

    if let Some(source) = text_source {
        return text::check(found.as_ref(), &source);
    }

    let Some((root, policy_path)) = found else {
        return Err(no_policy_here(&working));
    };

    let policy = config::load(&root, &policy_path)?;
    let scanner = scan::Scan::new(&root, &policy);
    let failures = scanner.run()?;
    for failure in &failures {
        failure.print();
    }

    let skipped = scanner.not_text();
    if !skipped.is_empty() {
        // SAID ALOUD, ALWAYS. The point of skipping a declared artifact is that
        // content rules do not apply to it; the point of counting it is that
        // "we did not check these" and "these were clean" must never look the
        // same in this output.
        println!(
            "{} path(s) skipped: declared not text in .gitattributes",
            skipped.len()
        );
        for path in skipped {
            println!("  {path}");
        }
    }

    // The other half of that distinction, and the one nobody declared. A path
    // a rule selected and could not open was dropped from the list on the way
    // in, so the rule searched what was left, found nothing there, and the run
    // said `policy checks passed` over a tree it had not finished reading.
    // Named here, one line each, and exit 2 -- the same shape `audit
    // --for-publication` uses for a forge surface it could not list.
    let unreadable = scanner.unreadable();
    if !unreadable.is_empty() {
        eprintln!(
            "{} path(s) could not be read, so this run searched part of the tree and not the \
             rest -- which is not the same as finding nothing:",
            unreadable.len()
        );
        for note in &unreadable {
            eprintln!("  {note}");
        }
    }

    // A violation outranks an unreadable path: something was found, and exit 1
    // is the answer to "is this tree publishable" that the reader has to act on
    // first. The unreadable list is printed either way, so nothing is hidden by
    // the ranking -- only the exit code is decided by it. The ranking itself is
    // `error::verdict`, which `audit` and `check` also ask, because three
    // transcriptions of one decision is three places for it to drift.
    let exit = verdict(failures.len(), unreadable.len());
    if exit == Exit::Clean {
        println!("policy checks passed");
    }
    Ok(exit)
}

fn guard_command(arguments: &[OsString]) -> Result<Exit> {
    let mut stage: Option<guard::Stage> = None;
    let mut message: Option<PathBuf> = None;
    let mut remote_name: Option<String> = None;
    let mut remote_url: Option<String> = None;
    let mut text_source: Option<String> = None;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        // A stage name, a remote name, a remote URL and a text source are all
        // read as text by what they are handed to, so those values convert
        // here. `--message` does not: it is a path, and a path does not have to
        // be text to be opened.
        let value = |at: usize, flag: &str| -> Result<String> {
            let given = arguments
                .get(at)
                .ok_or_else(|| Fatal::new(format!("{flag} needs a value")))?;
            Ok(text_of(given)?.to_owned())
        };
        match text_of(argument)? {
            "--stage" => {
                index += 1;
                stage = Some(guard::Stage::parse(&value(index, "--stage")?)?);
            }
            "--message" => {
                index += 1;
                let path = arguments
                    .get(index)
                    .ok_or_else(|| Fatal::new("--message needs a value"))?;
                message = Some(PathBuf::from(path));
            }
            "--remote" => {
                index += 1;
                remote_name = Some(value(index, "--remote")?);
            }
            "--remote-url" => {
                index += 1;
                remote_url = Some(value(index, "--remote-url")?);
            }
            "--text" => {
                index += 1;
                text_source = Some(match arguments.get(index) {
                    Some(given) => text_of(given)?.to_owned(),
                    None => String::from("-"),
                });
            }
            other => return Err(Fatal::new(format!("unknown option {other:?}\n\n{USAGE}"))),
        }
        index += 1;
    }

    let working = std::env::current_dir()?;
    let (root, policy_path) = discover(&working).ok_or_else(|| no_policy_here(&working))?;
    let policy = config::load(&root, &policy_path)?;

    if let Some(source) = text_source {
        // Text that never becomes a file, and never had a stage: a
        // pull-request body, a release note, a branch name. Only the guards
        // that can judge text run, because handing one that reads the index a
        // body and reporting a pass is a check that did not happen.
        let text = if source == "-" {
            use std::io::Read;
            let mut buffer = String::new();
            std::io::stdin().read_to_string(&mut buffer)?;
            buffer
        } else {
            std::fs::read_to_string(&source)
                .map_err(|error| Fatal::at(Path::new(&source), error))?
        };
        let refusals = guard::over_text(&root, &policy, &source, &text)?;
        for refusal in &refusals {
            eprintln!("guard refused: {}", guard::refused_by(&policy, refusal));
            eprintln!("{}", refusal.report.trim_end());
        }
        if refusals.is_empty() {
            println!("text checks passed");
            return Ok(Exit::Clean);
        }
        return Ok(Exit::Violations);
    }

    // No default. A guard reads a different artifact at every stage, so guessing
    // one would make it answer a question nobody asked -- and answer it green.
    let stage = stage.ok_or_else(|| Fatal::new(format!("guard needs --stage\n\n{USAGE}")))?;

    // git feeds a pre-push hook its ref lines on stdin. pre-commit and prek
    // consume that stdin themselves and re-publish it as environment, so this
    // asks both channels rather than only the one git documents -- see
    // `runner`, where the difference is the whole module.
    let push = if stage == guard::Stage::PrePush {
        runner::push(&root, remote_name, remote_url)?
    } else {
        runner::Push {
            refs: String::new(),
            remote_name,
            remote_url,
            source: runner::Source::Absent,
        }
    };

    guard::run(
        &root,
        &policy,
        &guard::RunRequest {
            stage,
            message_file: message.as_deref(),
            push_refs: &push.refs,
            push_source: push.source,
            remote_name: push.remote_name.as_deref(),
            remote_url: push.remote_url.as_deref(),
        },
    )
}

fn audit_command(arguments: &[OsString]) -> Result<Exit> {
    // No default mode. `audit` on its own would have to pick a question, and
    // the one it would pick is the one this tool exists because nothing asks.
    match arguments {
        [only] if only == "--for-publication" => {}
        _ => {
            return Err(Fatal::new(format!(
                "audit needs --for-publication\n\n{USAGE}"
            )))
        }
    }
    let working = std::env::current_dir()?;
    let (root, policy_path) = discover(&working).ok_or_else(|| no_policy_here(&working))?;
    let policy = config::load(&root, &policy_path)?;
    audit::for_publication(&root, &policy)
}

/// What one bundled set refuses, so nobody has to read the docs -- or the
/// source -- to learn what a name they are about to inherit means.
fn rules_command(name: &str) -> Result<Exit> {
    let set = config::bundled_set(name)?;
    println!("{name}: {} rule(s)", set.rules.len());
    if set.stages.is_empty() {
        println!("  installs no git hook");
    } else {
        println!("  may install at: {}", set.stages.join(", "));
    }
    for rule in set.rules {
        let check = rule
            .check()
            .map_or_else(|| String::from("?"), |check| check.to_string());
        println!("  {}  ({check})", rule.id);
        let message = rule.message();
        if let Some(first) = message.lines().find(|line| !line.trim().is_empty()) {
            println!("      {}", first.trim());
        }
    }
    Ok(Exit::Clean)
}

/// What a bundled set IS, field for field, for a reader who has to compare two
/// versions of this binary.
///
/// The human form above is a summary, and a summary cannot answer the question
/// this one exists for: a set ships compiled in, so a pattern that changed
/// between two releases changes what is refused in every inheriting repository
/// with NO DIFF IN ANY OF THEM. `diff <(uphold-a rules --sets --json)
/// <(uphold-b rules --sets --json)` is that diff, and `policy/base/sets.lock.json`
/// is the same document committed here so the change is reviewable in the one
/// repository that can review it.
///
/// Serialized from the rule struct itself rather than field by field. A writer
/// naming the fields it knows about is a list that drifts from the schema, and
/// a field missing from THIS output is a behaviour change that diffs to
/// nothing -- which is the exact failure the output exists to catch.
fn set_json_command(only: Option<&str>) -> Result<Exit> {
    let sets = match only {
        Some(name) => vec![config::bundled_set(name)?],
        None => config::bundled_sets()?,
    };
    let document: Vec<serde_json::Value> = sets
        .iter()
        .map(|set| {
            let rules: Vec<serde_json::Value> = set
                .rules
                .iter()
                .map(|rule| pruned(serde_json::to_value(rule).unwrap_or(serde_json::Value::Null)))
                .collect();
            serde_json::json!({
                "set": set.name,
                "stages": set.stages,
                "rules": rules,
            })
        })
        .collect();
    let text = serde_json::to_string_pretty(&document)
        .map_err(|error| Fatal::new(format!("could not render the set document: {error}")))?;
    println!("{text}");
    Ok(Exit::Clean)
}

/// Drop what an absent field serializes to, so the document says what the file
/// says.
///
/// A `null` and an empty list are how "the author did not write this" arrives
/// here, and printing them would make every rule carry thirty lines of things
/// it is not. Lossless in the direction that matters: nothing in the schema
/// distinguishes an absent list from an empty one -- `Rule::validate` refuses
/// a written parameter its check does not read, so an explicit `[]` is not a
/// state a loaded rule can be in.
fn pruned(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(fields) => serde_json::Value::Object(
            fields
                .into_iter()
                .filter(|(_, field)| match field {
                    serde_json::Value::Null => false,
                    serde_json::Value::Array(items) => !items.is_empty(),
                    _ => true,
                })
                .map(|(name, field)| (name, pruned(field)))
                .collect(),
        ),
        other => other,
    }
}

/// One JSON string, escaped.
///
/// Hand-written rather than pulled in with a serialization crate, because this
/// is the only JSON this binary emits and a rule id is the only thing in it
/// that is not a fixed literal. The escapes are the ones RFC 8259 requires: the
/// two structural characters, and every control character below U+0020, which
/// a `\u` escape covers whatever it is.
fn json_string(value: &str, into: &mut String) {
    into.push('"');
    for character in value.chars() {
        match character {
            '"' => into.push_str("\\\""),
            '\\' => into.push_str("\\\\"),
            '\n' => into.push_str("\\n"),
            '\r' => into.push_str("\\r"),
            '\t' => into.push_str("\\t"),
            control if control < ' ' => {
                // Two digits is the whole range: everything below U+0020 fits
                // in a byte, and `from_digit` is total for a value under 16, so
                // the fallback below is unreachable rather than a guess.
                let code = u32::from(control);
                into.push_str("\\u00");
                into.push(char::from_digit(code >> 4, 16).unwrap_or('0'));
                into.push(char::from_digit(code & 0xf, 16).unwrap_or('0'));
            }
            ordinary => into.push(ordinary),
        }
    }
    into.push('"');
}

/// Every rule this repository actually resolves to, after inheritance.
///
/// It exists so that nothing else has to re-implement `config::load`. What a
/// repository runs is the bundled sets it names, plus the extra policy files
/// `inherit.paths` merges, minus `inherit.disabled_rules`, with its own rules
/// shadowing an inherited id -- five interacting fields, and every second
/// reader of them is a reader free to disagree with the engine about which
/// rules run. The reconciler in `uphold_check.py` is that second reader today,
/// and this is what ends it: one loader answers, and everything else asks.
///
/// `--json` because the caller is a program. The human form is the same answer
/// for a person standing in a repository asking what it is holding itself to.
fn effective_rules_command(as_json: bool) -> Result<Exit> {
    let working = std::env::current_dir()?;
    let (root, policy_path) = discover(&working).ok_or_else(|| no_policy_here(&working))?;
    let policy = config::load(&root, &policy_path)?;

    if !as_json {
        println!("{} rule(s) in effect", policy.rules.len());
        for rule in &policy.rules {
            let hooks = rule.hooks();
            let at = if hooks.is_empty() {
                // Which seam, where there is no hook to name. "no git hook" was
                // true of a content rule and of a checker standing in front of
                // `gh` alike, and those are not the same place.
                match rule.seams().as_slice() {
                    [] => String::from("nothing runs it"),
                    seams => seams.join(", "),
                }
            } else {
                hooks.join(", ")
            };
            println!("  {}  ({at})", rule.id);
        }
        return Ok(Exit::Clean);
    }

    let mut document = String::from("[");
    for (index, rule) in policy.rules.iter().enumerate() {
        if index > 0 {
            document.push(',');
        }
        document.push_str("\n  {\"id\": ");
        json_string(&rule.id, &mut document);
        document.push_str(", \"git_hooks\": [");
        for (position, hook) in rule.hooks().iter().enumerate() {
            if position > 0 {
                document.push_str(", ");
            }
            json_string(hook, &mut document);
        }
        // `git_hooks` alone cannot answer where a hookless rule runs, and a
        // caller that has to guess guesses the scan -- which is how a claim on
        // a rule whose only place is `command.before` reconciled green in a
        // repository where nothing runs it. The loader knows; it says so here.
        document.push_str("], \"seams\": [");
        for (position, seam) in rule.seams().iter().enumerate() {
            if position > 0 {
                document.push_str(", ");
            }
            json_string(seam, &mut document);
        }
        document.push_str("]}");
    }
    if !policy.rules.is_empty() {
        document.push('\n');
    }
    document.push(']');
    println!("{document}");
    Ok(Exit::Clean)
}

/// `uphold shim` answers two questions, and the first word says which.
///
/// A command name is what follows it in every other case, and no command is
/// called `--install`. Keeping the links under the same word rather than under a
/// subcommand of its own is not tidiness: what a link IS -- this binary reached
/// through a name that is not its own -- is the whole of the shim, and a reader
/// looking for where the seam comes from looks where the seam is documented.
fn shim_or_links(rest: &[OsString]) -> Result<Exit> {
    let (first, after) = rest
        .split_first()
        .ok_or_else(|| Fatal::new(format!("shim needs a command\n\n{USAGE}")))?;
    // `--as-editor` is the shim re-entering itself as the command's own editor,
    // and it is a word here rather than a variable in the environment for the
    // reason `shim::Invoked::AsEditor` gives: an environment reaches every
    // descendant, and the descendants of this pass include the `git` that IS
    // this binary under a link.
    if first == shim::EDITOR_FLAG {
        let (name, shimmed) = after
            .split_first()
            .ok_or_else(|| Fatal::new(format!("shim needs a command\n\n{USAGE}")))?;
        return shim_command(text_of(name)?, shimmed, shim::Invoked::AsEditor);
    }
    let word = text_of(first)?;
    match word {
        "--install" | "--uninstall" | "--status" | "--path" | "--hook" => {
            links_command(word, after)
        }
        // No command is spelt with a leading dash, so an option here is a
        // mistyped mode rather than a command to stand in front of. Read as a
        // command it becomes `no shim declares the command "--dir"`, which names
        // the wrong problem: the mode is what the reader meant and the order is
        // what they got wrong.
        other if other.starts_with('-') => Err(Fatal::new(format!(
            "{other:?} is not one of the shim modes, and no command is called that. The mode \
             comes first:\n\n  uphold shim --install|--status|--uninstall|--hook|--path \
             [--dir PATH]\n\n{USAGE}"
        ))),
        _ => shim_command(word, after, shim::Invoked::ByName),
    }
}

/// The links on PATH: made, taken back, reported on, or handed to a shell.
fn links_command(mode: &str, rest: &[OsString]) -> Result<Exit> {
    let mut explicit_dir: Option<PathBuf> = None;
    let mut words: Vec<String> = Vec::new();
    let mut index = 0;
    while let Some(argument) = rest.get(index) {
        match text_of(argument)? {
            "--dir" => {
                index += 1;
                let value = rest
                    .get(index)
                    .ok_or_else(|| Fatal::new("--dir needs a path"))?;
                // A path keeps its bytes; only the option NAME had to be text.
                explicit_dir = Some(PathBuf::from(value));
            }
            other if other.starts_with('-') => {
                return Err(Fatal::new(format!("unknown option {other:?}\n\n{USAGE}")))
            }
            other => words.push(other.to_owned()),
        }
        index += 1;
    }
    let directory = install::directory(
        explicit_dir.as_deref(),
        std::env::var_os("HOME"),
        &std::env::current_dir()?,
    )?;
    match mode {
        "--install" => install::install(&directory, &link_names(words)?),
        "--hook" => match words.as_slice() {
            [shell] => install::hook(shell, &directory),
            _ => Err(Fatal::new(format!(
                "usage: uphold shim --hook bash|zsh|fish [--dir PATH]\n\n{USAGE}"
            ))),
        },
        // The rest read the directory and take no names: what is linked there is
        // what is there, and a repository standing somewhere else has no say in
        // it.
        _ if !words.is_empty() => Err(Fatal::new(format!(
            "uphold shim {mode} takes no command names -- it reads the directory. \
             Names are for --install\n\n{USAGE}"
        ))),
        "--uninstall" => install::uninstall(&directory),
        "--status" => install::status(&directory),
        "--path" => install::shell_path(&directory),
        other => Err(Fatal::new(format!("unknown option {other:?}\n\n{USAGE}"))),
    }
}

/// The commands to stand in front of: the ones named, or the ones this
/// repository declares.
///
/// Defaulting to the policy is the only evidence there is about which commands
/// matter, and it is deliberately not a claim that they are all of them -- the
/// links are machine-wide and the next repository declares its own. Running this
/// again in that tree adds what is missing and leaves the rest, which is why
/// nothing here removes a link it did not ask for.
fn link_names(from_argv: Vec<String>) -> Result<Vec<String>> {
    let mut names = from_argv;
    if names.is_empty() {
        let working = std::env::current_dir()?;
        let (root, policy_path) = discover(&working).ok_or_else(|| {
            Fatal::new(format!(
                "nothing here says which commands to stand in front of, so name them, or \
                 run this inside a repository that declares them:\n\n  uphold shim --install \
                 git gh\n\n{}",
                no_policy_here(&working)
            ))
        })?;
        let policy = config::load(&root, &policy_path)?;
        names = policy
            .shims
            .iter()
            .map(|shim| shim.command.clone())
            .collect();
        if names.is_empty() {
            return Err(Fatal::new(format!(
                "{} declares no `[[shim]]`, so this repository stands in front of no \
                 command. Name the commands to link if you want them anyway",
                policy_path.display()
            )));
        }
    }
    // A name is a file name in one directory. `--install ../../bin/git` would
    // write a link outside the directory this command is reporting on, which is
    // both a surprise and a link `--uninstall` would never find again.
    for name in &names {
        if Path::new(name)
            .file_name()
            .is_none_or(|file| file != name.as_str())
        {
            return Err(Fatal::new(format!(
                "{name:?} is not a command name. A link is made in the shims directory \
                 under the command's own name, and a name carrying a path separator would \
                 put it somewhere else"
            )));
        }
    }
    // One link per name however many times it was written -- `dedup` alone drops
    // only neighbours, and the report would say `linked` and then `already` for
    // one file.
    let mut seen = std::collections::BTreeSet::new();
    names.retain(|name| seen.insert(name.clone()));
    Ok(names)
}

fn shim_command(name: &str, argv: &[OsString], invoked: shim::Invoked) -> Result<Exit> {
    let working = std::env::current_dir()?;
    // No policy where the command was typed means no repository here declares
    // anything to stand in front of it. Run as the command, that is the command
    // running: the link is on PATH for the whole machine -- `/tmp`, somebody
    // else's checkout, a shell that never enters a participating repository --
    // and refusing there protects nothing, breaks `git` everywhere, and gets
    // the link removed, which is how the seam is lost in the repositories that
    // DID declare it. Asked for by name, it is still an error, because the
    // caller asked this repository for a shim it does not have.
    //
    // A policy that exists and cannot be read is a different answer and still
    // fatal both ways: `config::load` below says so, because a declaration that
    // could not be read might have been the one standing in front of this
    // command.
    let Some((root, policy_path)) = discover(&working) else {
        return match invoked {
            shim::Invoked::AsTheCommand => shim::exec_through(name, argv),
            shim::Invoked::ByName => Err(no_policy_here(&working)),
            // Re-entered as an editor with no policy to read, which is a body
            // written for publication and nothing to check it against. Not
            // `exec_through`: the argv here is an editor's, so running the real
            // command with it would hand `gh` a file path where a subcommand
            // goes. The editor variable was installed by a pass that HAD a
            // policy, so arriving here means the two disagree about where the
            // repository is -- and the honest answer to that is exit 2.
            shim::Invoked::AsEditor => Err(Fatal::new(format!(
                "{name}: re-entered as this command's editor from {}, where no policy \
                 was found. Nothing was checked, so nothing should be published",
                working.display()
            ))),
        };
    };
    // Asked BEFORE the policy is read, and only here. `UPHOLD_ALLOW=all` already
    // means "run this unchecked" wherever a policy loads: every rule reports
    // itself bypassed and the command runs. The one state where the two answers
    // differed was a policy file that cannot be parsed -- there the shim refused
    // every invocation of the command it stands in front of, including the `git
    // checkout` that would put the file back.
    //
    // The refusal is right and the trap was real: the tool that stops an
    // unchecked change reaching a forge also stopped the repair of the
    // declaration that says what checking means, and the ways out were to know
    // the real binary's path or to take the link off PATH. Neither is something
    // to learn while holding a broken tree.
    //
    // It is still not a pass. Nothing is checked here and nothing pretends to
    // be: the line below says so on stderr, every time, so a bypass that became
    // habit is visible in a shell history and in a CI log.
    if guard::bypassed_entirely() {
        eprintln!(
            "uphold shim: {name} ran unchecked, by UPHOLD_ALLOW=all. Nothing here looked at \
             what it publishes."
        );
        return shim::exec_through(name, argv);
    }
    // A policy that exists and cannot be read is fatal, and the refusal names
    // the way out. Without that line the reader is holding a broken declaration
    // and a command that will not run until they know something the tool never
    // told them.
    let policy = config::load(&root, &policy_path).map_err(|error| {
        Fatal::new(format!(
            "{error}\n\nNothing checked what `{name}` would publish, so it did not run. To \
             run it anyway -- to repair the file above, for instance -- say so for this one \
             invocation:\n\n  UPHOLD_ALLOW=all {name} ..."
        ))
    })?;
    // The shimmed command's arguments stay bytes all the way to the exec. On
    // Unix an argument is an arbitrary byte string -- `git add` on a file named
    // in latin-1 is an ordinary thing to type, and this binary is installed in
    // front of `git` exactly where that happens. `shim::run` reads a lossy copy
    // to decide what the invocation is, and hands these to the exec, so the
    // command that runs is the command that was typed. Where the shim has
    // something to CHECK, it refuses the untranslatable argument itself, in the
    // words of what it could not read.
    shim::run(&root, &policy, name, argv, invoked)
}

fn main() {
    let exit = match run() {
        Ok(exit) => exit,
        Err(error) => {
            eprintln!("policy check error: {error}");
            Exit::Broken
        }
    };
    // A verdict nobody received is not a verdict. Where a write failed for a
    // reason that is not a reader closing a pipe -- a full disk under a
    // redirected report, a file this process may no longer write -- the findings
    // are not wherever they were sent, and exiting on the run's own code would
    // report a clean tree to a caller holding half a file. A reader that went
    // away is the other case and is not this one: see `out`.
    if let Some(problem) = out::unwritten() {
        eprintln!(
            "policy check error: part of this report could not be written ({problem}), so what \
             was printed is not what this run found"
        );
        std::process::exit(Exit::Broken.code());
    }
    std::process::exit(exit.code());
}

#[cfg(test)]
mod tests {
    use super::{discover, root_of};
    use std::path::{Path, PathBuf};

    /// One directory per case. The suite runs in parallel threads of a single
    /// process, so a path keyed on the process id alone is the SAME path for
    /// every case, and one case reads the tree another just built.
    fn workspace() -> PathBuf {
        let root = crate::fixture::scratch("discover");
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn write_policy(directory: &Path) -> PathBuf {
        std::fs::create_dir_all(directory.join("policy")).unwrap();
        let path = directory.join("policy/principles.toml");
        std::fs::write(&path, "allowed_scripts = [\"Latin\"]\n").unwrap();
        path
    }

    /// The live bug: nine repositories with no policy of their own, each inside
    /// a superproject that has one.
    ///
    /// The old walk climbed past the inner repository's own root, loaded the
    /// superproject's policy and adopted the SUPERPROJECT'S directory as root,
    /// so the report named files outside the repository the command was run in.
    #[test]
    fn a_repository_with_no_policy_does_not_borrow_the_superprojects() {
        let superproject = workspace();
        write_policy(&superproject);
        let inner = superproject.join("inner");
        std::fs::create_dir_all(inner.join("src")).unwrap();
        std::fs::create_dir_all(inner.join(".git")).unwrap();

        assert!(discover(&inner).is_none(), "borrowed the superproject");
        assert!(
            discover(&inner.join("src")).is_none(),
            "climbed out of the repository from a subdirectory"
        );
        // And the superproject itself still finds its own, from any depth: the
        // stop is a boundary, not a ban on walking up.
        assert_eq!(
            discover(&superproject).map(|(root, _)| root),
            Some(superproject.clone())
        );
    }

    /// A `.git` FILE is the boundary too -- that is what a linked worktree and
    /// a submodule have where a clone has a directory.
    #[test]
    fn a_git_file_stops_the_walk_the_way_a_git_directory_does() {
        let superproject = workspace();
        write_policy(&superproject);
        let inner = superproject.join("submodule");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join(".git"), "gitdir: ../.git/modules/submodule\n").unwrap();

        assert!(discover(&inner).is_none());
    }

    /// The boundary is where the walk STOPS, not where it refuses to look: a
    /// repository root carrying its own policy is the ordinary case.
    #[test]
    fn a_repository_root_with_its_own_policy_is_still_found() {
        let superproject = workspace();
        write_policy(&superproject);
        let inner = superproject.join("inner");
        std::fs::create_dir_all(inner.join(".git")).unwrap();
        let policy = write_policy(&inner);
        std::fs::create_dir_all(inner.join("src")).unwrap();

        assert_eq!(
            discover(&inner.join("src")),
            Some((inner.clone(), policy)),
            "a repository's own policy is what it is checked against"
        );
    }

    /// `--policy` derived the root by taking the file's grandparent and
    /// checking nothing, so `--policy principles.toml` rooted the scan at the
    /// repository's PARENT and a policy one directory below `/` rooted it at
    /// `/`. The default include of `["."]` then walked that.
    #[test]
    fn an_explicit_policy_off_the_layout_has_no_root_to_scan() {
        for off_layout in [
            "principles.toml",
            "/principles.toml",
            "/srv/example/rules/principles.toml",
        ] {
            let error = root_of(Path::new(off_layout))
                .expect_err("a root derived from a layout that is not there is the wrong tree");
            assert!(
                error.to_string().contains("<root>/policy/<name>.toml"),
                "{off_layout}: {error}"
            );
        }
    }

    #[test]
    fn an_explicit_policy_in_the_layout_roots_at_the_repository() {
        assert_eq!(
            root_of(Path::new("/srv/example/policy/principles.toml")).unwrap(),
            Path::new("/srv/example")
        );
    }
}
