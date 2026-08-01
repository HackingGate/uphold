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

mod audit;
mod config;
mod engine;
mod error;
mod git;
mod guard;
mod pins;
mod report;
mod runner;
mod scan;
mod selection;
mod shim;
mod sources;
mod text;

use std::path::{Path, PathBuf};

use crate::error::{Exit, Fatal, Result};

const USAGE: &str = "\
usage:
  uphold scan [--policy PATH]        run the content policy over this repository
  uphold scan --text [FILE|-]        run the host-identity rules over text
  uphold guard --stage STAGE         run the guards that fire at STAGE
  uphold guard --text [FILE|-]       run the text-capable guards over text
  uphold audit --for-publication     what a private->public flip would republish
  uphold rules --set NAME            what a bundled rule set refuses, rule by rule
  uphold shim <command> [args...]     check what a command would publish, then run it

Invoked under a command's own name -- a link called `gh` on PATH ahead of the
real one -- the binary runs that command's shim directly. That is what a
multicall binary is for: argv[0] decides, and there is no installer.
  uphold --version

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

/// Walk up from the working directory until a policy file appears.
fn discover(start: &Path) -> Option<(PathBuf, PathBuf)> {
    let mut candidate = start.to_path_buf();
    loop {
        for name in POLICY_NAMES {
            let policy = candidate.join("policy").join(name);
            if policy.is_file() {
                return Some((candidate.clone(), policy));
            }
        }
        if !candidate.pop() {
            return None;
        }
    }
}

fn run() -> Result<Exit> {
    // argv[0] first. Invoked through a link named for a command it shims, the
    // binary IS that shim -- which is what ends `install.sh` and the
    // sibling-checkout coupling: there is nothing to install but a link, and
    // nothing to find but this binary.
    let invoked_as = std::env::args()
        .next()
        .map(PathBuf::from)
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    if !invoked_as.is_empty() && invoked_as != "uphold" {
        let argv: Vec<String> = std::env::args().skip(1).collect();
        return shim_command(&invoked_as, &argv);
    }

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut arguments = argv.iter().map(String::as_str);

    match arguments.next() {
        Some("--version" | "-V") => {
            println!("uphold {}", env!("CARGO_PKG_VERSION"));
            Ok(Exit::Clean)
        }
        Some("--help" | "-h") | None => {
            print!("{USAGE}");
            Ok(Exit::Clean)
        }
        Some("scan") => scan_command(&arguments.collect::<Vec<_>>()),
        Some("guard") => guard_command(&arguments.collect::<Vec<_>>()),
        Some("audit") => audit_command(&arguments.collect::<Vec<_>>()),
        Some("rules") => {
            let rest: Vec<&str> = arguments.collect();
            match rest.as_slice() {
                ["--set", name] => rules_command(name),
                _ => Err(Fatal::new(format!(
                    "usage: uphold rules --set NAME\n\n{USAGE}"
                ))),
            }
        }
        Some("shim") => {
            let rest: Vec<&str> = arguments.collect();
            let (name, shimmed) = rest
                .split_first()
                .ok_or_else(|| Fatal::new(format!("shim needs a command\n\n{USAGE}")))?;
            shim_command(
                name,
                &shimmed
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<String>>(),
            )
        }
        Some(other) => Err(Fatal::new(format!(
            "unknown subcommand {other:?}\n\n{USAGE}"
        ))),
    }
}

fn scan_command(arguments: &[&str]) -> Result<Exit> {
    let mut explicit_policy: Option<PathBuf> = None;
    let mut text_source: Option<String> = None;
    let mut index = 0;
    while let Some(argument) = arguments.get(index).copied() {
        match argument {
            "--policy" => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| Fatal::new("--policy needs a path"))?;
                explicit_policy = Some(PathBuf::from(value));
            }
            "--text" => {
                index += 1;
                text_source = Some(arguments.get(index).copied().unwrap_or("-").to_owned());
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
            let root = policy
                .parent()
                .and_then(Path::parent)
                .map_or_else(|| working.clone(), Path::to_path_buf);
            Some((root, policy))
        }
        None => discover(&working),
    };

    if let Some(source) = text_source {
        return text::check(found.as_ref(), &source);
    }

    let Some((root, policy_path)) = found else {
        return Err(Fatal::new(format!(
            "no policy file found (looked for policy/{} walking up from {})",
            POLICY_NAMES.join(" or policy/"),
            working.display()
        )));
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

    if failures.is_empty() {
        println!("policy checks passed");
        return Ok(Exit::Clean);
    }
    Ok(Exit::Violations)
}

fn guard_command(arguments: &[&str]) -> Result<Exit> {
    let mut stage: Option<guard::Stage> = None;
    let mut message: Option<PathBuf> = None;
    let mut remote_name: Option<String> = None;
    let mut remote_url: Option<String> = None;
    let mut text_source: Option<String> = None;
    let mut index = 0;
    while let Some(argument) = arguments.get(index).copied() {
        let value = |at: usize, flag: &str| -> Result<String> {
            arguments
                .get(at)
                .map(ToString::to_string)
                .ok_or_else(|| Fatal::new(format!("{flag} needs a value")))
        };
        match argument {
            "--stage" => {
                index += 1;
                stage = Some(guard::Stage::parse(&value(index, "--stage")?)?);
            }
            "--message" => {
                index += 1;
                message = Some(PathBuf::from(value(index, "--message")?));
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
                text_source = Some(arguments.get(index).copied().unwrap_or("-").to_owned());
            }
            other => return Err(Fatal::new(format!("unknown option {other:?}\n\n{USAGE}"))),
        }
        index += 1;
    }

    let working = std::env::current_dir()?;
    let (root, policy_path) = discover(&working).ok_or_else(|| {
        Fatal::new(format!(
            "no policy file found (looked for policy/{} walking up from {})",
            POLICY_NAMES.join(" or policy/"),
            working.display()
        ))
    })?;
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
            eprintln!("guard refused: {}", refusal.id);
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

fn audit_command(arguments: &[&str]) -> Result<Exit> {
    // No default mode. `audit` on its own would have to pick a question, and
    // the one it would pick is the one this tool exists because nothing asks.
    match arguments.first().copied() {
        Some("--for-publication") if arguments.len() == 1 => {}
        _ => {
            return Err(Fatal::new(format!(
                "audit needs --for-publication\n\n{USAGE}"
            )))
        }
    }
    let working = std::env::current_dir()?;
    let (root, policy_path) = discover(&working).ok_or_else(|| {
        Fatal::new(format!(
            "no policy file found (looked for policy/{} walking up from {})",
            POLICY_NAMES.join(" or policy/"),
            working.display()
        ))
    })?;
    let policy = config::load(&root, &policy_path)?;
    audit::for_publication(&root, &policy)
}

/// What one bundled set refuses, so nobody has to read the docs -- or the
/// source -- to learn what a name they are about to inherit means.
fn rules_command(name: &str) -> Result<Exit> {
    let rules = config::bundled_set(name)?;
    println!("{name}: {} rule(s)", rules.len());
    for rule in rules {
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

fn shim_command(name: &str, argv: &[String]) -> Result<Exit> {
    let working = std::env::current_dir()?;
    let (root, policy_path) = discover(&working).ok_or_else(|| {
        Fatal::new(format!(
            "no policy file found (looked for policy/{} walking up from {})",
            POLICY_NAMES.join(" or policy/"),
            working.display()
        ))
    })?;
    let policy = config::load(&root, &policy_path)?;
    shim::run(&root, &policy, name, argv)
}

fn main() {
    let exit = match run() {
        Ok(exit) => exit,
        Err(error) => {
            eprintln!("policy check error: {error}");
            Exit::Broken
        }
    };
    std::process::exit(exit.code());
}
