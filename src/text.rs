//! Checking something that never becomes a file.
//!
//! A commit message, a pull-request body, a release note. Those are published
//! the moment they are written, and a file-scanning checker cannot see them at
//! all -- the content reaches a public API without passing through the tree it
//! would have been scanned in.
//!
//! Only the literal rules apply. They are the ones whose needles describe the
//! RUNNING HOST rather than a repository convention, so they mean something
//! against any text. A pattern rule is scoped by `include` and `glob` to
//! particular paths and file types; firing it at a pull-request body would be
//! guesswork, and a guard that guesses gets turned off.

use std::io::Read;
use std::path::PathBuf;

use crate::config::{self, Check, Policy, Rule};
use crate::engine::{self, Query};
use crate::error::{Exit, Fatal, Result};
use crate::report::Failure;
use crate::sources;

/// The built-in literal source that reads the running host: its username, its
/// home path, its hostname. Named once, because the fallback below and the test
/// for whether anything already covers it have to mean the same string.
const RUNNING_OS_IDENTITY: &str = "running-os-identity";

/// Used when the caller's repository declares no dynamic rules of its own, or
/// has no policy file at all.
///
/// Text mode is reached from things like `gh pr create`, which runs wherever the
/// author happens to be standing: a superproject that only tracks submodules, a
/// scratch checkout, someone else's clone. Falling back to "nothing to check"
/// there would leave the guard absent in exactly the places nobody thought to
/// configure it, which is how identity gets published.
fn fallback_rule() -> Rule {
    let mut rule = Rule::synthetic("no-running-os-identity-metadata", Check::ForbiddenLiterals);
    rule.message = Some(String::from(
        "Do not put identity metadata from the running OS into text that gets published. \
         The policy checker reads the current username, home path, and hostname (including \
         the identifying parts of it) at runtime, then searches the text you are about to \
         send. Use neutral placeholders such as example-user, example-host, example.test, \
         and /srv/example instead.",
    ));
    rule.forbidden_literals = Some(String::from(RUNNING_OS_IDENTITY));
    rule
}

/// The text to judge, or a refusal.
///
/// `from_utf8_lossy` stood here, and it is the quiet version of the failure
/// this whole tool is about: an invalid sequence became U+FFFD without a word,
/// so `printf 'caf\xe9 latin1\n' | uphold scan --text -` printed "policy checks
/// passed (text)" and exited 0 over bytes that were never the text they were
/// searched as. Every other reader in this binary already refuses this --
/// `scan` says "clean would mean unexamined" about a non-UTF-8 file, and
/// `guard --text` errors out -- so this is the one place the answer differed.
///
/// It is exit 2 rather than exit 1: nothing was found and nothing was cleared.
/// The bytes could not be looked at.
fn decode(bytes: Vec<u8>, source: &str) -> Result<String> {
    String::from_utf8(bytes).map_err(|error| {
        Fatal::new(format!(
            "{source}: is not UTF-8 (invalid byte at offset {}), so it cannot be searched \
             as text and \"clean\" would mean \"unexamined\". Re-encode it as UTF-8, or \
             hand this checker the text rather than the bytes",
            error.utf8_error().valid_up_to()
        ))
    })
}

fn read(source: &str) -> Result<String> {
    if source == "-" {
        let mut buffer = Vec::new();
        std::io::stdin().read_to_end(&mut buffer)?;
        return decode(buffer, "standard input");
    }
    let path = PathBuf::from(source);
    let bytes = std::fs::read(&path).map_err(|error| Fatal::at(&path, error))?;
    decode(bytes, source)
}

pub(crate) fn check(found: Option<&(PathBuf, PathBuf)>, source: &str) -> Result<Exit> {
    let text = read(source)?;

    let (root, policy) = match found {
        Some((root, policy_path)) => (root.clone(), config::load(root, policy_path)?),
        None => (std::env::current_dir()?, Policy::default()),
    };

    // The test is for the identity rule itself, not for the CHECK KIND it
    // happens to use. Asking whether any `forbidden_literals` rule existed made
    // an unrelated one -- a repository's own list of literals, a command
    // source, anything at all -- silently remove the fallback, which exists per
    // its own docstring so that the guard is not absent "in exactly the places
    // nobody thought to configure it, which is how identity gets published".
    // Declaring a rule about something else is not a decision to stop checking
    // this, so both run: the declared rules, and the fallback when nothing
    // among them reads the running host's identity.
    let mut owned: Vec<Rule> = policy.of_check(Check::ForbiddenLiterals).cloned().collect();
    if !owned
        .iter()
        .any(|rule| rule.forbidden_literals.as_deref() == Some(RUNNING_OS_IDENTITY))
    {
        owned.push(fallback_rule());
    }

    let mut failures: Vec<Failure> = Vec::new();
    for rule in &owned {
        let needles = sources::resolve(
            // `forbidden_literals_from` IS the command source; v2 said it twice.
            if rule.forbidden_literals_from.is_some() {
                "command"
            } else {
                rule.forbidden_literals.as_deref().unwrap_or_default()
            },
            rule.forbidden_literals_from.as_deref(),
            &root,
            rule.files().word,
            &rule.id,
            rule.ignore_literals.as_deref().unwrap_or(&[]),
        )?;
        for needle in needles {
            let label = format!("{} ({})", rule.id, needle.label);
            let hits =
                engine::search_text(&text, &Query::literal(&needle.value, needle.word), &label)?;
            if hits.is_empty() {
                continue;
            }
            let body = hits
                .iter()
                .map(|hit| {
                    let line = hit.line.unwrap_or(0);
                    if policy.redact_matches {
                        format!("line {line}: [REDACTED_MATCH]")
                    } else {
                        format!("line {line}: {}", hit.text)
                    }
                })
                .collect::<Vec<String>>()
                .join("\n");
            failures.push(Failure::new(label, rule.message(), body));
        }
    }

    for failure in &failures {
        failure.print();
    }
    if failures.is_empty() {
        println!("policy checks passed (text)");
        return Ok(Exit::Clean);
    }
    Ok(Exit::Violations)
}
