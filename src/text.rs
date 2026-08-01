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
    rule.forbidden_literals = Some(String::from("running-os-identity"));
    rule
}

fn read(source: &str) -> Result<String> {
    if source == "-" {
        let mut buffer = Vec::new();
        std::io::stdin().read_to_end(&mut buffer)?;
        return Ok(String::from_utf8_lossy(&buffer).into_owned());
    }
    let path = PathBuf::from(source);
    let bytes = std::fs::read(&path).map_err(|error| Fatal::at(&path, error))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub(crate) fn check(found: Option<&(PathBuf, PathBuf)>, source: &str) -> Result<Exit> {
    let text = read(source)?;

    let (root, policy) = match found {
        Some((root, policy_path)) => (root.clone(), config::load(root, policy_path)?),
        None => (std::env::current_dir()?, Policy::default()),
    };

    let owned: Vec<Rule> = if policy.has_check(Check::ForbiddenLiterals) {
        policy.of_check(Check::ForbiddenLiterals).cloned().collect()
    } else {
        vec![fallback_rule()]
    };

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
