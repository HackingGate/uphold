//! A rule a bundled set already ships, written out by hand instead.
//!
//! Every other check in this binary reads a repository's CONTENT. This one
//! reads its policy, because the defect it is about leaves no trace in any
//! tracked file: a rule copied out of a bundled set into a repository's own
//! policy is a rule that has stopped moving. The set's copy is compiled in and
//! is whatever the installed binary says it is; the transcription is frozen at
//! the moment somebody typed it, and nothing anywhere compares the two. The id
//! is present, the claim in `upheld.toml` resolves, `uphold check` reconciles
//! green -- over a rule that may no longer match what the rule it is named
//! after matches.
//!
//! Measured, across the fleet that produced this check: two repositories had
//! hand-rolled the compiled-in Unicode class as a `regexp` literal under the
//! id of the built-in, declared no `git.hooks` for it, and both reconciled
//! clean.
//!
//! WHAT IT DOES NOT FIRE ON, and the exclusion is the design:
//!
//! * A repository that inherits the set and overrides one of its ids. That is
//!   the documented override, it is a decision written in the same file as the
//!   `[inherit]` line that makes it visible, and the loader already says so
//!   when the override changes the check kind (`config::report_reshaped_shadows`).
//! * An id no bundled set owns. A repository's own rules are its own business;
//!   this is about the ones it did not have to write.
//!
//! It registers at `manual` and nowhere else. A check that reports on the
//! SHAPE of a policy has no business standing between anyone and a commit
//! before its false-positive behaviour has been seen in the open -- and a rule
//! that arrives inside a set eight in ten adopting repositories already
//! inherit is a rule nobody in those repositories reviewed.

use std::fmt::Write as _;

use super::{Refusal, Request};
use crate::config::{bundled_ids, Origin};
use crate::error::Result;

pub(crate) fn no_hand_copied_base_rule(request: &Request<'_>) -> Result<Option<Refusal>> {
    let owned = bundled_ids()?;
    let policy = request.policy;

    let mut findings: Vec<String> = Vec::new();
    let mut sets: Vec<&str> = Vec::new();
    for rule in &policy.rules {
        if rule.origin != Origin::Own {
            continue;
        }
        let Some((set, ids)) = owned.iter().find(|(_, ids)| ids.contains(&rule.id)) else {
            continue;
        };
        if policy.inherited_sets.iter().any(|name| name == set) {
            // Inherited and overridden: the documented shadow, and a decision
            // this repository wrote down beside the `[inherit]` line that
            // shows it.
            continue;
        }
        // The coverage delta is the argument, not decoration. Inheriting the
        // set to replace one hand-copied rule is only worth doing if the rest
        // of the set is worth having, and the reader cannot weigh that without
        // being told what the rest of the set is.
        let missing: Vec<&str> = ids
            .iter()
            .filter(|id| !policy.rules.iter().any(|declared| declared.id == **id))
            .map(String::as_str)
            .collect();
        let mut finding = format!("  {} -- shipped by the bundled set {set:?}", rule.id);
        if missing.is_empty() && ids.len() == 1 {
            // A one-rule set has no delta to report, and saying "every other
            // rule is already here" of a set with no other rule is a sentence
            // that reads like a measurement and is a tautology.
            finding.push_str("\n    That set holds this rule and nothing else.");
        } else if missing.is_empty() {
            finding.push_str(
                "\n    Every other rule in that set is already declared here, by hand, \
                 one by one.",
            );
        } else {
            write!(
                finding,
                "\n    Inheriting it would also bring {}: {}",
                missing.len(),
                missing.join(", ")
            )
            .ok();
        }
        findings.push(finding);
        sets.push(set);
    }

    if findings.is_empty() {
        return Ok(None);
    }

    let mut report = String::from(
        "this policy writes out rules a bundled set already ships, from sets it does not \
         inherit:\n\n",
    );
    report.push_str(&findings.join("\n"));
    report.push_str(
        "\n\nA transcribed rule is a rule that has stopped moving: the bundled one is \
         re-read from the binary on every run, and this copy is whatever was typed the day \
         it was typed. Take the set instead:\n\n  [inherit]\n  sets = [",
    );
    sets.sort_unstable();
    sets.dedup();
    let quoted: Vec<String> = sets.iter().map(|set| format!("{set:?}")).collect();
    report.push_str(&quoted.join(", "));
    report.push_str(
        "]\n\nand delete the local copy. `uphold rules --set <name>` prints what a set \
         holds before you take it. If the copy is deliberately narrower than the bundled \
         rule, give it an id of its own -- an id that names somebody else's rule while \
         checking something else is the one shape nothing here can see.",
    );

    Ok(Some(Refusal {
        id: request.rule.id.clone(),
        report,
    }))
}
