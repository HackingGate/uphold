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
//! # Two stages, and they answer different questions
//!
//! It shipped at `manual` and nowhere else, on the reasoning that a check
//! reporting on the SHAPE of a policy has no business standing between anyone
//! and a commit before its false-positive behaviour has been seen in the open.
//! That reasoning was sound and its consequence was measured: a sweep of 77
//! repositories found 76 inheriting `process-residue` -- so the check was
//! LOADED almost everywhere -- and roughly forty of them carrying
//! transcriptions it had never once reported. Nothing runs a manual stage on
//! its own. A report a reader has to ask for is a report nobody asks for, and
//! the coverage of this check was zero in every repository that had it.
//!
//! So it now runs at `pre-commit` as well, and the two stages say different
//! things:
//!
//! * `manual` reports EVERY transcription, which is the sweep. Unchanged.
//! * `pre-commit` refuses only the transcriptions THIS COMMIT INTRODUCES --
//!   ids absent from the policy file as of `HEAD`.
//!
//! The ratchet is not softness, it is the only shape in which this can arrive
//! at a hook at all. Arriving as a gate over existing declarations would refuse
//! the next commit in roughly forty repositories on the strength of a version
//! bump, with nothing in any of those trees to review -- and the cheapest
//! response to that is switching the check off, which returns coverage to the
//! zero it already had. Refusing what is being ADDED costs nothing in a
//! repository that adds none, and it is the whole of what the sweep needs:
//! deleting the copies is worth doing only if the sweep cannot refill.
//!
//! What the ratchet reads is `HEAD`, not the index. A transcription staged and
//! committed in one go is new against `HEAD` and is refused; one that was
//! already committed is not, whoever staged it. That is the same baseline a
//! reviewer would use, and it is the only one that does not need this check to
//! have been installed when the copy was made.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use super::{Refusal, Request, Stage};
use crate::config::{bundled_ids, Origin, Policy};
use crate::error::Result;
use crate::git;

/// One transcription: the id, the bundled set that owns it, and the paragraph a
/// reader is shown.
struct Finding {
    id: String,
    set: &'static str,
    text: String,
}

pub(crate) fn no_hand_copied_base_rule(request: &Request<'_>) -> Result<Option<Refusal>> {
    let findings = findings(request.policy)?;
    if findings.is_empty() {
        return Ok(None);
    }

    // `manual` is the sweep and reports everything. Every other stage is a
    // ratchet over what this change introduces -- and `pre-commit` is the only
    // other stage the set is permitted to install, so the arm is written the
    // way the permission is: manual reports, anything else ratchets.
    let (findings, baseline) = if request.stage == Stage::Manual {
        (findings, Baseline::NotAsked)
    } else {
        let baseline = declared_at_head(request.root, request.policy)?;
        let introduced: Vec<Finding> = findings
            .into_iter()
            .filter(|finding| !baseline.holds(&finding.id))
            .collect();
        if introduced.is_empty() {
            return Ok(None);
        }
        (introduced, baseline)
    };

    Ok(Some(Refusal {
        id: request.rule.id.clone(),
        report: report(&findings, request.stage, &baseline),
    }))
}

/// What the committed policy file said, and whether it could be read at all.
///
/// The third case is the one that has to exist. Folding "HEAD's policy would
/// not parse" into "HEAD declared nothing" makes every transcription already in
/// the file read as one this change introduced -- which is a measurement
/// reported over a comparison that never happened, and the reader would be told
/// they added nine rules while repairing a broken file.
enum Baseline {
    /// `manual` reports the whole policy, so no comparison was made.
    NotAsked,
    /// The ids the committed policy file declared.
    Declared(BTreeSet<String>),
    /// There is a committed policy file and it could not be parsed.
    Unreadable,
}

impl Baseline {
    /// Was this id already declared in the committed file?
    ///
    /// `false` where the baseline is unreadable, so the finding is still
    /// reported: a comparison that could not be made is not a comparison that
    /// passed. What stops that being a lie is [`Baseline::caveat`], which says
    /// on the refusal itself that the comparison did not happen.
    fn holds(&self, id: &str) -> bool {
        match self {
            Self::Declared(ids) => ids.contains(id),
            Self::NotAsked | Self::Unreadable => false,
        }
    }

    fn caveat(&self) -> Option<&'static str> {
        matches!(self, Self::Unreadable).then_some(
            "\n\nThe policy file at HEAD could not be parsed, so nothing could be compared \
             against it. Every id above may already have been here; what is certain is only \
             that they are here now.",
        )
    }
}

/// Every rule this policy wrote out itself that a bundled set it does not
/// inherit already ships.
fn findings(policy: &Policy) -> Result<Vec<Finding>> {
    let owned = bundled_ids()?;
    let mut findings: Vec<Finding> = Vec::new();

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
        let mut text = format!("  {} -- shipped by the bundled set {set:?}", rule.id);
        if missing.is_empty() && ids.len() == 1 {
            // A one-rule set has no delta to report, and saying "every other
            // rule is already here" of a set with no other rule is a sentence
            // that reads like a measurement and is a tautology.
            text.push_str("\n    That set holds this rule and nothing else.");
        } else if missing.is_empty() {
            text.push_str(
                "\n    Every other rule in that set is already declared here, by hand, \
                 one by one.",
            );
        } else {
            write!(
                text,
                "\n    Inheriting it would also bring {}: {}",
                missing.len(),
                missing.join(", ")
            )
            .ok();
        }
        findings.push(Finding {
            id: rule.id.clone(),
            set,
            text,
        });
    }

    Ok(findings)
}

/// The ids this repository's own policy file declared as of `HEAD`.
///
/// Only the repository's own file is read, because [`Origin::Own`] means
/// exactly that file: a rule reaching the policy through `inherit.paths` is
/// `Origin::Path` and never reaches [`findings`].
///
/// An EMPTY declaration -- not `Unreadable` -- is returned for a policy file git
/// has never seen: an unborn branch, or a file this very commit adds. That is
/// an answer rather than a missing one, and the right answer, because every id
/// in a policy file being written now is an id being written now. The failure
/// that is NOT folded in is git being unable to run at all, which
/// `git::try_run` reports rather than swallows.
fn declared_at_head(root: &Path, policy: &Policy) -> Result<Baseline> {
    let Some(relative) = relative_to(root, &policy.path) else {
        // A policy file outside the repository it is the policy for. There is
        // no committed counterpart to have declared anything.
        return Ok(Baseline::Declared(BTreeSet::new()));
    };
    let Some(text) = git::try_run(root, &["show", &format!("HEAD:{relative}")])? else {
        return Ok(Baseline::Declared(BTreeSet::new()));
    };
    // Parsed as an untyped document on purpose. The question is which ids the
    // committed file DECLARED, and a committed file that no longer LOADS --
    // written against an older binary, carrying a field this one refuses -- has
    // still declared them. Holding the baseline to today's schema would turn
    // "this rule is not new" into "this file did not parse", which is the
    // reading that refuses work over a change that fixed something.
    //
    // What is left is a file that is not TOML at all, and that is a different
    // answer from "declared nothing": treating it as an empty baseline would
    // report every transcription already in the file as one this change
    // introduced, in exactly the commit that repairs the broken file.
    let Ok(document) = text.parse::<toml::Table>() else {
        return Ok(Baseline::Unreadable);
    };
    Ok(Baseline::Declared(
        document
            .get("rule")
            .and_then(toml::Value::as_table)
            .map(|rules| rules.keys().cloned().collect())
            .unwrap_or_default(),
    ))
}

/// `path` as git spells it, relative to the repository root.
fn relative_to(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    let parts: Vec<String> = relative
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect();
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn report(findings: &[Finding], stage: Stage, baseline: &Baseline) -> String {
    let mut report = String::from(if stage == Stage::Manual {
        "this policy writes out rules a bundled set already ships, from sets it does not \
         inherit:\n\n"
    } else {
        // Named as a change and not as a state, because that is what was
        // judged. A reader shown "this policy writes out" over one line of a
        // diff would go looking for the other eight and be told they are fine.
        "this change adds rules a bundled set already ships, from sets this policy does not \
         inherit:\n\n"
    });
    report.push_str(
        &findings
            .iter()
            .map(|finding| finding.text.as_str())
            .collect::<Vec<&str>>()
            .join("\n"),
    );
    report.push_str(
        "\n\nA transcribed rule is a rule that has stopped moving: the bundled one is \
         re-read from the binary on every run, and this copy is whatever was typed the day \
         it was typed. Take the set instead:\n\n  [inherit]\n  sets = [",
    );
    let mut sets: Vec<&str> = findings.iter().map(|finding| finding.set).collect();
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
    if stage != Stage::Manual {
        report.push_str(
            "\n\nOnly what this change ADDS is refused here; `uphold guard --stage manual` \
             reports every transcription already in this policy.",
        );
    }
    if let Some(caveat) = baseline.caveat() {
        report.push_str(caveat);
    }
    report
}
