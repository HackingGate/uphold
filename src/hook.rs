//! `uphold hook` -- the guard on the path that spawns no process.
//!
//! `shim` decides by `argv[0]`, and that answer holds for exactly as long as
//! publishing means running a command. An agent reaching a forge through an MCP
//! server sends a pull-request body over HTTPS from inside its own process:
//! there is no command, no `argv[0]`, no link to install, and every rule that
//! reads a published string sees nothing. Not because one was disabled, but
//! because all of them are reached from a seam that needs a process to have
//! been spawned first.
//!
//! What stands in for `argv[0]` is the harness's own pre-call decision point,
//! which hands a hook the pending call as JSON and reads a verdict back. This
//! is a smaller claim than the shim's and the difference is worth stating: the
//! shim reaches a human at a terminal, a CI step and a script, whatever
//! launched them, and this reaches every transport a harness can make and none
//! of it when the harness is a different one. Neither contains the other, which
//! is why installing this is not a reason to stop installing that.
//!
//! ## Which calls arrive here is not this module's decision
//!
//! A harness matches tool names itself, in its own configuration, and invokes
//! the hook for what matches. Re-deciding that here would be a second matcher
//! free to disagree with the first, and the operator would have to keep both in
//! their head. What arrives is checked; what to send is `mechanism-policy-separation`
//! answered on the harness's side of the line.
//!
//! ## The shapes are data
//!
//! Every harness asks the same three things in its own spelling: what is this
//! call, what is it about to send, and how do I say no. Those are JSON pointers
//! and a refusal document, so they are a table rather than a function per
//! harness -- `parameterize-do-not-enumerate`, and the same move `shim` made
//! when `SPEC_MATCH` stopped being a bash variable. A harness the table does
//! not describe is named and refused, never guessed at.
//!
//! ## The exit code is not uphold's to choose
//!
//! Everywhere else in this binary, 1 means refused and 2 means could not look.
//! Here the harness owns the protocol: Claude Code reads a refusal out of a
//! JSON document on stdout and treats a non-zero status as an error in the hook
//! rather than a verdict on the call, so exiting 1 to signal a refusal would
//! let the call through with a complaint attached. The refusal travels in the
//! document, and it is ALSO printed to stderr, so that a person running
//! `uphold hook` by hand sees the report rather than a line of JSON.

use std::fmt::Write as _;
use std::io::Read;
use std::path::PathBuf;

use serde_json::Value;

use crate::config::{self, Policy};
use crate::error::{Exit, Fatal, Result};
use crate::guard;
use crate::text;

/// What one harness calls the three things every harness has.
struct Shape {
    /// The name this harness is asked for by, on the command line.
    name: &'static str,
    /// JSON pointer to what the call is called. Reported, never matched on.
    label: &'static str,
    /// JSON pointer to the object holding what the call is about to send.
    subject: &'static str,
    /// The document a refusal is spelled as, for the harness to read.
    refusal: &'static str,
    /// Where inside that document the report belongs.
    reason_at: &'static str,
    /// What this harness reads as "blocked". See the module doc.
    refused: Exit,
}

/// One entry. A second harness is two pointers and a document, and if adding it
/// turns out to need a function instead, that is the discovery that this table
/// was the wrong shape rather than a reason to special-case one member of it.
const SHAPES: &[Shape] = &[Shape {
    name: "claude-code",
    label: "/tool_name",
    subject: "/tool_input",
    refusal: r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}"#,
    reason_at: "/hookSpecificOutput/permissionDecisionReason",
    refused: Exit::Clean,
}];

/// The names this binary knows, for the refusal that lists them.
pub(crate) fn known() -> String {
    SHAPES
        .iter()
        .map(|shape| shape.name)
        .collect::<Vec<&str>>()
        .join("|")
}

/// Every string anywhere under `value`.
///
/// Deliberately not a list of field names per harness and per tool. A server
/// decides what to call the field holding a pull-request body, a release note
/// or a branch name, and a table of those names is a table that is missing the
/// one a new server just added -- silently, and in the green direction. Reading
/// them all costs a second pass over text that is already in memory; missing
/// one costs the whole seam.
///
/// The order is whatever the JSON reader hands back, which for an object is by
/// key rather than by the order somebody wrote the fields in. Nothing here
/// depends on it: the strings are joined and searched, and a rule that matched
/// only when two fields happened to be adjacent would be a rule about the
/// harness's serializer.
fn strings(value: &Value, into: &mut Vec<String>) {
    match value {
        Value::String(text) => into.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                strings(item, into);
            }
        }
        Value::Object(fields) => {
            for field in fields.values() {
                strings(field, into);
            }
        }
        _ => {}
    }
}

/// Put the report inside the harness's refusal document.
///
/// Through `serde_json` rather than by formatting a string, because a report
/// carries newlines, quotes and whatever the offending text was, and a hand
/// written template is how a refusal about unusual characters becomes a
/// document the harness cannot parse.
fn refusal_document(shape: &Shape, report: &str) -> Result<String> {
    let mut document: Value = serde_json::from_str(shape.refusal)
        .map_err(|error| Fatal::new(format!("{}: malformed refusal shape: {error}", shape.name)))?;
    let (parent, key) = shape.reason_at.rsplit_once('/').ok_or_else(|| {
        Fatal::new(format!(
            "{}: refusal shape names no place for the report",
            shape.name
        ))
    })?;
    let target = document
        .pointer_mut(parent)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            Fatal::new(format!(
                "{}: refusal shape has no object at {parent:?}",
                shape.name
            ))
        })?;
    target.insert(key.to_owned(), Value::String(report.to_owned()));
    serde_json::to_string(&document)
        .map_err(|error| Fatal::new(format!("{}: refusal is not writable: {error}", shape.name)))
}

/// Judge one pending tool call, read from stdin in the harness's own shape.
///
/// `found` is the policy where the call was made, and it is an `Option` here
/// where every other seam requires one: a git hook runs in the repository whose
/// policy applies by construction, and a tool call does not. What still runs
/// without one is the host-identity half, which carries its own fallback for
/// exactly this case; the guards do not, and their absence is reported rather
/// than counted as a pass.
pub(crate) fn run(harness: &str, found: Option<&(PathBuf, PathBuf)>) -> Result<Exit> {
    let shape = SHAPES
        .iter()
        .find(|shape| shape.name == harness)
        .ok_or_else(|| {
            Fatal::new(format!(
                "unknown harness {harness:?}. This binary knows {}. A harness it does not \
                 describe is refused rather than guessed at: the pointers into its event and \
                 the document it reads a refusal from are not derivable from the name",
                known()
            ))
        })?;

    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw)?;
    // Exit 2 and not 1. A malformed event is nothing found and nothing cleared,
    // and it is also the failure mode of a harness that changed its schema --
    // which the operator has to be told about rather than have reported as a
    // call that passed.
    let event: Value = serde_json::from_str(&raw).map_err(|error| {
        Fatal::new(format!(
            "the {harness} event is not JSON ({error}), so nothing in it was checked and \
             \"allowed\" would mean \"unexamined\""
        ))
    })?;

    // The label is what the report calls this call, and nothing else conditions
    // on it. An event that does not carry one is checked exactly as thoroughly
    // with the harness name in its place: refusing over a field that only
    // decides a word in a message would be a gate firing on work it had no
    // finding about, which is how a gate on a hot path gets deleted.
    let label = event
        .pointer(shape.label)
        .and_then(Value::as_str)
        .unwrap_or(harness);

    // Absent is not empty, and the difference is the whole of `explicit-unknown`
    // at this seam. An event carrying nothing at all where the subject belongs
    // is a harness whose schema moved, or a name pointed at the wrong shape --
    // and what the call was about to send was not read. Reporting that as a
    // clean call is the failure this module refuses one level up, where an
    // event that is not JSON exits 2 rather than passing.
    //
    // What is NOT this case: a subject that is present and holds no strings. A
    // call carrying only numbers and flags publishes no text there is a rule
    // about, it was read, and it passed. Nor is a subject that is a bare string
    // rather than an object -- that is text, and it is checked as text. The
    // question here is whether the subject was found, never what shape the
    // harness chose for it.
    let Some(subject) = event.pointer(shape.subject) else {
        return Err(Fatal::new(format!(
            "the {harness} event carries nothing at {:?}, so what this call was about to \
             send could not be read and \"allowed\" would mean \"unexamined\". That pointer \
             is the shape this harness's events have; an event without it is a harness that \
             changed rather than a call that published nothing",
            shape.subject
        )));
    };

    let mut collected = Vec::new();
    strings(subject, &mut collected);
    // Read, and carrying no text this binary has a rule about.
    if collected.is_empty() {
        return Ok(Exit::Clean);
    }
    let text = collected.join("\n");

    let mut report = String::new();

    // The host-identity rules run wherever the call was made from, policy or
    // no policy: `text::failures` carries its own fallback for exactly this
    // case, and it is the case a tool call is usually in. A session starts in
    // a workspace superproject, a scratch directory, or a checkout that has no
    // policy of its own, and a seam that stood down there would be absent in
    // precisely the places nobody thought to configure it.
    for failure in text::failures(found, &text)? {
        writeln!(
            report,
            "policy check failed: {}\n{}\n",
            failure.label,
            failure.body.trim_end()
        )
        .ok();
    }

    // The guards need a policy, because which guards a repository runs is that
    // repository's own answer and an enclosing superproject's is not borrowed.
    // Where there is none they do not run, and saying so on stderr is the
    // difference between a check that passed and a check that did not happen.
    match found {
        Some((root, policy_path)) => {
            let policy: Policy = config::load(root, policy_path)?;
            for refusal in guard::over_text(root, &policy, label, &text)? {
                writeln!(
                    report,
                    "guard refused: {}\n{}\n",
                    guard::refused_by(&policy, &refusal),
                    refusal.report.trim_end()
                )
                .ok();
            }
        }
        None => eprintln!(
            "uphold hook: no policy where this call was made, so the guards did not run \
             and only the host-identity rules did. That is partial coverage, not a pass."
        ),
    }

    if report.is_empty() {
        return Ok(Exit::Clean);
    }

    let report = format!(
        "uphold refused what {label} was about to publish.\n\n{report}Nothing was sent. Fix the \
         text and make the call again."
    );
    eprintln!("{report}");
    println!("{}", refusal_document(shape, &report)?);
    Ok(shape.refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape() -> &'static Shape {
        SHAPES.first().unwrap()
    }

    #[test]
    fn every_string_is_collected_whatever_the_field_is_called() {
        let event: Value = serde_json::from_str(
            r#"{"title":"a","nested":{"body":"b"},"list":["c"],"count":1,"flag":true}"#,
        )
        .unwrap();
        let mut found = Vec::new();
        strings(&event, &mut found);
        found.sort();
        assert_eq!(found, vec!["a", "b", "c"]);
    }

    /// The report is what the offending text is quoted in, so the one thing the
    /// refusal document must survive is the text that caused it.
    #[test]
    fn a_report_full_of_quotes_and_newlines_stays_parseable() {
        let report = "line \"one\"\nline\ttwo \\ three\nU+2014 EM DASH";
        let written = refusal_document(shape(), report).unwrap();
        let parsed: Value = serde_json::from_str(&written).unwrap();
        assert_eq!(
            parsed
                .pointer("/hookSpecificOutput/permissionDecisionReason")
                .and_then(Value::as_str),
            Some(report)
        );
    }

    #[test]
    fn the_refusal_keeps_the_fields_the_harness_reads() {
        let written = refusal_document(shape(), "because").unwrap();
        let parsed: Value = serde_json::from_str(&written).unwrap();
        assert_eq!(
            parsed
                .pointer("/hookSpecificOutput/permissionDecision")
                .and_then(Value::as_str),
            Some("deny")
        );
        assert_eq!(
            parsed
                .pointer("/hookSpecificOutput/hookEventName")
                .and_then(Value::as_str),
            Some("PreToolUse")
        );
    }
}
