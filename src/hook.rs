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
//! ## Which calls arrive is the harness's; which are judged is the policy's
//!
//! A harness matches tool names itself, in its own configuration, and invokes
//! the hook for what matches. That matcher is one line serving every consumer
//! of it, so it cannot say which of a server's tools publish, or where to:
//! that is each repository's policy. A `[[hook]]` table says it -- see
//! [`table`] -- and a call it names as a read is not judged, while a call it
//! names a destination for is judged under each rule's scope at that
//! destination, as the shim judges the same act made through `gh`. A call no
//! table names is judged with its destination unknown.
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
//! Here the harness owns the protocol: Claude Code and Codex read a refusal
//! out of a JSON document on stdout at exit 0. Exit 1 is an error in the hook
//! rather than a verdict on the call, so using it to signal a refusal would
//! let the call through with a complaint attached. The refusal travels in the
//! document, and it is ALSO printed to stderr, so that a person running
//! `uphold hook` by hand sees the report rather than a line of JSON.
//!
//! ## One command, two moments
//!
//! The same `uphold hook claude-code` entry is configured for `SessionStart`
//! and `Stop` as well, and `hook_event_name` says which arrived. Those two are
//! the end-of-turn gate in [`stop`]; every other event, and an event naming
//! none, is the pre-call judgment below, as it was before the gate existed.

mod stop;
mod table;

pub(crate) use table::{Answers, Table, Written};

use std::fmt::Write as _;
use std::io::Read;
use std::path::PathBuf;

use serde_json::Value;

use crate::error::{Exit, Fatal, Result};
use crate::guard;
use crate::invocation::{Invocation, Observed};
use crate::junit::{Place, Record, Run};
use crate::shim::{Walked, walk_strings};
use crate::text::{self, Verdict};

/// What one harness calls the three things every harness has.
struct Shape {
    /// Harness names sharing this wire protocol, as accepted on the command line.
    names: &'static [&'static str],
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

/// Claude Code and Codex share the same input pointers and refusal document.
/// A different protocol needs another shape; another name for this protocol
/// belongs in the same entry so the wire contracts cannot drift apart.
const SHAPES: &[Shape] = &[Shape {
    names: &["claude-code", "codex"],
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
        .flat_map(|shape| shape.names.iter().copied())
        .collect::<Vec<&str>>()
        .join("|")
}

/// Put the report inside the harness's refusal document.
///
/// Through `serde_json` rather than by formatting a string, because a report
/// carries newlines, quotes and whatever the offending text was, and a hand
/// written template is how a refusal about unusual characters becomes a
/// document the harness cannot parse.
fn refusal_document(shape: &Shape, report: &str) -> Result<String> {
    let mut document: Value = serde_json::from_str(shape.refusal).map_err(|error| {
        Fatal::new(format!(
            "{}: malformed refusal shape: {error}",
            shape.names.join("|")
        ))
    })?;
    let (parent, key) = shape.reason_at.rsplit_once('/').ok_or_else(|| {
        Fatal::new(format!(
            "{}: refusal shape names no place for the report",
            shape.names.join("|")
        ))
    })?;
    let target = document
        .pointer_mut(parent)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            Fatal::new(format!(
                "{}: refusal shape has no object at {parent:?}",
                shape.names.join("|")
            ))
        })?;
    target.insert(key.to_owned(), Value::String(report.to_owned()));
    serde_json::to_string(&document).map_err(|error| {
        Fatal::new(format!(
            "{}: refusal is not writable: {error}",
            shape.names.join("|")
        ))
    })
}

/// Take out what the call carries and the server will not send, so no rule
/// judges a subject that is never published.
///
/// One case: an exactly empty `commit_title`. The GitHub MCP server's
/// `merge_pull_request` (github/github-mcp-server v2.0.2,
/// pkg/github/pullrequests.go:1743 and :1761) reads it untrimmed and hands it to
/// go-github, whose merge request field is `CommitTitle string` tagged
/// `json:"commit_title,omitempty"` (github/go-github v92.0.0,
/// github/pulls.go:514), so `""` is left out of the request and the forge
/// writes the pull request's title, as if the argument were absent. That is
/// the shim's `gh pr merge --subject ""`, and it is taken out here for the
/// shim's reason: in the extraction, not in a rule, so every rule that selects
/// titles sees what the forge does. Whitespace is sent, and stays.
///
/// Not `title`: the same server's `update_pull_request` sends an empty one as
/// written (pkg/github/pullrequests.go:1039), so it is a subject that reaches the
/// forge. And not `walk_strings`, which also reads a `gh api --input` document,
/// where an empty `commit_title` is sent as written.
fn drop_unsent(collected: &mut Walked) {
    collected
        .headlines
        .retain(|(key, text)| !(key == "commit_title" && text.is_empty()));
}

/// Judge one pending tool call, read from stdin in the harness's own shape.
///
/// `found` is the policy where the call was made, and it is an `Option` here
/// where every other seam requires one: a git hook runs in the repository whose
/// policy applies by construction, and a tool call does not. What still runs
/// without one is the host-identity half, which carries its own fallback for
/// exactly this case; the guards do not, and their absence is reported rather
/// than counted as a pass.
///
/// `evidence` is the directory a `JUnit` document goes into, one per call,
/// where one was asked for. Written on every call that got as far as judging,
/// refused or not: a hook that wrote only on a refusal would make an absent
/// file mean "passed or never ran", which is the ambiguity the record exists
/// to remove. A call its `[[hook]]` table skips as a read has its text rules
/// written down as out of scope, and its tool-name rules asked.
pub(crate) fn run(
    harness: &str,
    found: Option<&(PathBuf, PathBuf)>,
    evidence: Option<PathBuf>,
) -> Result<Exit> {
    let shape = SHAPES
        .iter()
        .find(|shape| shape.names.contains(&harness))
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

    if let Some(name @ ("SessionStart" | "Stop")) =
        event.pointer("/hook_event_name").and_then(Value::as_str)
    {
        // The gate is a repository's own declaration, so with no policy there
        // is nothing to run -- said, not passed, as the guards' absence is.
        if found.is_none() {
            eprintln!(
                "uphold hook: no policy where this {name} arrived, so no [stop] gate ran. That \
                 is no gate, not a passing one."
            );
            return Ok(Exit::Clean);
        }
        if evidence.is_some() {
            eprintln!("uphold hook: --junit is not written for {name}; it records tool calls");
        }
        let (root, policy) = text::load_for(found)?;
        return if name == "Stop" {
            stop::stop(&event, &root, &policy)
        } else {
            stop::session_start(&event, &root, &policy)
        };
    }

    // The label names the call in reports and is its `tool` subject. A missing
    // name retains the harness fallback; supplied argument text is still read.
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
    // call carrying only numbers and flags still has a tool name to judge.
    // Nor is a subject that is a bare string
    // rather than an object -- that is text, and it is checked as text. The
    // question here is whether the subject was found, never what shape the
    // harness chose for it.
    let observation = event.pointer(shape.subject).map_or_else(
        || {
            Observed::Unread(format!(
                "the {harness} event carries nothing at {:?}, so what this call was about to \
                 send could not be read and \"allowed\" would mean \"unexamined\". That pointer \
                 is the shape this harness's events have; an event without it is a harness that \
                 changed rather than a call that published nothing",
                shape.subject
            ))
        },
        Observed::Present,
    );
    let subject = observation.read()?.copied();

    // Everything a piece of published text is judged by, from the one place
    // that knows what that is. The host-identity rules run wherever the call
    // was made from, policy or no policy: `text::load_for` carries an empty
    // policy for exactly that case, and it is the case a tool call is usually
    // in. A session starts in a workspace superproject, a scratch directory, or
    // a checkout that has no policy of its own, and a seam that stood down
    // there would be absent in precisely the places nobody thought to configure
    // it. The guards and the prose rules are declarations, so an empty policy
    // is an empty list of them rather than a fallback -- which is the same
    // sentence as "they did not run", said below.
    //
    // Loaded before the subject is looked at, not after. A policy that does not
    // load is exit 2 on every call, and one that loaded only when the call
    // carried text would pass every string-free call through a broken
    // configuration at exit 0 -- a gate whose failure is visible only on the
    // calls that happen to publish something.
    let (root, policy) = text::load_for(found)?;

    // The first table naming the call speaks for it. A read it names
    // publishes nothing, so it is judged as a call carrying no strings: a rule
    // about what the call IS -- its tool name -- still runs, as it did before
    // any table said the call was a read, and it runs wherever the call goes,
    // since a read goes nowhere. The rules about published text are written
    // down as set aside rather than asked.
    let named = policy.hooks.iter().find(|table| table.names(label));
    let read = named.is_some_and(|table| table.skips(label));
    let mut scoping = table::Scoping::new(named, &policy.shims, label, subject, &root);
    let destination = if read {
        None
    } else {
        scoping.destination().map(str::to_owned)
    };

    let mut collected = Walked::default();
    if !read && let Some(subject) = subject {
        walk_strings(subject, None, &mut collected);
    }
    drop_unsent(&mut collected);
    let has_text = !collected.prose.is_empty() || !collected.headlines.is_empty();
    let text = collected.prose.join("\n");
    let headlines: Vec<text::Headline> = collected
        .headlines
        .into_iter()
        .map(|(key, headline)| text::Headline {
            label: format!("{label} {key}"),
            text: headline,
        })
        .collect();

    let mut report = String::new();

    // Opened before the first rule is asked, so a directory that cannot be
    // written into stops the call while it has decided nothing.
    let mut record = Record::new(
        evidence.map(Place::Directory),
        Run::Hook(harness.to_owned()),
    );
    record.open()?;
    if read {
        text::set_aside(&policy, label, &mut record.ledger);
    }
    let invocation = Invocation::text(
        text::Seam::Hook,
        label,
        if has_text {
            Observed::Present(text.as_str())
        } else {
            Observed::Absent
        },
        &headlines,
    );
    let verdicts = match text::judged(
        &invocation,
        &root,
        &policy,
        destination.as_deref(),
        &mut |rule| if read { Ok(true) } else { scoping.holds(rule) },
        &mut record.ledger,
    ) {
        Ok(verdicts) => verdicts,
        Err(error) => return record.finish(Err(error)),
    };
    record.write(false)?;
    for verdict in verdicts {
        match verdict {
            // The message as well as the finding. At the shim and at `--text`
            // the message is what tells the author what to do instead; here the
            // reader is an agent, and an id alone gives it nothing to act on.
            Verdict::Rule(failure) => writeln!(
                report,
                "policy check failed: {}\n{}\n",
                failure.label,
                failure.report()
            ),
            Verdict::Guard(refusal) => writeln!(
                report,
                "guard refused: {}\n{}\n",
                guard::refused_by(&policy, &refusal),
                refusal.report.trim_end()
            ),
        }
        .ok();
    }

    // Which guards a repository runs is that repository's own answer, and an
    // enclosing superproject's is not borrowed. Where there is no policy the
    // guards and the prose rules have nothing to run, and saying so on stderr
    // is the difference between a check that passed and a check that did not
    // happen.
    if found.is_none() {
        eprintln!(
            "uphold hook: no policy where this call was made, so the guards did not run \
             and only the host-identity rules did. That is partial coverage, not a pass."
        );
    }

    if text::refusals(&record.ledger) == 0 {
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
        let mut found = Walked::default();
        walk_strings(&event, None, &mut found);
        found.prose.sort();
        assert_eq!(found.prose, vec!["b", "c"]);
        assert_eq!(found.headlines, vec![("title".to_owned(), "a".to_owned())]);
    }

    /// A title key is read at any depth, and a message key splits its value
    /// into the subject line and the body below it.
    #[test]
    fn a_title_key_marks_a_headline_at_any_depth() {
        let event: Value = serde_json::from_str(
            r#"{"merge":{"commit_title":"t","subject":["s"]},"squash_commit_message":"m\n\nbody"}"#,
        )
        .unwrap();
        let mut found = Walked::default();
        walk_strings(&event, None, &mut found);
        found.headlines.sort();
        assert_eq!(
            found.headlines,
            vec![
                ("commit_title".to_owned(), "t".to_owned()),
                ("squash_commit_message".to_owned(), "m".to_owned()),
                ("subject".to_owned(), "s".to_owned()),
            ]
        );
        assert_eq!(found.prose, vec!["\n\nbody"]);
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
