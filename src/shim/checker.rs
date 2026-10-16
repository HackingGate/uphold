//! Evaluate one declared checker against one normalized subject.
//! Selection, scope and check order belong to the shim orchestrator.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use super::Subject;
use crate::config::Rule;
use crate::error::{Fatal, Result};

/// One pattern rule's verdict over one subject.
///
/// The same engine `scan` searches files with, asked about a string that never
/// becomes one -- same regex grammar, same meaning. `require_regexp` refuses a
/// subject the pattern is absent from; `regexp` refuses one it is present in.
/// Both name the kind and the pattern, because the reader's next step is to
/// fix the text, and "refused" without which-test-failed is a round trip.
///
/// `prose_regexp` is the third, and the subject reaches it as whole-text prose:
/// a pull-request body is a document, so a fenced example in one is skipped
/// here exactly as it is in a committed document, and a sentence wrapped by
/// whatever composed the body is unwrapped before the pattern sees it. A rule
/// that refused a shape in a document and allowed it in the body announcing
/// that document would be one rule with two answers.
pub(super) fn pattern_refusal(rule: &Rule, subject: &Subject) -> Result<Option<String>> {
    Ok(pattern_finding(rule, subject)?.map(|finding| format!("{finding}\n{}", rule.message())))
}

/// What a pattern rule found in one subject, as the line a report names it by,
/// without the rule's message. Split from [`pattern_refusal`] for the hook,
/// whose report carries the message as its own paragraph, the way `--text`
/// prints it.
pub(crate) fn pattern_finding(rule: &Rule, subject: &Subject) -> Result<Option<String>> {
    let multiline = rule.files().multiline;
    if let Some(pattern) = rule.prose_regexp() {
        let matcher = crate::prose::compile(pattern, &rule.id)?;
        let Some(span) = crate::prose::of_text(&subject.value)
            .into_iter()
            .find(|span| matcher.is_match(&span.text))
        else {
            return Ok(None);
        };
        return Ok(Some(format!(
            "{}: the {} subject matches {pattern:?}: {}",
            rule.id, subject.kind, span.text
        )));
    }
    if let Some(pattern) = rule.require_regexp() {
        let hits = crate::engine::search_text(
            &subject.value,
            &crate::engine::Query::regex(pattern, multiline),
            &rule.id,
        )?;
        if hits.is_empty() {
            return Ok(Some(format!(
                "{}: the {} subject does not satisfy {pattern:?}",
                rule.id, subject.kind
            )));
        }
        return Ok(None);
    }
    let Some(pattern) = rule.regexp() else {
        return Ok(None);
    };
    let hits = crate::engine::search_text(
        &subject.value,
        &crate::engine::Query::regex(pattern, multiline),
        &rule.id,
    )?;
    let Some(hit) = hits.first() else {
        return Ok(None);
    };
    Ok(Some(format!(
        "{}: the {} subject matches {pattern:?}: {}",
        rule.id,
        subject.kind,
        hit.text.trim_end()
    )))
}

/// Run one checker over one subject.
///
/// The contract cmd-shims documented, unchanged and now the only one: the
/// subject on stdin, its kind in the environment, 0 to pass, 1 to refuse, 2 to
/// say it could not look. A checker written in anything satisfies it.
///
/// All three pipes are worked at once, and that is not tidiness. A pipe holds
/// about 64 KiB: writing a longer subject blocks until the checker reads it,
/// and a checker that writes more than a bufferful blocks until this process
/// reads THAT. Writing the whole subject first and reading afterwards means
/// each side is waiting for the other and neither ever moves -- on exactly the
/// long bodies a guard most needs to see, and with no output at all to say
/// what happened.
pub(super) fn consult(root: &Path, rule: &Rule, subject: &Subject) -> Result<Option<String>> {
    // `exec`, not `values_from`. They were one field called `run` in v2, and a
    // checker whose command reads empty passes everything it is asked about --
    // which is also why an ABSENT command is an error here rather than a
    // default: a rule mis-dispatched to this function once ran `sh -c ""`,
    // approved everything, and the pass was indistinguishable from a checker
    // that looked.
    let Some(run) = rule.exec().filter(|command| !command.trim().is_empty()) else {
        return Err(Fatal::new(format!(
            "{}: consulted as an `exec` checker while declaring no `exec` command, so \
             nothing could have been asked -- a dispatch hole, not a pass",
            rule.id
        )));
    };
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(run)
        .current_dir(root)
        .env("UPHOLD_KIND", subject.kind)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| Fatal::new(format!("{}: {error}", rule.id)))?;

    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let body = subject.value.as_bytes();

    let (written, report) =
        std::thread::scope(|scope| -> Result<(std::io::Result<()>, Vec<u8>)> {
            let writer = scope.spawn(move || -> std::io::Result<()> {
                let Some(pipe) = stdin.as_mut() else {
                    return Ok(());
                };
                pipe.write_all(body)?;
                pipe.flush()
                // Dropped on the way out of this closure, which is the end of
                // input the checker is waiting for.
            });
            // Drained rather than read: the contract puts a checker's report on
            // stderr, but a checker that writes to stdout still fills a pipe,
            // and a full pipe nobody empties is the same deadlock from the
            // other side.
            let drain = scope.spawn(move || {
                if let Some(pipe) = stdout.as_mut() {
                    drop(pipe.read_to_end(&mut Vec::new()));
                }
            });
            let mut report = Vec::new();
            if let Some(pipe) = stderr.as_mut() {
                drop(pipe.read_to_end(&mut report));
            }
            let written = writer.join().map_err(|_| {
                Fatal::new(format!(
                    "{}: the thread feeding it the subject died",
                    rule.id
                ))
            })?;
            drain.join().map_err(|_| {
                Fatal::new(format!("{}: the thread draining its output died", rule.id))
            })?;
            Ok((written, report))
        })?;

    let status = child
        .wait()
        .map_err(|error| Fatal::new(format!("{}: {error}", rule.id)))?;
    let report = String::from_utf8_lossy(&report);
    let report = report.trim();
    match (status.code(), written) {
        // A refusal stands even where the write did not finish. A checker that
        // stopped reading and then said no had already seen enough to say it,
        // and turning that into an infrastructure error would teach people to
        // re-run until the refusal went away.
        (Some(1), _) => Ok(Some(format!(
            "{} refused a {} subject: {report}",
            rule.id, subject.kind
        ))),
        // The write result is an answer, not something to drop with `.ok()`: a
        // subject that never arrived is the one case where a 0 means nothing at
        // all, because the checker approved whatever part of it got through and
        // that is not what this invocation is about to publish.
        (_, Err(error)) => Err(Fatal::new(format!(
            "{} did not take the whole {} subject ({error}), so its answer is not about what \
             would be published: {report}",
            rule.id, subject.kind
        ))),
        (Some(0), Ok(())) => Ok(None),
        // 2 is could-not-look, and it is not a pass. A checker that could not
        // read what it was handed has established nothing.
        (other, Ok(())) => Err(Fatal::new(format!(
            "{} exited {} on a {} subject: {report}",
            rule.id,
            other.unwrap_or(-1),
            subject.kind
        ))),
    }
}
