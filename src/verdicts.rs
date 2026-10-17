//! `UPHOLD_VERDICTS` -- what a guard run decided, for whoever ran it.
//!
//! uphold decides and does not record. Signing a pass, storing it beside the
//! commit and publishing it are a recorder's, and a recorder already knows
//! where its record goes; what it cannot know without parsing prose is which
//! rules ran and what each one answered. So the caller names a file, and each
//! rule the run evaluated appends one JSON line to it. Unset, nothing is
//! written and the run is the run it always was.
//!
//! A line carries the decision and never the subject: no message, no body, no
//! argv. A record of a refusal that quoted what was refused would hold exactly
//! the text the rule existed to keep out of somewhere.
//!
//! A file that cannot be written is exit 2. A caller who asked for verdicts and
//! received none must not read the absence as a run that found nothing.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use serde::Serialize;

use crate::error::{Fatal, Result};

/// The variable naming the file. A path, never a descriptor: a hook runner
/// owns the descriptors a hook inherits, and a path survives every one of them.
pub(crate) const VARIABLE: &str = "UPHOLD_VERDICTS";

/// Bumped when a field changes meaning or goes away, never when one is added.
/// The same contract `uphold check --json` keeps.
const SCHEMA_VERSION: u32 = 1;

/// The four answers a rule can give, and no fifth: they are the exit codes and
/// the bypass, named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Ran, and found nothing to refuse.
    Pass,
    /// Ran, and refused.
    Refuse,
    /// Did not run, because `UPHOLD_ALLOW` named it for this invocation.
    Bypass,
    /// Could not look. The run stops here with exit 2, so a line with this
    /// outcome is the last one the run writes.
    Unknown,
}

impl Outcome {
    const fn name(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Refuse => "refuse",
            Self::Bypass => "bypass",
            Self::Unknown => "unknown",
        }
    }
}

/// One line, in the order a reader scans it.
#[derive(Serialize)]
struct Line<'a> {
    schema_version: u32,
    seam: &'a str,
    stage: &'a str,
    rule: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    set: Option<&'a str>,
    outcome: &'a str,
    /// What switched the rule off, present on a bypass and only there.
    #[serde(skip_serializing_if = "Option::is_none")]
    by: Option<&'a str>,
}

/// Where this run's verdicts go, if anywhere.
pub(crate) struct Sink {
    open: Option<(PathBuf, File)>,
}

impl Sink {
    /// The file the caller named, opened for appending before any rule runs,
    /// so a path that cannot be written stops the run before it decides
    /// anything rather than after it decided everything.
    pub(crate) fn from_env() -> Result<Self> {
        let Some(path) = std::env::var_os(VARIABLE) else {
            return Ok(Self { open: None });
        };
        // Refused rather than read as unset. A caller who exported the
        // variable and blanked it asked for verdicts somewhere; running on as
        // if they had not is the silent absence this file exists to rule out.
        if path.is_empty() {
            return Err(Fatal::new(format!(
                "{VARIABLE} is set and names no file. Unset it to write no verdicts"
            )));
        }
        let path = PathBuf::from(path);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| Fatal::at(&path, format!("{VARIABLE}: {error}")))?;
        Ok(Self {
            open: Some((path, file)),
        })
    }

    /// Append one rule's answer. One `write_all` per line on a file opened for
    /// appending, so two runs sharing a file interleave whole lines.
    pub(crate) fn record(
        &mut self,
        stage: &str,
        rule: &str,
        set: Option<&str>,
        outcome: Outcome,
    ) -> Result<()> {
        let Some((path, file)) = &mut self.open else {
            return Ok(());
        };
        let line = Line {
            schema_version: SCHEMA_VERSION,
            seam: "guard",
            stage,
            rule,
            set,
            outcome: outcome.name(),
            by: (outcome == Outcome::Bypass).then_some("UPHOLD_ALLOW"),
        };
        let mut bytes = serde_json::to_vec(&line)
            .map_err(|error| Fatal::at(path, format!("{VARIABLE}: {error}")))?;
        bytes.push(b'\n');
        file.write_all(&bytes)
            .map_err(|error| Fatal::at(path, format!("{VARIABLE}: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written(outcome: Outcome, set: Option<&str>) -> serde_json::Value {
        let directory = crate::fixture::scratch("verdicts");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("run.jsonl");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let mut sink = Sink {
            open: Some((path.clone(), file)),
        };
        sink.record("pre-push", "a-rule", set, outcome).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.ends_with('\n') && text.lines().count() == 1, "{text}");
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn a_bypass_names_what_switched_the_rule_off_and_a_pass_does_not() {
        let bypass = written(Outcome::Bypass, Some("a-set"));
        assert_eq!(bypass["outcome"], "bypass");
        assert_eq!(bypass["by"], "UPHOLD_ALLOW");
        assert_eq!(bypass["set"], "a-set");
        let pass = written(Outcome::Pass, None);
        assert_eq!(pass["outcome"], "pass");
        assert!(pass.get("by").is_none(), "{pass}");
        assert!(pass.get("set").is_none(), "{pass}");
        assert_eq!(pass["schema_version"], 1);
        assert_eq!(pass["seam"], "guard");
    }

    #[test]
    fn a_sink_nobody_asked_for_writes_nothing() {
        let mut sink = Sink { open: None };
        sink.record("pre-push", "a-rule", None, Outcome::Refuse)
            .unwrap();
    }
}
