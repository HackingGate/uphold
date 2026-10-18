//! `UPHOLD_JUNIT` -- what a guard run decided, as one `JUnit` XML document.
//!
//! uphold decides and does not record. Signing a pass, storing it beside the
//! commit and publishing it belong to whatever runs the gate, and that caller
//! already knows where its record goes; what it cannot know without parsing
//! prose is which rules ran and what each one answered. So the caller names a
//! file, and the run writes one document to it: one `<testsuite>` for the
//! stage, one `<testcase>` per rule the stage evaluated. Unset, nothing is
//! written and the run is the run it always was.
//!
//! `JUnit` because the gate tier already speaks it: its evidence directory holds
//! `JUnit` files, its publisher turns them into one report, and its recorder links
//! that report. A format of uphold's own would be one more thing for each of
//! them to read. The four testcase states are the four answers a guard gives:
//!
//! | guard   | testcase        |
//! | ------- | --------------- |
//! | pass    | no child        |
//! | refuse  | `<failure>`     |
//! | unknown | `<error>`       |
//! | bypass  | `<skipped>`     |
//!
//! "Evidence" in this module means what it means in the gate's directory, a
//! record of a run. It is not `crate::evidence`, a provider's facts handed to a
//! policy; the two do not meet.
//!
//! A testcase carries the decision and never the subject: no message, no body,
//! no path, no argv. A record of a refusal that quoted what was refused would
//! hold exactly the text the rule existed to keep out of somewhere, and the
//! report a reader acts on is still the one on stderr. No hostname and no user
//! name either; the timestamp is the only run metadata kept.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use quick_junit::{NonSuccessKind, Property, Report, TestCase, TestCaseStatus, TestSuite};

use crate::error::{Fatal, Result};
use crate::guard::Allowed;

/// The variable naming the file. A path, never a descriptor: a hook runner
/// owns the descriptors a hook inherits, and a path survives every one of them.
pub(crate) const VARIABLE: &str = "UPHOLD_JUNIT";

/// The file the caller asked for, if they asked.
///
/// Read and judged before anything else the run does, so a value that names no
/// usable place is exit 2 before a policy is loaded or a rule is asked.
pub(crate) fn requested() -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(VARIABLE) else {
        return Ok(None);
    };
    // Refused rather than read as unset, the opposite reading from
    // `UPHOLD_ALLOW=` on purpose. There, blank-means-set switched every guard
    // off and said nothing, so blank is read as unset. Here, blank-means-unset
    // would be the silent one: a caller who exported the variable and blanked
    // it asked for evidence somewhere, and a run that wrote none and exited 0
    // reads to them as a run whose record went missing later. Refusing one run
    // loudly is the cheaper of the two mistakes.
    if value.is_empty() {
        return Err(Fatal::new(format!(
            "{VARIABLE}= is set and names no file. Unset it to write no evidence, \
             or name an absolute path"
        )));
    }
    let path = PathBuf::from(value);
    // git runs a hook from the top of the working tree, not from where the
    // caller stood, so a relative path would be written somewhere the caller
    // did not look -- and the place they did look would hold nothing, which is
    // the absence this file exists to rule out.
    if !path.is_absolute() {
        return Err(Fatal::new(format!(
            "{VARIABLE}={} is a relative path. A hook runs from the top of the \
             working tree, so name an absolute one",
            path.display()
        )));
    }
    Ok(Some(path))
}

/// Where one run's document goes, opened before any rule is asked.
pub(crate) struct Sink<'a> {
    out: Box<dyn Write + 'a>,
    /// Named in an error, so a failed write says which file.
    place: PathBuf,
}

impl std::fmt::Debug for Sink<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Sink")
            .field("place", &self.place)
            .finish_non_exhaustive()
    }
}

impl Sink<'static> {
    /// Create or replace the file, never append to it.
    ///
    /// A `JUnit` document is one tree, and a second run appended to the first
    /// is not a document at all. That is why the variable names a file per
    /// stage and not one per act. Opened here, before the run, so a path that
    /// cannot be written stops it while it has decided nothing rather than after
    /// it decided everything.
    pub(crate) fn create(path: &Path) -> Result<Self> {
        let file =
            File::create(path).map_err(|error| Fatal::at(path, format!("{VARIABLE}: {error}")))?;
        Ok(Self::new(file, path))
    }
}

impl<'a> Sink<'a> {
    /// Any writer, named by `place` in an error. The file is one; a test's
    /// buffer is another.
    pub(crate) fn new(out: impl Write + 'a, place: &Path) -> Self {
        Self {
            out: Box::new(out),
            place: place.to_path_buf(),
        }
    }
}

/// One rule's answer, and no fifth: the exit codes and the bypass, named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Ran, and found nothing to refuse.
    Pass,
    /// Ran, and refused.
    Refuse,
    /// Could not look. The run stops here with exit 2, so this is the last
    /// testcase the document holds; a rule the run never reached has none,
    /// because absence is not a claim.
    Unknown,
    /// Did not run, because `UPHOLD_ALLOW` named it or said `all`.
    Bypass(Allowed),
}

/// What a rule is, as far as its testcase says.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Case<'r> {
    /// The rule's id: the testcase's `name`.
    pub id: &'r str,
    /// The dispatch name, since a repository may call a rule anything.
    pub builtin: Option<&'r str>,
    /// The bundled set the rule came from, or `None` for a rule written here.
    pub set: Option<&'r str>,
}

/// The suite under construction for one stage.
#[derive(Debug)]
pub(crate) struct Suite<'a> {
    sink: Sink<'a>,
    stage: String,
    built: TestSuite,
}

impl<'a> Suite<'a> {
    pub(crate) fn new(sink: Sink<'a>, stage: &str) -> Self {
        let mut suite = TestSuite::new(format!("uphold guard {stage}"));
        // Allure's JUnit reader takes the `package` attribute as its package
        // label, so the report groups these suites under the tool that wrote
        // them. It reads no `<properties>`, which is why the grouping cannot
        // ride on one.
        suite.extra.insert("package".into(), "uphold".into());
        suite.set_timestamp(chrono::DateTime::<chrono::Utc>::from(
            std::time::SystemTime::now(),
        ));
        Self {
            sink,
            stage: stage.to_owned(),
            built: suite,
        }
    }

    /// Add one rule's testcase.
    pub(crate) fn record(&mut self, case: Case<'_>, outcome: Outcome) {
        let status = match outcome {
            Outcome::Pass => TestCaseStatus::success(),
            Outcome::Refuse => non_success(NonSuccessKind::Failure, case.id, "refused"),
            Outcome::Unknown => non_success(NonSuccessKind::Error, case.id, "could not look"),
            Outcome::Bypass(_) => {
                let mut skipped = TestCaseStatus::skipped();
                skipped.set_message("bypassed by UPHOLD_ALLOW");
                skipped
            }
        };
        let mut testcase = TestCase::new(case.id, status);
        // `local` rather than no classname: Allure files a testcase by its
        // class, and a rule written in this repository's own policy is as much
        // a class as one a set brought in.
        testcase.set_classname(case.set.unwrap_or("local"));
        if let Some(builtin) = case.builtin {
            testcase.add_property(Property::new("builtin", builtin));
        }
        if let Some(set) = case.set {
            testcase.add_property(Property::new("set", set));
        }
        testcase.add_property(Property::new("stage", self.stage.as_str()));
        // A bundled set's contents are a property of the binary, so the
        // version is what says which rules `set` meant on this run.
        testcase.add_property(Property::new("uphold", env!("CARGO_PKG_VERSION")));
        if let Outcome::Bypass(allowed) = outcome {
            testcase.add_property(Property::new(
                "allowed",
                match allowed {
                    Allowed::Named => "id",
                    Allowed::All => "all",
                },
            ));
        }
        self.built.add_test_case(testcase);
    }

    /// Serialize the whole document. Called once, on every path out of the run
    /// that got as far as opening the sink.
    pub(crate) fn write(self) -> Result<()> {
        let Self {
            mut sink, built, ..
        } = self;
        let mut report = Report::new("uphold guard");
        report.add_test_suite(built);
        let failed =
            |error: &dyn std::fmt::Display| Fatal::at(&sink.place, format!("{VARIABLE}: {error}"));
        report
            .serialize(&mut sink.out)
            .map_err(|error| failed(&error))?;
        sink.out.flush().map_err(|error| failed(&error))
    }
}

/// A failure or an error whose message is the rule and the word, and nothing
/// the rule read.
fn non_success(kind: NonSuccessKind, id: &str, word: &str) -> TestCaseStatus {
    let mut status = TestCaseStatus::non_success(kind);
    status.set_message(format!("{id} {word}"));
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written(cases: &[(Case<'_>, Outcome)]) -> Report {
        let mut buffer = Vec::new();
        let mut suite = Suite::new(Sink::new(&mut buffer, Path::new("memory")), "pre-push");
        for (case, outcome) in cases {
            suite.record(*case, *outcome);
        }
        suite.write().unwrap();
        Report::deserialize_from_str(std::str::from_utf8(&buffer).unwrap()).unwrap()
    }

    fn property<'c>(case: &'c TestCase, name: &str) -> Option<&'c str> {
        case.properties
            .iter()
            .find(|property| property.name.as_str() == name)
            .map(|property| property.value.as_str())
    }

    const BUNDLED: Case<'static> = Case {
        id: "a-rule",
        builtin: Some("a-builtin"),
        set: Some("a-set"),
    };
    const LOCAL: Case<'static> = Case {
        id: "b-rule",
        builtin: Some("b-builtin"),
        set: None,
    };

    #[test]
    fn each_answer_is_its_own_testcase_state() {
        let report = written(&[
            (BUNDLED, Outcome::Pass),
            (LOCAL, Outcome::Refuse),
            (BUNDLED, Outcome::Bypass(Allowed::All)),
            (LOCAL, Outcome::Unknown),
        ]);
        assert_eq!(report.test_suites.len(), 1, "{report:?}");
        let suite = &report.test_suites[0];
        assert_eq!(suite.name.as_str(), "uphold guard pre-push");
        assert_eq!(
            suite
                .extra
                .get("package")
                .map(quick_junit::XmlString::as_str),
            Some("uphold")
        );
        assert!(suite.timestamp.is_some());
        assert_eq!(
            (suite.tests, suite.failures, suite.errors, suite.skipped),
            (4, 1, 1, 1)
        );
        assert_eq!(suite.test_cases.len(), 4, "{suite:?}");
        let (pass, refuse, bypass, unknown) = (
            &suite.test_cases[0],
            &suite.test_cases[1],
            &suite.test_cases[2],
            &suite.test_cases[3],
        );
        assert!(matches!(pass.status, TestCaseStatus::Success { .. }));
        assert!(matches!(
            &refuse.status,
            TestCaseStatus::NonSuccess { kind: NonSuccessKind::Failure, message: Some(message), .. }
                if message.as_str() == "b-rule refused"
        ));
        assert!(matches!(
            &bypass.status,
            TestCaseStatus::Skipped { message: Some(message), .. }
                if message.as_str() == "bypassed by UPHOLD_ALLOW"
        ));
        assert!(matches!(
            &unknown.status,
            TestCaseStatus::NonSuccess { kind: NonSuccessKind::Error, message: Some(message), .. }
                if message.as_str() == "b-rule could not look"
        ));
        assert_eq!(property(bypass, "allowed"), Some("all"));
        assert_eq!(property(pass, "allowed"), None);
        assert_eq!(
            pass.classname.as_ref().map(quick_junit::XmlString::as_str),
            Some("a-set")
        );
        assert_eq!(property(pass, "set"), Some("a-set"));
        assert_eq!(
            refuse
                .classname
                .as_ref()
                .map(quick_junit::XmlString::as_str),
            Some("local")
        );
        assert_eq!(property(refuse, "set"), None);
        for case in &suite.test_cases {
            assert_eq!(property(case, "stage"), Some("pre-push"));
            assert_eq!(property(case, "uphold"), Some(env!("CARGO_PKG_VERSION")));
            assert!(property(case, "builtin").is_some());
        }
    }

    #[test]
    fn a_stage_with_nothing_to_ask_is_still_a_document() {
        let report = written(&[]);
        assert_eq!(report.test_suites.len(), 1, "{report:?}");
        let suite = &report.test_suites[0];
        assert_eq!(suite.tests, 0);
    }
}
