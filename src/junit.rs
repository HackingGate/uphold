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
//! A stage is one of four places a rule is evaluated. The shim in front of
//! `gh` and `git push`, `uphold hook <harness>` and `uphold guard --text` judge
//! text that never becomes a file, and each writes the same document under its
//! own suite name. The shim runs many times in one act and nobody can type a
//! flag into the argv it stands in front of, so the variable may name a
//! DIRECTORY instead: one file per invocation inside it, named for the suite
//! and a fresh id, which is the results-directory convention every `JUnit`
//! publisher already reads. The shim and the hook take only that form, since
//! two `gh` calls replacing one file would lose the first.
//!
//! `JUnit` because the gate tier already speaks it: its evidence directory holds
//! `JUnit` files, its publisher turns them into one report, and its recorder links
//! that report. A format of uphold's own would be one more thing for each of
//! them to read. The four testcase states are the four answers a guard gives:
//!
//! | guard        | testcase                          |
//! | ------------ | --------------------------------- |
//! | pass         | no child                          |
//! | refuse       | `<failure>`                       |
//! | unknown      | `<error>`                         |
//! | bypass       | `<skipped>`, property `allowed`   |
//! | out of scope | `<skipped>`, property `scope`     |
//!
//! The fifth is the seams' alone: a rule whose own scope did not hold at this
//! destination neither ran nor was bypassed. It is a skipped testcase rather
//! than an absence because it is a decision made about THIS invocation, and a
//! reader of a bypass log asking whether the private-name check ran on that
//! body should get the answer from the file and not from a second source.
//!
//! "Evidence" in this module means what it means in the gate's directory, a
//! record of a run. It is not `crate::evidence`, a provider's facts handed to a
//! policy; the two do not meet.
//!
//! A testcase carries the decision and never the subject: no message, no body,
//! no path, no argv. A record of a refusal that quoted what was refused would
//! hold exactly the text the rule existed to keep out of somewhere, and the
//! report a reader acts on is still the one on stderr. What a seam records of
//! its subject is the KIND -- `text`, `title`, a tool's name -- never what was
//! in it. Nor where it was going: the repository a shim invocation publishes
//! to is what `prevent-unowned-target` protects, so no owner, repository, URL
//! or branch. No hostname and no user name either; the timestamp is the only
//! run metadata kept.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use quick_junit::{NonSuccessKind, Property, Report, TestCase, TestCaseStatus, TestSuite};

use crate::error::{Exit, Fatal, Result};
use crate::guard::Allowed;
use crate::text::{Answered, Judgment};

/// The variable naming the file. A path, never a descriptor: a hook runner
/// owns the descriptors a hook inherits, and a path survives every one of them.
pub(crate) const VARIABLE: &str = "UPHOLD_JUNIT";

/// The flag naming the file: the conventional spelling, as `--junitxml` is
/// pytest's, for a caller who owns the command line.
pub(crate) const FLAG: &str = "--junit";

/// Where the caller asked for the document: one file, or a directory to put
/// one file per invocation in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Place {
    /// Created or replaced, as `guard --stage` always has.
    File(PathBuf),
    /// An existing directory, which gets a new file on every invocation.
    Directory(PathBuf),
}

/// The place the caller asked for, if they asked.
///
/// A directory that already exists is the directory form, and anything else
/// is a file to create or replace. Read off the filesystem rather than off a
/// trailing slash, because the caller who exported the variable once for a
/// whole act did not necessarily spell it with one.
///
/// Two spellings of one request. `--junit FILE` is the one a caller types who
/// owns the command line. The variable exists for the caller who does not: a
/// hook's argv is the hook definition's, pinned by the repository, and the
/// only channel that reaches from `git push` through the runner to the guard
/// is the environment. The flag wins when both are given, as a flag usually
/// does over the environment it was typed into.
///
/// Read and judged before anything else the run does, so a value that names no
/// usable place is exit 2 before a policy is loaded or a rule is asked.
pub(crate) fn requested(flag: Option<&OsStr>) -> Result<Option<Place>> {
    Ok(named(flag)?.map(|path| {
        if path.is_dir() {
            Place::Directory(path)
        } else {
            Place::File(path)
        }
    }))
}

/// [`requested`], for a seam that runs many times in one act and so takes
/// only the directory form: a file value is exit 2 naming it, before anything
/// else the run does.
pub(crate) fn directory_requested(flag: Option<&OsStr>, seam: &str) -> Result<Option<PathBuf>> {
    match requested(flag)? {
        None => Ok(None),
        Some(Place::Directory(path)) => Ok(Some(path)),
        Some(Place::File(path)) => Err(Fatal::new(format!(
            "{}={} names no existing directory. `{seam}` runs many times in one act, and \
             each run replacing one file would leave only the last; name an existing \
             directory and each run writes its own file in it",
            if flag.is_some() { FLAG } else { VARIABLE },
            path.display()
        ))),
    }
}

/// The path the caller named, before it is told file from directory.
fn named(flag: Option<&OsStr>) -> Result<Option<PathBuf>> {
    if let Some(given) = flag {
        if given.is_empty() {
            return Err(Fatal::new(format!("{FLAG} names no file")));
        }
        let path = PathBuf::from(given);
        // Typed where the caller stands, so a relative path means what it
        // means to any other command: this directory. The hook case below is
        // the one where "this directory" is not the caller's.
        return Ok(Some(if path.is_absolute() {
            path
        } else {
            std::env::current_dir()?.join(path)
        }));
    }
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

    /// Open the document one run writes at `place`: the file itself, or a new
    /// file in the directory, named for the suite. Created new and never
    /// opened over an existing one, so a name that somehow repeated is an
    /// error and not a lost record.
    pub(crate) fn open(place: &Place, run: &Run) -> Result<Self> {
        match place {
            Place::File(path) => Self::create(path),
            Place::Directory(directory) => {
                let path = directory.join(format!("{}-{}.xml", run.slug(), fresh_id()));
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .map_err(|error| Fatal::at(&path, format!("{VARIABLE}: {error}")))?;
                Ok(Self::new(file, &path))
            }
        }
    }
}

/// A name no other invocation on this machine is writing.
///
/// The clock to the millisecond and the microsecond under it, the process id
/// and a counter for a process that writes twice -- which is unique on one
/// machine by construction, where a random id is unique by probability and
/// needs a random source this crate does not otherwise carry. Laid out as a
/// version 8 UUID so the name has the shape a reader expects, and so names
/// sort by when they were written.
fn fresh_id() -> uuid::Uuid {
    static WRITTEN: AtomicU32 = AtomicU32::new(0);
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let millis = u64::try_from(since.as_millis()).unwrap_or(u64::MAX);
    let micros = since.subsec_micros() % 1000;
    let mut bytes = [0_u8; 16];
    bytes[..6].copy_from_slice(&millis.to_be_bytes()[2..]);
    // Twelve bits under the version nibble, and a thousand needs ten.
    bytes[6..8].copy_from_slice(&u16::try_from(micros).unwrap_or(0).to_be_bytes());
    // Thirty bits under the variant's two, and a process id needs fewer.
    bytes[8..12].copy_from_slice(&std::process::id().to_be_bytes());
    bytes[12..].copy_from_slice(&WRITTEN.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    uuid::Uuid::new_v8(bytes)
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

/// One rule's answer, and no sixth: the exit codes, the bypass and the scope,
/// named.
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
    /// Did not run, because its own scope did not hold at this destination.
    /// Only a seam with a destination answers this; a stage never does.
    OutOfScope,
}

impl Answered for Outcome {
    fn outcome(&self) -> Outcome {
        *self
    }
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
    /// The kinds of subject the rule was asked about at a seam -- `text`,
    /// `title`, a tool's name -- and never what any of them said.
    pub subjects: &'r [String],
}

/// What wrote a suite, which is its name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Run {
    /// `uphold guard --stage <stage>`.
    Stage(String),
    /// The shim, standing in front of the named command.
    Shim(String),
    /// `uphold hook <harness>`.
    Hook(String),
    /// `uphold guard --text`.
    Text,
}

impl Run {
    /// The suite's name.
    fn name(&self) -> String {
        match self {
            Self::Stage(stage) => format!("uphold guard {stage}"),
            Self::Shim(command) => format!("uphold shim {command}"),
            Self::Hook(harness) => format!("uphold hook {harness}"),
            Self::Text => String::from("uphold guard --text"),
        }
    }

    /// The document's name, which is the command that wrote it.
    const fn report(&self) -> &'static str {
        match self {
            Self::Stage(_) | Self::Text => "uphold guard",
            Self::Shim(_) => "uphold shim",
            Self::Hook(_) => "uphold hook",
        }
    }

    /// The property every testcase carries to say where it was decided: the
    /// stage a hook ran at, or which seam judged the text.
    const fn property(&self) -> (&'static str, &str) {
        match self {
            Self::Stage(stage) => ("stage", stage.as_str()),
            Self::Shim(_) => ("seam", crate::text::Seam::Command.name()),
            Self::Hook(_) => ("seam", crate::text::Seam::Hook.name()),
            Self::Text => ("seam", crate::text::Seam::Guard.name()),
        }
    }

    /// The suite's name as a file name: what is not a letter or a digit
    /// becomes one dash, so `uphold guard --text` is `uphold-guard-text`.
    fn slug(&self) -> String {
        let mut slug = String::new();
        for character in self.name().chars() {
            if character.is_ascii_alphanumeric() {
                slug.push(character.to_ascii_lowercase());
            } else if !slug.is_empty() && !slug.ends_with('-') {
                slug.push('-');
            }
        }
        slug.trim_end_matches('-').to_owned()
    }
}

/// The suite under construction for one run.
#[derive(Debug)]
pub(crate) struct Suite<'a> {
    sink: Sink<'a>,
    run: Run,
    built: TestSuite,
}

impl<'a> Suite<'a> {
    pub(crate) fn new(sink: Sink<'a>, run: Run) -> Self {
        let mut suite = TestSuite::new(run.name());
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
            run,
            built: suite,
        }
    }

    /// Say on the suite that `UPHOLD_ALLOW=all` ran the command unchecked
    /// before any rule was read. Allure reads no suite property; the machine
    /// reader does, and "ran unchecked" is then a document and not an absence.
    pub(crate) fn allowed_all(&mut self) {
        self.built.add_property(Property::new("allowed", "all"));
    }

    /// Add one rule's testcase.
    pub(crate) fn record(&mut self, case: Case<'_>, outcome: Outcome) {
        let status = match outcome {
            Outcome::Pass => TestCaseStatus::success(),
            Outcome::Refuse => non_success(NonSuccessKind::Failure, case.id, "refused"),
            Outcome::Unknown => non_success(NonSuccessKind::Error, case.id, "could not look"),
            Outcome::Bypass(_) => skipped("bypassed by UPHOLD_ALLOW"),
            Outcome::OutOfScope => skipped("out of scope at this destination"),
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
        for subject in case.subjects {
            testcase.add_property(Property::new("subject", subject.as_str()));
        }
        let (where_, decided) = self.run.property();
        testcase.add_property(Property::new(where_, decided));
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
        if outcome == Outcome::OutOfScope {
            testcase.add_property(Property::new("scope", "destination"));
        }
        self.built.add_test_case(testcase);
    }

    /// A testcase for a run that could not look at something no one rule
    /// owns. Named for the tool rather than a rule, because no rule refused
    /// and no rule was skipped.
    fn could_not_look(&mut self) {
        let mut testcase = TestCase::new(
            "uphold",
            non_success(NonSuccessKind::Error, "uphold", "could not look"),
        );
        testcase.set_classname("uphold");
        let (where_, decided) = self.run.property();
        testcase.add_property(Property::new(where_, decided));
        testcase.add_property(Property::new("uphold", env!("CARGO_PKG_VERSION")));
        self.built.add_test_case(testcase);
    }

    /// Serialize the whole document. Called once, on every path out of the run
    /// that got as far as opening the sink.
    pub(crate) fn write(self) -> Result<()> {
        let Self {
            mut sink,
            run,
            built,
        } = self;
        let mut report = Report::new(run.report());
        report.add_test_suite(built);
        let failed =
            |error: &dyn std::fmt::Display| Fatal::at(&sink.place, format!("{VARIABLE}: {error}"));
        report
            .serialize(&mut sink.out)
            .map_err(|error| failed(&error))?;
        sink.out.flush().map_err(|error| failed(&error))
    }
}

/// What one seam invocation decided, held until it is written.
///
/// A stage records into its suite as each rule answers. A seam keeps the
/// answers as a list instead, because that list is also what its report and
/// its exit are computed from -- the report a reader acts on and the file a
/// publisher renders are two readings of one list, so they cannot disagree --
/// and the suite is built from it when the run is done.
///
/// Written once, on every way out: before the shim hands the process to the
/// real command, since nothing runs after that, and otherwise when the seam
/// returns.
#[derive(Debug)]
pub(crate) struct Record {
    place: Option<Place>,
    run: Run,
    sink: Option<Sink<'static>>,
    allowed_all: bool,
    written: bool,
    /// Every rule's answer, in the order asked. A rule asked about several
    /// subjects appears once per subject here and once in the file.
    pub ledger: Vec<Judgment>,
}

impl Record {
    /// A record of `run`, written to `place` where one was asked for.
    pub(crate) const fn new(place: Option<Place>, run: Run) -> Self {
        Self {
            place,
            run,
            sink: None,
            allowed_all: false,
            written: false,
            ledger: Vec::new(),
        }
    }

    /// A record nobody asked for: it keeps the list a seam reports from, and
    /// writes nothing.
    pub(crate) const fn unrequested() -> Self {
        Self::new(None, Run::Text)
    }

    /// Open the file now rather than when it is written, so a place that
    /// cannot be written stops the run while it has decided nothing.
    pub(crate) fn open(&mut self) -> Result<()> {
        if let (Some(place), None) = (&self.place, &self.sink) {
            self.sink = Some(Sink::open(place, &self.run)?);
        }
        Ok(())
    }

    /// See [`Suite::allowed_all`].
    pub(crate) const fn allowed_all(&mut self) {
        self.allowed_all = true;
    }

    /// Write the document, if one was asked for and it is not written yet.
    ///
    /// `failed` is a run that ended at exit 2. Where its last answer is not
    /// already a rule that could not look -- the destination could not be
    /// read, the subject was not text -- the suite says so in a testcase of
    /// its own, because a document of passes beside an exit 2 reads to a
    /// publisher as a run that passed.
    pub(crate) fn write(&mut self, failed: bool) -> Result<()> {
        if std::mem::replace(&mut self.written, true) {
            return Ok(());
        }
        let Some(place) = &self.place else {
            return Ok(());
        };
        let sink = match self.sink.take() {
            Some(sink) => sink,
            None => Sink::open(place, &self.run)?,
        };
        let mut suite = Suite::new(sink, self.run.clone());
        if self.allowed_all {
            suite.allowed_all();
        }
        for merged in merged(&self.ledger) {
            suite.record(
                Case {
                    id: &merged.id,
                    builtin: merged.builtin.as_deref(),
                    set: merged.set.as_deref(),
                    subjects: &merged.subjects,
                },
                merged.outcome,
            );
        }
        if failed
            && self
                .ledger
                .last()
                .is_none_or(|last| last.outcome() != Outcome::Unknown)
        {
            suite.could_not_look();
        }
        suite.write()
    }

    /// Write after the run ended in `result`, and hand `result` back: the
    /// run's own error is still the one a reader acts on, with the file's
    /// appended if both failed.
    pub(crate) fn finish(&mut self, result: Result<Exit>) -> Result<Exit> {
        let failed = matches!(result, Err(_) | Ok(Exit::Broken));
        match (self.write(failed), result) {
            (Ok(()), result) => result,
            (Err(also), Err(error)) => Err(Fatal::new(format!("{error}\n\n{also}"))),
            (Err(also), Ok(_)) => Err(also),
        }
    }
}

/// One testcase's worth of a seam's list: a rule asked about a title and then
/// a body is one rule, and two testcases would count one refusal twice.
struct Merged {
    id: String,
    builtin: Option<String>,
    set: Option<String>,
    subjects: Vec<String>,
    outcome: Outcome,
}

/// The list folded to one entry per rule, in the order each was first asked.
/// The answer kept is the one a reader most needs: could not look over
/// refused over passed over did not run.
fn merged(ledger: &[Judgment]) -> Vec<Merged> {
    const fn weight(outcome: Outcome) -> u8 {
        match outcome {
            Outcome::Unknown => 4,
            Outcome::Refuse => 3,
            Outcome::Pass => 2,
            Outcome::Bypass(_) => 1,
            Outcome::OutOfScope => 0,
        }
    }
    let mut merged: Vec<Merged> = Vec::new();
    for judgment in ledger {
        let outcome = judgment.outcome();
        if !merged.iter().any(|entry| entry.id == judgment.id) {
            merged.push(Merged {
                id: judgment.id.clone(),
                builtin: judgment.builtin.clone(),
                set: judgment.set.clone(),
                subjects: Vec::new(),
                outcome,
            });
        }
        let Some(entry) = merged.iter_mut().find(|entry| entry.id == judgment.id) else {
            continue;
        };
        if weight(outcome) > weight(entry.outcome) {
            entry.outcome = outcome;
        }
        if let Some(subject) = &judgment.subject
            && !entry.subjects.contains(subject)
        {
            entry.subjects.push(subject.clone());
        }
    }
    merged
}

fn skipped(message: &str) -> TestCaseStatus {
    let mut status = TestCaseStatus::skipped();
    status.set_message(message);
    status
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
        let mut suite = Suite::new(
            Sink::new(&mut buffer, Path::new("memory")),
            Run::Stage(String::from("pre-push")),
        );
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
        subjects: &[],
    };
    const LOCAL: Case<'static> = Case {
        id: "b-rule",
        builtin: Some("b-builtin"),
        set: None,
        subjects: &[],
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

    /// The fifth state is a skip of its own, told from a bypass by its
    /// message and its property.
    #[test]
    fn out_of_scope_is_skipped_and_says_the_destination_stood_it_down() {
        let report = written(&[(LOCAL, Outcome::OutOfScope)]);
        let suite = &report.test_suites[0];
        assert_eq!((suite.tests, suite.skipped), (1, 1));
        let case = &suite.test_cases[0];
        assert!(matches!(
            &case.status,
            TestCaseStatus::Skipped { message: Some(message), .. }
                if message.as_str() == "out of scope at this destination"
        ));
        assert_eq!(property(case, "scope"), Some("destination"));
        assert_eq!(property(case, "allowed"), None);
    }

    #[test]
    fn a_suite_name_becomes_a_file_name_of_dashes_and_lowercase() {
        assert_eq!(Run::Text.slug(), "uphold-guard-text");
        assert_eq!(Run::Shim(String::from("gh")).slug(), "uphold-shim-gh");
        assert_eq!(
            Run::Hook(String::from("claude-code")).slug(),
            "uphold-hook-claude-code"
        );
    }

    #[test]
    fn two_ids_from_one_process_differ() {
        assert_ne!(fresh_id(), fresh_id());
    }

    fn judged(id: &str, subject: &str, answer: crate::text::Answer) -> Judgment {
        Judgment {
            id: id.to_owned(),
            builtin: None,
            set: None,
            subject: Some(subject.to_owned()),
            answer,
        }
    }

    /// One rule asked about a title and a body is one testcase, carrying both
    /// kinds and the answer that refused.
    #[test]
    fn a_rule_asked_about_two_subjects_is_one_testcase() {
        use crate::text::Answer;
        let refusal = crate::guard::Refusal {
            id: String::from("a"),
            report: String::from("no"),
        };
        let merged = merged(&[
            judged("a", "title", Answer::Pass),
            judged("b", "title", Answer::Pass),
            judged(
                "a",
                "text",
                Answer::Refused(crate::text::Verdict::Guard(refusal)),
            ),
        ]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].id, "a");
        assert_eq!(merged[0].outcome, Outcome::Refuse);
        assert_eq!(merged[0].subjects, ["title", "text"]);
        assert_eq!(merged[1].outcome, Outcome::Pass);
    }
}
