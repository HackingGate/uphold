//! Reading back the `JUnit` documents a seam writes, with the library that
//! wrote them.
//!
//! Shared because three seams write the same document -- the shim, the harness
//! hook and `guard --text` -- and each suite asks the same questions of it:
//! which file, which suite, which testcase, and what state it is in.

#![expect(
    clippy::expect_used,
    reason = "a test's reader reports by panicking; there is no caller to hand a Result to"
)]

use std::path::{Path, PathBuf};

use quick_junit::{NonSuccessKind, Report, TestCase, TestCaseStatus, TestSuite, XmlString};

/// The file read back, holding exactly one suite, and the text it was read
/// from -- for the assertions about what is NOT in it.
pub fn suite(path: &Path) -> (TestSuite, String) {
    let text = std::fs::read_to_string(path).expect("the document a run wrote");
    let mut report = Report::deserialize_from_str(&text).expect("a JUnit document");
    assert_eq!(report.test_suites.len(), 1, "{text}");
    (report.test_suites.remove(0), text)
}

/// Every file in `directory`, in name order, which is the order they were
/// written in.
pub fn files_in(directory: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(directory)
        .expect("the evidence directory")
        .map(|entry| entry.expect("a directory entry").path())
        .collect();
    files.sort();
    files
}

/// The one testcase named `id`.
pub fn case<'s>(suite: &'s TestSuite, id: &str) -> &'s TestCase {
    let mut found = suite
        .test_cases
        .iter()
        .filter(|case| case.name.as_str() == id);
    let case = found.next();
    assert!(case.is_some(), "no {id} in {suite:?}");
    assert!(found.next().is_none(), "{id} twice in {suite:?}");
    case.expect("asserted above")
}

/// Every value of the property `name`, in order.
pub fn properties<'c>(case: &'c TestCase, name: &str) -> Vec<&'c str> {
    case.properties
        .iter()
        .filter(|property| property.name.as_str() == name)
        .map(|property| property.value.as_str())
        .collect()
}

/// The first value of the property `name`.
pub fn property<'c>(case: &'c TestCase, name: &str) -> Option<&'c str> {
    properties(case, name).first().copied()
}

/// Which of the testcase states this is, and the message it carries.
pub fn state(case: &TestCase) -> (&'static str, Option<&str>) {
    match &case.status {
        TestCaseStatus::Success { .. } => ("pass", None),
        TestCaseStatus::NonSuccess {
            kind: NonSuccessKind::Failure,
            message,
            ..
        } => ("failure", message.as_ref().map(XmlString::as_str)),
        TestCaseStatus::NonSuccess {
            kind: NonSuccessKind::Error,
            message,
            ..
        } => ("error", message.as_ref().map(XmlString::as_str)),
        TestCaseStatus::Skipped { message, .. } => {
            ("skipped", message.as_ref().map(XmlString::as_str))
        }
    }
}

/// The suite's own `package` attribute.
pub fn package(suite: &TestSuite) -> Option<&str> {
    suite.extra.get("package").map(XmlString::as_str)
}
