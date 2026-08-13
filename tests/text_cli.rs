//! CLI-level tests for `uphold scan --text`.
//!
//! Text mode is the one entry point whose subject never becomes a file: a
//! commit message, a pull-request body, a release note, handed in on stdin and
//! published the moment it is accepted. Every test here is driven through the
//! binary rather than through `text::check`, because what is being preserved is
//! what the CALLER sees -- the exit code, and whether a refusal was printed at
//! all. A test calling `dedent` directly cannot tell the difference between a
//! violation report and a process that died at exit 101 before printing one,
//! and that difference is the whole subject of the first test below.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A policy directory and nothing else. No `git init`: `discover` stops at a
/// repository root but does not require one, and text mode runs wherever the
/// author happens to be standing.
fn workspace(policy: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "uphold-text-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    std::fs::write(root.join("policy/principles.toml"), policy).unwrap();
    root
}

/// `HOME` is set on every run, never inherited. The identity needles are read
/// from the environment the scan runs in, so a test that let the real one
/// through would assert on this machine's username and home path and mean
/// something different on the next machine.
fn scan_text(root: &Path, stdin: &[u8], home: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["scan", "--text", "-"])
        .current_dir(root)
        .env_remove("UPHOLD_ALLOW")
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

// ── the report survives the message it has to print ──────────────────

/// A message no policy author is forbidden to write used to be a crash.
///
/// `report::dedent` minimised a BYTE count over the non-blank lines while
/// `trim_start` stripped UNICODE whitespace, so the minimum taken from the
/// two-space ASCII line landed inside the first U+3000 of the wide-indented
/// line and `&line[indent..]` panicked. The two whitespace-only lines are the
/// second way in -- excluded from the minimum and sliced by it anyway -- and
/// the single ASCII space is shorter than the minimum in BYTES as well, so it
/// panicked on the range rather than on the boundary. Both are in one message
/// because both reach the same function from the same field.
///
/// The consequence is why this is a CLI test and not a unit test. The panic
/// happened INSIDE the function whose only job is printing a violation, so the
/// run that found the violation exited 101 having said nothing about it -- a
/// check that looked, found, and then reported neither a pass nor a failure.
/// Only the process boundary can tell that apart from a report.
#[test]
fn a_message_indented_with_unicode_whitespace_is_printed_not_panicked() {
    let root = workspace(
        "[rule.no-example-needle]\n\
         message = \"\"\"\n  \
         ASCII indent, and a multi-byte character: caf\u{e9} \u{2014}\n\
         \u{3000}\u{3000}Wide-space indent on this line.\n\
         \u{a0}\n \n  \
         Use neutral placeholders such as example-user instead.\n\
         \"\"\"\n\
         forbidden_literals_from = \"printf 'example-needle\\n'\"\n\
         \n\
         [rule.no-example-needle.files]\n",
    );

    let output = scan_text(
        &root,
        b"deployed with example-needle today\n",
        "/srv/example",
    );

    assert_eq!(code(&output), 1, "{}", stderr(&output));
    // Named explicitly: 101 is the abort the fix exists to remove, and it is
    // the one wrong answer that also looks like "some other failure".
    assert_ne!(code(&output), 101, "{}", stderr(&output));
    assert!(!stderr(&output).contains("panicked"), "{}", stderr(&output));

    // The three non-blank lines arrive with the shared two-CHARACTER indent
    // gone and their characters intact. Asserting on the text and not just on
    // the exit code is what distinguishes a report from a rule that happened to
    // fire while printing nothing usable.
    let printed = stderr(&output);
    assert!(
        printed.contains("ASCII indent, and a multi-byte character: caf\u{e9} \u{2014}"),
        "{printed}"
    );
    assert!(
        printed.contains("Wide-space indent on this line."),
        "{printed}"
    );
    assert!(
        printed.contains("Use neutral placeholders such as example-user instead."),
        "{printed}"
    );
    assert!(printed.contains("no-example-needle"), "{printed}");
}

// ── the bytes that could not be read ─────────────────────────────────

/// stdin that is not UTF-8 is exit 2, and the wording is `scan`'s wording.
///
/// `tests/guard_recovered_halves.rs` pins the exit code for the same input;
/// this pins the ANSWER, because the failure being guarded against was never a
/// wrong exit code on its own -- it was "policy checks passed (text)" printed
/// over bytes `from_utf8_lossy` had already replaced. So the pass line is
/// asserted absent, and the phrase `scan` uses about a non-UTF-8 file is
/// asserted present, since two readers giving the same bytes two different
/// answers is how one of them stops being believed.
#[test]
fn non_utf8_stdin_says_unexamined_and_never_prints_the_pass_line() {
    let root = workspace(
        "[rule.no-example-needle]\n\
         message = \"do not publish the needle\"\n\
         forbidden_literals_from = \"printf 'example-needle\\n'\"\n\
         \n\
         [rule.no-example-needle.files]\n",
    );

    let output = scan_text(&root, b"caf\xe9 latin1 bytes\n", "/srv/example");

    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(stderr(&output).contains("not UTF-8"), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("unexamined"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stdout(&output).contains("policy checks passed"),
        "{}",
        stdout(&output)
    );
}

// ── the host-identity fallback ───────────────────────────────────────

/// A distinctive home path, so that only the `home-path` needle can match and
/// the assertion does not depend on this machine's username or hostname.
const EXAMPLE_HOME: &str = "/srv/example-home-7c3e91";

/// A repository that declares a literal rule about something ELSE keeps the
/// fallback.
///
/// The test used to be for the check KIND, so any `forbidden_literals` rule at
/// all -- a repository's own literal list, a command source, a rule about the
/// default route -- silently deleted the one rule that stops the running host's
/// identity being published. Declaring a rule about the default route is not a
/// decision to stop checking identity.
///
/// The fallback's own id is asserted rather than only the exit code: the
/// declared rule is present in this policy too, and an exit of 1 alone cannot
/// say which of the two produced it.
#[test]
fn an_unrelated_literal_rule_leaves_the_identity_fallback_in_place() {
    let root = workspace(
        "[rule.no-default-route-in-text]\n\
         message = \"Do not publish this machine's default route.\"\n\
         forbidden_literals = \"running-default-route\"\n\
         files.include = [\".\"]\n",
    );

    let subject = format!("the log said {EXAMPLE_HOME}/work/output.txt\n");
    let output = scan_text(&root, subject.as_bytes(), EXAMPLE_HOME);

    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no-running-os-identity-metadata"),
        "{}",
        stderr(&output)
    );
}

/// A repository that declares the identity rule ITSELF is answered once.
///
/// The other half of the same test. Matching on the rule's literal source and
/// not on its check kind has to suppress the fallback exactly when the
/// repository has already said this -- otherwise the same home path is reported
/// twice under two rule names, and a reader who fixes the one they were shown
/// still has a finding open.
#[test]
fn a_declared_identity_rule_is_not_reported_twice() {
    let root = workspace(
        "[rule.house-identity-rule]\n\
         message = \"Do not publish host identity.\"\n\
         forbidden_literals = \"running-os-identity\"\n\
         files.include = [\".\"]\n",
    );

    let subject = format!("the log said {EXAMPLE_HOME}/work/output.txt\n");
    let output = scan_text(&root, subject.as_bytes(), EXAMPLE_HOME);

    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("house-identity-rule"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("no-running-os-identity-metadata"),
        "{}",
        stderr(&output)
    );
}
