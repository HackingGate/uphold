//! CLI-level tests for `uphold supply-chain`.
//!
//! The scanners are stubbed on PATH, because what is under test is the
//! orchestration's three answers -- clean, refused, and COULD NOT LOOK -- and
//! that the third is exit 2 rather than either of the others. A missing
//! scanner spelled the same way as a refusal, or worse as a pass, is the
//! failure the shell task this replaces had.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn repository() -> PathBuf {
    let root = support::scratch("supply-chain");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    std::fs::write(
        root.join("policy/principles.toml"),
        "[rule.no-shouting]\nregexp = '^SHOUTING'\nmessage = \"quiet\"\nfiles.include = [\".\"]\n",
    )
    .unwrap();
    root
}

/// A directory of stub scanners, each a script that records and answers.
fn stubs(entries: &[(&str, &str)]) -> PathBuf {
    let directory = support::scratch("supply-chain-stubs");
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    for (name, script) in entries {
        let path = directory.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    directory
}

fn supply(root: &Path, path_extra: Option<&Path>) -> Output {
    let path = path_extra.map_or_else(
        || std::ffi::OsString::from("/usr/bin:/bin"),
        |directory| {
            let mut path = directory.as_os_str().to_owned();
            path.push(":/usr/bin:/bin");
            path
        },
    );
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .arg("supply-chain")
        .env("PATH", path)
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn text(output: &Output) -> String {
    let mut all = String::from_utf8_lossy(&output.stdout).into_owned();
    all.push_str(&String::from_utf8_lossy(&output.stderr));
    all
}

#[test]
fn a_missing_scanner_is_could_not_look_and_exit_2_not_a_pass() {
    // The shell task this replaces answered `command not found` with the same
    // exit 1 a refusal gets; worse spellings answer it with a pass. It is
    // neither: nothing was looked at.
    let root = repository();
    let output = supply(&root, None);
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("osv-scanner is not on PATH"),
        "{}",
        text(&output)
    );
    assert!(
        !text(&output).contains("all checks passed"),
        "{}",
        text(&output)
    );
}

#[test]
fn clean_scanners_over_a_tree_with_nothing_else_is_a_pass_that_says_what_ran() {
    let root = repository();
    let tools = stubs(&[("osv-scanner", "exit 0"), ("guarddog", "exit 0")]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 0, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("all checks passed"), "{said}");
    // The sections with nothing to read say so: "no manifests found" and
    // "checked and clean" must never look the same.
    assert!(said.contains("no workflows here"), "{said}");
    assert!(said.contains("no deny.toml"), "{said}");
    assert!(said.contains("no supply-chain/ store"), "{said}");
}

#[test]
fn a_refusing_scanner_is_a_failure_and_its_words_are_shown() {
    let root = repository();
    let tools = stubs(&[("osv-scanner", "echo 'CVE-0000-0001 in left-pad'\nexit 1")]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 1, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("CVE-0000-0001 in left-pad"), "{said}");
    assert!(said.contains("FAILED"), "{said}");
}

#[test]
fn zizmor_is_handed_the_bundled_config_where_the_repository_has_none() {
    let root = repository();
    std::fs::create_dir_all(root.join(".github/workflows")).unwrap();
    std::fs::write(root.join(".github/workflows/ci.yml"), "on: push\n").unwrap();
    // The stub reads the file its --config names and proves it is the bundled
    // ref-pin policy rather than zizmor's own hash-pin default.
    let tools = stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "zizmor",
            "shift # --config\ngrep -q 'ref-pin' \"$1\" || { echo 'not the bundled policy'; exit 1; }\nexit 0",
        ),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 0, "{}", text(&output));

    // And the repository's own zizmor.yml wins over the bundled one.
    std::fs::write(root.join("zizmor.yml"), "rules: {}\n").unwrap();
    let own = stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "zizmor",
            "shift # --config\ngrep -q 'ref-pin' \"$1\" && { echo 'bundled config used over the repository own'; exit 1; }\nexit 0",
        ),
    ]);
    let repeated = supply(&root, Some(&own));
    assert_eq!(code(&repeated), 0, "{}", text(&repeated));
}
