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
    run(root, &path)
}

/// The stub directory as the WHOLE of `PATH`.
///
/// `/usr/bin` is not neutral for this command: a distro that ships a `cargo`
/// shim there -- rustup's, on the machine this was written on -- makes the
/// "cargo is not on PATH" branch unreachable through the helper above, and a
/// branch no test can reach is one that gets to be wrong.
fn supply_without_the_system_path(root: &Path, tools: &Path) -> Output {
    run(root, tools.as_os_str())
}

fn run(root: &Path, path: &std::ffi::OsStr) -> Output {
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

/// A scanner that died on a signal answered nothing.
///
/// `output.status.code()` is `None` there, and the two shapes a wrapper reaches
/// for -- `success()` (false, so a refusal) or a defaulted code -- both invent a
/// verdict out of a run that produced none. An OOM-killed osv-scanner reported
/// as "found vulnerabilities" is the wrong red; reported as clean it is the
/// failure this crate exists to refuse. It is exit 2, by name.
#[test]
fn a_scanner_killed_by_a_signal_is_could_not_look_rather_than_either_verdict() {
    let root = repository();
    let tools = stubs(&[("osv-scanner", "kill -9 $$")]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(
        said.contains("osv-scanner was killed and gave no verdict"),
        "{said}"
    );
    assert!(!said.contains("all checks passed"), "{said}");
    assert!(!said.contains("   FAILED"), "{said}");
}

/// Workflows present and zizmor absent is not "no workflows here".
///
/// The section short-circuits to `Nothing` when the tree has no workflow
/// directory, and that branch is a pass. Reaching the missing-tool check only
/// after the enumeration is what keeps the two apart: a repository whose
/// workflows nobody scanned must exit 2 and name zizmor.
#[test]
fn workflows_with_no_zizmor_on_path_is_could_not_look_not_no_workflows_here() {
    let root = repository();
    std::fs::create_dir_all(root.join(".github/workflows")).unwrap();
    std::fs::write(root.join(".github/workflows/ci.yml"), "on: push\n").unwrap();
    let tools = stubs(&[("osv-scanner", "exit 0")]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("zizmor is not on PATH"), "{said}");
    assert!(!said.contains("no workflows here"), "{said}");
}

/// A `deny.toml` over a tree with no crate root is read-nothing, not clean.
///
/// The manifest filter is the load-bearing half: a `Cargo.toml` that declares
/// neither `[package]` nor `[workspace]` is not a thing cargo-deny can be
/// pointed at, and counting it would print "1 crate(s) checked" for a run that
/// checked none. The count is the only place a reader can see the difference.
#[test]
fn a_deny_toml_with_no_crate_under_it_says_so_instead_of_counting_a_check() {
    let root = repository();
    std::fs::write(
        root.join("deny.toml"),
        "[bans]\nmultiple-versions = 'deny'\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join("fragment")).unwrap();
    std::fs::write(
        root.join("fragment/Cargo.toml"),
        "[dependencies]\nleft-pad = '1'\n",
    )
    .unwrap();
    let tools = stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "cargo",
            "echo 'cargo-deny was handed a manifest with no crate in it'; exit 1",
        ),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 0, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("0 crate(s) checked"), "{said}");
    assert!(
        said.contains("a deny.toml and no crate to hold to it"),
        "{said}"
    );
    assert!(!said.contains("cargo-deny was handed a manifest"), "{said}");
}

/// cargo-deny's headlines are shown and its config classes are not.
///
/// Grepping for `warning[` alone once reported cargo-deny's own informational
/// warnings as failures, so four classes that describe `deny.toml` rather than
/// a dependency are dropped -- and the exit code, not the grep, decides. Both
/// halves are asserted at once because dropping the wrong one is silent: the
/// run stays red either way, and only the printed reason changes.
#[test]
fn cargo_deny_headlines_are_printed_and_the_config_only_classes_are_not() {
    let root = repository();
    std::fs::write(root.join("deny.toml"), "[bans]\n").unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]\nname = 'fixture'\n").unwrap();
    let tools = stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "cargo",
            "echo 'error[vulnerability]: RUSTSEC-0000-0001 in left-pad'\n\
             echo 'warning[license-not-encountered]: MIT was allowed and never used'\n\
             echo '  = the indented detail nobody reads'\n\
             exit 1",
        ),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 1, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("RUSTSEC-0000-0001 in left-pad"), "{said}");
    assert!(said.contains("1 crate(s) checked"), "{said}");
    assert!(said.contains("FAILED: cargo-deny"), "{said}");
    assert!(!said.contains("license-not-encountered"), "{said}");
    assert!(!said.contains("the indented detail nobody reads"), "{said}");
}

/// cargo-deny that is not installed is exit 2, not a refusal and not a pass.
///
/// `cargo` itself is on PATH, so the missing-tool check above the loop cannot
/// see this one: an absent `cargo-deny` subcommand arrives as exit 127 from
/// cargo, which every other exit code in this loop is treated as a finding.
/// Reading 127 as "cargo-deny found something" is a red nobody can fix;
/// reading it as clean is the fail-open.
#[test]
fn a_cargo_deny_that_is_not_installed_is_could_not_look_rather_than_a_finding() {
    let root = repository();
    std::fs::write(root.join("deny.toml"), "[bans]\n").unwrap();
    std::fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
    let tools = stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "cargo",
            "echo 'error: no such command: `deny`' >&2; exit 127",
        ),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("cargo deny could not run"), "{said}");
    assert!(!said.contains("FAILED"), "{said}");
}

/// cargo-vet runs where a store exists, and its refusal is the run's.
///
/// The section is conditional on `supply-chain/` because a vet store carries an
/// exemption for every dependency present the day it was made, so creating one
/// automatically would manufacture stores nobody owns. The cost of that
/// conditional is that the opted-in path is the one no other test reaches: a
/// crate that ran `cargo vet init` and whose audit refuses must exit 1 with the
/// words vet printed, not the "no store here" pass its neighbour gets.
#[test]
fn a_repository_with_a_vet_store_runs_vet_and_reports_what_it_said() {
    let root = repository();
    std::fs::create_dir_all(root.join("supply-chain")).unwrap();
    std::fs::write(root.join("supply-chain/audits.toml"), "[audits]\n").unwrap();
    let tools = stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "cargo",
            "[ \"$1\" = vet ] || exit 0\n\
             echo 'error: some crates are unaudited: left-pad 1.0.0'\n\
             exit 1",
        ),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 1, "{}", text(&output));
    let said = text(&output);
    assert!(
        said.contains("some crates are unaudited: left-pad"),
        "{said}"
    );
    assert!(!said.contains("no supply-chain/ store here"), "{said}");
}

/// A Python lock is exported by uv and handed to guarddog.
///
/// guarddog reads a requirements file, uv.lock is not one, and the export is
/// therefore not plumbing but the whole section: a run that skipped it would
/// scan nothing and say "checked". The refusal is asserted rather than a clean
/// run so that the count and the verdict are both pinned.
#[test]
fn a_python_lock_is_exported_for_guarddog_and_its_refusal_is_the_runs() {
    let root = repository();
    std::fs::create_dir_all(root.join("service")).unwrap();
    std::fs::write(root.join("service/uv.lock"), "version = 1\n").unwrap();
    let tools = stubs(&[
        ("osv-scanner", "exit 0"),
        ("uv", "echo 'reqests==2.0.0'"),
        (
            "guarddog",
            "grep -q 'reqests==2.0.0' \"$3\" || { echo 'guarddog was not handed the export'; exit 2; }\n\
             echo 'typosquatting: reqests shadows requests'\n\
             exit 1",
        ),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 1, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("FAILED: guarddog pypi"), "{said}");
    assert!(said.contains("1 Python/npm manifest(s) checked"), "{said}");
    assert!(
        !said.contains("guarddog was not handed the export"),
        "{said}"
    );
}

/// A `uv` that is not on PATH is could-not-look, not a clean Python section.
///
/// guarddog IS installed here, so the section's own missing-tool check passes
/// and the run reaches the export. Nothing was read; a pass would say the
/// Python manifests were scanned when uv never ran.
#[test]
fn a_python_lock_with_no_uv_on_path_is_could_not_look_not_a_pass() {
    let root = repository();
    std::fs::write(root.join("uv.lock"), "version = 1\n").unwrap();
    let tools = stubs(&[("osv-scanner", "exit 0"), ("guarddog", "exit 0")]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("uv is not on PATH"), "{said}");
    assert!(!said.contains("all checks passed"), "{said}");
}

/// An export that fails is a failure of the section, not a skipped manifest.
///
/// `uv export` refusing -- a lock out of date with its `pyproject.toml` is the
/// ordinary cause -- leaves guarddog nothing to read. Continuing to the next
/// manifest without recording it would let a run over one broken lock and one
/// clean one print a pass.
#[test]
fn a_uv_export_that_fails_is_a_failure_rather_than_a_manifest_quietly_skipped() {
    let root = repository();
    std::fs::write(root.join("uv.lock"), "version = 1\n").unwrap();
    let tools = stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "uv",
            "echo 'error: the lock file is not up to date' >&2; exit 2",
        ),
        ("guarddog", "echo 'guarddog ran on nothing'; exit 0"),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 1, "{}", text(&output));
    let said = text(&output);
    assert!(
        said.contains("FAILED: guarddog: uv export failed"),
        "{said}"
    );
    assert!(!said.contains("guarddog ran on nothing"), "{said}");
}

/// An npm manifest is scanned in its own directory, and a clean one passes.
///
/// `package.json` is handed to guarddog by bare name with the working directory
/// set to the manifest's own, so a nested package scanned from the repository
/// root would read the wrong file or none. The clean case is asserted here
/// because it is the only place the section's success path and its count are
/// both visible.
#[test]
fn an_npm_manifest_is_scanned_where_it_lives_and_a_clean_one_is_a_pass() {
    let root = repository();
    std::fs::create_dir_all(root.join("web")).unwrap();
    std::fs::write(root.join("web/package.json"), "{\"name\": \"web\"}\n").unwrap();
    let tools = stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "guarddog",
            "grep -q '\"web\"' package.json || { echo 'wrong directory'; exit 1; }\nexit 0",
        ),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 0, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("1 Python/npm manifest(s) checked"), "{said}");
    assert!(said.contains("all checks passed"), "{said}");
    assert!(!said.contains("wrong directory"), "{said}");
}

/// A refusing npm scan is a failure, named by the directory it came from.
///
/// A fleet run prints many sections; "guarddog npm" without the directory is a
/// finding nobody can locate, which was the divergence between the seven copies
/// of the shell task this replaces -- one dumped the failure output, the rest
/// printed a bare FAILED.
#[test]
fn a_refusing_npm_scan_names_the_directory_it_refused_in() {
    let root = repository();
    std::fs::create_dir_all(root.join("web")).unwrap();
    std::fs::write(root.join("web/package.json"), "{\"name\": \"web\"}\n").unwrap();
    let tools = stubs(&[("osv-scanner", "exit 0"), ("guarddog", "exit 1")]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 1, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("FAILED: guarddog npm"), "{said}");
    assert!(said.contains("web"), "{said}");
}

/// A section with work to do and no tool to do it names the tool.
///
/// Both of these sections gate on the tree first -- `deny.toml` here, a
/// `package.json` there -- and the gate's other answer is a pass. Reaching the
/// missing-tool check only after the gate is what keeps "nothing to check" and
/// "nobody checked" apart, and the reader is owed the name of what to install
/// rather than a bare exit 2.
#[test]
fn a_section_with_work_and_no_tool_installed_names_the_tool_and_is_not_a_pass() {
    let root = repository();
    std::fs::write(root.join("deny.toml"), "[bans]\n").unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]\nname = 'fixture'\n").unwrap();
    std::fs::write(root.join("package.json"), "{\"name\": \"fixture\"}\n").unwrap();
    let tools = stubs(&[("osv-scanner", "exit 0")]);
    let output = supply_without_the_system_path(&root, &tools);
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("cargo is not on PATH"), "{said}");
    assert!(said.contains("guarddog is not on PATH"), "{said}");
    assert!(!said.contains("all checks passed"), "{said}");
    assert!(!said.contains("no deny.toml"), "{said}");
    assert!(!said.contains("no Python or npm manifests here"), "{said}");
}

/// A cargo-deny that finds nothing is clean, and says how many it looked at.
///
/// The count is the only evidence in the output that anything ran: a manifest
/// filter that matched nothing produces the same silent green as a workspace
/// cargo-deny approved, and the two must not read alike. This is the section's
/// success path, which every other cargo-deny test here deliberately fails.
#[test]
fn a_cargo_deny_that_finds_nothing_is_clean_and_says_how_many_crates_it_read() {
    let root = repository();
    std::fs::write(root.join("deny.toml"), "[bans]\n").unwrap();
    std::fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = ['a']\n").unwrap();
    std::fs::create_dir_all(root.join("a")).unwrap();
    std::fs::write(root.join("a/Cargo.toml"), "[package]\nname = 'a'\n").unwrap();
    let tools = stubs(&[("osv-scanner", "exit 0"), ("cargo", "exit 0")]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 0, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("2 crate(s) checked"), "{said}");
    assert!(said.contains("all checks passed"), "{said}");
    assert!(!said.contains("no crate to hold to it"), "{said}");
}
