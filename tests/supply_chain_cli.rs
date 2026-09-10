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

/// The whole-tree form, which is what every section test here is about.
///
/// `--all` is spelled out rather than defaulted because the command no longer
/// has a default: with no range and no flag it refuses, and a helper that hid
/// which of the two modes each test drives would make the scoped tests below
/// read as the same run.
fn run(root: &Path, path: &std::ffi::OsStr) -> Output {
    invoke(root, path, &["--all"], &[])
}

/// One invocation, with the runner's push variables under the test's control.
///
/// They are REMOVED unless a test sets them: a suite run from a pre-push hook
/// inherits a real `PRE_COMMIT_FROM_REF`, and the test that asserts the refusal
/// would then be handed somebody's actual push to scan.
fn invoke(root: &Path, path: &std::ffi::OsStr, args: &[&str], push: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
    command
        .arg("supply-chain")
        .args(args)
        .env("PATH", path)
        // Where each stub records that it ran, and with what.
        .env("STUB_LOG", root.join("stub.log"))
        .current_dir(root)
        .stdin(Stdio::null());
    for name in [
        "PRE_COMMIT_FROM_REF",
        "PRE_COMMIT_TO_REF",
        "PRE_COMMIT_SOURCE",
        "PRE_COMMIT_ORIGIN",
        "PRE_COMMIT_LOCAL_BRANCH",
        "PRE_COMMIT_REMOTE_BRANCH",
    ] {
        command.env_remove(name);
    }
    for (name, value) in push {
        command.env(name, value);
    }
    command.output().unwrap()
}

/// The scoped form, driven the way prek drives it: the range in the two
/// variables the pre-push guard already reads.
fn pushed(root: &Path, tools: &Path, from: &str, to: &str) -> Output {
    let mut path = tools.as_os_str().to_owned();
    path.push(":/usr/bin:/bin");
    invoke(
        root,
        &path,
        &[],
        &[("PRE_COMMIT_FROM_REF", from), ("PRE_COMMIT_TO_REF", to)],
    )
}

/// What the stubs recorded, or the empty string where none ran.
fn journal(root: &Path) -> String {
    std::fs::read_to_string(root.join("stub.log")).unwrap_or_default()
}

/// A stub that records its name, its working directory and its arguments.
///
/// The working directory is half the assertion in the scoped tests: guarddog is
/// run from the manifest's own directory, and a scan of the right file from the
/// wrong place reads the wrong `package.json`.
/// A clean `guarddog verify --output-format json` report.
///
/// guarddog is run with `--output-format json` because its exit code cannot
/// say it found something: `verify` answers 0 either way. So a stub that only
/// answers `exit 0` no longer models the tool -- a clean run PRINTS a report
/// whose `risks` list is empty, and printing nothing is a run that did not
/// report, which is could-not-look.
const GUARDDOG_CLEAN: &str = "echo '[{\"dependency\":\"six\",\"result\":\
    {\"errors\":{},\"issues\":0,\"results\":{},\"risks\":[]}}]'\nexit 0";

/// The same report with one risk in it, which is a finding at exit 0.
const GUARDDOG_RISK: &str = "echo '[{\"dependency\":\"reqests\",\"result\":\
    {\"errors\":{},\"issues\":1,\"results\":{},\"risks\":\
    [{\"name\":\"typosquatting\",\"severity\":\"high\"}]}}]'\nexit 0";

fn recording(answer: &str) -> String {
    format!("echo \"$(basename \"$0\") [$PWD] $*\" >> \"$STUB_LOG\"\n{answer}")
}

fn git(root: &Path, args: &[&str]) {
    let output = Command::new(support::real_git())
        .args(args)
        .current_dir(root)
        .stdout(Stdio::null())
        .output()
        .unwrap();
    // What git said, and where. A helper that swallowed stderr reported a
    // missing committer identity as `git ["commit", ...] failed`, which is the
    // one fact a reader already has -- and the cause was one config line away in
    // a message nobody could see.
    assert!(
        output.status.success(),
        "git {args:?} in {} failed:\n{}",
        root.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn commit(root: &Path, message: &str) -> String {
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "--allow-empty", "-m", message]);
    head(root)
}

fn head(root: &Path) -> String {
    let output = Command::new(support::real_git())
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// A fixture with history, because a range is the subject of every test below.
fn tracked() -> PathBuf {
    let root = support::scratch("supply-chain-range");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    // Git first, policy second: on a machine with the shims installed, `git
    // init` inside a tree whose policy is already written runs the shim, and
    // the fixture's setup would be reading its own subject.
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.name", "Test"]);
    git(&root, &["config", "user.email", "test@example.test"]);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    std::fs::write(
        root.join("policy/principles.toml"),
        "[rule.no-shouting]\nregexp = '^SHOUTING'\nmessage = \"quiet\"\nfiles.include = [\".\"]\n",
    )
    .unwrap();
    commit(&root, "the tree before the range");
    root
}

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
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
            // `$5`, not `$3`: the export path sits after `--output-format json`,
            // which guarddog needs because its exit code cannot report a find.
            &format!(
                "grep -q 'reqests==2.0.0' \"$5\" || {{ echo 'guarddog was not handed the \
                 export'; exit 2; }}\n{GUARDDOG_RISK}"
            ),
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
            &format!(
                "grep -q '\"web\"' package.json || {{ echo 'wrong directory'; exit 1; }}\n{GUARDDOG_CLEAN}"
            ),
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
    let tools = stubs(&[("osv-scanner", "exit 0"), ("guarddog", GUARDDOG_RISK)]);
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

// ── the range, and what it selects ───────────────────────────────────
//
// Every scanner here reaches the network, and the whole-tree form charged a
// push that changed no lockfile, manifest or workflow for all five. What the
// scoped mode has to prove is not that it is faster: it is that the narrowing
// is the RANGE's and not the walker's convenience -- a manifest inside a bumped
// submodule is in the push as surely as one at the root, and a range this
// command cannot read is refused rather than narrowed to nothing.

/// No range and no flag refuses, naming both flags.
///
/// This is the guard's own rule about an absent source, at a second seam: the
/// fall-through available here is the working tree, which at pre-push is quite
/// likely a different branch, and reporting on it would be a green tick about
/// something nobody pushed. The message has to name both flags, because a
/// refusal that does not say how to proceed is the one people work around.
#[test]
fn no_range_and_no_flag_refuses_and_names_the_two_flags_that_supply_one() {
    let root = tracked();
    let tools = stubs(&[("osv-scanner", "exit 0")]);
    let mut path = tools.as_os_str().to_owned();
    path.push(":/usr/bin:/bin");
    let output = invoke(&root, &path, &[], &[]);
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("--base"), "{said}");
    assert!(said.contains("--all"), "{said}");
    assert!(journal(&root).is_empty(), "{}", journal(&root));
}

/// A range with nothing a scanner reads runs nothing, and says so once.
///
/// The line matters as much as the exit code: a run that printed five empty
/// sections would read as five scans that found nothing, and this one made no
/// network call at all.
#[test]
fn a_range_touching_no_manifest_runs_no_scanner_and_says_so_in_one_line() {
    let root = tracked();
    write(&root, "src/main.rs", "fn main() {}\n");
    let before = head(&root);
    let after = commit(&root, "source only");
    let tools = stubs(&[
        ("osv-scanner", &recording("exit 0")),
        ("zizmor", &recording("exit 0")),
        ("guarddog", &recording(GUARDDOG_CLEAN)),
        ("cargo", &recording("exit 0")),
    ]);
    let output = pushed(&root, &tools, &before, &after);
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains("nothing in this range"),
        "{}",
        text(&output)
    );
    assert!(journal(&root).is_empty(), "{}", journal(&root));
}

/// `--all` over the same tree still scans every manifest.
///
/// The scoped mode narrows what a push pays for; it does not decide what the
/// tree contains. A scheduled full sweep is the second hook id, and if `--all`
/// inherited the range's filter there would be nothing left that ever reads a
/// manifest no commit touched.
#[test]
fn all_scans_every_manifest_even_where_the_range_holds_none_of_them() {
    let root = tracked();
    write(&root, "harness/uv.lock", "version = 1\n");
    write(&root, ".github/workflows/ci.yml", "on: push\n");
    write(&root, "src/main.rs", "fn main() {}\n");
    let _ = commit(&root, "a tree with manifests in it");
    let tools = stubs(&[
        ("osv-scanner", &recording("exit 0")),
        ("zizmor", &recording("exit 0")),
        ("uv", &recording("echo 'requests==2.0.0'")),
        ("guarddog", &recording(GUARDDOG_CLEAN)),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 0, "{}", text(&output));
    let ran = journal(&root);
    assert!(ran.contains("osv-scanner"), "{ran}");
    assert!(ran.contains("zizmor"), "{ran}");
    assert!(ran.contains("guarddog"), "{ran}");
}

/// A changed Python lock is scanned where it lives, and nowhere else.
///
/// The second manifest is the assertion. guarddog is a minute of network per
/// handful of packages, and a scoped run that still walked to every `uv.lock`
/// in the tree would have narrowed nothing at the only cost that mattered.
#[test]
fn a_changed_python_lock_runs_guarddog_in_that_directory_and_not_the_others() {
    let root = tracked();
    write(&root, "other/uv.lock", "version = 1\n");
    let _ = commit(&root, "a lock this push does not touch");
    let before = head(&root);
    write(&root, "harness/uv.lock", "version = 1\n");
    let after = commit(&root, "the lock this push does touch");
    let tools = stubs(&[
        ("osv-scanner", &recording("exit 0")),
        ("uv", &recording("echo 'requests==2.0.0'")),
        ("guarddog", &recording(GUARDDOG_CLEAN)),
    ]);
    let output = pushed(&root, &tools, &before, &after);
    assert_eq!(code(&output), 0, "{}", text(&output));
    let ran = journal(&root);
    assert!(ran.contains("guarddog"), "{ran}");
    assert!(ran.contains("harness"), "{ran}");
    assert!(!ran.contains("other"), "{ran}");
    // The lock is handed to osv-scanner by path, not scanned for by a walk.
    assert!(ran.contains("-L"), "{ran}");
    assert!(
        text(&output).contains("1 lockfile(s) in this range"),
        "{}",
        text(&output)
    );
}

/// A changed workflow reaches zizmor as a FILE, and its neighbours do not.
///
/// zizmor handed the directory would report the whole directory's backlog for
/// one edited workflow -- findings nobody in this push introduced, on the run
/// that blocks it.
#[test]
fn a_changed_workflow_is_handed_to_zizmor_by_file_and_its_neighbours_are_not() {
    let root = tracked();
    write(&root, ".github/workflows/release.yml", "on: release\n");
    let _ = commit(&root, "a workflow this push does not touch");
    let before = head(&root);
    write(&root, ".github/workflows/ci.yml", "on: push\n");
    let after = commit(&root, "the workflow this push does touch");
    let tools = stubs(&[
        ("osv-scanner", &recording("exit 0")),
        ("zizmor", &recording("exit 0")),
    ]);
    let output = pushed(&root, &tools, &before, &after);
    assert_eq!(code(&output), 0, "{}", text(&output));
    let ran = journal(&root);
    assert!(ran.contains("ci.yml"), "{ran}");
    assert!(!ran.contains("release.yml"), "{ran}");
    assert!(
        text(&output).contains("1 workflow file(s) in this range"),
        "{}",
        text(&output)
    );
}

/// A push carrying only a pipeline definition is told the file went unscanned.
///
/// What this replaces is "nothing in this range that a scanner reads" --
/// literally true, heard as "nothing here needed scanning". A job that mints a
/// token or pulls an unpinned orb is the surface zizmor exists for, in a file
/// zizmor cannot parse.
#[test]
fn a_range_holding_only_a_ci_config_says_the_file_is_unscanned_not_that_there_was_nothing() {
    let root = tracked();
    let before = head(&root);
    write(&root, ".circleci/config.yml", "version: 2.1\njobs: {}\n");
    let after = commit(&root, "a pipeline no scanner here reads");
    let tools = stubs(&[
        ("osv-scanner", &recording("exit 0")),
        ("zizmor", &recording("exit 0")),
        ("guarddog", &recording(GUARDDOG_CLEAN)),
        ("cargo", &recording("exit 0")),
    ]);
    let output = pushed(&root, &tools, &before, &after);
    // A declaration, not a verdict: neither count moves, so this exits clean.
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains(".circleci/config.yml is CI configuration no scanner here reads"),
        "{}",
        text(&output)
    );
    assert!(
        !text(&output).contains("nothing in this range"),
        "{}",
        text(&output)
    );
    // And no scanner was handed it: the declaration says the file is unread.
    assert!(journal(&root).is_empty(), "{}", journal(&root));
}

/// The whole-tree form declares it too, beside the workflows it did scan.
///
/// `--all` is the sweep a reader trusts to have seen everything, so it is the
/// run where five green sections over an unscanned pipeline mislead most.
///
/// A DIFFERENT VENDOR FROM THE TEST ABOVE, deliberately: the class is every CI
/// system no scanner reads, and two tests over one vendor would leave every
/// other name in the list resting on the unit test alone.
#[test]
fn a_whole_tree_sweep_declares_the_ci_configuration_it_did_not_scan() {
    let root = tracked();
    write(&root, ".github/workflows/ci.yml", "on: push\n");
    write(&root, ".gitlab-ci.yml", "stages:\n  - build\n");
    let _ = commit(&root, "two CI vendors, one scanner between them");
    let tools = stubs(&[
        ("osv-scanner", &recording("exit 0")),
        ("zizmor", &recording("exit 0")),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains(".gitlab-ci.yml is CI configuration no scanner here reads"),
        "{}",
        text(&output)
    );
    let ran = journal(&root);
    assert!(ran.contains("zizmor"), "{ran}");
    assert!(!ran.contains(".gitlab-ci.yml"), "{ran}");
}

/// A member repository, cloned into the fixture as a real submodule.
fn with_a_submodule(root: &Path) {
    let member = support::scratch("supply-chain-member");
    std::fs::create_dir_all(&member).unwrap();
    git(&member, &["init", "-q", "-b", "main"]);
    git(&member, &["config", "user.name", "Test"]);
    git(&member, &["config", "user.email", "test@example.test"]);
    write(&member, "uv.lock", "version = 1\n");
    commit(&member, "the member's own lock");
    // `protocol.file.allow` because git refuses a local-path submodule by
    // default since CVE-2022-39253, and the fixture is exactly a local path.
    git(
        root,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            &member.display().to_string(),
            "sub",
        ],
    );
    // The submodule in the working tree is a CLONE, and a clone carries none of
    // the source repository's local config. Every other repository this fixture
    // builds is handed an identity at `init`; this one is handed one here,
    // because the tests that commit into it commit into the clone and not into
    // the source. Without it the fixture borrows whoever is configured globally,
    // which is a machine that has somebody -- and CI is a machine that does not.
    let checkout = root.join("sub");
    git(&checkout, &["config", "user.name", "Test"]);
    git(&checkout, &["config", "user.email", "test@example.test"]);
    commit(root, "track the member");
}

/// A bumped submodule pointer is expanded into the member's own diff.
///
/// The superproject's diff shows one changed path, `sub`, and no scanner reads
/// a gitlink. Stopping there is the failure: a member whose lockfile moved
/// arrives in the push with nothing having looked at it, and the run says
/// "nothing in this range" about a dependency change.
#[test]
fn a_bumped_submodule_pointer_expands_into_the_members_own_manifests() {
    let root = tracked();
    with_a_submodule(&root);
    let before = head(&root);
    let member = root.join("sub");
    write(&member, "uv.lock", "version = 1\n# and a dependency more\n");
    commit(&member, "the member's lock moves");
    let after = commit(&root, "bump the pointer");
    let tools = stubs(&[
        ("osv-scanner", &recording("exit 0")),
        ("uv", &recording("echo 'requests==2.0.0'")),
        ("guarddog", &recording(GUARDDOG_CLEAN)),
    ]);
    let output = pushed(&root, &tools, &before, &after);
    assert_eq!(code(&output), 0, "{}", text(&output));
    let ran = journal(&root);
    assert!(ran.contains("guarddog"), "{ran}");
    assert!(ran.contains("sub"), "{ran}");
}

/// A pointer to a commit the member's store lacks widens to every manifest.
///
/// A shallow clone, or a fetch nobody ran, and the member's range cannot be
/// read at all. Narrowing to nothing there would be the same silent pass as
/// reading the gitlink and stopping; widening is what a scan does when it
/// cannot narrow honestly, and the run says which submodule it happened to.
#[test]
fn a_submodule_commit_the_store_does_not_have_widens_to_every_manifest_under_it() {
    let root = tracked();
    with_a_submodule(&root);
    let before = head(&root);
    git(
        &root,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            "160000,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,sub",
        ],
    );
    git(&root, &["commit", "-q", "-m", "a pointer nobody fetched"]);
    let after = head(&root);
    let tools = stubs(&[
        ("osv-scanner", &recording("exit 0")),
        ("uv", &recording("echo 'requests==2.0.0'")),
        ("guarddog", &recording(GUARDDOG_CLEAN)),
    ]);
    let output = pushed(&root, &tools, &before, &after);
    assert_eq!(code(&output), 0, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("does not have"), "{said}");
    assert!(journal(&root).contains("guarddog"), "{}", journal(&root));
}

/// A submodule that is not checked out is exit 2, not a widening.
///
/// There is no tree to widen INTO. Widening would enumerate an empty directory
/// and report a clean scan of manifests that are not on disk, which is the
/// "looked at part of it, reported on all of it" shape this crate exists to
/// refuse; the operator is told which submodule and how to make it readable.
#[test]
fn a_submodule_that_is_not_checked_out_is_refused_rather_than_widened() {
    let root = tracked();
    with_a_submodule(&root);
    let before = head(&root);
    let member = root.join("sub");
    write(&member, "uv.lock", "version = 1\n# and a dependency more\n");
    commit(&member, "the member's lock moves");
    let after = commit(&root, "bump the pointer");
    std::fs::remove_dir_all(&member).unwrap();
    std::fs::create_dir_all(&member).unwrap();
    let tools = stubs(&[("osv-scanner", &recording("exit 0"))]);
    let output = pushed(&root, &tools, &before, &after);
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("not checked out"), "{said}");
    assert!(said.contains("sub"), "{said}");
}

/// guarddog rules that did not run are could-not-look, not a pass.
///
/// guarddog prints "Some rules failed to run while scanning <package>" and
/// exits 0, and the two email-domain rules time out routinely. An orchestrator
/// reading only the exit code files that under clean: the publisher-identity
/// question was asked and nobody answered it, which is the third verdict this
/// command exists for, and the reason names the package and how many rules.
#[test]
fn guarddog_rules_that_did_not_run_are_could_not_look_rather_than_a_clean_scan() {
    let root = repository();
    std::fs::write(root.join("package.json"), "{\"name\": \"fixture\"}\n").unwrap();
    let tools = stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "guarddog",
            "echo 'Some rules failed to run while scanning left-pad:'\n\
             echo '* potentially_compromised_email_domain: failed to run rule \
             potentially_compromised_email_domain: timed out'\n\
             exit 0",
        ),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("left-pad"), "{said}");
    assert!(said.contains("1 rule(s) unrun"), "{said}");
    assert!(!said.contains("all checks passed"), "{said}");
}

/// cargo-vet's finding and cargo-vet's refusal to start share exit 255.
///
/// A dependency carrying no audit and a store that does not parse are the same
/// code, so a section answering by exit code alone files the second under the
/// first. The stream separates them: the finding is on stdout and the refusal
/// is on stderr. This is the finding half, which must stay a verdict.
#[test]
fn cargo_vet_that_found_unvetted_dependencies_is_a_finding_and_exits_one() {
    let root = repository();
    std::fs::create_dir_all(root.join("supply-chain")).unwrap();
    let tools = stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "cargo",
            "case \"$1\" in\n\
             vet) echo 'Vetting Failed!'; echo '11 unvetted dependencies:'; exit 255 ;;\n\
             *) exit 0 ;;\n\
             esac",
        ),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 1, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("Vetting Failed!"), "{said}");
    assert!(!said.contains("could not run"), "{said}");
}

/// The refusal half of the same exit code.
///
/// cargo-vet that could not open its store judged no dependency at all, and
/// that is could-not-look rather than a tree that is out of step. Reading the
/// exit code alone would report this repository as failing an audit nobody
/// ran.
#[test]
fn cargo_vet_that_could_not_open_its_store_is_could_not_look_and_exits_two() {
    let root = repository();
    std::fs::create_dir_all(root.join("supply-chain")).unwrap();
    let tools = stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "cargo",
            "case \"$1\" in\n\
             vet) echo 'ERROR   x Failed to parse toml file' >&2; exit 255 ;;\n\
             *) exit 0 ;;\n\
             esac",
        ),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("nothing here was vetted"), "{said}");
    assert!(!said.contains("all checks passed"), "{said}");
}

/// osv-scanner says could-not-look in its own exit code, and 1 is not it.
///
/// `1` is a vulnerability. `127` is a path it could not resolve, a lockfile it
/// could not parse, a config it could not read or a query it could not send,
/// and reading it as a refusal reports a network outage as a vulnerability in
/// this tree.
#[test]
fn osv_scanner_that_could_not_resolve_its_input_is_could_not_look_not_a_finding() {
    let root = repository();
    let tools = stubs(&[(
        "osv-scanner",
        "echo 'failed to resolve path: no such file or directory' >&2\nexit 127",
    )]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("no lockfile here was checked"), "{said}");
    assert!(!said.contains("all checks passed"), "{said}");
}

/// The control for the case above: exit 1 stays a vulnerability.
#[test]
fn osv_scanner_that_found_a_vulnerability_is_a_finding_and_exits_one() {
    let root = repository();
    let tools = stubs(&[(
        "osv-scanner",
        "echo 'Total 2 packages affected by 64 known vulnerabilities'\nexit 1",
    )]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 1, "{}", text(&output));
    assert!(
        text(&output).contains("64 known vulnerabilities"),
        "{}",
        text(&output)
    );
}

/// zizmor's could-not-look wears exit 0, which is the whole problem.
///
/// Handed one workflow it cannot parse alongside workflows it can, zizmor
/// skips the bad one, audits the rest and exits 0 saying it found nothing. Its
/// SARIF reports executionSuccessful true in exactly that case, so the only
/// witness is the warning on stderr. A section believing the zero calls a
/// workflow nobody read clean.
#[test]
fn zizmor_that_skipped_a_workflow_it_could_not_parse_is_not_a_clean_audit() {
    let root = repository();
    let workflows = root.join(".github/workflows");
    std::fs::create_dir_all(&workflows).unwrap();
    std::fs::write(workflows.join("ci.yml"), "on: push\njobs: {}\n").unwrap();
    let tools = stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "zizmor",
            "echo ' WARN collect_inputs: zizmor::registry::input: failed to parse input: \
             mapping values are not allowed' >&2\n\
             echo 'No findings to report. Good job! (2 suppressed)'\n\
             exit 0",
        ),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("could not parse 1"), "{said}");
    assert!(!said.contains("all checks passed"), "{said}");
}

/// The control: zizmor's severity ladder stays a finding.
///
/// 11 through 14 are the codes it answers when it audited everything and found
/// something, one per severity present. Only the other non-zero codes, and the
/// skipped-input warning above, are could-not-look.
#[test]
fn zizmor_severity_exit_codes_are_findings_rather_than_could_not_look() {
    let root = repository();
    let workflows = root.join(".github/workflows");
    std::fs::create_dir_all(&workflows).unwrap();
    std::fs::write(workflows.join("ci.yml"), "on: push\njobs: {}\n").unwrap();
    let tools = stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "zizmor",
            "echo 'warning[artipacked]: credential persistence'\nexit 14",
        ),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 1, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("artipacked"), "{said}");
    assert!(!said.contains("without auditing anything"), "{said}");
}

/// cargo-deny's exit 1 is an advisory OR a database it could not fetch.
///
/// The code is a bitmask over which check refused, and advisories own the 1,
/// so an advisory database that would not download shares its code with a
/// RUSTSEC match. A run that reached its checks prints the per-check summary
/// on stdout; one that did not leaves stdout empty.
#[test]
fn cargo_deny_that_never_reached_a_check_is_could_not_look_not_an_advisory() {
    let root = repository();
    std::fs::write(root.join("deny.toml"), "[bans]\n").unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"f\"\n").unwrap();
    let tools = stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "cargo",
            "[ \"$1\" = deny ] || exit 0\n\
             echo '[ERROR] failed to fetch advisory database' >&2\n\
             exit 1",
        ),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("reached no check"), "{said}");
    assert!(!said.contains("all checks passed"), "{said}");
}

/// guarddog reports a finding at exit 0, and the finding must survive that.
///
/// `guarddog verify` answers 0 whether it found three high-severity risks or
/// none, so a section reading the exit code called every finding clean. This
/// is the false negative that reading `risks` exists to close, on the one
/// scanner here whose job is malware and typosquats.
#[test]
fn guarddog_that_found_risks_and_exited_zero_is_a_finding_not_a_clean_scan() {
    let root = repository();
    std::fs::create_dir_all(root.join("web")).unwrap();
    std::fs::write(root.join("web/package.json"), "{\"name\": \"web\"}\n").unwrap();
    let tools = stubs(&[("osv-scanner", "exit 0"), ("guarddog", GUARDDOG_RISK)]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 1, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("objected to reqests"), "{said}");
    assert!(!said.contains("all checks passed"), "{said}");
}

/// `issues` is not the finding count, so a clean package stays clean.
///
/// `six` reports `issues: 2` with `risks: []` and guarddog's own label
/// `no_risks_detected`; the two issues are capability matches on an `exec()`.
/// This is why `--exit-non-zero-on-finding`, which counts issues, is not the
/// remedy for the case above: it would fail a package guarddog calls clean.
#[test]
fn guarddog_issues_without_risks_are_not_a_finding() {
    let root = repository();
    std::fs::create_dir_all(root.join("web")).unwrap();
    std::fs::write(root.join("web/package.json"), "{\"name\": \"web\"}\n").unwrap();
    let tools = stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "guarddog",
            "echo '[{\"dependency\":\"six\",\"result\":{\"errors\":{},\"issues\":2,\
             \"results\":{},\"risks\":[]}}]'\nexit 0",
        ),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains("all checks passed"),
        "{}",
        text(&output)
    );
}

/// A dependency guarddog could not download is could-not-look, not clean.
///
/// The 404 and network paths populate `errors` and drop `results`, and still
/// exit 0. Reading the code alone calls a package nobody scanned clean.
#[test]
fn guarddog_that_could_not_scan_a_dependency_is_could_not_look() {
    let root = repository();
    std::fs::create_dir_all(root.join("web")).unwrap();
    std::fs::write(root.join("web/package.json"), "{\"name\": \"web\"}\n").unwrap();
    let tools = stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "guarddog",
            "echo '[{\"dependency\":\"left-pad\",\"result\":{\"errors\":\
             {\"download-package\":\"Received status code: 404 from PyPI\"},\"issues\":0}}]'\nexit 0",
        ),
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("could not scan left-pad"), "{said}");
    assert!(!said.contains("all checks passed"), "{said}");
}
