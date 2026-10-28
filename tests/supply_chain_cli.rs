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

/// What each stubbed scanner answers when asked its version: the floor
/// release, in the shape the real tool prints it.
///
/// Every scanner is asked before it runs, and a stub that answered `--version`
/// with its scan script would be a scanner whose version nobody can read,
/// which is could-not-look. Answered first and not recorded, so the journal
/// holds only the scans.
fn version_answer(name: &str) -> &'static str {
    match name {
        "osv-scanner" => {
            "[ \"$1\" = --version ] && { printf 'osv-scanner version: 2.5.1\\nosv-scalibr \
             version: 0.5.2\\n'; exit 0; }\n"
        }
        "zizmor" => "[ \"$1\" = --version ] && { echo 'zizmor 1.30.0'; exit 0; }\n",
        "cargo" => {
            "[ \"$1 $2\" = 'deny --version' ] && { echo 'cargo-deny 0.20.2'; exit 0; }\n\
             [ \"$1 $2\" = 'vet --version' ] && { echo 'cargo-vet 0.10.2'; exit 0; }\n"
        }
        _ => "",
    }
}

/// A directory of stub scanners, each a script that records and answers, and
/// that answers its version at the floor.
fn stubs(entries: &[(&str, &str)]) -> PathBuf {
    let scripts: Vec<(&str, String)> = entries
        .iter()
        .map(|(name, script)| (*name, format!("{}{script}", version_answer(name))))
        .collect();
    let borrowed: Vec<(&str, &str)> = scripts
        .iter()
        .map(|(name, script)| (*name, script.as_str()))
        .collect();
    raw_stubs(&borrowed)
}

/// The same, with each script answering `--version` however it says, or not
/// at all.
fn raw_stubs(entries: &[(&str, &str)]) -> PathBuf {
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
    // The binary asks git about the fixture's ranges, and a hook's GIT_DIR
    // would answer about the repository running the suite instead.
    support::without_git_environment(&mut command);
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
/// The working directory is half the assertion in the scoped tests: `uv export` is
/// run from the manifest's own directory, and a scan of the right file from the
/// wrong place reads the wrong `package.json`.
fn recording(answer: &str) -> String {
    format!("echo \"$(basename \"$0\") [$PWD] $*\" >> \"$STUB_LOG\"\n{answer}")
}

fn commit(root: &Path, message: &str) -> String {
    support::git(root, &["add", "-A"]);
    support::git(root, &["commit", "-q", "--allow-empty", "-m", message]);
    head(root)
}

fn head(root: &Path) -> String {
    let output = support::git_command(root)
        .args(["rev-parse", "HEAD"])
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
    support::git(&root, &["init", "-q", "-b", "main"]);
    support::git(&root, &["config", "user.name", "Test"]);
    support::git(&root, &["config", "user.email", "test@example.test"]);
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
    let tools = stubs(&[("osv-scanner", "exit 0")]);
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
    std::fs::write(root.join("Cargo.lock"), "version = 4\n").unwrap();
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
    std::fs::write(root.join("Cargo.lock"), "version = 4\n").unwrap();
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

/// A `uv` that is not on PATH is could-not-look, not a clean Python section.
///
/// The run reaches the export. Nothing was read; a pass would say the
/// Python manifests were scanned when uv never ran.
#[test]
fn a_python_lock_with_no_uv_on_path_is_could_not_look_not_a_pass() {
    let root = repository();
    std::fs::write(root.join("uv.lock"), "version = 1\n").unwrap();
    let tools = stubs(&[("osv-scanner", "exit 0")]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("uv is not on PATH"), "{said}");
    assert!(!said.contains("all checks passed"), "{said}");
}

/// An export that fails is a failure of the section, not a skipped manifest.
///
/// `uv export` refusing -- a lock out of date with its `pyproject.toml` is the
/// ordinary cause -- leaves nothing to read. Continuing to the next
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
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 1, "{}", text(&output));
    let said = text(&output);
    assert!(
        said.contains("FAILED: git pins: uv export failed"),
        "{said}"
    );
}

/// A lock out of step with its manifest is exported as it is, and the tree is
/// not written.
///
/// The lock records an `exclude-newer` its `pyproject.toml` lacks, which is how
/// a lock made with the option on the command line reads to `uv lock --check`.
/// Whether the pair agrees is uv's question; the scan reads the pinned
/// set. The `uv` modelled here refuses `--locked` on such a pair, relocks
/// and writes without either flag, and exports the lock as it stands under
/// `--frozen`.
#[test]
fn a_lock_out_of_step_with_its_manifest_is_exported_without_a_write() {
    let root = repository();
    write(
        &root,
        "service/pyproject.toml",
        "[project]\nname = 'service'\n",
    );
    write(
        &root,
        "service/uv.lock",
        "version = 1\n\n[options]\nexclude-newer = \"2026-10-20T01:06:13Z\"\n",
    );
    let uv = recording(
        "for argument do\n\
         [ \"$argument\" = --frozen ] && frozen=yes\n\
         [ \"$argument\" = --locked ] && locked=yes\n\
         done\n\
         [ -n \"$locked\" ] && { echo 'error: the lock file needs to be updated' >&2; exit 2; }\n\
         [ -z \"$frozen\" ] && echo '# relocked' > uv.lock\n\
         echo 'requests==2.0.0'",
    );
    let tools = stubs(&[("osv-scanner", "exit 0"), ("uv", &uv)]);
    let before = tree(&root);
    let output = supply(&root, Some(&tools));
    assert_eq!(tree(&root), before, "the scan wrote into the tree");
    assert_eq!(code(&output), 0, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("1 Python/npm manifest(s) checked"), "{said}");
    assert!(
        journal(&root).contains("export --frozen"),
        "{}",
        journal(&root)
    );
}

/// An npm manifest with registry dependencies alone has no git pin to check,
/// and passes.
///
/// The clean case is asserted here because it is the only place the git pins
/// section's success path and its count are both visible.
#[test]
fn an_npm_manifest_with_no_git_dependency_is_counted_and_a_pass() {
    let root = repository();
    std::fs::create_dir_all(root.join("web")).unwrap();
    std::fs::write(
        root.join("web/package.json"),
        "{\"name\": \"web\", \"dependencies\": {\"cookie\": \"^1.1.1\"}}\n",
    )
    .unwrap();
    let tools = stubs(&[("osv-scanner", "exit 0")]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 0, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("1 Python/npm manifest(s) checked"), "{said}");
    assert!(said.contains("all checks passed"), "{said}");
}

/// A section with work to do and no tool to do it names the tool.
///
/// The section gates on the tree first -- `deny.toml` here -- and the gate's
/// other answer is a pass. Reaching the
/// missing-tool check only after the gate is what keeps "nothing to check" and
/// "nobody checked" apart, and the reader is owed the name of what to install
/// rather than a bare exit 2.
#[test]
fn a_section_with_work_and_no_tool_installed_names_the_tool_and_is_not_a_pass() {
    let root = repository();
    std::fs::write(root.join("deny.toml"), "[bans]\n").unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]\nname = 'fixture'\n").unwrap();
    let tools = stubs(&[("osv-scanner", "exit 0")]);
    let output = supply_without_the_system_path(&root, &tools);
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("cargo is not on PATH"), "{said}");
    assert!(!said.contains("all checks passed"), "{said}");
    assert!(!said.contains("no deny.toml"), "{said}");
}

/// A cargo-deny that finds nothing is clean, and says how many it looked at.
///
/// The count is the only evidence in the output that anything ran: a manifest
/// filter that matched nothing produces the same silent green as a workspace
/// cargo-deny approved, and the two must not read alike. This is the section's
/// success path, which every other cargo-deny test here deliberately fails.
///
/// The member has no lock beside it and is still run on its own, through its
/// workspace's lock: cargo-deny pointed at a root that is also a package roots
/// its graph there, and the member's run is the one rooted at the member.
#[test]
fn a_cargo_deny_that_finds_nothing_is_clean_and_says_how_many_crates_it_read() {
    let root = repository();
    std::fs::write(root.join("deny.toml"), "[bans]\n").unwrap();
    std::fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = ['a']\n").unwrap();
    std::fs::write(root.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::create_dir_all(root.join("a")).unwrap();
    std::fs::write(root.join("a/Cargo.toml"), "[package]\nname = 'a'\n").unwrap();
    let cargo = recording(&format!(
        "[ \"$1\" = metadata ] && {{ printf '%s\\n' '{}'; exit 0; }}\nexit 0",
        metadata_of(&root, &[("a", true)])
    ));
    let tools = stubs(&[("osv-scanner", "exit 0"), ("cargo", &cargo)]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 0, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("2 crate(s) checked"), "{said}");
    assert!(said.contains("all checks passed"), "{said}");
    assert!(!said.contains("no crate to hold to it"), "{said}");
    assert!(!said.contains("checked through"), "{said}");
    let member = root.join("a/Cargo.toml").display().to_string();
    assert!(
        journal(&root)
            .lines()
            .any(|line| line.contains(" deny ") && line.contains(&member)),
        "{}",
        journal(&root)
    );
}

// ── a crate with no lock of its own ──────────────────────────────────
//
// cargo-deny pointed at a crate with no Cargo.lock that cargo would use made
// cargo resolve one and write it into the tree under scan, at versions nobody
// builds. These pin both halves: no file appears, and a crate some lock here
// pins is reported as checked through that lock rather than run alone.

/// What `cargo metadata` of a crate prints, reduced to what the section reads:
/// each package the lock pins with no `source`, by manifest, and which of them
/// are members of the workspace. The crate at the root is always one, and a
/// member of its own workspace.
fn metadata_of(root: &Path, packages: &[(&str, bool)]) -> String {
    let mut listed = vec![("", true)];
    listed.extend_from_slice(packages);
    let id = |directory: &str| format!("path+file://{}", root.join(directory).display());
    serde_json::json!({
        "packages": listed
            .iter()
            .map(|(directory, _)| serde_json::json!({
                "id": id(directory),
                "source": null,
                "manifest_path": root.join(directory).join("Cargo.toml"),
            }))
            .collect::<Vec<_>>(),
        "workspace_members": listed
            .iter()
            .filter(|(_, member)| *member)
            .map(|(directory, _)| id(directory))
            .collect::<Vec<_>>(),
    })
    .to_string()
}

/// A cargo that does what cargo does about a missing lock.
///
/// Handed `--manifest-path` with no Cargo.lock beside it, it writes one -- the
/// defect, modelled -- unless `--locked` is among its arguments, when it
/// refuses on stderr with stdout empty, as cargo does. `metadata` then prints
/// `metadata`, and anything else passes. Every call is recorded.
fn lock_writing_cargo(metadata: &str) -> String {
    recording(&format!(
        "manifest=; locked=; previous=\n\
         for argument do\n\
         [ \"$previous\" = --manifest-path ] && manifest=$argument\n\
         [ \"$argument\" = --locked ] && locked=yes\n\
         previous=$argument\n\
         done\n\
         if [ -n \"$manifest\" ] && [ ! -f \"$(dirname \"$manifest\")/Cargo.lock\" ]; then\n\
         [ -n \"$locked\" ] && {{ echo \"error: cannot create the lock file because --locked \
         was passed to prevent this\" >&2; exit 101; }}\n\
         echo '# resolved afresh' > \"$(dirname \"$manifest\")/Cargo.lock\"\n\
         fi\n\
         [ \"$1\" = metadata ] && {{ printf '%s\\n' '{metadata}'; exit 0; }}\n\
         exit 0"
    ))
}

/// Every file under the fixture and its bytes, less the journal the stubs
/// write there.
fn tree(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let mut found = std::collections::BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if path != root.join("stub.log") {
                found.insert(path.clone(), std::fs::read(&path).unwrap());
            }
        }
    }
    found
}

/// A crate at the root with its lock, and a deny.toml to hold it to.
fn locked_crate(root: &Path) {
    write(root, "deny.toml", "[bans]\n");
    write(root, "Cargo.toml", "[package]\nname = 'app'\n");
    write(root, "Cargo.lock", "version = 4\n");
}

/// The cargo-deny calls in a journal, one line each.
fn deny_runs(root: &Path) -> Vec<String> {
    journal(root)
        .lines()
        .filter(|line| line.contains(" deny ") && !line.contains("--version"))
        .map(String::from)
        .collect()
}

/// A vendored path-dependency crate without its own lockfile is checked
/// through the lock that pins it, and the sweep writes nothing.
///
/// Run alone, cargo resolved the crate afresh and wrote a Cargo.lock beside
/// it: an untracked file after every sweep, and a verdict on versions the
/// build never uses. The versions that ship are the parent's, so the parent's
/// run is the check, and the line names it.
#[test]
fn a_path_dependency_without_its_own_lock_is_checked_through_the_lock_that_pins_it() {
    let root = repository();
    locked_crate(&root);
    write(
        &root,
        "third_party/vendored/Cargo.toml",
        "[package]\nname = 'vendored'\n",
    );
    let cargo = lock_writing_cargo(&metadata_of(&root, &[("third_party/vendored", false)]));
    let tools = stubs(&[("osv-scanner", "exit 0"), ("cargo", &cargo)]);
    let before = tree(&root);
    let output = supply(&root, Some(&tools));
    assert_eq!(tree(&root), before, "the sweep wrote into the tree");
    assert_eq!(code(&output), 0, "{}", text(&output));
    let said = text(&output);
    assert!(
        said.contains(&format!(
            "{}: checked through {}",
            root.join("third_party/vendored/Cargo.toml").display(),
            root.join("Cargo.toml").display()
        )),
        "{said}"
    );
    assert!(said.contains("2 crate(s) checked"), "{said}");
    let runs = deny_runs(&root);
    assert_eq!(runs.len(), 1, "{runs:?}");
    assert!(runs.iter().all(|run| !run.contains("vendored")), "{runs:?}");
    // Every cargo call that could resolve is asked not to write.
    let ran = journal(&root);
    assert!(
        ran.lines()
            .filter(|line| line.contains(" deny ") || line.contains(" metadata "))
            .filter(|line| !line.contains("--version"))
            .all(|line| line.contains("--locked")),
        "{ran}"
    );
}

/// A crate with no lock that no lock here pins is not checked, and no lock is
/// written for it.
///
/// There is no set of versions anybody builds for it, so there is nothing to
/// hold to deny.toml: a resolution made for the scan would be judged in place
/// of one that does not exist. That is could-not-look, exit 2, never a pass --
/// and the crate beside it that has a lock is still checked.
#[test]
fn a_crate_without_a_lock_that_nothing_pins_is_not_checked_and_no_file_appears() {
    let root = repository();
    locked_crate(&root);
    write(
        &root,
        "standalone/Cargo.toml",
        "[package]\nname = 'standalone'\n",
    );
    let cargo = lock_writing_cargo(&metadata_of(&root, &[]));
    let tools = stubs(&[("osv-scanner", "exit 0"), ("cargo", &cargo)]);
    let before = tree(&root);
    let output = supply(&root, Some(&tools));
    assert_eq!(tree(&root), before, "the sweep wrote into the tree");
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(
        said.contains(&format!(
            "NOT CHECKED: {}: no Cargo.lock: cargo-deny would resolve versions nobody builds",
            root.join("standalone/Cargo.toml").display()
        )),
        "{said}"
    );
    assert!(said.contains("1 crate(s) checked"), "{said}");
    assert!(!said.contains("checked through"), "{said}");
    let runs = deny_runs(&root);
    assert_eq!(runs.len(), 1, "{runs:?}");
    assert!(
        runs.iter().all(|run| !run.contains("standalone")),
        "{runs:?}"
    );
}

/// A lone crate with no lock anywhere is not checked, and cargo is never
/// pointed at it.
///
/// With no lock in the tree there is nobody to ask, so `cargo metadata` is not
/// run either, and the section is could-not-look rather than the "no crate to
/// hold to it" a tree without crates gets.
#[test]
fn a_lone_crate_with_no_lock_is_not_checked_and_cargo_resolves_nothing() {
    let root = repository();
    write(&root, "deny.toml", "[bans]\n");
    write(&root, "Cargo.toml", "[package]\nname = 'app'\n");
    let cargo = lock_writing_cargo("{}");
    let tools = stubs(&[("osv-scanner", "exit 0"), ("cargo", &cargo)]);
    let before = tree(&root);
    let output = supply(&root, Some(&tools));
    assert_eq!(tree(&root), before, "the sweep wrote into the tree");
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("no Cargo.lock: cargo-deny"), "{said}");
    assert!(said.contains("0 crate(s) checked"), "{said}");
    assert!(!said.contains("no crate to hold to it"), "{said}");
    let ran = journal(&root);
    assert!(!ran.contains(" metadata "), "{ran}");
    assert!(deny_runs(&root).is_empty(), "{ran}");
}

/// A lock that could not be asked is named, never read as pinning nothing.
///
/// "No lock here pins it" said because `cargo metadata` failed would be a
/// claim made on a question nobody answered, so the reason carries what cargo
/// said about the lock it could not read.
#[test]
fn a_lock_that_could_not_be_asked_is_named_in_the_reason() {
    let root = repository();
    locked_crate(&root);
    write(
        &root,
        "third_party/vendored/Cargo.toml",
        "[package]\nname = 'vendored'\n",
    );
    let cargo = recording(
        "[ \"$1\" = metadata ] && { echo 'error: failed to parse lock file at: Cargo.lock' >&2; \
         exit 101; }\nexit 0",
    );
    let tools = stubs(&[("osv-scanner", "exit 0"), ("cargo", &cargo)]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 2, "{}", text(&output));
    let said = text(&output);
    assert!(
        said.contains("a lock that may pin it could not be read"),
        "{said}"
    );
    assert!(said.contains("failed to parse lock file"), "{said}");
}

/// A refusal elsewhere outranks could-not-look, and the unchecked crate is
/// still named.
///
/// The section answers one verdict and a finding is the higher one, so the
/// crate nobody looked at would vanish from the output under it. It is printed
/// beside the refusal instead.
#[test]
fn an_unchecked_crate_beside_a_refusal_is_named_and_the_run_is_a_failure() {
    let root = repository();
    locked_crate(&root);
    write(
        &root,
        "standalone/Cargo.toml",
        "[package]\nname = 'standalone'\n",
    );
    let cargo = recording(&format!(
        "[ \"$1\" = metadata ] && {{ printf '%s\\n' '{}'; exit 0; }}\n\
         echo 'error[vulnerability]: RUSTSEC-0000-0001 in left-pad'\nexit 1",
        metadata_of(&root, &[])
    ));
    let tools = stubs(&[("osv-scanner", "exit 0"), ("cargo", &cargo)]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 1, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("RUSTSEC-0000-0001"), "{said}");
    assert!(
        said.contains(&format!(
            "NOT CHECKED: {}: no Cargo.lock",
            root.join("standalone/Cargo.toml").display()
        )),
        "{said}"
    );
}

/// A range that moves only a path dependency runs the crate whose lock pins
/// it.
///
/// The parent did not move, and a scan narrowed to what moved would not run
/// it -- but the dependency's manifest is part of what the parent resolves, so
/// "checked through" is only true if the parent is run.
#[test]
fn a_range_moving_only_a_path_dependency_runs_the_crate_that_pins_it() {
    let root = tracked();
    locked_crate(&root);
    write(
        &root,
        "third_party/vendored/Cargo.toml",
        "[package]\nname = 'vendored'\n",
    );
    let before = commit(&root, "a crate and the path dependency it vendors");
    write(
        &root,
        "third_party/vendored/Cargo.toml",
        "[package]\nname = 'vendored'\n\n[dependencies]\nleft-pad = '1'\n",
    );
    let after = commit(&root, "the vendored crate gains a dependency");
    let cargo = lock_writing_cargo(&metadata_of(&root, &[("third_party/vendored", false)]));
    let tools = stubs(&[("osv-scanner", "exit 0"), ("cargo", &cargo)]);
    let output = pushed(&root, &tools, &before, &after);
    assert_eq!(code(&output), 0, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("checked through"), "{said}");
    let runs = deny_runs(&root);
    let parent = format!("--manifest-path {}", root.join("Cargo.toml").display());
    assert!(runs.iter().any(|run| run.contains(&parent)), "{runs:?}");
    assert!(runs.iter().all(|run| !run.contains("vendored")), "{runs:?}");
    let status = support::git_command(&root)
        .args(["status", "--porcelain", "--untracked-files=all"])
        .output()
        .unwrap();
    let status = String::from_utf8_lossy(&status.stdout);
    assert!(
        status.lines().all(|line| line.ends_with("stub.log")),
        "{status}"
    );
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
    // And the two hook ids, because the usual way here is the range id pinned
    // at a stage with no push: the refusal names where it belongs and what the
    // sweep is called.
    assert!(
        said.contains("`uphold-supply-chain` belongs at pre-push"),
        "{said}"
    );
    assert!(said.contains("`uphold-supply-chain-all`"), "{said}");
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
    ]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 0, "{}", text(&output));
    let ran = journal(&root);
    assert!(ran.contains("osv-scanner"), "{ran}");
    assert!(ran.contains("zizmor"), "{ran}");
    assert!(ran.contains("export --frozen"), "{ran}");
}

/// A changed Python lock is scanned where it lives, and nowhere else.
///
/// The second manifest is the assertion. A scoped run that still walked to
/// every `uv.lock` in the tree would have narrowed nothing.
#[test]
fn a_changed_python_lock_is_exported_in_that_directory_and_not_the_others() {
    let root = tracked();
    write(&root, "other/uv.lock", "version = 1\n");
    let _ = commit(&root, "a lock this push does not touch");
    let before = head(&root);
    write(&root, "harness/uv.lock", "version = 1\n");
    let after = commit(&root, "the lock this push does touch");
    let tools = stubs(&[
        ("osv-scanner", &recording("exit 0")),
        ("uv", &recording("echo 'requests==2.0.0'")),
    ]);
    let output = pushed(&root, &tools, &before, &after);
    assert_eq!(code(&output), 0, "{}", text(&output));
    let ran = journal(&root);
    assert!(ran.contains("export --frozen"), "{ran}");
    assert!(ran.contains("harness"), "{ran}");
    assert!(!ran.contains("other"), "{ran}");
    // The lock is handed to osv-scanner by path, not scanned for by a walk.
    assert!(ran.contains("-L"), "{ran}");
    // And read as it is, never rewritten.
    assert!(ran.contains("export --frozen"), "{ran}");
    assert!(
        text(&output).contains("1 lockfile(s) in this range"),
        "{}",
        text(&output)
    );
}

/// A moved `pyproject.toml` with no `uv.lock` beside it is not exported, and
/// no lock is written.
///
/// `uv export` in such a directory resolves the project and writes a
/// `uv.lock` into the tree under scan. The whole-tree walk never reaches the
/// directory, because it looks for locks; the range leaves it out the same
/// way, and says so rather than reading as nothing having moved.
#[test]
fn a_moved_pyproject_with_no_uv_lock_is_not_exported_and_no_lock_is_written() {
    let root = tracked();
    let before = head(&root);
    write(
        &root,
        "tooling/pyproject.toml",
        "[project]\nname = 'tooling'\n",
    );
    let after = commit(&root, "a project with no lock");
    let tools = stubs(&[
        ("osv-scanner", &recording("exit 0")),
        (
            "uv",
            &recording("echo '# resolved afresh' > uv.lock\necho 'requests==2.0.0'"),
        ),
    ]);
    let output = pushed(&root, &tools, &before, &after);
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(!root.join("tooling/uv.lock").exists());
    let said = text(&output);
    assert!(
        said.contains(&format!(
            "{}: no uv.lock beside it",
            root.join("tooling/pyproject.toml").display()
        )),
        "{said}"
    );
    let ran = journal(&root);
    assert!(!ran.lines().any(|line| line.starts_with("uv ")), "{ran}");
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
    support::submodule(root, "sub", &[("uv.lock", "version = 1\n")]);
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
    ]);
    let output = pushed(&root, &tools, &before, &after);
    assert_eq!(code(&output), 0, "{}", text(&output));
    let ran = journal(&root);
    assert!(ran.contains("export --frozen"), "{ran}");
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
    support::git(
        &root,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            "160000,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,sub",
        ],
    );
    support::git(&root, &["commit", "-q", "-m", "a pointer nobody fetched"]);
    let after = head(&root);
    let tools = stubs(&[
        ("osv-scanner", &recording("exit 0")),
        ("uv", &recording("echo 'requests==2.0.0'")),
    ]);
    let output = pushed(&root, &tools, &before, &after);
    assert_eq!(code(&output), 0, "{}", text(&output));
    let said = text(&output);
    assert!(said.contains("does not have"), "{said}");
    assert!(
        journal(&root).contains("export --frozen"),
        "{}",
        journal(&root)
    );
}

/// A push from a linked worktree reads the member's range in the member.
///
/// git exports `GIT_DIR` to a hook when the push comes from a linked worktree,
/// and not when it comes from the main checkout. Inherited by the git calls made
/// INSIDE the submodule, it sent them to the superproject's object store, which
/// has neither of the member's commits: every bumped submodule read as "moved
/// to a commit its object store does not have" and was scanned whole, and a
/// push that touched one lockfile was refused over findings in files nobody
/// changed. Driven through a real linked worktree, with the `GIT_DIR` git would
/// hand the hook, and the member's untouched lock is the assertion that the
/// range was read rather than widened.
#[test]
fn a_push_from_a_linked_worktree_reads_the_members_range_in_the_member() {
    let root = tracked();
    with_a_submodule(&root);
    let before = head(&root);
    let member = root.join("sub");
    write(&member, "harness/uv.lock", "version = 1\n");
    commit(&member, "a second lock in the member");
    let after = commit(&root, "bump the pointer");

    let linked = support::scratch("supply-chain-linked");
    support::git(
        &root,
        &[
            "worktree",
            "add",
            "-q",
            "--detach",
            &linked.display().to_string(),
            &after,
        ],
    );
    // The member's new commit exists only in the main checkout's clone of it,
    // so that clone is where the linked worktree's own clone is made from.
    support::git(
        &linked,
        &["config", "submodule.sub.url", &member.display().to_string()],
    );
    support::git(
        &linked,
        &[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "update",
            "--init",
            "-q",
        ],
    );
    let git_dir = support::git_command(&linked)
        .args(["rev-parse", "--absolute-git-dir"])
        .output()
        .unwrap();
    let git_dir = String::from_utf8_lossy(&git_dir.stdout).trim().to_owned();
    assert!(git_dir.contains("worktrees"), "{git_dir}");

    let tools = stubs(&[
        ("osv-scanner", &recording("exit 0")),
        ("uv", &recording("echo 'requests==2.0.0'")),
    ]);
    let mut path = tools.as_os_str().to_owned();
    path.push(":/usr/bin:/bin");
    let output = invoke(
        &linked,
        &path,
        &[],
        &[
            ("PRE_COMMIT_FROM_REF", &before),
            ("PRE_COMMIT_TO_REF", &after),
            ("GIT_DIR", &git_dir),
        ],
    );
    assert_eq!(code(&output), 0, "{}", text(&output));
    let said = text(&output);
    assert!(!said.contains("does not have"), "{said}");
    assert!(said.contains("1 lockfile(s) in this range"), "{said}");
    let ran = journal(&linked);
    assert!(ran.contains("sub/harness]"), "{ran}");
    assert!(!ran.contains("sub]"), "{ran}");
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

/// A submodule folded into the superproject is files, not a moved pointer.
///
/// The gitlink is deleted and the member's tree is tracked at the same path,
/// which is how a repository is merged into its superproject with its history.
/// The pointer then points at nothing, so there is no member checkout to read
/// and none was asked for -- the push was refused for one, naming a
/// submodule that no longer exists. What stands at the path now is the
/// superproject's own files, and the lockfile among them is what gets scanned.
#[test]
fn a_submodule_replaced_by_its_own_files_is_scanned_as_files() {
    let root = tracked();
    with_a_submodule(&root);
    let before = head(&root);
    support::git(&root, &["rm", "-q", "--cached", "sub"]);
    support::git(&root, &["rm", "-q", "-f", ".gitmodules"]);
    std::fs::remove_dir_all(root.join("sub")).unwrap();
    write(
        &root,
        "sub/uv.lock",
        "version = 1\n# now the superproject's own\n",
    );
    let after = commit(&root, "fold the member in");
    let tools = stubs(&[
        ("osv-scanner", &recording("exit 0")),
        ("uv", &recording("echo 'requests==2.0.0'")),
    ]);
    let output = pushed(&root, &tools, &before, &after);
    assert_eq!(code(&output), 0, "{}", text(&output));
    let said = text(&output);
    assert!(!said.contains("not checked out"), "{said}");
    assert!(said.contains("1 lockfile(s) in this range"), "{said}");
}

/// A submodule removed outright leaves nothing in the range to read.
///
/// The pointer is gone and nothing replaces it, so the range adds no manifest.
/// Demanding a checkout of the removed member would refuse every push that
/// drops a dependency, which is the push least likely to add a risk.
#[test]
fn a_removed_submodule_needs_no_checkout() {
    let root = tracked();
    with_a_submodule(&root);
    let before = head(&root);
    support::git(&root, &["rm", "-q", "-f", "sub"]);
    let after = commit(&root, "drop the member");
    let tools = stubs(&[("osv-scanner", &recording("exit 0"))]);
    let output = pushed(&root, &tools, &before, &after);
    assert_eq!(code(&output), 0, "{}", text(&output));
    let said = text(&output);
    assert!(!said.contains("not checked out"), "{said}");
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
    std::fs::write(root.join("Cargo.lock"), "version = 4\n").unwrap();
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

// ── version floors ───────────────────────────────────────────────────────

/// A scanner older than the release its reader was measured against is exit 2
/// and is never run.
///
/// The readers match the text a scanner prints when it did not look; an older
/// release printing something else would fall through to whichever verdict the
/// unmatched text reaches. The reason names the tool, the version found and the
/// floor, and the scan itself is not in the journal.
#[test]
fn a_scanner_below_its_floor_is_could_not_look_and_is_never_run() {
    let root = repository();
    std::fs::create_dir_all(root.join(".github/workflows")).unwrap();
    std::fs::write(root.join(".github/workflows/ci.yml"), "on: push\n").unwrap();
    let tools = raw_stubs(&[
        (
            "osv-scanner",
            &format!("{}{}", version_answer("osv-scanner"), recording("exit 0")),
        ),
        (
            "zizmor",
            &format!(
                "[ \"$1\" = --version ] && {{ echo 'zizmor 1.29.0'; exit 0; }}\n{}",
                recording("exit 0")
            ),
        ),
    ]);
    let output = supply(&root, Some(&tools));
    let said = text(&output);
    assert_eq!(code(&output), 2, "{said}");
    assert!(
        said.contains("zizmor 1.29.0 is older than 1.30.0"),
        "{said}"
    );
    assert!(said.contains("NOT CHECKED"), "{said}");
    assert!(!said.contains("   FAILED"), "{said}");
    // osv-scanner, at its floor, ran; zizmor, below it, did not.
    let journal = journal(&root);
    assert!(journal.contains("osv-scanner"), "{journal}");
    assert!(!journal.contains("zizmor"), "{journal}");
}

/// A version answer nobody can read, or a version command that fails, is not a
/// pass either.
#[test]
fn a_scanner_whose_version_cannot_be_read_is_could_not_look() {
    let root = repository();
    let tools = raw_stubs(&[("osv-scanner", "echo 'osv-scanner (devel)'\nexit 0")]);
    let output = supply(&root, Some(&tools));
    let said = text(&output);
    assert_eq!(code(&output), 2, "{said}");
    assert!(
        said.contains("`osv-scanner --version` printed no version this could read"),
        "{said}"
    );
    assert!(!said.contains("all checks passed"), "{said}");
}

/// cargo on PATH and no cargo-deny: `cargo deny --version` is cargo's "no such
/// command", and that is could-not-look before any manifest is handed over.
#[test]
fn a_version_command_that_fails_is_could_not_look_and_no_manifest_is_handed_over() {
    let root = repository();
    std::fs::write(root.join("deny.toml"), "[bans]\n").unwrap();
    std::fs::write(root.join("Cargo.toml"), "[package]\nname = 'fixture'\n").unwrap();
    let tools = raw_stubs(&[
        (
            "osv-scanner",
            &format!("{}exit 0", version_answer("osv-scanner")),
        ),
        (
            "cargo",
            &format!(
                "echo 'error: no such command: `deny`' >&2\n{}",
                recording("exit 101")
            ),
        ),
    ]);
    let output = supply(&root, Some(&tools));
    let said = text(&output);
    assert_eq!(code(&output), 2, "{said}");
    assert!(
        said.contains("`cargo deny --version` did not answer (is cargo-deny installed?)"),
        "{said}"
    );
    assert!(said.contains("no such command"), "{said}");
    assert!(!said.contains("FAILED"), "{said}");
    // Asked its version once, and handed no manifest.
    let journal = journal(&root);
    assert_eq!(journal.lines().count(), 1, "{journal}");
    assert!(journal.contains("deny --version"), "{journal}");
}

// ── gitleaks ─────────────────────────────────────────────────────────────

/// The gitleaks release the binary pins. Stated here as well as in
/// `src/supply.rs` on purpose: a bump that forgets this file fails the tests
/// below, which is the moment someone should read what the bump changes.
const GITLEAKS_PINNED: &str = "8.30.1";

/// A policy that inherits the set which asks for gitleaks.
const WITH_CREDENTIALS: &str = "[inherit]\nsets = [\"credentials\"]\n";

/// A stub gitleaks answering `version` with `version`, recording every other
/// run, copying the file its `--config` names beside the log, and then
/// answering `then`. Builtins only: some tests give it no `/usr/bin`.
fn gitleaks_stub(version: &str, then: &str) -> String {
    format!(
        "if [ \"$1\" = version ]; then echo '{version}'; exit 0; fi\n\
         echo \"gitleaks $*\" >> \"$STUB_LOG\"\n\
         while [ $# -gt 0 ]; do\n\
           if [ \"$1\" = --config ]; then\n\
             while IFS= read -r line; do echo \"$line\"; done < \"$2\" > \"$STUB_LOG.config\"\n\
           fi\n\
           shift\n\
         done\n\
         {then}"
    )
}

fn inheriting_credentials() -> PathBuf {
    let root = repository();
    std::fs::write(root.join("policy/principles.toml"), WITH_CREDENTIALS).unwrap();
    root
}

/// The two scanners that answer over an empty tree, clean, beside gitleaks.
fn quiet_neighbours(gitleaks: &str) -> PathBuf {
    stubs(&[("osv-scanner", "exit 0"), ("gitleaks", gitleaks)])
}

#[test]
fn a_policy_inheriting_credentials_with_no_gitleaks_installed_is_exit_2() {
    let root = inheriting_credentials();
    let tools = stubs(&[("osv-scanner", "exit 0")]);
    let output = supply_without_the_system_path(&root, &tools);
    let said = text(&output);
    assert_eq!(code(&output), 2, "{said}");
    assert!(said.contains("gitleaks is not on PATH"), "{said}");
    assert!(!said.contains("all checks passed"), "{said}");
}

#[test]
fn a_gitleaks_at_another_version_is_exit_2_and_scans_nothing() {
    for version in ["8.29.0", "v8.30.2", "version is set by build process"] {
        let root = inheriting_credentials();
        let tools = quiet_neighbours(&gitleaks_stub(version, "exit 0"));
        let output = supply_without_the_system_path(&root, &tools);
        let said = text(&output);
        assert_eq!(code(&output), 2, "{version}: {said}");
        assert!(
            said.contains(&format!("pinned to {GITLEAKS_PINNED}")),
            "{said}"
        );
        assert!(journal(&root).is_empty(), "{}", journal(&root));
    }
}

#[test]
fn all_scans_every_commit_with_the_bundled_config_and_a_finding_code_of_its_own() {
    let root = inheriting_credentials();
    let tools = quiet_neighbours(&gitleaks_stub(&format!("v{GITLEAKS_PINNED}"), "exit 0"));
    let output = supply_without_the_system_path(&root, &tools);
    let said = text(&output);
    assert_eq!(code(&output), 0, "{said}");
    assert!(said.contains("every commit"), "{said}");
    let ran = journal(&root);
    assert!(ran.starts_with("gitleaks git "), "{ran}");
    assert!(ran.contains("--exit-code=3"), "{ran}");
    assert!(ran.contains("--redact"), "{ran}");
    // gitleaks' own default, `--full-history --all`, with git notes left out.
    assert!(
        ran.contains("--log-opts=--full-history --exclude=refs/notes/* --all"),
        "{ran}"
    );
    let config = std::fs::read_to_string(root.join("stub.log.config")).unwrap();
    assert!(config.contains("useDefault = true"), "{config}");
    assert!(config.contains("_test"), "{config}");
}

#[test]
fn the_repositorys_own_gitleaks_toml_is_handed_over_in_place_of_the_default() {
    let root = inheriting_credentials();
    std::fs::write(
        root.join(".gitleaks.toml"),
        "# the repository's own\n[extend]\nuseDefault = true\n",
    )
    .unwrap();
    let tools = quiet_neighbours(&gitleaks_stub(GITLEAKS_PINNED, "exit 0"));
    let output = supply_without_the_system_path(&root, &tools);
    assert_eq!(code(&output), 0, "{}", text(&output));
    let config = std::fs::read_to_string(root.join("stub.log.config")).unwrap();
    assert!(config.contains("the repository's own"), "{config}");
}

#[test]
fn a_gitleaks_finding_is_exit_1_and_its_words_are_shown() {
    let root = inheriting_credentials();
    let tools = quiet_neighbours(&gitleaks_stub(
        GITLEAKS_PINNED,
        "echo 'RuleID: github-pat'\nexit 3",
    ));
    let output = supply_without_the_system_path(&root, &tools);
    let said = text(&output);
    assert_eq!(code(&output), 1, "{said}");
    assert!(said.contains("RuleID: github-pat"), "{said}");
    assert!(said.contains(".gitleaksignore"), "{said}");
}

/// gitleaks answers 1 for a partial scan as well as for findings, which is
/// why the findings are moved to another code: 1 is left meaning "did not
/// finish".
#[test]
fn gitleaks_own_exit_1_is_a_scan_that_did_not_finish() {
    let root = inheriting_credentials();
    let tools = quiet_neighbours(&gitleaks_stub(
        GITLEAKS_PINNED,
        "echo 'partial scan completed' >&2\nexit 1",
    ));
    let output = supply_without_the_system_path(&root, &tools);
    let said = text(&output);
    assert_eq!(code(&output), 2, "{said}");
    assert!(said.contains("NOT CHECKED: gitleaks exited 1"), "{said}");
}

#[test]
fn a_policy_that_does_not_inherit_credentials_never_asks_gitleaks() {
    let root = repository();
    let tools = quiet_neighbours(&gitleaks_stub(GITLEAKS_PINNED, "exit 3"));
    let output = supply_without_the_system_path(&root, &tools);
    let said = text(&output);
    assert_eq!(code(&output), 0, "{said}");
    assert!(
        said.contains("does not inherit the `credentials` set"),
        "{said}"
    );
    assert!(journal(&root).is_empty(), "{}", journal(&root));
}

/// A push that changes no manifest still carries commits, and gitleaks reads
/// commits: it runs alone, over exactly the pushed range.
#[test]
fn a_range_touching_no_manifest_still_runs_gitleaks_over_that_range() {
    let root = tracked();
    std::fs::write(root.join("policy/principles.toml"), WITH_CREDENTIALS).unwrap();
    let before = commit(&root, "inherit credentials");
    write(&root, "src/main.rs", "fn main() {}\n");
    let after = commit(&root, "source only");
    let tools = stubs(&[
        ("osv-scanner", &recording("exit 0")),
        ("gitleaks", &gitleaks_stub(GITLEAKS_PINNED, "exit 0")),
    ]);
    let output = pushed(&root, &tools, &before, &after);
    let said = text(&output);
    assert_eq!(code(&output), 0, "{said}");
    assert!(
        said.contains("only gitleaks has anything to read"),
        "{said}"
    );
    let ran = journal(&root);
    assert!(
        ran.contains(&format!("--log-opts={before}..{after}")),
        "{ran}"
    );
    assert!(!ran.contains("osv-scanner"), "{ran}");
}

/// A push of git notes: the commits a tool's notes ref carries, here a gate
/// record. Run as prek exports it, the ref named and its sha given.
fn notes_pushed(root: &Path, tools: &Path, from: Option<&str>, to: &str) -> Output {
    let mut path = tools.as_os_str().to_owned();
    path.push(":/usr/bin:/bin");
    let mut push = vec![
        ("PRE_COMMIT_LOCAL_BRANCH", "refs/notes/gate"),
        ("PRE_COMMIT_REMOTE_BRANCH", "refs/notes/gate"),
        ("PRE_COMMIT_TO_REF", to),
    ];
    if let Some(from) = from {
        push.push(("PRE_COMMIT_FROM_REF", from));
    }
    invoke(root, &path, &[], &push)
}

/// A notes ref holds no manifest, and its first push names the all-zero sha,
/// which would widen to every commit: one gate record refusing the push that
/// publishes it. It is left out, and the run says so.
#[test]
fn a_push_of_git_notes_is_a_declared_gap_and_widens_to_nothing() {
    let root = tracked();
    std::fs::write(root.join("policy/principles.toml"), WITH_CREDENTIALS).unwrap();
    // Two records, so the second push has a remote sha that is a notes commit.
    let record = |message: &str| {
        let gated = commit(&root, message);
        support::git(
            &root,
            &[
                "notes",
                "--ref=gate",
                "add",
                "-m",
                "{\"cacheKey\": \"0123\"}",
                &gated,
            ],
        );
        let output = support::git_command(&root)
            .args(["rev-parse", "refs/notes/gate"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    };
    let first = record("inherit credentials");
    let notes = record("a second gated commit");
    for from in [None, Some(first.as_str())] {
        let _ = std::fs::remove_file(root.join("stub.log"));
        let tools = stubs(&[
            ("osv-scanner", &recording("exit 0")),
            ("gitleaks", &gitleaks_stub(GITLEAKS_PINNED, "exit 3")),
        ]);
        let output = notes_pushed(&root, &tools, from, &notes);
        let said = text(&output);
        assert_eq!(code(&output), 0, "{from:?}: {said}");
        assert!(
            said.contains("refs/notes/gate is git notes, which no scanner here reads"),
            "{said}"
        );
        assert!(!said.contains("every manifest and every commit"), "{said}");
        assert!(journal(&root).is_empty(), "{}", journal(&root));
    }
}

// ── gitleaks over the staged diff ────────────────────────────────────────

/// `--staged`, with the stub directory as the whole of `PATH` so a scanner
/// run by mistake is a missing one and says so.
fn staged(root: &Path, tools: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["--staged"];
    args.extend_from_slice(extra);
    invoke(root, tools.as_os_str(), &args, &[])
}

/// Every stub a range scan would reach, so the assertion that none of the
/// five dependency scanners ran is about the command and not about PATH.
fn every_scanner(gitleaks: &str) -> PathBuf {
    stubs(&[
        ("osv-scanner", &recording("exit 0")),
        ("zizmor", &recording("exit 0")),
        ("cargo", &recording("exit 0")),
        ("gitleaks", gitleaks),
    ])
}

#[test]
fn staged_runs_gitleaks_alone_over_the_index_with_the_bundled_config() {
    let root = inheriting_credentials();
    let tools = every_scanner(&gitleaks_stub(GITLEAKS_PINNED, "exit 0"));
    let output = staged(&root, &tools, &[]);
    let said = text(&output);
    assert_eq!(code(&output), 0, "{said}");
    assert!(said.contains("the staged diff"), "{said}");
    let ran = journal(&root);
    assert!(ran.starts_with("gitleaks git "), "{ran}");
    assert!(ran.contains(" --staged"), "{ran}");
    assert!(ran.contains("--exit-code=3"), "{ran}");
    assert!(ran.contains("--redact"), "{ran}");
    assert!(!ran.contains("--log-opts"), "{ran}");
    assert_eq!(ran.lines().count(), 1, "one scanner, once: {ran}");
    let config = std::fs::read_to_string(root.join("stub.log.config")).unwrap();
    assert!(config.contains("useDefault = true"), "{config}");
}

#[test]
fn a_staged_finding_is_exit_1_and_its_words_are_shown() {
    let root = inheriting_credentials();
    let tools = every_scanner(&gitleaks_stub(
        GITLEAKS_PINNED,
        "echo 'Fingerprint: leak.rs:github-pat:1'\nexit 3",
    ));
    let output = staged(&root, &tools, &[]);
    let said = text(&output);
    assert_eq!(code(&output), 1, "{said}");
    assert!(said.contains("leak.rs:github-pat:1"), "{said}");
    assert!(said.contains(".gitleaksignore"), "{said}");
    assert!(!said.contains("passed"), "{said}");
}

/// The commit path is where a missing scanner would be most tempting to
/// pass: it is exit 2, as at the push.
#[test]
fn staged_with_no_gitleaks_installed_is_exit_2() {
    let root = inheriting_credentials();
    let tools = stubs(&[("osv-scanner", &recording("exit 0"))]);
    let output = staged(&root, &tools, &[]);
    let said = text(&output);
    assert_eq!(code(&output), 2, "{said}");
    assert!(said.contains("gitleaks is not on PATH"), "{said}");
    assert!(!said.contains("passed"), "{said}");
    assert!(journal(&root).is_empty(), "{}", journal(&root));
}

#[test]
fn staged_with_a_gitleaks_at_another_version_is_exit_2_and_scans_nothing() {
    let root = inheriting_credentials();
    let tools = every_scanner(&gitleaks_stub("8.29.0", "exit 0"));
    let output = staged(&root, &tools, &[]);
    let said = text(&output);
    assert_eq!(code(&output), 2, "{said}");
    assert!(
        said.contains(&format!("pinned to {GITLEAKS_PINNED}")),
        "{said}"
    );
    assert!(journal(&root).is_empty(), "{}", journal(&root));
}

#[test]
fn staged_exit_1_from_gitleaks_is_a_scan_that_did_not_finish() {
    let root = inheriting_credentials();
    let tools = every_scanner(&gitleaks_stub(
        GITLEAKS_PINNED,
        "echo 'partial scan completed' >&2\nexit 1",
    ));
    let output = staged(&root, &tools, &[]);
    let said = text(&output);
    assert_eq!(code(&output), 2, "{said}");
    assert!(said.contains("NOT CHECKED: gitleaks exited 1"), "{said}");
}

/// What gitleaks 8.30.1 does with a git that wrote to stderr, measured: logs
/// the line at `ERR`, scans nothing, says `no leaks found`, and exits 0.
const GITLEAKS_BLINDED: &str = "echo '9:52PM ERR [git] warning: something' >&2\n\
     echo '9:52PM ERR error=\"stderr is not empty\"' >&2\n\
     echo '9:52PM INF no leaks found' >&2\n\
     exit 0";

#[test]
fn staged_exit_0_from_a_gitleaks_that_logged_an_error_is_not_a_pass() {
    let root = inheriting_credentials();
    let tools = every_scanner(&gitleaks_stub(GITLEAKS_PINNED, GITLEAKS_BLINDED));
    let output = staged(&root, &tools, &[]);
    let said = text(&output);
    assert_eq!(code(&output), 2, "{said}");
    assert!(said.contains("stderr is not empty"), "{said}");
    assert!(!said.contains("staged diff passed"), "{said}");
}

/// The two halves of #410 together: a token staged, uphold linked in front of
/// git as an install puts it with a `[[shim]]` for git declared, and a gitleaks
/// that reads the index through the argv the real one runs and answers as the
/// real one does -- a git that wrote to stderr is a diff it did not read. The
/// shim warned on that argv, so the scan read nothing and the commit passed.
#[test]
fn a_staged_token_is_refused_with_the_git_shim_on_path() {
    let root = tracked();
    std::fs::write(
        root.join("policy/principles.toml"),
        format!(
            "{WITH_CREDENTIALS}\n[rule.no-wip-branch]\nmessage = \"unfinished\"\n\
             regexp = '^WIP'\ncommand.before = [\"git push\"]\n\
             \n[[shim]]\ncommand = \"git\"\nmatch = [\"push:*\"]\n\
             target = \"git-remote\"\nscope = \"public-target\"\ncollect = \"git-refs\"\n"
        ),
    )
    .unwrap();
    commit(&root, "inherit credentials and shim git");
    // Spelled at run time, so this file holds no token of its own.
    write(
        &root,
        "leak.txt",
        &format!("token = \"ghp_{}\"\n", "a1".repeat(18)),
    );
    support::git(&root, &["add", "leak.txt"]);

    let reader = "out=\"$STUB_LOG.diff\"\n\
         err=$(git -C . diff -U0 --no-ext-diff --staged . 2>&1 >\"$out\")\n\
         if [ -n \"$err\" ]; then\n\
           echo \"9:52PM ERR [git] $err\" >&2\n\
           echo '9:52PM ERR error=\"stderr is not empty\"' >&2\n\
           exit 0\n\
         fi\n\
         while IFS= read -r line; do\n\
           case \"$line\" in *ghp_*) echo 'RuleID: github-pat'; exit 3;; esac\n\
         done < \"$out\"\n\
         exit 0";
    let tools = every_scanner(&gitleaks_stub(GITLEAKS_PINNED, reader));
    let front = root.join("front");
    std::fs::create_dir_all(&front).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), front.join("git")).unwrap();
    let mut path = tools.as_os_str().to_owned();
    path.push(":");
    path.push(front.as_os_str());
    path.push(":/usr/bin:/bin");

    let output = invoke(&root, &path, &["--staged"], &[]);
    let said = text(&output);
    assert_eq!(code(&output), 1, "{said}");
    assert!(said.contains("RuleID: github-pat"), "{said}");
    assert!(!said.contains("uphold shim"), "{said}");
}

#[test]
fn staged_in_a_policy_that_does_not_inherit_credentials_asks_nothing() {
    let root = repository();
    let tools = every_scanner(&gitleaks_stub(GITLEAKS_PINNED, "exit 3"));
    let output = staged(&root, &tools, &[]);
    let said = text(&output);
    assert_eq!(code(&output), 0, "{said}");
    assert!(
        said.contains("does not inherit the `credentials` set"),
        "{said}"
    );
    assert!(journal(&root).is_empty(), "{}", journal(&root));
}

/// A range and the index are two subjects; naming both would leave one of
/// them silently unscanned.
#[test]
fn staged_with_a_range_flag_is_a_usage_error() {
    for extra in [&["--all"][..], &["--base", "HEAD"][..]] {
        let root = inheriting_credentials();
        let tools = every_scanner(&gitleaks_stub(GITLEAKS_PINNED, "exit 0"));
        let output = staged(&root, &tools, extra);
        let said = text(&output);
        assert_eq!(code(&output), 2, "{extra:?}: {said}");
        assert!(said.contains("--staged]"), "{said}");
        assert!(journal(&root).is_empty(), "{}", journal(&root));
    }
}

const RETIRED_WAIVER: &str = "\n[[supply_chain.waive]]\nscanner = \"guarddog\"\n\
    package = \"npm:swagger-ui-express@5.0.1\"\ncheck = \"metadata_mismatch\"\n\
    reason = \"a false positive\"\n";

/// A `[[supply_chain.waive]]` row naming guarddog, which uphold no longer runs,
/// still loads: the run names the row as ignored on stderr and is not failed
/// by it, so a policy written before the section went keeps working until its
/// owner deletes the row.
#[test]
fn a_waiver_naming_guarddog_is_ignored_with_a_warning_and_is_not_a_failure() {
    let root = repository();
    let path = root.join("policy/principles.toml");
    let policy = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{policy}{RETIRED_WAIVER}")).unwrap();
    let tools = stubs(&[("osv-scanner", "exit 0")]);
    let output = supply(&root, Some(&tools));
    let said = text(&output);
    assert_eq!(code(&output), 0, "{said}");
    assert!(
        said.contains(
            "ignoring `[[supply_chain.waive]]` for npm:swagger-ui-express@5.0.1 \
             (metadata_mismatch)"
        ),
        "{said}"
    );
    assert!(said.contains("all checks passed"), "{said}");
}

/// A waiver naming any other scanner is still refused at load: exit 2 before
/// any scanner runs. Only the one scanner that was removed is read and ignored.
#[test]
fn a_waiver_naming_any_other_scanner_is_refused_at_load() {
    let root = repository();
    let path = root.join("policy/principles.toml");
    let policy = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        format!(
            "{policy}{}",
            RETIRED_WAIVER.replace("guarddog", "osv-scanner")
        ),
    )
    .unwrap();
    let tools = stubs(&[("osv-scanner", "exit 0")]);
    let output = supply(&root, Some(&tools));
    assert_eq!(code(&output), 2, "{}", text(&output));
    assert!(
        text(&output).contains("names the scanner \"osv-scanner\""),
        "{}",
        text(&output)
    );
    assert!(journal(&root).is_empty(), "{}", journal(&root));
}

// ── direct references: git sources, URLs and paths no index holds ──

/// A repository whose policy declares `owner = "example-org"`.
fn owned_by_example_org() -> PathBuf {
    let root = repository();
    let path = root.join("policy/principles.toml");
    let policy = std::fs::read_to_string(&path).unwrap();
    std::fs::write(path, format!("owner = \"example-org\"\n{policy}")).unwrap();
    root
}

/// A git remote standing in for `https://github.com/example-org/example-kit`,
/// with an annotated tag `v0.1.0` on its first commit and `main` one commit
/// past it, and a git config that sends the forge URL to it.
///
/// Returns the config file, for `GIT_CONFIG_GLOBAL`, and the two commits. The
/// remote is real, so `git ls-remote` is the real command answering; only the
/// URL is rewritten, by git's own `insteadOf`.
fn example_kit_remote() -> (PathBuf, String, String) {
    let base = support::scratch("supply-chain-forge");
    let remote = base.join("forge/example-org/example-kit");
    std::fs::create_dir_all(&remote).unwrap();
    support::git(&remote, &["init", "-q", "-b", "main"]);
    support::git(&remote, &["config", "user.name", "Test"]);
    support::git(&remote, &["config", "user.email", "test@example.test"]);
    let tagged = commit(&remote, "the tagged release");
    support::git(&remote, &["tag", "-a", "v0.1.0", "-m", "v0.1.0"]);
    let tip = commit(&remote, "past the tag");
    let config = base.join("gitconfig");
    std::fs::write(
        &config,
        format!(
            "[url \"file://{}/\"]\n\tinsteadOf = https://github.com/\n",
            base.join("forge").display()
        ),
    )
    .unwrap();
    (config, tagged, tip)
}

/// A `uv.lock` whose one git source names `tag` at `commit`.
fn lock_naming(root: &Path, tag: &str, commit: &str) {
    std::fs::write(
        root.join("uv.lock"),
        format!(
            "version = 1\n[[package]]\nname = \"example-kit\"\nversion = \"0.1.0\"\n\
             source = {{ git = \"https://github.com/example-org/example-kit?tag={tag}#{commit}\" }}\n"
        ),
    )
    .unwrap();
}

/// Stubs whose `uv export` prints `lines`. A `uv.lock` is written where the
/// test wrote none, because the section reads nothing without one.
fn exporting(root: &Path, lines: &[&str]) -> PathBuf {
    if !root.join("uv.lock").exists() {
        std::fs::write(root.join("uv.lock"), "version = 1\n").unwrap();
    }
    let quoted: Vec<String> = lines.iter().map(|line| format!("'{line}'")).collect();
    stubs(&[
        ("osv-scanner", "exit 0"),
        (
            "uv",
            &recording(&format!("printf '%s\\n' {}", quoted.join(" "))),
        ),
    ])
}

/// The environment that points git at the stand-in forge.
fn forge_environment(config: &Path) -> [(&'static str, String); 2] {
    [
        ("GIT_CONFIG_GLOBAL", config.display().to_string()),
        ("GIT_CONFIG_NOSYSTEM", String::from("1")),
    ]
}

fn supply_with(root: &Path, tools: &Path, environment: &[(&str, String)]) -> Output {
    let mut path = tools.as_os_str().to_owned();
    path.push(":/usr/bin:/bin");
    let borrowed: Vec<(&str, &str)> = environment
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    invoke(root, &path, &["--all"], &borrowed)
}

/// A first-party package depended on through a uv git source is asked of its
/// own remote: the tag the lock names is there and points at the locked
/// commit.
#[test]
fn a_first_party_git_source_whose_tag_resolves_passes() {
    let root = owned_by_example_org();
    let (config, tagged, _) = example_kit_remote();
    lock_naming(&root, "v0.1.0", &tagged);
    let tools = exporting(
        &root,
        &[
            "-e .",
            "requests==2.32.0",
            &format!("example-kit @ git+https://github.com/example-org/example-kit@{tagged}"),
        ],
    );
    let output = supply_with(&root, &tools, &forge_environment(&config));
    let said = text(&output);
    assert_eq!(code(&output), 0, "{said}");
    assert!(
        said.contains(&format!(
            "first party: example-kit: tag v0.1.0 on https://github.com/example-org/example-kit \
             is {tagged}"
        )),
        "{said}"
    );
    assert!(
        journal(&root).contains("export --frozen"),
        "{}",
        journal(&root)
    );
    assert!(said.contains("all checks passed"), "{said}");
}

/// With no tag in the lock, the locked commit must be what some ref points at;
/// `main`'s tip is.
#[test]
fn a_first_party_git_source_at_a_branch_tip_passes() {
    let root = owned_by_example_org();
    let (config, _, tip) = example_kit_remote();
    let tools = exporting(
        &root,
        &[
            "requests==2.32.0",
            &format!("example-kit @ git+https://github.com/example-org/example-kit@{tip}"),
        ],
    );
    let output = supply_with(&root, &tools, &forge_environment(&config));
    assert_eq!(code(&output), 0, "{}", text(&output));
    assert!(
        text(&output).contains(&format!("{tip} is refs/heads/main")),
        "{}",
        text(&output)
    );
}

/// A commit no branch or tag points at is refused by name: nothing on the
/// remote holds it in place.
#[test]
fn a_first_party_git_source_whose_commit_no_ref_points_at_is_refused_by_name() {
    let root = owned_by_example_org();
    let (config, _, _) = example_kit_remote();
    let orphan = "0123456789abcdef0123456789abcdef01234567";
    let tools = exporting(
        &root,
        &[
            "requests==2.32.0",
            &format!("example-kit @ git+https://github.com/example-org/example-kit@{orphan}"),
        ],
    );
    let output = supply_with(&root, &tools, &forge_environment(&config));
    let said = text(&output);
    assert_eq!(code(&output), 1, "{said}");
    assert!(
        said.contains(&format!(
            "example-kit is locked to {orphan}, and no branch or tag on \
             https://github.com/example-org/example-kit points at it"
        )),
        "{said}"
    );
}

/// A tag the lock names that points somewhere other than the locked commit is
/// refused: the tag moved, or the lock came from elsewhere.
#[test]
fn a_first_party_tag_that_points_elsewhere_is_refused() {
    let root = owned_by_example_org();
    let (config, _, tip) = example_kit_remote();
    lock_naming(&root, "v0.1.0", &tip);
    let tools = exporting(
        &root,
        &[
            "requests==2.32.0",
            &format!("example-kit @ git+https://github.com/example-org/example-kit@{tip}"),
        ],
    );
    let output = supply_with(&root, &tools, &forge_environment(&config));
    assert_eq!(code(&output), 1, "{}", text(&output));
    assert!(text(&output).contains("the tag moved"), "{}", text(&output));
}

/// A remote `git ls-remote` cannot reach is could-not-look with git's own
/// reason, exit 2, and never a pass.
#[test]
fn a_first_party_remote_that_cannot_be_asked_is_could_not_look() {
    let root = owned_by_example_org();
    let base = support::scratch("supply-chain-no-forge");
    std::fs::create_dir_all(&base).unwrap();
    let config = base.join("gitconfig");
    std::fs::write(
        &config,
        format!(
            "[url \"file://{}/\"]\n\tinsteadOf = https://github.com/\n",
            base.join("nothing-here").display()
        ),
    )
    .unwrap();
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let tools = exporting(
        &root,
        &[
            "requests==2.32.0",
            &format!("example-kit @ git+https://github.com/example-org/example-kit@{commit}"),
        ],
    );
    let output = supply_with(&root, &tools, &forge_environment(&config));
    let said = text(&output);
    assert_eq!(code(&output), 2, "{said}");
    assert!(
        said.contains("NOT CHECKED: git ls-remote could not answer for example-kit"),
        "{said}"
    );
    assert!(!said.contains("all checks passed"), "{said}");
}

/// A git source under an owner other than the declared one is refused by
/// name, and never reaches the remote.
#[test]
fn a_git_source_under_another_owner_is_refused_by_name() {
    let root = owned_by_example_org();
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let tools = exporting(
        &root,
        &[
            "requests==2.32.0",
            &format!("other-kit @ git+https://github.com/another-org/other-kit@{commit}"),
        ],
    );
    let output = supply_with(&root, &tools, &[]);
    let said = text(&output);
    assert_eq!(code(&output), 1, "{said}");
    assert!(
        said.contains(
            "other-kit is a git source under github.com/another-org, not under \
             github.com/example-org"
        ),
        "{said}"
    );
}

/// Where the policy declares no owner, no git source is first party.
#[test]
fn a_git_source_in_a_policy_with_no_owner_is_refused() {
    let root = repository();
    let commit = "0123456789abcdef0123456789abcdef01234567";
    let tools = exporting(
        &root,
        &[
            "requests==2.32.0",
            &format!("example-kit @ git+https://github.com/example-org/example-kit@{commit}"),
        ],
    );
    let output = supply_with(&root, &tools, &[]);
    assert_eq!(code(&output), 1, "{}", text(&output));
    assert!(
        text(&output).contains("this policy declares no `owner`"),
        "{}",
        text(&output)
    );
}

/// A direct URL, and a path outside the repository, are refused by name.
#[test]
fn a_direct_url_and_a_path_outside_the_tree_are_refused_by_name() {
    let root = owned_by_example_org();
    std::fs::create_dir_all(root.parent().unwrap().join("outside-the-tree")).unwrap();
    let tools = exporting(
        &root,
        &[
            "requests==2.32.0",
            "wheel-dep @ https://example.test/wheel-dep-1.0-py3-none-any.whl",
            "-e ../outside-the-tree",
        ],
    );
    let output = supply_with(&root, &tools, &[]);
    let said = text(&output);
    assert_eq!(code(&output), 1, "{said}");
    assert!(said.contains("wheel-dep is a direct URL"), "{said}");
    assert!(
        said.contains("../outside-the-tree is a path dependency outside this repository"),
        "{said}"
    );
    // The export was still read.
    assert!(
        journal(&root).contains("export --frozen"),
        "{}",
        journal(&root)
    );
}

// ── npm git dependencies ──

/// A `package.json` whose `dependencies` hold `spec` for example-kit beside a
/// registry range, a `bun.lock` recording `commit` for it, and stub scanners.
fn npm_depending_on(root: &Path, spec: &str, commit: &str) -> PathBuf {
    std::fs::write(
        root.join("package.json"),
        format!(
            "{{\"name\":\"app\",\"dependencies\":{{\"example-kit\":\"{spec}\",\
             \"cookie\":\"^1.1.1\"}}}}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("bun.lock"),
        format!(
            "{{\n  \"packages\": {{\n    \"example-kit\": [\"example-kit@{spec}#{commit}\", \
             {{}}, \"{commit}\"],\n  }}\n}}\n"
        ),
    )
    .unwrap();
    stubs(&[("osv-scanner", "exit 0")])
}

/// The npm half: a first-party package depended on by git has the tag the
/// manifest names asked of the remote, against the commit `bun.lock` holds.
#[test]
fn a_first_party_npm_git_dependency_whose_tag_resolves_passes() {
    let root = owned_by_example_org();
    let (config, tagged, _) = example_kit_remote();
    let tools = npm_depending_on(
        &root,
        "git+https://github.com/example-org/example-kit#v0.1.0",
        &tagged,
    );
    let output = supply_with(&root, &tools, &forge_environment(&config));
    let said = text(&output);
    assert_eq!(code(&output), 0, "{said}");
    assert!(
        said.contains(&format!(
            "first party: example-kit: tag v0.1.0 on \
             https://github.com/example-org/example-kit is {tagged}"
        )),
        "{said}"
    );
    assert!(said.contains("all checks passed"), "{said}");
}

/// A lock whose commit is not where the manifest's tag points is refused.
#[test]
fn a_first_party_npm_tag_that_points_elsewhere_is_refused() {
    let root = owned_by_example_org();
    let (config, _, tip) = example_kit_remote();
    let tools = npm_depending_on(&root, "github:example-org/example-kit#v0.1.0", &tip);
    let output = supply_with(&root, &tools, &forge_environment(&config));
    assert_eq!(code(&output), 1, "{}", text(&output));
    assert!(text(&output).contains("the tag moved"), "{}", text(&output));
}

/// A git dependency under another owner is refused by name, and is never
/// asked of the remote.
#[test]
fn an_npm_git_dependency_under_another_owner_is_refused_by_name() {
    let root = owned_by_example_org();
    let (config, tagged, _) = example_kit_remote();
    let tools = npm_depending_on(&root, "github:someone-else/example-kit#v0.1.0", &tagged);
    let output = supply_with(&root, &tools, &forge_environment(&config));
    let said = text(&output);
    assert_eq!(code(&output), 1, "{said}");
    assert!(
        said.contains("example-kit is a git source under github.com/someone-else"),
        "{said}"
    );
    assert!(!said.contains("404"), "{said}");
}
