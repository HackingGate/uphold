//! CLI-level tests for the two questions every subcommand answers before it
//! looks at anything: WHICH repository is this about, and can argv even be read.
//!
//! At the CLI and not at `discover`/`root_of`, because both failures are only
//! visible from outside. A root taken from the enclosing superproject is a
//! function returning a perfectly ordinary `PathBuf`; what makes it a bug is
//! that the process then prints findings about files that are not in the
//! repository the command was run in. And an argv that is not UTF-8 does not
//! return anything at all -- it panics, and the only place exit 101 exists is in
//! the process's status.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// A rule that names a file, so a report about the WRONG tree is legible as
/// one: an exit code alone cannot say which repository was walked.
///
/// The policy file writes the pattern it matches on, so it excludes itself --
/// the same exclusion every bundled rule carries, for the same reason.
const POLICY: &str = r#"
[rule.no-todo]
message = "no TODO"
regexp = 'TODO'

[rule.no-todo.files]
exclude = ["policy/**"]
"#;

/// One directory per case, under a name no other test file claims. The suite
/// runs in parallel threads of one process, so a path keyed on the process id
/// alone is the SAME path for every case and one case reads the tree another is
/// still building.
fn workspace() -> PathBuf {
    let root = support::scratch("root-cli");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn write(directory: &Path, relative: &str, contents: &str) {
    let path = directory.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

fn write_policy(directory: &Path) {
    write(directory, "policy/principles.toml", POLICY);
}

/// Where a repository begins, as an ordinary clone spells it.
fn mark_repository(directory: &Path) {
    std::fs::create_dir_all(directory.join(".git")).unwrap();
}

fn uphold<S: AsRef<OsStr>>(working: &Path, arguments: &[S]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(arguments)
        .current_dir(working)
        // A guard bypass leaking in from the developer's shell would turn a
        // refusal these cases assert on into a pass.
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// `Option`, not `unwrap`: a process killed by a signal has no code, and the
/// panic-vs-exit cases below are exactly where that distinction matters.
fn code(output: &Output) -> Option<i32> {
    output.status.code()
}

// --- the repository boundary ------------------------------------------------

/// The live failure: a repository with no policy of its own, inside one that
/// has a policy.
///
/// The walk used to climb past the inner repository's root, load the
/// superproject's policy and adopt the SUPERPROJECT'S directory as root -- so
/// the run scanned a different tree and the report named files outside the
/// repository the command was run in, under this repository's name. Asserting
/// on the exit code alone would not catch it: the give-away is the file name.
#[test]
fn a_repository_with_no_policy_is_not_checked_against_the_superprojects() {
    let superproject = workspace();
    write_policy(&superproject);
    write(
        &superproject,
        "outside.txt",
        "TODO: the superproject's own\n",
    );

    let inner = superproject.join("inner");
    mark_repository(&inner);
    write(&inner, "inside.txt", "nothing to find here\n");

    // From the repository root, and from a directory below it -- the climb is
    // the same walk either way, and the boundary has to stop both.
    for working in [inner.clone(), inner.join("src")] {
        std::fs::create_dir_all(&working).unwrap();
        let output = uphold(&working, &["scan"]);
        assert_eq!(code(&output), Some(2), "{}", stderr(&output));
        assert!(
            stderr(&output).contains("no policy in this repository"),
            "{}",
            stderr(&output)
        );
        assert!(
            !stderr(&output).contains("outside.txt"),
            "reported on the superproject's tree: {}",
            stderr(&output)
        );
        assert!(
            !stdout(&output).contains("policy checks passed"),
            "a repository with nothing to check against is not a pass: {}",
            stdout(&output)
        );
    }
}

/// A `.git` FILE is the boundary a `.git` directory is.
///
/// That is what a linked worktree and a submodule have where a clone has a
/// directory, and a check that asked `is_dir` would walk straight out of both
/// -- which is precisely the shape the superproject case is made of.
#[test]
fn a_git_file_stops_the_walk_the_way_a_git_directory_does() {
    let superproject = workspace();
    write_policy(&superproject);
    write(
        &superproject,
        "outside.txt",
        "TODO: the superproject's own\n",
    );

    let submodule = superproject.join("submodule");
    std::fs::create_dir_all(&submodule).unwrap();
    std::fs::write(
        submodule.join(".git"),
        "gitdir: ../.git/modules/submodule\n",
    )
    .unwrap();

    let output = uphold(&submodule, &["scan"]);
    assert_eq!(code(&output), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no policy in this repository"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("outside.txt"),
        "a submodule borrowed the superproject's policy: {}",
        stderr(&output)
    );
}

/// Every entry point that resolves a root, not just `scan`.
///
/// They each call the same walk, and a fix applied at one call site and not the
/// others would leave `guard` refusing a commit on the strength of a policy
/// belonging to a tree the committer has never opened.
#[test]
fn every_subcommand_that_resolves_a_root_stops_at_the_boundary() {
    let superproject = workspace();
    write_policy(&superproject);
    let inner = superproject.join("inner");
    mark_repository(&inner);

    for arguments in [
        vec!["scan"],
        vec!["guard", "--stage", "manual"],
        vec!["audit", "--for-publication"],
        vec!["check"],
        vec!["check", "--coverage"],
        vec!["rules", "--effective"],
        // Asked for BY NAME, an absent policy is an error rather than a
        // passthrough: the caller asked this repository for a shim, and the
        // answer is that this repository declares none -- not the
        // superproject's answer to the same question.
        vec!["shim", "faux", "--version"],
    ] {
        let output = uphold(&inner, &arguments);
        assert_eq!(code(&output), Some(2), "{arguments:?}: {}", stderr(&output));
        assert!(
            stderr(&output).contains("no policy in this repository"),
            "{arguments:?}: {}",
            stderr(&output)
        );
    }
}

/// The boundary is where the walk STOPS, not a refusal to look: a repository
/// carrying its own policy is the ordinary case, and it is checked against its
/// own -- reporting its own files and none of the superproject's.
#[test]
fn a_repository_with_its_own_policy_reports_its_own_files_and_no_others() {
    let superproject = workspace();
    write_policy(&superproject);
    write(
        &superproject,
        "outside.txt",
        "TODO: the superproject's own\n",
    );

    let inner = superproject.join("inner");
    mark_repository(&inner);
    write_policy(&inner);
    write(&inner, "inside.txt", "TODO: this repository's own\n");

    let below = inner.join("src");
    std::fs::create_dir_all(&below).unwrap();

    let output = uphold(&below, &["scan"]);
    assert_eq!(code(&output), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("inside.txt"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("outside.txt"),
        "named a file outside the repository it was run in: {}",
        stderr(&output)
    );
}

// --- --policy, and the root it implies --------------------------------------

/// `--policy` used to take the file's grandparent as the root and check
/// nothing, so `--policy principles.toml` rooted the scan at the repository's
/// PARENT and the default include of `["."]` then walked that. A root that
/// cannot be established is exit 2: scanning the wrong tree and reporting on it
/// is worse than saying the layout was not understood.
#[test]
fn an_explicit_policy_off_the_layout_is_refused_rather_than_rooted_elsewhere() {
    let root = workspace();
    // Deliberately NOT under `policy/`: this is the layout that used to make
    // the temporary directory's parent the tree under test.
    write(&root, "principles.toml", POLICY);
    write(&root, "a.txt", "TODO: here\n");

    for given in ["principles.toml", "./principles.toml"] {
        let output = uphold(&root, &["scan", "--policy", given]);
        assert_eq!(code(&output), Some(2), "{given}: {}", stderr(&output));
        assert!(
            stderr(&output).contains("<root>/policy/<name>.toml"),
            "{given}: {}",
            stderr(&output)
        );
        assert!(
            !stdout(&output).contains("policy checks passed"),
            "{given}: a layout that was not understood is not a pass: {}",
            stdout(&output)
        );
    }
}

/// The layout it does accept, and the root it names -- asked from a
/// subdirectory, because the root has to come from where the policy file sits
/// and not from where the command was typed.
#[test]
fn an_explicit_policy_in_the_layout_roots_at_the_repository() {
    let root = workspace();
    write_policy(&root);
    write(&root, "a.txt", "TODO: here\n");
    let below = root.join("src");
    std::fs::create_dir_all(&below).unwrap();

    let output = uphold(&below, &["scan", "--policy", "../policy/principles.toml"]);
    assert_eq!(code(&output), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("a.txt"),
        "the root is where the policy file says it is: {}",
        stderr(&output)
    );
}

// --- argv that is not text --------------------------------------------------

/// `std::env::args()` PANICS on an argument that is not Unicode.
///
/// Exit 101, out of a binary that promises three exit codes and is installed in
/// front of `git`, `gh` and `npm` -- where a path spelled in latin-1 is an
/// ordinary thing to be handed. Every assertion here is on the CODE and not
/// only on the message, because 101 is the whole finding: a panic also writes
/// to stderr, and a test that only read stderr would pass on one.
#[test]
fn an_argument_that_is_not_text_is_exit_two_and_never_a_panic() {
    use std::os::unix::ffi::OsStringExt;

    let root = workspace();
    write_policy(&root);
    // `caf\xe9`, a perfectly good file name that is not UTF-8.
    let latin1 = OsString::from_vec(b"caf\xe9".to_vec());

    for arguments in [
        // A subcommand name.
        vec![latin1.clone()],
        // An option name, past a subcommand that parses its own arguments.
        vec![OsString::from("scan"), latin1.clone()],
        vec![OsString::from("guard"), latin1.clone()],
        // A value that has to be text to mean anything: a rule-set name is
        // matched against literals, so bytes that spell none of them name
        // nothing this binary has.
        vec![
            OsString::from("rules"),
            OsString::from("--set"),
            latin1.clone(),
        ],
        // The command a shim stands in front of.
        vec![OsString::from("shim"), latin1],
    ] {
        let output = uphold(&root, &arguments);
        assert_eq!(code(&output), Some(2), "{arguments:?}: {}", stderr(&output));
        assert!(
            !stderr(&output).contains("panicked"),
            "{arguments:?}: {}",
            stderr(&output)
        );
    }
}

/// A link named in bytes that are not text names no command, and says so.
///
/// argv[0] decides which shim this binary is, and it is read before anything
/// else -- so it was the first thing `std::env::args()` panicked on, in the one
/// invocation shape this binary is installed as.
#[test]
fn a_link_whose_name_is_not_text_is_refused_rather_than_a_panic() {
    use std::os::unix::ffi::OsStringExt;

    let root = workspace();
    write_policy(&root);
    let mut name = OsString::from_vec(b"caf\xe9".to_vec());
    let link = {
        let mut path = root.clone().into_os_string();
        path.push("/");
        path.push(&mut name);
        PathBuf::from(path)
    };
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), &link).unwrap();

    let output = Command::new(&link)
        .arg("--version")
        .current_dir(&root)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("not valid UTF-8"),
        "{}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains("panicked"), "{}", stderr(&output));
}

/// The other half of the same promise: where the bytes are a PATH rather than a
/// name, they are not converted at all.
///
/// A lossy conversion here would leave the binary opening `caf\u{FFFD}.toml`,
/// which does not exist -- so the run would fail with the wrong reason, or
/// worse, be read as "no policy" and treated as nothing to check. The policy
/// file opens because it kept the bytes it was given, and the proof is that the
/// scan it drives finds the violation.
#[test]
fn a_policy_path_that_is_not_text_still_opens_the_file_it_names() {
    use std::os::unix::ffi::OsStringExt;

    let root = workspace();
    std::fs::create_dir_all(root.join("policy")).unwrap();
    let policy = {
        let mut path = root.join("policy").into_os_string();
        path.push("/");
        path.push(OsString::from_vec(b"caf\xe9.toml".to_vec()));
        PathBuf::from(path)
    };
    std::fs::write(&policy, POLICY).unwrap();
    write(&root, "a.txt", "TODO: here\n");

    let output = uphold(
        &root,
        &[
            OsString::from("scan"),
            OsString::from("--policy"),
            policy.into_os_string(),
        ],
    );
    assert_eq!(code(&output), Some(1), "{}", stderr(&output));
    assert!(stderr(&output).contains("a.txt"), "{}", stderr(&output));
}

// --- a reader that goes away -------------------------------------------------

/// `uphold rules --effective | head -2` exited 101.
///
/// `println!` unwraps its write and panics, and Rust ignores `SIGPIPE` at
/// startup, so a reader closing a pipe reached the macro as an ordinary `EPIPE`
/// and left this binary exiting on a code its own contract does not define --
/// out of a process installed in front of `git`, `gh` and `npm`. The run had
/// already decided its verdict; what failed was writing the tail of it to
/// somebody who had stopped listening.
///
/// Driven by closing the pipe rather than by spawning `head`, because `head`
/// puts its own status where the shell reads one and this test is about the
/// status of THIS process.
#[test]
fn a_reader_that_closes_the_pipe_does_not_panic_the_run() {
    let root = workspace();
    write_policy(&root);
    write(&root, "a.txt", "nothing to find here\n");

    for arguments in [
        // Long output, so the writes keep coming after the reader has gone, and
        // short output, so the case where everything was already buffered is
        // covered by the same assertion.
        vec!["rules", "--sets", "--json"],
        vec!["scan"],
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_uphold"))
            .args(&arguments)
            .current_dir(&root)
            .env_remove("UPHOLD_ALLOW")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // The reader goes away here: the read end is dropped while the child is
        // still starting, so every write it makes lands on a pipe nobody holds.
        drop(child.stdout.take());
        let status = child.wait().unwrap();

        assert_eq!(
            status.code(),
            Some(0),
            "{arguments:?} exited {:?}, and the three codes this tool promises do not \
             include 101",
            status.code()
        );
    }
}

/// The other write that fails, and it is not the same answer.
///
/// A full disk under a redirected report is not a reader's decision: the
/// findings are not in the file, nothing downstream has them, and a run that
/// exited on its own verdict would report a clean tree to a caller holding half
/// of one. `/dev/full` is that condition, available on every Linux runner this
/// suite runs on -- and skipped OUT LOUD where it is not, because a test that
/// silently checks nothing is the shape this repository refuses.
#[test]
fn a_report_that_could_not_be_written_is_not_a_report() {
    if !Path::new("/dev/full").exists() {
        println!("/dev/full is not here, so the unwritable-report case was not run");
        return;
    }
    let root = workspace();
    write_policy(&root);

    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["rules", "--effective"])
        .current_dir(&root)
        .env_remove("UPHOLD_ALLOW")
        .stdout(Stdio::from(full))
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert_eq!(code(&output), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("could not be written"),
        "the reader has to be told which half they are holding: {}",
        stderr(&output)
    );
}
