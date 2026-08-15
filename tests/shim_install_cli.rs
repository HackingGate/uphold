//! CLI-level tests for the links a shim is reached through.
//!
//! The unit tests in `src/install.rs` drive one name at a time. What is left to
//! this file is the pair of facts a directory of links exists to make visible --
//! that the links are THERE, and that PATH REACHES them -- and the one case that
//! proves the whole seam: a link made by `--install`, on a PATH the shell would
//! actually walk, refusing a publication.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// One shim, whose scope is `always` so the tests need no forge.
const POLICY: &str = r#"
[rule.no-published-markers]
message = "remove the marker"
exec = "uphold guard --text -"
command.before = ["faux"]

# What the checker above consults. `uphold guard --text -` runs the
# text-capable guards this policy declares, and a policy declaring none is a
# checker that approves everything -- which is the shape this suite exists to
# catch rather than to reproduce.
[rule.prevent-ai-author]
builtin = "prevent-ai-author"
git.hooks = ["commit-msg"]

[[shim]]
command = "faux"
match = ["pr:create"]
text_flags = ["-t", "--title"]
scope = "always"
"#;

/// A repository that declares the shim above, and a real `faux` for it to exec
/// through to.
fn workspace(name: &str) -> PathBuf {
    let root = support::scratch(name);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    std::fs::create_dir_all(root.join("bin")).unwrap();
    std::fs::create_dir_all(root.join("shims")).unwrap();
    std::fs::write(root.join("policy/principles.toml"), POLICY).unwrap();
    // The checker in this policy is the binary consulting itself, so it has to
    // be on PATH under its own name.
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), root.join("bin/uphold")).unwrap();
    executable(&root.join("bin/faux"), "#!/bin/sh\necho \"faux ran: $*\"\n");
    Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(&root)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    root
}

fn executable(at: &Path, body: &str) {
    std::fs::write(at, body).unwrap();
    let mut permissions = std::fs::metadata(at).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(at, permissions).unwrap();
}

/// PATH as a shell that has NOT adopted the shims directory would have it.
fn plain_path(root: &Path) -> String {
    format!(
        "{}:{}",
        root.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

/// PATH as a shell that has adopted it would: the shims directory first.
fn shimmed_path(root: &Path) -> String {
    format!("{}:{}", root.join("shims").display(), plain_path(root))
}

fn run(root: &Path, path: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(args)
        .current_dir(root)
        .env("PATH", path)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap()
}

fn links(root: &Path, path: &str, args: &[&str]) -> Output {
    let dir = root.join("shims");
    let mut all: Vec<&str> = vec!["shim"];
    all.extend_from_slice(args);
    all.push("--dir");
    let dir = dir.to_string_lossy().into_owned();
    all.push(&dir);
    run(root, path, &all)
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The whole seam, end to end: a link this command made, on a PATH a shell
/// would walk, standing in front of a publication and refusing it.
///
/// Every other case here is about the report. This one is about whether the
/// thing works at all, and it is the only one that would notice a link pointing
/// at the wrong file.
#[test]
fn a_link_this_command_made_refuses_a_publication() {
    let root = workspace("install-e2e");
    let made = links(&root, &plain_path(&root), &["--install", "faux"]);
    assert_eq!(code(&made), 1, "{}", stderr(&made));
    assert!(stdout(&made).contains("linked"), "{}", stdout(&made));
    // Exit 1, and this is the word that earns it: the link exists, the real
    // `faux` in `bin` comes first, and a seam that is installed and inert must
    // not read as one that is standing in front of anything.
    assert!(stdout(&made).contains("SHADOWED"), "{}", stdout(&made));

    let path = shimmed_path(&root);
    let refused = Command::new("faux")
        .args(["pr", "create", "-t", "Generated with Claude Code"])
        .current_dir(&root)
        .env("PATH", &path)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap();
    assert_eq!(code(&refused), 1, "{}", stderr(&refused));
    assert!(
        !stdout(&refused).contains("faux ran:"),
        "{}",
        stdout(&refused)
    );

    // And the other half, which a shim that refuses everything would also pass:
    // an ordinary title reaches the real command.
    let ran = Command::new("faux")
        .args(["pr", "create", "-t", "An ordinary title"])
        .current_dir(&root)
        .env("PATH", &path)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap();
    assert_eq!(code(&ran), 0, "{}", stderr(&ran));
    assert!(stdout(&ran).contains("faux ran:"), "{}", stdout(&ran));
}

/// Installed and reached are different facts, and only the second one is a
/// seam. The exit code is the difference, because a report nobody reads is what
/// a CI step consumes.
#[test]
fn a_link_nothing_reaches_is_not_reported_as_installed() {
    let root = workspace("install-reach");
    let unreached = links(&root, &plain_path(&root), &["--install", "faux"]);
    assert_eq!(code(&unreached), 1, "{}", stdout(&unreached));

    let reached = links(&root, &shimmed_path(&root), &["--status"]);
    assert_eq!(code(&reached), 0, "{}", stdout(&reached));
    assert!(stdout(&reached).contains("reached"), "{}", stdout(&reached));
}

/// A directory on PATH that holds the command already, ahead of this one, is a
/// shim that will never run -- and it looks exactly like one that will.
#[test]
fn a_command_reached_somewhere_else_first_is_reported_as_shadowed() {
    let root = workspace("install-shadow");
    let _ = links(&root, &plain_path(&root), &["--install", "faux"]);
    // `bin` holds the real `faux`, so putting it FIRST is the shadowing case.
    let path = format!("{}:{}", plain_path(&root), root.join("shims").display());
    let output = links(&root, &path, &["--status"]);
    assert_eq!(code(&output), 1, "{}", stdout(&output));
    assert!(stdout(&output).contains("SHADOWED"), "{}", stdout(&output));
    assert!(
        stdout(&output).contains("bin/faux"),
        "the report has to name what wins: {}",
        stdout(&output)
    );
}

/// With no names, the commands are the ones this repository declares -- the only
/// evidence there is about which commands matter.
#[test]
fn the_commands_default_to_the_ones_this_policy_declares() {
    let root = workspace("install-declared");
    let output = links(&root, &plain_path(&root), &["--install"]);
    assert!(stdout(&output).contains("faux"), "{}", stdout(&output));
    assert!(root.join("shims/faux").is_symlink());

    // Twice is once. A second install says so rather than reporting work it did
    // not do.
    let again = links(&root, &plain_path(&root), &["--install"]);
    assert!(stdout(&again).contains("already"), "{}", stdout(&again));
}

/// Outside a repository there is nothing to read the names out of, and guessing
/// them would put links on PATH for commands nobody named.
#[test]
fn with_no_policy_and_no_names_there_is_nothing_to_install() {
    let bare = support::scratch("install-bare");
    std::fs::create_dir_all(bare.join("shims")).unwrap();
    let output = links(
        &bare,
        &std::env::var("PATH").unwrap_or_default(),
        &["--install"],
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("uphold shim --install git gh"),
        "{}",
        stderr(&output)
    );
}

/// The directory name is a thing people mistype, and what would be overwritten
/// is a command somebody depends on.
#[test]
fn a_file_this_command_did_not_write_is_never_replaced() {
    let root = workspace("install-occupied");
    executable(&root.join("shims/faux"), "#!/bin/sh\necho \"not ours\"\n");
    let output = links(&root, &plain_path(&root), &["--install", "faux"]);
    assert_eq!(code(&output), 2, "{}", stdout(&output));
    assert!(stdout(&output).contains("REFUSED"), "{}", stdout(&output));
    assert!(std::fs::read_to_string(root.join("shims/faux"))
        .unwrap()
        .contains("not ours"));
}

/// A link is made in one directory under the command's own name. A name
/// carrying a separator would put it somewhere else, and `--uninstall` would
/// never find it again.
#[test]
fn a_name_that_is_a_path_is_not_a_command_name() {
    let root = workspace("install-escape");
    let output = links(&root, &plain_path(&root), &["--install", "../escaped"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(!root.join("escaped").exists());
}

/// The mode comes first, and an option in the command's place is a mistyped
/// mode rather than a command called `--dir`.
#[test]
fn an_option_where_a_command_goes_names_the_modes() {
    let root = workspace("install-order");
    let output = run(
        &root,
        &plain_path(&root),
        &["shim", "--dir", "shims", "--install", "faux"],
    );
    assert_eq!(code(&output), 2, "{}", stdout(&output));
    assert!(
        stderr(&output).contains("is not one of the shim modes"),
        "{}",
        stderr(&output)
    );
}

/// Take back what this command put there, and nothing else.
#[test]
fn uninstall_removes_our_links_and_leaves_everything_else() {
    let root = workspace("uninstall");
    let _ = links(&root, &plain_path(&root), &["--install", "faux"]);
    std::fs::write(root.join("shims/notes.txt"), "somebody else's file").unwrap();

    let output = links(&root, &plain_path(&root), &["--uninstall"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(!root.join("shims/faux").exists());
    assert!(root.join("shims/notes.txt").is_file());

    // And a second run is not an error: there is nothing of ours there.
    let again = links(&root, &plain_path(&root), &["--uninstall"]);
    assert_eq!(code(&again), 0, "{}", stderr(&again));
}

/// Nothing installed is not a violation. It is a question with an answer, and
/// the answer names the command that would change it.
#[test]
fn a_directory_with_nothing_of_ours_in_it_is_reported_and_is_not_a_failure() {
    let root = workspace("status-empty");
    let output = links(&root, &plain_path(&root), &["--status"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stdout(&output).contains("nothing is linked here"),
        "{}",
        stdout(&output)
    );
}

/// What the shell hook installs, and the whole of its logic: the directory goes
/// on PATH inside a tree that declares a policy and comes off outside one.
#[test]
fn the_path_a_shell_should_have_follows_the_policy_and_never_doubles() {
    let root = workspace("shell-path");
    let dir = root.join("shims").display().to_string();

    let inside = links(&root, "/usr/bin:/bin", &["--path"]);
    assert_eq!(stdout(&inside).trim(), format!("{dir}:/usr/bin:/bin"));

    // Already there is still once there. A hook that appended would grow PATH by
    // one entry per prompt.
    let again = links(&root, &format!("{dir}:/usr/bin:/bin"), &["--path"]);
    assert_eq!(stdout(&again).trim(), format!("{dir}:/usr/bin:/bin"));

    // And outside a participating tree it comes off, which is the half that
    // makes this the direnv shape rather than a slower way to install it
    // everywhere.
    let outside = support::scratch("shell-path-outside");
    std::fs::create_dir_all(&outside).unwrap();
    let away = run(
        &outside,
        &format!("{dir}:/usr/bin:/bin"),
        &["shim", "--path", "--dir", &dir],
    );
    assert_eq!(stdout(&away).trim(), "/usr/bin:/bin");
}

/// The hook is text this tool writes into somebody's shell profile, so the
/// three dialects are asserted rather than assumed -- and a shell it has not
/// been taught is an error rather than a guess.
#[test]
fn a_hook_is_written_for_each_shell_it_claims_and_for_no_other() {
    let root = workspace("hook");
    let dir = root.join("shims").display().to_string();
    for shell in ["bash", "zsh", "fish"] {
        let output = links(&root, &plain_path(&root), &["--hook", shell]);
        assert_eq!(code(&output), 0, "{shell}: {}", stderr(&output));
        let text = stdout(&output);
        assert!(text.contains(&dir), "{shell}: {text}");
        assert!(text.contains("shim --path"), "{shell}: {text}");
        assert!(
            text.contains(env!("CARGO_BIN_EXE_uphold")),
            "the hook names the binary it was written for: {shell}: {text}"
        );
    }
    let unknown = links(&root, &plain_path(&root), &["--hook", "csh"]);
    assert_eq!(code(&unknown), 2, "{}", stdout(&unknown));
    assert!(
        stderr(&unknown).contains("uphold shim --path"),
        "an unsupported shell is told how to write its own: {}",
        stderr(&unknown)
    );
}

/// The hook a shell would actually source, sourced by that shell.
///
/// Asserting on the text is asserting that this tool wrote what it meant to
/// write; only running it says the shell agrees. Each dialect is skipped where
/// the shell is not installed -- and skipped OUT LOUD, because a test that
/// silently checks nothing on the CI runner is the shape this repository
/// refuses.
#[test]
fn each_hook_is_run_by_the_shell_it_was_written_for() {
    let root = workspace("hook-run");
    let dir = root.join("shims").display().to_string();
    let mut ran = 0;
    for (shell, script) in [
        ("bash", "source HOOK; echo $PATH"),
        ("zsh", "source HOOK; echo $PATH"),
        ("fish", "source HOOK; echo $PATH"),
    ] {
        let written = links(&root, &plain_path(&root), &["--hook", shell]);
        let path = root.join(format!("hook.{shell}"));
        std::fs::write(&path, stdout(&written)).unwrap();
        let line = script.replace("HOOK", &path.display().to_string());
        let Ok(output) = Command::new(shell)
            .args(["-c", &line])
            .current_dir(&root)
            .env("PATH", plain_path(&root))
            .output()
        else {
            println!("{shell} is not installed here, so its hook was not run");
            continue;
        };
        ran += 1;
        assert!(
            stdout(&output).contains(&dir),
            "{shell} sourced its hook and the shims directory is not on PATH: {} {}",
            stdout(&output),
            stderr(&output)
        );
    }
    assert!(ran > 0, "no shell on this machine ran a hook");
}
