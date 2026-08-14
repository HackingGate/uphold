//! CLI-level tests for the seams where `uphold shim` hands off.
//!
//! Kept apart from `shim_cli.rs`, which asks what the shim decides. These ask
//! what it does with the process afterwards -- the stdin it consumed, the pipes
//! it holds a checker on, the editor the body is really written in, the exec it
//! disappears into, and which forge it asks about a target. Every one of them
//! was a path where the shim reported 0 without having looked.

#![expect(
    clippy::expect_used,
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The rule every case here shares: the binary consulting itself over text,
/// which is the point of a checker -- the rule that judges a commit message and
/// the rule that judges a pull-request body are the same rule.
const MARKER_RULE: &str = r#"
[rule.no-published-markers]
message = "remove the marker"
exec = "uphold guard --text -"

[rule.no-published-markers.command]
before = ["faux"]

[rule.prevent-ai-author]
builtin = "prevent-ai-author"

[rule.prevent-ai-author.git]
hooks = ["commit-msg"]
"#;

/// A workspace with a policy, this binary on PATH under its own name, and the
/// stub commands one case needs.
fn workspace(policy: &str, stubs: &[(&str, &str)]) -> PathBuf {
    let root = support::scratch("shim-handoff");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    std::fs::create_dir_all(root.join("bin")).unwrap();
    std::fs::write(root.join("policy/principles.toml"), policy).unwrap();
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), root.join("bin/uphold")).unwrap();

    for (name, script) in stubs {
        let path = root.join("bin").join(name);
        std::fs::write(&path, script).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        std::fs::set_permissions(&path, permissions).unwrap();
    }

    Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(&root)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    root
}

/// One invocation of the shim, with everything a case needs to vary about it.
#[derive(Debug)]
struct Run<'a> {
    args: &'a [&'a str],
    envs: &'a [(&'a str, &'a str)],
    stdin: Option<&'a [u8]>,
    /// Run under `timeout`, so a case that regresses into a deadlock reports a
    /// failure instead of hanging the suite forever. Switched off for the case
    /// that asserts on HOW the command died: `timeout` waits on a child and
    /// reports a signal death as an ordinary exit code, which is the very thing
    /// that case exists to catch.
    guarded: bool,
}

impl Default for Run<'_> {
    fn default() -> Self {
        Self {
            args: &[],
            envs: &[],
            stdin: None,
            guarded: true,
        }
    }
}

impl Run<'_> {
    fn go(&self, root: &Path) -> Output {
        let path = format!(
            "{}:{}",
            root.join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        // `timeout` is GNU coreutils and is not on a stock macOS or BSD, where
        // `Command::new("timeout")` fails to spawn and every guarded case would
        // fail for the environment rather than for the shim. Its whole job here
        // is to turn a deadlock into a failure instead of a suite that hangs, so
        // where it is missing the test still runs and a regression shows up as a
        // hang rather than as a named failure -- worse, and better than a red
        // suite on a machine that has nothing wrong with it.
        let mut command = if self.guarded && has_timeout() {
            let mut guarded = Command::new("timeout");
            guarded.arg("60").arg(env!("CARGO_BIN_EXE_uphold"));
            guarded
        } else {
            Command::new(env!("CARGO_BIN_EXE_uphold"))
        };
        command
            .arg("shim")
            .args(self.args)
            .current_dir(root)
            .env("PATH", path)
            .env_remove("UPHOLD_ALLOW")
            // The editor variables this shim sets on its way through. A test
            // machine that has them set for its own reasons would otherwise be
            // answering the question instead of the code.
            .env_remove("UPHOLD_SHIM_EDITOR")
            .env_remove("UPHOLD_SHIM_EDITOR_REAL")
            .env_remove("UPHOLD_SHIM_EDITOR_ARGV")
            .env_remove("GIT_EDITOR")
            .env_remove("VISUAL")
            .env_remove("EDITOR");
        for (name, value) in self.envs {
            command.env(name, value);
        }
        // Its own process group, and everything left in it is killed when the
        // run returns. `timeout` ends the process it started; it cannot end the
        // ones that process left behind, and what these cases drive is a shim
        // that RUNS things -- an editor, a checker, `git`. A regression that
        // spawns without end therefore outlived both the timeout and the suite:
        // one arrived as tens of thousands of orphaned `git` processes reparented
        // to init, on a developer machine, until the kernel ran out of process
        // ids. A test that can wedge the machine it is run on does not get to
        // rely on the code under test terminating.
        command.process_group(0);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        let group = child.id();
        let mut stdin = child.stdin.take().unwrap();
        if let Some(bytes) = self.stdin {
            stdin
                .write_all(bytes)
                .expect("the shim reads its stdin whole before it writes anything");
        }
        // Closed either way: a command that reads stdin and is handed a pipe
        // nobody closes waits for input that is not coming.
        drop(stdin);

        // Drained on threads, and the group killed on the DIRECT child's exit
        // rather than on end of file. The pipes are inherited, so a descendant
        // that outlives the process `timeout` killed is still holding the write
        // end: waiting for end of file first is waiting for the runaway to
        // finish, which is the hang this whole arrangement exists to end.
        // Reading has to happen on another thread all the same -- a child that
        // fills a pipe nobody is draining stops, and would never reach the exit
        // this waits for.
        let mut out = child.stdout.take().unwrap();
        let mut err = child.stderr.take().unwrap();
        let output = std::thread::scope(|scope| {
            let reading_out = scope.spawn(move || {
                let mut bytes = Vec::new();
                out.read_to_end(&mut bytes).ok();
                bytes
            });
            let reading_err = scope.spawn(move || {
                let mut bytes = Vec::new();
                err.read_to_end(&mut bytes).ok();
                bytes
            });
            let status = child.wait().unwrap();
            quell(group);
            Output {
                status,
                stdout: reading_out.join().unwrap(),
                stderr: reading_err.join().unwrap(),
            }
        });
        output
    }
}

/// Kill everything left in one run's process group.
fn quell(group: u32) {
    Command::new("pkill")
        .args(["-9", "-g", &group.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok();
}

/// Is GNU `timeout` on this machine to wrap a case that could hang?
fn has_timeout() -> bool {
    Command::new("timeout")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn code(output: &Output) -> i32 {
    // 124 is `timeout` saying the run never finished, which is a deadlock
    // reported rather than waited on.
    output.status.code().unwrap_or(-1)
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn the_stdin_a_shim_read_is_handed_to_the_command_it_took_it_from() {
    // The shim reads stdin to have a subject at all, and the real command reads
    // the same stdin to have a body. Only one of them can, so the bytes have to
    // be handed on -- a guard that eats the body it approved publishes an empty
    // one under a title nobody notices is alone.
    let root = workspace(
        &format!(
            r#"{MARKER_RULE}
[[shim]]
command = "faux"
match = ["pr:create"]
file_flags = ["-F", "--body-file"]
scope = "always"
"#
        ),
        &[(
            "faux",
            // `tr -d ' '` because BSD and macOS `wc` pad the count with leading
            // spaces where GNU does not, so the printed line would not match the
            // length asserted below for a reason that has nothing to do with the
            // shim.
            "#!/bin/sh\necho \"faux ran: $*\"\necho \"faux body bytes: $(wc -c | tr -d ' ')\"\n",
        )],
    );

    // Well past the ~64 KiB a pipe holds, because that is the size at which a
    // replay through one would have quietly become a deadlock instead.
    let body = "ordinary release note text\n".repeat(4_000);
    let output = Run {
        args: &["faux", "pr", "create", "-F", "-"],
        stdin: Some(body.as_bytes()),
        ..Run::default()
    }
    .go(&root);

    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stdout(&output).contains(&format!("faux body bytes: {}", body.len())),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_body_that_is_refused_on_stdin_never_reaches_the_command() {
    let root = workspace(
        &format!(
            r#"{MARKER_RULE}
[[shim]]
command = "faux"
match = ["pr:create"]
file_flags = ["-F", "--body-file"]
scope = "always"
"#
        ),
        &[("faux", "#!/bin/sh\necho \"faux ran: $*\"\n")],
    );
    let output = Run {
        args: &["faux", "pr", "create", "-F", "-"],
        stdin: Some(b"Generated with Claude Code\n"),
        ..Run::default()
    }
    .go(&root);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("faux ran:"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_long_subject_and_a_loud_checker_do_not_wait_on_each_other() {
    // A pipe holds about 64 KiB. Writing the subject first and reading the
    // checker's output afterwards means each side blocks on the other, forever,
    // with nothing printed -- and the sizes that trigger it are ordinary: a
    // release note and a checker that echoes what it read.
    let root = workspace(
        r#"
[rule.loud]
message = "x"
exec = "yes noise | head -n 40000; cat > /dev/null"

[rule.loud.command]
before = ["faux"]

[[shim]]
command = "faux"
match = ["pr:create"]
file_flags = ["-F"]
scope = "always"
"#,
        &[("faux", "#!/bin/sh\necho \"faux ran: $*\"\n")],
    );
    std::fs::write(
        root.join("body.md"),
        "an ordinary paragraph of release note\n".repeat(6_000),
    )
    .unwrap();

    let output = Run {
        args: &["faux", "pr", "create", "-F", "body.md"],
        ..Run::default()
    }
    .go(&root);
    assert_eq!(
        code(&output),
        0,
        "124 means it never finished: {}",
        stderr(&output)
    );
    assert!(stdout(&output).contains("faux ran:"), "{}", stdout(&output));
}

#[test]
fn a_command_killed_by_a_signal_reports_a_signal_and_not_an_exit_code() {
    // `exit(status.code().unwrap_or(1))` flattened every death by a signal into
    // a plain exit 1, which in this tool's vocabulary is a policy violation --
    // so a caller that pressed Ctrl-C read "the guard refused". A real exec has
    // nothing to flatten: the shim IS the command by then.
    let root = workspace(
        &format!(
            r#"{MARKER_RULE}
[[shim]]
command = "faux"
match = ["pr:create"]
text_flags = ["-t"]
scope = "always"
"#
        ),
        &[("faux", "#!/bin/sh\nkill -TERM $$\n")],
    );
    let output = Run {
        args: &["faux", "pr", "create", "-t", "An ordinary title"],
        guarded: false,
        ..Run::default()
    }
    .go(&root);
    assert_eq!(output.status.code(), None, "{}", stderr(&output));
    assert_eq!(output.status.signal(), Some(15), "{}", stderr(&output));
}

#[test]
fn an_option_before_the_subcommand_does_not_switch_the_shim_off() {
    // Read positionally, `faux --repo acme/widget issue create` has the verb
    // `--repo`, matches no entry, and execs a publishing command unexamined --
    // silently, and with an exit code of 0.
    let root = workspace(
        &format!(
            r#"{MARKER_RULE}
[[shim]]
command = "faux"
match = ["pr:create", "issue:*"]
text_flags = ["-t", "--title"]
target_flags = ["-R", "--repo"]
scope = "always"
"#
        ),
        &[("faux", "#!/bin/sh\necho \"faux ran: $*\"\n")],
    );
    for form in [
        vec![
            "faux",
            "--repo",
            "acme/widget",
            "issue",
            "create",
            "-t",
            "Generated with Claude Code",
        ],
        vec![
            "faux",
            "--repo=acme/widget",
            "pr",
            "create",
            "-t",
            "Generated with Claude Code",
        ],
    ] {
        let output = Run {
            args: &form,
            ..Run::default()
        }
        .go(&root);
        assert_eq!(code(&output), 1, "{form:?}: {}", stderr(&output));
        assert!(!stdout(&output).contains("faux ran:"), "{form:?}");
    }
}

/// A command that writes its body in an editor, which is how most bodies are
/// actually written: no text in argv, and none until the editor closes.
const EDITING_COMMAND: &str = "#!/bin/sh\nfile=\"$PWD/body.md\"\n: > \"$file\"\nsh -c \"$FAUX_EDITOR \\\"$file\\\"\" || exit $?\necho \"faux published: $(cat \"$file\")\"\n";

const EDITOR_POLICY: &str = r#"
[[shim]]
command = "faux"
match = ["pr:create"]
text_flags = ["-t", "--title", "-b", "--body"]
skip_flags = ["--fill"]
web_flags = ["-w", "--web"]
editor_env = "FAUX_EDITOR"
scope = "always"
"#;

#[test]
fn a_body_typed_into_an_editor_is_read_when_the_editor_closes() {
    // The path uphold only warned about. cmd-shims installed itself as the
    // command's own editor variable and read the file back; warning instead
    // leaves the text unchecked and tells somebody who did nothing wrong to do
    // it differently.
    let root = workspace(
        &format!("{MARKER_RULE}{EDITOR_POLICY}"),
        &[
            ("faux", EDITING_COMMAND),
            (
                "dirty-editor",
                "#!/bin/sh\nprintf 'Generated with Claude Code\\n' > \"$1\"\n",
            ),
        ],
    );
    let editor = root.join("bin/dirty-editor");
    let output = Run {
        args: &["faux", "pr", "create"],
        envs: &[("EDITOR", &editor.to_string_lossy())],
        ..Run::default()
    }
    .go(&root);

    assert_ne!(code(&output), 0, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("faux published:"),
        "{}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("no-published-markers"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_editor_that_writes_something_ordinary_is_left_alone() {
    // The half that is easy to lose. A checkpoint that refuses everything is
    // not a checkpoint, and the command still has to run.
    let root = workspace(
        &format!("{MARKER_RULE}{EDITOR_POLICY}"),
        &[
            ("faux", EDITING_COMMAND),
            (
                "clean-editor",
                "#!/bin/sh\nprintf 'An ordinary body\\n' > \"$1\"\n",
            ),
        ],
    );
    let editor = root.join("bin/clean-editor");
    let output = Run {
        args: &["faux", "pr", "create"],
        envs: &[("EDITOR", &editor.to_string_lossy())],
        ..Run::default()
    }
    .go(&root);

    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stdout(&output).contains("faux published: An ordinary body"),
        "{}",
        stdout(&output)
    );
}

/// A checker that is a BUILT-IN rather than a program this repository names.
const BUILTIN_RULE: &str = r#"
[rule.no-private-repo-names]
builtin = "no-private-repo-names"
visibility = "public"
private_owners = ["acme-private"]

[rule.no-private-repo-names.command]
before = ["faux"]
"#;

#[test]
fn a_builtin_checker_stands_at_the_editor_checkpoint_as_well() {
    // The editor round trip consulted `exec` rules and nothing else, so a
    // repository whose checker for this command is a built-in got a checkpoint
    // with nobody standing at it: the shim installed itself as the editor, ran
    // it, read the file back, consulted zero rules and exited 0. That is the
    // same guard judging a body one way through `--body` and another through the
    // editor, under one id.
    let root = workspace(
        &format!("{BUILTIN_RULE}{EDITOR_POLICY}"),
        &[
            ("faux", EDITING_COMMAND),
            (
                "private-editor",
                "#!/bin/sh\nprintf 'this fixes acme-private/thing\\n' > \"$1\"\n",
            ),
        ],
    );
    let editor = root.join("bin/private-editor");
    let output = Run {
        args: &["faux", "pr", "create"],
        envs: &[("EDITOR", &editor.to_string_lossy())],
        ..Run::default()
    }
    .go(&root);

    assert_ne!(code(&output), 0, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("faux published:"),
        "{}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("acme-private"),
        "{}",
        stderr(&output)
    );
}

/// A checker that names one command line, standing in front of a shim that
/// names more than one.
const NARROWED_RULE: &str = r#"
[rule.no-published-markers]
message = "remove the marker"
exec = "uphold guard --text -"

[rule.no-published-markers.command]
before = ["faux pr create"]
"#;

#[test]
fn an_editor_checkpoint_with_nothing_to_consult_is_not_a_pass() {
    // Re-entered as the editor for a command line no rule stands in front of --
    // here because the argv the editor was opened for did not survive into this
    // process, which is how the checkers that ran on the way in are chosen. The
    // body exists by now and nobody is left to read it, so exit 2: the command
    // abandons what it was doing on any non-zero, and a body read by nothing
    // must not leave here looking like a body that passed.
    let root = workspace(
        &format!("{NARROWED_RULE}{EDITOR_POLICY}"),
        &[
            ("faux", EDITING_COMMAND),
            (
                "clean-editor",
                "#!/bin/sh\nprintf 'An ordinary body\\n' > \"$1\"\n",
            ),
        ],
    );
    let editor = root.join("bin/clean-editor");
    let output = Run {
        // `--as-editor` is what says this process IS the editor. It used to be
        // an environment variable, which every child of the checking pass
        // inherited: see `an_editor_pass_does_not_re_enter_the_git_it_runs`.
        args: &["--as-editor", "faux", "body.md"],
        envs: &[("UPHOLD_SHIM_EDITOR_REAL", &editor.to_string_lossy())],
        ..Run::default()
    }
    .go(&root);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("nothing would have been checked"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_body_given_on_the_command_line_does_not_open_an_editor_at_all() {
    // The editor is installed for the one case that needs it. A body already in
    // argv has been read, and re-entering through an editor that nobody opened
    // would be a second checkpoint on text that passed the first.
    let root = workspace(
        &format!("{MARKER_RULE}{EDITOR_POLICY}"),
        &[("faux", "#!/bin/sh\necho \"faux editor: [$FAUX_EDITOR]\"\n")],
    );
    let output = Run {
        args: &["faux", "pr", "create", "-b", "An ordinary body"],
        ..Run::default()
    }
    .go(&root);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stdout(&output).contains("faux editor: []"),
        "{}",
        stdout(&output)
    );
}

/// The GitLab visibility endpoint, and a stub that publishes.
const GITLAB_COMMAND: &str = "#!/bin/sh\nif [ \"$1\" = api ]; then\n  printf '{\"id\":7,\"visibility\":\"%s\"}\\n' \"${FAKE_VISIBILITY:-public}\"\n  exit 0\nfi\necho \"glab ran: $*\"\n";

const GITLAB_POLICY: &str = r#"
[rule.no-published-markers]
message = "remove the marker"
exec = "uphold guard --text -"

[rule.no-published-markers.command]
before = ["glab"]

[rule.prevent-ai-author]
builtin = "prevent-ai-author"

[rule.prevent-ai-author.git]
hooks = ["commit-msg"]

[[shim]]
command = "glab"
match = ["mr:create"]
text_flags = ["-t", "--title", "-d", "--description"]
target_flags = ["-R", "--repo"]
target = "forge-repo"
scope = "public-target"
"#;

#[test]
fn a_gitlab_target_is_asked_of_gitlab() {
    // `gh api repos/<owner>/<repo>` answers about GitHub and about nothing
    // else, so the shipped `glab` shim -- declared `public-target` -- resolved
    // nothing on every invocation and was inert.
    let root = workspace(GITLAB_POLICY, &[("glab", GITLAB_COMMAND)]);
    let output = Run {
        args: &[
            "glab",
            "mr",
            "create",
            "-R",
            "acme/widget",
            "-t",
            "Generated with Claude Code",
        ],
        envs: &[("FAKE_VISIBILITY", "public")],
        ..Run::default()
    }
    .go(&root);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("glab ran:"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_gitlab_project_that_is_internal_is_not_public() {
    // `internal` is not public to the internet but is public to everyone with
    // an account, and that distinction is the reason this scope reads one word
    // rather than a boolean.
    let root = workspace(GITLAB_POLICY, &[("glab", GITLAB_COMMAND)]);
    let output = Run {
        args: &[
            "glab",
            "mr",
            "create",
            "-R",
            "acme/widget",
            "-t",
            "Generated with Claude Code",
        ],
        envs: &[("FAKE_VISIBILITY", "internal")],
        ..Run::default()
    }
    .go(&root);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("glab ran:"), "{}", stdout(&output));
}

#[test]
fn an_editor_pass_does_not_re_enter_the_git_it_runs() {
    // The fork bomb. The editor re-entry was routed by an environment variable,
    // and an environment reaches every descendant: the checkers this pass
    // consults run `git`, and on a machine that installed the shim the way
    // `README.md` describes, `git` on PATH IS this binary under a link. That
    // child read the marker, decided it was somebody's editor, ran the user's
    // editor on whatever its last argument happened to be, consulted the same
    // checkers, ran `git` again -- and did not stop. It wedged this suite for
    // sixty seconds on a developer machine while passing in CI, where no such
    // link exists, which is the whole reason the link is planted here.
    let root = workspace(
        &format!("{BUILTIN_RULE}{EDITOR_POLICY}"),
        &[
            ("faux", EDITING_COMMAND),
            (
                "private-editor",
                "#!/bin/sh\nprintf 'this fixes acme-private/thing\\n' > \"$1\"\n",
            ),
        ],
    );
    // The install this repository documents: a link named for the command,
    // ahead of the real one on PATH.
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), root.join("bin/git")).unwrap();
    std::fs::write(root.join("body.md"), "placeholder\n").unwrap();

    // A witness BEHIND the link, so the assertions can tell "no recursion" from
    // "no descendant". `no-private-repo-names` asks git which repository this is
    // before it judges anything, and that question is what the recursion rode:
    // the shim resolves `git`, skips its own link, and reaches this -- which
    // records the call and runs the real one. A run that never touches it proves
    // nothing about the path the fork bomb took.
    let behind = root.join("behind");
    std::fs::create_dir_all(&behind).unwrap();
    let witness = root.join("git-calls.log");
    let wrapper = behind.join("git");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\necho \"$@\" >> {}\nexec /usr/bin/git \"$@\"\n",
            witness.display()
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&wrapper).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(&wrapper, permissions).unwrap();

    let editor = root.join("bin/private-editor");
    // Written out rather than inherited, so the only `git` this run can reach is
    // the link and the witness behind it. A machine that has its own shim
    // installed would otherwise put a third one in the middle.
    let path = format!(
        "{}:{}:/usr/bin:/bin",
        root.join("bin").display(),
        behind.display()
    );
    let output = Run {
        args: &["--as-editor", "faux", "body.md"],
        envs: &[
            ("PATH", &path),
            ("UPHOLD_SHIM_EDITOR_REAL", &editor.to_string_lossy()),
            ("UPHOLD_SHIM_EDITOR_ARGV", "faux pr create"),
        ],
        ..Run::default()
    }
    .go(&root);

    // 124 is `timeout` reporting a run that never finished, which is what the
    // recursion looked like from here.
    assert_ne!(code(&output), 124, "the editor pass re-entered itself");
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("acme-private"),
        "{}",
        stderr(&output)
    );
    let calls = std::fs::read_to_string(&witness).unwrap_or_default();
    assert!(
        calls.contains("remote get-url origin"),
        "the checkers never ran a `git` through the link, so this case did not \
         exercise the path it is named for: {calls:?}"
    );
}
