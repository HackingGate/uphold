//! CLI-level tests for `uphold shim`.
//!
//! Every case drives a real invocation and lets it exec through to a stub
//! command on PATH, because "checked and then ran the command" is the contract
//! -- a shim that refuses correctly and never execs has broken the command it
//! was standing in front of.

#![expect(
    clippy::let_underscore_must_use,
    clippy::shadow_unrelated,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// A shim whose scope is `always`, so the tests do not need a forge.
const POLICY: &str = r#"
[rule.no-published-markers]
message = "remove the marker"
exec = "uphold guard --text -"

# The shim under test, and only it. Naming the command here is what the
# scoping is: a checker used to be consulted by every declared shim, so this
# fixture would have exercised the rule even if the shim below were for a
# different command entirely.
[rule.no-published-markers.command]
before = ["faux"]

[rule.prevent-ai-author]
builtin = "prevent-ai-author"

[rule.prevent-ai-author.git]
hooks = ["commit-msg"]

[[shim]]
command = "faux"
match = ["pr:create", "issue:*"]
text_flags = ["-t", "--title", "-b", "--body"]
file_flags = ["-F", "--body-file"]
skip_flags = ["--fill"]
web_flags = ["-w", "--web"]
editor_env = "FAUX_EDITOR"
scope = "always"
"#;

fn workspace(policy: &str) -> PathBuf {
    let root = support::scratch("shim-cli");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("policy")).unwrap();
    std::fs::create_dir_all(root.join("bin")).unwrap();
    std::fs::write(root.join("policy/principles.toml"), policy).unwrap();

    // The checkers in this policy are the binary consulting itself, which is
    // the point of them -- the rule that judges a commit message and the rule
    // that judges a pull-request body are the same rule. So it has to be on
    // PATH under its own name, which the multicall entry then dispatches
    // normally.
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), root.join("bin/uphold")).unwrap();

    // The real command, which must be reached when nothing refuses.
    let stub = root.join("bin/faux");
    std::fs::write(&stub, "#!/bin/sh\necho \"faux ran: $*\"\n").unwrap();
    let mut permissions = std::fs::metadata(&stub).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(&stub, permissions).unwrap();

    Command::new(support::real_git())
        .args(["init", "-q", "-b", "main"])
        .current_dir(&root)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    root
}

fn shim(root: &Path, args: &[&str]) -> Output {
    let path = format!(
        "{}:{}",
        root.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .arg("shim")
        .args(args)
        .current_dir(root)
        .env("PATH", path)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap()
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

#[test]
fn a_clean_invocation_is_checked_and_then_actually_runs() {
    // The half that is easy to lose. A shim that refuses correctly and never
    // execs has broken the command it was standing in front of.
    let root = workspace(POLICY);
    let output = shim(&root, &["faux", "pr", "create", "-t", "An ordinary title"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"), "{}", stdout(&output));
}

#[test]
fn a_marker_in_a_title_is_refused_and_the_command_never_runs() {
    let root = workspace(POLICY);
    let output = shim(
        &root,
        &["faux", "pr", "create", "-t", "Generated with Claude Code"],
    );
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("faux ran:"),
        "{}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("Nothing was published"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_unnamed_subcommand_is_not_this_shims_business() {
    // Named rather than pattern-matched. `pr checkout` publishes nothing.
    let root = workspace(POLICY);
    let output = shim(
        &root,
        &["faux", "pr", "checkout", "-t", "Generated with Claude Code"],
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"));
}

#[test]
fn a_flag_is_read_in_both_spellings() {
    let root = workspace(POLICY);
    for form in [
        vec![
            "faux",
            "issue",
            "create",
            "--body=Generated with Claude Code",
        ],
        vec![
            "faux",
            "issue",
            "create",
            "--body",
            "Generated with Claude Code",
        ],
    ] {
        let output = shim(&root, &form);
        assert_eq!(code(&output), 1, "{form:?}: {}", stderr(&output));
    }
}

#[test]
fn a_body_file_is_read_and_a_skip_flag_is_not() {
    let root = workspace(POLICY);
    std::fs::write(root.join("body.md"), "Generated with Claude Code\n").unwrap();
    let output = shim(&root, &["faux", "pr", "create", "-F", "body.md"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));

    // `--fill` takes the body from commit messages, which commit-msg already
    // guarded on the way in.
    let output = shim(&root, &["faux", "pr", "create", "--fill"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_body_composed_in_an_editor_makes_the_editor_the_checkpoint() {
    // This case used to be the one thing a shim admitted it could not see: no
    // body in argv, no `--web`, and a command about to open an editor, so there
    // was nothing to hand a checker and the shim said so and execed. Saying so
    // leaves the text unchecked and tells somebody who did nothing wrong to do
    // it differently, so the shim now installs itself in the command's own
    // editor variable and reads the file back when the editor closes.
    //
    // The assertion is on what is HANDED to the command, because that is what
    // decides whether the checkpoint exists: the stub prints its environment,
    // and the shim's declared `editor_env` has to be pointing at this binary by
    // the time the command runs. `tests/shim_handoff_cli.rs` drives the whole
    // round trip with a real editor; this holds the near end of it.
    let root = workspace(POLICY);
    let stub = root.join("bin/faux");
    std::fs::write(
        &stub,
        "#!/bin/sh\necho \"faux ran: $*\"\necho \"editor: $FAUX_EDITOR\"\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&stub).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(&stub, permissions).unwrap();

    let output = shim(&root, &["faux", "pr", "create"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        // `--as-editor` is the word that routes the re-entry. It was an
        // environment variable, which every descendant of the checking pass
        // inherited -- see `an_editor_pass_does_not_re_enter_the_git_it_runs`.
        stdout(&output).contains("editor: ") && stdout(&output).contains("shim --as-editor 'faux'"),
        "the command was handed no checkpoint to open: {}",
        stdout(&output)
    );
    // And it says which checkpoint it is, rather than reporting a pass over
    // text nothing has read yet.
    assert!(
        stderr(&output).contains("the editor is the checkpoint"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn the_bypass_names_the_checker_it_switched_off() {
    let root = workspace(POLICY);
    let path = format!(
        "{}:{}",
        root.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args([
            "shim",
            "faux",
            "pr",
            "create",
            "-t",
            "Generated with Claude Code",
        ])
        .current_dir(&root)
        .env("PATH", path)
        .env("UPHOLD_ALLOW", "no-published-markers")
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"));
}

/// Asked BY NAME for a shim this repository does not have, and told so.
///
/// The other half of this pair lets the same reading through, and the two are
/// not in tension: what differs is what was asked. `uphold shim unknown ...` is
/// a question typed with an answer in mind, and nothing is standing in front of
/// anything, so the caller hears it rather than watching a typo run.
#[test]
fn a_command_no_shim_declares_is_refused_rather_than_silently_passed_through() {
    let root = workspace(POLICY);
    let output = shim(&root, &["unknown-command", "publish"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no shim declares"),
        "{}",
        stderr(&output)
    );
}

/// A link is on PATH for the whole machine; a `[[shim]]` is a line in one
/// repository's policy.
///
/// So the undeclared case is the ordinary one, not the exception: every
/// directory outside a participating repository reaches it, and so does every
/// participating repository that declares a shim for some OTHER command. While
/// that answer was an error, installing the link as the documentation describes
/// made the command exit 2 nearly everywhere it was typed -- and what gets
/// installed after that is nothing, which loses the seam in the repositories
/// that did declare it.
#[test]
fn a_command_this_policy_does_not_declare_still_runs_when_the_link_is_the_command() {
    let root = workspace(POLICY);
    // The real command, behind a link named for it. Two directories, because one
    // cannot hold two files of the same name -- and the link has to come first.
    std::fs::create_dir_all(root.join("front")).unwrap();
    let stub = root.join("bin/undeclared");
    std::fs::write(&stub, "#!/bin/sh\necho \"undeclared ran: $*\"\n").unwrap();
    let mut permissions = std::fs::metadata(&stub).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(&stub, permissions).unwrap();
    let link = root.join("front/undeclared");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), &link).unwrap();

    let path = format!(
        "{}:{}:{}",
        root.join("front").display(),
        root.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(&link)
        .args(["publish", "--now"])
        .current_dir(&root)
        .env("PATH", path)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stdout(&output).contains("undeclared ran: publish --now"),
        "{}{}",
        stdout(&output),
        stderr(&output)
    );
}

/// No policy where the command was typed is not a repository refusing; it is a
/// directory that declares nothing.
///
/// `/tmp`, somebody else's checkout, a shell that never enters a participating
/// repository -- a machine-wide link meets these far more often than it meets a
/// declaration. Refusing here protects nothing and breaks the command
/// everywhere.
#[test]
fn a_directory_with_no_policy_at_all_does_not_break_the_command() {
    let root = workspace(POLICY);
    // Outside `root`, deliberately: a subdirectory of it would find the policy
    // by walking up, which is the case this test is not about.
    let elsewhere = support::run_root().join(format!(
        "shim-no-policy-{}",
        root.file_name().unwrap().to_string_lossy()
    ));
    let _ = std::fs::remove_dir_all(&elsewhere);
    std::fs::create_dir_all(&elsewhere).unwrap();

    // Named for the stub, so PATH resolution finds the link first and the real
    // command second, exactly as an install puts them.
    std::fs::create_dir_all(root.join("front")).unwrap();
    let front = root.join("front/faux");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), &front).unwrap();

    let path = format!(
        "{}:{}:{}",
        root.join("front").display(),
        root.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(&front)
        .args(["pr", "create", "-t", "anything"])
        .current_dir(&elsewhere)
        .env("PATH", path)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stdout(&output).contains("faux ran:"),
        "{}{}",
        stdout(&output),
        stderr(&output)
    );
}

#[test]
fn a_checker_that_could_not_look_is_not_a_pass() {
    // Exit 2 is the third answer, and folding it into either of the others is
    // the failure `explicit-unknown` names.
    let root = workspace(
        r#"
[rule.cannot-look]
message = "x"
exec = "exit 2"

[rule.cannot-look.command]
before = ["faux"]

[[shim]]
command = "faux"
match = ["pr:create"]
text_flags = ["-t"]
scope = "always"
"#,
    );
    let output = shim(&root, &["faux", "pr", "create", "-t", "anything"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(!stdout(&output).contains("faux ran:"));
}

#[test]
fn the_binary_run_under_a_commands_name_is_that_commands_shim() {
    // The multicall entry, which is what ends the installer: there is nothing
    // to install but a link, and nothing to find but this binary.
    let root = workspace(POLICY);
    let link = root.join("bin/faux-link");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_uphold"), &link).unwrap();

    let mut policy = std::fs::read_to_string(root.join("policy/principles.toml")).unwrap();
    policy = policy.replace("command = \"faux\"", "command = \"faux-link\"");
    policy = policy.replace("before = [\"faux\"]", "before = [\"faux-link\"]");
    std::fs::write(root.join("policy/principles.toml"), policy).unwrap();

    let path = format!(
        "{}:{}",
        root.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(&link)
        .args(["pr", "create", "-t", "Generated with Claude Code"])
        .current_dir(&root)
        .env("PATH", path)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap();
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("Nothing was published"),
        "{}",
        stderr(&output)
    );
}

/// argv is bytes, and a shim that stands in front of `git` will be handed some.
///
/// `std::env::args()` PANICS on an argument that is not UTF-8 -- exit 101, out
/// of a binary whose whole promise is three exit codes and transparency. A file
/// named in latin-1 is an ordinary argument to `git add`, and this binary is
/// installed exactly where such a name gets typed. So the bytes go through
/// untouched where there is nothing to check, and where there IS something to
/// check the shim says it could not read them rather than checking a lossy copy.
#[test]
fn an_argument_that_is_not_text_reaches_the_command_it_was_typed_for() {
    use std::os::unix::ffi::OsStringExt;

    let root = workspace(POLICY);
    let path = format!(
        "{}:{}",
        root.join("bin").display(),
        std::env::var("PATH").unwrap_or_default()
    );
    // `caf\xe9`, which is a perfectly good file name and is not UTF-8.
    let latin1 = std::ffi::OsString::from_vec(b"caf\xe9.txt".to_vec());

    // `repo clone` is not in this shim's `match` list, so there is nothing to
    // check and nothing to stop: the command must run.
    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["shim", "faux", "repo", "clone"])
        .arg(&latin1)
        .current_dir(&root)
        .env("PATH", &path)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(
        stdout(&output).contains("faux ran: repo clone"),
        "{}",
        stdout(&output)
    );

    // `pr create` is, so the same bytes are now part of an invocation whose text
    // is checked. Exit 2: nothing was found and nothing was cleared.
    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["shim", "faux", "pr", "create", "-t"])
        .arg(&latin1)
        .current_dir(&root)
        .env("PATH", &path)
        .env_remove("UPHOLD_ALLOW")
        .output()
        .unwrap();
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("is not UTF-8 text"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stdout(&output).contains("faux ran:"),
        "{}",
        stdout(&output)
    );
}

/// A text-capable built-in standing in front of a command, with no `exec`
/// checker anywhere and no git hook.
///
/// The seam some guards belong at and could not name. `no-private-repo-names`
/// reads a commit message at every git hook, which refuses the issue citations
/// a repository's own prose is full of -- so a repository that wants it over a
/// pull-request body and NOWHERE else had no field to say it in, and three
/// wrote `command.before` on the built-in independently while the loader
/// refused all three.
const BUILTIN_CHECKER: &str = r#"
[[shim]]
command = "faux"
match = ["pr:create"]
text_flags = ["-t", "--title", "-b", "--body"]
scope = "always"

[rule.no-private-repo-names]
builtin = "no-private-repo-names"
visibility = "public"
private_owners = ["acme-private"]

[rule.no-private-repo-names.command]
before = ["faux"]
"#;

#[test]
fn a_text_capable_builtin_refuses_the_body_it_stands_in_front_of() {
    let root = workspace(BUILTIN_CHECKER);
    let output = shim(
        &root,
        &[
            "faux",
            "pr",
            "create",
            "-b",
            "this fixes acme-private/thing",
        ],
    );
    assert_eq!(code(&output), 1, "{}", stdout(&output));
    assert!(
        stderr(&output).contains("acme-private"),
        "{}",
        stderr(&output)
    );
    // Refused means not published: the real command must not have run.
    assert!(!stdout(&output).contains("faux ran"), "{}", stdout(&output));
}

#[test]
fn a_clean_body_reaches_the_real_command_through_a_builtin_checker() {
    let root = workspace(BUILTIN_CHECKER);
    let output = shim(&root, &["faux", "pr", "create", "-b", "an ordinary change"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran"), "{}", stdout(&output));
}

/// A `git` shim as the shipped policy declares it, with git's own global
/// grammar written nowhere in it.
const GIT_POLICY: &str = r#"
[rule.no-published-markers]
message = "remove the marker"
exec = "uphold guard --text -"

[rule.no-published-markers.command]
before = ["git"]

[rule.prevent-ai-author]
builtin = "prevent-ai-author"

[rule.prevent-ai-author.git]
hooks = ["commit-msg"]

[[shim]]
command = "git"
match = ["push:*"]
text_flags = ["-m"]
scope = "always"
"#;

/// A stub for a command the workspace does not install by default.
fn stub(root: &Path, name: &str, script: &str) {
    let path = root.join("bin").join(name);
    std::fs::write(&path, script).unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(&path, permissions).unwrap();
}

#[test]
fn a_git_global_option_before_the_subcommand_does_not_switch_the_shim_off() {
    // A `[[shim]]` table names the flags whose values it publishes; nothing in
    // one says what `git -c` does, and no repository should have to write git's
    // grammar into its policy to be guarded. Skipping only the table's flags,
    // `git -c user.name=x push ...` reads `user.name=x` as the verb -- no
    // `match` entry contains that, so a push to a public forge exec'd
    // unexamined, silently and with an exit code of 0.
    let root = workspace(GIT_POLICY);
    stub(&root, "git", "#!/bin/sh\necho \"git ran: $*\"\n");
    for form in [
        vec![
            "git",
            "-c",
            "user.name=x",
            "push",
            "-m",
            "Generated with Claude Code",
        ],
        vec![
            "git",
            "-C",
            "/somewhere/else",
            "push",
            "-m",
            "Generated with Claude Code",
        ],
        vec![
            "git",
            "--git-dir",
            "/elsewhere/.git",
            "push",
            "-m",
            "Generated with Claude Code",
        ],
    ] {
        let output = shim(&root, &form);
        assert_eq!(code(&output), 1, "{form:?}: {}", stderr(&output));
        assert!(!stdout(&output).contains("git ran:"), "{form:?}");
    }

    // And the half a looser matcher would lose: `-c` takes the word after it,
    // so `status` there is a value and not a subcommand this shim checks. Read
    // as a decision rather than as an ambiguity -- knowing git's grammar is
    // what keeps every `git -c ... status` on the machine quiet.
    let output = shim(&root, &["git", "-c", "user.name=push", "status"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("git ran:"), "{}", stdout(&output));
    assert!(
        !stderr(&output).contains("This is not a pass."),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_option_nothing_can_classify_is_said_out_loud_rather_than_passed_in_silence() {
    // TWO options nothing can classify, which is what leaves the subcommand
    // genuinely undetermined: `words` applies `unknown_takes_value` uniformly,
    // so two of them have four readings and exactly two are tried. Running the
    // command anyway is deliberate -- the link is on PATH for the whole
    // machine, and refusing every command that grows an option would make the
    // guard the reason work stops -- but running it in silence is the shape of
    // failure this tool refuses.
    let root = workspace(POLICY);
    let output = shim(
        &root,
        &["faux", "--fic-a", "x", "--fic-b", "y", "repo", "clone"],
    );
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"), "{}", stdout(&output));
    assert!(
        stderr(&output).contains("This is not a pass."),
        "{}",
        stderr(&output)
    );

    // And ONE is not a doubt, because the two readings are then the whole
    // space and both were asked. Said at this level as well as in the unit
    // test, because this line is the one a person actually sees: before #56 a
    // git shim declaring `push:*` printed the refusal over `git show --stat
    // HEAD`, `git commit -F -` and seven more of sixteen ordinary invocations,
    // and stayed quiet on `git push`.
    let output = shim(&root, &["faux", "--fictional", "value", "repo", "clone"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"), "{}", stdout(&output));
    assert!(
        !stderr(&output).contains("This is not a pass."),
        "{}",
        stderr(&output)
    );
}

/// A shim that names this invocation, and a checker that names another one.
///
/// The load refuses a `[[shim]]` whose command no rule names at all. This is
/// the same reading one invocation later: `faux pr create` is checked, and
/// `faux issue create` -- which the same `match` list names -- is collected,
/// consulted by nobody, and exec'd.
const NARROWED_CHECKER: &str = r#"
[rule.no-published-markers]
message = "remove the marker"
exec = "uphold guard --text -"

[rule.no-published-markers.command]
before = ["faux pr create"]

[[shim]]
command = "faux"
match = ["pr:create", "issue:*"]
text_flags = ["-t", "--title", "-b", "--body"]
scope = "always"
"#;

#[test]
fn an_invocation_no_checker_stands_in_front_of_is_not_a_pass() {
    let root = workspace(NARROWED_CHECKER);

    // The invocation a rule does name is checked, and runs.
    let output = shim(&root, &["faux", "pr", "create", "-t", "An ordinary title"]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains("faux ran:"), "{}", stdout(&output));

    // The one it does not is exit 2 and no command at all. A body collected and
    // consulted by nobody exits 0 otherwise, which is indistinguishable from a
    // body every checker approved.
    let output = shim(
        &root,
        &["faux", "issue", "create", "-t", "An ordinary title"],
    );
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        !stdout(&output).contains("faux ran:"),
        "{}",
        stdout(&output)
    );
    assert!(
        stderr(&output).contains("nothing would have been checked"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_builtin_checker_satisfies_the_shim_that_would_otherwise_check_nothing() {
    // The load refuses a shim no checker names, because a command collected and
    // consulted by nothing runs anyway -- an invocation that passed because
    // nothing looked at it. A built-in is a checker, and counting only `exec`
    // rules refused a policy whose shim WAS checked, by a guard rather than a
    // script.
    let root = workspace(BUILTIN_CHECKER);
    let output = shim(&root, &["faux", "--version"]);
    assert_eq!(code(&output), 0, "{}{}", stdout(&output), stderr(&output));
}

#[test]
fn a_policy_that_cannot_be_read_refuses_the_command_and_names_the_way_out() {
    // The trap this closes: with an unparseable policy, the shim refused every
    // invocation of the command it stands in front of -- including the `git
    // checkout` that would put the file back. The refusal is right. Being
    // unable to repair the declaration without knowing the real binary's path
    // is not.
    let root = workspace("this is not toml [[[\n");

    let refused = shim(&root, &["faux", "pr", "create", "-t", "a title"]);
    assert_eq!(code(&refused), 2, "{}", stderr(&refused));
    let text = stderr(&refused);
    assert!(text.contains("did not run"), "{text}");
    assert!(text.contains("UPHOLD_ALLOW=all"), "{text}");

    // And the way out works, says so, and is not silent about it: a bypass that
    // became habit has to be visible in a shell history and a CI log.
    let allowed = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["shim", "faux", "pr", "create", "-t", "a title"])
        .current_dir(&root)
        .env(
            "PATH",
            format!(
                "{}:{}",
                root.join("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("UPHOLD_ALLOW", "all")
        .output()
        .unwrap();
    assert_eq!(allowed.status.code().unwrap(), 0, "{}", stderr(&allowed));
    assert!(
        String::from_utf8_lossy(&allowed.stdout).contains("faux ran"),
        "the real command did not run"
    );
    assert!(
        stderr(&allowed).contains("ran unchecked"),
        "{}",
        stderr(&allowed)
    );
}

#[test]
fn an_empty_allow_variable_switches_nothing_off() {
    // `UPHOLD_ALLOW=` is a variable somebody exported and then cleared. Read as
    // a list it is one empty field, and an early version of the whole-invocation
    // bypass answered yes to it -- which would have switched the seam off in
    // every shell that had ever set the variable.
    let root = workspace("this is not toml [[[\n");

    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["shim", "faux", "pr", "create", "-t", "a title"])
        .current_dir(&root)
        .env(
            "PATH",
            format!(
                "{}:{}",
                root.join("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("UPHOLD_ALLOW", "")
        .output()
        .unwrap();
    assert_eq!(output.status.code().unwrap(), 2, "{}", stderr(&output));
}
