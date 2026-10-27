//! The same applicable policy fixture through every supported publication path.
//! Process exits and the harness refusal document are different protocols; both
//! must distinguish refusal, permission and an unread required surface.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "The fixture drives processes; a harness failure is a test failure"
)]

mod support;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const POLICY: &str = r#"
[rule.publication-word]
message = "Remove the forbidden publication word."
prose_regexp = 'publication-forbidden-word'
files.include = ["."]
command.before = ["faux"]

[[shim]]
command = "faux"
match = ["pr:create"]
text_flags = ["-b", "--body"]
scope = "always"

# The hook's counterpart: the tool call is the same act as `faux`, so it is
# judged under the `faux` table's scope. A tool no table names is judged with
# its destination unknown, which refuses.
[[hook]]
tools = '^create_publication$'
shim = "faux"
"#;

fn workspace() -> PathBuf {
    let root = support::scratch("publication-paths");
    std::fs::create_dir_all(root.join("policy")).unwrap();
    std::fs::create_dir_all(root.join("bin")).unwrap();
    std::fs::write(root.join("policy/principles.toml"), POLICY).unwrap();
    let command = root.join("bin/faux");
    std::fs::write(&command, "#!/bin/sh\nprintf 'publication command ran\\n'\n").unwrap();
    let mut permissions = std::fs::metadata(&command).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(command, permissions).unwrap();
    root
}

fn invoke(root: &Path, args: &[&str], input: &str, editor: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
    command
        .args(args)
        .current_dir(root)
        .env(
            "PATH",
            format!(
                "{}:{}",
                root.join("bin").display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("HOME", "/srv/example")
        .env_remove("UPHOLD_ALLOW")
        .env_remove("UPHOLD_SHIM_INNER")
        .env_remove("GH_REPO")
        .env_remove("GH_HOST")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if editor {
        std::fs::write(root.join("body.md"), input).unwrap();
        command
            .env("UPHOLD_SHIM_EDITOR_REAL", "true")
            .env("UPHOLD_SHIM_EDITOR_ARGV", "pr create");
    }
    let mut child = command.spawn().unwrap();
    if let Err(error) = child.stdin.take().unwrap().write_all(input.as_bytes()) {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    child.wait_with_output().unwrap()
}

#[test]
fn one_publication_fixture_is_refused_and_allowed_at_every_applicable_entry_path() {
    let root = workspace();
    for (text, refused) in [
        ("publication-forbidden-word", true),
        ("ordinary publication", false),
    ] {
        // Effect-by-entry-path matrix: each path reads the same prose and rule.
        // Hook permission is exit 0 plus an absent refusal document; process
        // seams use exit 1 for refusal. Shim permission also reaches handoff.
        for path in ["scan", "guard", "hook", "shim", "editor"] {
            let event =
                serde_json::json!({"tool_name":"create_publication", "tool_input":{"body":text}})
                    .to_string();
            let output = match path {
                "scan" => invoke(&root, &["scan", "--text", "-"], text, false),
                "guard" => invoke(&root, &["guard", "--text", "-"], text, false),
                "hook" => invoke(&root, &["hook", "codex"], &event, false),
                "shim" => invoke(
                    &root,
                    &["shim", "faux", "pr", "create", "-b", text],
                    "",
                    false,
                ),
                "editor" => invoke(
                    &root,
                    &["shim", "--as-editor", "faux", "body.md"],
                    text,
                    true,
                ),
                _ => unreachable!(),
            };
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert_eq!(
                output.status.code(),
                Some(if path == "hook" {
                    0
                } else {
                    i32::from(refused)
                }),
                "{path}: {stderr}"
            );
            assert_eq!(
                stderr.contains("publication-word"),
                refused,
                "{path}: {stderr}"
            );
            if path == "hook" {
                if refused {
                    let document: serde_json::Value = serde_json::from_str(&stdout).unwrap();
                    assert_eq!(
                        document
                            .pointer("/hookSpecificOutput/permissionDecision")
                            .and_then(serde_json::Value::as_str),
                        Some("deny")
                    );
                } else {
                    assert!(stdout.is_empty(), "{stdout}");
                }
            }
            if path == "shim" {
                assert_eq!(
                    stdout.contains("publication command ran"),
                    !refused,
                    "{stdout}"
                );
            }
        }
    }
}

#[test]
fn unread_required_surfaces_never_report_permission() {
    let root = workspace();
    for path in ["scan", "guard", "hook", "shim"] {
        let output = match path {
            "scan" => invoke(&root, &["scan", "--text", "missing.txt"], "", false),
            "guard" => invoke(&root, &["guard", "--text", "missing.txt"], "", false),
            "hook" => invoke(
                &root,
                &["hook", "codex"],
                r#"{"tool_name":"create_publication"}"#,
                false,
            ),
            "shim" => {
                let policy = POLICY.replace("text_flags =", "file_flags = [\"-F\"]\ntext_flags =");
                std::fs::write(root.join("policy/principles.toml"), policy).unwrap();
                invoke(
                    &root,
                    &["shim", "faux", "pr", "create", "-F", "missing.txt"],
                    "",
                    false,
                )
            }
            _ => unreachable!(),
        };
        assert_eq!(
            output.status.code(),
            Some(2),
            "{path}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stdout.is_empty(),
            "{path}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}
