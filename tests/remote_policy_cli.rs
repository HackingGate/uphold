//! Exercise the normal loader against real Git blobs, with network URLs
//! rewritten per child process to an isolated local policy repository.
#![expect(
    clippy::let_underscore_must_use,
    clippy::indexing_slicing,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "CLI fixtures report failures by assertions"
)]
mod support;

use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture {
    root: PathBuf,
    source: PathBuf,
    config: PathBuf,
    rev: String,
}

impl Fixture {
    fn new(text: &str) -> Self {
        let root = support::scratch("remote-policy");
        let source = root.join("source");
        std::fs::create_dir_all(source.join("policy")).unwrap();
        support::git(&source, &["init", "-q", "-b", "main"]);
        support::git(&source, &["config", "user.name", "Test"]);
        support::git(&source, &["config", "user.email", "test@example.test"]);
        std::fs::write(source.join("policy/org.toml"), text).unwrap();
        support::git(&source, &["add", "."]);
        support::git(&source, &["commit", "-qm", "policy"]);
        let answer = support::git_command(&source)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        let rev = String::from_utf8(answer.stdout).unwrap().trim().to_owned();
        let config = root.join("gitconfig");
        std::fs::write(
            &config,
            format!(
                "[url \"file://{}\"]\n insteadOf = https://github.com/example/policy.git\n",
                source.display()
            ),
        )
        .unwrap();
        std::fs::create_dir_all(root.join("consumer/policy")).unwrap();
        support::git(&root.join("consumer"), &["init", "-q", "-b", "main"]);
        let fixture = Self {
            root,
            source,
            config,
            rev,
        };
        fixture.policy("");
        fixture
    }

    fn repin(&mut self) {
        support::git(&self.source, &["add", "."]);
        support::git(&self.source, &["commit", "-qm", "update"]);
        let output = support::git_command(&self.source)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .clone_into(&mut self.rev);
        self.policy("");
    }

    fn policy(&self, suffix: &str) {
        self.with_remote("example/policy", &self.rev, "policy/org.toml", suffix);
    }

    fn with_remote(&self, repo: &str, rev: &str, path: &str, suffix: &str) {
        std::fs::write(self.root.join("consumer/policy/principles.toml"), format!(
            "[inherit]\nremote = [{{ repo = {repo:?}, rev = {rev:?}, path = {path:?} }}]\n{suffix}"
        )).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_uphold"));
        command
            .args(args)
            .current_dir(self.root.join("consumer"))
            .env("GIT_CONFIG_GLOBAL", &self.config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0");
        support::without_git_environment(&mut command);
        // Every load also exercises the environment exported to a Git hook.
        command.env("GIT_DIR", self.root.join("consumer/.git"));
        command.output().unwrap()
    }
}

const RULE: &str = "[rule.org-rule]\nregexp = 'ORG_BANNED'\nmessage = 'organization rule'\n[rule.org-rule.files]\nexclude = ['policy/**']\n";

#[test]
fn remote_rules_run_keep_provenance_and_accept_overrides() {
    let fixture = Fixture::new(RULE);
    fixture.policy("[override.org-rule]\nmessage = 'local wording'\n[override.org-rule.files]\nexclude = ['policy/**', 'skip.txt']\n");
    let output = fixture.run(&["rules", "--effective", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rules: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rules[0]["remote"]["rev"], fixture.rev);
    assert_eq!(rules[0]["remote"]["repo"], "example/policy");
    assert_eq!(rules[0]["remote"]["path"], "policy/org.toml");
    assert!(
        rules[0]["overridden"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("message"))
    );
    std::fs::write(fixture.root.join("consumer/skip.txt"), "ORG_BANNED").unwrap();
    support::git(&fixture.root.join("consumer"), &["add", "."]);
    let clean = fixture.run(&["scan"]);
    assert_eq!(
        clean.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    std::fs::write(fixture.root.join("consumer/hit.txt"), "ORG_BANNED").unwrap();
    support::git(&fixture.root.join("consumer"), &["add", "."]);
    let refused = fixture.run(&["scan"]);
    assert_eq!(
        refused.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        format!(
            "{}{}",
            String::from_utf8_lossy(&refused.stdout),
            String::from_utf8_lossy(&refused.stderr)
        )
        .contains("local wording"),
        "{refused:?}"
    );
}

#[test]
fn disabled_and_own_rules_use_the_same_remote_snapshot() {
    let fixture = Fixture::new(RULE);
    fixture.policy("disabled_rules = ['org-rule']\n");
    let output = fixture.run(&["rules", "--effective", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!([])
    );
    fixture.policy(
        "[rule.org-rule]\nregexp = 'LOCAL_BANNED'\nmessage = 'own rule'\nfiles.include = ['.']\nfiles.exclude = ['policy/**']\n",
    );
    let own_output = fixture.run(&["rules", "--effective", "--json"]);
    assert_eq!(
        own_output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&own_output.stderr)
    );
    let rules: serde_json::Value = serde_json::from_slice(&own_output.stdout).unwrap();
    assert!(rules[0].get("remote").is_none());
}

#[test]
fn a_changed_source_cannot_change_the_pinned_policy() {
    let fixture = Fixture::new(RULE);
    std::fs::write(
        fixture.source.join("policy/org.toml"),
        "[rule.replacement]\nregexp = 'NEW'\nmessage = 'new rule'\n",
    )
    .unwrap();
    support::git(&fixture.source, &["add", "."]);
    support::git(&fixture.source, &["commit", "-qm", "change"]);
    let output = fixture.run(&["rules", "--effective", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rules: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rules[0]["id"], "org-rule");
}

#[test]
fn missing_commits_files_and_unreachable_repositories_fail_closed() {
    let fixture = Fixture::new(RULE);
    for (rev, path) in [
        (
            "1111111111111111111111111111111111111111",
            "policy/org.toml",
        ),
        (fixture.rev.as_str(), "policy/missing.toml"),
    ] {
        fixture.with_remote("example/policy", rev, path, "");
        let output = fixture.run(&["rules", "--effective", "--json"]);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(output.stdout, Vec::<u8>::new());
        assert!(String::from_utf8_lossy(&output.stderr).contains("pinned commit"));
    }
    fixture.policy("");
    std::fs::remove_dir_all(&fixture.source).unwrap();
    let output = fixture.run(&["rules", "--effective", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, Vec::<u8>::new());
}

#[test]
fn mutable_pins_and_unsafe_paths_are_refused_before_network_access() {
    let fixture = Fixture::new(RULE);
    for (repo, rev, path, field) in [
        ("example/policy", "main", "policy/org.toml", "rev"),
        ("example/policy", "v1", "policy/org.toml", "rev"),
        (
            "https://example.test/policy",
            fixture.rev.as_str(),
            "policy/org.toml",
            "repo",
        ),
        (
            "example/policy",
            fixture.rev.as_str(),
            "../org.toml",
            "path",
        ),
        ("example/policy", fixture.rev.as_str(), "/org.toml", "path"),
    ] {
        fixture.with_remote(repo, rev, path, "");
        let output = fixture.run(&["rules", "--effective"]);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(&format!("inherit.remote.{field}"))
        );
    }
}

#[test]
fn inherited_shims_and_transitive_inheritance_are_explicit_errors() {
    for (text, evidence) in [
        (
            "[[shim]]\ncommand = 'gh'\nmatch = ['api:*']\n",
            "shims are not adopted",
        ),
        (
            "[inherit]\nsets = ['process-residue']\n",
            "may not declare `[inherit]`",
        ),
    ] {
        let fixture = Fixture::new(text);
        let output = fixture.run(&["rules", "--effective"]);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(evidence),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn invalid_remote_content_is_never_a_partial_policy() {
    for bytes in [b"[rule.broken".as_slice(), b"\xff".as_slice()] {
        let mut fixture = Fixture::new(RULE);
        std::fs::write(fixture.source.join("policy/org.toml"), bytes).unwrap();
        fixture.repin();
        let output = fixture.run(&["rules", "--effective", "--json"]);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(output.stdout, Vec::<u8>::new());
    }
}

#[cfg(unix)]
#[test]
fn a_remote_symlink_is_not_a_policy_blob() {
    let mut fixture = Fixture::new(RULE);
    std::os::unix::fs::symlink("org.toml", fixture.source.join("policy/link.toml")).unwrap();
    fixture.repin();
    fixture.with_remote("example/policy", &fixture.rev, "policy/link.toml", "");
    let output = fixture.run(&["rules", "--effective", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, Vec::<u8>::new());
}

#[test]
fn a_magic_looking_remote_filename_is_read_literally() {
    let mut fixture = Fixture::new(RULE);
    std::fs::write(fixture.source.join("abc.toml"), RULE).unwrap();
    let literal = RULE.replace("org-rule", "literal-rule");
    std::fs::write(fixture.source.join(":(literal)abc.toml"), literal).unwrap();
    fixture.repin();
    fixture.with_remote("example/policy", &fixture.rev, ":(literal)abc.toml", "");
    let output = fixture.run(&["rules", "--effective", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rules: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rules[0]["id"], "literal-rule");
}

#[cfg(unix)]
#[test]
fn pathspec_magic_cannot_use_a_regular_files_mode_to_read_a_symlink() {
    let mut fixture = Fixture::new(RULE);
    // Without literal pathspecs, ls-tree checks abc.toml's regular-file mode
    // while rev:path reads this symlink's target bytes as valid TOML.
    std::fs::write(fixture.source.join("abc.toml"), RULE).unwrap();
    std::os::unix::fs::symlink(RULE, fixture.source.join(":(literal)abc.toml")).unwrap();
    fixture.repin();
    fixture.with_remote("example/policy", &fixture.rev, ":(literal)abc.toml", "");
    let output = fixture.run(&["rules", "--effective", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, Vec::<u8>::new());
}
