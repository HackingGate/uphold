//! CLI-level tests for `uphold scan`.
//!
//! Deliberately at the CLI and not at the function boundary. The thing being
//! preserved across the port from Python is what a caller SEES -- the exit code,
//! which rule fired, and which file and line it named -- and a test that reached
//! inside would pass on a refactor that changed all three.

#![expect(
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A CLI test asserts on the outcome; a panic in the harness that builds the fixture IS the failure report, and there is no caller to hand a Result to"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

fn workspace() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "uphold-scan-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(path.join("policy")).unwrap();
    path
}

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

fn write_bytes(root: &Path, relative: &str, contents: &[u8]) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, contents).unwrap();
}

fn scan(root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uphold"))
        .arg("scan")
        .current_dir(root)
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap()
}

// --- the seven kinds -------------------------------------------------------

#[test]
fn a_pattern_rule_names_the_file_and_the_line() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-todo]
        message = "no TODO"
        regexp = 'TODO'
        # The policy file writes the pattern, so it matches itself. This is the
        # reason every bundled rule carries the same exclusion.

        [rule.no-todo.files]
        exclude = ["policy/**"]
"#,
    );
    write(&root, "src/a.txt", "fine\nTODO: later\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("src/a.txt:2:TODO: later"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_multiline_pattern_spans_lines_and_a_single_line_one_does_not() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.block]
        message = "no block"
        regexp = '^start$[\s\S]*?^end$'

        [rule.block.files]
        multiline = true
"#,
    );
    write(&root, "a.txt", "start\nmiddle\nend\n");
    assert_eq!(code(&scan(&root)), 1);

    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.block]
        message = "no block"
        regexp = '^start$[\s\S]*?^end$'

        [rule.block.files]
"#,
    );
    assert_eq!(code(&scan(&root)), 0);
}

#[test]
fn a_size_rule_reports_the_count_and_the_limit() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.short-files]
        message = "too long"
        max_lines = 3

        [rule.short-files.files]
        glob = ["*.txt"]
"#,
    );
    write(&root, "long.txt", "1\n2\n3\n4\n5\n");
    write(&root, "short.txt", "1\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("long.txt: 5 lines (limit 3)"),
        "{}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("short.txt"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_path_rule_matches_the_path_and_not_the_content() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-traces]
        message = "no traces"
        path_regexp = '\.trace$'

        [rule.no-traces.files]
"#,
    );
    write(&root, "capture.trace", "innocent\n");
    write(&root, "notes.md", "capture.trace is mentioned here\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(text.contains("capture.trace"), "{text}");
    assert!(!text.contains("notes.md"), "{text}");
}

#[test]
fn a_require_rule_fails_on_the_file_that_is_missing_the_pattern() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.scripts-are-strict]
        message = "every script must set -euo pipefail"
        require_regexp = 'set -euo pipefail'

        [rule.scripts-are-strict.files]
        glob = ["*.sh"]
"#,
    );
    write(&root, "good.sh", "#!/bin/sh\nset -euo pipefail\n");
    write(&root, "bad.sh", "#!/bin/sh\necho hi\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(
        text.contains("bad.sh: required pattern not found"),
        "{text}"
    );
    assert!(!text.contains("good.sh"), "{text}");
}

#[test]
fn a_link_rule_separates_a_missing_target_from_one_outside_the_repository() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.links-resolve]
        builtin = "links-resolve"
        message = "fix the link"

        [rule.links-resolve.files]
        glob = ["*.md"]
"#,
    );
    write(
        &root,
        "README.md",
        "[a](gone.md)\n[b](../outside.md)\n[c](here.md)\n",
    );
    write(&root, "here.md", "hello\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(text.contains("gone.md -> no such file"), "{text}");
    assert!(
        text.contains("../outside.md -> outside the repository"),
        "{text}"
    );
    assert!(!text.contains("here.md ->"), "{text}");
}

#[test]
fn a_script_rule_admits_a_script_only_under_the_path_it_names() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        allowed_scripts = ["Latin"]

        [rule.japanese-docs]
        allowed_scripts = ["Latin", "Hiragana", "Katakana", "Han"]
        files.include = ["docs/ja"]
"#,
    );
    write(&root, "docs/ja/readme.md", "こんにちは\n");
    write(&root, "docs/en/readme.md", "hello\n");
    assert_eq!(code(&scan(&root)), 0);

    write(&root, "docs/en/oops.md", "こんにちは\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(text.contains("docs/en/oops.md"), "{text}");
    assert!(text.contains("HIRAGANA"), "{text}");
    assert!(!text.contains("docs/ja/readme.md"), "{text}");
}

#[test]
fn a_scoped_list_is_the_whole_truth_and_does_not_union_with_the_top_level() {
    // The old field silently ADDED the global declaration, so nothing beside
    // the rule said Latin was admitted in its files. Now the list beside the
    // path is the whole truth for the path: a scoped rule that omits Latin
    // refuses it, whatever the top level says.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        allowed_scripts = ["Latin"]

        [rule.kana-fixtures]
        allowed_scripts = ["Hiragana"]
        files.include = ["fixtures"]
"#,
    );
    write(&root, "fixtures/kana.txt", "かな\n");
    assert_eq!(code(&scan(&root)), 0);

    write(&root, "fixtures/mixed.txt", "latin\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(text.contains("fixtures/mixed.txt"), "{text}");
    assert!(text.contains("Latin"), "{text}");
}

#[test]
fn an_exclusive_rule_refuses_its_scripts_outside_its_paths() {
    // The reverse direction: Japanese text leaking into src/ fails, even with
    // no top-level declaration at all -- and the finding names the rule whose
    // exclusivity was violated.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        allowed_scripts = ["Latin"]

        [rule.ja-content-under-i18n]
        allowed_scripts = ["Latin", "Hiragana", "Katakana", "Han"]
        exclusive = true
        files.include = ["i18n"]
"#,
    );
    write(&root, "i18n/ja.md", "こんにちは\n");
    // Latin appears in the exclusive rule's list AND everywhere else -- the
    // top-level grant is what admits it outside i18n; exclusivity does not
    // revoke an explicit grant.
    write(&root, "src.txt", "plain latin\n");
    assert_eq!(code(&scan(&root)), 0);

    write(&root, "leaked.txt", "こんにちは\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(text.contains("ja-content-under-i18n"), "{text}");
    assert!(text.contains("leaked.txt"), "{text}");
    assert!(text.contains("exclusive"), "{text}");
}

#[test]
fn an_encoding_rule_holds_a_file_to_its_declared_charset() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.scrape-output-is-shift-jis]
        encoding = "Shift_JIS"
        message = "scrape output is Shift-JIS by contract"
        files.glob = ["scrape/**"]
"#,
    );
    // こんにちは, encoded as Shift_JIS.
    write_bytes(
        &root,
        "scrape/greeting.txt",
        b"\x82\xb1\x82\xf1\x82\xc9\x82\xbf\x82\xcd\n",
    );
    assert_eq!(code(&scan(&root)), 0);

    // A lead byte with an impossible trail byte decodes as nothing.
    write_bytes(&root, "scrape/corrupt.txt", b"\x82\x39\xff\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(text.contains("scrape/corrupt.txt"), "{text}");
    assert!(text.contains("does not decode as"), "{text}");
}

#[test]
fn an_unknown_charset_label_is_refused_at_load() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.bad-label]
        encoding = "Shift-JIS-2004-but-wrong"
        message = "no"
        files.include = ["."]
"#,
    );
    let output = scan(&root);
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("WHATWG"), "{}", stderr(&output));
}

#[test]
fn a_file_the_script_check_cannot_read_is_reported_not_skipped() {
    // The silent skip this check shipped with: a non-UTF-8 file under a script
    // declaration was passed over, so "clean" meant "unexamined". It is exit-2
    // territory now, with the three cures named.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        "allowed_scripts = [\"Latin\"]\n",
    );
    write_bytes(&root, "mystery.txt", b"\x82\xb1\x82\xf1\n");
    let output = scan(&root);
    assert_eq!(code(&output), 2);
    let text = stderr(&output);
    assert!(text.contains("mystery.txt"), "{text}");
    assert!(text.contains(".gitattributes"), "{text}");
}

#[test]
fn a_declared_encoding_lets_the_script_check_read_the_bytes() {
    // The two layers compose: the encoding rule says how the bytes decode, and
    // the script check judges the DECODED text -- so Shift-JIS Japanese under
    // a Latin-only script constraint is a script finding, not a silent skip
    // and not an unreadable file.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        allowed_scripts = ["Latin"]

        [rule.scrape-output-is-shift-jis]
        encoding = "Shift_JIS"
        message = "scrape output is Shift-JIS by contract"
        files.glob = ["scrape/**"]
"#,
    );
    write_bytes(
        &root,
        "scrape/greeting.txt",
        b"\x82\xb1\x82\xf1\x82\xc9\x82\xbf\x82\xcd\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(text.contains("scrape/greeting.txt"), "{text}");
    assert!(text.contains("Hiragana"), "{text}");
}

#[test]
fn a_dynamic_rule_searches_what_its_source_produced() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-host-identity]
        message = "do not commit host identity"
        forbidden_literals_from = "printf 'secret-host\n'"

        [rule.no-host-identity.files]
"#,
    );
    write(&root, "a.txt", "deployed to secret-host\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("no-host-identity (secret-host)"),
        "{}",
        stderr(&output)
    );
}

// --- baselines -------------------------------------------------------------

#[test]
fn a_baselined_path_is_allowed_and_a_new_one_is_not() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-todo]
        message = "no TODO"
        regexp = 'TODO'
        # The policy file writes the pattern, so it matches itself. This is the
        # reason every bundled rule carries the same exclusion.

        [rule.no-todo.files]
        exclude = ["policy/**"]
        baseline = "policy/todo-baseline.txt"
"#,
    );
    write(
        &root,
        "policy/todo-baseline.txt",
        "# grandfathered\nold.txt\n",
    );
    write(&root, "old.txt", "TODO: ancient\n");
    assert_eq!(code(&scan(&root)), 0);

    write(&root, "new.txt", "TODO: fresh\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(text.contains("new.txt"), "{text}");
    assert!(!text.contains("old.txt:"), "{text}");
}

#[test]
fn a_baseline_entry_that_no_longer_matches_is_reported_as_stale() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-todo]
        message = "no TODO"
        regexp = 'TODO'
        # The policy file writes the pattern, so it matches itself. This is the
        # reason every bundled rule carries the same exclusion.

        [rule.no-todo.files]
        exclude = ["policy/**"]
        baseline = "policy/todo-baseline.txt"
"#,
    );
    write(&root, "policy/todo-baseline.txt", "paid.txt\n");
    write(&root, "paid.txt", "clean now\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(text.contains("no-todo (stale baseline)"), "{text}");
    assert!(text.contains("paid.txt: no longer matches"), "{text}");
}

#[test]
fn a_require_baseline_goes_stale_the_other_way_round() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.must-say-ok]
        message = "say ok"
        require_regexp = 'ok'

        [rule.must-say-ok.files]
        glob = ["*.txt"]
        baseline = "policy/exempt.txt"
"#,
    );
    write(&root, "policy/exempt.txt", "fixed.txt\n");
    write(&root, "fixed.txt", "ok now\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(text.contains("must-say-ok (stale baseline)"), "{text}");
    assert!(text.contains("fixed.txt: satisfied or gone"), "{text}");
}

#[test]
fn a_size_baseline_pins_a_file_at_its_current_length() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.short-files]
        message = "too long"
        max_lines = 2

        [rule.short-files.files]
        glob = ["*.txt"]
        baseline = "policy/sizes.txt"
"#,
    );
    write(&root, "policy/sizes.txt", "legacy.txt 5\n");
    write(&root, "legacy.txt", "1\n2\n3\n4\n5\n");
    assert_eq!(code(&scan(&root)), 0);

    write(&root, "legacy.txt", "1\n2\n3\n4\n5\n6\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("legacy.txt: 6 lines (baseline 5; must not grow)"),
        "{}",
        stderr(&output)
    );
}

// --- scoping ---------------------------------------------------------------

#[test]
fn an_exclude_wins_over_an_earlier_include_glob() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-todo]
        message = "no TODO"
        regexp = 'TODO'

        [rule.no-todo.files]
        glob = ["*.txt"]
        exclude = ["**/fixtures/**"]
"#,
    );
    write(&root, "src/a.txt", "TODO\n");
    write(&root, "tests/fixtures/b.txt", "TODO\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(text.contains("src/a.txt"), "{text}");
    assert!(!text.contains("fixtures"), "{text}");
}

#[test]
fn a_dotfile_is_repository_content() {
    // ripgrep skips hidden files by default, which is why the security base
    // set's `.env` rules could never match the files their globs name.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-populated-env]
        message = "no values in a committed env file"
        regexp = '^[A-Z_]*TOKEN\s*=\s*\S'

        [rule.no-populated-env.files]
        glob = [".env", ".env.*"]
"#,
    );
    write(&root, ".env", "API_TOKEN=abc123\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    assert!(stderr(&output).contains(".env:1:"), "{}", stderr(&output));
}

#[test]
fn a_cfg_test_block_is_skipped_when_the_rule_opts_in() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-home-paths]
        message = "no home paths"
        regexp = '/home/[a-z]+'

        [rule.no-home-paths.files]
        exclude_cfg_test = true
"#,
    );
    write(
        &root,
        "src/lib.rs",
        "fn main() {}\n#[cfg(test)]\nmod tests {\n    const H: &str = \"/home/someone\";\n}\n",
    );
    assert_eq!(code(&scan(&root)), 0);

    write(
        &root,
        "src/other.rs",
        "const H: &str = \"/home/someone\";\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(text.contains("src/other.rs"), "{text}");
    assert!(!text.contains("src/lib.rs"), "{text}");
}

// --- redaction -------------------------------------------------------------

#[test]
fn redaction_withholds_the_match_and_keeps_the_location() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        redact_matches = true

        [rule.no-secret]
        message = "no secret"
        regexp = 'hunter2'

        [rule.no-secret.files]
"#,
    );
    write(&root, "a.txt", "password is hunter2\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(text.contains("a.txt:1: [REDACTED_MATCH]"), "{text}");
    assert!(!text.contains("hunter2"), "{text}");
}

// --- exit codes ------------------------------------------------------------

#[test]
fn a_clean_tree_exits_zero_and_says_so() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-todo]
        message = "no TODO"
        regexp = 'TODO'
        # The policy file writes the pattern, so it matches itself. This is the
        # reason every bundled rule carries the same exclusion.

        [rule.no-todo.files]
        exclude = ["policy/**"]
"#,
    );
    write(&root, "a.txt", "clean\n");
    let output = scan(&root);
    assert_eq!(code(&output), 0);
    assert!(stdout(&output).contains("policy checks passed"));
}

#[test]
fn a_policy_that_will_not_parse_exits_two_and_not_one() {
    // The distinction is the whole point. Exit 1 means the tool looked and found
    // something; exit 2 means it could not look. A caller that folds them
    // together reads a broken policy as a clean tree.
    let root = workspace();
    write(&root, "policy/principles.toml", "[rule.x]\n");
    let output = scan(&root);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("policy check error"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn ignore_literals_extends_the_suppression_list() {
    // The suppression used to be hard-coded and invisible: generic hostname
    // words were never searched for and nothing said so. The field is the same
    // suppression where the operator can see and extend it.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-lan-hostnames]
        message = "use neutral placeholders"
        forbidden_literals_from = "printf 'draco\n'"
        files.include = ["."]
        files.exclude = ["policy/**"]
"#,
    );
    write(
        &root,
        "notes.md",
        "the draco box
",
    );
    assert_eq!(code(&scan(&root)), 1);

    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-lan-hostnames]
        message = "use neutral placeholders"
        forbidden_literals_from = "printf 'draco\n'"
        ignore_literals = ["draco"]
        files.include = ["."]
        files.exclude = ["policy/**"]
"#,
    );
    assert_eq!(code(&scan(&root)), 0);
}

#[test]
fn ignore_literals_beside_a_check_with_no_literals_is_refused() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.x]
        message = "no"
        regexp = "TODO"
        ignore_literals = ["nas"]
        files.include = ["."]
"#,
    );
    let output = scan(&root);
    assert_eq!(code(&output), 2);
    assert!(
        stderr(&output).contains("read by nothing"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_unknown_literal_source_exits_two() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.bad-source]
        message = "x"
        forbidden_literals = "no-such-source"

        [rule.bad-source.files]
"#,
    );
    write(&root, "a.txt", "content\n");
    let output = scan(&root);
    assert_eq!(code(&output), 2);
    assert!(
        stderr(&output).contains("unknown literal source"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn no_policy_file_anywhere_exits_two() {
    let root = workspace();
    std::fs::remove_dir_all(root.join("policy")).unwrap();
    write(&root, "a.txt", "content\n");
    let output = scan(&root);
    assert_eq!(code(&output), 2);
}

// --- the floor that catches a selection covering nothing --------------------

#[test]
fn require_any_link_fires_when_the_glob_selects_nothing() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.docs-link-somewhere]
        builtin = "links-resolve"
        message = "the link rule covers nothing"
        require_any_link = true
        files.glob = ["*.markdown"]
"#,
    );
    write(&root, "README.md", "[a](README.md)\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("no longer covers anything"),
        "{}",
        stderr(&output)
    );
}

// --- text mode -------------------------------------------------------------

#[test]
fn text_mode_checks_something_that_never_becomes_a_file() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-host-identity]
        message = "do not publish host identity"
        forbidden_literals_from = "printf 'secret-host\n'"

        [rule.no-host-identity.files]
"#,
    );
    write(&root, "message.txt", "deployed from secret-host today\n");
    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["scan", "--text", "message.txt"])
        .current_dir(&root)
        .output()
        .unwrap();
    assert_eq!(code(&output), 1);
    assert!(stderr(&output).contains("line 1:"), "{}", stderr(&output));
}

// --- this repository's own policy -------------------------------------------

// The calibration record for `no-before-after-narrative`, executable. The rule
// is read out of the real policy file so the pattern under test is the pattern
// that ships -- a copy here would agree until it did not. One file carries the
// phrases the rule is known to match, and one carries the present-tense uses
// that kept `replaces`, `no longer` and `becomes` out of the pattern.
#[test]
fn the_before_after_narrative_rule_matches_its_calibrated_inputs() {
    let shipped: toml::Value = toml::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("policy/principles.toml"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut rules = toml::value::Table::new();
    rules.insert(
        "no-before-after-narrative".into(),
        shipped
            .get("rule")
            .and_then(|table| table.get("no-before-after-narrative"))
            .unwrap()
            .clone(),
    );
    let mut policy = toml::value::Table::new();
    policy.insert("rule".into(), toml::Value::Table(rules));

    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        &toml::to_string(&toml::Value::Table(policy)).unwrap(),
    );
    write(
        &root,
        "docs/narrative.md",
        "The flag became a list.\n\
         The set was renamed in the port.\n\
         The set was renamed to say what it refuses.\n\
         The list, formerly hard-coded, is documented.\n\
         The set previously called hygiene is inherited.\n\
         The lists used to be a match arm.\n",
    );
    write(
        &root,
        "docs/spec.md",
        "A scoped rule's list replaces the top-level declaration.\n\
         A baselined path the rule no longer selects is reported.\n\
         The old declaration becomes the new field.\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    for line in 1..=6 {
        assert!(
            text.contains(&format!("docs/narrative.md:{line}:")),
            "{text}"
        );
    }
    assert!(!text.contains("docs/spec.md"), "{text}");
}

/// Each newly bundled set is shown to refuse something.
///
/// A set that lands green has not been shown to work, and these three are
/// promotions rather than new inventions: the rules were already running in the
/// consuming repositories, so the thing at risk is not the pattern but the
/// SCOPE the bundled copy carries -- a glob that reaches no fixture directory,
/// or an `include` narrowed to a tree layout only one repository has. One probe
/// per set, each on the layout the promotion was written for.
#[test]
fn the_promoted_sets_refuse_what_they_were_promoted_for() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        "[inherit]\nsets = [\"host-identity\", \"broken-links\", \"captured-fixtures\"]\n",
    );

    // host-identity reads the running machine, so the fixture has to be built
    // from it. HOME is a harness precondition: without it there is no literal
    // to plant, and a test that quietly asserted less would be the silence this
    // set exists to end.
    let home = std::env::var("HOME").unwrap();
    write(&root, "docs/setup.md", &format!("run it from {home}\n"));
    // broken-links: one target that resolves and one that does not, so the
    // failure is the missing path rather than the rule firing on everything.
    write(
        &root,
        "README.md",
        "[gone](docs/missing.md)\n[here](docs/setup.md)\n",
    );
    // captured-fixtures, in the layout the Go half of the fleet uses. The other
    // half writes tests/fixtures/, which the same glob list reaches.
    write(
        &root,
        "testdata/account.json",
        "{\"holder\": \"\u{30c8}\u{30e8}\u{30bf}\"}\n",
    );

    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("no-running-os-identity-metadata"), "{text}");
    assert!(text.contains("docs/setup.md:1:"), "{text}");
    assert!(text.contains("no-broken-doc-links"), "{text}");
    assert!(text.contains("docs/missing.md"), "{text}");
    assert!(text.contains("no-non-ascii-in-fixtures"), "{text}");
    assert!(text.contains("testdata/account.json:1:"), "{text}");
    // And the resolving link is not reported, which is the half a rule that
    // fired on everything would also satisfy.
    assert!(!text.contains("docs/setup.md -> "), "{text}");
}
