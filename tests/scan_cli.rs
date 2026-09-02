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

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace() -> PathBuf {
    let path = support::scratch("scan");
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

/// The bytes every check reads are decoded, not lossily guessed at.
///
/// `regexp`, `forbidden_literals` and `require_regexp` reached the tree through
/// a searcher with binary detection off and a lossy sink, so a UTF-16 file was
/// a run of replacement characters by the time a pattern was matched against
/// it: nothing was ever found, and the file was reported as read. The script
/// check refused the very same file in the very same run for being unreadable.
#[test]
fn a_utf16_file_is_decoded_before_a_pattern_is_asked_about_it() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-todo]
        message = "no TODO"
        regexp = 'TODO'

        [rule.no-todo.files]
        exclude = ["policy/**"]
"#,
    );
    let mut bytes = vec![0xFF, 0xFE];
    for unit in "a note: TODO later\n".encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    write_bytes(&root, "note.txt", &bytes);

    let output = scan(&root);
    let text = stderr(&output);
    assert_eq!(code(&output), 1, "{text}");
    assert!(text.contains("note.txt"), "{text}");
    assert!(text.contains("TODO"), "{text}");
}

/// And the file nothing can decode is could-not-look rather than clean.
///
/// The same stance `allowed_scripts` already took, now taken by every check
/// that reads a file: Latin-1 bytes are not UTF-8, are not binary, and are not
/// declared, so nobody read the file -- which is exit 2 with the path named and
/// the cures beside it.
#[test]
fn a_file_no_charset_declares_is_reported_by_the_pattern_checks_too() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-todo]
        message = "no TODO"
        regexp = 'TODO'

        [rule.no-todo.files]
        exclude = ["policy/**"]
"#,
    );
    // Latin-1, which is neither UTF-8 nor binary.
    write_bytes(&root, "caf\u{e9}.txt", b"caf\xe9 au lait\n");

    let output = scan(&root);
    let text = stderr(&output);
    assert_eq!(code(&output), 2, "{text}");
    assert!(text.contains("cannot be read as text"), "{text}");
    assert!(!stdout(&output).contains("policy checks passed"), "{text}");

    // Declaring the charset is one of the cures, and it puts the file back in
    // the scan rather than merely quieting the report.
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-todo]
        message = "no TODO"
        regexp = 'TODO'

        [rule.no-todo.files]
        exclude = ["policy/**"]

        [rule.captures-are-latin1]
        encoding = "windows-1252"
        message = "a capture keeps the venue's own encoding"
        files.glob = ["*.txt"]
"#,
    );
    assert_eq!(code(&scan(&root)), 0, "{}", stderr(&scan(&root)));
}

/// A file that must contain a marker and cannot be read is not a file missing
/// the marker.
///
/// The worst direction of the lossy read: `require_regexp` searched the
/// replacement characters, found no marker, and reported a violation about a
/// marker that may well have been there. It is could-not-look now.
#[test]
fn a_required_marker_is_not_declared_missing_from_a_file_nobody_could_read() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.every-doc-has-a-status]
        message = "every doc says its status"
        require_regexp = 'Status:'
        files.glob = ["docs/**"]
"#,
    );
    write_bytes(&root, "docs/one.txt", b"caf\xe9 au lait\n");

    let output = scan(&root);
    let text = stderr(&output);
    assert_eq!(code(&output), 2, "{text}");
    assert!(text.contains("cannot be read as text"), "{text}");
    // Not reported as a document that is missing the marker.
    assert!(!text.contains("every doc says its status"), "{text}");
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
fn a_size_baseline_line_that_does_not_parse_is_refused_rather_than_skipped() {
    // The failure is silent in the direction that matters. A size baseline is a
    // ratchet -- a file held at 8 lines under a limit of 10 may not grow to 9 --
    // and dropping the entry checks the file against the LIMIT instead, so it
    // may now grow to 10 with nothing reported.
    //
    // The staleness check cannot cover this: a dropped entry is never in the
    // map, so it is not "listed", and the mechanism for noticing a baseline
    // that stopped describing the tree is blind to one that never loaded.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.file-size]
        max_lines = 10
        message = "files must be short"

        [rule.file-size.files]
        include = ["src"]
        baseline = "policy/size-baseline.txt"
"#,
    );
    write(&root, "src/big.py", &"x\n".repeat(9));

    // Held at 8, grown to 9: the ratchet fires.
    write(
        &root,
        "policy/size-baseline.txt",
        "# ratchet\nsrc/big.py 8\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("must not grow"),
        "{}",
        stderr(&output)
    );

    // One character wrong in the count. This used to pass the same tree.
    write(
        &root,
        "policy/size-baseline.txt",
        "# ratchet\nsrc/big.py 8x\n",
    );
    let typo = scan(&root);
    assert_eq!(code(&typo), 2, "{}", stderr(&typo));
    let text = stderr(&typo);
    assert!(text.contains("line 2"), "{text}");
    assert!(text.contains("not a number"), "{text}");
    assert!(text.contains("src/big.py 8x"), "{text}");

    // A path with no count at all is the other half.
    write(&root, "policy/size-baseline.txt", "src/big.py\n");
    let countless = scan(&root);
    assert_eq!(code(&countless), 2, "{}", stderr(&countless));
    assert!(
        stderr(&countless).contains("no line count after the path"),
        "{}",
        stderr(&countless)
    );
}

#[test]
fn a_path_baseline_line_with_a_signature_and_no_path_is_refused() {
    // A signature with nothing to sign. It reads as an entry and excuses no
    // path, which is the malformed size entry one file over.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-todo]
        message = "no TODO"
        regexp = 'TODO'

        [rule.no-todo.files]
        exclude = ["policy/**"]
        baseline = "policy/todo-baseline.txt"
"#,
    );
    write(&root, "old.txt", "TODO: ancient\n");
    write(&root, "policy/todo-baseline.txt", " | alice | a reason\n");

    let output = scan(&root);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no path before the signature"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_unsigned_baseline_entry_is_reported_where_the_policy_asks_for_signatures() {
    // A baseline holds two different things and the format could only express
    // one. Eight modules awaiting the same migration need one reason at the top
    // of the file. A list of the places a rule is WRONG needs one reason per
    // line -- and until now the whole line was the path, so the judgement had
    // nowhere to go but a comment nothing associates with an entry.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        baselines_signed = true

        [rule.no-todo]
        message = "no TODO"
        regexp = 'TODO'

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

    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("no-todo (unsigned baseline)"), "{text}");
    assert!(text.contains("old.txt: no owner and reason"), "{text}");
    // It names the file to edit: a report that says three entries are unsigned
    // and not where they are sends its reader looking.
    assert!(text.contains("policy/todo-baseline.txt"), "{text}");

    // Signed, it passes -- and the entry still suppresses what it excused.
    write(
        &root,
        "policy/todo-baseline.txt",
        "# grandfathered\nold.txt | alice | the tracker this cites was closed; text stays\n",
    );
    assert_eq!(code(&scan(&root)), 0);
}

#[test]
fn an_unsigned_baseline_is_fine_where_the_policy_does_not_ask() {
    // The default is not neutrality, it is what every existing baseline file
    // already is. Turning this on is a repository saying its baselines have
    // stopped being one homogeneous debt.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-todo]
        message = "no TODO"
        regexp = 'TODO'

        [rule.no-todo.files]
        exclude = ["policy/**"]
        baseline = "policy/todo-baseline.txt"
"#,
    );
    write(&root, "policy/todo-baseline.txt", "old.txt\n");
    write(&root, "old.txt", "TODO: ancient\n");
    assert_eq!(code(&scan(&root)), 0);
}

#[test]
fn a_signed_entry_still_goes_stale_when_it_stops_describing_the_tree() {
    // The signature is an addition to the record, not a way out of it. A
    // reason explains why an entry is there; it says nothing about whether it
    // still needs to be.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        baselines_signed = true

        [rule.no-todo]
        message = "no TODO"
        regexp = 'TODO'

        [rule.no-todo.files]
        exclude = ["policy/**"]
        baseline = "policy/todo-baseline.txt"
"#,
    );
    write(
        &root,
        "policy/todo-baseline.txt",
        "paid.txt | alice | pre-existing, being migrated\n",
    );
    write(&root, "paid.txt", "clean now\n");

    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("no-todo (stale baseline)"), "{text}");
    assert!(!text.contains("unsigned baseline"), "{text}");
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

#[test]
fn a_byte_rule_reports_the_count_and_the_limit_in_bytes() {
    // The other measure, and the reason there is one: a reflow changes the
    // line count of a document and does not change its size, so a repository
    // that means "this file may not get bigger" says so in the unit that does
    // not move.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.small-files]
        message = "too big"
        max_bytes = 8

        [rule.small-files.files]
        glob = ["*.txt"]
"#,
    );
    write(&root, "big.txt", "0123456789\n");
    write(&root, "small.txt", "hi\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(text.contains("big.txt: 11 bytes (limit 8)"), "{text}");
    assert!(!text.contains("small.txt"), "{text}");
}

/// The two are separate rules over one tree, and each reports in its own unit.
///
/// A file inside the line cap and over the byte cap is the case that says the
/// measures are not the same question: one long line is one line.
#[test]
fn a_line_cap_and_a_byte_cap_bound_the_same_file_from_two_sides() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.short-files]
        message = "too long"
        max_lines = 4

        [rule.short-files.files]
        glob = ["*.txt"]

        [rule.small-files]
        message = "too big"
        max_bytes = 20

        [rule.small-files.files]
        glob = ["*.txt"]
"#,
    );
    write(
        &root,
        "wide.txt",
        "0123456789012345678901234567890123456789\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    assert!(text.contains("wide.txt: 41 bytes (limit 20)"), "{text}");
    assert!(!text.contains("lines (limit 4)"), "{text}");
}

#[test]
fn a_byte_baseline_ratchets_and_reports_an_entry_that_stopped_matching() {
    // The same ratchet the line cap has, in bytes: a file listed at its current
    // size is held THERE rather than at the limit, and an entry naming a path
    // this rule no longer selects is the allowance nothing reports.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.small-files]
        message = "too big"
        max_bytes = 4

        [rule.small-files.files]
        glob = ["*.txt"]
        exclude = ["policy/**"]
        baseline = "policy/sizes.txt"
"#,
    );
    write(&root, "policy/sizes.txt", "legacy.txt 11\n");
    write(&root, "legacy.txt", "0123456789\n");
    assert_eq!(code(&scan(&root)), 0, "{}", stderr(&scan(&root)));

    write(&root, "legacy.txt", "01234567890\n");
    let grown = scan(&root);
    assert_eq!(code(&grown), 1, "{}", stderr(&grown));
    assert!(
        stderr(&grown).contains("legacy.txt: 12 bytes (baseline 11; must not grow)"),
        "{}",
        stderr(&grown)
    );

    // The entry names a path the rule no longer selects.
    std::fs::remove_file(root.join("legacy.txt")).unwrap();
    let stale = scan(&root);
    assert_eq!(code(&stale), 1, "{}", stderr(&stale));
    let text = stderr(&stale);
    assert!(text.contains("small-files (stale baseline)"), "{text}");
    assert!(text.contains("legacy.txt: no longer matches"), "{text}");
}

/// A malformed byte-baseline entry names the unit it could not read.
///
/// The line cap's own refusal says "line count", and telling a reader of a byte
/// cap to go and fix a line count sends them looking for a file that is not
/// there.
#[test]
fn a_malformed_byte_baseline_entry_is_refused_in_its_own_unit() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.small-files]
        message = "too big"
        max_bytes = 4

        [rule.small-files.files]
        glob = ["*.txt"]
        exclude = ["policy/**"]
        baseline = "policy/sizes.txt"
"#,
    );
    write(&root, "legacy.txt", "0123456789\n");
    write(&root, "policy/sizes.txt", "legacy.txt 11x\n");
    let output = scan(&root);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("the byte count is not a number"), "{text}");
    assert!(text.contains("`<path> <bytes>`"), "{text}");
}

#[test]
fn a_comment_rule_reads_a_go_file_through_the_go_grammar() {
    // The third language, and the same property the first two were added for:
    // the marker inside the string literal is a string literal, and only the
    // grammar can say so.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-before-after]
        message = "state what holds"
        comment_regexp = '(?i)\bused to be\b'

        [rule.no-before-after.files]
        glob = ["*.go"]
"#,
    );
    write(
        &root,
        "cmd/x/main.go",
        "package main\n\n// This used to be a switch.\nfunc main() {\n\tmarker := \"used to be\"\n\t_ = marker\n}\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("cmd/x/main.go:3"), "{text}");
    assert!(!text.contains("main.go:5"), "{text}");
}

// --- prose -----------------------------------------------------------------

#[test]
fn a_prose_rule_matches_a_sentence_a_formatter_wrapped() {
    // The reason `prose_regexp` is not `regexp`: the sentence is split across
    // two lines by whatever last rewrapped the paragraph, and a pattern over
    // bytes finds neither half.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-announcing-sentence]
        message = "say it once"
        prose_regexp = '(?i)\bas (?:we|you) (?:will|shall) see\b'

        [rule.no-announcing-sentence.files]
        include = ["."]
        exclude = ["policy/**"]
"#,
    );
    write(
        &root,
        "notes.md",
        "The count is taken once. As we\nwill see, it is wrong.\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("notes.md:1:"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_prose_rule_reads_a_comment_a_configuration_line_and_a_document_alike() {
    // One rule, four file kinds, one pattern. The point of the extractor is
    // that the pattern never has to know how the comment is spelled.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-empty-hedge]
        message = "state the claim"
        prose_regexp = '(?i)\barguably\b'

        [rule.no-empty-hedge.files]
        include = ["."]
        exclude = ["policy/**"]
"#,
    );
    write(&root, "notes.md", "Arguably the count is right.\n");
    write(
        &root,
        "src/lib.rs",
        "// Arguably the count is right.\npub struct X;\n",
    );
    write(
        &root,
        "cmd/x/main.go",
        "package main\n\n// Arguably the count is right.\nfunc main() {}\n",
    );
    write(
        &root,
        "settings.toml",
        "# Arguably the count is right.\nkey = 1\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let text = stderr(&output);
    for path in [
        "notes.md:1:",
        "src/lib.rs:1:",
        "cmd/x/main.go:3:",
        "settings.toml:1:",
    ] {
        assert!(text.contains(path), "{path} missing from {text}");
    }
}

#[test]
fn a_prose_rule_says_nothing_about_a_fenced_example_or_a_file_it_reads_no_prose_from() {
    // The two silences, and both are deliberate. A shape quoted inside a fence
    // is an example of the shape, not an instance of it; and a file kind this
    // binary reads no prose from contributes nothing rather than a finding,
    // because `include = ["."]` over a mixed tree is the normal thing to write.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-empty-hedge]
        message = "state the claim"
        prose_regexp = '(?i)\barguably\b'

        [rule.no-empty-hedge.files]
        include = ["."]
        exclude = ["policy/**"]
"#,
    );
    write(
        &root,
        "notes.md",
        "The shape is this:\n\n```\nArguably the count is right.\n```\n",
    );
    write(
        &root,
        "capture.json",
        "{\"note\": \"Arguably the count is right.\"}\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

/// A selection with no prose in it reads exactly like prose with nothing wrong,
/// and `files.min_selected` is the floor that tells them apart.
#[test]
fn a_prose_rule_that_selects_nothing_is_caught_by_the_floor_and_not_by_silence() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-empty-hedge]
        message = "state the claim"
        prose_regexp = '(?i)\barguably\b'

        [rule.no-empty-hedge.files]
        glob = ["*.mkd"]
        min_selected = 1
"#,
    );
    write(&root, "notes.md", "Arguably the count is right.\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("min_selected"),
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
        # Excluded for the reason the bundled sets carry the same line: an
        # unanchored literal written as `regexp = '...'` contains its own text
        # on that line, so a rule selecting the whole tree reports its own
        # policy file. Refused at load by `validate_no_self_match`.
        exclude = ["policy/**"]
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

/// The defect `files.min_selected` closes. A `require_regexp` over an empty
/// selection returned no failures at all, so a rule whose `include` root had
/// been renamed away reported `policy checks passed` forever -- the loudest
/// version of the silence `require_any_link` was given for links.
#[test]
fn a_require_rule_over_an_empty_selection_fails_under_a_floor() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.workflows-declare-permissions]
        message = "declare the token scopes the job needs"
        require_regexp = '^permissions:'
        files.include = [".github/workflows-renamed-away"]
        files.glob = ["*.yml"]
        files.min_selected = 1
"#,
    );
    write(&root, ".github/workflows/ci.yml", "on: push\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let said = stderr(&output);
    // The four things the reader edits from: which rule, the floor, the count,
    // and the keys that produced the count.
    assert!(said.contains("workflows-declare-permissions"), "{said}");
    assert!(said.contains("files.min_selected = 1"), "{said}");
    assert!(said.contains("selected 0 file(s)"), "{said}");
    assert!(
        said.contains("include = [\".github/workflows-renamed-away\"]"),
        "{said}"
    );
    assert!(said.contains("glob = [\"*.yml\"]"), "{said}");
}

/// The other half, and the half that catches a floor which has quietly become a
/// constant: with the failing case tested alone, a floor that fired on every
/// selection would pass every test while refusing every repository's scan.
#[test]
fn a_selection_that_meets_its_floor_passes() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.workflows-declare-permissions]
        message = "declare the token scopes the job needs"
        require_regexp = '^permissions:'
        files.include = [".github/workflows"]
        files.glob = ["*.yml"]
        files.min_selected = 2
"#,
    );
    write(&root, ".github/workflows/ci.yml", "permissions: {}\n");
    write(&root, ".github/workflows/release.yml", "permissions: {}\n");
    let output = scan(&root);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

/// The floor is measured where every rule's selection is built, so it is not
/// the require check's own knob. A `regexp` rule finds nothing over nothing and
/// reports exactly what it reports over a tree it read in full.
#[test]
fn the_floor_is_read_by_every_check_that_selects() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-todo]
        message = "no TODO"
        regexp = 'TO[D]O'
        files.include = ["src"]
        files.glob = ["*.renamed"]
        files.min_selected = 1
"#,
    );
    write(&root, "src/a.rs", "fine\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("selected 0 file(s)"),
        "{}",
        stderr(&output)
    );
}

/// One rule below its floor is one finding, however many times the scan builds
/// its selection. The script check reads an `encoding` rule's selection to
/// learn how to decode a file, and the encoding check then builds it again --
/// so this rule's count is taken twice in one run, and a reader must not be
/// told twice that one rule selected nothing.
#[test]
fn a_rule_selected_for_twice_reports_its_floor_once() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.captures-are-shift-jis]
        message = "a capture keeps the venue's own encoding"
        encoding = "Shift_JIS"
        files.include = ["captures-renamed-away"]
        files.min_selected = 1

        [rule.latin-only]
        allowed_scripts = ["Latin"]
        files.include = ["src"]
"#,
    );
    write(&root, "src/a.txt", "plain\n");
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let said = stderr(&output);
    assert_eq!(
        said.matches("(selection floor)").count(),
        1,
        "one rule, one finding: {said}"
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
    // from it -- but from a HOME this test SETS rather than the one it happens
    // to inherit. Reading the ambient one made the assertion depend on who ran
    // it: a hosted runner's home belongs to a shared build account, which
    // `KNOWN_PUBLIC_IDENTITY` deliberately does not treat as anybody's identity,
    // so the rule correctly did not fire and the test read that as the rule
    // having stopped working. Planting a personal home asks the question the set
    // was promoted to answer, and asks it the same way on every machine.
    let home = format!("/{}/fixture-person", "home");
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

    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .arg("scan")
        .current_dir(&root)
        .env("HOME", &home)
        .output()
        .unwrap();
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

/// A repository, because the two cases below are about git's index and a
/// directory without one takes the walk instead.
fn repository(root: &Path) {
    for arguments in [
        &["init", "-q", "-b", "main"][..],
        &["config", "user.name", "Test"][..],
        &["config", "user.email", "test@example.test"][..],
    ] {
        let status = Command::new(support::real_git())
            .args(arguments)
            .current_dir(root)
            .status()
            .unwrap();
        assert!(status.success(), "git {arguments:?} failed");
    }
}

fn add(root: &Path) {
    let status = Command::new(support::real_git())
        .args(["add", "-A", "."])
        .current_dir(root)
        .status()
        .unwrap();
    assert!(status.success());
}

/// A path git tracks and the working tree cannot produce is exit 2, named.
///
/// It used to be dropped from the selection without a word, so every rule
/// searched what was left, found nothing there, and the run printed `policy
/// checks passed` at exit 0 over a tree it had not finished reading. The four
/// ways in are an unstaged deletion, a sparse checkout, a directory this
/// process may not enter, and a filesystem that lost the file; the report has
/// to name the path in all of them, because that is the only part the reader
/// can act on.
#[test]
fn a_tracked_path_the_tree_cannot_produce_is_named_and_is_not_a_pass() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-todo]
        message = "no TODO"
        regexp = 'TODO'

        [rule.no-todo.files]
        exclude = ["policy/**"]
"#,
    );
    write(&root, "kept.txt", "fine\n");
    write(&root, "gone.txt", "fine\n");
    repository(&root);
    add(&root);
    std::fs::remove_file(root.join("gone.txt")).unwrap();

    let output = scan(&root);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("gone.txt"), "{text}");
    assert!(text.contains("could not be read"), "{text}");
    // Not a pass, and it must not read like one either.
    assert!(!stdout(&output).contains("policy checks passed"), "{text}");
}

/// The other half: the unreadable path does not swallow the findings.
///
/// This is why the list rides out beside the files instead of ending the run at
/// the first rule that hits it. A tree with one missing path still has an
/// answer for every other rule, and a reader who only ever sees "restore this
/// file" never learns there was a violation waiting behind it.
#[test]
fn an_unreadable_path_is_reported_beside_the_findings_and_not_instead_of_them() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-todo]
        message = "no TODO"
        regexp = 'TODO'

        [rule.no-todo.files]
        exclude = ["policy/**"]
"#,
    );
    write(&root, "offender.txt", "TODO: later\n");
    write(&root, "gone.txt", "fine\n");
    repository(&root);
    add(&root);
    std::fs::remove_file(root.join("gone.txt")).unwrap();

    let output = scan(&root);
    let text = stderr(&output);
    // Exit 1: something was found, and that is the answer the reader acts on
    // first. The unreadable path is still named.
    assert_eq!(code(&output), 1, "{text}");
    assert!(text.contains("offender.txt:1:TODO: later"), "{text}");
    assert!(text.contains("gone.txt"), "{text}");
}

/// The one loader, asked rather than re-implemented.
///
/// Which rules a repository runs is five interacting fields -- the bundled sets
/// it inherits, the extra policy files `inherit.paths` merges, the ids
/// `inherit.disabled_rules` drops, and its own rules shadowing an inherited id
/// -- and every second reader of them is a reader free to disagree with the
/// engine about what runs. `uphold_check.py` was that second reader. This is
/// the answer it can ask for instead, so the assertions here are exactly the
/// interactions a re-implementation gets wrong.
#[test]
fn the_effective_rules_are_what_inheritance_resolved_to() {
    let root = workspace();
    write(
        &root,
        "policy/extra.toml",
        r#"
        [rule.from-a-path]
        message = "inherited through inherit.paths"
        regexp = 'nothing-matches-this'
        files.include = ["."]
"#,
    );
    write(
        &root,
        "policy/principles.toml",
        r#"
        [inherit]
        sets = ["process-residue"]
        paths = ["policy/extra.toml"]
        disabled_rules = ["no-task-tracker-references"]

        [rule.of-its-own]
        message = "declared here"
        regexp = 'nothing-matches-this-either'
        files.include = ["."]
        files.exclude = ["policy/**"]

        [rule.no-local-merge]
        builtin = "no-local-merge"
        git.hooks = ["pre-merge-commit", "manual"]
"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["rules", "--effective", "--json"])
        .current_dir(&root)
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let text = stdout(&output);

    // Inherited from a bundled set, merged from a path, and declared here.
    assert!(text.contains("\"no-merge-conflict-markers\""), "{text}");
    assert!(text.contains("\"from-a-path\""), "{text}");
    assert!(text.contains("\"of-its-own\""), "{text}");
    // Dropped by name, which is the field a reader of `[rule.*]` tables alone
    // never sees.
    assert!(!text.contains("no-task-tracker-references"), "{text}");
    // And the hooks travel with the rule, because "which rules run" cannot be
    // answered without saying WHEN -- a claim on a guard is supplied only where
    // the seam it fires at is installed.
    assert!(
        text.contains(
            "{\"id\": \"no-local-merge\", \"git_hooks\": [\"pre-merge-commit\", \"manual\"], \
             \"seams\": [\"guard\"]}"
        ),
        "{text}"
    );
    // A content rule fires at no git hook, and says so rather than being
    // reported under whichever stage happened to be installed -- and names the
    // seam, because an empty hook list is true of a content rule and of a
    // checker standing in front of a command alike, and those are not the same
    // place. A reader that has to guess between them guesses the scan.
    assert!(
        text.contains("{\"id\": \"of-its-own\", \"git_hooks\": [], \"seams\": [\"scan\"]}"),
        "{text}"
    );
}

// --- a guard's own file scope is not the scan's to fail on -----------------

#[test]
fn a_scoped_guard_does_not_abort_the_content_scan() {
    // `[rule.files]` on a guard built-in is the supported way to narrow one:
    // `guard::scope::in_file_scope` reads it. The scan aborted on it anyway,
    // exit 2 for the WHOLE repository, with a diagnosis -- "would be read by
    // nothing" -- that was not true of the rule it named. Scoping one guard
    // switched off every content rule in the policy.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.no-todo]
        message = "no TODO"
        regexp = 'TODO'

        [rule.no-todo.files]
        exclude = ["policy/**"]

        [rule.prevent-unusual-unicode-in-files]
        builtin = "prevent-unusual-unicode-in-files"

        [rule.prevent-unusual-unicode-in-files.files]
        include = ["src"]

        [rule.prevent-unusual-unicode-in-files.git]
        hooks = ["pre-commit"]
"#,
    );
    write(&root, "src/a.txt", "fine\nTODO: later\n");

    let output = scan(&root);
    assert_eq!(
        code(&output),
        1,
        "the scan should report the pattern rule, not abort: {}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("src/a.txt:2:TODO: later"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_guard_built_in_that_no_hook_runs_is_still_refused() {
    // The other side of the same question. With `files.*` and no `git.hooks`,
    // nothing runs the rule at either seam, so the keys really are read by
    // nothing -- and passing over it would report a check that did not happen
    // as one that did.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.prevent-unusual-unicode-in-files]
        builtin = "prevent-unusual-unicode-in-files"

        [rule.prevent-unusual-unicode-in-files.files]
        include = ["src"]
"#,
    );
    write(&root, "src/a.txt", "fine\n");

    let output = scan(&root);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("prevent-unusual-unicode-in-files"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_rule_that_only_stands_in_front_of_a_command_names_the_shim_seam() {
    // The seam `git_hooks` cannot express. A checker with `command.before` and
    // no hooks looked identical to a content rule -- an empty list for both --
    // so every reader downstream had to guess, and the reconciler guessed the
    // scan. A claim on such a rule then reconciled green in a repository where
    // the scan never touches it.
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [[shim]]
        command = "gh"
        match = ["pr:create"]
        text_flags = ["-b", "--body"]

        [rule.stands-in-front]
        message = "do not publish that"
        exec = "uphold guard --text -"
        command.before = ["gh"]

        [rule.searches-the-tree]
        message = "no TODO"
        regexp = 'TODO'
        files.include = ["."]
        files.exclude = ["policy/**"]
"#,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["rules", "--effective", "--json"])
        .current_dir(&root)
        .output()
        .unwrap();
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let text = stdout(&output);

    assert!(
        text.contains("{\"id\": \"stands-in-front\", \"git_hooks\": [], \"seams\": [\"shim\"]}"),
        "{text}"
    );
    assert!(
        text.contains("{\"id\": \"searches-the-tree\", \"git_hooks\": [], \"seams\": [\"scan\"]}"),
        "{text}"
    );

    // And the human form says it too, where it used to say "no git hook" of
    // both.
    let human = Command::new(env!("CARGO_BIN_EXE_uphold"))
        .args(["rules", "--effective"])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(
        stdout(&human).contains("stands-in-front  (shim)"),
        "{}",
        stdout(&human)
    );
}

// -- anchors-resolve --------------------------------------------------------
//
// The control comes first, and it is not a formality: if a document whose
// anchors all agree is not accepted, every refusal below it is vacuous. Both
// verdicts are driven here because a check observed saying only yes has not
// been observed.

/// A repository with one record and one document that leans on it.
fn anchored(root: &Path, document: &str) {
    write(
        root,
        "policy/principles.toml",
        r#"
        [rule.anchors-resolve]
        builtin = "anchors-resolve"
        message = "the fact moved"

        [rule.anchors-resolve.files]
        glob = ["*.md"]
"#,
    );
    write(
        root,
        "config/svc.yaml",
        "read_path: captured\nscope:\n  - read_only\n  - trade\nenabled: true\nabsent: null\n",
    );
    write(root, "README.md", document);
}

#[test]
fn every_shape_of_agreeing_anchor_is_accepted() {
    let root = workspace();
    anchored(
        &root,
        // A string, a list index, a boolean, and a null -- the last because
        // `absent: null` is a deliberate answer a record gives, and reporting
        // it as a MISSING KEY would be the fail-open this check exists to name.
        "<!-- fact-anchor: source=config/svc.yaml key=read_path states=captured -->\n\
         <!-- fact-anchor: source=config/svc.yaml key=scope.1 states=trade -->\n\
         <!-- fact-anchor: source=config/svc.yaml key=enabled states=true -->\n\
         <!-- fact-anchor: source=config/svc.yaml key=absent states=none -->\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_value_that_moved_is_refused_and_names_both_readings() {
    let root = workspace();
    anchored(
        &root,
        "<!-- fact-anchor: source=config/svc.yaml key=read_path states=api -->\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    let text = stderr(&output);
    // Both sides, because the reader of this failure did not write the sentence
    // and has to decide which of the two is the thing that is wrong.
    assert!(text.contains(r#"states "api" for read_path"#), "{text}");
    assert!(text.contains(r#"which says "captured""#), "{text}");
    assert!(text.contains("README.md:1"), "{text}");
}

#[test]
fn a_key_that_is_gone_is_refused_as_a_missing_key_not_a_moved_value() {
    let root = workspace();
    anchored(
        &root,
        "<!-- fact-anchor: source=config/svc.yaml key=renamed states=captured -->\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("which does not exist there"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_source_that_is_gone_is_refused() {
    let root = workspace();
    anchored(
        &root,
        "<!-- fact-anchor: source=config/departed.yaml key=read_path states=captured -->\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("which is not present"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_data_anchor_is_required_to_be_present_and_never_compared() {
    let root = workspace();
    anchored(
        &root,
        "<!-- data-anchor: artifact=captures/*.json states=a figure nobody here owns -->\n",
    );
    let missing = scan(&root);
    assert_eq!(code(&missing), 1);
    assert!(
        stderr(&missing).contains("matches no file that is present"),
        "{}",
        stderr(&missing)
    );

    // Present is the whole test. The artifact's CONTENTS disagree with the
    // stated text in every way a string can, and that is not a finding: this
    // repository does not get to say what a captured document contains.
    write(&root, "captures/filing.json", "{\"unrelated\": 1}\n");
    assert_eq!(code(&scan(&root)), 0);
}

#[test]
fn a_stated_value_containing_spaces_is_compared_whole() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.anchors-resolve]
        builtin = "anchors-resolve"
        message = "the fact moved"

        [rule.anchors-resolve.files]
        glob = ["*.md"]
"#,
    );
    write(&root, "config/svc.yaml", "note: the issuer's own figure\n");
    // Stopping at the first space would compare "the" to "the", pass, and hide
    // every disagreement after the first word.
    write(
        &root,
        "README.md",
        "<!-- fact-anchor: source=config/svc.yaml key=note states=the issuer's own guess -->\n",
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains(r#"which says "the issuer's own figure""#),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_document_with_no_anchor_passes_and_the_floor_is_opt_in() {
    let root = workspace();
    anchored(&root, "prose that anchors nothing at all\n");
    // Zero is the goal state, not a narrowed selection: every fact rendered or
    // read at runtime, no sentence needing one pinned. Unlike `links-resolve`,
    // the floor here is off unless a repository says otherwise.
    assert_eq!(code(&scan(&root)), 0);

    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.anchors-resolve]
        builtin = "anchors-resolve"
        message = "the fact moved"
        require_any_anchor = true

        [rule.anchors-resolve.files]
        glob = ["*.md"]
"#,
    );
    let output = scan(&root);
    assert_eq!(code(&output), 1);
    assert!(
        stderr(&output).contains("found no anchor"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn the_anchor_floor_is_refused_on_a_rule_that_reads_no_anchor() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.links-resolve]
        builtin = "links-resolve"
        message = "fix the link"
        require_any_anchor = true

        [rule.links-resolve.files]
        glob = ["*.md"]
"#,
    );
    write(&root, "README.md", "[a](README.md)\n");
    let output = scan(&root);
    // Config that is accepted and does nothing is the failure this repository
    // exists to make loud, so the knob is refused where nothing reads it.
    assert_eq!(code(&output), 2);
    assert!(
        stderr(&output).contains("require_any_anchor"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_source_that_escapes_the_repository_is_refused_and_never_read() {
    let root = workspace();
    anchored(&root, "");
    // `Path::join` REPLACES the path when handed an absolute one, so without a
    // confinement check this reads the named file and prints what it found
    // into a finding -- a document anchor as a file-disclosure primitive.
    for (marker, expected) in [
        (
            "<!-- fact-anchor: source=/etc/hostname key=a states=b -->\n",
            "absolute path",
        ),
        (
            "<!-- fact-anchor: source=../outside.yaml key=a states=b -->\n",
            "outside this repository",
        ),
    ] {
        write(&root, "README.md", marker);
        // Present and readable, so "refused" cannot be confused with "absent".
        write(
            root.parent().unwrap(),
            "outside.yaml",
            "a: the value next door\n",
        );
        let output = scan(&root);
        assert_eq!(code(&output), 1, "{}", stderr(&output));
        let text = stderr(&output);
        assert!(text.contains(expected), "{text}");
        // The whole point: whatever is over there is not quoted back.
        assert!(!text.contains("the value next door"), "{text}");
    }
}

#[test]
fn an_ignored_artifact_is_still_present() {
    let root = workspace();
    anchored(
        &root,
        "<!-- data-anchor: artifact=captures/*.json states=a figure nobody here owns -->\n",
    );
    write(&root, "captures/filing.json", "{}\n");
    // A captured artifact is very often exactly the thing a repository declines
    // to track. Under the walker's default ignore filters this file is invisible
    // and the finding reads "nobody captured this", which is the reverse of the
    // truth and unarguable from the message.
    write(&root, ".gitignore", "captures/\n");
    let output = scan(&root);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn an_anchor_rule_wired_to_a_git_hook_is_refused() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
        [rule.anchors-resolve]
        builtin = "anchors-resolve"
        message = "the fact moved"
        git.hooks = ["pre-commit"]

        [rule.anchors-resolve.files]
        glob = ["*.md"]
"#,
    );
    write(&root, "README.md", "nothing anchored here\n");
    let output = scan(&root);
    // `seams()` routes a file-reading built-in with a hook to the guard, and
    // no guard arm dispatches this one -- so it would be installed, counted in
    // "N guard(s) passed", and never run.
    assert_eq!(code(&output), 2);
    assert!(
        stderr(&output).contains("never dispatches it"),
        "{}",
        stderr(&output)
    );
}

// --- commands-resolve ------------------------------------------------------
//
// The third resolver. `links-resolve` resolves a path a reader would click,
// `anchors-resolve` a value a reader would believe, this a command a reader
// would run. Every case here is about the half that decides whether the rule is
// usable at all: a verb list read wrong produces confident findings against
// documents that were right, so a command judges nothing until two readings of
// its own sources agree.

/// A Go command with a real dispatch and a usage block that agrees with it.
const FG_REGISTRY: &str = r#"package main

// fg-registry sync [options]
// fg-registry services

func main() {
	args := os.Args[1:]
	switch args[0] {
	case "sync":
		sync()
	case "services":
		services()
	default:
		usage()
	}
}
"#;

const COMMANDS_POLICY: &str = r#"
[rule.doc-commands-resolve]
builtin = "commands-resolve"
message = "Name a verb the command dispatches on."
command_sources = ["cmd/{}/*.go"]

[rule.doc-commands-resolve.files]
glob = ["*.md"]
"#;

#[test]
fn a_document_naming_a_verb_the_command_does_not_dispatch_on_is_refused() {
    // The defect this was built from, reproduced: a README opened with a verb
    // the binary had never had, and every gate in every repository stayed green
    // for as long as the file existed.
    let root = workspace();
    write(&root, "policy/principles.toml", COMMANDS_POLICY);
    write(&root, "cmd/fg-registry/main.go", FG_REGISTRY);
    write(
        &root,
        "README.md",
        "Read the metadata with:\n\n```\nfg-registry credentials\n```\n",
    );

    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let text = stderr(&output);
    assert!(text.contains("README.md:4"), "{text}");
    assert!(text.contains("fg-registry credentials"), "{text}");
    // The verbs it DOES have, because a refusal that names the wrong verb and
    // not the right ones sends the reader to the source anyway.
    assert!(text.contains("services, sync"), "{text}");
}

#[test]
fn a_verb_the_command_really_dispatches_on_passes() {
    let root = workspace();
    write(&root, "policy/principles.toml", COMMANDS_POLICY);
    write(&root, "cmd/fg-registry/main.go", FG_REGISTRY);
    write(
        &root,
        "README.md",
        "Fast-forward with `fg-registry sync`.\n",
    );

    let output = scan(&root);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    // The denominator, printed on every run. "Every documented verb resolves"
    // and "every documented verb this could read resolves" are different
    // sentences, and only one of them is what happened.
    assert!(
        stdout(&output).contains("1 command(s) discovered, 1 judged, 0 skipped"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn a_command_whose_two_readings_disagree_judges_nothing_and_says_so() {
    // The agreement gate. This command's usage block names a verb its dispatch
    // does not offer, so one of the two readings is wrong and there is no way to
    // tell which -- the rule refuses to guess, and refuses to condemn a document
    // on the strength of a parse it cannot trust.
    let root = workspace();
    write(&root, "policy/principles.toml", COMMANDS_POLICY);
    write(
        &root,
        "cmd/fg-registry/main.go",
        r#"package main

// fg-registry credentials

func main() {
	switch os.Args[1] {
	case "sync":
		sync()
	case "services":
		services()
	default:
		usage()
	}
}
"#,
    );
    write(
        &root,
        "README.md",
        "Read the metadata with:\n\n```\nfg-registry credentials\n```\n",
    );

    let output = scan(&root);
    // Exit 1, and NOT because the document was judged: nothing could be judged,
    // and zero commands judged is the state a broken pattern and a grammar that
    // stopped matching both arrive in.
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("0 judged, 1 skipped"), "{out}");
    assert!(out.contains("its own usage names credentials"), "{out}");
}

#[test]
fn a_tagless_switch_is_skipped_rather_than_read_as_a_verb_list() {
    // The form that supplied 22 of one run's 38 false findings in the
    // implementation this ports. Its arms are booleans, not verbs, and the
    // grammar is what tells them apart.
    let root = workspace();
    write(&root, "policy/principles.toml", COMMANDS_POLICY);
    write(
        &root,
        "cmd/session/main.go",
        r"package main

func main() {
	switch {
	case ready():
		run()
	default:
		stop()
	}
}
",
    );
    write(&root, "README.md", "Try `session claim`.\n");

    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    let out = stdout(&output);
    assert!(out.contains("no dispatch this parse can read"), "{out}");
    // And the document was not condemned on the strength of it.
    assert!(
        !stderr(&output).contains("session claim"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_command_name_in_prose_is_not_an_instruction() {
    // Only a code span, and only at its first token. An invocation begins with
    // the binary; a sentence that happens to contain the same two words in a row
    // does not, and matching one is how this rule would earn a blanket waiver.
    let root = workspace();
    write(&root, "policy/principles.toml", COMMANDS_POLICY);
    write(&root, "cmd/fg-registry/main.go", FG_REGISTRY);
    write(
        &root,
        "README.md",
        "The very fg-registry credentials it captures with are held elsewhere.\n\
         See `the fg-registry credentials note` for where.\n",
    );

    let output = scan(&root);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_pattern_that_discovers_nothing_is_refused_rather_than_reported_clean() {
    // Zero commands is the state a renamed directory, a typo in the glob and a
    // grammar that stopped matching all arrive in, and without this it is
    // indistinguishable from a tree whose every documented verb resolves.
    let root = workspace();
    write(&root, "policy/principles.toml", COMMANDS_POLICY);
    write(&root, "README.md", "Nothing here.\n");

    let output = scan(&root);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no document was judged"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn the_resolver_refuses_to_load_without_a_pattern_to_discover_with() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
[rule.doc-commands-resolve]
builtin = "commands-resolve"
message = "Name a real verb."

[rule.doc-commands-resolve.files]
glob = ["*.md"]
"#,
    );
    write(&root, "README.md", "x\n");

    let output = scan(&root);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("needs `command_sources`"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn a_pattern_with_no_placeholder_names_no_command_and_is_refused() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        &COMMANDS_POLICY.replace("cmd/{}/*.go", "cmd/fg-registry/*.go"),
    );
    write(&root, "cmd/fg-registry/main.go", FG_REGISTRY);
    write(&root, "README.md", "x\n");

    let output = scan(&root);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("exactly one"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn the_pattern_is_read_by_this_built_in_and_no_other() {
    let root = workspace();
    write(
        &root,
        "policy/principles.toml",
        r#"
[rule.no-shouting]
regexp = "SHOUTING"
message = "do not shout"
command_sources = ["cmd/{}/*.go"]

[rule.no-shouting.files]
glob = ["*.md"]
"#,
    );
    write(&root, "README.md", "x\n");

    let output = scan(&root);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(
        stderr(&output).contains("read by nothing"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn glob_syntax_the_name_capture_cannot_read_is_refused_at_load() {
    // The pattern is read twice -- as a glob to select the files, as a regex to
    // name the command in each path -- and only `*`, `**`, `/` and literal text
    // mean the same thing to both. A construct only the glob understands selects
    // a source whose command cannot be named, and that source then vanishes out
    // of the discovered count with nothing said, which is the failure this rule
    // exists to refuse arriving through its own configuration.
    for pattern in ["cmd/{}/main?.go", "cmd/{}/[ab].go", "cmd/{}/{a,b}.go"] {
        let root = workspace();
        write(
            &root,
            "policy/principles.toml",
            &COMMANDS_POLICY.replace("cmd/{}/*.go", pattern),
        );
        write(&root, "README.md", "x\n");

        let output = scan(&root);
        assert_eq!(code(&output), 2, "{pattern}: {}", stderr(&output));
        assert!(
            stderr(&output).contains("does not accept"),
            "{pattern}: {}",
            stderr(&output)
        );
    }
}
