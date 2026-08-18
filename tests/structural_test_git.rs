//! No fixture in this suite may name `git` and let `PATH` decide which one.
//!
//! THE RULE. `Command::new("git")` resolves through `PATH`, and on a machine
//! where `uphold shim --install` has been run the first `git` on `PATH` is a
//! symlink to this binary. Every fixture-setup call then runs the shim, which
//! loads the repository's policy before running anything and refuses when it
//! cannot.
//!
//! WHY THAT IS THE SHIM BEING RIGHT, which is what makes the failure hard to
//! read. The tests it broke were the three in `base_sets_cli.rs` whose fixture
//! is a policy that deliberately does not load -- an absent owner source, a
//! file that will not parse, a word that is not a visibility -- so `git add -A`
//! inside such a tree is precisely the invocation `uphold` exists to refuse.
//! The panic named `git ["add", "-A"] failed` and said nothing about a shim, so
//! the first read is that the fixture is broken.
//!
//! WHY IT IS A RULE AND NOT A NOTE. CI has no shims installed, so the suite was
//! green in the one place a regression is caught and red only for whoever is
//! developing the tool -- the people most likely to have the shims on `PATH`.
//! Green in CI and red on a developer machine is the shape that gets a test
//! deleted. `support::real_git()` is the fix, and a shared helper nobody is
//! required to use is a note rather than a rule, which is the argument
//! `structural_git_env.rs` already makes for `detached()` in `src/probe.rs`.
//! This is the same argument for the same reason, one directory over.
//!
//! WHY A PARSER AND NOT A REGEX, and here the difference is not academic.
//! `structural_git_env.rs` contains the literal text `Command::new("git")`
//! four times, inside raw-string fixtures it hands to its own reader and inside
//! a comment in one of them. A grep refuses that file; a syntax tree does not
//! see a call there at all, because the contents of a string literal are not
//! Rust. So the check needs no exemption list, and a file that needs no
//! exemption cannot have a stale one.
//!
//! WHAT A CLEAN RUN IS NOT. tree-sitter recovers a tree from almost any input,
//! so a reader that only counts what it found reports the same silence over a
//! compliant file and over one whose parse collapsed -- and a `Command::new`
//! inside a recovered ERROR region is invisible to the walk. `unparsed` is what
//! makes that case loud, and it is asked of every file rather than of the suite
//! as a whole, so the answer names the file.

#![expect(
    clippy::expect_used,
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    reason = "A test asserts on the outcome; a panic in the harness IS the failure report, and there is no caller to hand a Result to. `let_underscore_must_use` is for the shared support module's best-effort filesystem calls, which are compiled into every test binary that includes it -- the same allowance structural_git_env.rs carries"
)]

mod support;

use support::syntax::{calls, enclosing_function, unparsed};

#[test]
fn no_fixture_lets_path_decide_which_git_it_meant() {
    let mut offenders: Vec<String> = Vec::new();

    for path in test_sources() {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("<unnamed>")
            .to_owned();
        let source = std::fs::read_to_string(&path).expect("a listed test source is readable");

        assert_eq!(
            unparsed(&source),
            None,
            "tests/{name} did not parse, so this check looked at a recovered fragment of it \
             and found nothing there -- which is not the same as the rule holding"
        );

        offenders.extend(
            bare_git(&source)
                .into_iter()
                .map(|where_| format!("tests/{name} {where_}")),
        );
    }

    assert!(
        offenders.is_empty(),
        "a fixture builds `git` by name, so on a machine with `uphold shim --install` run it \
         drives the shim rather than git -- and the tests it breaks are the ones whose fixture \
         is a policy that deliberately does not load. Use `support::real_git()`: {}",
        offenders.join(", ")
    );
}

/// Every `Command::new("git")` in `source`, by line and enclosing function.
///
/// The literal is what is refused, not the variable: `Command::new(program)`
/// inside a helper that was handed a resolved path is the shape this rule wants
/// and cannot be told from the offending one by name alone. So the test is on
/// the ARGUMENT, read off the call node's own text.
///
/// A call with no enclosing function -- a static initializer, a module-level
/// const -- is an offender rather than a skip, since the rule is about where the
/// construction happens and "nowhere in particular" is not a resolved path.
fn bare_git(source: &str) -> Vec<String> {
    calls(source)
        .into_iter()
        .filter(|(function, _)| function == "Command::new")
        .filter(|(_, node)| {
            source[node.byte_range()]
                .replace(char::is_whitespace, "")
                .starts_with("Command::new(\"git\")")
        })
        .map(|(_, node)| {
            format!(
                "line {} in {}",
                node.start_position().row + 1,
                enclosing_function(source, node)
                    .unwrap_or_else(|| "<no enclosing function>".into())
            )
        })
        .collect()
}

/// Every Rust source in `tests/`, including this one and the support module.
///
/// Listed from the directory rather than written out, because a rule that has
/// to be added to by hand is a rule the next test file silently escapes.
fn test_sources() -> Vec<std::path::PathBuf> {
    let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests"));
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                found.push(path);
            }
        }
    }
    assert!(
        found.len() > 20,
        "the suite has {} Rust sources, which is too few to be the whole of tests/ -- \
         the walk found the wrong directory and the rule would pass over nothing",
        found.len()
    );
    found
}

#[test]
fn the_check_can_tell_a_bare_name_from_a_resolved_one() {
    // The negative control. A test that cannot fail is worth nothing, and the
    // three cases below are exactly the three this rule has to separate.
    let offending = r#"
        use std::process::Command;
        fn fixture(root: &Path) {
            let _ = Command::new("git").arg("add").current_dir(root).status();
        }
    "#;
    assert_eq!(bare_git(offending).len(), 1, "the bare name was not found");
    assert_eq!(unparsed(offending), None, "the fixture itself is Rust");

    let clean = r#"
        use std::process::Command;
        fn fixture(root: &Path) {
            // Command::new("git") in a comment is not a call.
            let _ = Command::new(support::real_git()).arg("add").status();
        }
        fn helper(program: PathBuf) -> Command {
            Command::new(program)
        }
    "#;
    assert!(
        bare_git(clean).is_empty(),
        "a comment or a resolved path was read as a violation"
    );
    assert_eq!(unparsed(clean), None, "the fixture itself is Rust");

    // The case that makes the parser worth its cost, and it is not
    // hypothetical: `structural_git_env.rs` carries this shape four times, and
    // a grep-based rule would refuse the file that argues against grep.
    let in_a_string = r###"
        fn fixture() {
            let source = r##"
                let _ = Command::new("git").arg("worktree").output();
            "##;
            let _ = source;
        }
    "###;
    assert!(
        bare_git(in_a_string).is_empty(),
        "text inside a string literal was read as a call"
    );
    assert_eq!(unparsed(in_a_string), None, "the fixture itself is Rust");
}
