//! One structural check, written with the parser this binary already carries.
//!
//! It exists twice over: as a rule this repository needs, and as the prototype
//! the structural-tier research asks for.
//!
//! THE RULE. `probe` shells out to `git` to make a throwaway worktree, and to a
//! hook runner to drive one hook. Both must run with git's own environment taken
//! away: a hook runner exports `GIT_DIR` and `GIT_INDEX_FILE`, several of them
//! RELATIVE to the repository the hook fired in, so a child that inherits them
//! is answered about a repository the run was never about -- with write access
//! to it. The first version of `probe` did exactly that and could not create its
//! worktree at all; where it could, the staging would have gone into somebody
//! else's index.
//!
//! `detached()` is the one place that strips them. This test is what makes
//! skipping it turn something red, because a shared helper nobody is required to
//! use is a note rather than a rule.
//!
//! WHY A PARSER AND NOT A REGEX. `Command::new` is greppable and that is not the
//! rule: what has to be true is that every construction of a command in this
//! module goes through the helper, which is a question about the call expression
//! rather than about the line. A regex over `Command::new` cannot tell the call
//! inside `detached` -- the one that is allowed, because it is the helper -- from
//! the calls that must not exist, and a regex over `detached(` cannot tell a call
//! from a comment mentioning one. This file uses the tree-sitter grammar this
//! crate already depends on for `comment_regexp`, so the tier costs no new
//! dependency.
//!
//! WHAT A CLEAN RUN IS NOT. tree-sitter recovers a tree from almost any input,
//! so a reader that only counts what it found reports the same silence over a
//! compliant module and over one whose parse collapsed. An unterminated string
//! literal early in a file swallows everything after it into one ERROR node,
//! and a `Command::new` inside that region is invisible to the walk -- the
//! check goes green over the exact defect it was written for. `unparsed` is
//! what makes that case loud, and the third test below is what proves the
//! invisibility is real rather than theoretical.
//!
//! `comments.rs` answers this differently for the rule it carries, and the
//! difference is the point: a forbidden-comment rule reads what error recovery
//! recovered because comments survive it, and a comment it missed is a comment
//! nobody wrote a rule about. A structural rule asking "does this shape appear
//! anywhere" has no such luck -- the shape it missed is the shape it was hunting.
//!
//! WHAT THE CHEAP VERSION DOES NOT DO, said plainly because it is the finding.
//! One consuming repository carries a 492-line Python checker for the same rule,
//! and the length is not waste: it traces the `env=` argument through wrappers,
//! assignments and parameters, and stops where certainty does. This asks a
//! narrower question -- does any `Command::new` appear outside the helper -- and
//! that question is answerable from the syntax tree alone. The moment the rule
//! needs "and the environment it passes is traceable to the helper", it needs
//! more than a syntax tree, which is the boundary the research issue is about.

#![expect(
    clippy::expect_used,
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    reason = "A test asserts on the outcome; a panic in the harness IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use support::syntax::{calls, enclosing_function, function_named, unparsed};

#[test]
fn every_command_probe_builds_has_gits_environment_taken_away() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/probe.rs"))
        .expect("probe.rs is where the rule applies");

    assert_eq!(
        unparsed(&source),
        None,
        "src/probe.rs did not parse, so this check looked at a recovered fragment of it \
         and found nothing there -- which is not the same as the rule holding"
    );

    let offenders = bare_constructions(&source);
    assert!(
        offenders.is_empty(),
        "src/probe.rs builds a command without going through `detached`, so it inherits \
         GIT_DIR and GIT_INDEX_FILE from whatever ran this binary -- under a hook runner \
         those name another repository's index: {}",
        offenders.join(", ")
    );

    // And the helper still strips, read off its own body rather than off the
    // file. A `source.contains("\"GIT_DIR\"")` is satisfied by this very
    // sentence, and by a `GIT_DIR` in any other function -- which is the
    // required-shape direction a matcher cannot express, in the file arguing
    // that it cannot.
    let stripped = stripped_names(&source);
    for name in [
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_WORK_TREE",
        "GIT_PREFIX",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG_PARAMETERS",
    ] {
        assert!(
            stripped.iter().any(|found| found == name),
            "`detached` no longer calls env_remove({name}), so a child of this module is \
             answered about the repository the hook fired in. It strips: {stripped:?}"
        );
    }
}

/// Every construction of a command outside the helper, by line and function.
///
/// `detached` is the helper: its own `Command::new` is the one that is allowed
/// to exist, because it is the construction every other one has to go through.
/// A call with no enclosing function -- a static initializer, or a module-level
/// const -- is an offender rather than a skip, since the rule is about where the
/// construction happens and "nowhere in particular" is not `detached`.
fn bare_constructions(source: &str) -> Vec<String> {
    calls(source)
        .into_iter()
        .filter(|(function, _)| function == "Command::new")
        .filter_map(|(_, node)| {
            let inside = enclosing_function(source, node);
            match inside.as_deref() {
                Some("detached") => None,
                other => Some(format!(
                    "line {} in {}",
                    node.start_position().row + 1,
                    other.unwrap_or("<no enclosing function>")
                )),
            }
        })
        .collect()
}

/// The environment names `detached` takes away, read off `detached`'s body.
///
/// Empty when there is no such function and empty when it calls no
/// `env_remove`, because both leave the environment in place and the assertion
/// reading this should not have to tell them apart.
///
/// WHAT THIS DOES NOT PROVE, and it is the same boundary the ADR draws. The
/// helper hands `env_remove` a loop variable, so the argument at the call site
/// is an identifier: what is read here is that the helper removes SOMETHING and
/// that the name appears as a literal in the same function. Tying this literal
/// to that call means following the value into the loop, which is the tier
/// above a syntax tree.
fn stripped_names(source: &str) -> Vec<String> {
    let Some(helper) = function_named(source, "detached") else {
        return Vec::new();
    };
    let mut cursor = helper.walk();
    let mut pending = vec![helper];
    let mut removes = false;
    let mut names = Vec::new();
    while let Some(node) = pending.pop() {
        if node.kind() == "call_expression"
            && node
                .child_by_field_name("function")
                .is_some_and(|function| source[function.byte_range()].ends_with("env_remove"))
        {
            removes = true;
        }
        if node.kind() == "string_literal" {
            names.push(source[node.byte_range()].trim_matches('"').to_owned());
        }
        pending.extend(node.children(&mut cursor));
    }
    if removes {
        names
    } else {
        Vec::new()
    }
}

#[test]
fn the_check_can_tell_the_helper_from_a_bare_construction() {
    // The negative control. A test that cannot fail is worth nothing, and this
    // one is cheap: hand the same reader a module with the defect in it and it
    // has to find it, and one with only the helper's own call and it has to
    // stay quiet.
    let offending = r#"
        use std::process::Command;
        fn detached(program: &str) -> Command {
            let mut command = Command::new(program);
            command.env_remove("GIT_DIR");
            command
        }
        fn worktree(root: &Path) {
            let _ = Command::new("git").arg("worktree").current_dir(root).output();
        }
    "#;
    assert_eq!(
        bare_constructions(offending).len(),
        1,
        "the bare construction was not found"
    );
    assert_eq!(unparsed(offending), None, "the fixture itself is Rust");

    let clean = r#"
        fn detached(program: &str) -> Command {
            Command::new(program)
        }
        fn worktree(root: &Path) {
            // Command::new("git") in a comment is not a call.
            let _ = detached("git").arg("status").output();
        }
    "#;
    assert!(
        bare_constructions(clean).is_empty(),
        "a comment or a helper call was read as a violation"
    );
    assert_eq!(unparsed(clean), None, "the fixture itself is Rust");

    // The other direction, driven both ways as well: the helper in `offending`
    // removes something and names it, the one in `clean` removes nothing. A
    // required-shape assertion nobody has seen fail is a required-shape
    // assertion that may be reading the wrong thing.
    assert_eq!(
        stripped_names(offending),
        ["GIT_DIR"],
        "the names were not read out of the helper's own body"
    );
    assert!(
        stripped_names(clean).is_empty(),
        "a helper that calls no env_remove was reported as stripping something"
    );
}

#[test]
fn a_source_that_did_not_parse_is_not_a_source_that_passed() {
    // Two sources one character apart, with opposite verdicts from the walk.
    //
    // The defect is the same line in both. In the first, an unterminated string
    // literal above it collapses the rest of the file into one ERROR region and
    // the call inside it is not a `call_expression` any more -- so the walk
    // finds nothing, and a check that reported what it found would call this
    // file clean. That is the whole failure mode: not a rule that says the wrong
    // thing, a rule that has stopped being able to look and says the same silence
    // it says when everything is in order.
    let swallowed = r#"
        fn earlier() {
            let text = "one quote away from parsing;
        }
        fn worktree(root: &Path) {
            let _ = Command::new("git").arg("worktree").current_dir(root).output();
        }
    "#;
    assert!(
        bare_constructions(swallowed).is_empty(),
        "the fixture no longer hides its defect from the walk, so this test has \
         stopped standing for the case it was written for"
    );
    // Line 6 and not line 3: the grammar keeps lexing past the opening quote and
    // gives up further down, so what this reports is where recovery failed
    // rather than where the mistake is. Pinned rather than smoothed over,
    // because a reader sent to the wrong line by a check is owed the difference.
    assert_eq!(
        unparsed(swallowed),
        Some(6),
        "the reader did not notice that it was looking at a fragment"
    );

    let repaired = r#"
        fn earlier() {
            let text = "one quote away from parsing";
        }
        fn worktree(root: &Path) {
            let _ = Command::new("git").arg("worktree").current_dir(root).output();
        }
    "#;
    assert_eq!(unparsed(repaired), None, "the repaired twin is Rust");
    assert_eq!(
        bare_constructions(repaired).len(),
        1,
        "the same defect, now that the grammar can reach it"
    );
}
