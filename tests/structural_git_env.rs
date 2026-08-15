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
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "A test asserts on the outcome; a panic in the harness IS the failure report, and there is no caller to hand a Result to"
)]

use tree_sitter::{Node, Parser};

/// The tree, kept alive for the nodes handed out of these readers.
fn parse(source: &str) -> &'static tree_sitter::Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(source, None).unwrap();
    Box::leak(Box::new(tree))
}

/// The line of the first region the grammar could not read, if there is one.
///
/// A structural check over a source this returns `Some` for has established
/// nothing about that source, and reporting it clean is the `UNKNOWN -> PASS`
/// this repository keeps refusing one seam at a time.
fn unparsed(source: &str) -> Option<usize> {
    let tree = parse(source);
    if !tree.root_node().has_error() {
        return None;
    }
    let mut cursor = tree.walk();
    let mut pending = vec![tree.root_node()];
    let mut first = None;
    while let Some(node) = pending.pop() {
        if node.is_error() || node.is_missing() {
            let line = node.start_position().row + 1;
            first = Some(first.map_or(line, |earlier: usize| earlier.min(line)));
        }
        pending.extend(node.children(&mut cursor));
    }
    // `has_error` is true and no node carries the flag only if the grammar
    // changed shape underneath this reader. Line 1 is the honest answer then:
    // something is wrong and the reader cannot say where.
    Some(first.unwrap_or(1))
}

/// Every call expression in `source`, with the text of the function called.
///
/// What the grammar recovered, which over a broken source is less than what is
/// there. Every caller asks `unparsed` first.
fn calls(source: &str) -> Vec<(String, Node<'_>)> {
    let tree = parse(source);

    let mut found = Vec::new();
    let mut cursor = tree.walk();
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let text = source[function.byte_range()].to_owned();
                found.push((text, node));
            }
        }
        pending.extend(node.children(&mut cursor));
    }
    found
}

/// The function a node sits inside, by name.
fn enclosing_function<'a>(source: &'a str, node: Node<'a>) -> Option<String> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "function_item" {
            let name = parent.child_by_field_name("name")?;
            return Some(source[name.byte_range()].to_owned());
        }
        current = parent;
    }
    None
}

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

    let offenders: Vec<String> = calls(&source)
        .into_iter()
        .filter(|(function, _)| function == "Command::new")
        .filter_map(|(_, node)| {
            let inside = enclosing_function(&source, node);
            // `detached` is the helper. Its own `Command::new` is the one that
            // is allowed to exist, because it is the construction every other
            // one has to go through.
            match inside.as_deref() {
                Some("detached") => None,
                other => Some(format!(
                    "line {} in {}",
                    node.start_position().row + 1,
                    other.unwrap_or("<no enclosing function>")
                )),
            }
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "src/probe.rs builds a command without going through `detached`, so it inherits \
         GIT_DIR and GIT_INDEX_FILE from whatever ran this binary -- under a hook runner \
         those name another repository's index: {}",
        offenders.join(", ")
    );

    // And the helper still exists and still strips: a test that only counted
    // call sites would pass over a `detached` that had quietly stopped removing
    // anything.
    for name in ["GIT_DIR", "GIT_INDEX_FILE", "GIT_WORK_TREE"] {
        assert!(
            source.contains(&format!("\"{name}\"")),
            "`detached` no longer names {name}, so nothing takes it away"
        );
    }
    assert!(
        source.contains("env_remove"),
        "`detached` no longer removes anything from the environment"
    );
}

/// What the check counts: constructions outside the helper.
///
/// One function rather than the same four lines at each call site, because the
/// three tests below differ by the source they are handed and by nothing else.
fn bare_constructions(source: &str) -> usize {
    calls(source)
        .iter()
        .filter(|(function, _)| function == "Command::new")
        .filter_map(|(_, node)| enclosing_function(source, *node))
        .filter(|inside| inside != "detached")
        .count()
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
        bare_constructions(offending),
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
    assert_eq!(
        bare_constructions(clean),
        0,
        "a comment or a helper call was read as a violation"
    );
    assert_eq!(unparsed(clean), None, "the fixture itself is Rust");
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
            let unterminated = "quote that never closes;
        }
        fn worktree(root: &Path) {
            let _ = Command::new("git").arg("worktree").current_dir(root).output();
        }
    "#;
    assert_eq!(
        bare_constructions(swallowed),
        0,
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
            let terminated = "quote that closes";
        }
        fn worktree(root: &Path) {
            let _ = Command::new("git").arg("worktree").current_dir(root).output();
        }
    "#;
    assert_eq!(unparsed(repaired), None, "the repaired twin is Rust");
    assert_eq!(
        bare_constructions(repaired),
        1,
        "the same defect, now that the grammar can reach it"
    );
}
