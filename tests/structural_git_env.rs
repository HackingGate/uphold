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

/// Every call expression in `source`, with the text of the function called.
fn calls(source: &str) -> Vec<(String, Node<'_>)> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(source, None).unwrap();
    let tree = Box::leak(Box::new(tree));

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
    let bare = calls(offending)
        .iter()
        .filter(|(function, _)| function == "Command::new")
        .filter_map(|(_, node)| enclosing_function(offending, *node))
        .filter(|inside| inside != "detached")
        .count();
    assert_eq!(bare, 1, "the bare construction was not found");

    let clean = r#"
        fn detached(program: &str) -> Command {
            Command::new(program)
        }
        fn worktree(root: &Path) {
            // Command::new("git") in a comment is not a call.
            let _ = detached("git").arg("status").output();
        }
    "#;
    let quiet = calls(clean)
        .iter()
        .filter(|(function, _)| function == "Command::new")
        .filter_map(|(_, node)| enclosing_function(clean, *node))
        .filter(|inside| inside != "detached")
        .count();
    assert_eq!(
        quiet, 0,
        "a comment or a helper call was read as a violation"
    );
}
