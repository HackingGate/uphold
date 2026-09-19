//! A policy names no provider.
//!
//! THE RULE. No file under `src/policy/` mentions a provider: not `git`, not
//! `tree_sitter`, not a provider's module under `src/evidence/`, and not the
//! name a provider reports itself under. A policy is handed a body of facts
//! and judges the facts, and the names it prints in a refusal are read off the
//! facts rather than written into the predicate.
//!
//! WHY IT IS THE PROOF AND NOT A STYLE. Issue 165 asks that a provider can be
//! replaced without the policy being rewritten. `src/policy.rs` demonstrates
//! the replacement -- one predicate judged over the parser's body and over the
//! diff's -- and this is what makes the demonstration mean something: a
//! predicate that could not have named either provider could not have been
//! written against one. The two compose. The test in `src/policy.rs` shows the
//! substitution works today; this shows the next edit cannot quietly undo it.
//!
//! WHY THE LIST IS READ AND NOT WRITTEN. The provider names are collected off
//! `src/evidence/`, so a provider added there is a name refused here on the
//! same commit. A list written into this file would be the one that fell
//! behind.
//!
//! WHAT A CLEAN RUN IS NOT. The file is parsed first, for the reason every
//! structural test here gives: a source the grammar could not read is a source
//! this check read a fragment of, and a fragment naming nothing is not a file
//! naming nothing.

#![expect(
    clippy::expect_used,
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    reason = "A test asserts on the outcome; a panic in the harness IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};

use support::syntax::unparsed;

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` file directly under `directory`, sorted.
fn sources_under(directory: &Path) -> Vec<(String, String)> {
    let listing = std::fs::read_dir(directory).expect("a source directory is readable");
    let mut found: Vec<(String, String)> = listing
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.extension().is_some_and(|kind| kind == "rs"))
        .map(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("a file name")
                .to_owned();
            (name, std::fs::read_to_string(&path).expect("a source file"))
        })
        .collect();
    found.sort();
    found
}

/// The words a policy may not use: `git`, `tree_sitter`, each provider
/// module's stem, and each name a provider reports itself under.
fn forbidden() -> Vec<String> {
    let mut names = vec![String::from("git"), String::from("tree_sitter")];
    for (file, source) in sources_under(&manifest().join("src/evidence")) {
        assert_eq!(unparsed(&source), None, "src/evidence/{file} is Rust");
        names.push(file.trim_end_matches(".rs").to_owned());
        // `name: "<provider>"` inside a `Provider { .. }` literal, which is
        // the only place a provider's name is spelled.
        for (index, _) in source.match_indices("name: \"") {
            let rest = source.get(index + "name: \"".len()..).unwrap_or_default();
            let name = rest.split('"').next().unwrap_or_default();
            if !name.is_empty() {
                names.push(name.to_owned());
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

/// The words of a source, where a word is a run of identifier characters and
/// hyphens -- so `tree-sitter` and `diff-text` are one word each, and `git`
/// inside `digit` is not a word at all.
fn words(source: &str) -> Vec<String> {
    source
        .split(|character: char| {
            !character.is_alphanumeric() && character != '_' && character != '-'
        })
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect()
}

fn offending_words(source: &str, forbidden: &[String]) -> Vec<String> {
    let mut found: Vec<String> = words(source)
        .into_iter()
        .filter(|word| forbidden.contains(word))
        .collect();
    found.sort();
    found.dedup();
    found
}

#[test]
fn no_policy_names_a_provider() {
    let forbidden = forbidden();
    assert!(
        forbidden.iter().any(|name| name == "tree-sitter")
            && forbidden.iter().any(|name| name == "diff-text"),
        "the provider names were not read off src/evidence/, so this test is checking against \
         a list it did not build: {forbidden:?}"
    );

    let policies = sources_under(&manifest().join("src/policy"));
    assert!(
        !policies.is_empty(),
        "src/policy/ holds no policy, so nothing was checked"
    );
    for (file, source) in policies {
        assert_eq!(
            unparsed(&source),
            None,
            "src/policy/{file} did not parse, so this check read a fragment of it and found \
             nothing there -- which is not the same as the file naming no provider"
        );
        let offending = offending_words(&source, &forbidden);
        assert!(
            offending.is_empty(),
            "src/policy/{file} names a provider, which is the coupling a policy exists not to \
             have: {offending:?}. Read the fact's `provider.name` off the evidence instead."
        );
    }
}

#[test]
fn the_reader_can_tell_a_policy_that_names_a_provider_from_one_that_does_not() {
    // The negative control, both ways. A rule that reports nothing over the
    // one policy here is not evidence that it would report the next one.
    let forbidden = forbidden();
    let naming = r#"
        /// Reads the tree-sitter facts and, when those are missing, asks git.
        pub(crate) fn judge(body: &Body) -> bool {
            body.found.iter().any(|item| item.provider.name == "diff-text")
        }
    "#;
    assert_eq!(unparsed(naming), None, "the fixture is Rust");
    assert_eq!(
        offending_words(naming, &forbidden),
        ["diff-text", "git", "tree-sitter"]
    );

    let silent = r"
        /// A digit is not the forbidden word, and a legitimate word is not either.
        pub(crate) fn judge(body: &Body) -> bool {
            body.established(Kind::FunctionRemoved).clean()
        }
    ";
    assert_eq!(unparsed(silent), None, "the fixture is Rust");
    assert!(offending_words(silent, &forbidden).is_empty());
}
