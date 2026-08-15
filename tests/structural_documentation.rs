//! The second structural rule, and the boundary the documentation research asks
//! about: what a parser can DECIDE, and where generation would have to start.
//!
//! THE RULE. Every declaration one module offers another -- `pub` or
//! `pub(crate)`, at the top level of a file in `src/` -- has a doc comment above
//! it. Nothing here judges what the comment says.
//!
//! WHY A PARSER, when rustc has `missing_docs`. Because that lint says nothing
//! about this crate. It fires on items reachable from the crate root as PUBLIC,
//! and this is a binary: there is no public API, every shared item is
//! `pub(crate)`, and turning the lint on reports zero while twenty-five shared
//! declarations carry no documentation at all. The compiler is asking a question
//! about a published surface, and the surface a reader of this crate meets is
//! the one between its modules.
//!
//! WHY IT IS A LIST AND NOT A NUMBER. The tree does not comply -- see `KNOWN`.
//! A ceiling ("no more than twenty-five") is satisfied by documenting one
//! declaration while adding another, and the gate stays green through the swap.
//! Naming them means a new one fails, and a stale entry -- an id that is
//! documented now, or gone -- fails too, the way `policy/hooks.toml` refuses a
//! waiver that matches nothing. An exemption that no longer describes the tree
//! reads as a decision while doing nothing.
//!
//! WHERE GENERATION WOULD START, AND WHY IT IS NOT HERE. Selecting the material
//! a writer needs is deterministic and cheap: the signature, the module's own
//! docstring, the body, and every call site in the tree. `the_material_a_writer_
//! would_be_handed` below prints exactly that bundle and generates nothing. What
//! cannot be mechanized is the sentence, because the sentence is the reason the
//! code is that way -- which is not in the syntax tree, and is why a generated
//! comment that restates the signature is worse than no comment. This repository
//! already refuses that half from the other side: `no-trivial-comment` reads
//! doc comments too, so a `/// Gets the name.` inserted to satisfy this rule is
//! refused by the content policy on the same commit. The two compose, and
//! neither is an LLM deciding whether a declaration is adequately documented.

#![expect(
    clippy::expect_used,
    clippy::let_underscore_must_use,
    clippy::tests_outside_test_module,
    reason = "A test asserts on the outcome; a panic in the harness IS the failure report, and there is no caller to hand a Result to"
)]

mod support;

use std::path::{Path, PathBuf};

use support::syntax::{declarations, unparsed, Declaration};

/// The shared declarations that carry no documentation today.
///
/// `path::name`. Lowering this list is the commit that earns it, which is the
/// same arrangement `scripts/coverage.sh` has with its floor. Nothing may be
/// added to it: a new undocumented declaration is a failing test, and the fix
/// is a sentence rather than a line here.
const KNOWN: &[&str] = &[
    "audit.rs::for_publication",
    "catalog.rs::Enforcement",
    "catalog.rs::get",
    "check.rs::Supply",
    "check.rs::installed",
    "config.rs::PolicyFile",
    "config.rs::Rule",
    "git.rs::config_global",
    "git.rs::dir",
    "git.rs::run",
    "guard/message.rs::prevent_ai_author",
    "guard/message.rs::prevent_unusual_unicode",
    "guard/message.rs::unusual_unicode_in",
    "guard/mod.rs::RunRequest",
    "guard/names.rs::in_message",
    "guard/push.rs::prevent_public_push",
    "guard/sets.rs::no_hand_copied_base_rule",
    "guard/unicode.rs::in_files",
    "pins.rs::Declaration",
    "pins.rs::read_pins",
    "report.rs::body_for",
    "scan.rs::Scan",
    "shim.rs::Shim",
    "text.rs::check",
];

/// Every `.rs` file under `src/`, by path relative to it.
fn sources() -> Vec<(String, String)> {
    fn walk(directory: &Path, root: &Path, found: &mut Vec<(String, String)>) {
        let listing = std::fs::read_dir(directory).expect("src/ is readable");
        let mut entries: Vec<PathBuf> = listing
            .map(|entry| entry.expect("a directory entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, root, found);
            } else if path.extension().is_some_and(|kind| kind == "rs") {
                let name = path
                    .strip_prefix(root)
                    .expect("a path under src/")
                    .to_string_lossy()
                    .replace('\\', "/");
                found.push((name, std::fs::read_to_string(&path).expect("a source file")));
            }
        }
    }

    let root = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));
    let mut found = Vec::new();
    walk(&root, &root, &mut found);
    found
}

/// `path::name` for every shared declaration with no doc comment above it.
fn undocumented() -> Vec<String> {
    let mut found = Vec::new();
    for (path, source) in sources() {
        assert_eq!(
            unparsed(&source),
            None,
            "src/{path} did not parse, so this check read a recovered fragment of it and \
             found nothing there -- which is not the same as every declaration in it being \
             documented"
        );
        for declaration in declarations(&source) {
            if declaration.shared && !declaration.documented {
                found.push(format!("{path}::{}", declaration.name));
            }
        }
    }
    found.sort();
    found
}

#[test]
fn every_declaration_one_module_offers_another_is_documented() {
    let found = undocumented();

    let new: Vec<&String> = found
        .iter()
        .filter(|id| !KNOWN.contains(&id.as_str()))
        .collect();
    assert!(
        new.is_empty(),
        "a module offers these to the rest of the crate with nothing said about them. \
         The reader of a `pub(crate)` item is somebody who is not looking at this file: \
         {new:?}"
    );

    let stale: Vec<&&str> = KNOWN
        .iter()
        .filter(|id| !found.iter().any(|current| current == **id))
        .collect();
    assert!(
        stale.is_empty(),
        "these are documented now, or gone. Remove them from KNOWN: an exemption that no \
         longer describes the tree reads as a decision while doing nothing, and the next \
         one to go stale is indistinguishable from it: {stale:?}"
    );
}

#[test]
fn the_reader_can_tell_a_documented_declaration_from_an_undocumented_one() {
    // The negative control, driven both ways. A rule that reports 25 things is
    // not evidence that it can report the twenty-sixth, or that it would stay
    // quiet about a declaration somebody documented.
    let source = r"
        /// What this one is for.
        pub(crate) fn documented(path: &Path) -> bool { true }

        pub(crate) fn bare(path: &Path) -> bool { false }

        /// Documented, and derived, which puts an attribute between the two.
        #[derive(Debug, Default)]
        pub(crate) struct Derived { field: usize }

        #[derive(Debug)]
        pub(crate) struct BareDerived { field: usize }

        // An ordinary comment is not documentation, and the grammar is what
        // tells them apart -- `//` and `///` are one character apart and mean
        // different things.
        pub(crate) fn remarked_upon(path: &Path) -> bool { false }

        /// Private, so out of scope however well it is written.
        fn private_helper() -> bool { true }

        fn bare_private_helper() -> bool { true }
    ";
    assert_eq!(unparsed(source), None, "the fixture itself is Rust");

    let found: Vec<String> = declarations(source)
        .iter()
        .filter(|declaration| declaration.shared && !declaration.documented)
        .map(|declaration| declaration.name.clone())
        .collect();
    assert_eq!(
        found,
        ["bare", "BareDerived", "remarked_upon"],
        "the reader disagrees with a fixture written to be read one way"
    );
}

#[test]
fn the_material_a_writer_would_be_handed() {
    // Not generation, and not a gate: the selection step, run and printed so
    // that what is deterministic here is visible and what is not stays outside
    // this repository. `cargo test -- --nocapture the_material` prints it.
    //
    // Everything below is read off the parse or off the tree. The sentence
    // nobody can read off either is the reason the declaration exists, which is
    // why the output is a bundle for a person and not a draft comment.
    let Some(subject) = KNOWN.first() else {
        return;
    };
    let (file, name) = subject.split_once("::").expect("path::name");
    let source = std::fs::read_to_string(
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src")).join(file),
    )
    .expect("the file KNOWN names");

    let declaration: Declaration = declarations(&source)
        .into_iter()
        .find(|found| found.name == name)
        .expect("the declaration KNOWN names");

    println!("subject: src/{file} line {}", declaration.line);
    println!("kind: {}", declaration.kind);
    let module = source
        .lines()
        .take_while(|line| line.starts_with("//!"))
        .count();
    println!("module docstring: {module} line(s)");
    let callers: Vec<String> = sources()
        .iter()
        .filter(|(path, body)| path != file && body.contains(&format!("{name}(")))
        .map(|(path, _)| format!("src/{path}"))
        .collect();
    println!("called from: {}", callers.join(", "));
    println!(
        "signature: {}",
        source
            .lines()
            .nth(declaration.line.saturating_sub(1))
            .unwrap_or_default()
            .trim()
    );

    // The assertion is about the SELECTION, which is the only part this
    // repository is responsible for: a bundle naming no call site is a bundle a
    // writer cannot use, and it is the case that would go unnoticed.
    assert!(
        !callers.is_empty(),
        "a shared declaration that no other module calls: either the selection is broken \
         or `{subject}` is not shared at all"
    );
}
