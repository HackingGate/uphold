//! Function declarations, as the parser sees them, before and after the
//! change.
//!
//! Proven: a `function_item` in the tree at `HEAD` that is in no tree in the
//! index is a function the change removes, and no reading of the text is
//! involved. The grammars are the ones this binary already links for its
//! comment rules, read off the same table, so a language added there is a
//! language this provider reads.
//!
//! The one rule this provider carries that the others do not is ADR 0003's:
//! a tree with an ERROR or MISSING node in it is a tree the grammar recovered
//! rather than read, and a walk over it finds less than is there. A file that
//! did not parse on either side makes the whole answer `Unavailable`, naming
//! the file and the line, rather than a shorter list of facts that reads
//! exactly like a clean one. Files in a language this binary links no grammar
//! for are outside the claim and are skipped without a word.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use tree_sitter::{Node, Parser};

use super::{Context, Evidence, FILE_REMOVED, Kind, Observation, Provider, Source, Strength};
use crate::comments::Language;

/// Who this is.
pub(crate) const PROVIDER: Provider = Provider {
    name: "tree-sitter",
    strength: Strength::Proven,
    claims: &[
        Kind::FunctionAdded,
        Kind::FunctionRemoved,
        Kind::SignatureChanged,
    ],
};

/// What the two sides are: the commit the index is measured against, and the
/// index. The same spelling the textual provider uses, so the two providers'
/// facts about one function are about one comparison.
pub(crate) const REVISION: &str = "HEAD..index";

/// The provider over the staged change's syntax trees.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Declarations;

impl Source for Declarations {
    fn provider(&self) -> Provider {
        PROVIDER
    }

    fn observe(&self, context: &Context<'_>) -> Observation {
        let Some(changed) = context.changed else {
            return Observation::Unavailable {
                provider: PROVIDER,
                reason: format!(
                    "no index to compare against HEAD at {}",
                    context.stage.as_str()
                ),
            };
        };
        let mut found = Vec::new();
        for path in changed {
            let Some(language) = Language::for_path(path) else {
                continue;
            };
            let Some((grammar, _)) = language.grammar() else {
                continue;
            };
            match file_facts(context.root, path, language, &grammar) {
                Ok(items) => found.extend(items),
                Err(reason) => {
                    return Observation::Unavailable {
                        provider: PROVIDER,
                        reason,
                    };
                }
            }
        }
        Observation::Found(found)
    }
}

/// The facts one file's two sides establish, or the reason one side could
/// not be read as a tree.
///
/// A side the revision has no blob at declares nothing, and when that side is
/// the index the file itself is what the change removes: every removal is then
/// marked [`FILE_REMOVED`], so a policy can tell a function deleted with its
/// file from one deleted out of a file that stays.
fn file_facts(
    root: &Path,
    path: &str,
    language: Language,
    grammar: &tree_sitter::Language,
) -> Result<Vec<Evidence>, String> {
    let declared = |rev: &str, at: &str| {
        read_side(root, rev, path)?
            .map(|source| {
                declared_in(grammar, language, &source).map_err(|line| {
                    format!(
                        "{path}:{line} at {at} did not parse, so the functions it declares \
                         were never read"
                    )
                })
            })
            .transpose()
    };
    let before = declared(&format!("HEAD:{path}"), "HEAD")?.unwrap_or_default();
    let after = declared(&format!(":{path}"), "the index")?;
    let file_removed = after.is_none();
    Ok(compare(
        path,
        &before,
        &after.unwrap_or_default(),
        file_removed,
    ))
}

/// One side's text, `None` where the path has no blob at that revision, or
/// the reason it could not be read.
fn read_side(root: &Path, rev: &str, path: &str) -> Result<Option<String>, String> {
    let sha = crate::git::try_run(root, &["rev-parse", "-q", "--verify", rev])
        .map_err(|error| error.to_string())?;
    let Some(sha) = sha else {
        return Ok(None);
    };
    let bytes = crate::guard::scope::read_object(root, sha.trim(), path)
        .map_err(|error| error.to_string())?;
    match crate::guard::scope::decode(&bytes) {
        crate::guard::scope::Decoded::Text(text) => Ok(Some(text)),
        crate::guard::scope::Decoded::Binary => Err(format!(
            "{path} at {rev} is binary, and a grammar reads text"
        )),
        crate::guard::scope::Decoded::Unreadable(why) => {
            Err(format!("{path} at {rev} cannot be read as text ({why})"))
        }
    }
}

/// The node kinds that declare a function in each grammar.
const fn function_kinds(language: Language) -> &'static [&'static str] {
    match language {
        Language::Rust => &["function_item"],
        Language::Python => &["function_definition"],
        Language::Go => &["function_declaration", "method_declaration"],
        Language::HashLines => &[],
    }
}

/// Every function a source declares, by name, with each declaration's
/// signature -- or the first line the grammar could not read.
///
/// A name maps to a list because one file declares `fn new` once per `impl`,
/// and a reader keyed on the name alone would report the second as a change
/// to the first. The lists are sorted, so two sides declaring the same
/// signatures in a different order compare equal.
fn declared_in(
    grammar: &tree_sitter::Language,
    language: Language,
    source: &str,
) -> Result<BTreeMap<String, Vec<String>>, usize> {
    let mut parser = Parser::new();
    if parser.set_language(grammar).is_err() {
        return Err(1);
    }
    let Some(tree) = parser.parse(source, None) else {
        return Err(1);
    };
    if let Some(line) = first_unparsed(tree.root_node()) {
        return Err(line);
    }
    let kinds = function_kinds(language);
    let mut declared: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut cursor = tree.walk();
    let mut pending = vec![tree.root_node()];
    while let Some(node) = pending.pop() {
        if kinds.contains(&node.kind())
            && let Some(name) = node.child_by_field_name("name")
        {
            let receiver = node
                .child_by_field_name("receiver")
                .map(|receiver| text_of(receiver, source))
                .unwrap_or_default();
            let parameters = node
                .child_by_field_name("parameters")
                .map(|parameters| text_of(parameters, source))
                .unwrap_or_default();
            declared
                .entry(text_of(name, source).to_owned())
                .or_default()
                .push(format!("{receiver}{parameters}"));
        }
        pending.extend(node.children(&mut cursor));
    }
    for signatures in declared.values_mut() {
        signatures.sort();
    }
    Ok(declared)
}

/// The line of the first region the grammar could not read, if any.
///
/// `has_error` on the root is the cheap test; the walk is what names a line.
/// A root that reports an error while no node carries the flag is a grammar
/// that changed shape under this reader, and line one is the honest answer:
/// something is wrong and the reader cannot say where.
fn first_unparsed(root: Node<'_>) -> Option<usize> {
    if !root.has_error() {
        return None;
    }
    let mut cursor = root.walk();
    let mut pending = vec![root];
    let mut first: Option<usize> = None;
    while let Some(node) = pending.pop() {
        if node.is_error() || node.is_missing() {
            let line = node.start_position().row + 1;
            first = Some(first.map_or(line, |earlier| earlier.min(line)));
        }
        pending.extend(node.children(&mut cursor));
    }
    Some(first.unwrap_or(1))
}

fn text_of<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.byte_range()).unwrap_or_default()
}

/// The facts one file's two sides establish between them.
fn compare(
    path: &str,
    before: &BTreeMap<String, Vec<String>>,
    after: &BTreeMap<String, Vec<String>>,
    file_removed: bool,
) -> Vec<Evidence> {
    let names: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    let mut found = Vec::new();
    for name in names {
        let (kind, mut properties) = match (before.get(name), after.get(name)) {
            (Some(was), None) => (
                Kind::FunctionRemoved,
                BTreeMap::from([("before", was.join("; "))]),
            ),
            (None, Some(is)) => (
                Kind::FunctionAdded,
                BTreeMap::from([("after", is.join("; "))]),
            ),
            (Some(was), Some(is)) if was != is => (
                Kind::SignatureChanged,
                BTreeMap::from([("before", was.join("; ")), ("after", is.join("; "))]),
            ),
            _ => continue,
        };
        if file_removed {
            properties.insert(FILE_REMOVED.0, FILE_REMOVED.1.to_owned());
        }
        found.push(Evidence {
            kind,
            subject: format!("{path}::{name}"),
            properties,
            provider: PROVIDER,
            revision: String::from(REVISION),
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;
    use crate::guard::Stage;

    /// A repository with `before` committed at `path` and `after` staged
    /// there, or the path deleted from the index when `after` is `None`.
    fn staged(path: &str, before: &str, after: Option<&str>) -> std::path::PathBuf {
        let root = fixture::scratch("syntax");
        std::fs::create_dir_all(&root).unwrap();
        fixture::git(&root, &["init", "-q", "-b", "main"]);
        fixture::git(&root, &["config", "user.name", "Test"]);
        fixture::git(&root, &["config", "user.email", "test@example.test"]);
        std::fs::write(root.join(path), before).unwrap();
        fixture::git(&root, &["add", "-A"]);
        fixture::git(&root, &["commit", "-qm", "before", "--no-verify"]);
        match after {
            Some(text) => std::fs::write(root.join(path), text).unwrap(),
            None => std::fs::remove_file(root.join(path)).unwrap(),
        }
        fixture::git(&root, &["add", "-A"]);
        root
    }

    fn observed(root: &Path, changed: &[String]) -> Observation {
        Declarations.observe(&Context {
            root,
            stage: Stage::CommitMsg,
            message: None,
            changed: Some(changed),
        })
    }

    #[test]
    fn a_function_in_head_and_not_in_the_index_is_reported_removed() {
        let root = staged(
            "lib.rs",
            "fn keep(a: u8) {}\nfn drop_me(b: u8) {}\n",
            Some("fn keep(a: u8) {}\n"),
        );
        let Observation::Found(found) = observed(&root, &[String::from("lib.rs")]) else {
            unreachable!("both sides parse");
        };
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, Kind::FunctionRemoved);
        assert_eq!(found[0].subject, "lib.rs::drop_me");
        assert_eq!(found[0].properties["before"], "(b: u8)");
        assert_eq!(found[0].revision, REVISION);
    }

    #[test]
    fn a_changed_parameter_list_is_a_signature_change_and_not_a_removal() {
        let root = staged(
            "m.py",
            "def go(a):\n    pass\n",
            Some("def go(a, b):\n    pass\n"),
        );
        let Observation::Found(found) = observed(&root, &[String::from("m.py")]) else {
            unreachable!("both sides parse");
        };
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, Kind::SignatureChanged);
        assert_eq!(found[0].properties["before"], "(a)");
        assert_eq!(found[0].properties["after"], "(a, b)");
    }

    #[test]
    fn a_go_method_is_read_with_its_receiver() {
        let root = staged(
            "m.go",
            "package m\nfunc (t T) Go() {}\nfunc Free() {}\n",
            Some("package m\nfunc (t *T) Go() {}\n"),
        );
        let Observation::Found(found) = observed(&root, &[String::from("m.go")]) else {
            unreachable!("both sides parse");
        };
        let kinds: Vec<(Kind, &str)> = found
            .iter()
            .map(|item| (item.kind, item.subject.as_str()))
            .collect();
        assert_eq!(
            kinds,
            [
                (Kind::FunctionRemoved, "m.go::Free"),
                (Kind::SignatureChanged, "m.go::Go")
            ]
        );
    }

    #[test]
    fn a_deleted_file_reports_every_function_it_declared_removed_and_says_the_file_went() {
        let root = staged("gone.rs", "fn a() {}\nfn b() {}\n", None);
        let Observation::Found(found) = observed(&root, &[String::from("gone.rs")]) else {
            unreachable!("the committed side parses and the index has no side");
        };
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|item| item.kind == Kind::FunctionRemoved));
        assert!(found.iter().all(
            |item| item.properties.get(FILE_REMOVED.0).map(String::as_str) == Some(FILE_REMOVED.1)
        ));

        // A function gone from a file that stays carries no such mark.
        let kept = staged("lib.rs", "fn a() {}\nfn b() {}\n", Some("fn a() {}\n"));
        let Observation::Found(unmarked) = observed(&kept, &[String::from("lib.rs")]) else {
            unreachable!("both sides parse");
        };
        assert_eq!(unmarked.len(), 1);
        assert!(!unmarked[0].properties.contains_key(FILE_REMOVED.0));
    }

    #[test]
    fn a_side_that_did_not_parse_makes_the_whole_answer_unavailable() {
        // ADR 0003's measurement, at this seam: the removed function is
        // three lines under an unterminated string, the recovered tree does
        // not contain it, and a walk would report nothing -- which is the
        // report from a file that removes nothing. The answer names the file
        // and the line instead.
        let root = staged(
            "lib.rs",
            "fn keep() {}\nfn drop_me() {}\n",
            Some("const S: &str = \"open;\nfn keep() {}\n"),
        );
        let Observation::Unavailable { provider, reason } =
            observed(&root, &[String::from("lib.rs")])
        else {
            unreachable!("an unparseable side is not a shorter list of facts");
        };
        assert_eq!(provider, PROVIDER);
        assert!(
            reason.starts_with("lib.rs:1 at the index did not parse"),
            "{reason}"
        );
    }

    #[test]
    fn a_file_in_no_linked_grammar_is_outside_the_claim() {
        let root = staged("notes.md", "fn looks_like_one() {}\n", Some("gone\n"));
        assert_eq!(
            observed(&root, &[String::from("notes.md")]),
            Observation::Found(Vec::new())
        );
    }

    #[test]
    fn a_stage_with_no_index_is_unavailable() {
        let root = staged("lib.rs", "fn a() {}\n", Some("fn a() {}\n"));
        let observed = Declarations.observe(&Context {
            root: &root,
            stage: Stage::PrePush,
            message: None,
            changed: None,
        });
        assert!(matches!(observed, Observation::Unavailable { .. }));
    }
}
