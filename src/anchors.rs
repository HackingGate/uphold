//! A document's stated fact, resolved against the file it names.
//!
//! The sibling of the `links-resolve` built-in, for the other half of what a
//! document asserts about the tree. That one resolves a path a reader would
//! CLICK; this resolves a VALUE a reader would believe. Both are prose that
//! happens to be checkable, and before either existed both failed the same way:
//! silently, forever, with every check in every repository still green.
//!
//! # The two markers
//!
//! A `fact-anchor` names a file somebody in this repository EDITS, and the
//! value the prose relies on:
//!
//! ```text
//! <!-- fact-anchor: source=config/services/db.yaml key=read_path states=api -->
//! ```
//!
//! A `data-anchor` names a file NOBODY here controls -- a captured document, a
//! filing, a fixture -- as a glob:
//!
//! ```text
//! // data-anchor: artifact=captures/*/filing.json states=the issuer's own NAV
//! ```
//!
//! The asymmetry is deliberate and is the whole difference between the two. A
//! `fact-anchor` is COMPARED, because this repository owns the value and can be
//! held to it. A `data-anchor` is only required to be PRESENT, because the point
//! of a captured artifact is that this repository does not get to say what is
//! inside it -- what fails is a literal standing in for a document that was
//! never captured at all.
//!
//! # What is not read
//!
//! English. No check can look at "Not yet recorded" and know it asserted
//! something machine-checkable; the author believed the sentence when writing
//! it. So this covers facts somebody DECLARED as facts by anchoring them, which
//! is worth having and is not the same as solving the problem. Saying otherwise
//! would make this one more instrument that reads healthier than it is.

use std::path::Path;
use std::sync::OnceLock;

use globset::Glob;
use regex::Regex;

use crate::engine;

/// Where a value lives, and what a document says it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Anchor {
    pub(crate) line: u64,
    pub(crate) kind: Kind,
    /// The path or glob the marker names.
    pub(crate) source: String,
    /// The dotted key, for a `fact-anchor`. Empty for a `data-anchor`.
    pub(crate) key: String,
    /// The value the prose relies on.
    pub(crate) states: String,
}

/// Which marker this is, and it decides what "resolve" means.
///
/// The asymmetry is the whole difference between the two: a fact this
/// repository owns can be compared against the record, and a document it merely
/// captured cannot be, because the point of a captured artifact is that nobody
/// here gets to say what is inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A value this repository owns, compared against the record.
    Fact,
    /// An artifact this repository captured, required only to be present.
    Data,
}

/// The value at a dotted key, or the fact that there is none.
///
/// An enum and not `Option`, because a null IS a value a record can hold --
/// `read_path: none` is a real, deliberate answer -- and conflating "the record
/// says nothing here" with "the record says nothing is here" is exactly the
/// fail-open this check exists to catch elsewhere.
enum Found<'a> {
    Value(&'a serde_json::Value),
    Missing,
}

/// The named group, or the empty string.
///
/// Every group these patterns capture is inside the alternation that made the
/// pattern match at all, so a miss is unreachable -- but reaching for it by
/// index would turn "unreachable" into "panics in somebody's pre-commit", which
/// is the trade this crate refuses everywhere else.
fn group(hit: &regex::Captures<'_>, name: &str) -> String {
    hit.name(name)
        .map_or_else(String::new, |m| m.as_str().to_owned())
}

/// Every anchor a document declares, in line order.
pub(crate) fn parse(text: &str) -> Vec<Anchor> {
    // `states=` runs to the end of the line because a stated value has spaces
    // in it often enough that stopping at the first one would silently compare
    // half of it and pass.
    static FACT: OnceLock<Regex> = OnceLock::new();
    static DATA: OnceLock<Regex> = OnceLock::new();
    static TAIL: OnceLock<Regex> = OnceLock::new();

    // Cheap reject first: the overwhelming majority of files in any tree carry
    // no marker, and the whole point of testing for the substring is that a
    // document which declares nothing costs one memchr rather than two regex
    // passes per line.
    if !text.contains("-anchor:") {
        return Vec::new();
    }
    let fact = FACT.get_or_init(|| {
        engine::literal_pattern(
            r"fact-anchor:\s*source=(?P<source>\S+)\s+key=(?P<key>\S+)\s+states=(?P<states>.*)$",
        )
    });
    let data = DATA.get_or_init(|| {
        engine::literal_pattern(r"data-anchor:\s*artifact=(?P<source>\S+)\s+states=(?P<states>.*)$")
    });
    // A marker in markdown sits inside an HTML comment, and one in a code
    // comment often ends in `*/`. Neither is part of the stated value.
    let tail = TAIL.get_or_init(|| engine::literal_pattern(r"\s*(?:-->|\*/)\s*$"));

    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line_number = index as u64 + 1;
        let (kind, hit) = if let Some(hit) = fact.captures(line) {
            (Kind::Fact, hit)
        } else if let Some(hit) = data.captures(line) {
            (Kind::Data, hit)
        } else {
            continue;
        };
        found.push(Anchor {
            line: line_number,
            kind,
            source: group(&hit, "source"),
            key: group(&hit, "key"),
            states: tail.replace(&group(&hit, "states"), "").trim().to_owned(),
        });
    }
    found
}

/// The finding this anchor produces, or `None` when it agrees.
///
/// Every branch names the source and says what the document rests on, because
/// the reader of this failure is somebody who did not write the sentence and
/// has to decide whether the prose or the record is the thing that is wrong.
pub(crate) fn resolve(anchor: &Anchor, root: &Path) -> Option<String> {
    match anchor.kind {
        Kind::Data => resolve_artifact(anchor, root),
        Kind::Fact => resolve_fact(anchor, root),
    }
}

fn resolve_artifact(anchor: &Anchor, root: &Path) -> Option<String> {
    let glob = match Glob::new(&anchor.source) {
        Ok(glob) => glob.compile_matcher(),
        Err(error) => {
            return Some(format!(
                "names artifact {:?}, which is not a valid glob: {error}",
                anchor.source
            ))
        }
    };
    // Walking the tree is the resolver here, so a glob naming a directory that
    // does not exist costs nothing and a glob that matches costs one hit.
    let present = ignore::WalkBuilder::new(root)
        .hidden(false)
        .build()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_some_and(|kind| kind.is_file()))
        .any(|entry| {
            entry
                .path()
                .strip_prefix(root)
                .is_ok_and(|relative| glob.is_match(relative))
        });
    (!present).then(|| {
        format!(
            "names artifact {:?}, which matches no file that is present. The literal beside \
             this marker stands in for a document nobody captured, so nothing has ever \
             compared the two.",
            anchor.source
        )
    })
}

fn resolve_fact(anchor: &Anchor, root: &Path) -> Option<String> {
    let path = root.join(&anchor.source);
    let suffix = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    // A table rather than a branch, so a fourth format is one arm beside the
    // three that already work.
    if !matches!(suffix, "yaml" | "yml" | "toml" | "json") {
        return Some(format!(
            "names source {:?}, whose suffix is not one this check can read (json, toml, \
             yaml, yml)",
            anchor.source
        ));
    }
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Some(format!(
            "names source {:?}, which is not present. The document rests on a file that \
             is gone, and says so nowhere a reader can see.",
            anchor.source
        ));
    };
    // Every format is parsed INTO the JSON value model rather than compared in
    // its own: one walker, one rendering, and a `key` that means the same thing
    // whichever of the three the record happens to be written in.
    let document: serde_json::Value = match suffix {
        "json" => match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(error) => return Some(parse_failure(&anchor.source, &error)),
        },
        "toml" => match toml::from_str(&text) {
            Ok(value) => value,
            Err(error) => return Some(parse_failure(&anchor.source, &error)),
        },
        _ => match serde_yaml_ng::from_str(&text) {
            Ok(value) => value,
            Err(error) => return Some(parse_failure(&anchor.source, &error)),
        },
    };

    match read_key(&document, &anchor.key) {
        Found::Missing => Some(format!(
            "names key {:?} in {}, which does not exist there. Either it was renamed and this \
             sentence was not, or it never existed and nothing has ever checked.",
            anchor.key, anchor.source
        )),
        Found::Value(value) => {
            let actual = rendered(value);
            (actual != anchor.states).then(|| {
                format!(
                    "states {:?} for {} in {}, which says {actual:?}. The document was true \
                     when it was written.",
                    anchor.states, anchor.key, anchor.source
                )
            })
        }
    }
}

fn parse_failure(source: &str, error: &impl std::fmt::Display) -> String {
    format!("names source {source:?}, which does not parse: {error}")
}

/// The value at a dotted key. An integer segment indexes a list, so `scope.0`
/// reaches the first entry of a sequence.
///
/// Anything that is neither a mapping with that key nor a list with that index
/// stops the walk: a partial resolution is not a value.
fn read_key<'a>(document: &'a serde_json::Value, key: &str) -> Found<'a> {
    let mut node = document;
    for segment in key.split('.') {
        node = match node {
            serde_json::Value::Object(map) if map.contains_key(segment) => &map[segment],
            serde_json::Value::Array(items) => {
                // A negative index counts from the end, which is what a reader
                // who writes `-1` in a marker means by it. Resolved by
                // subtraction on the usize rather than by casting the length
                // into a signed width: an index out of range is Missing on
                // either path, and only one of them is a cast that can wrap.
                let found = segment.strip_prefix('-').map_or_else(
                    || segment.parse::<usize>().ok().and_then(|at| items.get(at)),
                    |back| {
                        back.parse::<usize>()
                            .ok()
                            .filter(|from_end| *from_end > 0 && *from_end <= items.len())
                            .and_then(|from_end| items.get(items.len() - from_end))
                    },
                );
                let Some(value) = found else {
                    return Found::Missing;
                };
                value
            }
            _ => return Found::Missing,
        };
    }
    Found::Value(node)
}

/// The value as a document would write it.
///
/// Booleans lowercase because that is how YAML, TOML and JSON all spell them,
/// and a null renders as `none` because that is the word a record uses for a
/// deliberate absence. A string renders as itself and not as its quoted JSON
/// form, because the marker is prose and a reader writes `states=api`.
fn rendered(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => String::from("none"),
        serde_json::Value::Bool(flag) => flag.to_string(),
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two helpers under test, composed the way `resolve_fact` composes
    /// them, so a case reads as the question it is asking: what does this
    /// document say at this key, as a document would write it?
    fn read(document: &serde_json::Value, key: &str) -> Option<String> {
        match read_key(document, key) {
            Found::Value(value) => Some(rendered(value)),
            Found::Missing => None,
        }
    }

    fn json(text: &str) -> serde_json::Value {
        serde_json::from_str(text).unwrap_or(serde_json::Value::Null)
    }

    #[test]
    fn a_markdown_marker_parses_with_its_comment_stripped() {
        let anchors = parse("<!-- fact-anchor: source=a.yaml key=b.c states=live -->\n");
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0].kind, Kind::Fact);
        assert_eq!(anchors[0].source, "a.yaml");
        assert_eq!(anchors[0].key, "b.c");
        assert_eq!(anchors[0].states, "live");
        assert_eq!(anchors[0].line, 1);
    }

    #[test]
    fn a_stated_value_keeps_its_spaces() {
        // Stopping at the first space would compare "the" against "the issuer's
        // own NAV" and pass, which is the failure mode a value-comparing check
        // can least afford.
        let anchors = parse("# data-anchor: artifact=cap/*.json states=the issuer's own NAV\n");
        assert_eq!(anchors[0].kind, Kind::Data);
        assert_eq!(anchors[0].states, "the issuer's own NAV");
    }

    #[test]
    fn a_file_with_no_marker_parses_to_nothing() {
        assert!(parse("ordinary prose about anchors and facts\n").is_empty());
    }

    #[test]
    fn a_null_is_a_value_and_not_a_missing_key() {
        // `read_path: none` is a deliberate answer. Rendering it as `none` and
        // reporting it as ABSENT are different verdicts, and only one is true.
        let document: serde_json::Value =
            serde_yaml_ng::from_str("read_path: null\n").unwrap_or(serde_json::Value::Null);
        assert_eq!(read(&document, "read_path"), Some(String::from("none")));
        assert_eq!(read(&document, "absent"), None);
    }

    #[test]
    fn an_integer_segment_indexes_a_list() {
        let document = json(r#"{"scope": ["read", "trade"]}"#);
        assert_eq!(read(&document, "scope.1"), Some(String::from("trade")));
        // From the end, and past both ends.
        assert_eq!(read(&document, "scope.-1"), Some(String::from("trade")));
        assert_eq!(read(&document, "scope.9"), None);
        assert_eq!(read(&document, "scope.-9"), None);
    }

    #[test]
    fn a_partial_resolution_is_not_a_value() {
        assert_eq!(read(&json(r#"{"a": "text"}"#), "a.b"), None);
    }

    #[test]
    fn booleans_and_numbers_render_as_a_document_writes_them() {
        let document = json(r#"{"on": true, "n": 3, "s": "x"}"#);
        for (key, want) in [("on", "true"), ("n", "3"), ("s", "x")] {
            assert_eq!(read(&document, key), Some(String::from(want)), "{key}");
        }
    }
}
