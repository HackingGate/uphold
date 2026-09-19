//! Function declarations, as a pattern over the diff's lines sees them.
//!
//! Heuristic, and the second implementation of what `syntax` reports: a
//! removed line matching `fn name(` is a function the change probably removes,
//! and "probably" is the whole difference between this provider and the
//! parser. It exists for two reasons. It is the textual fallback the parser
//! needs when a file did not parse -- the strength rule lets it add a refusal
//! there and never a clean verdict -- and it is a second provider of the same
//! kinds, which is what makes substituting one for the other under an
//! unchanged policy a thing a test can demonstrate.
//!
//! A name on both a removed and an added line is reported as a signature
//! change rather than as a removal and an addition: the ordinary edit to a
//! function's first line is its parameter list, and reporting that as a
//! removal would refuse every commit that widened a signature.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use regex::Regex;

use super::{Context, Evidence, FILE_REMOVED, Kind, Observation, Provider, Source, Strength};
use crate::comments::Language;

/// Who this is.
pub(crate) const PROVIDER: Provider = Provider {
    name: "diff-text",
    strength: Strength::Heuristic,
    claims: &[
        Kind::FunctionAdded,
        Kind::FunctionRemoved,
        Kind::SignatureChanged,
    ],
};

/// The provider over the staged diff's added and removed lines.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Lines;

impl Source for Lines {
    fn provider(&self) -> Provider {
        PROVIDER
    }

    fn observe(&self, context: &Context<'_>) -> Observation {
        let Some(changed) = context.changed else {
            return Observation::Unavailable {
                provider: PROVIDER,
                reason: format!(
                    "no index to diff against HEAD at {}",
                    context.stage.as_str()
                ),
            };
        };
        let mut found = Vec::new();
        for path in changed {
            let Some(language) = Language::for_path(path) else {
                continue;
            };
            let Some(pattern) = declaration_pattern(language) else {
                continue;
            };
            let diff = match staged_diff(context.root, path) {
                Ok(diff) => diff,
                Err(reason) => {
                    return Observation::Unavailable {
                        provider: PROVIDER,
                        reason,
                    };
                }
            };
            found.extend(compare(path, pattern, &diff));
        }
        Observation::Found(found)
    }
}

/// The lines that open a function declaration in each language, with the
/// name captured. `None` for a language whose files this provider does not
/// read.
fn declaration_pattern(language: Language) -> Option<&'static Regex> {
    static RUST: OnceLock<Regex> = OnceLock::new();
    static PYTHON: OnceLock<Regex> = OnceLock::new();
    static GO: OnceLock<Regex> = OnceLock::new();
    Some(match language {
        Language::Rust => RUST.get_or_init(|| {
            crate::engine::literal_pattern(
                r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:(?:const|async|unsafe|extern\s+\S+)\s+)*fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]",
            )
        }),
        Language::Python => PYTHON.get_or_init(|| {
            crate::engine::literal_pattern(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
        }),
        Language::Go => GO.get_or_init(|| {
            crate::engine::literal_pattern(
                r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*[(\[]",
            )
        }),
        Language::HashLines => return None,
    })
}

/// One path's staged diff, with no context lines and nothing a personal
/// config could put in front of a `+` or a `-`. The flags are the ones
/// `guard::names::added_lines` argues for at length, and for the same
/// reason: an external diff or a colour setting turns this into a diff with
/// no marked lines in it, which reads as a change that removes nothing.
fn staged_diff(root: &std::path::Path, path: &str) -> Result<String, String> {
    let spec = format!(":(literal){path}");
    crate::git::run(
        root,
        &[
            "-c",
            "core.quotepath=false",
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "-U0",
            "--",
            &spec,
        ],
    )
    .map_err(|error| error.to_string())
}

/// The facts one path's diff establishes.
///
/// A file the change deletes is marked [`FILE_REMOVED`] on each of its
/// removals. The header says so twice, as `deleted file mode` and as a `+++`
/// naming `/dev/null`, and either is read: a diff has both, and a reader that
/// insisted on one would miss a diff that carried the other.
fn compare(path: &str, pattern: &Regex, diff: &str) -> Vec<Evidence> {
    let mut removed: BTreeMap<String, String> = BTreeMap::new();
    let mut added: BTreeMap<String, String> = BTreeMap::new();
    let mut in_hunk = false;
    let mut file_removed = false;
    for record in diff.lines() {
        if record.starts_with("@@") {
            in_hunk = true;
            continue;
        }
        if record.starts_with("diff --git ") {
            in_hunk = false;
            continue;
        }
        if !in_hunk {
            if record.starts_with("deleted file mode ") || record == "+++ /dev/null" {
                file_removed = true;
            }
            continue;
        }
        let (side, line) = if let Some(line) = record.strip_prefix('-') {
            (&mut removed, line)
        } else if let Some(line) = record.strip_prefix('+') {
            (&mut added, line)
        } else {
            continue;
        };
        if let Some(name) = pattern.captures(line).and_then(|captured| captured.get(1)) {
            side.entry(name.as_str().to_owned())
                .or_insert_with(|| line.trim().to_owned());
        }
    }
    let names: BTreeSet<&String> = removed.keys().chain(added.keys()).collect();
    let mut found = Vec::new();
    for name in names {
        let (kind, mut properties) = match (removed.get(name), added.get(name)) {
            (Some(was), None) => (
                Kind::FunctionRemoved,
                BTreeMap::from([("before", was.clone())]),
            ),
            (None, Some(is)) => (Kind::FunctionAdded, BTreeMap::from([("after", is.clone())])),
            (Some(was), Some(is)) => (
                Kind::SignatureChanged,
                BTreeMap::from([("before", was.clone()), ("after", is.clone())]),
            ),
            (None, None) => continue,
        };
        if file_removed && kind == Kind::FunctionRemoved {
            properties.insert(FILE_REMOVED.0, FILE_REMOVED.1.to_owned());
        }
        found.push(Evidence {
            kind,
            subject: format!("{path}::{name}"),
            properties,
            provider: PROVIDER,
            revision: String::from(super::syntax::REVISION),
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rust() -> &'static Regex {
        declaration_pattern(Language::Rust).unwrap()
    }

    #[test]
    fn a_removed_declaration_line_is_a_removal_and_a_rewritten_one_is_a_signature_change() {
        // Reading the diff rather than the tree, so the fixture is the diff.
        let diff = "diff --git a/lib.rs b/lib.rs\n\
                    --- a/lib.rs\n\
                    +++ b/lib.rs\n\
                    @@ -1,2 +1 @@\n\
                    -fn drop_me(b: u8) {}\n\
                    -pub(crate) fn widen(a: u8) {}\n\
                    +pub(crate) fn widen(a: u8, b: u8) {}\n\
                    @@ -9 +8 @@\n\
                    +fn fresh() {}\n";
        let found = compare("lib.rs", rust(), diff);
        let kinds: Vec<(Kind, &str)> = found
            .iter()
            .map(|item| (item.kind, item.subject.as_str()))
            .collect();
        assert_eq!(
            kinds,
            [
                (Kind::FunctionRemoved, "lib.rs::drop_me"),
                (Kind::FunctionAdded, "lib.rs::fresh"),
                (Kind::SignatureChanged, "lib.rs::widen"),
            ]
        );
        assert_eq!(found[0].properties["before"], "fn drop_me(b: u8) {}");
    }

    #[test]
    fn a_deleted_file_marks_each_removal_and_a_kept_file_marks_none() {
        let deleted = "diff --git a/old.rs b/old.rs\n\
                       deleted file mode 100644\n\
                       --- a/old.rs\n\
                       +++ /dev/null\n\
                       @@ -1,2 +0,0 @@\n\
                       -fn a() {}\n\
                       -fn b() {}\n";
        let found = compare("old.rs", rust(), deleted);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|item| item.kind == Kind::FunctionRemoved));
        assert!(found.iter().all(
            |item| item.properties.get(FILE_REMOVED.0).map(String::as_str) == Some(FILE_REMOVED.1)
        ));

        let kept = "diff --git a/lib.rs b/lib.rs\n\
                    --- a/lib.rs\n\
                    +++ b/lib.rs\n\
                    @@ -2 +1,0 @@\n\
                    -fn b() {}\n";
        let unmarked = compare("lib.rs", rust(), kept);
        assert_eq!(unmarked.len(), 1);
        assert!(!unmarked[0].properties.contains_key(FILE_REMOVED.0));
    }

    #[test]
    fn a_line_outside_a_hunk_is_a_header_and_not_a_declaration() {
        // `--- a/fn_x.rs` opens with the removal marker and is not a line
        // of the file; only a hunk's lines are.
        let diff = "diff --git a/lib.rs b/lib.rs\n--- a/lib.rs\n+++ b/lib.rs\n";
        assert!(compare("lib.rs", rust(), diff).is_empty());
    }

    #[test]
    fn each_language_has_a_declaration_shape_and_a_hash_line_file_has_none() {
        let python = declaration_pattern(Language::Python).unwrap();
        assert_eq!(
            python.captures("async def go(a):").unwrap()[1].to_owned(),
            "go"
        );
        let go = declaration_pattern(Language::Go).unwrap();
        assert_eq!(
            go.captures("func (r *T) Go(a int) {").unwrap()[1].to_owned(),
            "Go"
        );
        assert_eq!(
            go.captures("func Free[T any]() {").unwrap()[1].to_owned(),
            "Free"
        );
        assert_eq!(
            rust().captures("    pub async fn go<T>(a: T) {").unwrap()[1].to_owned(),
            "go"
        );
        assert!(rust().captures("let s = \"fn not_one(\";").is_none());
        assert!(declaration_pattern(Language::HashLines).is_none());
    }
}
