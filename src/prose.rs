//! The prose of a file, whatever the file is.
//!
//! `regexp` reads bytes and `comment_regexp` reads comment nodes. Both are the
//! right answer for what they were written for, and neither can carry a rule
//! about how a SENTENCE is written -- because a sentence is spelled differently
//! in every file that holds one. In a document it is a paragraph, wrapped at
//! whatever column the last editor used. In a Rust or Go source file it is a run
//! of `//` lines, one comment node per line. In a TOML or shell file it is a run
//! of `#` lines that no grammar here parses at all. A pattern written against
//! any one of those spellings is a pattern that stops matching when the same
//! sentence is written somewhere else.
//!
//! So this module answers one question -- what is the prose of this file -- and
//! answers it in one shape: a [`Span`] per run of prose, unwrapped onto a single
//! line, carrying the line the run starts at. A pattern is then written against
//! sentences and against nothing else, and a paragraph somebody rewrapped
//! matches exactly as it did before.
//!
//! What is NOT prose is left out rather than reported: a fenced code block, an
//! indented code block, and every file of a kind no extractor here reads. A rule
//! that wants to know its selection still covers something says so with
//! `files.min_selected`, which is the one floor that can tell "no prose" from
//! "prose with nothing wrong in it".

use regex::Regex;

use crate::comments::{self, Language};
use crate::config::{Check, Policy};
use crate::error::{Fatal, Result};
use crate::report::Failure;

/// One run of prose, unwrapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Span {
    /// 1-based, and the line the run STARTS at -- matching every other line
    /// number this crate reports, and naming the place a reader begins reading
    /// the sentence that was refused.
    pub line: u64,
    /// The run with its markers stripped and its wrapping removed: every
    /// internal stretch of whitespace, newlines included, collapsed to one
    /// space.
    pub text: String,
}

/// Where a file's prose is, given what kind of file it is.
///
/// Three answers and no fourth. A file whose kind is not one of these has no
/// prose this binary can find, which is `None` -- silence rather than a
/// finding, because `files.include = ["."]` over a mixed tree is the normal
/// thing to write and a PNG under it is not a document somebody wrote badly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// The whole file is prose, apart from the code in it. `markdown` says
    /// whether an indented block is code -- in Markdown four spaces open one,
    /// and in a plain text file they are how somebody indented a sentence.
    Document { markdown: bool },
    /// The prose is the comments, read by the grammar.
    Source(Language),
    /// The prose is the lines whose first non-space character is `#`.
    Hashes,
}

/// The kind of one repository-relative path, or `None` for a file this module
/// reads no prose from.
fn kind_of(path: &str) -> Option<Kind> {
    let name = path.rsplit('/').next().unwrap_or(path);
    // A leading dot is part of the NAME, not the start of an extension.
    // `.gitignore` has no extension at all, and reading one off it would find
    // `gitignore` -- while `.pre-commit-config.yaml` really is YAML and has to
    // stay YAML, which is why the dot is stripped before the split rather than
    // the whole name being treated as one.
    let extension = name
        .strip_prefix('.')
        .unwrap_or(name)
        .rsplit_once('.')
        .map(|(_, found)| found);
    match extension {
        Some("md") => Some(Kind::Document { markdown: true }),
        Some("rst" | "txt" | "adoc") => Some(Kind::Document { markdown: false }),
        Some("rs") => Some(Kind::Source(Language::Rust)),
        Some("py" | "pyi") => Some(Kind::Source(Language::Python)),
        Some("go") => Some(Kind::Source(Language::Go)),
        Some("toml" | "yaml" | "yml" | "sh" | "bash" | "zsh" | "ini" | "cfg") => Some(Kind::Hashes),
        Some(_) => None,
        // No extension. A dotfile is configuration -- `.gitignore`,
        // `.dockerignore`, `.editorconfig` -- and its remarks are `#` lines.
        // Anything else with no extension is a document: LICENSE, CODEOWNERS,
        // the file somebody wrote and did not name.
        None if name.starts_with('.') => Some(Kind::Hashes),
        None => Some(Kind::Document { markdown: false }),
    }
}

/// Whether this module reads any prose out of a path at all.
///
/// Asked before the file is opened, which is the whole point: a rule selecting
/// the tree must not read a captured PNG as text to discover it has no
/// sentences in it.
pub(crate) fn reads(path: &str) -> bool {
    kind_of(path).is_some()
}

/// The prose of one file, by its path and its text.
pub(crate) fn of(path: &str, text: &str) -> Vec<Span> {
    match kind_of(path) {
        Some(Kind::Document { markdown }) => of_document(text, markdown),
        Some(Kind::Source(language)) => of_comments(text, language),
        Some(Kind::Hashes) => of_hash_lines(text),
        None => Vec::new(),
    }
}

/// The prose of text that never became a file.
///
/// A pull-request body, a release note, a commit message. It is read as a
/// document, because that is what it is: Markdown is what every forge renders
/// these as, so a fenced example in a pull-request body is a fenced example
/// here too rather than four sentences somebody wrote badly.
pub(crate) fn of_text(text: &str) -> Vec<Span> {
    of_document(text, true)
}

/// Collapse a run onto one line: this is what makes a wrapped sentence one
/// subject rather than two half-sentences a pattern cannot match.
fn unwrapped(lines: &[&str]) -> String {
    lines
        .join(" ")
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

/// The fence a line opens or closes, as the three characters it is made of.
///
/// Compared by its characters rather than by its whole length so that a longer
/// closing fence -- which `CommonMark` allows -- still closes the block.
fn fence_of(trimmed: &str) -> Option<&'static str> {
    if trimmed.starts_with("```") {
        return Some("```");
    }
    if trimmed.starts_with("~~~") {
        return Some("~~~");
    }
    None
}

fn of_document(text: &str, markdown: bool) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut run: Vec<&str> = Vec::new();
    let mut start = 0_u64;
    let mut fence: Option<&str> = None;

    let mut flush = |pending: &mut Vec<&str>, from: u64| {
        if !pending.is_empty() {
            spans.push(Span {
                line: from,
                text: unwrapped(pending),
            });
            pending.clear();
        }
    };

    for (index, line) in text.lines().enumerate() {
        let number = index as u64 + 1;
        let trimmed = line.trim_start();
        if let Some(open) = fence {
            if trimmed.starts_with(open) {
                fence = None;
            }
            continue;
        }
        if let Some(opened) = fence_of(trimmed) {
            flush(&mut run, start);
            fence = Some(opened);
            continue;
        }
        // An indented block is code in Markdown and is a sentence somebody
        // indented anywhere else. Refusing a shape inside a four-space block of
        // a plain text file would be refusing the indentation, not the prose.
        if markdown && (line.starts_with("    ") || line.starts_with('\t')) {
            flush(&mut run, start);
            continue;
        }
        if trimmed.is_empty() {
            flush(&mut run, start);
            continue;
        }
        if run.is_empty() {
            start = number;
        }
        run.push(trimmed);
    }
    flush(&mut run, start);
    spans
}

fn of_hash_lines(text: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut run: Vec<&str> = Vec::new();
    let mut start = 0_u64;
    for (index, line) in text.lines().enumerate() {
        let number = index as u64 + 1;
        let Some(body) = line.trim_start().strip_prefix('#') else {
            if !run.is_empty() {
                spans.push(Span {
                    line: start,
                    text: unwrapped(&run),
                });
                run.clear();
            }
            continue;
        };
        if run.is_empty() {
            start = number;
        }
        run.push(body);
    }
    if !run.is_empty() {
        spans.push(Span {
            line: start,
            text: unwrapped(&run),
        });
    }
    spans
}

fn of_comments(text: &str, language: Language) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut run: Vec<String> = Vec::new();
    let mut start = 0_u64;
    let mut previous = 0_u64;
    // Doc comments included, and that is the one place this parts company with
    // `comment_regexp`. That check excludes them because acting on its findings
    // deletes a public item's documentation; this one is about how a sentence
    // is written, and a doc comment is the sentence most people read.
    for comment in comments::collect(text, language) {
        if !run.is_empty() && comment.line != previous + 1 {
            spans.push(Span {
                line: start,
                text: unwrapped(&run.iter().map(String::as_str).collect::<Vec<&str>>()),
            });
            run.clear();
        }
        if run.is_empty() {
            start = comment.line;
        }
        previous = comment.line;
        run.push(comment.text);
    }
    if !run.is_empty() {
        spans.push(Span {
            line: start,
            text: unwrapped(&run.iter().map(String::as_str).collect::<Vec<&str>>()),
        });
    }
    spans
}

/// The regex one prose rule searches with, compiled once and named on failure.
pub(crate) fn compile(pattern: &str, id: &str) -> Result<Regex> {
    Regex::new(pattern).map_err(|error| Fatal::new(format!("rule {id:?}: {error}")))
}

/// Every prose rule standing in front of a command, asked about text that never
/// becomes a file.
///
/// The seam `--text` is: a commit message at `commit-msg`, a body piped in by
/// hand, a release note. A rule that refuses a shape in a pull-request body has
/// nothing different to say about a commit message, and hearing it only at the
/// shim would mean the same sentence is refused when `gh` publishes it and
/// accepted when `git commit` records it.
///
/// Only the rules that declare `command.before`. A prose rule that is purely a
/// content rule is scoped by `files.*` to particular paths, and firing it at a
/// commit message would be guesswork -- the argument `text.rs` makes about
/// pattern rules generally, and it holds here.
pub(crate) fn over_text(policy: &Policy, text: &str) -> Result<Vec<Failure>> {
    let mut failures = Vec::new();
    for rule in policy.of_check(Check::ProseRegexp) {
        if rule
            .command
            .as_ref()
            .is_none_or(|where_| where_.before.is_empty())
        {
            continue;
        }
        // The same waiver the shim seam honours for the same rule. A prose rule
        // is a judgement about a sentence, and the sentence it is wrong about
        // is one invocation's -- which is what `UPHOLD_ALLOW` is for, and why
        // it stays in the environment rather than becoming a field.
        if crate::guard::bypassed(&rule.id) {
            eprintln!("uphold: {} bypassed by UPHOLD_ALLOW", rule.id);
            continue;
        }
        let matcher = compile(rule.prose_regexp.as_deref().unwrap_or_default(), &rule.id)?;
        let body = of_text(text)
            .into_iter()
            .filter(|span| matcher.is_match(&span.text))
            .map(|span| {
                if policy.redact_matches {
                    format!("line {}: [REDACTED_MATCH]", span.line)
                } else {
                    format!("line {}: {}", span.line, span.text)
                }
            })
            .collect::<Vec<String>>()
            .join("\n");
        if body.is_empty() {
            continue;
        }
        failures.push(Failure::new(&rule.id, rule.message(), body));
    }
    Ok(failures)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(spans: &[Span]) -> Vec<&str> {
        spans.iter().map(|span| span.text.as_str()).collect()
    }

    #[test]
    fn a_wrapped_paragraph_is_one_span_a_sentence_can_be_matched_in() {
        // The reason spans exist. The sentence is split across two lines by a
        // formatter, and a per-line pattern would find neither half.
        let found = of("notes.md", "As we will\nsee, this holds.\n");
        assert_eq!(texts(&found), ["As we will see, this holds."]);
        assert_eq!(found.first().map(|span| span.line), Some(1));
    }

    #[test]
    fn a_blank_line_ends_a_paragraph() {
        let found = of("notes.md", "First one.\n\nSecond one.\n");
        assert_eq!(texts(&found), ["First one.", "Second one."]);
        assert_eq!(found.get(1).map(|span| span.line), Some(3));
    }

    #[test]
    fn a_fenced_block_is_not_prose() {
        let found = of(
            "notes.md",
            "Before.\n\n```rust\n// as we will see\n```\n\nAfter.\n",
        );
        assert_eq!(texts(&found), ["Before.", "After."]);
    }

    #[test]
    fn a_tilde_fence_closes_the_way_a_backtick_fence_does() {
        let found = of("notes.md", "Before.\n\n~~~\nnot prose\n~~~\n\nAfter.\n");
        assert_eq!(texts(&found), ["Before.", "After."]);
    }

    /// Four spaces open a code block in Markdown and indent a sentence in a
    /// plain text file, so the same lines are read two ways on purpose.
    #[test]
    fn an_indented_block_is_code_in_markdown_and_prose_in_a_text_file() {
        let sample = "Before.\n\n    it could be argued\n\nAfter.\n";
        assert_eq!(texts(&of("notes.md", sample)), ["Before.", "After."]);
        assert_eq!(
            texts(&of("notes.txt", sample)),
            ["Before.", "it could be argued", "After."]
        );
    }

    #[test]
    fn an_rst_and_an_adoc_file_are_documents() {
        assert_eq!(
            texts(&of("notes.rst", "Arguably true.\n")),
            ["Arguably true."]
        );
        assert_eq!(
            texts(&of("notes.adoc", "Arguably true.\n")),
            ["Arguably true."]
        );
    }

    /// A file nobody gave an extension is a document, and a dotfile is
    /// configuration. Both have no extension and they are not the same thing.
    #[test]
    fn a_file_with_no_extension_is_a_document_and_a_dotfile_is_configuration() {
        assert_eq!(
            texts(&of("LICENSE", "Arguably free.\n")),
            ["Arguably free."]
        );
        assert_eq!(
            texts(&of(".gitignore", "# arguably ignored\ntarget/\n")),
            ["arguably ignored"]
        );
    }

    #[test]
    fn a_hash_run_is_one_span_and_a_code_line_ends_it() {
        let found = of(
            "config.toml",
            "# in what\n# follows\nkey = 1\n# separate remark\n",
        );
        assert_eq!(texts(&found), ["in what follows", "separate remark"]);
        assert_eq!(found.first().map(|span| span.line), Some(1));
        assert_eq!(found.get(1).map(|span| span.line), Some(4));
    }

    #[test]
    fn a_shell_and_a_yaml_file_read_their_hash_lines() {
        assert_eq!(
            texts(&of("run.sh", "# needless to say\nrun\n")),
            ["needless to say"]
        );
        assert_eq!(
            texts(&of("ci.yml", "# needless to say\non: [push]\n")),
            ["needless to say"]
        );
    }

    #[test]
    fn a_rust_comment_run_is_one_span_and_a_doc_comment_is_prose() {
        let found = of(
            "src/lib.rs",
            "// One might\n// argue otherwise.\n\n/// The outer method.\npub struct Config;\n",
        );
        assert_eq!(
            texts(&found),
            ["One might argue otherwise.", "The outer method."]
        );
    }

    #[test]
    fn a_marker_inside_a_string_literal_is_not_prose() {
        // The reason source files go through the grammar rather than a line
        // test: this file contains the characters and no comment at all.
        let found = of("src/lib.rs", "fn f() { let s = \"// arguably\"; }\n");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_go_comment_is_prose_and_a_python_one_is_too() {
        assert_eq!(
            texts(&of("main.go", "// Arguably fine.\nfunc main() {}\n")),
            ["Arguably fine."]
        );
        assert_eq!(
            texts(&of("run.py", "# Arguably fine.\nrun()\n")),
            ["Arguably fine."]
        );
    }

    #[test]
    fn a_file_of_no_kind_contributes_nothing_rather_than_a_finding() {
        assert!(!reads("capture.png"));
        assert!(of("capture.png", "arguably\n").is_empty());
    }

    #[test]
    fn a_dotted_dotfile_keeps_the_extension_it_has() {
        // `.pre-commit-config.yaml` is YAML, and stripping a leading dot must
        // not turn every dotfile into one thing.
        assert_eq!(
            texts(&of(
                ".pre-commit-config.yaml",
                "# in what follows\nrepos: []\n"
            )),
            ["in what follows"]
        );
    }
}
