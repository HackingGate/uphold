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
use crate::config::{CheckKind, Policy};
use crate::error::{Fatal, Result};
use crate::report::Failure;
use crate::text::Seam;

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
///
/// Which files hold comments is the comment module's fact, asked of it rather
/// than transcribed here, so the two cannot disagree about a `.fish` script.
/// What is decided here is only what is a document: the extensions that name
/// one, and the extensionless file that is not a dotfile -- LICENSE, CODEOWNERS,
/// the file somebody wrote and did not name.
fn kind_of(path: &str) -> Option<Kind> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let extension = name
        .strip_prefix('.')
        .unwrap_or(name)
        .rsplit_once('.')
        .map(|(_, found)| found);
    match (extension, Language::for_path(path)) {
        (Some("md"), _) => Some(Kind::Document { markdown: true }),
        (Some("rst" | "txt" | "adoc"), _) | (None, None) => {
            Some(Kind::Document { markdown: false })
        }
        (_, Some(Language::HashLines)) => Some(Kind::Hashes),
        (_, Some(language)) => Some(Kind::Source(language)),
        (Some(_), None) => None,
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

/// A fenced block that is open: the character it is made of, the length of the
/// run that opened it, and the column of the list item it opened inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fence {
    mark: char,
    length: usize,
    base: usize,
}

/// The width of a line's indentation and the text after it, a tab counted to
/// the next stop of four the way `CommonMark` counts it.
fn indented(line: &str) -> (usize, &str) {
    let rest = line.trim_start_matches([' ', '\t']);
    let width = line
        .chars()
        .take_while(|character| matches!(character, ' ' | '\t'))
        .fold(0, |width, character| {
            if character == '\t' {
                width + 4 - width % 4
            } else {
                width + 1
            }
        });
    (width, rest)
}

/// The fence a line opens, if it opens one: a run of three or more backticks
/// or tildes. A backtick run followed by another backtick is a code span, as
/// in ```` ```a``` ````, and opens nothing.
fn fence_of(rest: &str, base: usize) -> Option<Fence> {
    let mark = rest
        .chars()
        .next()
        .filter(|first| matches!(first, '`' | '~'))?;
    let length = rest.chars().take_while(|found| *found == mark).count();
    let info = rest.trim_start_matches(mark);
    (length >= 3 && !(mark == '`' && info.contains('`'))).then_some(Fence { mark, length, base })
}

/// Whether a line closes an open fence: a run of the same character at least
/// as long as the one that opened it, and nothing after it but spaces.
///
/// Compared by length rather than by the three characters so that a longer
/// closing fence closes the block and a shorter one -- a three-backtick fence
/// quoted inside a four-backtick one -- is a line of it. And a closing fence
/// carries no info string, so ```` ```bash ```` inside an open ```` ```sh ````
/// block is a line of it rather than its end.
fn closes(fence: Fence, rest: &str) -> bool {
    let length = rest
        .chars()
        .take_while(|found| *found == fence.mark)
        .count();
    length >= fence.length
        && rest
            .trim_start_matches(fence.mark)
            .trim_matches([' ', '\t'])
            .is_empty()
}

/// The column a list item's text starts at, if the line opens one: a bullet
/// (`-`, `*`, `+`) or up to nine digits and `.` or `)`, then a space or the end
/// of the line. One to four spaces after the marker are part of it; past four,
/// the text starts one space after the marker and the rest is its indentation.
fn item_of(width: usize, rest: &str) -> Option<usize> {
    let digits = rest.chars().take_while(char::is_ascii_digit).count();
    let marker = match rest.chars().nth(digits)? {
        '-' | '*' | '+' if digits == 0 => 1,
        '.' | ')' if (1..=9).contains(&digits) => digits + 1,
        _ => return None,
    };
    let (gap, text) = indented(rest.get(marker..)?);
    match (gap, text.is_empty()) {
        (_, true) | (5.., false) => Some(width + marker + 1),
        (0, false) => None,
        (_, false) => Some(width + marker + gap),
    }
}

/// Whether a line is an ATX heading: one to six `#` and then a space or the end
/// of the line. A heading is not a paragraph, so code may follow it directly.
fn heading(rest: &str) -> bool {
    let hashes = rest.chars().take_while(|found| *found == '#').count();
    (1..=6).contains(&hashes)
        && rest
            .trim_start_matches('#')
            .chars()
            .next()
            .is_none_or(|after| matches!(after, ' ' | '\t'))
}

/// The paragraphs of a document, by the `CommonMark` rules for where code
/// starts and ends.
///
/// A fence opens on three or more backticks or tildes and closes on the rules
/// of [`closes`]; one never closed runs to the end of the document, as it does
/// in `CommonMark`. In Markdown a fence or a closing fence indented four spaces
/// past its container is not one, and four spaces open an indented code block
/// only where they do not continue a paragraph and are counted from the text of
/// the list item the line sits in, not from the margin.
///
/// Lists are approximated rather than parsed. A line opening a list item pushes
/// the column its text starts at, and a line indented less than that column --
/// after a blank line, or when it opens something itself -- pops it. A line
/// under paragraph text that opens no fence, item or heading continues the
/// paragraph however it is indented, which is the lazy continuation
/// `CommonMark` allows. Not modelled: block quotes, an item's first line
/// holding a fence or code of its own, the rule that only an ordinal of 1 and
/// a non-empty item may interrupt a paragraph, and a fence ending because the
/// list item around it ended -- here it ends only at its closing line.
///
/// A plain text file has no indented code and no lists, so there a fence opens
/// and closes at any indentation and every other line is prose.
fn of_document(text: &str, markdown: bool) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut run: Vec<&str> = Vec::new();
    let mut start = 0_u64;
    let mut fence: Option<Fence> = None;
    // The column each open list item's text starts at, innermost last.
    let mut items: Vec<usize> = Vec::new();
    // Whether the last line was paragraph text the next one may continue.
    let mut paragraph = false;

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
        let (width, rest) = indented(line);
        if let Some(open) = fence {
            if closes(open, rest) && (!markdown || width < open.base + 4) {
                fence = None;
            }
            continue;
        }
        if rest.trim_start().is_empty() {
            flush(&mut run, start);
            paragraph = false;
            continue;
        }
        if markdown {
            let inside = items.last().copied().unwrap_or(0);
            let opens = width < inside + 4
                && (fence_of(rest, inside).is_some()
                    || item_of(width, rest).is_some()
                    || heading(rest));
            if opens || !paragraph {
                while items.last().is_some_and(|column| *column > width) {
                    items.pop();
                }
                let base = items.last().copied().unwrap_or(0);
                // An indented block is code in Markdown and is a sentence
                // somebody indented anywhere else. Refusing a shape inside a
                // four-space block of a plain text file would be refusing the
                // indentation, not the prose.
                if width >= base + 4 {
                    flush(&mut run, start);
                    paragraph = false;
                    continue;
                }
                if let Some(opened) = fence_of(rest, base) {
                    flush(&mut run, start);
                    fence = Some(opened);
                    paragraph = false;
                    continue;
                }
                if let Some(column) = item_of(width, rest) {
                    items.push(column);
                }
                paragraph = !heading(rest);
            }
        } else if let Some(opened) = fence_of(rest, 0) {
            flush(&mut run, start);
            fence = Some(opened);
            continue;
        }
        if run.is_empty() {
            start = number;
        }
        run.push(rest);
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
///
/// And only the rules whose `seams`, where given, names `seam`: a rule written
/// to refuse a command through the shim and the hook is not asked about a
/// commit message that merely mentions the command.
pub(crate) fn over_text(policy: &Policy, seam: Seam, text: &str) -> Result<Vec<Failure>> {
    let mut failures = Vec::new();
    for rule in policy.of_check(CheckKind::ProseRegexp) {
        if rule
            .command
            .as_ref()
            .is_none_or(|where_| where_.before.is_empty())
        {
            continue;
        }
        if !rule.judged_at(seam) {
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
        let matcher = compile(rule.prose_regexp().unwrap_or_default(), &rule.id)?;
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

    /// Indented code cannot interrupt a paragraph, so a line indented four
    /// spaces under paragraph text continues it -- lazily or inside the item
    /// the paragraph belongs to.
    #[test]
    fn an_indented_line_under_paragraph_text_continues_it() {
        assert_eq!(
            texts(&of("notes.md", "A paragraph\n    banana continues it.\n")),
            ["A paragraph banana continues it."]
        );
        assert_eq!(
            texts(&of(
                "notes.md",
                "- The first item\n    banana continues it.\n"
            )),
            ["- The first item banana continues it."]
        );
        assert_eq!(
            texts(&of("notes.md", "1. Install it.\n    - banana nested\n")),
            ["1. Install it. - banana nested"]
        );
    }

    /// Inside a list item four spaces are counted from where the item's text
    /// starts, not from the margin, so a nested bullet or a second paragraph
    /// after a blank line is prose and only four more than that is code.
    #[test]
    fn a_list_item_counts_its_indentation_from_its_text() {
        assert_eq!(
            texts(&of("notes.md", "1. Install it.\n\n    - banana nested\n")),
            ["1. Install it.", "- banana nested"]
        );
        assert_eq!(
            texts(&of("notes.md", "- An item.\n\n    banana in the item.\n")),
            ["- An item.", "banana in the item."]
        );
        assert_eq!(
            texts(&of("notes.md", "- An item.\n\n      banana code\n")),
            ["- An item."]
        );
        assert_eq!(
            texts(&of(
                "notes.md",
                "1. Run it:\n\n   ```sh\n   banana code\n   ```\n\n   After it, banana.\n"
            )),
            ["1. Run it:", "After it, banana."]
        );
    }

    /// A paragraph at the margin closes the list, and indented code after it
    /// is code again; a heading is no paragraph, so code may follow one.
    #[test]
    fn an_indented_block_after_a_closed_list_or_a_heading_is_code() {
        assert_eq!(
            texts(&of("notes.md", "- An item.\n\nAfter.\n\n    banana code\n")),
            ["- An item.", "After."]
        );
        assert_eq!(
            texts(&of("notes.md", "# Title\n    banana code\n")),
            ["# Title"]
        );
        assert_eq!(
            texts(&of("notes.md", "Text.\n# Title\n    banana code\n")),
            ["Text. # Title"]
        );
    }

    /// A fence closes only on a run of its own character at least as long as
    /// the one that opened it, so a four-backtick fence can quote a
    /// three-backtick one.
    #[test]
    fn a_shorter_fence_inside_a_longer_one_is_its_content() {
        assert_eq!(
            texts(&of(
                "notes.md",
                "````markdown\nA fence opens with\n```\n````\n\nAfter, banana.\n"
            )),
            ["After, banana."]
        );
    }

    /// A closing fence carries no info string, so a ```` ```bash ```` line
    /// inside an open ```` ```sh ```` block is a line of it rather than its
    /// end -- in a text file too.
    #[test]
    fn a_fence_with_an_info_string_does_not_close_one() {
        let sample = "```sh\necho one\n```bash\nbanana inside\n```\n\nAfter, banana.\n";
        assert_eq!(texts(&of("notes.md", sample)), ["After, banana."]);
        assert_eq!(texts(&of("notes.txt", sample)), ["After, banana."]);
    }

    /// Four spaces before a closing fence make it a line of the block, and a
    /// backtick in the info string makes the opener a code span instead.
    #[test]
    fn a_fence_opens_and_closes_only_where_commonmark_says() {
        assert_eq!(
            texts(&of(
                "notes.md",
                "```\n    ```\nbanana code\n```\n\nAfter, banana.\n"
            )),
            ["After, banana."]
        );
        assert_eq!(
            texts(&of("notes.md", "```a``` is a span, banana.\n\nAfter.\n")),
            ["```a``` is a span, banana.", "After."]
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
        assert!(
            of("capture.png", "arguably\n").is_empty(),
            "{:?}",
            of("capture.png", "arguably\n")
        );
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
