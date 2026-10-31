//! Where a Markdown document's code, links and headings are, as `CommonMark`
//! 0.31.2 says, read by `pulldown-cmark`.
//!
//! Every reader in this crate that needs to know whether a line is code, which
//! text is a link's destination, or where a heading is asks here. The answers
//! are positions in the source (1-based line numbers, as every other line
//! number this crate reports), so a reader keeps working on the text as the
//! author wrote it and takes only the structure from the parser. That split is
//! deliberate: a prose rule matches the sentence as written, markers and all,
//! and what a parser would render it as is a different subject.
//!
//! No extension is enabled. A table, a footnote or a task list is a paragraph
//! here, which is what a reader that asks only "is this code" needs, and keeps
//! the answer the one the specification gives.

use pulldown_cmark::{CodeBlockKind, Event, LinkType, Options, Parser, Tag, TagEnd};

/// The byte offset each line of `text` starts at, in the order
/// [`str::lines`] yields them.
struct Lines(Vec<usize>);

impl Lines {
    fn of(text: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(
            text.match_indices('\n')
                .map(|(at, _)| at + 1)
                .filter(|start| *start < text.len()),
        );
        Self(starts)
    }

    /// The 0-based index of the line holding byte `offset`.
    fn index(&self, offset: usize) -> usize {
        self.0
            .partition_point(|start| *start <= offset)
            .saturating_sub(1)
    }
}

/// Whether each line of `text`, by index, is inside a code block, fenced or
/// indented. A fence's opening and closing lines are inside it.
pub(crate) fn code_lines(text: &str) -> Vec<bool> {
    let lines = Lines::of(text);
    let mut code = vec![false; lines.0.len()];
    for (event, range) in Parser::new_ext(text, Options::empty()).into_offset_iter() {
        if let Event::Start(Tag::CodeBlock(_)) = event {
            let last = lines.index(range.end.saturating_sub(1).max(range.start));
            for line in lines.index(range.start)..=last {
                if let Some(slot) = code.get_mut(line) {
                    *slot = true;
                }
            }
        }
    }
    code
}

/// `(line, code)` for every line of every code block and every inline code
/// span, in document order.
///
/// A block's lines are its content without the fences. A span is its content
/// as `CommonMark` gives it: one leading and one trailing space stripped where
/// both are there, and a line ending inside it read as a space.
pub(crate) fn code(text: &str) -> Vec<(u64, String)> {
    let lines = Lines::of(text);
    let mut found = Vec::new();
    let mut block: Option<(usize, bool)> = None;
    for (event, range) in Parser::new_ext(text, Options::empty()).into_offset_iter() {
        match event {
            Event::Start(Tag::CodeBlock(kind)) => {
                let first = lines.index(range.start);
                // A fenced block's content starts on the line after its fence.
                let fenced = matches!(kind, CodeBlockKind::Fenced(_));
                block = Some((first + usize::from(fenced), fenced));
            }
            Event::End(TagEnd::CodeBlock) => block = None,
            Event::Text(content) => {
                if let Some((first, _)) = block {
                    let start = lines.index(range.start).max(first);
                    for (offset, line) in content.lines().enumerate() {
                        found.push(((start + offset) as u64 + 1, line.to_owned()));
                    }
                }
            }
            Event::Code(content) => {
                found.push((lines.index(range.start) as u64 + 1, content.into_string()));
            }
            _ => {}
        }
    }
    found
}

/// `(line, destination)` for every inline link and image, and every link
/// reference definition, in document order.
///
/// A reference-style use (`[text][label]`) is not listed: its destination is
/// the definition's, which is listed once, on its own line. A link inside code
/// is not a link.
pub(crate) fn link_destinations(text: &str) -> Vec<(u64, String)> {
    let lines = Lines::of(text);
    let parser = Parser::new_ext(text, Options::empty());
    let mut found: Vec<(u64, String)> = parser
        .reference_definitions()
        .iter()
        .map(|(_, definition)| {
            (
                lines.index(definition.span.start) as u64 + 1,
                definition.dest.to_string(),
            )
        })
        .collect();
    for (event, range) in parser.into_offset_iter() {
        if let Event::Start(
            Tag::Link {
                link_type: LinkType::Inline,
                dest_url,
                ..
            }
            | Tag::Image {
                link_type: LinkType::Inline,
                dest_url,
                ..
            },
        ) = event
        {
            found.push((lines.index(range.start) as u64 + 1, dest_url.into_string()));
        }
    }
    found.sort_by_key(|(line, _)| *line);
    found
}

/// `(line, level, title)` for every heading, ATX or setext, its title as the
/// source writes it with its markers taken off.
pub(crate) fn headings(text: &str) -> Vec<(u64, usize, String)> {
    let lines = Lines::of(text);
    let mut found = Vec::new();
    let mut open: Option<(u64, usize, String)> = None;
    for (event, range) in Parser::new_ext(text, Options::empty()).into_offset_iter() {
        match event {
            Event::Start(Tag::Heading { level, .. }) => {
                open = Some((
                    lines.index(range.start) as u64 + 1,
                    level as usize,
                    String::new(),
                ));
            }
            Event::Text(content) | Event::Code(content) => {
                if let Some((_, _, title)) = open.as_mut() {
                    title.push_str(&content);
                }
            }
            Event::End(TagEnd::Heading(_)) => {
                if let Some(heading) = open.take() {
                    found.push(heading);
                }
            }
            _ => {}
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fence_and_an_indented_block_are_code_and_their_lines_are_numbered() {
        let text = "prose\n\n```sh\nrun a\n```\n\n    run b\n\nafter\n";
        assert_eq!(
            code_lines(text),
            [false, false, true, true, true, false, true, false, false]
        );
        assert_eq!(
            code(text),
            [(4, String::from("run a")), (7, String::from("run b"))]
        );
    }

    #[test]
    fn a_shorter_fence_inside_a_longer_one_is_a_line_of_it() {
        let text = "````md\n```\nx\n```\n````\nprose\n";
        assert_eq!(code_lines(text), [true, true, true, true, true, false]);
    }

    #[test]
    fn a_code_span_is_found_with_its_line_and_an_unclosed_run_is_text() {
        let text = "one `a b` two\nthree ``c ` d`` and ` open\n";
        assert_eq!(
            code(text),
            [(1, String::from("a b")), (2, String::from("c ` d"))]
        );
    }

    #[test]
    fn inline_links_images_and_definitions_are_listed_once_each() {
        let text =
            "[a](one.md) ![i](<two words.png>)\n\n[r][id] `[c](no.md)`\n\n[id]: three.md \"T\"\n";
        assert_eq!(
            link_destinations(text),
            [
                (1, String::from("one.md")),
                (1, String::from("two words.png")),
                (5, String::from("three.md")),
            ]
        );
    }

    #[test]
    fn headings_carry_their_level_line_and_title() {
        let text = "# One\n\ntext\n\nTwo\n---\n\n```\n# not\n```\n";
        assert_eq!(
            headings(text),
            [(1, 1, String::from("One")), (5, 2, String::from("Two"))]
        );
    }
}
