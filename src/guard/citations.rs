//! `citations-linked` -- does each citation of a numbered standard or an
//! identifier link to what it cites?
//!
//! A pull-request body that says `RFC 9110 §10.2.3` asks its reader to find
//! the section; a link to it is the citation the reader can check. A link to
//! the whole RFC, or to another section, looks the same until it is followed.
//!
//! ONE MECHANISM, A TABLE OF FAMILIES. A citation is `<family> <document id>
//! [<locator>]`. Each row of [`FAMILIES`] says how to recognize one family's
//! citations, which URLs are that family's links to a given document, and,
//! where the family's anchors follow from the number, what a link to a given
//! section ends with. The rows are data compiled into the binary: a family
//! added is a row, never a second built-in.
//!
//! EACH FAMILY IS HELD TO THE STRONGEST CHECK ITS LINKS ALLOW. A Section row
//! checks that the link is to that document and, when a section is cited, to
//! that section. A Record row checks that the link is to that record. Which
//! class a row is follows from what its links can carry, recorded in the
//! design issue with the date each page was read.
//!
//! WHAT IS READ. The text as `pulldown-cmark` parses it, the way a forge
//! renders a body: code blocks and code spans are left out, and a link's
//! destination is the parser's, reference links resolved through their
//! definitions. A URL written out in prose is found by `linkify`, which knows
//! where a URL ends and the sentence's punctuation begins. A citation is
//! checked against the link whose text it is, or else against the first URL
//! written out after it and before the next citation in the same block. No
//! link is fetched: the section anchors follow from the number, so there is no
//! network call and no exit 2 of this guard's own.

use std::ops::Range;
use std::sync::OnceLock;

use linkify::{LinkFinder, LinkKind};
use pulldown_cmark::{Event, LinkType, Options, Parser, Tag, TagEnd};
use regex::Regex;

use crate::config::Rule;
use crate::guard::Refusal;

/// How far a family's links let a check go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// Linked, to that document, and to the cited section.
    Section,
    /// Linked, to that record.
    Record,
}

/// One family of citations.
struct Family {
    name: &'static str,
    class: Class,
    /// Recognizes one citation. Named groups: `id`, the document id the link
    /// templates take; `version`, where a citation may state one the link
    /// must then carry; `section` and `appendix`, a cited locator.
    pattern: &'static str,
    /// The family's links to document `<id>`, matched against the whole URL
    /// with its fragment taken off. `*` is one path segment.
    links: &'static [&'static str],
    /// Whether `<id>` compares without regard to case, as a DOI does.
    id_any_case: bool,
    /// What a link may carry after `<id>` that the citation need not state:
    /// an arXiv version. A version the citation does state must be the one
    /// linked.
    id_suffix: &'static str,
}

/// The RFC and Internet-Draft locators: `§10.2.3`, `Section 10.2.3` or
/// `Appendix A`, after the document id.
macro_rules! locator {
    () => {
        r"(?:,?[ \u{a0}]*(?:§[ \u{a0}]?|[Ss]ection[ \u{a0}]+)(?P<section>[0-9]+(?:\.[0-9]+)*)|,?[ \u{a0}]*Appendix[ \u{a0}]+(?P<appendix>[A-Z](?:\.[0-9]+)*))?"
    };
}

/// The families of the first version. The order is the order a citation is
/// looked for in, which matters only where two rows could claim the same
/// text; none here can.
const FAMILIES: &[Family] = &[
    Family {
        name: "RFC",
        class: Class::Section,
        pattern: concat!(r"\bRFC[ \u{a0}]*(?P<id>[1-9][0-9]{0,4})\b", locator!()),
        links: &[
            "https://www.rfc-editor.org/rfc/rfc<id>.html",
            "https://datatracker.ietf.org/doc/html/rfc<id>",
        ],
        id_any_case: false,
        id_suffix: "",
    },
    Family {
        name: "Internet-Draft",
        class: Class::Section,
        pattern: concat!(
            r"\b(?P<id>draft-[a-z0-9]+(?:-[a-z0-9]+)*-[0-9]{2})\b",
            locator!()
        ),
        links: &["https://datatracker.ietf.org/doc/html/<id>"],
        id_any_case: false,
        id_suffix: "",
    },
    Family {
        name: "BCP",
        class: Class::Record,
        pattern: r"\bBCP[ \u{a0}]*(?P<id>[1-9][0-9]*)\b",
        links: &["https://www.rfc-editor.org/info/bcp<id>"],
        id_any_case: false,
        id_suffix: "",
    },
    Family {
        name: "STD",
        class: Class::Record,
        pattern: r"\bSTD[ \u{a0}]*(?P<id>[1-9][0-9]*)\b",
        links: &["https://www.rfc-editor.org/info/std<id>"],
        id_any_case: false,
        id_suffix: "",
    },
    Family {
        name: "CVE",
        class: Class::Record,
        pattern: r"\b(?P<id>CVE-[0-9]{4}-[0-9]{4,})\b",
        links: &[
            "https://www.cve.org/CVERecord?id=<id>",
            "https://nvd.nist.gov/vuln/detail/<id>",
        ],
        id_any_case: false,
        id_suffix: "",
    },
    Family {
        name: "CWE",
        class: Class::Record,
        pattern: r"\bCWE-(?P<id>[1-9][0-9]*)\b",
        links: &["https://cwe.mitre.org/data/definitions/<id>.html"],
        id_any_case: false,
        id_suffix: "",
    },
    Family {
        name: "GHSA",
        class: Class::Record,
        pattern: r"\b(?P<id>GHSA(?:-[0-9a-z]{4}){3})\b",
        links: &[
            "https://github.com/advisories/<id>",
            "https://github.com/*/*/security/advisories/<id>",
        ],
        id_any_case: false,
        id_suffix: "",
    },
    Family {
        name: "DOI",
        class: Class::Record,
        pattern: r"(?:\bdoi:[ \u{a0}]?|\b)(?P<id>10\.[0-9]{4,9}/(?:[^\s<>()\[\]]|\([^\s<>()\[\]]*\))*(?:[^\s<>()\[\].,;:!?'`]|\([^\s<>()\[\]]*\)))",
        links: &["https://doi.org/<id>"],
        id_any_case: true,
        id_suffix: "",
    },
    Family {
        name: "arXiv",
        class: Class::Record,
        pattern: r"\barXiv:[ \u{a0}]?(?P<id>[0-9]{4}\.[0-9]{4,5})(?P<version>v[0-9]+)?\b",
        links: &["https://arxiv.org/abs/<id>", "https://arxiv.org/pdf/<id>"],
        id_any_case: false,
        id_suffix: "(?:v[0-9]+)?",
    },
];

fn compiled() -> &'static [Regex] {
    static COMPILED: OnceLock<Vec<Regex>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        FAMILIES
            .iter()
            .map(|family| crate::engine::literal_pattern(family.pattern))
            .collect()
    })
}

/// One block of prose -- a paragraph, a heading, a list item, a table cell --
/// as text, with where its links are.
#[derive(Debug, Default)]
struct Block {
    /// The block's text, a code span or a break each one space, and every URL
    /// written out blanked so that an id inside one is not a citation.
    text: String,
    /// The ranges of `text` that are a link's text, with its destination.
    links: Vec<(Range<usize>, String)>,
    /// The ranges of `text` that were a URL written out, with the URL.
    urls: Vec<(Range<usize>, String)>,
}

impl Block {
    /// Append prose, blanking each URL in it. Outside a link's text the URL is
    /// kept as a candidate link; inside one it is only the link's text.
    fn push(&mut self, prose: &str, in_link: bool) {
        let offset = self.text.len();
        self.text.push_str(prose);
        let mut finder = LinkFinder::new();
        finder.kinds(&[LinkKind::Url]);
        for url in finder.links(prose) {
            let range = offset + url.start()..offset + url.end();
            if !in_link {
                self.urls.push((range.clone(), url.as_str().to_owned()));
            }
            blank(&mut self.text, range);
        }
    }
}

/// The blocks of prose in a Markdown text.
fn blocks(text: &str) -> Vec<Block> {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_FOOTNOTES;
    let mut blocks = Vec::new();
    let mut block = Block::default();
    let mut in_code = 0_usize;
    let mut link: Option<(usize, String, bool)> = None;
    for event in Parser::new_ext(text, options) {
        match event {
            Event::Start(Tag::CodeBlock(_)) => in_code += 1,
            Event::End(TagEnd::CodeBlock) => in_code = in_code.saturating_sub(1),
            Event::Start(Tag::Link {
                link_type,
                dest_url,
                ..
            }) => {
                let autolink = matches!(link_type, LinkType::Autolink | LinkType::Email);
                link = Some((block.text.len(), dest_url.into_string(), autolink));
            }
            Event::End(TagEnd::Link) => {
                if let Some((start, url, autolink)) = link.take() {
                    let range = start..block.text.len();
                    if autolink {
                        blank(&mut block.text, range.clone());
                        block.urls.push((range, url));
                    } else {
                        block.links.push((range, url));
                    }
                }
            }
            Event::Text(prose) if in_code == 0 => block.push(&prose, link.is_some()),
            Event::Code(_) | Event::SoftBreak | Event::HardBreak => block.text.push(' '),
            // A formatting tag joins the text on either side, as a browser
            // renders it; a line break separates it.
            Event::InlineHtml(tag) if tag.to_ascii_lowercase().starts_with("<br") => {
                block.text.push(' ');
            }
            Event::Start(Tag::List(_))
            | Event::End(
                TagEnd::Paragraph
                | TagEnd::Heading(_)
                | TagEnd::Item
                | TagEnd::TableCell
                | TagEnd::BlockQuote(_)
                | TagEnd::FootnoteDefinition,
            ) => blocks.push(std::mem::take(&mut block)),
            _ => {}
        }
    }
    blocks.push(block);
    blocks.retain(|kept| !kept.text.trim().is_empty());
    blocks
}

/// One citation, as the text wrote it.
#[derive(Debug, PartialEq, Eq)]
struct Citation {
    family: usize,
    written: String,
    id: String,
    version: Option<String>,
    /// The anchor a link to the cited section ends with, where a section is
    /// cited and the family's links carry one.
    anchor: Option<String>,
    link: Option<String>,
}

/// Judge one piece of published text. `None` where every citation links to
/// what it cites, including where there is no citation at all.
pub(crate) fn in_text(rule: &Rule, label: &str, text: &str) -> Option<Refusal> {
    let failures: Vec<String> = blocks(text)
        .iter()
        .flat_map(citations)
        .filter_map(|citation| judge(&citation).map(|why| format!("- {}: {why}", citation.written)))
        .collect();
    if failures.is_empty() {
        return None;
    }
    Some(Refusal {
        id: rule.id.clone(),
        report: format!(
            "{label}: a citation does not link to what it cites:\n{}\n\nLink each citation \
             to the document it names, and to the section where it names one, so a reader who \
             follows the link finds what was cited.",
            failures.join("\n")
        ),
    })
}

/// What is wrong with one citation's link, or `None`.
fn judge(citation: &Citation) -> Option<String> {
    let family = FAMILIES.get(citation.family)?;
    let Some(link) = &citation.link else {
        return Some(format!("no link; link it to {}", wanted(family, citation)));
    };
    let (document, fragment) = link
        .split_once('#')
        .map_or((link.as_str(), None), |(document, fragment)| {
            (document, Some(fragment))
        });
    if !family
        .links
        .iter()
        .any(|template| links_to(template, &citation.id, family, document))
    {
        return Some(format!(
            "links to {link}, which is not {} {}; link it to {}",
            family.name,
            citation.id,
            wanted(family, citation)
        ));
    }
    if let Some(version) = &citation.version
        && !document.ends_with(&format!("{}{version}", citation.id))
    {
        return Some(format!(
            "cites {}{version} and links to {link}, another version",
            citation.id
        ));
    }
    if family.class == Class::Section
        && let Some(anchor) = &citation.anchor
        && !fragment.is_some_and(|fragment| in_section(fragment, anchor))
    {
        return Some(format!(
            "cites #{anchor} and links to {link}; link it to {document}#{anchor}"
        ));
    }
    None
}

/// The links a citation should have, for its message: each of the family's
/// links to its document, with the cited section's anchor where there is one.
fn wanted(family: &Family, citation: &Citation) -> String {
    let anchor = citation
        .anchor
        .as_ref()
        .map_or_else(String::new, |anchor| format!("#{anchor}"));
    // A version the citation states is part of the link it should have.
    let linked_id = format!(
        "{}{}",
        citation.id,
        citation.version.as_deref().unwrap_or("")
    );
    family
        .links
        .iter()
        .map(|link| format!("{}{anchor}", link.replace("<id>", &linked_id)))
        .collect::<Vec<_>>()
        .join(" or ")
}

/// Whether `document` is `template` with `<id>` filled in.
fn links_to(template: &str, id: &str, family: &Family, document: &str) -> bool {
    let mut pattern = String::from("^");
    for (index, part) in template.split("<id>").enumerate() {
        if index > 0 {
            if family.id_any_case {
                pattern.push_str("(?i:");
                pattern.push_str(&regex::escape(id));
                pattern.push(')');
            } else {
                pattern.push_str(&regex::escape(id));
            }
            pattern.push_str(family.id_suffix);
        }
        pattern.push_str(&regex::escape(part).replace(r"\*", "[^/?#]+"));
    }
    pattern.push('$');
    Regex::new(&pattern).is_ok_and(|compiled| compiled.is_match(document))
}

/// Whether a fragment names the section `anchor` or a paragraph in it: the
/// RFC series numbers a section's paragraphs `section-10.2.3-1` and so on.
fn in_section(fragment: &str, anchor: &str) -> bool {
    fragment == anchor
        || fragment
            .strip_prefix(anchor)
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Every citation in one block of prose, each with the link it is read
/// against.
fn citations(block: &Block) -> Vec<Citation> {
    let masked = &block.text;
    let mut found: Vec<(Range<usize>, Citation)> = Vec::new();
    for (index, pattern) in compiled().iter().enumerate() {
        for captures in pattern.captures_iter(masked) {
            let (Some(whole), Some(id)) = (captures.get(0), captures.name("id")) else {
                continue;
            };
            if found
                .iter()
                .any(|(range, _)| range.start < whole.end() && whole.start() < range.end)
                || preceded_by_word(masked, whole.start())
            {
                continue;
            }
            let anchor = captures
                .name("section")
                .map(|section| format!("section-{}", section.as_str()))
                .or_else(|| {
                    captures
                        .name("appendix")
                        .map(|appendix| format!("appendix-{}", appendix.as_str()))
                });
            found.push((
                whole.range(),
                Citation {
                    family: index,
                    written: whole.as_str().trim().to_owned(),
                    id: id.as_str().to_owned(),
                    version: captures
                        .name("version")
                        .map(|version| version.as_str().to_owned()),
                    anchor,
                    link: None,
                },
            ));
        }
    }
    found.sort_by_key(|(range, _)| range.start);

    let starts: Vec<usize> = found.iter().map(|(range, _)| range.start).collect();
    for (position, (range, citation)) in found.iter_mut().enumerate() {
        citation.link = block
            .links
            .iter()
            .find(|(inner, _)| inner.start <= range.start && range.end <= inner.end)
            .map(|(_, url)| url.clone())
            .or_else(|| {
                let next = starts.get(position + 1).copied().unwrap_or(usize::MAX);
                block
                    .urls
                    .iter()
                    .find(|(url, _)| url.start >= range.end && url.start < next)
                    .map(|(_, url)| url.clone())
            });
    }
    found.into_iter().map(|(_, citation)| citation).collect()
}

/// Whether the byte before `at` continues a word or an identifier, so that
/// `xRFC 1` and `foo-draft-x-00` are not citations.
fn preceded_by_word(text: &str, at: usize) -> bool {
    text.get(..at)
        .and_then(|before| before.chars().next_back())
        .is_some_and(|character| {
            character.is_alphanumeric() || character == '-' || character == '/'
        })
}

/// Replace a byte range with spaces, keeping every other offset where it was.
fn blank(text: &mut String, range: Range<usize>) {
    if let Some(slice) = text.get(range.clone()) {
        let spaces = " ".repeat(slice.len());
        text.replace_range(range, &spaces);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> Vec<(String, Option<String>, Option<String>)> {
        blocks(text)
            .iter()
            .flat_map(citations)
            .map(|citation| (citation.written, citation.anchor, citation.link))
            .collect()
    }

    #[test]
    fn a_citation_is_read_against_the_link_it_is_the_text_of() {
        assert_eq!(
            read(
                "See [RFC 9110 §10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3)."
            ),
            [(
                String::from("RFC 9110 §10.2.3"),
                Some(String::from("section-10.2.3")),
                Some(String::from(
                    "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3"
                ))
            )]
        );
    }

    #[test]
    fn a_bare_url_belongs_to_the_citation_before_it_and_no_later_one() {
        let found = read("RFC 9110 (https://www.rfc-editor.org/rfc/rfc9110.html) and RFC 9111.");
        assert_eq!(found.len(), 2);
        assert!(found.first().is_some_and(|first| first.2.is_some()));
        assert!(found.get(1).is_some_and(|second| second.2.is_none()));
    }

    #[test]
    fn an_id_inside_a_url_or_inline_code_is_not_a_citation() {
        assert_eq!(
            read("https://www.cve.org/CVERecord?id=CVE-2024-3094 and `RFC 9110`").len(),
            0
        );
    }

    #[test]
    fn a_reference_link_resolves_through_its_definition() {
        let found: Vec<Option<String>> =
            read("See [CWE-79][1].\n\n[1]: https://cwe.mitre.org/data/definitions/79.html\n")
                .into_iter()
                .map(|(_, _, link)| link)
                .collect();
        assert_eq!(
            found,
            [Some(String::from(
                "https://cwe.mitre.org/data/definitions/79.html"
            ))]
        );
    }

    #[test]
    fn a_fenced_block_and_a_code_span_are_not_read() {
        assert_eq!(read("```\nRFC 9110\n```\n\nRun `RFC 9110` here.").len(), 0);
    }

    #[test]
    fn spacing_and_formatting_tags_do_not_hide_a_citation() {
        for text in [
            "RFC  9110 says so.",
            "<em>RFC 9110</em> says so.",
            "<em>RFC</em> 9110 says so.",
            "Line one<br>RFC 9110 says so.",
        ] {
            assert_eq!(read(text).len(), 1, "{text}");
        }
    }

    #[test]
    fn a_doi_keeps_its_balanced_parentheses_and_drops_a_closing_one() {
        let found = read("(doi:10.1016/0012-365X(95)00186-7)");
        assert_eq!(
            found.first().map(|citation| citation.0.as_str()),
            Some("doi:10.1016/0012-365X(95)00186-7")
        );
    }

    #[test]
    fn a_versioned_arxiv_citation_is_told_its_versioned_link() {
        let citation = citations(&blocks("arXiv:1706.03762v7").remove(0)).remove(0);
        let family = FAMILIES.get(citation.family).expect("a row");
        assert!(wanted(family, &citation).starts_with("https://arxiv.org/abs/1706.03762v7"));
    }

    #[test]
    fn a_paragraph_of_the_cited_section_is_in_it() {
        assert!(in_section("section-10.2.3-1", "section-10.2.3"));
        assert!(!in_section("section-10.2.30", "section-10.2.3"));
        assert!(!in_section("section-10.2", "section-10.2.3"));
    }

    #[test]
    fn a_template_segment_matches_one_path_segment() {
        let template = "https://github.com/*/*/security/advisories/<id>";
        let id = "GHSA-jfh8-c2jp-5v3q";
        let ghsa = FAMILIES
            .iter()
            .find(|family| family.name == "GHSA")
            .expect("a GHSA row");
        assert!(links_to(
            template,
            id,
            ghsa,
            "https://github.com/owner/repo/security/advisories/GHSA-jfh8-c2jp-5v3q"
        ));
        assert!(!links_to(
            template,
            id,
            ghsa,
            "https://github.com/owner/security/advisories/GHSA-jfh8-c2jp-5v3q"
        ));
    }
}
