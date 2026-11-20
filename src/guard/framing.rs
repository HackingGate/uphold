//! `questions-name-a-standard` -- does each design question name the
//! published standard its parts follow, or say why none fits?
//!
//! A ruling can only pick among the options a question offers, and the
//! records it rules from ask parts to conform to the standard they implement.
//! A question that names no standard leaves the ruler to find one, and a
//! ruler that does not is ruling on options none of which may conform. The
//! framer names it, on one line under the question:
//!
//! ```text
//! ### Q1. Access lookup
//!
//! Standard: role-based access control, [ANSI/INCITS 359-2012](https://csrc.nist.gov/projects/role-based-access-control)
//! ```
//!
//! or `Standard: none -- <why none fits>`.
//!
//! WHICH TEXT IS A QUESTION. A [MADR 4.0](https://adr.github.io/madr/)
//! record's one decision, from its `Considered Options` heading through its
//! `Decision Outcome`, is one question, opened at that heading. Otherwise, the
//! section under a heading whose title says "question", as
//! `ruling-citations-resolve` reads it. Where the section has
//! sub-headings, each sub-heading at the shallowest level among them opens a
//! question. Where it has none, each top-level item of an ordered list opens
//! one, and so does each top-level bullet item or paragraph whose text opens
//! `Q<n>`. A question runs to the next one or to the end of the section, so
//! its options and its answer are inside it. Text before the first question
//! belongs to none.
//!
//! WHAT IS READ. Lines outside code, each with at most one list marker taken
//! off. A line `Standard: ` passes its question when the rest of the line
//! carries an `http` or `https` URL, inline or written out, or is
//! `none -- ` followed by a reason. No link is fetched and no forge is asked,
//! so there is no exit 2: a body is judged on its text alone, whatever the
//! issue is labelled.
//!
//! WHAT IT CANNOT READ. A questions section with text in it and no question in
//! any of the shapes above. Nothing there can be judged, and the guard says so
//! on stderr rather than refusing a body it did not understand or reporting a
//! pass for it.

use std::sync::OnceLock;

use linkify::{LinkFinder, LinkKind};
use regex::Regex;

use crate::config::Rule;
use crate::guard::Refusal;
use crate::guard::ruling::{decision_sections, list_item, question_sections};
use crate::markdown::Block;

/// A question opened by its number: `Q1`, `**Q2.**`.
static NUMBERED: OnceLock<Regex> = OnceLock::new();

fn numbered() -> &'static Regex {
    NUMBERED.get_or_init(|| crate::engine::literal_pattern(r"^(?:\*\*|__|\*|_)?Q[0-9]+\b"))
}

/// One question: the 0-based line it opens on and the lines it runs over.
struct Question {
    opens: usize,
    lines: std::ops::Range<usize>,
}

/// What a reading of one body found.
#[derive(Debug, Default, PartialEq, Eq)]
struct Framing {
    /// Each question with no `Standard:` line that passes, and why.
    unframed: Vec<String>,
    /// Questions sections with text and no question this could find.
    unread: usize,
}

/// Judge one piece of published text. `None` where every question names a
/// standard or says why none fits, including where there is no question.
pub(crate) fn in_text(rule: &Rule, label: &str, text: &str) -> Option<Refusal> {
    let framing = read(text);
    if framing.unread > 0 {
        eprintln!(
            "uphold: {}: {label}: {} questions section(s) hold text and no question this rule \
             can find (a sub-heading, a numbered item, or a line opening `Q<n>`), so no \
             `Standard:` line was checked there: this rule judged nothing in them.",
            rule.id, framing.unread
        );
    }
    if framing.unframed.is_empty() {
        return None;
    }
    Some(Refusal {
        id: rule.id.clone(),
        report: format!(
            "{label}: {} question(s) name no standard:\n{}\n\nUnder each question write one \
             line `Standard: <the published standard its parts read, write, speak or \
             implement, with a link>`, or `Standard: none -- <why none fits>`, so the ruling \
             reads the same standard the framer did.",
            framing.unframed.len(),
            framing.unframed.join("\n")
        ),
    })
}

fn read(text: &str) -> Framing {
    let code = crate::markdown::code_lines(text);
    let lines: Vec<&str> = text.lines().collect();
    let headings = crate::markdown::headings(text);
    let blocks = crate::markdown::top_level_blocks(text);
    let mut framing = Framing::default();
    let decisions = decision_sections(text)
        .into_iter()
        .map(|(opens, span)| Question { opens, lines: span });
    for question in decisions {
        judge(&question, &code, &lines, &mut framing);
    }
    for (level, section) in question_sections(text) {
        let inside = |line: u64| {
            usize::try_from(line)
                .ok()
                .and_then(|line| line.checked_sub(1))
                .filter(|index| section.contains(index))
        };
        let subs: Vec<(usize, usize)> = headings
            .iter()
            .filter(|(_, sub, _)| *sub > level)
            .filter_map(|(line, sub, _)| inside(*line).map(|index| (index, *sub)))
            .collect();
        let shallowest = subs.iter().map(|(_, sub)| *sub).min();
        let opens: Vec<usize> = if subs.is_empty() {
            blocks
                .iter()
                .filter_map(|(line, block)| inside(*line).map(|index| (index, *block)))
                .filter(|(index, block)| {
                    *block == Block::Ordered
                        || lines
                            .get(*index)
                            .is_some_and(|line| numbered().is_match(list_item(line.trim_start())))
                })
                .map(|(index, _)| index)
                .collect()
        } else {
            subs.iter()
                .filter(|(_, sub)| Some(*sub) == shallowest)
                .map(|(index, _)| *index)
                .collect()
        };
        if opens.is_empty() {
            let holds_text = section.clone().any(|index| {
                !code.get(index).copied().unwrap_or(false)
                    && lines.get(index).is_some_and(|line| !line.trim().is_empty())
            });
            framing.unread += usize::from(holds_text);
            continue;
        }
        let questions = opens.iter().enumerate().map(|(at, opens_on)| Question {
            opens: *opens_on,
            lines: *opens_on..opens.get(at + 1).copied().unwrap_or(section.end),
        });
        for question in questions {
            judge(&question, &code, &lines, &mut framing);
        }
    }
    framing
}

/// Record one question that names no standard, or says nothing on one.
fn judge(question: &Question, code: &[bool], lines: &[&str], framing: &mut Framing) {
    let standards: Vec<&str> = question
        .lines
        .clone()
        .filter(|index| !code.get(*index).copied().unwrap_or(false))
        .filter_map(|index| lines.get(index))
        .filter_map(|line| list_item(line.trim_start()).strip_prefix("Standard:"))
        .collect();
    let failure = if standards.is_empty() {
        "has no `Standard:` line"
    } else if standards.iter().any(|rest| names_a_standard(rest)) {
        return;
    } else {
        "has a `Standard:` line with no link, and it is not `none -- <why none fits>`"
    };
    let title = lines.get(question.opens).map_or("", |line| line.trim());
    framing.unframed.push(format!(
        "- line {}, {:?}: {failure}",
        question.opens + 1,
        shortened(title)
    ));
}

/// Whether the rest of a `Standard:` line names a standard by link, or says
/// why none fits.
fn names_a_standard(rest: &str) -> bool {
    let rest = rest.trim();
    if let Some(after) = rest.strip_prefix("none")
        && (after.is_empty() || after.starts_with([' ', '-']))
    {
        return after
            .trim_start()
            .strip_prefix("--")
            .is_some_and(|why| !why.trim().is_empty());
    }
    let mut finder = LinkFinder::new();
    finder.kinds(&[LinkKind::Url]);
    finder.links(rest).any(|url| {
        let url = url.as_str().to_ascii_lowercase();
        url.starts_with("https://") || url.starts_with("http://")
    })
}

/// A question's opening line, cut to a length a report can carry.
fn shortened(line: &str) -> String {
    const MOST: usize = 80;
    if line.chars().count() <= MOST {
        return line.to_owned();
    }
    let mut cut: String = line.chars().take(MOST).collect();
    cut.push_str("...");
    cut
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "Standard: [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html)";

    fn unframed(text: &str) -> Vec<usize> {
        read(text)
            .unframed
            .iter()
            .filter_map(|failure| {
                failure
                    .strip_prefix("- line ")
                    .and_then(|rest| rest.split(',').next())
                    .and_then(|line| line.parse().ok())
            })
            .collect()
    }

    #[test]
    fn each_sub_heading_at_the_shallowest_level_is_a_question() {
        let body = format!(
            "## Questions\n\nPreamble with no standard.\n\n### Q1. One\n\n{LINK}\n\n- (a) x\n\n\
             #### Reasoning\n\n### Q2. Two\n\n1. (a) a numbered option\n\n## Done when\n\n\
             ### Not a question\n"
        );
        assert_eq!(unframed(&body), [13]);
    }

    #[test]
    fn numbered_items_are_questions_and_their_options_are_not() {
        let body = format!(
            "## Questions for the ruling\n\n1. **Mode.**\n   (a) one\n   {LINK}\n\
             2. **Time.**\n   (a) two\n   - (b) three\n"
        );
        assert_eq!(unframed(&body), [6]);
    }

    #[test]
    fn a_q_numbered_paragraph_or_bullet_is_a_question_and_option_bullets_are_not() {
        let body = "## Questions\n\nQ1. How is input read?\n\n- (a) one\n- (b) two\n\n\
                    Standard: none -- no published standard orders a terminal's two directions\n\n\
                    - **Q2.** Which?\n  - (a) x\n\n  Answered: (a)\n";
        assert_eq!(unframed(body), [10]);
    }

    #[test]
    fn a_standard_line_needs_a_link_or_a_reason() {
        for (line, passes) in [
            ("Standard: https://www.w3.org/TR/WCAG22/", true),
            (
                "- Standard: [NIST RBAC](https://csrc.nist.gov/projects/role-based-access-control)",
                true,
            ),
            (
                "Standard: none -- a project convention, no published standard",
                true,
            ),
            ("Standard: none--nothing covers it", true),
            ("Standard: RFC 9110", false),
            ("Standard: none", false),
            ("Standard: none -- ", false),
            ("Standard: [RFC 9110](rfc9110.html)", false),
            ("Standards: https://example.com/", false),
        ] {
            let body = format!("## Questions\n\n1. Which?\n   {line}\n");
            assert_eq!(unframed(&body).is_empty(), passes, "{line}");
        }
    }

    #[test]
    fn a_long_opening_line_is_cut_in_the_report() {
        let long = "x".repeat(90);
        assert_eq!(shortened(&long), format!("{}...", "x".repeat(80)));
        assert_eq!(shortened("Q1. Short"), "Q1. Short");
    }

    #[test]
    fn a_standard_line_in_code_does_not_count() {
        let body = format!("## Questions\n\n### Q1\n\n```text\n{LINK}\n```\n");
        assert_eq!(unframed(&body), [3]);
    }

    #[test]
    fn a_body_with_no_questions_heading_is_not_read() {
        let body = "## Decision\n\n1. Which?\n\nQ1. Which?\n";
        assert_eq!(read(body), Framing::default());
    }

    #[test]
    fn a_questions_section_with_text_and_no_question_is_unread_not_passed() {
        let read = read("## Open questions\n\nWhether the cache is shared.\n\n## Plan\n");
        assert_eq!(read.unread, 1);
        assert_eq!(read.unframed, Vec::<String>::new());
        assert_eq!(
            super::read("## Questions\n\n## Plan\n"),
            Framing::default(),
            "an empty section holds nothing to judge"
        );
    }

    #[test]
    fn a_madr_record_is_one_question_framed_under_its_options() {
        let framed = "## Considered Options\n\nStandard: none -- ours\n\n- (a)\n- (b)\n\n\
                      ## Decision Outcome\n\nAnswered: (a)\n";
        assert_eq!(read(framed), Framing::default());
        let bare = "## Context and Problem Statement\n\nx\n\n## Considered Options\n\n- (a)\n- (b)\n\n\
                    ## Decision Outcome\n\n### Confirmation\n\n- [ ] t\n";
        assert_eq!(unframed(bare), [5]);
    }

    #[test]
    fn options_held_under_a_question_are_that_question_s_and_not_a_second_one() {
        let body = "## Questions\n\n### Q1. Which?\n\nStandard: none -- project policy\n\n\
                    #### Considered Options\n\n- (a) one\n\n#### Decision Outcome\n\nAnswered: (a)\n";
        assert_eq!(read(body), Framing::default());
        assert_eq!(decision_sections(body), []);
    }
}
