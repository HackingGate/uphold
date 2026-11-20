//! `ruling-citations-resolve` -- does each catalog item an answer cites still
//! say what the answer quotes, in the catalog this repository pins?
//!
//! A design question is answered from the records a repository adopts, and
//! the answer cites each record by its id, linked to the record's file with
//! no revision and no line, with a quote of the item it used:
//!
//! ```text
//! Answered: (a). [unix-composability review_questions](https://github.com/HackingGate/uphold/blob/HEAD/principles/unix-composability.toml) "Can a script or an agent do everything a person at a terminal can"
//! ```
//!
//! The quote identifies the item, as the exact text of a
//! [W3C Web Annotation TextQuoteSelector](https://www.w3.org/TR/annotation-model/#text-quote-selector)
//! does, and not its position: the item is found wherever it is in the
//! record, so a bump that only moves it needs no edit to the body. Which
//! catalog the quote is read in is the pin, written once in the hook
//! configuration. A link that names a revision or
//! a line again is refused, because that copy of the pin goes stale on the
//! next bump while the body still reads as current.
//!
//! A quote no item of its record holds at the pin is refused, and the refusal
//! names the question that holds it: the text the ruling rested on changed,
//! and the question is re-ruled before the body is published again.
//!
//! WHICH TEXT IS AN ANSWER. A line that opens `Answered:`, optionally as a list
//! item, outside a code fence, under a heading whose title says "question", or
//! in a [MADR 4.0](https://adr.github.io/madr/) record's one decision: the
//! `Considered Options` section and the `Decision Outcome` after it
//! ([`decision_sections`]). The marker is the subject, so no forge is asked how the issue is
//! labelled and a body with no such line passes without a pin being read.
//!
//! WHICH ITEM. Any string the record's TOML holds, its `claim`, an element of
//! `applies_when` or `does_not_mean`, a source's `locator`, read as parsed, so
//! a quote never spans TOML syntax. The link text may name the field for a
//! reader; it is not read.
//!
//! WHICH CATALOG. The one compiled into this binary, which is the catalog of
//! exactly one tag, `v<version>`. A pin naming any other revision is a
//! catalog this binary cannot read, and that is exit 2 rather than a guess at
//! what the other revision holds: running the uphold the repository pins is
//! the answer, and the message says so.

use std::collections::BTreeSet;
use std::ops::Range;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;

use crate::config::Rule;
use crate::error::{Fatal, Result};
use crate::guard::Refusal;

/// A link into the catalog: a URL or Markdown link target, then
/// `principles/<id>.toml`, then whatever follows it up to a delimiter -- a
/// fragment, a query, another extension. A bare path is a citation only with
/// a fragment, as the line-numbered form wrote it, so that a relative,
/// foreign, old-form or suffixed link is found and refused rather than passed
/// over, while a file named in prose is not read as one.
static CITATION: OnceLock<Regex> = OnceLock::new();

fn citation_pattern() -> &'static Regex {
    CITATION.get_or_init(|| {
        crate::engine::literal_pattern(
            r#"(https?://[^\s()<>\[\]"]*?/|\]\([^\s()<>\[\]"]*?)?principles/([a-z0-9][a-z0-9-]*)\.toml([^\s()<>\[\]"]*)"#,
        )
    })
}

/// The prefix a link must carry: this repository's blob view, at a revision.
static BLOB: OnceLock<Regex> = OnceLock::new();

fn blob_pattern() -> &'static Regex {
    BLOB.get_or_init(|| {
        crate::engine::literal_pattern(r"^https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/$")
    })
}

/// The quoted item after a link, in straight or curly double quotes.
static QUOTE: OnceLock<Regex> = OnceLock::new();

fn quote_pattern() -> &'static Regex {
    QUOTE.get_or_init(|| crate::engine::literal_pattern(r#""([^"]+)"|“([^”]+)”"#))
}

/// The revision segment a link carries in place of one: GitHub's name for the
/// default branch, which states no revision of its own.
const NO_REVISION: &str = "HEAD";

/// One citation, as an answer wrote it.
#[derive(Debug)]
struct Citation<'a> {
    link: &'a str,
    /// The revision in `github.com/<this repository>/blob/<rev>/`; `None`
    /// where the link is not to this repository's blob view.
    rev: Option<&'a str>,
    /// What follows `.toml` in the link: empty in the one form this rule
    /// accepts, `#L<n>` in the line-numbered form.
    suffix: &'a str,
    id: &'a str,
    quote: Option<&'a str>,
}

/// One answer line, with the question it answers.
#[derive(Debug)]
struct Answer<'a> {
    question: String,
    line: &'a str,
}

/// Judge one piece of published text. `None` where every citation resolves,
/// including where there is no answer or no citation at all.
pub(crate) fn in_text(
    root: &Path,
    rule: &Rule,
    label: &str,
    text: &str,
) -> Result<Option<Refusal>> {
    let cited: Vec<(String, Citation<'_>)> = answers(text)
        .into_iter()
        .flat_map(|answer| {
            cited(answer.line)
                .into_iter()
                .map(move |citation| (answer.question.clone(), citation))
        })
        .collect();
    if cited.is_empty() {
        return Ok(None);
    }
    let carried = format!("v{}", env!("CARGO_PKG_VERSION"));
    let pin = pinned_revision(root, &rule.id, &carried)?;
    let mut failures = Vec::new();
    for (question, citation) in &cited {
        if let Some(failure) = judge(citation, crate::catalog::source(citation.id), &pin) {
            failures.push(format!("- {question}: {}: {failure}", citation.link));
        }
    }
    if failures.is_empty() {
        return Ok(None);
    }
    Ok(Some(Refusal {
        id: rule.id.clone(),
        report: format!(
            "{label}: {} citation(s) of the catalog do not resolve in the uphold catalog \
             this repository pins ({pin}):\n{}\n\nLink each record as {} with no line, and \
             quote the item as the record says it. Where the record no longer says it, \
             re-rule that question before publishing the body.",
            failures.len(),
            failures.join("\n"),
            record_link("<id>"),
        ),
    }))
}

/// The one link form a citation takes for record `id`.
fn record_link(id: &str) -> String {
    let (owner, name) = crate::check::upstream_slug().unwrap_or(("", ""));
    format!("https://github.com/{owner}/{name}/blob/{NO_REVISION}/principles/{id}.toml")
}

/// What is wrong with one citation of a record whose file at the pin is
/// `source`, or `None`.
fn judge(citation: &Citation<'_>, source: Option<&str>, pin: &str) -> Option<String> {
    let to_write = record_link(citation.id);
    match citation.rev {
        None => {
            return Some(format!(
                "not a link to {to_write}, so a reader cannot follow it to the record"
            ));
        }
        Some(rev) if rev != NO_REVISION || citation.suffix.starts_with("#L") => {
            let rev = if rev == NO_REVISION {
                String::new()
            } else {
                format!(" the revision {rev}")
            };
            let line = if citation.suffix.is_empty() {
                String::new()
            } else {
                format!(" {}", citation.suffix)
            };
            return Some(format!(
                "names{rev}{line}, a copy of the pin the hook configuration already \
                 states. Link {to_write} and keep the quote"
            ));
        }
        Some(_) if !citation.suffix.is_empty() => {
            return Some(format!(
                "carries {:?} after the record's file name. Link {to_write} with nothing \
                 after it",
                citation.suffix
            ));
        }
        Some(_) => {}
    }
    let Some(source) = source else {
        return Some(format!(
            "{pin} has no record {:?} in its catalog",
            citation.id
        ));
    };
    let Some(quote) = citation.quote else {
        return Some(String::from(
            "carries no quote. Follow the link with the item it cites, in double quotes",
        ));
    };
    if !items(source).iter().any(|item| item.contains(quote)) {
        return Some(format!(
            "no item of principles/{}.toml at {pin} says {quote:?}: the text this answer \
             rested on changed, so re-rule this question",
            citation.id
        ));
    }
    None
}

/// Every string a record's TOML holds, at any depth, as parsed.
fn items(source: &str) -> Vec<String> {
    fn walk(value: &toml::Value, found: &mut Vec<String>) {
        match value {
            toml::Value::String(text) => found.push(text.clone()),
            toml::Value::Array(values) => values.iter().for_each(|item| walk(item, found)),
            toml::Value::Table(table) => table.values().for_each(|item| walk(item, found)),
            _ => {}
        }
    }
    let mut found = Vec::new();
    if let Ok(table) = toml::from_str::<toml::Table>(source) {
        table.values().for_each(|value| walk(value, &mut found));
    }
    found
}

/// The one revision of this repository the hook configuration here pins, which
/// must be the one whose catalog this binary carries. No pin, or a pin at any
/// other revision, is exit 2: what the catalog says there cannot be read here.
fn pinned_revision(root: &Path, rule: &str, carried: &str) -> Result<String> {
    let (owner, name) = crate::check::upstream_slug().unwrap_or(("", ""));
    let pinned: BTreeSet<String> = crate::pins::read_pins(root)?
        .pins
        .into_iter()
        .filter(|pin| {
            crate::git::owner_repo(&pin.repo).is_some_and(|(pin_owner, pin_name)| {
                pin_owner.eq_ignore_ascii_case(owner) && pin_name.eq_ignore_ascii_case(name)
            })
        })
        .map(|pin| pin.rev)
        .collect();
    if pinned.is_empty() {
        return Err(Fatal::new(format!(
            "rule {rule:?}: this text cites uphold's catalog, and no hook configuration here \
             pins {owner}/{name}, so the catalog a citation must resolve in cannot be read. \
             Nothing was published; pin uphold, or run this where it is pinned"
        )));
    }
    let other: Vec<&str> = pinned
        .iter()
        .map(String::as_str)
        .filter(|rev| *rev != carried)
        .collect();
    if !other.is_empty() {
        return Err(Fatal::new(format!(
            "rule {rule:?}: this repository pins uphold at {}, and this binary carries the \
             catalog of {carried}, so whether a citation resolves there cannot be read here. \
             Nothing was published; run the uphold the repository pins",
            other.join(", ")
        )));
    }
    Ok(carried.to_owned())
}

/// The citations on one answer line, each with the first quote after it and
/// before the next citation.
fn cited(line: &str) -> Vec<Citation<'_>> {
    // A file named in prose is no citation, and it does not end the window in
    // which the citation before it looks for its quote.
    let found: Vec<regex::Captures<'_>> = citation_pattern()
        .captures_iter(line)
        .filter(|captures| {
            captures.get(1).is_some()
                || captures
                    .get(3)
                    .is_some_and(|suffix| suffix.as_str().starts_with('#'))
        })
        .collect();
    let mut citations = Vec::new();
    for (index, captures) in found.iter().enumerate() {
        let (Some(whole), Some(id)) = (captures.get(0), captures.get(2)) else {
            continue;
        };
        let prefix = captures.get(1).map(|prefix| {
            prefix
                .as_str()
                .strip_prefix("](")
                .unwrap_or(prefix.as_str())
        });
        let suffix = captures.get(3).map_or("", |suffix| suffix.as_str());
        let end = found
            .get(index + 1)
            .and_then(|next| next.get(0))
            .map_or(line.len(), |next| next.start());
        let after = line.get(whole.end()..end).unwrap_or("");
        let quote = quote_pattern()
            .captures(after)
            .and_then(|quoted| quoted.get(1).or_else(|| quoted.get(2)))
            .map(|quoted| quoted.as_str());
        let rev = prefix
            .and_then(|prefix| blob_pattern().captures(prefix))
            .and_then(|blob| {
                let (owner, name) = crate::check::upstream_slug()?;
                let same = blob.get(1)?.as_str().eq_ignore_ascii_case(owner)
                    && blob.get(2)?.as_str().eq_ignore_ascii_case(name);
                same.then(|| blob.get(3).map(|rev| rev.as_str())).flatten()
            });
        let written = whole.as_str().strip_prefix("](").unwrap_or(whole.as_str());
        citations.push(Citation {
            link: written,
            rev,
            suffix,
            id: id.as_str(),
            quote,
        });
    }
    citations
}

/// The questions sections of a body: for each heading whose title says
/// "question", its level and the 0-based indices of the lines under it, up to
/// the next heading at that level or above.
///
/// A heading below the questions heading's level stays inside its section
/// whatever it says. Which lines are headings is the parser's answer
/// ([`crate::markdown`]), so a `#` line in a code block is not one.
pub(crate) fn question_sections(text: &str) -> Vec<(usize, Range<usize>)> {
    let mut found = Vec::new();
    let mut open: Option<(usize, usize)> = None;
    for (line, level, title) in crate::markdown::headings(text) {
        let index = usize::try_from(line)
            .unwrap_or(usize::MAX)
            .saturating_sub(1);
        if open.is_some_and(|(questions, _)| level > questions) {
            continue;
        }
        if let Some((questions, start)) = open.take() {
            found.push((questions, start..index));
        }
        if title.to_lowercase().contains("question") {
            open = Some((level, index + 1));
        }
    }
    if let Some((questions, start)) = open {
        found.push((questions, start..text.lines().count().max(start)));
    }
    found
}

/// The one decision of each [MADR 4.0](https://adr.github.io/madr/) record in a
/// body: the 0-based line of its `Considered Options` heading, and the lines
/// from there through the `Decision Outcome` heading at the same level that
/// follows it, up to the next heading at that level or above. A record holds
/// one decision, so the span is one question: its `Standard:` line sits with
/// the options, and its `Answered:` line under the outcome.
pub(crate) fn decision_sections(text: &str) -> Vec<(usize, Range<usize>)> {
    let headings: Vec<(usize, usize, String)> = crate::markdown::headings(text)
        .into_iter()
        .filter_map(|(line, level, title)| {
            let index = usize::try_from(line).ok()?.checked_sub(1)?;
            Some((index, level, title.trim().to_lowercase()))
        })
        .collect();
    let end_of_text = text.lines().count();
    let mut found = Vec::new();
    for (at, (index, level, title)) in headings.iter().enumerate() {
        if title != "considered options" {
            continue;
        }
        let mut rest = headings
            .iter()
            .skip(at + 1)
            .filter(|(_, other, _)| other <= level);
        let mut end = rest.next();
        if end.is_some_and(|(_, other, next)| other == level && next == "decision outcome") {
            end = rest.next();
        }
        let end = end.map_or(end_of_text, |(next, _, _)| *next);
        found.push((*index, index + 1..end.max(index + 1)));
    }
    found
}

/// The answer lines of a body: `Answered:` under a questions heading, outside
/// code, each named by the question it answers -- the nearest heading above it
/// inside the section, or its line number where the section has none.
///
/// Which lines are code is the parser's answer, so a three-backtick example
/// inside a four-backtick block stays inside it.
fn answers(text: &str) -> Vec<Answer<'_>> {
    let code = crate::markdown::code_lines(text);
    let headings = crate::markdown::headings(text);
    let lines: Vec<&str> = text.lines().collect();
    let mut found = Vec::new();
    let sections = question_sections(text)
        .into_iter()
        .map(|(_, range)| range)
        .chain(decision_sections(text).into_iter().map(|(_, range)| range));
    for range in sections {
        for index in range.clone() {
            if code.get(index).copied().unwrap_or(false) {
                continue;
            }
            let Some(line) = lines.get(index).copied() else {
                continue;
            };
            if !list_item(line.trim_start()).starts_with("Answered:") {
                continue;
            }
            let question = headings
                .iter()
                .filter_map(|(number, _, title)| {
                    let at = usize::try_from(*number).ok()?.checked_sub(1)?;
                    (range.contains(&at) && at < index).then_some(title)
                })
                .next_back()
                .map_or_else(
                    || format!("line {}", index + 1),
                    |title| format!("{title:?}"),
                );
            found.push(Answer { question, line });
        }
    }
    found
}

/// A line with one list marker taken off its front, if it opens with one.
pub(crate) fn list_item(line: &str) -> &str {
    if let Some(rest) = ["- ", "* ", "+ "]
        .into_iter()
        .find_map(|marker| line.strip_prefix(marker))
    {
        return rest.trim_start();
    }
    let digits = line.chars().take_while(char::is_ascii_digit).count();
    if digits > 0
        && let Some(rest) = line
            .get(digits..)
            .and_then(|rest| rest.strip_prefix(". ").or_else(|| rest.strip_prefix(") ")))
    {
        return rest.trim_start();
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "https://github.com/HackingGate/uphold/blob/HEAD/principles/fail-fast.toml";

    fn citation(line: &str) -> Citation<'_> {
        cited(line).into_iter().next().expect("one citation")
    }

    #[test]
    fn only_answer_lines_under_a_questions_heading_are_read() {
        let body = "\
## Decision

Answered: not under questions

## Questions for the ruling

1. **Edit without a label.** (a) or (b)?
   Answered: (a)

### A sub-heading stays under it

- Answered: (b)

```text
Answered: inside a fence
```

## Done when

Answered: after the section

## Questions

### Question one

### Wording

Answered: (c)

````markdown
```
```
Answered: inside a longer fence
````
";
        assert_eq!(
            answers(body)
                .into_iter()
                .map(|answer| answer.line.trim())
                .collect::<Vec<_>>(),
            ["Answered: (a)", "- Answered: (b)", "Answered: (c)"]
        );
    }

    #[test]
    fn a_madr_record_is_one_decision_from_its_options_through_its_outcome() {
        let body = "## Context and Problem Statement\n\nAnswered: not here\n\n\
                    ## Considered Options\n\nStandard: none -- x\n\n- (a) one\n- (b) two\n\n\
                    ## Decision Outcome\n\nAnswered: (a)\n\n### Consequences\n\n- Good\n\n\
                    ### Confirmation\n\n- [ ] a test\n\n## More Information\n\nAnswered: after\n";
        let spans = decision_sections(body);
        assert_eq!(spans.len(), 1);
        let named: Vec<(String, &str)> = answers(body)
            .into_iter()
            .map(|answer| (answer.question, answer.line))
            .collect();
        assert_eq!(
            named,
            [(String::from("\"Decision Outcome\""), "Answered: (a)")]
        );
    }

    #[test]
    fn options_with_no_outcome_after_them_end_at_the_next_section() {
        let body = "## Considered Options\n\n- (a)\n\n## More Information\n\nAnswered: x\n";
        assert_eq!(decision_sections(body), [(0, 1..4)]);
        assert!(answers(body).is_empty());
    }

    #[test]
    fn an_answer_is_named_by_the_heading_of_its_question() {
        let body = "## Questions\n\n### Q1. What identifies an item?\n\n- (a) x\n\nAnswered: (a)\n\n\
                    ## Questions for the ruling\n\n1. Which?\n   Answered: (b)\n";
        let named: Vec<String> = answers(body)
            .into_iter()
            .map(|answer| answer.question)
            .collect();
        assert_eq!(named, ["\"Q1. What identifies an item?\"", "line 12"]);
    }

    #[test]
    fn each_citation_takes_the_quote_after_it_and_before_the_next() {
        let line = format!(
            "Answered: (a). [x]({LINK}) \"one\" and principles/least-power.toml#L3 \"two\""
        );
        let found = cited(&line);
        assert_eq!(found.len(), 2);
        assert_eq!(found.first().and_then(|c| c.rev), Some(NO_REVISION));
        assert_eq!(found.first().and_then(|c| c.quote), Some("one"));
        assert_eq!(found.get(1).and_then(|c| c.rev), None);
        assert_eq!(found.get(1).map(|c| c.id), Some("least-power"));
        assert_eq!(found.get(1).map(|c| c.suffix), Some("#L3"));
        assert_eq!(found.get(1).and_then(|c| c.quote), Some("two"));
    }

    #[test]
    fn a_file_named_in_prose_is_not_a_citation_and_a_relative_link_is() {
        assert!(cited("Answered: (a); the change is to principles/fail-fast.toml").is_empty());
        let relative = citation("Answered: (a). [x](../principles/fail-fast.toml) \"y\"");
        assert_eq!(relative.rev, None);
        assert_eq!(relative.link, "../principles/fail-fast.toml");
    }

    #[test]
    fn a_file_named_in_prose_does_not_end_the_quote_window() {
        let line = format!("Answered: (a). [x]({LINK}), see principles/least-power.toml, \"one\"");
        let found = cited(&line);
        assert_eq!(found.len(), 1);
        assert_eq!(found.first().and_then(|c| c.quote), Some("one"));
    }

    #[test]
    fn a_link_with_anything_after_the_file_name_is_refused() {
        for (link, says) in [
            (format!("{LINK}.bak"), "after the record's file name"),
            (format!("{LINK}?plain=1"), "after the record's file name"),
            (format!("{LINK}?plain=1#L8"), "after the record's file name"),
        ] {
            let line = format!("Answered: (a). [x]({link}) \"Stop early.\"");
            let failure =
                judge(&citation(&line), Some("claim = \"Stop early.\"\n"), "v1").expect("refused");
            assert!(failure.contains(says), "{link}: {failure}");
        }
    }

    #[test]
    fn requirement_ids_after_the_last_quote_are_not_citations() {
        let line = format!(
            "Answered: (b). [x]({LINK}) \"one\"; specification: changes `req~ruled-decision~1`, \
             removes `req~old~2`; precedent: none"
        );
        let found = cited(&line);
        assert_eq!(found.len(), 1);
        assert_eq!(found.first().and_then(|c| c.quote), Some("one"));
    }

    #[test]
    fn a_link_to_another_repository_names_no_revision() {
        let found =
            citation("https://github.com/someone/else/blob/HEAD/principles/fail-fast.toml \"x\"");
        assert_eq!(found.rev, None);
        assert!(
            judge(&found, Some("claim = \"x\"\n"), "v1.0.0")
                .is_some_and(|failure| failure.contains("not a link to"))
        );
    }

    /// A record at two revisions, the second with lines added above the
    /// cited item: a citation by quote resolves at both, unedited.
    #[test]
    fn a_cited_item_that_only_moved_still_resolves() {
        let before =
            "id = \"fail-fast\"\nclaim = \"Stop early.\"\napplies_when = [\"A check fails.\"]\n";
        let after = "id = \"fail-fast\"\ntitle = \"Fail Fast\"\nsummary = \"New.\"\n\
                     claim = \"Stop early.\"\napplies_when = [\"Another case.\", \"A check fails.\"]\n";
        let line = format!("Answered: (a). [fail-fast applies_when]({LINK}) \"A check fails.\"");
        let found = citation(&line);
        assert_eq!(judge(&found, Some(before), "v1.0.0"), None);
        assert_eq!(judge(&found, Some(after), "v1.1.0"), None);
    }

    /// The quoted item's text changed between revisions: refused, and told
    /// to re-rule.
    #[test]
    fn a_cited_item_whose_text_changed_is_refused_for_a_re_ruling() {
        let after = "id = \"fail-fast\"\napplies_when = [\"A check fails loudly.\"]\n";
        let line = format!("Answered: (a). [x]({LINK}) \"A check fails.\"");
        let failure = judge(&citation(&line), Some(after), "v1.1.0").expect("refused");
        assert!(failure.contains("re-rule this question"), "{failure}");
    }

    #[test]
    fn items_are_read_as_parsed_strings_at_any_depth() {
        let source = "claim = \"One.\"\napplies_when = [\"Two \\\"quoted\\\".\"]\n\
                      [[sources]]\nlocator = \"§4.2.4\"\n";
        let mut found = items(source);
        found.sort();
        assert_eq!(found, ["One.", "Two \"quoted\".", "§4.2.4"]);
    }

    #[test]
    fn a_link_that_names_a_revision_or_a_line_is_refused_as_a_copy_of_the_pin() {
        for link in [
            "https://github.com/HackingGate/uphold/blob/v1.56.0/principles/fail-fast.toml#L8",
            "https://github.com/HackingGate/uphold/blob/v1.56.0/principles/fail-fast.toml",
            "https://github.com/HackingGate/uphold/blob/HEAD/principles/fail-fast.toml#L8",
        ] {
            let line = format!("Answered: (a). [x]({link}) \"Stop early.\"");
            let failure = judge(
                &citation(&line),
                Some("claim = \"Stop early.\"\n"),
                "v1.56.0",
            )
            .expect("refused");
            assert!(failure.contains("a copy of the pin"), "{link}: {failure}");
        }
    }

    /// The answer form the design-ruling skill writes is the one this rule
    /// resolves.
    #[test]
    fn the_skill_writes_the_citation_form_this_rule_reads() {
        let skill = include_str!("../../skills/design-ruling/SKILL.md");
        let template = skill
            .lines()
            .find(|line| line.starts_with("Answered: (a). ["))
            .expect("the skill's answer template");
        let line = template
            .replace("<id>", "fail-fast")
            .replace("<field>", "claim")
            .replace("<the item, exactly as the record says it>", "Stop early.");
        let found = cited(&line);
        assert_eq!(found.len(), 1, "{line}");
        assert_eq!(
            found
                .first()
                .and_then(|c| judge(c, Some("claim = \"Stop early.\"\n"), "v1")),
            None,
            "{line}"
        );
    }
}
