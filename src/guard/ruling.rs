//! `ruling-citations-resolve` -- does each catalog line an answer cites say
//! what the answer quotes, at the revision this repository pins?
//!
//! A design question is answered from the records a repository adopts, and
//! the answer cites each record by line, linked at the uphold revision the
//! repository pins, with a quote of the item it used:
//!
//! ```text
//! Answered: (a). [unix-composability L18](https://github.com/HackingGate/uphold/blob/v1.36.0/principles/unix-composability.toml#L18) "Can a script or an agent do everything a person at a terminal can"
//! ```
//!
//! Every part of that can be wrong without anything looking wrong: a link at
//! a revision the repository does not run, a record id that is not in the
//! catalog there, a line past the end of the file, or a quote that was on line
//! 18 two releases ago. A reader who follows the link finds out; this finds
//! out first.
//!
//! WHICH TEXT IS AN ANSWER. A line that opens `Answered:`, optionally as a list
//! item, under a heading whose title says "question", and outside a code
//! fence. The marker is the subject, so no forge is asked how the issue is
//! labelled and a body with no such line passes without a pin being read.
//!
//! WHICH CATALOG. The one compiled into this binary, which is the catalog of
//! exactly one tag, `v<version>`. A pin naming any other revision is a
//! catalog this binary cannot read, and that is exit 2 rather than a guess at
//! what the other revision holds: running the uphold the repository pins is
//! the answer, and the message says so.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;

use crate::config::Rule;
use crate::error::{Fatal, Result};
use crate::guard::Refusal;

/// A link into the catalog: any URL prefix, then `principles/<id>.toml#L<n>`.
/// The prefix is optional so that a relative or foreign link is found and
/// refused rather than passed over.
static CITATION: OnceLock<Regex> = OnceLock::new();

fn citation_pattern() -> &'static Regex {
    CITATION.get_or_init(|| {
        crate::engine::literal_pattern(
            r#"(?:https?://[^\s()<>\[\]"]*?/)?principles/([a-z0-9][a-z0-9-]*)\.toml#L([0-9]+)"#,
        )
    })
}

/// The prefix a citation must carry: this repository's blob view at one rev.
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

/// One citation, as an answer wrote it.
#[derive(Debug)]
struct Citation<'a> {
    link: &'a str,
    /// `None` where the link is not `github.com/<this repository>/blob/<rev>/`.
    rev: Option<&'a str>,
    id: &'a str,
    line: &'a str,
    quote: Option<&'a str>,
}

/// Judge one piece of published text. `None` where every citation resolves,
/// including where there is no answer or no citation at all.
pub(crate) fn in_text(
    root: &Path,
    rule: &Rule,
    label: &str,
    text: &str,
) -> Result<Option<Refusal>> {
    let citations: Vec<Citation<'_>> = answers(text).into_iter().flat_map(cited).collect();
    if citations.is_empty() {
        return Ok(None);
    }
    let pinned = pinned_revisions(root, &rule.id)?;
    let carried = format!("v{}", env!("CARGO_PKG_VERSION"));
    let mut failures = Vec::new();
    for citation in &citations {
        if let Some(failure) = judge(citation, &pinned, &carried, &rule.id)? {
            failures.push(format!("- {}: {failure}", citation.link));
        }
    }
    if failures.is_empty() {
        return Ok(None);
    }
    Ok(Some(Refusal {
        id: rule.id.clone(),
        report: format!(
            "{label}: {} citation(s) of the catalog do not resolve at the uphold revision \
             this repository pins ({}):\n{}\n\nLink each record line at the pinned revision \
             and quote the item as that line says it, so a reader who follows the link finds \
             what the answer used.",
            failures.len(),
            pinned.into_iter().collect::<Vec<_>>().join(", "),
            failures.join("\n")
        ),
    }))
}

/// What is wrong with one citation, or `None`. `Err` only where the catalog
/// at the pinned revision is not the one this binary carries.
fn judge(
    citation: &Citation<'_>,
    pinned: &BTreeSet<String>,
    carried: &str,
    rule: &str,
) -> Result<Option<String>> {
    let Some(rev) = citation.rev else {
        let (owner, name) = crate::check::upstream_slug().unwrap_or(("", ""));
        return Ok(Some(format!(
            "not a link to https://github.com/{owner}/{name}/blob/<rev>/, so it names no \
             revision of the catalog"
        )));
    };
    if !pinned.contains(rev) {
        return Ok(Some(format!(
            "cites the catalog at {rev}, and this repository pins {}",
            pinned.iter().cloned().collect::<Vec<_>>().join(", ")
        )));
    }
    if rev != carried {
        return Err(Fatal::new(format!(
            "rule {rule:?}: this repository pins uphold at {rev}, and this binary carries the \
             catalog of {carried}, so whether a citation resolves there cannot be read here. \
             Nothing was published; run the uphold the repository pins"
        )));
    }
    let Some(source) = crate::catalog::source(citation.id) else {
        return Ok(Some(format!(
            "{rev} has no record {:?} in its catalog",
            citation.id
        )));
    };
    let Some(cited) = citation
        .line
        .parse::<usize>()
        .ok()
        .and_then(|number| number.checked_sub(1))
        .and_then(|index| source.lines().nth(index))
    else {
        return Ok(Some(format!(
            "principles/{}.toml at {rev} has {} line(s), and the link is to line {}",
            citation.id,
            source.lines().count(),
            citation.line
        )));
    };
    let Some(quote) = citation.quote else {
        return Ok(Some(String::from(
            "carries no quote. Follow the link with the item it cites, in double quotes",
        )));
    };
    if !cited.contains(quote) {
        return Ok(Some(format!(
            "line {} of principles/{}.toml at {rev} does not say {quote:?}",
            citation.line, citation.id
        )));
    }
    Ok(None)
}

/// Every revision of this repository a hook configuration in the tree pins.
/// None is exit 2: a citation's revision can only be judged against one.
fn pinned_revisions(root: &Path, rule: &str) -> Result<BTreeSet<String>> {
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
             pins {owner}/{name}, so the revision a citation must be at cannot be read. \
             Nothing was published; pin uphold, or run this where it is pinned"
        )));
    }
    Ok(pinned)
}

/// The citations on one answer line, each with the first quote after it and
/// before the next citation.
fn cited(line: &str) -> Vec<Citation<'_>> {
    let found: Vec<regex::Captures<'_>> = citation_pattern().captures_iter(line).collect();
    let mut citations = Vec::new();
    for (index, captures) in found.iter().enumerate() {
        let (Some(whole), Some(id), Some(number)) =
            (captures.get(0), captures.get(1), captures.get(2))
        else {
            continue;
        };
        let end = found
            .get(index + 1)
            .and_then(|next| next.get(0))
            .map_or(line.len(), |next| next.start());
        let after = line.get(whole.end()..end).unwrap_or("");
        let quote = quote_pattern()
            .captures(after)
            .and_then(|quoted| quoted.get(1).or_else(|| quoted.get(2)))
            .map(|quoted| quoted.as_str());
        let prefix = line.get(whole.start()..id.start()).unwrap_or("");
        let prefix = prefix.strip_suffix("principles/").unwrap_or(prefix);
        let rev = blob_pattern().captures(prefix).and_then(|blob| {
            let (owner, name) = crate::check::upstream_slug()?;
            let same = blob.get(1)?.as_str().eq_ignore_ascii_case(owner)
                && blob.get(2)?.as_str().eq_ignore_ascii_case(name);
            same.then(|| blob.get(3).map(|rev| rev.as_str())).flatten()
        });
        citations.push(Citation {
            link: whole.as_str(),
            rev,
            id: id.as_str(),
            line: number.as_str(),
            quote,
        });
    }
    citations
}

/// The answer lines of a body: `Answered:` under a questions heading, outside
/// a code fence.
///
/// A heading below the questions heading's level stays inside its section
/// whatever it says. A fence closes on a run of its own character at least as
/// long as the one that opened it, with nothing after (`CommonMark` 0.31.2,
/// §4.5), so a three-backtick example inside a four-backtick block stays
/// inside it.
fn answers(text: &str) -> Vec<&str> {
    let mut under: Option<usize> = None;
    let mut fence: Option<(char, usize)> = None;
    let mut found = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let run = fence_run(trimmed);
        if let Some((character, length)) = fence {
            if run.is_some_and(|(closing, count, rest)| {
                closing == character && count >= length && rest.trim().is_empty()
            }) {
                fence = None;
            }
            continue;
        }
        if let Some((character, count, _)) = run {
            fence = Some((character, count));
            continue;
        }
        if let Some((level, title)) = heading(trimmed) {
            if under.is_some_and(|questions| level > questions) {
                continue;
            }
            under = title.to_lowercase().contains("question").then_some(level);
            continue;
        }
        if under.is_some() && list_item(trimmed).starts_with("Answered:") {
            found.push(line);
        }
    }
    found
}

/// A fence marker: three or more backticks or tildes, and what follows them.
fn fence_run(line: &str) -> Option<(char, usize, &str)> {
    let character = line
        .chars()
        .next()
        .filter(|first| ['`', '~'].contains(first))?;
    let count = line.chars().take_while(|&next| next == character).count();
    (count >= 3).then(|| (character, count, line.get(count..).unwrap_or("")))
}

/// An ATX heading's level and title.
fn heading(line: &str) -> Option<(usize, &str)> {
    let level = line
        .chars()
        .take_while(|&character| character == '#')
        .count();
    let rest = line.get(level..)?;
    ((1..=6).contains(&level) && (rest.is_empty() || rest.starts_with([' ', '\t'])))
        .then(|| (level, rest.trim()))
}

/// A line with one list marker taken off its front, if it opens with one.
fn list_item(line: &str) -> &str {
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
            answers(body).into_iter().map(str::trim).collect::<Vec<_>>(),
            ["Answered: (a)", "- Answered: (b)", "Answered: (c)"]
        );
    }

    #[test]
    fn each_citation_takes_the_quote_after_it_and_before_the_next() {
        let line = "Answered: (a). [x](https://github.com/HackingGate/uphold/blob/v1.0.0/principles/fail-fast.toml#L7) \"one\" and principles/least-power.toml#L3 \"two\"";
        let found = cited(line);
        assert_eq!(found.len(), 2);
        assert_eq!(
            found.first().and_then(|citation| citation.rev),
            Some("v1.0.0")
        );
        assert_eq!(
            found.first().and_then(|citation| citation.quote),
            Some("one")
        );
        assert_eq!(found.get(1).and_then(|citation| citation.rev), None);
        assert_eq!(
            found.get(1).map(|citation| citation.id),
            Some("least-power")
        );
        assert_eq!(
            found.get(1).and_then(|citation| citation.quote),
            Some("two")
        );
    }

    #[test]
    fn a_link_to_another_repository_names_no_revision() {
        let found =
            cited("https://github.com/someone/else/blob/v1.0.0/principles/fail-fast.toml#L7 \"x\"");
        assert_eq!(found.first().map(|citation| citation.rev), Some(None));
    }
}
