//! The search itself, on ripgrep's own libraries.
//!
//! Embedding `grep-regex` and `grep-searcher` rather than reimplementing the
//! search is the whole reason the port is safe to make. Every pattern in every
//! consuming repository was written against ripgrep's dialect -- POSIX classes,
//! inline `(?i)`, `--multiline --multiline-dotall`, `--word-regexp` -- and a
//! second engine that agreed with it in every case anyone tested would disagree
//! somewhere nobody did.

use grep_regex::RegexMatcherBuilder;
use grep_searcher::sinks::Lossy;
use grep_searcher::{BinaryDetection, SearcherBuilder};
use regex::Regex;

use crate::error::{Fatal, Result};

/// Compile a pattern that is written into this binary.
///
/// Distinct from a pattern that arrives from a policy file, which is a user's
/// input and gets a `Result`. This one is a literal three lines up from the
/// call: it either compiles for every run or for none of them, so the failure
/// belongs to the build and not to the caller.
///
/// One function, so the reasoning is written once rather than implied by an
/// `unwrap()` at each of the sites that needs it.
#[expect(
    clippy::unwrap_used,
    reason = "the pattern is a literal in this crate, so a failure is a bug any test of the rule catches"
)]
pub(crate) fn literal_pattern(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap()
}

/// One match, located.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hit {
    pub path: String,
    pub line: Option<u64>,
    pub text: String,
}

/// What to look for, and how ripgrep should be told to look for it.
#[derive(Debug, Clone, Default)]
pub(crate) struct Query {
    pub pattern: String,
    /// Match the pattern literally. Set for every needle a dynamic source
    /// produces, because a hostname or a home path is text, not a regex, and
    /// `.` inside one would otherwise match anything.
    pub fixed_strings: bool,
    /// Whole words only. Exists for needles short enough to sit inside
    /// unrelated words -- the hostname segment `arc` is a substring of
    /// `search`, so a plain literal search for it fires on ordinary prose.
    /// Needles that are MEANT to be found inside a larger token leave this
    /// off: a separator-less MAC has to keep matching inside an interface name
    /// like `wlx7c3d095094a9`, which is the spelling it leaks in.
    pub word: bool,
    /// Match across line boundaries, with `.` covering newlines.
    pub multiline: bool,
}

impl Query {
    pub(crate) fn literal(value: &str, word: bool) -> Self {
        Self {
            pattern: value.to_owned(),
            fixed_strings: true,
            word,
            multiline: false,
        }
    }

    pub(crate) fn regex(pattern: &str, multiline: bool) -> Self {
        Self {
            pattern: pattern.to_owned(),
            fixed_strings: false,
            word: false,
            multiline,
        }
    }

    /// The query one rule's `[rule.files]` describes.
    ///
    /// `fixed_strings` and `word` were fields any rule could set and almost
    /// nothing read. The pattern path built `Query::regex`, which hardcodes
    /// both to false, so `regexp` beside `fixed_strings = true` searched a
    /// REGEX anyway -- `$HOME/secrets` read its `$` as an anchor and matched
    /// nothing, silently, which is the shape of a rule that looks enforced and
    /// is not. `require_regexp` honoured `fixed_strings` and dropped `word`, so
    /// `LICENSE` with `word = true` was satisfied by `LICENSEE`.
    ///
    /// Three call sites had three answers. One constructor now, so the
    /// difference between them can only be the fields the author wrote.
    pub(crate) fn from_files(pattern: &str, files: &crate::config::Files) -> Self {
        if files.fixed_strings.unwrap_or(false) {
            // `multiline` is a regex property. A literal search does not cross
            // lines and never did, so it is not silently accepted here either.
            Self::literal(pattern, files.word)
        } else {
            Self {
                word: files.word,
                ..Self::regex(pattern, files.multiline)
            }
        }
    }

    fn matcher(&self, label: &str) -> Result<grep_regex::RegexMatcher> {
        let pattern = if self.fixed_strings {
            regex::escape(&self.pattern)
        } else {
            self.pattern.clone()
        };
        let mut builder = RegexMatcherBuilder::new();
        builder.word(self.word);
        if self.multiline {
            builder.multi_line(true).dot_matches_new_line(true);
        }
        builder
            .build(&pattern)
            .map_err(|error| Fatal::new(format!("{label}: {error}")))
    }

    fn searcher(&self) -> grep_searcher::Searcher {
        let mut builder = SearcherBuilder::new();
        builder
            .line_number(true)
            .multi_line(self.multiline)
            // Everything reaching this searcher is `&str` now, so neither of
            // these can lose a byte: the decision about bytes that are not
            // UTF-8 was made before the text got here, by the one reader that
            // knows what the policy declares about the file's charset. They are
            // written anyway because a searcher that stopped at a NUL would
            // silently truncate a text a caller had already decoded, and a
            // default is not a decision.
            .binary_detection(BinaryDetection::none());
        builder.build()
    }
}

/// Search one file's DECODED text, attributed to its path.
///
/// The path is a label here and nothing else: this function does not open it.
/// It used to, through `search_path`, which handed ripgrep the raw bytes with
/// `BinaryDetection::none()` and a lossy sink -- so a UTF-16 file was searched
/// as a run of replacement characters and reported as read and clean, while
/// `allowed_scripts` refused the very same file in the very same run for being
/// unreadable. One of those two was wrong and it was not the one that stopped.
/// Deciding what a file's bytes say is now done once, in `scan`, where the
/// `encoding` declarations are; the engine is handed text.
pub(crate) fn search_in(path: &str, text: &str, query: &Query, label: &str) -> Result<Vec<Hit>> {
    Ok(search_text(text, query, label)?
        .into_iter()
        .map(|hit| Hit {
            path: path.to_owned(),
            ..hit
        })
        .collect())
}

/// Whether one text matches at all. The must-find kinds need no more than this.
pub(crate) fn text_matches(text: &str, query: &Query, label: &str) -> Result<bool> {
    let matcher = query.matcher(label)?;
    let mut searcher = query.searcher();
    let mut hit_found = false;
    let outcome = searcher.search_slice(
        &matcher,
        text.as_bytes(),
        Lossy(|_, _| {
            hit_found = true;
            // Stop at the first hit: the question is whether the pattern is
            // there, and counting the rest costs a full read of every file that
            // already answered it.
            Ok(false)
        }),
    );
    if let Err(error) = outcome {
        return Err(Fatal::new(format!("{label}: {error}")));
    }
    Ok(hit_found)
}

/// Search text that never becomes a file: a commit message, a release note, a
/// pull-request body. Same engine and same flags as the file path, so the two
/// cannot disagree about what counts as a match.
pub(crate) fn search_text(text: &str, query: &Query, label: &str) -> Result<Vec<Hit>> {
    let matcher = query.matcher(label)?;
    let mut searcher = query.searcher();
    let mut hits = Vec::new();
    let outcome = searcher.search_slice(
        &matcher,
        text.as_bytes(),
        Lossy(|line_number, line| {
            hits.push(Hit {
                path: String::from("-"),
                line: Some(line_number),
                text: line.trim_end_matches('\n').to_owned(),
            });
            Ok(true)
        }),
    );
    if let Err(error) = outcome {
        return Err(Fatal::new(format!("{label}: {error}")));
    }
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_literal_needle_is_not_read_as_a_regex() {
        let hits = search_text("a.c\nabc\n", &Query::literal("a.c", false), "t").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].text, "a.c");
    }

    /// `fixed_strings` and `word` reach a `regexp` rule.
    ///
    /// Both were accepted on every rule and read by almost none: the pattern
    /// path built `Query::regex`, which hardcodes them off. `$HOME/secrets`
    /// with `fixed_strings = true` was searched as a regex, so its `$` anchored
    /// and it matched nothing -- a rule that looked enforced and was not.
    #[test]
    fn the_files_table_decides_literal_and_word_for_a_pattern_rule() {
        let files = crate::config::Files {
            fixed_strings: Some(true),
            ..Default::default()
        };
        let query = Query::from_files("$HOME/secrets", &files);
        let hits = search_text("literally $HOME/secrets here\n", &query, "t").unwrap();
        assert_eq!(hits.len(), 1, "{hits:?}");

        // The same pattern without it is a regex, where `$` is an anchor.
        let plain = Query::from_files("$HOME/secrets", &crate::config::Files::default());
        assert!(search_text("literally $HOME/secrets here\n", &plain, "t")
            .unwrap()
            .is_empty());
    }

    /// `word` survives the literal branch too, which `require_regexp` dropped.
    #[test]
    fn a_word_bounded_literal_does_not_match_inside_a_longer_word() {
        let files = crate::config::Files {
            fixed_strings: Some(true),
            word: true,
            ..Default::default()
        };
        let query = Query::from_files("LICENSE", &files);
        assert!(search_text("LICENSEE\n", &query, "t").unwrap().is_empty());
        assert_eq!(search_text("LICENSE\n", &query, "t").unwrap().len(), 1);
    }

    #[test]
    fn word_matching_keeps_a_short_needle_out_of_a_longer_word() {
        let query = Query::literal("arc", true);
        assert!(search_text("search\n", &query, "t").unwrap().is_empty());
        assert_eq!(search_text("arc\n", &query, "t").unwrap().len(), 1);
    }

    #[test]
    fn a_needle_that_must_match_inside_a_token_leaves_word_off() {
        let query = Query::literal("7c3d095094a9", false);
        assert_eq!(
            search_text("wlx7c3d095094a9\n", &query, "t").unwrap().len(),
            1
        );
    }

    #[test]
    fn multiline_spans_a_conflict_block() {
        let text = "<<<<<<< HEAD\nmine\n=======\ntheirs\n>>>>>>> other\n";
        let pattern = r"^<{7} [\s\S]*?^={7}$[\s\S]*?^>{7} ";
        assert_eq!(
            search_text(text, &Query::regex(pattern, true), "t")
                .unwrap()
                .len(),
            1
        );
        assert!(search_text(text, &Query::regex(pattern, false), "t")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn posix_classes_and_inline_flags_survive_the_port() {
        let query = Query::regex(r"(?i)^Sta[t]us:[[:space:]]*[[:alnum:]_-]+", false);
        assert_eq!(
            search_text("status:  draft\n", &query, "t").unwrap().len(),
            1
        );
    }
}
