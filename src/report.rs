//! What a failing check prints.

use crate::engine::Hit;

/// Findings shown per rule when match content is redacted.
const MAX_FINDINGS_PER_RULE: usize = 20;

/// One failing finding.
#[derive(Debug, Clone)]
pub(crate) struct Failure {
    pub label: String,
    pub message: String,
    pub body: String,
}

impl Failure {
    pub(crate) fn new(
        label: impl Into<String>,
        message: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            label: label.into(),
            message: message.into(),
            body: body.into(),
        }
    }

    pub(crate) fn print(&self) {
        eprintln!("policy check failed: {}", self.label);
        eprintln!("{}", dedent(&self.message));
        eprintln!("{}", self.body.trim_end());
        eprintln!();
    }
}

/// Strip the common leading indentation a TOML multi-line string carries.
///
/// The indent is counted in CHARACTERS and never in bytes. It used to be a byte
/// count minimised over the non-blank lines while `trim_start` stripped Unicode
/// whitespace, so one line indented with a wide space -- U+3000 is three bytes
/// and one character -- put the minimum inside a character of another line, and
/// `&line[indent..]` panicked. That is exit 101 out of the function whose whole
/// job is printing a violation: the report the run exists to produce, replaced
/// by a crash, on text a policy author is free to write. Whitespace-only lines
/// were the second way in -- excluded from the minimum and sliced anyway.
fn dedent(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let indent = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.chars().count() - line.trim_start().chars().count())
        .min()
        .unwrap_or(0);
    lines
        .iter()
        .map(|line| {
            // Walking the characters and keeping what is left is what makes
            // this safe where the slice was not: the remainder always begins on
            // a character boundary, whatever the line is made of. A line with
            // fewer characters than the indent is whitespace-only by
            // construction -- every other line carries at least this much
            // leading whitespace -- so running the iterator out and keeping the
            // empty remainder is the right answer for it.
            let mut characters = line.chars();
            for _ in 0..indent {
                if characters.next().is_none() {
                    break;
                }
            }
            characters.as_str()
        })
        .collect::<Vec<&str>>()
        .join("\n")
        .trim()
        .to_owned()
}

/// `path:line: content` for every hit.
pub(crate) fn body(hits: &[Hit]) -> String {
    hits.iter()
        .map(|hit| {
            hit.line.map_or_else(
                || hit.path.clone(),
                |line| format!("{}:{}:{}", hit.path, line, hit.text),
            )
        })
        .collect::<Vec<String>>()
        .join("\n")
}

/// The same findings with the match content withheld.
///
/// For repositories whose tracked data is itself sensitive: the location of a
/// finding is what a reader acts on, and printing the matched bytes to a
/// terminal and a CI log is a second copy of the thing the rule caught.
pub(crate) fn redacted_body(hits: &[Hit]) -> String {
    let mut lines: Vec<String> = hits
        .iter()
        .take(MAX_FINDINGS_PER_RULE)
        .map(|hit| {
            hit.line.map_or_else(
                || format!("{}: [REDACTED_MATCH]", hit.path),
                |line| format!("{}:{}: [REDACTED_MATCH]", hit.path, line),
            )
        })
        .collect();
    if hits.len() > MAX_FINDINGS_PER_RULE {
        lines.push(format!(
            "... {} additional redacted matches omitted",
            hits.len() - MAX_FINDINGS_PER_RULE
        ));
    }
    lines.join("\n")
}

pub(crate) fn body_for(hits: &[Hit], redact: bool) -> String {
    if redact {
        redacted_body(hits)
    } else {
        body(hits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(path: &str, line: u64) -> Hit {
        Hit {
            path: path.to_owned(),
            line: Some(line),
            text: "secret".to_owned(),
        }
    }

    #[test]
    fn redaction_keeps_the_location_and_drops_the_match() {
        let body = redacted_body(&[hit("a.txt", 3)]);
        assert_eq!(body, "a.txt:3: [REDACTED_MATCH]");
        assert!(!body.contains("secret"));
    }

    /// The verified crash: a byte index into a character.
    ///
    /// U+3000 IDEOGRAPHIC SPACE is one character, three bytes, and stripped by
    /// `trim_start`, so the byte minimum taken from the ASCII line landed in
    /// the middle of it and the slice panicked. A message is policy-author
    /// text, so this is a message a rule may legitimately carry -- and the
    /// panic replaced the violation report with exit 101.
    #[test]
    fn a_wide_whitespace_indent_does_not_split_a_character() {
        assert_eq!(dedent("  ascii\n\u{3000}wide"), "ascii\nwide");
    }

    /// The second way in: a whitespace-only line is excluded from the minimum
    /// and was sliced by it anyway.
    #[test]
    fn a_whitespace_only_line_shorter_than_the_indent_survives() {
        assert_eq!(dedent("  ascii\n\u{3000}\n  more"), "ascii\n\nmore");
        assert_eq!(dedent("    first\n \n    second"), "first\n\nsecond");
    }

    #[test]
    fn a_long_redacted_report_says_how_much_it_withheld() {
        let hits: Vec<Hit> = (1..=25).map(|line| hit("a.txt", line)).collect();
        let body = redacted_body(&hits);
        assert!(
            body.ends_with("... 5 additional redacted matches omitted"),
            "{body}"
        );
    }
}
