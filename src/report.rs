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
fn dedent(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let indent = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.len() - line.trim_start().len())
        .min()
        .unwrap_or(0);
    lines
        .iter()
        .map(|line| {
            if line.len() >= indent {
                &line[indent..]
            } else {
                line
            }
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
