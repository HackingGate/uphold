//! Email-shaped text in pending arguments, before a web or shell tool runs.
//!
//! This is a conservative disclosure check, not a mailbox validator or a
//! network sandbox. It never reads account credentials and never quotes the
//! subject, even in evidence. Hidden headers and script contents are outside
//! the pre-call event and cannot be certified by inspecting it.

use regex::Regex;
use serde_json::Value;

use crate::error::{Fatal, Result};
use crate::guard::Refusal;
use crate::text::{Answer, Judgment, Verdict};

const ID: &str = "no-email-in-tool-arguments";
const REPORT: &str = "uphold refused: no-email-in-tool-arguments. Email-shaped text was found in the pending tool arguments, or URL encoding exceeded the inspection limit. The address and arguments are withheld. Remove personal information before retrying. No tool call was allowed by this hook.";

// RFC 5322 section 3.2.3's dot-atom characters, with letters and numbers
// extended for SMTPUTF8 (RFC 6531). Deliberately accepts more than a valid
// mailbox: malformed addresses can still identify a person. This does not
// attempt to reconstruct shell expressions.
const ADDRESS: &str = r#"(?:"[^"\r\n]+"|[\p{L}\p{N}.!#$%&'*+/=?^_`{|}~-]+)@[\p{L}\p{N}](?:[\p{L}\p{N}.-]*[\p{L}\p{N}])?"#;

fn sensitive(text: &str, address: &Regex) -> bool {
    let mut decoded = text.to_owned();
    // A fixed bound avoids quadratic work on adversarial nested encoding.
    // If another layer remains after it, refuse rather than clear unread text.
    for _ in 0..4 {
        if address.is_match(&decoded) {
            return true;
        }
        let next = percent_encoding::percent_decode_str(&decoded)
            .decode_utf8_lossy()
            .into_owned();
        if next == decoded {
            return false;
        }
        decoded = next;
    }
    address.is_match(&decoded)
        || percent_encoding::percent_decode_str(&decoded).decode_utf8_lossy() != decoded
}

fn contains_sensitive(subject: &Value, address: &Regex) -> bool {
    match subject {
        Value::String(text) => sensitive(text, address),
        Value::Array(values) => values
            .iter()
            .any(|value| contains_sensitive(value, address)),
        Value::Object(values) => values
            .iter()
            .any(|(key, value)| sensitive(key, address) || contains_sensitive(value, address)),
        _ => false,
    }
}

/// Judge every string and object key without retaining the matched content.
pub(super) fn judge(subject: Option<&Value>) -> Result<Judgment> {
    let address = Regex::new(ADDRESS)
        .map_err(|_| Fatal::new("privacy address pattern could not be compiled"))?;
    let refused = subject.is_some_and(|value| contains_sensitive(value, &address));
    Ok(Judgment {
        id: ID.to_owned(),
        builtin: None,
        set: None,
        subject: Some("tool arguments".to_owned()),
        answer: if refused {
            Answer::Refused(Verdict::Guard(Refusal {
                id: ID.to_owned(),
                report: REPORT.to_owned(),
            }))
        } else {
            Answer::Pass
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn international_and_quoted_addresses_are_refused() {
        let address = Regex::new(ADDRESS).unwrap();
        for text in [
            "person+tag@example.test",
            "\"person name\"@example.test",
            "\u{7528}\u{6237}@\u{4f8b}.test",
        ] {
            assert!(sensitive(text, &address), "{text}");
        }
    }

    #[test]
    fn nested_encoding_is_bounded_and_refused_instead_of_cleared() {
        let address = Regex::new(ADDRESS).unwrap();
        let mut text = "person%40example.test".to_owned();
        for _ in 0..12 {
            assert!(sensitive(&text, &address));
            text = text.replace('%', "%25");
        }
        assert!(!sensitive("https://example.test/a%20b%3Fc%3Dd", &address));
    }
}
