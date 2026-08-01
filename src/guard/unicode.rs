//! Characters in committed file content that draw nothing.
//!
//! A message gets a whitelist and a file gets an invisible-character ban, and
//! the asymmetry is the whole design: real repositories commit CJK punctuation,
//! box drawing and emoji that are DATA. What no repository needs is a codepoint
//! that occupies a position and renders as nothing, because the only thing such
//! a character can do to a reader is hide.
//!
//! Refused:
//!
//! * `Cc` control characters other than tab and newline, including a carriage
//!   return, which is a line ending somebody's editor chose and not content.
//! * `Cf` format characters: zero-width space and joiner, the bidirectional
//!   overrides, the ones that reorder a line without changing its bytes.
//! * `Co` private use -- a Nerd Font glyph pasted out of a prompt, which renders
//!   as a box for everyone who does not have that font.
//! * `Zs` other than U+0020, `Zl` and `Zp`: a non-breaking space in a shell
//!   script is a space that is not a space.
//! * `Default_Ignorable_Code_Point`, Unicode's own name for a codepoint a
//!   renderer is told to draw as nothing.
//! * The invisible letters and marks that sit outside all of the above:
//!   U+3164 HANGUL FILLER is an `Lo`, U+034F COMBINING GRAPHEME JOINER is an
//!   `Mn`, and both draw nothing.
//! * U+2800 BRAILLE PATTERN BLANK, named on its own because it is a graphic
//!   character whose glyph is empty.
//!
//! A variation selector is allowed only where it is doing the job it exists
//! for -- choosing how a REAL character is drawn, where the reader sees that
//! choice.

use std::collections::BTreeSet;

use globset::{Glob, GlobMatcher};

use super::scope;
use super::{Refusal, Request};
use crate::error::{Fatal, Result};

/// A codepoint admitted, optionally only under one path glob.
struct Allowance {
    codepoint: char,
    under: Option<GlobMatcher>,
}

/// `U+00A0`, or `U+00A0:tests/fixtures/**`.
///
/// The glob half exists because an allowance repository-wide is a different
/// decision from an allowance for the one directory that holds captured
/// upstream markup, and only the second is usually meant.
fn parse_allowance(token: &str) -> Result<Allowance> {
    let (codepoint, glob) = match token.split_once(':') {
        Some((codepoint, glob)) => (codepoint.trim(), Some(glob.trim())),
        None => (token.trim(), None),
    };
    let hex = codepoint
        .strip_prefix("U+")
        .or_else(|| codepoint.strip_prefix("u+"))
        .ok_or_else(|| {
            Fatal::new(format!(
                "allow expects a codepoint like U+3000, got {token:?}"
            ))
        })?;
    let value = u32::from_str_radix(hex, 16).map_err(|_| {
        Fatal::new(format!(
            "allow: {codepoint:?} is not a hexadecimal codepoint"
        ))
    })?;
    let allowed = char::from_u32(value)
        .ok_or_else(|| Fatal::new(format!("allow: U+{value:04X} is not a character")))?;
    let under = match glob.filter(|glob| !glob.is_empty()) {
        Some(glob) => Some(
            Glob::new(glob)
                .map_err(|error| Fatal::new(format!("allow: glob {glob:?}: {error}")))?
                .compile_matcher(),
        ),
        None => None,
    };
    Ok(Allowance {
        codepoint: allowed,
        under,
    })
}

/// Whether a character renders as nothing.
///
/// Shared with the commit-message guard, which bans everything this bans and
/// more besides.
pub(crate) fn is_invisible(character: char) -> bool {
    const NAMED: &[char] = &[
        '\u{3164}', // HANGUL FILLER -- an invisible Lo
        '\u{115F}', // HANGUL CHOSEONG FILLER
        '\u{1160}', // HANGUL JUNGSEONG FILLER
        '\u{FFA0}', // HALFWIDTH HANGUL FILLER
        '\u{034F}', // COMBINING GRAPHEME JOINER -- an invisible Mn
        '\u{17B4}', // KHMER VOWEL INHERENT AQ
        '\u{17B5}', // KHMER VOWEL INHERENT AA
        '\u{2800}', // BRAILLE PATTERN BLANK -- a graphic character with no glyph
    ];
    if NAMED.contains(&character) {
        return true;
    }
    let value = character as u32;
    // Cf, the format characters. The ranges rather than a property lookup,
    // because these are the ones that matter and they are stable.
    matches!(
        value,
        0x00AD                  // SOFT HYPHEN
        | 0x061C                // ARABIC LETTER MARK
        | 0x180E                // MONGOLIAN VOWEL SEPARATOR
        | 0x200B..=0x200F       // zero width space .. right-to-left mark
        | 0x202A..=0x202E       // the bidirectional overrides
        | 0x2060..=0x2064       // word joiner .. invisible plus
        | 0x2066..=0x206F       // the isolates and the deprecated formats
        | 0xFEFF                // zero width no-break space
        | 0xFFF9..=0xFFFB       // interlinear annotation
        | 0x1D173..=0x1D17A     // musical formatting
        | 0xE0000..=0xE007F // the tag characters
    )
}

const fn is_private_use(character: char) -> bool {
    let value = character as u32;
    matches!(value, 0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x0010_0000..=0x0010_FFFD)
}

/// A variation selector, and what it is entitled to follow.
///
/// Each family selects a presentation for a real character, which is why it is
/// admitted at all: the reader sees the choice. Following something that has no
/// such presentation, it is an invisible codepoint with a licence.
fn selector_is_earned(selector: char, base: Option<char>) -> bool {
    let Some(base) = base else {
        return false;
    };
    match selector as u32 {
        // U+FE0E and U+FE0F choose between the text and the emoji presentation.
        // Below U+0080 the answer is no, with one exception: the keycap
        // sequence, which is three codepoints and is checked as a sequence
        // below rather than here.
        //
        // U+FE00..U+FE0D are the remaining standardized variation selectors,
        // which answer the same question about the same range.
        0xFE00..=0xFE0F => (base as u32) >= 0x80,
        // U+E0100..U+E01EF are the IDEOGRAPHIC variation selectors. They choose
        // between the shapes of a Han ideograph, so following anything else --
        // a digit, a letter -- they are a codepoint with no visible effect.
        0xE0100..=0xE01EF => is_unified_ideograph(base),
        // Mongolian's free variation selectors.
        0x180B..=0x180D | 0x180F => {
            unicode_script::UnicodeScript::script(&base) == unicode_script::Script::Mongolian
        }
        _ => false,
    }
}

const fn is_variation_selector(character: char) -> bool {
    matches!(
        character as u32,
        0xFE00..=0xFE0F | 0x180B..=0x180D | 0x180F | 0xE0100..=0xE01EF
    )
}

const fn is_unified_ideograph(character: char) -> bool {
    matches!(
        character as u32,
        0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0xF900..=0xFAFF
            | 0x20000..=0x2A6DF
            | 0x2A700..=0x2EBEF
            | 0x2F800..=0x2FA1F
            | 0x30000..=0x323AF
    )
}

/// Whether this position is the selector inside a keycap sequence.
///
/// `1<U+FE0F><U+20E3>` is the ASCII exception, and it is a licence only when the
/// U+20E3 is actually there: `port: 80<VS16>80` is not a keycap and must stay
/// refused. The sequence ENDS at the mark, which does not become a carrier in
/// its turn -- U+20E3 has no variation sequence of its own.
fn is_keycap(base: Option<char>, selector: char, next: Option<char>) -> bool {
    selector as u32 == 0xFE0F
        && next == Some('\u{20E3}')
        && base.is_some_and(|base| base.is_ascii_digit() || base == '#' || base == '*')
}

fn refused(character: char, base: Option<char>, next: Option<char>) -> bool {
    if character == '\t' || character == '\n' {
        return false;
    }
    if character == ' ' {
        return false;
    }
    if is_variation_selector(character) {
        return !(selector_is_earned(character, base) || is_keycap(base, character, next));
    }
    if character.is_control() {
        return true;
    }
    if is_invisible(character) || is_private_use(character) {
        return true;
    }
    // Zs other than U+0020, plus Zl and Zp.
    if character.is_whitespace() && character != ' ' {
        return true;
    }
    false
}

pub(crate) fn in_files(request: &Request<'_>) -> Result<Option<Refusal>> {
    let allowances: Vec<Allowance> = request
        .rule
        .allow()
        .iter()
        .map(|token| parse_allowance(token))
        .collect::<Result<Vec<Allowance>>>()?;

    let blobs = scope::blobs(
        request.root,
        request.stage,
        request.push_refs,
        request.push_source,
        request.remote_name,
    )?;
    let mut findings: Vec<String> = Vec::new();
    let mut looked = 0usize;

    for blob in &blobs {
        // `[rule.files]` is optional on a built-in and not refused when
        // written, so an `exclude` here used to parse and do nothing. `allow`
        // scopes a CODEPOINT to a path; this scopes the search itself, and both
        // were documented as available.
        if !scope::in_file_scope(request.rule, &blob.path)? {
            continue;
        }
        let bytes = scope::read(request.root, blob)?;
        // A blob that is not UTF-8 is not text somebody typed, and the
        // characters this guard is about cannot be identified in it.
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        looked += 1;
        findings.extend(scan(&text, &blob.path, &allowances));
    }

    if findings.is_empty() {
        return Ok(None);
    }
    Ok(Some(Refusal {
        id: request.rule.id.clone(),
        report: format!(
            "{}\n\n{looked} file(s) read. A character that draws nothing cannot be seen in \
             review. Delete it, or admit it in the rule's `allow` list -- \
             `\"U+00A0:docs/captured/**\"` admits one codepoint under one path.",
            findings.join("\n")
        ),
    }))
}

fn scan(text: &str, path: &str, allowances: &[Allowance]) -> Vec<String> {
    let characters: Vec<char> = text.chars().collect();
    let mut findings = Vec::new();
    let mut line = 1usize;
    let mut column = 1usize;
    let granted: BTreeSet<char> = allowances
        .iter()
        .filter(|allowance| {
            allowance
                .under
                .as_ref()
                .is_none_or(|glob| glob.is_match(path))
        })
        .map(|allowance| allowance.codepoint)
        .collect();

    for (index, &character) in characters.iter().enumerate() {
        if character == '\n' {
            line += 1;
            column = 1;
            continue;
        }
        let base = index
            .checked_sub(1)
            .and_then(|previous| characters.get(previous).copied());
        let next = characters.get(index + 1).copied();
        if refused(character, base, next) && !granted.contains(&character) {
            findings.push(format!(
                "{path}:{line}:{column}: U+{:04X} {}",
                character as u32,
                unicode_names2::name(character)
                    .map_or_else(|| String::from("UNKNOWN"), |name| name.to_string()),
            ));
        }
        column += 1;
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn findings(text: &str) -> Vec<String> {
        scan(text, "a.txt", &[])
    }

    #[test]
    fn a_zero_width_space_is_refused_and_located() {
        let found = findings("ab\u{200B}c\n");
        assert_eq!(found.len(), 1);
        assert!(found[0].starts_with("a.txt:1:3: U+200B"), "{found:?}");
    }

    #[test]
    fn ordinary_text_and_real_emoji_pass() {
        assert!(findings("hello\tworld\n日本語 ☕\n").is_empty());
    }

    #[test]
    fn a_variation_selector_after_an_emoji_is_earned() {
        assert!(findings("\u{26A0}\u{FE0F}\n").is_empty());
    }

    #[test]
    fn a_variation_selector_after_ascii_is_not() {
        // `port: 80<VS16>80` is the case: an invisible codepoint with no
        // presentation to select.
        assert_eq!(findings("80\u{FE0F}80\n").len(), 1);
    }

    #[test]
    fn a_keycap_sequence_is_the_one_ascii_exception() {
        assert!(findings("1\u{FE0F}\u{20E3}\n").is_empty());
    }

    #[test]
    fn an_ideographic_selector_needs_an_ideograph() {
        assert!(findings("\u{845B}\u{E0100}\n").is_empty());
        assert_eq!(findings("7\u{E0100}\n").len(), 1);
    }

    #[test]
    fn a_carriage_return_is_a_line_ending_and_not_content() {
        assert_eq!(findings("a\r\n").len(), 1);
    }

    #[test]
    fn a_non_breaking_space_is_a_space_that_is_not_a_space() {
        assert_eq!(findings("a\u{00A0}b\n").len(), 1);
    }

    #[test]
    fn an_allowance_may_be_scoped_to_a_path() {
        let allowances = vec![parse_allowance("U+00A0:docs/**").unwrap()];
        assert!(scan("a\u{00A0}b\n", "docs/page.md", &allowances).is_empty());
        assert_eq!(scan("a\u{00A0}b\n", "src/main.rs", &allowances).len(), 1);
    }

    #[test]
    fn an_allowance_grants_and_never_revokes() {
        // Adding an entry cannot tighten the guard on anybody else's file.
        let allowances = vec![parse_allowance("U+00A0").unwrap()];
        assert!(scan("a\u{00A0}b\n", "any.txt", &allowances).is_empty());
        assert_eq!(scan("a\u{200B}b\n", "any.txt", &allowances).len(), 1);
    }

    #[test]
    fn a_malformed_allowance_is_refused_with_its_own_message() {
        assert!(parse_allowance("00A0").is_err());
        assert!(parse_allowance("U+ZZZZ").is_err());
    }
}
