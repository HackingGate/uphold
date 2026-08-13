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
use crate::selection::{normalize_rel, not_text_paths};

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

/// What a blob's bytes turned out to be.
///
/// Three answers rather than two, because "there is no text here" and "the text
/// here could not be read" are the difference between a skip and a refusal. A
/// binary file has no lines for a codepoint to hide in and is skipped on
/// purpose; a file that is text except for one byte is the most literal
/// could-not-look there is, and treating it as a skip buys the whole file a
/// pass on the strength of the very byte that should have stopped it.
#[derive(Debug)]
enum Decoded {
    Text(String),
    Binary,
    Unreadable(String),
}

/// A blob's text, or the reason there is none.
///
/// The byte-order mark is consulted first because a UTF-16 file is full of NUL
/// bytes: read as UTF-8 it fails, and the NUL test below would then dismiss a
/// perfectly ordinary text file as an image, taking its content out of the scan
/// while looking exactly like a skipped binary.
///
/// A UTF-8 mark is deliberately NOT consumed there. It decodes as U+FEFF, which
/// this guard already refuses by name, and stripping it would quietly grant an
/// exemption to the one invisible codepoint that turns up in committed files
/// most often.
fn decode_for_scan(bytes: &[u8]) -> Decoded {
    if let Some((encoding, _)) = encoding_rs::Encoding::for_bom(bytes) {
        if encoding != encoding_rs::UTF_8 {
            let (text, _, had_errors) = encoding.decode(bytes);
            if had_errors {
                return Decoded::Unreadable(format!(
                    "declares a {} byte-order mark and does not decode as one",
                    encoding.name()
                ));
            }
            return Decoded::Text(text.into_owned());
        }
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => Decoded::Text(text.to_owned()),
        // git's own test for a binary file, and the reason it is applied to the
        // BYTES rather than to git's verdict: a `diff` or `text` attribute is a
        // claim about how to render a change, and whether there is readable
        // text in here is a question about the object.
        Err(_) if bytes.contains(&0) => Decoded::Binary,
        Err(_) => Decoded::Unreadable(String::from("not valid UTF-8, and not binary either")),
    }
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
    // The same declaration `uphold scan` reads, from the same place, because a
    // file the repository declares is not text is one file with one answer and
    // not two. It said so at the tree seam and refused at this one: a captured
    // page kept byte-for-byte in the encoding its venue served -- the use
    // `not_text_paths` names -- was skipped by the scan and made every commit
    // touching it exit 2 here, and `.gitattributes` is one of the three cures
    // the reference names for exactly that.
    //
    // The NUL test below keeps its job, which is a different one: it is the
    // guess about bytes NOBODY declared. A declaration is not a guess, and
    // where there is one it answers first. A `.gitattributes` that could not be
    // read leaves the list empty and the reason set, and then the refusal
    // stands with that reason attached -- an unanswered question is not a
    // declaration that a file is fine to skip.
    let (not_text, unmeasured) = not_text_paths(request.root);
    let declared_not_text: BTreeSet<&str> =
        not_text.iter().map(|path| normalize_rel(path)).collect();
    let mut skipped: Vec<&str> = Vec::new();
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
        // THE NAME, before anything is opened and whatever the content turns
        // out to be. A filename is committed text: it is read by reviewers, by
        // importers and by build rules, and a zero-width space in one is the
        // same attack in the one place nobody thinks to look. It is also the
        // only thing a gitlink has here -- the submodule's content is its own
        // repository's business, and its guards run there.
        findings.extend(scan_name(&blob.path, &allowances));
        if !blob.has_content() {
            continue;
        }
        // After the name and before the bytes. The name is committed text
        // whatever the content is declared to be.
        if let Some(path) = declared_not_text.get(normalize_rel(&blob.path)) {
            skipped.push(path);
            continue;
        }
        let bytes = scope::read(request.root, blob)?;
        match decode_for_scan(&bytes) {
            Decoded::Text(text) => {
                looked += 1;
                findings.extend(scan(&text, &blob.path, &allowances));
            }
            // No lines for a character to hide in. The one skip this guard
            // makes, and it is made on the bytes.
            Decoded::Binary => {}
            // Silently skipped before this, which is a file nobody read
            // reported as a file with nothing in it -- `explicit-unknown` by
            // name, in the guard that reports it about everyone else.
            Decoded::Unreadable(why) => {
                let unknown = unmeasured.as_deref().unwrap_or(
                    "Declare it not text in .gitattributes, declare its charset with an \
                     `encoding` rule, or exclude it from this rule.",
                );
                return Err(Fatal::new(format!(
                    "{}: cannot be read as text ({why}); refusing to report it clean \
                     over content that was never examined. {unknown}",
                    blob.path
                )));
            }
        }
    }

    // Said on the way past, refusal or not, for the reason `not_text_paths`
    // gives about its own two answers: "we did not check these" and "these were
    // clean" must never look the same on the way out.
    if !skipped.is_empty() {
        eprintln!(
            "{}: {} path(s) skipped, declared not text in .gitattributes:\n{}",
            request.rule.id,
            skipped.len(),
            skipped.join("\n")
        );
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

/// The codepoints admitted at one path.
fn granted_at(path: &str, allowances: &[Allowance]) -> BTreeSet<char> {
    allowances
        .iter()
        .filter(|allowance| {
            allowance
                .under
                .as_ref()
                .is_none_or(|glob| glob.is_match(path))
        })
        .map(|allowance| allowance.codepoint)
        .collect()
}

/// The path itself, judged as the committed text it is.
///
/// Stricter than the content rule by exactly two characters, and they are the
/// two the content rule exempts: a tab and a newline are legal INSIDE a file
/// and are never legitimate in a path. Everything else this guard refuses is
/// refused here for the same reasons, under the same `allow` list -- a
/// codepoint admitted under a glob is admitted in the names that glob matches.
fn scan_name(path: &str, allowances: &[Allowance]) -> Vec<String> {
    let characters: Vec<char> = path.chars().collect();
    let granted = granted_at(path, allowances);
    let mut findings = Vec::new();
    for (index, &character) in characters.iter().enumerate() {
        if granted.contains(&character) {
            continue;
        }
        let base = index
            .checked_sub(1)
            .and_then(|previous| characters.get(previous).copied());
        let next = characters.get(index + 1).copied();
        let offending = character == '\t' || character == '\n' || refused(character, base, next);
        if !offending {
            continue;
        }
        findings.push(format!(
            "{path}:1:{}: U+{:04X} {} in the FILE NAME",
            index + 1,
            character as u32,
            unicode_names2::name(character)
                .map_or_else(|| String::from("UNKNOWN"), |name| name.to_string()),
        ));
    }
    findings
}

fn scan(text: &str, path: &str, allowances: &[Allowance]) -> Vec<String> {
    let characters: Vec<char> = text.chars().collect();
    let mut findings = Vec::new();
    let mut line = 1usize;
    let mut column = 1usize;
    let granted: BTreeSet<char> = granted_at(path, allowances);

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

    #[test]
    fn a_filename_is_committed_text_too() {
        // The half that did not survive the port. A zero-width space in a path
        // is read by reviewers, importers and build rules, and nothing here
        // looked at a path at all -- so the one place a reader cannot see the
        // character was the one place the guard did not check.
        let found = scan_name("docs/re\u{200B}adme.md", &[]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("U+200B"), "{found:?}");
        assert!(found[0].contains("FILE NAME"), "{found:?}");
        assert!(scan_name("docs/readme.md", &[]).is_empty());
    }

    #[test]
    fn a_tab_is_legal_in_a_file_and_never_in_a_path() {
        // The two characters the content rule exempts, which is why the path
        // cannot simply be handed to `scan`.
        assert!(findings("a\tb\n").is_empty());
        assert_eq!(scan_name("a\tb", &[]).len(), 1);
        assert_eq!(scan_name("a\nb", &[]).len(), 1);
    }

    #[test]
    fn an_allowance_scoped_to_a_path_reaches_that_paths_name() {
        let allowances = vec![parse_allowance("U+00A0:docs/**").unwrap()];
        assert!(scan_name("docs/a\u{00A0}b.md", &allowances).is_empty());
        assert_eq!(scan_name("src/a\u{00A0}b.rs", &allowances).len(), 1);
    }

    #[test]
    fn a_blob_that_is_not_text_is_told_apart_from_one_that_is_binary() {
        // The direction that matters: an undecodable blob is `Unreadable` and
        // not a skip, because a file nobody read is not a file with nothing in
        // it. Binary is the one honest skip -- there are no lines in it for a
        // codepoint to hide in.
        assert!(matches!(decode_for_scan(b"plain\n"), Decoded::Text(_)));
        assert!(matches!(
            decode_for_scan(&[0x89, b'P', b'N', b'G', 0x00, 0x1A]),
            Decoded::Binary
        ));
        assert!(matches!(
            decode_for_scan(b"caf\xe9 latin1\n"),
            Decoded::Unreadable(_)
        ));
    }

    #[test]
    fn a_utf16_file_is_read_rather_than_dismissed_as_binary() {
        // It is full of NUL bytes, so the binary test alone takes an ordinary
        // text file out of the scan while looking exactly like a skipped image.
        let mut bytes = vec![0xFF, 0xFE];
        for unit in "a\u{200B}b".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let Decoded::Text(text) = decode_for_scan(&bytes) else {
            unreachable!("a UTF-16 file with a byte-order mark is text");
        };
        assert_eq!(scan(&text, "a.txt", &[]).len(), 1);
    }
}
