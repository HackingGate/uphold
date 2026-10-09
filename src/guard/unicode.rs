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
//! In a PATH, and only there, one more thing: a letter from another script
//! drawn like the letters of the word it sits in (UTS #39 mixed-script
//! confusable detection, through `unicode-security`). A path is what somebody
//! searches by substring; file content is prose and data in every script, and
//! is not asked.
//!
//! A variation selector is allowed only where it is doing the job it exists
//! for -- choosing how a REAL character is drawn, where the reader sees that
//! choice.

use std::collections::BTreeSet;

use globset::{Glob, GlobMatcher};
use unicode_script::{Script, UnicodeScript};
use unicode_security::MixedScript;

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
        Some((codepoint, glob)) => (codepoint, Some(glob.trim())),
        None => (token, None),
    };
    let allowed = parse_codepoint(codepoint)?;
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

/// `U+00A0`: the codepoint half of an allowance.
///
/// Shared with the message guard, whose `allow` is only ever this half: a
/// message has no path for a glob to select.
pub(crate) fn parse_codepoint(token: &str) -> Result<char> {
    let codepoint = token.trim();
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
    char::from_u32(value)
        .ok_or_else(|| Fatal::new(format!("allow: U+{value:04X} is not a character")))
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
        0x180B..=0x180D | 0x180F => base.script() == Script::Mongolian,
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

/// Whether a character, where it stands, draws nothing.
///
/// A control other than tab and newline, everything [`is_invisible`] names,
/// and a variation selector that is not choosing how the character before it
/// is drawn. The whole of what the message guard refuses on every surface, and
/// the part of [`refused`] that is about hiding rather than about a file's
/// hygiene: private use and the non-space spaces are visible, and a message is
/// not refused for them.
pub(crate) fn draws_nothing(character: char, base: Option<char>, next: Option<char>) -> bool {
    if character == '\t' || character == '\n' {
        return false;
    }
    if is_variation_selector(character) {
        return !(selector_is_earned(character, base) || is_keycap(base, character, next));
    }
    character.is_control() || is_invisible(character)
}

/// One letter inside a word that is drawn like a letter of the word's other
/// script: the Cyrillic `a` in a Latin word, which is a different word to a
/// substring search and the same word to a reader.
pub(crate) struct Lookalike {
    /// The character's position in the line, counted in characters from zero.
    pub(crate) column: usize,
    pub(crate) character: char,
    /// The script the character was taken from.
    pub(crate) from: Script,
    /// The script the rest of the word is written in.
    pub(crate) among: Script,
}

impl Lookalike {
    /// `U+0430 CYRILLIC SMALL LETTER A, a Cyrillic letter in a Latin word`.
    ///
    /// The NAME, because the glyph is the one thing that does not tell a reader
    /// anything: it looks exactly like the letter it replaced.
    pub(crate) fn describe(&self) -> String {
        format!(
            "U+{:04X} {}, a {} letter in a {} word",
            self.character as u32,
            unicode_names2::name(self.character)
                .map_or_else(|| String::from("UNKNOWN"), |name| name.to_string()),
            self.from.full_name(),
            self.among.full_name(),
        )
    }
}

/// The mixed-script confusables in one line, word by word.
///
/// UTS #39, sections 4 and 5, through `unicode-security`, which carries the
/// confusable table and the resolved script sets: a word is a maximal run of
/// letters and the marks on them, and a word is a finding only when it is not
/// single-script AND a letter from its minority script is drawn like the
/// majority's. So a Japanese word beside an English one is two single-script
/// words and passes, a kanji and kana word is single-script by the augmented
/// sets UTS #39 defines and passes, and `Rust` run into a kanji compound is
/// mixed and passes too, because no kanji is drawn like a Latin letter.
pub(crate) fn lookalikes(line: &str) -> Vec<Lookalike> {
    let mut found = Vec::new();
    let mut word: Vec<char> = Vec::new();
    let mut start = 0usize;
    // A trailing space closes the last word, so the loop has one exit.
    for (index, character) in line.chars().chain(std::iter::once(' ')).enumerate() {
        if in_a_word(character) {
            if word.is_empty() {
                start = index;
            }
            word.push(character);
        } else if !word.is_empty() {
            found.extend(lookalikes_in_word(&word, start));
            word.clear();
        }
    }
    found
}

/// A letter, or a mark riding on one. A combining accent is `Inherited` and
/// not alphabetic, and splitting a word at it would turn `e` + U+0301 into
/// two words that are each single-script.
fn in_a_word(character: char) -> bool {
    character.is_alphabetic() || character.script() == Script::Inherited
}

/// Whether a script property names a script at all. `Common`, `Inherited` and
/// `Unknown` are the property's answer for a character no script owns.
const fn names_a_script(script: Script) -> bool {
    !matches!(script, Script::Common | Script::Inherited | Script::Unknown)
}

/// The UTS #39 skeleton of one character.
fn skeleton_of(character: char) -> Vec<char> {
    let mut buffer = [0u8; 4];
    unicode_security::skeleton(character.encode_utf8(&mut buffer)).collect()
}

/// Whether `character` is drawn as a letter of `script`: its skeleton is not
/// itself, and everything in the skeleton is that script's or no script's.
fn drawn_as(character: char, script: Script) -> bool {
    let skeleton = skeleton_of(character);
    skeleton != [character]
        && !skeleton.is_empty()
        && skeleton
            .iter()
            .all(|&part| part.script() == script || !names_a_script(part.script()))
}

fn lookalikes_in_word(word: &[char], offset: usize) -> Vec<Lookalike> {
    let spelled: String = word.iter().collect();
    if spelled.as_str().is_single_script() {
        return Vec::new();
    }
    // The majority by count, the first seen on a tie. Only the minority is
    // reported: in `c\u{0430}che` it is the one letter that was swapped in.
    let mut counts: Vec<(Script, usize)> = Vec::new();
    for &character in word {
        let script = character.script();
        if !names_a_script(script) {
            continue;
        }
        match counts.iter_mut().find(|(seen, _)| *seen == script) {
            Some((_, count)) => *count += 1,
            None => counts.push((script, 1)),
        }
    }
    let Some(among) = counts
        .iter()
        .fold(
            None::<(Script, usize)>,
            |best, &(script, count)| match best {
                Some((_, most)) if most >= count => best,
                _ => Some((script, count)),
            },
        )
        .map(|(script, _)| script)
    else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for (index, &character) in word.iter().enumerate() {
        let from = character.script();
        if !names_a_script(from) || from == among {
            continue;
        }
        // Either way round. The Cyrillic `a` in a Latin word is drawn as a
        // Latin letter; the Latin `a` in a Cyrillic word is the prototype the
        // Cyrillic letters around it are drawn as, which is the same disguise
        // seen from the other side. A kanji is neither, and passes.
        let disguised = drawn_as(character, among)
            || (skeleton_of(character) == [character]
                && unicode_security::is_potential_mixed_script_confusable_char(character)
                && word
                    .iter()
                    .any(|&other| other.script() == among && drawn_as(other, from)));
        if disguised {
            found.push(Lookalike {
                column: offset + index,
                character,
                from,
                among,
            });
        }
    }
    found
}

fn refused(character: char, base: Option<char>, next: Option<char>) -> bool {
    if character == '\t' || character == '\n' || character == ' ' {
        return false;
    }
    if draws_nothing(character, base, next) || is_private_use(character) {
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
        match scope::decode(&bytes) {
            scope::Decoded::Text(text) => {
                looked += 1;
                findings.extend(scan(&text, &blob.path, &allowances));
            }
            // No lines for a character to hide in. The one skip this guard
            // makes, and it is made on the bytes.
            scope::Decoded::Binary => {}
            // Silently skipped before this, which is a file nobody read
            // reported as a file with nothing in it -- `explicit-unknown` by
            // name, in the guard that reports it about everyone else.
            scope::Decoded::Unreadable(why) => {
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
            "{}\n\n{looked} file(s) read. A character that draws nothing, or a letter \
             from another script inside a word of a path, cannot be seen in review. \
             Delete it or retype the name in one script, or admit it in the rule's \
             `allow` list -- `\"U+00A0:docs/captured/**\"` admits one codepoint under one \
             path.",
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
/// Stricter than the content rule in two ways. A tab and a newline, the two
/// characters the content rule exempts, are legal INSIDE a file and are never
/// legitimate in a path. And a word of a path that mixes a lookalike letter
/// from another script into it is refused, which the content is never asked
/// about -- see [`lookalikes`]. Everything else this guard refuses is
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
    // A path is searched by substring, which is the one use a lookalike
    // defeats: `src/c\u{0430}che.rs` with a Cyrillic small a is a different file to
    // every tool and the same file to every reader. Each segment's words are
    // asked, and a `/` is never a letter, so no word spans two segments. The
    // CONTENT is not asked this: a file holds prose and data in every script,
    // and the content half of this rule stays the invisible ban it was.
    for lookalike in lookalikes(path) {
        if granted.contains(&lookalike.character) {
            continue;
        }
        findings.push(format!(
            "{path}:1:{}: {} in the FILE NAME",
            lookalike.column + 1,
            lookalike.describe(),
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
        assert!(
            findings("hello\tworld\n日本語 ☕\n").is_empty(),
            "{:?}",
            findings("hello\tworld\n日本語 ☕\n")
        );
    }

    #[test]
    fn a_variation_selector_after_an_emoji_is_earned() {
        assert!(
            findings("\u{26A0}\u{FE0F}\n").is_empty(),
            "{:?}",
            findings("\u{26A0}\u{FE0F}\n")
        );
    }

    #[test]
    fn a_variation_selector_after_ascii_is_not() {
        // `port: 80<VS16>80` is the case: an invisible codepoint with no
        // presentation to select.
        assert_eq!(findings("80\u{FE0F}80\n").len(), 1);
    }

    #[test]
    fn a_keycap_sequence_is_the_one_ascii_exception() {
        assert!(
            findings("1\u{FE0F}\u{20E3}\n").is_empty(),
            "{:?}",
            findings("1\u{FE0F}\u{20E3}\n")
        );
    }

    #[test]
    fn an_ideographic_selector_needs_an_ideograph() {
        assert!(
            findings("\u{845B}\u{E0100}\n").is_empty(),
            "{:?}",
            findings("\u{845B}\u{E0100}\n")
        );
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
        assert!(
            scan("a\u{00A0}b\n", "docs/page.md", &allowances).is_empty(),
            "{:?}",
            scan("a\u{00A0}b\n", "docs/page.md", &allowances)
        );
        assert_eq!(scan("a\u{00A0}b\n", "src/main.rs", &allowances).len(), 1);
    }

    #[test]
    fn an_allowance_grants_and_never_revokes() {
        // Adding an entry cannot tighten the guard on anybody else's file.
        let allowances = vec![parse_allowance("U+00A0").unwrap()];
        assert!(
            scan("a\u{00A0}b\n", "any.txt", &allowances).is_empty(),
            "{:?}",
            scan("a\u{00A0}b\n", "any.txt", &allowances)
        );
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
        assert!(
            scan_name("docs/readme.md", &[]).is_empty(),
            "{:?}",
            scan_name("docs/readme.md", &[])
        );
    }

    #[test]
    fn a_tab_is_legal_in_a_file_and_never_in_a_path() {
        // The two characters the content rule exempts, which is why the path
        // cannot simply be handed to `scan`.
        assert!(findings("a\tb\n").is_empty(), "{:?}", findings("a\tb\n"));
        assert_eq!(scan_name("a\tb", &[]).len(), 1);
        assert_eq!(scan_name("a\nb", &[]).len(), 1);
    }

    #[test]
    fn an_allowance_scoped_to_a_path_reaches_that_paths_name() {
        let allowances = vec![parse_allowance("U+00A0:docs/**").unwrap()];
        assert!(
            scan_name("docs/a\u{00A0}b.md", &allowances).is_empty(),
            "{:?}",
            scan_name("docs/a\u{00A0}b.md", &allowances)
        );
        assert_eq!(scan_name("src/a\u{00A0}b.rs", &allowances).len(), 1);
    }

    #[test]
    fn a_lookalike_letter_in_a_path_segment_is_refused_and_named() {
        let found = scan_name("src/c\u{0430}che.rs", &[]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].starts_with("src/c\u{0430}che.rs:1:6: U+0430"),
            "{found:?}"
        );
        assert!(found[0].contains("CYRILLIC SMALL LETTER A"), "{found:?}");
        assert!(
            found[0].contains("a Cyrillic letter in a Latin word"),
            "{found:?}"
        );
        // The allowance reaches it like any other codepoint.
        let allowances = vec![parse_allowance("U+0430").unwrap()];
        assert!(
            scan_name("src/c\u{0430}che.rs", &allowances).is_empty(),
            "{:?}",
            scan_name("src/c\u{0430}che.rs", &allowances)
        );
    }

    #[test]
    fn a_segment_in_each_script_is_not_a_lookalike() {
        for path in [
            "docs/\u{65E5}\u{672C}\u{8A9E}/readme.md",
            "docs/\u{043A}\u{044D}\u{0448}/readme.md",
            "docs/S\u{00E3}o-Paulo.md",
        ] {
            assert!(
                scan_name(path, &[]).is_empty(),
                "{path}: {:?}",
                scan_name(path, &[])
            );
        }
    }

    #[test]
    fn content_is_never_asked_about_lookalikes() {
        // The content half stays the invisible ban: a file holds prose in
        // every script, and a mixed word in it is data.
        assert!(
            findings("let c\u{0430}che = 1;\n").is_empty(),
            "{:?}",
            findings("let c\u{0430}che = 1;\n")
        );
    }

    #[test]
    fn a_lookalike_is_found_either_way_round_and_a_kanji_is_not_one() {
        // A Cyrillic letter in a Latin word, a Latin letter in a Cyrillic word.
        assert_eq!(lookalikes("c\u{0430}che").len(), 1);
        let latin_in_cyrillic = lookalikes("\u{043A}\u{043E}\u{0442}a\u{0441}");
        assert_eq!(latin_in_cyrillic.len(), 1, "{}", latin_in_cyrillic.len());
        assert_eq!(latin_in_cyrillic[0].character, 'a');
        // Latin run into a kanji compound is mixed, and nothing in it is drawn
        // like anything else.
        assert!(lookalikes("Rust\u{88FD}").is_empty());
        assert!(lookalikes("Dockerfile\u{3092}\u{4FEE}\u{6B63}").is_empty());
        // Kanji and kana together are single-script by UTS #39's augmented sets.
        assert!(lookalikes("\u{65E5}\u{672C}\u{30C6}\u{30B9}\u{30C8}").is_empty());
    }

    #[test]
    fn a_utf16_file_is_read_rather_than_dismissed_as_binary() {
        // It is full of NUL bytes, so the binary test alone takes an ordinary
        // text file out of the scan while looking exactly like a skipped image.
        let mut bytes = vec![0xFF, 0xFE];
        for unit in "a\u{200B}b".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        let scope::Decoded::Text(text) = scope::decode(&bytes) else {
            unreachable!("a UTF-16 file with a byte-order mark is text");
        };
        assert_eq!(scan(&text, "a.txt", &[]).len(), 1);
    }
}
