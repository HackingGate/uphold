//! Guards over the commit message.

use std::path::PathBuf;
use std::sync::OnceLock;

use regex::Regex;
use unicode_script::{Script, UnicodeScript};

use super::{Refusal, Request};
use crate::error::{Fatal, Result};

/// The message file, or the one git itself wrote.
///
/// The fallback is for a caller that forwards nothing at all, and it is the one
/// thing about these guards that is easy to get wrong in the direction nobody
/// notices. Under `git commit` `.git/COMMIT_EDITMSG` happens to be the right
/// file, which is what makes the mistake survivable and therefore permanent; it
/// stops being the right file the moment anyone asks the guard about a NAMED
/// message, at which point it reads the previous commit's -- clean -- and
/// reports a pass over a file it never opened.
fn message_text(request: &Request<'_>) -> Result<(PathBuf, String)> {
    // A named file that is not there is not "nothing was forwarded". The
    // `.is_file()` filter used to turn one into the other, which is the exact
    // failure the paragraph above describes: the fallback then reads the
    // PREVIOUS commit's message, finds it clean, and reports a pass over a file
    // it never opened. A typo'd path, a relative `$1` resolved from the wrong
    // directory, or an unset variable in a wrapper all produce it.
    if let Some(named) = request.message_file {
        if !named.is_file() {
            return Err(Fatal::new(format!(
                "{}: {} was named as the commit-message file and is not a file. \
                 Refusing to fall back to the previous commit's message and report \
                 a pass over a file that was never opened",
                request.rule.id,
                named.display()
            )));
        }
    }
    let path = if let Some(path) = request.message_file {
        path.to_path_buf()
    } else {
        let git_dir = crate::git::dir(request.root)?;
        let fallback = git_dir.join("COMMIT_EDITMSG");
        if !fallback.is_file() {
            return Err(Fatal::new(format!(
                "{}: no commit message file was forwarded and {} does not exist",
                request.rule.id,
                fallback.display()
            )));
        }
        fallback
    };
    // Decoded through the one reader, which refuses bytes that are not text
    // rather than lossily pretending they are. A message in UTF-16 used to
    // arrive here as replacement characters with NULs between them, and every
    // guard over it passed.
    let text = super::scope::read_message(&request.rule.id, &path)?;
    Ok((path, text))
}

/// Every message this run is actually about, labelled.
///
/// At `pre-push` that is the messages of the commits being published, and NOT
/// `.git/COMMIT_EDITMSG`. Reading the fallback there is the same mistake the
/// paragraph above `message_text` describes, arriving by the other door: the
/// file exists, it holds whatever the last `git commit` wrote, and it is clean
/// -- so a push carrying a marker in a commit made by `git commit-tree`, a
/// rebase, a cherry-pick, `git am`, `--no-verify`, or a fast-forward out of a
/// hookless clone was reported as one guard passed, exit 0.
///
/// `no-private-repo-names` already reads the pushed range for exactly this
/// reason; these two guards were the ones left asking the wrong file.
fn message_subjects(request: &Request<'_>) -> Result<Vec<(String, String)>> {
    if request.stage == super::Stage::PrePush {
        return Ok(super::scope::pushed_messages(
            request.root,
            request.stage,
            request.push_refs,
            request.push_source,
        )?
        .into_iter()
        .map(|(sha, body)| {
            let short: String = sha.chars().take(12).collect();
            (format!("commit {short} (its MESSAGE)"), body)
        })
        .collect());
    }
    let (path, text) = message_text(request)?;
    Ok(vec![(path.display().to_string(), text)])
}

/// The judgment, over text that may never have been a file.
pub(crate) fn ai_author_in(rule: &crate::config::Rule, label: &str, text: &str) -> Option<Refusal> {
    let mut found: Vec<&str> = Vec::new();
    if coauthor().is_match(text) {
        found.push("a Co-Authored-By trailer with a noreply address");
    }
    if generated().is_match(text) {
        found.push("a \"Generated with\" attribution");
    }
    if found.is_empty() {
        return None;
    }
    Some(Refusal {
        id: rule.id.clone(),
        report: format!(
            "{label} carries {}.\n\nRemove the marker and ensure the work is represented \
             as your own.",
            found.join(" and ")
        ),
    })
}

pub(crate) fn unusual_unicode_in(
    rule: &crate::config::Rule,
    label: &str,
    text: &str,
) -> Option<Refusal> {
    let findings = unusual_findings(label, text);
    if findings.is_empty() {
        return None;
    }
    Some(Refusal {
        id: rule.id.clone(),
        report: format!(
            "{}\n\nThis is prose somebody typed. Retype the character, or describe it in \
             words.",
            findings.join("\n")
        ),
    })
}

fn coauthor() -> &'static Regex {
    static COAUTHOR: OnceLock<Regex> = OnceLock::new();
    COAUTHOR.get_or_init(|| crate::engine::literal_pattern(r"(?im)^Co-Authored-By:.*<noreply@"))
}

fn generated() -> &'static Regex {
    static GENERATED: OnceLock<Regex> = OnceLock::new();
    GENERATED.get_or_init(|| {
        crate::engine::literal_pattern(
            r"(?i)Generated with.*(Claude|GPT|Copilot|Cody|Codeium|Anthropic|OpenAI)",
        )
    })
}

fn unusual_findings(label: &str, text: &str) -> Vec<String> {
    let mut findings = Vec::new();
    // Read off the WHOLE message and not the line, because the line where a
    // mark is refused is the line least likely to carry the letters that vouch
    // for it: a subject line ending in a single `。` over a body written in
    // Japanese is the ordinary shape of a Japanese commit.
    let written = scripts_written_in(text);
    for (index, line) in text.split('\n').enumerate() {
        for (column, character) in line.chars().enumerate() {
            if message_character_is_ordinary(character, &written) {
                continue;
            }
            findings.push(format!(
                "{label}:{}:{}: U+{:04X} {}",
                index + 1,
                column + 1,
                character as u32,
                unicode_names2::name(character)
                    .map_or_else(|| String::from("UNKNOWN"), |name| name.to_string()),
            ));
        }
    }
    findings
}

pub(crate) fn prevent_ai_author(request: &Request<'_>) -> Result<Option<Refusal>> {
    for (label, text) in message_subjects(request)? {
        if let Some(refusal) = ai_author_in(request.rule, &label, &text) {
            return Ok(Some(refusal));
        }
    }
    Ok(None)
}

/// The scripts this message is written in.
///
/// Read off the LETTERS, because a letter is the only character that says which
/// script a text belongs to: `。` is shared by six of them and settles nothing,
/// while one kana settles it. `Common`, `Inherited` and `Unknown` are dropped
/// rather than collected -- they are the property's answer for a character no
/// script owns, and a set holding one of them intersects every extension in
/// Unicode, which is the whole of Unicode admitted by an English subject line.
fn scripts_written_in(text: &str) -> Vec<Script> {
    let mut written: Vec<Script> = Vec::new();
    for character in text.chars() {
        if !character.is_alphabetic() {
            continue;
        }
        let script = character.script();
        if matches!(script, Script::Common | Script::Inherited | Script::Unknown) {
            continue;
        }
        if !written.contains(&script) {
            written.push(script);
        }
    }
    written
}

/// The scripts that write with the fullwidth forms.
const EAST_ASIAN: &[Script] = &[
    Script::Han,
    Script::Hiragana,
    Script::Katakana,
    Script::Hangul,
    Script::Bopomofo,
    Script::Yi,
];

/// A fullwidth ASCII variant or fullwidth sign.
///
/// Named here because the script test below cannot reach these: U+FF01..U+FF60
/// and U+FFE0..U+FFE6 carry `Script_Extensions=Common`, so `！` and `（` claim
/// no script at all, and Unicode's own property has nothing to say about the
/// one thing everybody knows about them. They are admitted on the presence of
/// an East Asian script instead, and never unconditionally: a fullwidth
/// exclamation mark in an English sentence is the paste artefact this rule
/// exists to catch. The halfwidth CJK punctuation just above the range --
/// U+FF61..U+FF65 -- needs no entry, because those DO name their scripts.
const fn is_fullwidth_form(character: char) -> bool {
    matches!(character as u32, 0xFF01..=0xFF60 | 0xFFE0..=0xFFE6)
}

/// Whether a mark is punctuation one of the message's own scripts writes with.
fn mark_belongs_to_a_written_script(character: char, written: &[Script]) -> bool {
    // The general category, so that this admits the MARKS a script writes with
    // and not everything else that happens to carry a script extension.
    if !is_punctuation_or_symbol(character) {
        return false;
    }
    if is_fullwidth_form(character) {
        return written.iter().any(|script| EAST_ASIAN.contains(script));
    }
    let extension = character.script_extension();
    // `Common` and `Inherited` extensions intersect EVERY script by
    // construction, so `contains_script` answers yes to all of them. Asked
    // before the intersection because otherwise the presence of any script at
    // all -- the Latin of an ordinary English subject line -- admits U+2014 EM
    // DASH and the curly quotes, which are the characters this fleet most
    // deliberately refuses in prose. An extension naming no script is not
    // evidence about any.
    if extension.is_common() || extension.is_inherited() || extension.is_empty() {
        return false;
    }
    written
        .iter()
        .any(|&script| extension.contains_script(script))
}

/// Whether a character is punctuation or a symbol.
///
/// The general category, which `char` does not expose and the regex engine
/// already in this binary does.
fn is_punctuation_or_symbol(character: char) -> bool {
    let mut buffer = [0u8; 4];
    punctuation_or_symbol().is_match(character.encode_utf8(&mut buffer))
}

fn punctuation_or_symbol() -> &'static Regex {
    static PUNCTUATION_OR_SYMBOL: OnceLock<Regex> = OnceLock::new();
    PUNCTUATION_OR_SYMBOL.get_or_init(|| crate::engine::literal_pattern(r"^[\p{P}\p{S}]$"))
}

/// Characters refused in a commit message.
///
/// A message gets a WHITELIST and a file gets an invisible-character ban, and
/// the asymmetry is deliberate: real repositories commit box drawing and emoji
/// that are DATA, while a commit message is prose somebody typed and has no
/// such need.
///
/// What the whitelist admits is decided by the message. ASCII and the letters
/// and digits of every script, always; and then the punctuation of the scripts
/// whose letters are ALREADY IN THIS TEXT. The rule before this one admitted
/// every script's letters and only Latin's punctuation, so a line of kana
/// passed and the same line with a full stop on it did not -- and Japanese
/// prose cannot be written without `。`, `、` and `「」`, so what the rule
/// actually produced downstream was a policy switching the whole of it off.
/// Scoping the admission to the text keeps the
/// case it exists for: a lone `。` in an English sentence is still a paste
/// artefact, because no Han, kana or Hangul letter anywhere in the message
/// vouches for it.
fn message_character_is_ordinary(character: char, written: &[Script]) -> bool {
    if character == '\n' || character == '\t' {
        return true;
    }
    if character.is_ascii_graphic() || character == ' ' {
        return true;
    }
    if character.is_control() {
        return false;
    }
    // Everything the file guard bans outright is refused here too, and asked
    // BEFORE any script can vouch for anything: U+3164 HANGUL FILLER is an
    // invisible `Lo` whose script is Hangul, so a Korean message is exactly
    // where a whitelist that asked the script first would let it through.
    if crate::guard::unicode::is_invisible(character) {
        return false;
    }
    if character.is_alphabetic() || character.is_numeric() || character.is_whitespace() {
        return true;
    }
    mark_belongs_to_a_written_script(character, written)
}

pub(crate) fn prevent_unusual_unicode(request: &Request<'_>) -> Result<Option<Refusal>> {
    for (label, text) in message_subjects(request)? {
        if let Some(refusal) = unusual_unicode_in(request.rule, &label, &text) {
            return Ok(Some(refusal));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The letters under test, in escapes. This repository's own content policy
    // sets `allowed_scripts = ["Latin"]`, so the scripts whose punctuation this
    // guard now admits are scripts whose letters cannot be typed into its
    // files -- and a fixture that cannot be committed is a test nobody runs.
    // The punctuation is written out, because that is the character each
    // assertion is about and it belongs to no script.
    const JAPANESE: &str = "\u{65E5}\u{672C}\u{8A9E}"; // "Japanese"
    const KANA: &str = "\u{30C6}\u{30B9}\u{30C8}"; // "test"
    const KOREAN: &str = "\u{D55C}\u{AD6D}\u{C5B4}"; // "Korean"
    const GREEK: &str = "\u{0395}\u{03BB}\u{03BB}\u{03B7}\u{03BD}"; // "Hellen"
    const ARABIC: &str = "\u{0627}\u{0644}\u{0639}\u{0631}\u{0628}"; // "al-arab"
    const HEBREW: &str = "\u{05E2}\u{05D1}\u{05E8}"; // "ivr"
    const CYRILLIC: &str = "\u{043A}\u{044D}\u{0448}"; // "kesh"

    fn findings(text: &str) -> Vec<String> {
        unusual_findings("m", text)
    }

    #[test]
    fn a_japanese_sentence_brings_its_own_punctuation() {
        // The case that made a consuming repository switch the rule off. Every
        // mark here is refused on its own and admitted beside the kana.
        let message = format!("{JAPANESE}\u{3002}\u{300C}{KANA}\u{300D}\u{3001}{JAPANESE}\n");
        let found = findings(&message);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_full_stop_from_a_script_nobody_wrote_in_is_still_a_paste_artefact() {
        let found = findings("Fix the parser\u{3002}\n");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("U+3002"), "{found:?}");
        // And with no letters at all there is nothing to vouch for it either.
        assert_eq!(findings("\u{3002}\n").len(), 1);
    }

    #[test]
    fn a_fullwidth_form_needs_an_east_asian_script_beside_it() {
        // `Script_Extensions=Common`, so the intersection cannot decide these
        // and the range decides them instead.
        assert!(findings(&format!("{JAPANESE}\u{FF08}{KANA}\u{FF09}\u{FF01}\n")).is_empty());
        assert_eq!(findings("Fix the parser\u{FF01}\n").len(), 1);
        assert_eq!(findings("Fix the parser\u{FF08}1\u{FF09}\n").len(), 2);
    }

    #[test]
    fn an_em_dash_is_refused_whatever_the_message_is_written_in() {
        // `Common`, which intersects every script: without the test that asks
        // first, one kana anywhere in the message would admit it.
        assert_eq!(findings("Fix \u{2014} the parser\n").len(), 1);
        assert_eq!(findings(&format!("{JAPANESE} \u{2014} {KANA}\n")).len(), 1);
    }

    #[test]
    fn curly_quotes_are_refused_whatever_the_message_is_written_in() {
        assert_eq!(findings("the \u{2018}parser\u{2019}\n").len(), 2);
        assert_eq!(
            findings(&format!("{JAPANESE} \u{201C}parser\u{201D}\n")).len(),
            2
        );
    }

    #[test]
    fn a_hangul_filler_is_refused_in_korean_text() {
        // An invisible `Lo` whose script is Hangul: the one character a
        // script-scoped whitelist is most likely to admit by accident.
        let found = findings(&format!("{KOREAN}\u{3164}{KOREAN}\n"));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("U+3164"), "{found:?}");
    }

    #[test]
    fn punctuation_is_admitted_only_by_the_script_that_owns_it() {
        // Greek, Arabic and Hebrew marks beside their own letters.
        assert!(findings(&format!("{GREEK}\u{0384}\n")).is_empty());
        assert!(findings(&format!("{ARABIC}\u{060C} {ARABIC}\n")).is_empty());
        assert!(findings(&format!("{HEBREW}\u{05C3}\n")).is_empty());
        // And the same marks with only Latin letters to vouch for them.
        assert_eq!(findings("Fix the parser\u{0384}\n").len(), 1);
        assert_eq!(findings("Fix the parser\u{060C}\n").len(), 1);
        assert_eq!(findings("Fix the parser\u{05C3}\n").len(), 1);
        // A script present in the message vouches for its own marks and for
        // nobody else's: a danda is not Japanese punctuation.
        assert_eq!(findings(&format!("{JAPANESE}\u{0964}\n")).len(), 1);
    }

    #[test]
    fn a_cyrillic_letter_admits_no_punctuation_it_does_not_own() {
        // Every script's LETTERS were ordinary before this change and still
        // are, so a Cyrillic homoglyph inside a Latin word is not what this
        // guard refuses. What it refuses is the mark that arrives with no
        // letters of its own script, and a Cyrillic word vouches for none.
        assert!(findings("Fix the c\u{0430}che\n").is_empty());
        assert_eq!(findings(&format!("{CYRILLIC}\u{3002}\n")).len(), 1);
    }

    #[test]
    fn ascii_prose_and_a_tab_are_untouched() {
        assert!(findings("Fix the parser\n\nIt read a\ttab.\n").is_empty());
    }
}
