//! Guards over the commit message.

use std::path::PathBuf;
use std::sync::OnceLock;

use regex::Regex;

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
    let bytes = std::fs::read(&path).map_err(|error| Fatal::at(&path, error))?;
    Ok((path, String::from_utf8_lossy(&bytes).into_owned()))
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
    for (index, line) in text.split('\n').enumerate() {
        for (column, character) in line.chars().enumerate() {
            if message_character_is_ordinary(character) {
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
    let (path, text) = message_text(request)?;
    Ok(ai_author_in(
        request.rule,
        &path.display().to_string(),
        &text,
    ))
}

/// Characters refused in a commit message.
///
/// A message gets a WHITELIST and a file gets an invisible-character ban, and
/// the asymmetry is deliberate: real repositories commit CJK punctuation, box
/// drawing and emoji that are DATA, while a commit message is prose somebody
/// typed and has no such need.
fn message_character_is_ordinary(character: char) -> bool {
    if character == '\n' || character == '\t' {
        return true;
    }
    // Printable ASCII, plus anything a Latin-script keyboard produces that is a
    // letter, a mark, a number or a separator.
    if character.is_ascii_graphic() || character == ' ' {
        return true;
    }
    if character.is_control() {
        return false;
    }
    // Everything the file guard bans outright is refused here too.
    if crate::guard::unicode::is_invisible(character) {
        return false;
    }
    character.is_alphabetic() || character.is_numeric() || character.is_whitespace()
}

pub(crate) fn prevent_unusual_unicode(request: &Request<'_>) -> Result<Option<Refusal>> {
    let (path, text) = message_text(request)?;
    Ok(unusual_unicode_in(
        request.rule,
        &path.display().to_string(),
        &text,
    ))
}
