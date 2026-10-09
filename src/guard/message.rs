//! Guards over the commit message.

use std::path::PathBuf;

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
pub(crate) fn message_text(request: &Request<'_>) -> Result<(PathBuf, String)> {
    // A named file that is not there is not "nothing was forwarded". The
    // `.is_file()` filter used to turn one into the other, which is the exact
    // failure the paragraph above describes: the fallback then reads the
    // PREVIOUS commit's message, finds it clean, and reports a pass over a file
    // it never opened. A typo'd path, a relative `$1` resolved from the wrong
    // directory, or an unset variable in a wrapper all produce it.
    if let Some(named) = request.message_file
        && !named.is_file()
    {
        return Err(Fatal::new(format!(
            "{}: {} was named as the commit-message file and is not a file. \
                 Refusing to fall back to the previous commit's message and report \
                 a pass over a file that was never opened",
            request.rule.id,
            named.display()
        )));
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
///
/// The markers are the evidence layer's: `evidence::git` reports an agent's
/// change from the same list, so a marker added there is refused here on the
/// same commit.
pub(crate) fn ai_author_in(rule: &crate::config::Rule, label: &str, text: &str) -> Option<Refusal> {
    let found: Vec<&str> = crate::evidence::git::agent_markers_in(text)
        .iter()
        .map(|marker| marker.called)
        .collect();
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

/// The codepoints a message rule's `allow` admits.
///
/// Read at load, where a bad entry is refused with the rule's id on it, and
/// again at each judgement, so the guard reads the declaration and never a
/// copy of it. The file guard's `allow` takes a path glob after the codepoint;
/// a message has no path, so an entry carrying one here would be a glob read
/// by nothing, and it is refused rather than dropped.
///
/// What no entry can admit is a character that draws nothing. The file guard
/// lets a fixture earn one of those, because a captured page or an emoji
/// corpus is DATA; a message is prose somebody typed, and a listed zero-width
/// joiner or bidirectional override would be the exact hole a consumer opened
/// by switching the whole guard off with `UPHOLD_ALLOW` -- which is what this
/// field exists to make unnecessary.
pub(crate) fn allowances(rule: &crate::config::Rule) -> Result<Vec<char>> {
    rule.allow()
        .iter()
        .map(|token| {
            if token.contains(':') {
                return Err(Fatal::new(format!(
                    "rule {:?}: allow entry {token:?} carries a path glob, and a message \
                     has no path for it to select. Write the codepoint alone",
                    rule.id
                )));
            }
            let codepoint = crate::guard::unicode::parse_codepoint(token)
                .map_err(|error| Fatal::new(format!("rule {:?}: {error}", rule.id)))?;
            if crate::guard::unicode::is_invisible(codepoint) {
                return Err(Fatal::new(format!(
                    "rule {:?}: allow lists U+{:04X} {}, which draws nothing, and a \
                     character that draws nothing is what this guard exists to refuse. \
                     No allowance admits one; delete the entry",
                    rule.id,
                    codepoint as u32,
                    unicode_names2::name(codepoint)
                        .map_or_else(|| String::from("UNKNOWN"), |name| name.to_string()),
                )));
            }
            Ok(codepoint)
        })
        .collect()
}

/// The message guard over text that has no subject line: a pull-request,
/// issue, release or gist body, a comment, `uphold guard --text`.
///
/// Prose a reader reads, and nobody searches it by substring for a commit. So
/// it is asked only whether it carries a character that draws nothing; a
/// lookalike letter is not a hazard here, and an accented name, a degree sign
/// or a comparison sign never was one.
pub(crate) fn unusual_unicode_in(
    rule: &crate::config::Rule,
    label: &str,
    text: &str,
) -> Result<Option<Refusal>> {
    unusual_unicode_over(rule, label, text, None)
}

/// The judgement, with the one line -- if any -- that is a subject.
fn unusual_unicode_over(
    rule: &crate::config::Rule,
    label: &str,
    text: &str,
    subject: Option<usize>,
) -> Result<Option<Refusal>> {
    let findings = unusual_findings(label, text, &allowances(rule)?, subject);
    if findings.is_empty() {
        return Ok(None);
    }
    Ok(Some(Refusal {
        id: rule.id.clone(),
        report: format!(
            "{}\n\nA character that draws nothing, or a letter from another script inside \
             a word of a commit subject, cannot be caught by reading. Delete the invisible \
             character, retype the word in one script, or -- where the character is meant \
             -- admit its codepoint in the rule's `allow` list.",
            findings.join("\n")
        ),
    }))
}

/// Which line of a commit message is its subject: the first one with anything
/// on it that git would keep. A comment line is stripped by git's default
/// cleanup and is not the subject, and a blank line is not one either.
fn subject_line(text: &str) -> Option<usize> {
    text.split('\n').position(|line| {
        let trimmed = line.trim();
        !trimmed.is_empty() && !trimmed.starts_with('#')
    })
}

/// Two passes, and the second only over the subject.
///
/// Every line is asked for a character that draws nothing -- the "Trojan
/// Source" set (CVE-2021-42574) and the rest of what
/// [`crate::guard::unicode::draws_nothing`] names. The subject line, where one
/// is given, is also asked for a mixed-script confusable word (UTS #39,
/// [`crate::guard::unicode::lookalikes`]), because a subject is what somebody
/// searches the log for. Nothing else is refused: a punctuation mark or a
/// symbol, in any script or in none, is not this rule's business.
fn unusual_findings(
    label: &str,
    text: &str,
    allowed: &[char],
    subject: Option<usize>,
) -> Vec<String> {
    let mut findings = Vec::new();
    for (index, line) in text.split('\n').enumerate() {
        let characters: Vec<char> = line.chars().collect();
        for (column, &character) in characters.iter().enumerate() {
            let base = column
                .checked_sub(1)
                .and_then(|previous| characters.get(previous).copied());
            let next = characters.get(column + 1).copied();
            if !crate::guard::unicode::draws_nothing(character, base, next)
                || admitted_by_allowance(character, allowed)
            {
                continue;
            }
            findings.push(format!(
                "{label}:{}:{}: U+{:04X} {}, which draws nothing",
                index + 1,
                column + 1,
                character as u32,
                unicode_names2::name(character)
                    .map_or_else(|| String::from("UNKNOWN"), |name| name.to_string()),
            ));
        }
        if subject != Some(index) {
            continue;
        }
        for lookalike in crate::guard::unicode::lookalikes(line) {
            if admitted_by_allowance(lookalike.character, allowed) {
                continue;
            }
            findings.push(format!(
                "{label}:{}:{}: {} in the SUBJECT LINE",
                index + 1,
                lookalike.column + 1,
                lookalike.describe(),
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

/// Whether a listed codepoint is the one being read.
///
/// The invisibility test is asked here as well as at load, and not as a second
/// copy of one decision: the load-time refusal is the sentence a policy author
/// reads, and this is what holds for a `Rule` that never met `validate` -- one
/// a test builds by hand, or one a later loader admits by another route. A
/// list is a fact about the policy; that nothing on it can admit a character
/// that draws nothing is a fact about the guard, and it is kept where the
/// guard is.
fn admitted_by_allowance(character: char, allowed: &[char]) -> bool {
    allowed.contains(&character) && !crate::guard::unicode::is_invisible(character)
}

/// The message guard at a git hook, where the message has a subject line.
///
/// The subject gets both passes and the body the invisible pass alone -- the
/// same split as the text seams, made here because this is the one seam that
/// knows which line is the subject.
pub(crate) fn prevent_unusual_unicode(request: &Request<'_>) -> Result<Option<Refusal>> {
    for (label, text) in message_subjects(request)? {
        if let Some(refusal) =
            unusual_unicode_over(request.rule, &label, &text, subject_line(&text))?
        {
            return Ok(Some(refusal));
        }
    }
    Ok(None)
}

/// A commit subject line that is not printable ASCII.
///
/// A house style, not a security check, and opt in: no bundled set declares
/// it. It is the typographic half `prevent-unusual-unicode` used to carry --
/// the em dash, the curly quote, the fullwidth `!` -- under a name that says
/// what it is, so a repository that wants it writes it by name and one that
/// does not never has to reason about lookalikes to turn it off. `allow`
/// admits a codepoint, and no allowance admits a character that draws nothing
/// (`prevent-unusual-unicode` refuses those whatever this rule says).
pub(crate) fn ascii_only_commit_subject(request: &Request<'_>) -> Result<Option<Refusal>> {
    let allowed = allowances(request.rule)?;
    for (label, text) in message_subjects(request)? {
        let findings = non_ascii_in_subject(&label, &text, &allowed);
        if findings.is_empty() {
            continue;
        }
        return Ok(Some(Refusal {
            id: request.rule.id.clone(),
            report: format!(
                "{}\n\nThis repository keeps commit subject lines to printable ASCII. Retype \
                 the character in ASCII, or admit its codepoint in the rule's `allow` list.",
                findings.join("\n")
            ),
        }));
    }
    Ok(None)
}

fn non_ascii_in_subject(label: &str, text: &str, allowed: &[char]) -> Vec<String> {
    let Some(index) = subject_line(text) else {
        return Vec::new();
    };
    let line = text.split('\n').nth(index).unwrap_or_default();
    line.chars()
        .enumerate()
        .filter(|&(_, character)| {
            !(character.is_ascii_graphic()
                || character == ' '
                || character == '\t'
                || admitted_by_allowance(character, allowed))
        })
        .map(|(column, character)| {
            format!(
                "{label}:{}:{}: U+{:04X} {}",
                index + 1,
                column + 1,
                character as u32,
                unicode_names2::name(character)
                    .map_or_else(|| String::from("UNKNOWN"), |name| name.to_string()),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The letters under test, in escapes. This repository's own content policy
    // sets `allowed_scripts = ["Latin"]`, so a fixture written in another
    // script's letters could not be committed -- and a test nobody can commit
    // is a test nobody runs. Every non-ASCII character below is an escape.
    const JAPANESE: &str = "\u{65E5}\u{672C}\u{8A9E}"; // "Japanese"
    const KANA: &str = "\u{30C6}\u{30B9}\u{30C8}"; // "test"
    const KOREAN: &str = "\u{D55C}\u{AD6D}\u{C5B4}"; // "Korean"
    const CYRILLIC: &str = "\u{043A}\u{044D}\u{0448}"; // "kesh"

    /// The text as a commit message at a git hook: its subject line gets the
    /// lookalike pass as well as the invisible one.
    fn findings(text: &str) -> Vec<String> {
        unusual_findings("m", text, &[], subject_line(text))
    }

    /// The text as prose at a text seam: the invisible pass alone.
    fn prose_findings(text: &str) -> Vec<String> {
        unusual_findings("m", text, &[], None)
    }

    fn subject_findings(text: &str, allowed: &[char]) -> Vec<String> {
        non_ascii_in_subject("m", text, allowed)
    }

    /// A rule as a policy loads it, with `allow` written out.
    ///
    /// Through the loader rather than a struct literal, because the load is
    /// where a bad entry is refused and that refusal is one of the subjects
    /// below.
    fn loaded_rule(name: &str, builtin: &str, allow: &str) -> Result<crate::config::Rule> {
        let root = crate::fixture::scratch(name);
        std::fs::create_dir_all(root.join("policy")).unwrap();
        let path = root.join("policy/principles.toml");
        std::fs::write(
            &path,
            format!(
                "[rule.{builtin}]\nbuiltin = \"{builtin}\"\n\
                 allow = {allow}\n\n[rule.{builtin}.git]\nhooks = [\"commit-msg\"]\n"
            ),
        )
        .unwrap();
        let policy = crate::config::load(&root, &path)?;
        Ok(policy
            .rules
            .iter()
            .find(|rule| rule.id == builtin)
            .expect("the fixture rule did not survive the load")
            .clone())
    }

    /// The message rule over a subject carrying a lookalike, which only the
    /// allowance can admit.
    fn loaded(name: &str, allow: &str) -> Result<Option<Refusal>> {
        let rule = loaded_rule(name, "prevent-unusual-unicode", allow)?;
        let text = "Fix the c\u{0430}che\n";
        unusual_unicode_over(&rule, "m", text, subject_line(text))
    }

    #[test]
    fn a_listed_codepoint_is_admitted_and_an_unlisted_one_is_not() {
        assert!(
            loaded("message-allow-listed", "[\"U+0430\"]")
                .unwrap()
                .is_none()
        );
        let refused = loaded("message-allow-unlisted", "[\"U+3000\"]")
            .unwrap()
            .expect("an unlisted lookalike passed");
        assert!(refused.report.contains("U+0430"), "{}", refused.report);
    }

    #[test]
    fn an_invisible_on_the_list_is_refused_at_load_and_never_admitted() {
        let error = loaded("message-allow-invisible", "[\"U+200B\"]").unwrap_err();
        let text = error.to_string();
        assert!(text.contains("U+200B"), "{text}");
        assert!(text.contains("draws nothing"), "{text}");
        // And past the loader, the guard itself holds the line: a list that
        // somehow carries one admits nothing.
        assert_eq!(
            unusual_findings("m", "a\u{200B}b\n", &['\u{200B}'], None).len(),
            1
        );
    }

    #[test]
    fn a_glob_on_a_message_allowance_is_refused_at_load() {
        let error = loaded("message-allow-glob", "[\"U+0430:docs/**\"]").unwrap_err();
        assert!(error.to_string().contains("no path"), "{error}");
    }

    // ── what a subject may carry ─────────────────────────────────────

    #[test]
    fn a_city_name_with_a_tilde_passes() {
        let found = findings("Add the S\u{00E3}o Paulo office\n");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_degree_sign_in_a_longitude_passes() {
        let found = findings("Set the meridian to 100\u{00B0}W\n");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_greater_than_or_equal_sign_passes() {
        let found = findings("Keep the quota \u{2265} 3\n");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn punctuation_and_symbols_of_any_script_pass() {
        // What the old whitelist refused unless the script's letters vouched
        // for it. None of it is a lookalike and none of it draws nothing.
        for text in [
            format!("{JAPANESE}\u{3002}\u{300C}{KANA}\u{300D}\u{3001}{JAPANESE}\n"),
            String::from("Fix the parser\u{3002}\n"),
            String::from("Fix \u{2014} the \u{2018}parser\u{2019}\n"),
            String::from("Fix the parser\u{FF01}\n"),
        ] {
            assert!(
                findings(&text).is_empty(),
                "{text:?}: {:?}",
                findings(&text)
            );
        }
    }

    #[test]
    fn a_cyrillic_letter_in_a_latin_word_is_refused_and_named() {
        let found = findings("Fix the c\u{0430}che\n");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].starts_with("m:1:10: U+0430"), "{found:?}");
        assert!(found[0].contains("CYRILLIC SMALL LETTER A"), "{found:?}");
        assert!(
            found[0].contains("a Cyrillic letter in a Latin word"),
            "{found:?}"
        );
    }

    #[test]
    fn a_cyrillic_word_beside_a_latin_word_passes() {
        let found = findings(&format!("Rename the {CYRILLIC} cache\n"));
        assert!(found.is_empty(), "{found:?}");
        let beside = findings(&format!("{JAPANESE} {KANA} parser\n"));
        assert!(beside.is_empty(), "{beside:?}");
    }

    #[test]
    fn a_lookalike_in_the_body_is_prose_and_passes() {
        // The subject is what is searched by substring; the body is read.
        let found = findings("Fix the cache\n\nThe c\u{0430}che word was pasted.\n");
        assert!(found.is_empty(), "{found:?}");
        // And a text seam has no subject at all.
        assert!(
            prose_findings("Fix the c\u{0430}che\n").is_empty(),
            "{:?}",
            prose_findings("Fix the c\u{0430}che\n")
        );
    }

    #[test]
    fn the_subject_is_the_first_line_git_keeps() {
        let found = findings("\n# a comment c\u{0430}che\nFix the c\u{0430}che\n");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].starts_with("m:3:"), "{found:?}");
    }

    // ── what draws nothing, anywhere ─────────────────────────────────

    #[test]
    fn a_zero_width_joiner_between_two_letters_is_refused() {
        let found = findings("Fix the pa\u{200D}rser\n");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("U+200D"), "{found:?}");
        assert_eq!(prose_findings("pa\u{200D}rser\n").len(), 1);
    }

    #[test]
    fn a_right_to_left_override_is_refused() {
        let found = findings("Fix the parser\n\nsee \u{202E}txt.exe\n");
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("U+202E"), "{found:?}");
        assert_eq!(prose_findings("see \u{202E}txt.exe\n").len(), 1);
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
    fn an_emoji_with_its_selector_passes_and_a_selector_on_ascii_does_not() {
        assert!(
            findings("Ship it \u{2615}\u{FE0F}\n").is_empty(),
            "{:?}",
            findings("Ship it \u{2615}\u{FE0F}\n")
        );
        assert_eq!(findings("port 80\u{FE0F}80\n").len(), 1);
    }

    #[test]
    fn ascii_prose_and_a_tab_are_untouched() {
        assert!(
            findings("Fix the parser\n\nIt read a\ttab.\n").is_empty(),
            "{:?}",
            findings("Fix the parser\n\nIt read a\ttab.\n")
        );
    }

    // ── ascii-only-commit-subject, the typographic rule ──────────────

    #[test]
    fn an_em_dash_is_refused_in_a_subject_whatever_the_message_is_written_in() {
        assert_eq!(subject_findings("Fix \u{2014} the parser\n", &[]).len(), 1);
        assert_eq!(
            subject_findings(&format!("{JAPANESE} \u{2014} {KANA}\n"), &[]).len(),
            // The em dash and every letter around it: the rule is a house style
            // for ASCII subjects, and a Japanese subject is not one.
            7
        );
    }

    #[test]
    fn curly_quotes_are_refused_in_a_subject() {
        assert_eq!(
            subject_findings("the \u{2018}parser\u{2019}\n", &[]).len(),
            2
        );
        assert_eq!(
            subject_findings("the \u{201C}parser\u{201D}\n", &[]).len(),
            2
        );
    }

    #[test]
    fn a_fullwidth_form_is_refused_in_a_subject() {
        let found = subject_findings("Fix the parser\u{FF01}\n", &[]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("U+FF01"), "{found:?}");
    }

    #[test]
    fn only_the_subject_line_is_held_to_ascii() {
        assert!(
            subject_findings("Fix the parser\n\nIt said \u{2014} no.\n", &[]).is_empty(),
            "{:?}",
            subject_findings("Fix the parser\n\nIt said \u{2014} no.\n", &[])
        );
    }

    #[test]
    fn an_allowance_admits_the_em_dash_in_a_subject() {
        let rule = loaded_rule(
            "ascii-subject-allow",
            "ascii-only-commit-subject",
            "[\"U+2014\"]",
        )
        .unwrap();
        let allowed = allowances(&rule).unwrap();
        assert!(
            subject_findings("Fix \u{2014} the parser\n", &allowed).is_empty(),
            "{:?}",
            subject_findings("Fix \u{2014} the parser\n", &allowed)
        );
        assert_eq!(
            subject_findings("Fix \u{2013} the parser\n", &allowed).len(),
            1
        );
        // The same field, the same load-time refusal of an invisible.
        let error = loaded_rule(
            "ascii-subject-invisible",
            "ascii-only-commit-subject",
            "[\"U+200B\"]",
        )
        .unwrap_err();
        assert!(error.to_string().contains("draws nothing"), "{error}");
    }
}
