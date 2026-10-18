//! A merge commit whose subject or body was given and is empty.
//!
//! A bulk merge wrote ninety-five squash commits onto a default branch whose
//! subject was ` (#N)` and nothing else: the subject it was handed was empty,
//! and the forge appended the pull-request number to nothing. Every text guard
//! at the shim had looked at that subject and found nothing wrong, because
//! there was nothing in it to be wrong -- a guard asks what text says, and an
//! empty string says nothing. The question that catches it is not about what
//! the text says but about whether there is any, asked of the one invocation
//! that writes a commit onto the base branch with no local hook in the way.
//!
//! Opt out rather than opt in, and shipped in `published-text`: no repository
//! means an empty merge subject, and a declaration nobody would write
//! differently is a declaration nobody should have to write. An ABSENT subject
//! is not this case and stays allowed -- the forge then writes its own default,
//! which is the pull request's title. Only a subject or body that was given
//! and is empty or blank is refused.
//!
//! Judged from what the shim read off the invocation and nowhere else: the
//! `[[shim]]` table's title and body flags on `gh pr merge`, and the
//! `commit_title` and `commit_message` fields of a `gh api` call to a
//! pull request's `merge` endpoint, in every field form that verb's grammar
//! parses. A GraphQL `mergePullRequest` mutation carries its headline inside a
//! query string, where no field form names it, and is not read here.

use std::fmt::Write as _;

use super::Refusal;
use crate::config::Rule;

/// One part of a merge commit message as the invocation gave it: what gave it
/// -- the flag or the field, `--subject`, `commit_title` -- whether it is the
/// subject rather than the body, and the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Part {
    pub given_by: String,
    pub subject: bool,
    pub text: String,
}

/// The verdict of `no-empty-merge-message` on one merge.
///
/// `parts` is every part the invocation gave; a part it did not give is not
/// in it, and is the forge's to compose. Blank is ASCII whitespace only, the
/// same reading the shim gives an empty subject: a character a guard exists to
/// see is not blank, and `prevent-unusual-unicode` judges it.
pub(crate) fn judge(rule: &Rule, command: &str, parts: &[Part]) -> Option<Refusal> {
    let empty: Vec<&Part> = parts
        .iter()
        .filter(|part| part.text.trim_ascii().is_empty())
        .collect();
    if empty.is_empty() {
        return None;
    }
    let mut report = String::new();
    for part in empty {
        let (what, keep) = if part.subject {
            (
                "an empty commit subject",
                "the pull request's title is the subject the forge writes when none is \
                 given -- leave the flag off to keep it, or write the subject",
            )
        } else {
            (
                "an empty commit body",
                "the forge writes its own body when none is given -- leave the flag off to \
                 keep it, or write the body",
            )
        };
        if !report.is_empty() {
            report.push('\n');
        }
        write!(
            report,
            "`{command}` would write a merge commit with {what}: `{}` was given {}. {keep}.",
            part.given_by,
            if part.text.is_empty() {
                "as nothing"
            } else {
                "as nothing but whitespace"
            }
        )
        .ok();
    }
    report.push_str(
        "\nAn empty subject is how a squash merge writes ` (#N)` and nothing else onto the \
         base branch, where no local hook can reach it.",
    );
    Some(Refusal {
        id: rule.id.clone(),
        report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> Rule {
        let root = crate::fixture::scratch("merge-message");
        std::fs::create_dir_all(root.join("policy")).unwrap();
        let path = root.join("policy/principles.toml");
        std::fs::write(
            &path,
            "[rule.merge-message]\nbuiltin = \"no-empty-merge-message\"\n\
             command.before = [\"gh\"]\ncommand.scope = \"always\"\n\n\
             [[shim]]\ncommand = \"gh\"\nmatch = [\"pr:merge\"]\n",
        )
        .unwrap();
        crate::config::load(&root, &path)
            .unwrap()
            .rules
            .into_iter()
            .next()
            .unwrap()
    }

    fn part(given_by: &str, subject: bool, text: &str) -> Part {
        Part {
            given_by: given_by.to_owned(),
            subject,
            text: text.to_owned(),
        }
    }

    #[test]
    fn a_given_subject_or_body_that_is_blank_is_refused_and_named() {
        let rule = rule();
        for (given, says) in [
            (
                part("--subject", true, ""),
                "empty commit subject: `--subject` was given as nothing",
            ),
            (
                part("-t", true, " \t "),
                "`-t` was given as nothing but whitespace",
            ),
            (
                part("commit_title", true, "\n"),
                "empty commit subject: `commit_title`",
            ),
            (
                part("--body", false, ""),
                "empty commit body: `--body` was given as nothing",
            ),
            (
                part("commit_message", false, "  "),
                "empty commit body: `commit_message`",
            ),
        ] {
            let report = judge(&rule, "gh pr merge", &[given])
                .expect("a blank part was allowed")
                .report;
            assert!(report.contains(says), "{says:?} not in {report}");
            assert!(report.contains("` (#N)`"), "{report}");
        }
    }

    #[test]
    fn a_written_part_and_no_part_at_all_pass() {
        let rule = rule();
        assert!(judge(&rule, "gh pr merge", &[]).is_none());
        assert!(
            judge(
                &rule,
                "gh pr merge",
                &[
                    part("--subject", true, "Fix the parser"),
                    part("--body", false, "Why.")
                ]
            )
            .is_none()
        );
        // A character that draws nothing is not blank: it is what another
        // guard is for, and calling it empty would hide it from that one.
        assert!(judge(&rule, "gh pr merge", &[part("--subject", true, "\u{200b}")]).is_none());
    }

    #[test]
    fn both_blank_parts_are_reported_in_one_refusal() {
        let report = judge(
            &rule(),
            "gh api",
            &[
                part("commit_title", true, ""),
                part("commit_message", false, ""),
            ],
        )
        .unwrap()
        .report;
        assert!(report.contains("empty commit subject"), "{report}");
        assert!(report.contains("empty commit body"), "{report}");
    }
}
