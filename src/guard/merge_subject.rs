//! A merge commit whose subject was given and is empty.
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
//! The SUBJECT and not the body. A subject is the line the log, a blame and
//! every notification show, and a commit without one is never what anybody
//! meant. An empty body is: `gh pr merge --squash --body ""` is how a squash
//! commit is kept from carrying the list of the branch's commits GitHub
//! writes there by default, and refusing that would refuse a deliberate,
//! routine choice and teach the bypass.
//!
//! Opt out rather than opt in, and shipped in `published-text`: no repository
//! means an empty merge subject, and a declaration nobody would write
//! differently is a declaration nobody should have to write. An ABSENT subject
//! is not this case and stays allowed -- the forge then writes its own default,
//! which is the pull request's title. Only a subject that was given and is
//! empty or blank is refused.
//!
//! Judged from what the shim read off the invocation and nowhere else: the
//! `[[shim]]` table's title flags on `gh pr merge`, and the `commit_title`
//! field of a `gh api` call to a pull request's `merge` endpoint, in every
//! field form that verb's grammar parses. A GraphQL `mergePullRequest`
//! mutation carries its headline inside a query string, where no field form
//! names it, and is not read here.

use std::fmt::Write as _;

use super::Refusal;
use crate::config::Rule;

/// One merge commit subject as the invocation gave it: what gave it -- the
/// flag or the field, `--subject`, `commit_title` -- and the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Subject {
    pub given_by: String,
    pub text: String,
}

/// The verdict of `no-empty-merge-subject` on one merge.
///
/// `subjects` is every subject the invocation gave; a merge that gave none is
/// an empty list, and its subject is the forge's to compose. Blank is ASCII
/// whitespace only, the same reading the shim gives an empty subject: a
/// character a guard exists to see is not blank, and `prevent-unusual-unicode`
/// judges it.
pub(crate) fn judge(rule: &Rule, command: &str, subjects: &[Subject]) -> Option<Refusal> {
    let mut report = String::new();
    for subject in subjects
        .iter()
        .filter(|subject| subject.text.trim_ascii().is_empty())
    {
        if !report.is_empty() {
            report.push('\n');
        }
        write!(
            report,
            "`{command}` would write a merge commit with an empty subject: `{}` was given \
             {}. The pull request's title is the subject the forge writes when none is \
             given -- leave it off to keep that, or write the subject.",
            subject.given_by,
            if subject.text.is_empty() {
                "as nothing"
            } else {
                "as nothing but whitespace"
            }
        )
        .ok();
    }
    if report.is_empty() {
        return None;
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
        let root = crate::fixture::scratch("merge-subject");
        std::fs::create_dir_all(root.join("policy")).unwrap();
        let path = root.join("policy/principles.toml");
        std::fs::write(
            &path,
            "[rule.merge-subject]\nbuiltin = \"no-empty-merge-subject\"\n\
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

    fn subject(given_by: &str, text: &str) -> Subject {
        Subject {
            given_by: given_by.to_owned(),
            text: text.to_owned(),
        }
    }

    #[test]
    fn a_given_subject_that_is_blank_is_refused_and_named() {
        let rule = rule();
        for (given, says) in [
            (
                subject("--subject", ""),
                "empty subject: `--subject` was given as nothing",
            ),
            (
                subject("-t", " \t "),
                "`-t` was given as nothing but whitespace",
            ),
            (
                subject("commit_title", "\n"),
                "empty subject: `commit_title`",
            ),
        ] {
            let report = judge(&rule, "gh pr merge", &[given])
                .expect("a blank subject was allowed")
                .report;
            assert!(report.contains(says), "{says:?} not in {report}");
            assert!(report.contains("` (#N)`"), "{report}");
        }
    }

    #[test]
    fn a_written_subject_and_no_subject_at_all_pass() {
        let rule = rule();
        assert!(judge(&rule, "gh pr merge", &[]).is_none());
        assert!(
            judge(
                &rule,
                "gh pr merge",
                &[subject("--subject", "Fix the parser")]
            )
            .is_none()
        );
        // A character that draws nothing is not blank: it is what another
        // guard is for, and calling it empty would hide it from that one.
        assert!(judge(&rule, "gh pr merge", &[subject("--subject", "\u{200b}")]).is_none());
    }

    #[test]
    fn every_blank_subject_is_reported_in_one_refusal() {
        let report = judge(
            &rule(),
            "gh pr merge",
            &[subject("-t", ""), subject("--subject", " ")],
        )
        .unwrap()
        .report;
        assert!(report.contains("`-t` was given as nothing."), "{report}");
        assert!(
            report.contains("`--subject` was given as nothing but"),
            "{report}"
        );
    }
}
