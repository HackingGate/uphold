//! The commit message, as facts.
//!
//! Proven, because what git is about to record is not a matter of reading:
//! the text is the artifact. What this reports is the message's intent -- its
//! subject line, and its body as a property -- and which of the two authorship
//! facts the message carries. The marker patterns that decide the second live
//! here and nowhere else; `guard::message::ai_author_in` reads them from here,
//! so the guard that refuses a marker and the provider that reports one cannot
//! drift into two definitions of what a marker is.
//!
//! The text is read the way git records it and not the way the hook receives
//! it. A `commit-msg` hook is handed the file before git cleans it, and under
//! `git commit -v` that file carries the whole staged diff below a scissors
//! line, with the template's comment lines naming every deleted path above
//! it. A `-fn drop_me` in that tail is a word in the file and no word of the
//! message, and a fact read off it would say the author named a removal the
//! author never wrote down. So comment lines go, and everything from the
//! scissors line on goes, before a fact is read.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;

use super::{Context, Evidence, Kind, Observation, Provider, Source, Strength};

/// Who this is.
pub(crate) const PROVIDER: Provider = Provider {
    name: "git",
    strength: Strength::Proven,
    claims: &[Kind::CommitIntent, Kind::HumanChange, Kind::AgentChange],
};

/// The provider over the message a guard was handed.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Messages;

impl Source for Messages {
    fn provider(&self) -> Provider {
        PROVIDER
    }

    fn observe(&self, context: &Context<'_>) -> Observation {
        let Some(message) = context.message else {
            return Observation::Unavailable {
                provider: PROVIDER,
                reason: format!(
                    "no commit message at {}: the stage records none, so what the change \
                     intends was never read",
                    context.stage.as_str()
                ),
            };
        };
        let comment = match comment_char(context.root) {
            Ok(comment) => comment,
            Err(reason) => {
                return Observation::Unavailable {
                    provider: PROVIDER,
                    reason,
                };
            }
        };
        Observation::Found(facts(message, comment))
    }
}

/// What a message is about. The commit it describes does not exist yet; the
/// index is what it will be made from.
const REVISION: &str = "index";

/// The character git strips a line for opening with, as this repository's
/// config has it.
///
/// `auto` tells git to pick, per message, a character the message does not
/// start a line with, and the pick is made after this hook has run; a value
/// longer than one character is `core.commentString`'s shape, which git reads
/// under either name. Both fall back to `#` here, and a message under either
/// setting is read with git's default and not with git's choice. Unset is
/// `#`, which is git's default too.
fn comment_char(root: &Path) -> Result<char, String> {
    let configured = crate::git::try_run(root, &["config", "--get", "core.commentChar"])
        .map_err(|error| error.to_string())?;
    let Some(value) = configured else {
        return Ok(DEFAULT_COMMENT);
    };
    let value = value.trim();
    let mut characters = value.chars();
    match (characters.next(), characters.next()) {
        (Some(one), None) if value != "auto" => Ok(one),
        _ => Ok(DEFAULT_COMMENT),
    }
}

/// Git's own default for `core.commentChar`.
const DEFAULT_COMMENT: char = '#';

/// The message as git will record it: without the lines that open with the
/// comment character, and without the scissors line and everything below it.
///
/// A comment line is one whose FIRST character is the comment character,
/// which is git's test; a line indented and then `#` is content. The scissors
/// line is the exact line git writes, and git cuts at that line only.
fn as_recorded(message: &str, comment: char) -> String {
    let scissors = format!("{comment} ------------------------ >8 ------------------------");
    message
        .lines()
        .take_while(|line| *line != scissors)
        .filter(|line| !line.starts_with(comment))
        .collect::<Vec<&str>>()
        .join("\n")
}

/// The facts one message carries: its intent, and exactly one of the two
/// authorship kinds. Both are read off the message as git records it.
fn facts(raw: &str, comment: char) -> Vec<Evidence> {
    let recorded = as_recorded(raw, comment);
    let message = recorded.as_str();
    let mut lines = message.lines().filter(|line| !line.trim().is_empty());
    let subject = lines.next().unwrap_or_default().trim().to_owned();
    let body = lines.collect::<Vec<&str>>().join("\n");
    let mut found = vec![Evidence {
        kind: Kind::CommitIntent,
        subject,
        properties: BTreeMap::from([("body", body)]),
        provider: PROVIDER,
        revision: String::from(REVISION),
    }];
    let marked = agent_markers_in(message);
    let (kind, properties) = marked.first().map_or_else(
        || (Kind::HumanChange, BTreeMap::new()),
        |marker| {
            (
                Kind::AgentChange,
                BTreeMap::from([("marker", marker.line.clone())]),
            )
        },
    );
    found.push(Evidence {
        kind,
        subject: message.trim().to_owned(),
        properties,
        provider: PROVIDER,
        revision: String::from(REVISION),
    });
    found
}

/// One authorship marker found in a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Marker {
    /// What a refusal calls it.
    pub called: &'static str,
    /// The line that carried it.
    pub line: String,
}

/// Every authorship marker a text carries, in the order the patterns are
/// defined. The one definition of what marks a message as an agent's.
///
/// Read over the text exactly as handed, with no comment line or scissors
/// tail taken out. The provider above strips those before calling this,
/// because its subject is what git records; `guard::message::ai_author_in`
/// does not, because its subjects include a pull-request body, where a line
/// opening with `#` is a heading, and a pushed commit's recorded message,
/// where git has already done its stripping and a `#` line left in it is
/// content.
pub(crate) fn agent_markers_in(text: &str) -> Vec<Marker> {
    let mut found = Vec::new();
    for (called, pattern) in patterns() {
        if let Some(hit) = pattern.find(text) {
            found.push(Marker {
                called,
                line: line_at(text, hit.start()).trim().to_owned(),
            });
        }
    }
    found
}

/// The whole line an offset falls on.
fn line_at(text: &str, offset: usize) -> &str {
    let start = text
        .get(..offset)
        .and_then(|before| before.rfind('\n'))
        .map_or(0, |at| at + 1);
    let end = text
        .get(offset..)
        .and_then(|after| after.find('\n'))
        .map_or(text.len(), |at| offset + at);
    text.get(start..end).unwrap_or_default()
}

fn patterns() -> &'static [(&'static str, Regex)] {
    static PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            (
                "a Co-Authored-By trailer with a noreply address",
                crate::engine::literal_pattern(r"(?im)^Co-Authored-By:.*<noreply@"),
            ),
            (
                "a \"Generated with\" attribution",
                crate::engine::literal_pattern(
                    r"(?i)Generated with.*(Claude|GPT|Copilot|Cody|Codeium|Anthropic|OpenAI)",
                ),
            ),
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::Stage;

    fn context(message: Option<&'static str>) -> Context<'static> {
        Context {
            root: Path::new("."),
            stage: Stage::CommitMsg,
            message,
            changed: None,
        }
    }

    #[test]
    fn a_message_yields_its_intent_and_one_authorship_fact() {
        let Observation::Found(found) =
            Messages.observe(&context(Some("Remove the parser\n\nIt read nothing.\n")))
        else {
            unreachable!("a message is readable");
        };
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].kind, Kind::CommitIntent);
        assert_eq!(found[0].subject, "Remove the parser");
        assert_eq!(found[0].properties["body"], "It read nothing.");
        assert_eq!(found[1].kind, Kind::HumanChange);
        assert!(found[1].properties.is_empty());
    }

    #[test]
    fn a_marker_makes_the_change_an_agents_and_names_the_line() {
        let Observation::Found(found) = Messages.observe(&context(Some(
            "Fix it\n\nCo-Authored-By: Bot <noreply@example.test>\n",
        ))) else {
            unreachable!("a message is readable");
        };
        assert_eq!(found[1].kind, Kind::AgentChange);
        assert_eq!(
            found[1].properties["marker"],
            "Co-Authored-By: Bot <noreply@example.test>"
        );
        // Exactly one of the two: a marked message is not also a human one.
        assert!(found.iter().all(|item| item.kind != Kind::HumanChange));
    }

    #[test]
    fn a_stage_with_no_message_is_unavailable_and_not_an_empty_answer() {
        // The provider's own answer to ADR 0005's third question. An empty
        // `Found` here would let a policy conclude the message names nothing
        // because nothing was removed, over a message nobody read.
        let observed = Messages.observe(&context(None));
        assert!(matches!(observed, Observation::Unavailable { .. }));
    }

    #[test]
    fn both_markers_are_reported_and_the_guard_reads_the_same_list() {
        let marked = agent_markers_in(
            "x\n\nGenerated with Claude Code\nCo-Authored-By: A <noreply@x.test>\n",
        );
        assert_eq!(marked.len(), 2);
        assert_eq!(marked[0].line, "Co-Authored-By: A <noreply@x.test>");
        assert_eq!(marked[1].line, "Generated with Claude Code");
        assert!(agent_markers_in("Plain\n").is_empty());
    }

    #[test]
    fn a_comment_line_and_the_scissors_tail_are_no_part_of_the_message() {
        // The file a `commit -v` hands the hook: the template names the
        // deleted path on a `#` line, and the diff below the scissors carries
        // the removed declaration itself. Neither is a word the author wrote.
        let raw = "Tidy the module\n\
                   \n\
                   # Please enter the commit message for your changes.\n\
                   #\tdeleted:    old.rs\n\
                   # ------------------------ >8 ------------------------\n\
                   # Do not modify or remove the line above.\n\
                   diff --git a/old.rs b/old.rs\n\
                   -fn drop_me() {}\n\
                   Co-Authored-By: Bot <noreply@example.test>\n";
        assert_eq!(as_recorded(raw, '#'), "Tidy the module\n");
        let found = facts(raw, '#');
        assert_eq!(found[0].subject, "Tidy the module");
        assert_eq!(found[0].properties["body"], "");
        assert!(!found[0].properties["body"].contains("drop_me"));
        assert_eq!(found[1].kind, Kind::HumanChange);
        assert_eq!(found[1].subject, "Tidy the module");
    }

    #[test]
    fn a_comment_character_the_repository_configured_is_the_one_stripped() {
        // With `;` as the comment character, `#` lines are content and `;`
        // lines are not -- and the scissors line is written with `;` too.
        let raw = "Drop it\n\
                   # drop_me is gone\n\
                   ; deleted:    old.rs\n\
                   ; ------------------------ >8 ------------------------\n\
                   -fn drop_me() {}\n";
        assert_eq!(as_recorded(raw, ';'), "Drop it\n# drop_me is gone");
        // An indented `#` is content under git's test as well as here.
        assert_eq!(as_recorded("x\n  # kept\n", '#'), "x\n  # kept");
    }

    #[test]
    fn the_comment_character_is_read_off_the_repository_and_falls_back_to_hash() {
        let root = crate::fixture::scratch("comment-char");
        std::fs::create_dir_all(&root).unwrap();
        crate::fixture::git(&root, &["init", "-q", "-b", "main"]);
        assert_eq!(comment_char(&root).unwrap(), '#');
        crate::fixture::git(&root, &["config", "core.commentChar", ";"]);
        assert_eq!(comment_char(&root).unwrap(), ';');
        // `auto` is a choice git makes after this hook has run, and a string
        // is not a character: both read as the default.
        crate::fixture::git(&root, &["config", "core.commentChar", "auto"]);
        assert_eq!(comment_char(&root).unwrap(), '#');
        crate::fixture::git(&root, &["config", "core.commentChar", "//"]);
        assert_eq!(comment_char(&root).unwrap(), '#');
    }
}
