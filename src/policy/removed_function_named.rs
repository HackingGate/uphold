//! Every function a change removes is named in the message that records it.
//!
//! A removal is the edit a reader of the history most needs the message for:
//! an addition is in the tree to be read, and a removal is in no tree at all.
//! A search of the history finds it only for a reader who already knows the
//! name, and the message is where the name is written for the reader who
//! does not.
//!
//! The predicate reads two kinds of fact and knows nothing about who supplied
//! them. Removals arrive as [`Kind::FunctionRemoved`] from whichever providers
//! report it, the intent as [`Kind::CommitIntent`], and the three rules the
//! body enforces are what this leans on: a removal a stronger provider could
//! not look for and a weaker one did not find is could-not-look and not clean;
//! a removal any provider did find is a refusal whatever else could not be
//! read; and two Proven providers disagreeing about one function is a refusal
//! naming both, because choosing between them would be a second checker over
//! one answer.
//!
//! A file the change deletes takes every function in it, and a message that
//! names the file has named the removal a reader will search for: the file,
//! not each function it held. A removal marked [`FILE_REMOVED`] is therefore
//! named by the file's path or its stem as well as by the function's name,
//! and a removal without the mark -- a function gone from a file that stays
//! -- is named by the function's name only.

use std::collections::BTreeSet;
use std::path::Path;

use crate::config::Rule;
use crate::error::{Fatal, Result};
use crate::evidence::{Body, Established, FILE_REMOVED, Kind};
use crate::guard::Refusal;

/// The judgment.
pub(crate) fn judge(rule: &Rule, body: &Body) -> Result<Option<Refusal>> {
    let contradicted: Vec<String> = body
        .contradictions()
        .iter()
        .filter(|pair| matches!(pair.first.kind, Kind::FunctionRemoved | Kind::FunctionAdded))
        .map(|pair| {
            format!(
                "{}: {} reports it {} and {} reports it {} at {}; refusing rather than \
                 picking one",
                pair.first.subject,
                pair.first.provider.name,
                describe(pair.first.kind),
                pair.second.provider.name,
                describe(pair.second.kind),
                pair.first.revision
            )
        })
        .collect();

    let removed = body.established(Kind::FunctionRemoved);
    let intent = body.established(Kind::CommitIntent);
    let named = Named::by(&intent);

    let subjects: BTreeSet<&str> = removed
        .found()
        .iter()
        .map(|item| item.subject.as_str())
        .collect();
    let mut unnamed: Vec<String> = Vec::new();
    let mut unread_intent = false;
    for subject in subjects {
        let (path, name) = subject.rsplit_once("::").unwrap_or(("", subject));
        let with_file = removed.found().iter().any(|item| {
            item.subject == subject
                && item.properties.get(FILE_REMOVED.0).map(String::as_str) == Some(FILE_REMOVED.1)
        });
        match &named {
            Some(named) if named.word(name) || (with_file && named.file(path)) => {}
            Some(_) => {
                let seen_by = body
                    .strongest(Kind::FunctionRemoved, subject)
                    .map_or("nothing", |item| item.provider.name);
                let what = if with_file {
                    "it or the deleted file"
                } else {
                    "it"
                };
                unnamed.push(format!(
                    "{path}: `{name}` is removed by this change and the commit message does \
                     not name {what} (seen by {seen_by})"
                ));
            }
            None => unread_intent = true,
        }
    }

    if !contradicted.is_empty() || !unnamed.is_empty() {
        let mut lines = contradicted;
        lines.extend(unnamed);
        return Ok(Some(Refusal {
            id: rule.id.clone(),
            report: format!(
                "{}\n\nName each removed function in the message -- what it was and why it \
                 is gone -- or keep it; a deleted file is named by its path or its stem, \
                 which names every function it held. A reader of the history finds a \
                 removal only by the message that names it.",
                lines.join("\n")
            ),
        }));
    }
    if !removed.answered() {
        return Err(Fatal::new(format!(
            "{}: whether this change removes a function could not be established, and a \
             removal nobody looked for is not a removal that was named.\n{}",
            rule.id,
            reasons(&removed)
        )));
    }
    if unread_intent {
        return Err(Fatal::new(format!(
            "{}: this change removes a function and no commit message was read to check it \
             is named there.\n{}",
            rule.id,
            reasons(&intent)
        )));
    }
    Ok(None)
}

/// What the message names: its words, and its text for the names a word
/// cannot hold.
struct Named {
    words: BTreeSet<String>,
    text: String,
}

impl Named {
    /// The message's words, or `None` where no message was read.
    fn by(intent: &Established<'_>) -> Option<Self> {
        if intent.found().is_empty() && !intent.clean() {
            return None;
        }
        let mut text = String::new();
        for item in intent.found() {
            let body = item.properties.get("body").map_or("", String::as_str);
            text.push_str(&item.subject);
            text.push('\n');
            text.push_str(body);
            text.push('\n');
        }
        let words = text
            .split(|character: char| !is_word(character))
            .filter(|word| !word.is_empty())
            .map(str::to_owned)
            .collect();
        Some(Self { words, text })
    }

    /// Whether the message uses this word.
    fn word(&self, word: &str) -> bool {
        self.words.contains(word)
    }

    /// Whether the message names this file: by its stem as a word, or by its
    /// path, which holds separators no word can and so is looked for as a run
    /// of path characters bounded by something that is not one.
    fn file(&self, path: &str) -> bool {
        let stem = Path::new(path)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default();
        if !stem.is_empty() && self.word(stem) {
            return true;
        }
        self.text.match_indices(path).any(|(start, _)| {
            let before = self
                .text
                .get(..start)
                .and_then(|text| text.chars().next_back());
            let after = self
                .text
                .get(start + path.len()..)
                .and_then(|text| text.chars().next());
            !before.is_some_and(is_path) && !after.is_some_and(is_path)
        })
    }
}

/// A character that can be part of a word in a message.
fn is_word(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// A character that can be part of a path in a message.
fn is_path(character: char) -> bool {
    is_word(character) || matches!(character, '/' | '.' | '-')
}

/// What the providers that could not look said, one per line.
fn reasons(established: &Established<'_>) -> String {
    established
        .unread()
        .iter()
        .map(|missing| format!("  {}: {}", missing.provider.name, missing.reason))
        .collect::<Vec<String>>()
        .join("\n")
}

const fn describe(kind: Kind) -> &'static str {
    match kind {
        Kind::FunctionRemoved => "removed",
        Kind::FunctionAdded => "added",
        Kind::SignatureChanged => "changed",
        Kind::CommitIntent => "intended",
        Kind::HumanChange => "a person's",
        Kind::AgentChange => "an agent's",
    }
}
