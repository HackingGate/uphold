//! The adapter-to-policy contract for supported publication entry points.
//!
//! Pathless text and command-collected subjects remain different inputs: a
//! command has subject kinds and scope that cannot be invented for raw text.
//! Missing text is a valid observation; unread text must stop judgment.

use crate::error::{Fatal, Result};
use crate::shim::Subject;
use crate::text::{Headline, Seam};

/// What an adapter knows about one subject surface, before policy runs.
pub(crate) enum Observed<T> {
    /// The surface was read and contains no subject of this kind.
    Absent,
    /// A subject was read, including a deliberately empty string.
    Present(T),
    /// The required surface could not be read, with evidence for the caller.
    Unread(String),
}

/// The prose and separately identified headlines of a pathless publication.
pub(crate) struct TextInput<'a> {
    /// Whole prose; absence leaves independently observed tool identity intact.
    pub prose: Observed<&'a str>,
    /// Headlines retain their report labels and separate guard treatment.
    pub headlines: &'a [Headline],
}

impl<T> Observed<T> {
    /// Reading an unavailable surface is an infrastructure error, never clean.
    pub(crate) fn read(&self) -> Result<Option<&T>> {
        match self {
            Self::Absent => Ok(None),
            Self::Present(value) => Ok(Some(value)),
            Self::Unread(why) => Err(Fatal::new(why)),
        }
    }
}

enum Input<'a> {
    Text(TextInput<'a>),
    Command(&'a [Subject]),
}

/// Identity and observed subjects, before choosing applicable rule kinds.
/// Destination/scope observations belong to the command adapter's context;
/// raw text and harness events do not establish a forge destination.
pub(crate) struct Invocation<'a> {
    /// Determines the authoritative set of rule kinds consulted.
    pub seam: Seam,
    /// Adapter identity in reports; a hook/command label is also its tool.
    pub label: &'a str,
    input: Input<'a>,
}

impl<'a> Invocation<'a> {
    /// Normalize pathless prose without inferring a destination or path.
    pub(crate) const fn text(
        seam: Seam,
        label: &'a str,
        prose: Observed<&'a str>,
        headlines: &'a [Headline],
    ) -> Self {
        Self {
            seam,
            label,
            input: Input::Text(TextInput { prose, headlines }),
        }
    }

    /// Preserve the command grammar's named subject kinds for policy dispatch.
    pub(crate) const fn command(label: &'a str, subjects: &'a [Subject]) -> Self {
        Self {
            seam: Seam::Command,
            label,
            input: Input::Command(subjects),
        }
    }

    /// A tool name is independently observable, including when the tool's
    /// argument object contains no strings. A source filename is not a tool.
    pub(crate) fn tool(&self) -> Option<&str> {
        matches!(self.seam, Seam::Hook | Seam::Command).then_some(self.label)
    }

    /// A command cannot lose its scope by entering the pathless evaluator.
    pub(crate) fn text_input(&self) -> Result<&TextInput<'a>> {
        match &self.input {
            Input::Text(text) => Ok(text),
            Input::Command(_) => Err(Fatal::new(
                "command subjects require command scope and judgment; they cannot be judged as pathless text",
            )),
        }
    }

    /// Pathless text cannot acquire command subject kinds by guessing.
    pub(crate) fn command_subjects(&self) -> Result<&[Subject]> {
        match &self.input {
            Input::Command(subjects) => Ok(subjects),
            Input::Text(_) => Err(Fatal::new(
                "pathless text has no command-collected subject kinds",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_prose_keeps_tool_identity_and_unread_prose_is_an_error() {
        let invocation = Invocation::text(Seam::Hook, "publish_tool", Observed::Absent, &[]);
        assert_eq!(invocation.tool(), Some("publish_tool"));
        assert!(
            invocation
                .text_input()
                .unwrap()
                .prose
                .read()
                .unwrap()
                .is_none()
        );
        let unread = Invocation::text(
            Seam::Hook,
            "publish_tool",
            Observed::Unread("arguments could not be read".to_owned()),
            &[],
        );
        assert!(unread.text_input().unwrap().prose.read().is_err());
    }

    #[test]
    fn subject_shapes_cannot_silently_cross_evaluators() {
        let command = Invocation::command("faux", &[]);
        assert!(command.text_input().is_err());
        let text = Invocation::text(Seam::Scan, "body.md", Observed::Present(""), &[]);
        assert!(text.command_subjects().is_err());
        assert_eq!(text.tool(), None);
        assert_eq!(text.text_input().unwrap().prose.read().unwrap(), Some(&""));
    }
}
