//! `[[hook]]` -- which tool calls publish, and where to.
//!
//! The two facts the shim reads off a command line, and a tool call carries in
//! no shape this binary can know in advance. A harness's matcher decides which
//! calls arrive, and once one matcher serves every consumer, what arrives
//! includes reads: a call that fetches a file from a private repository names
//! that repository and publishes nothing. A table says, per server, which
//! calls are judged and where the judged ones go, so each rule's scope is asked
//! the question the shim asks of the same act made through `gh`.
//!
//! Which calls are judged is a `skip` list of reads, and not a list of
//! writes. A tool nobody listed is judged: a server that adds a publishing
//! call next week is checked the day it arrives, and a read nobody listed
//! costs a refusal somebody reads, rather than a write nobody saw.

use std::cell::OnceCell;
use std::collections::BTreeMap;
use std::path::Path;

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use crate::config::Rule;
use crate::error::{Fatal, Result};
use crate::shim::{Forge, Scope, Shim, Standing, Target, Unresolved};

/// One `[[hook]]` table: the tool calls it names, and what it knows of them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct Table {
    /// A regular expression searched for in the call's tool name. The first
    /// table whose `tools` matches speaks for the call; the repository's own
    /// tables are read before the ones its sets ship.
    pub tools: String,
    /// Regular expressions searched for in the tool name of a call that
    /// reads. A call matching one is not judged at all.
    #[serde(default)]
    pub skip: Vec<String>,
    /// `forge-repo`, where the call names its repository in `owner` and
    /// `repo`; `none` (the default), where it names none.
    #[serde(default)]
    pub target: Target,
    /// The forge `owner/repo` is on, and the one asked about it. Required
    /// with `target = "forge-repo"`: a tool name says nothing about a host,
    /// and asking GitHub about a GitLab path answers about a stranger.
    #[serde(default)]
    pub forge: Option<Forge>,
    /// RFC 6901 JSON pointer into the call's input, to the owner.
    #[serde(default)]
    pub owner: Option<String>,
    /// RFC 6901 JSON pointer into the call's input, to the repository.
    #[serde(default)]
    pub repo: Option<String>,
    /// The command these calls are the same act as, whose `[[shim]]` table
    /// in this repository supplies `scope` and `unresolved`: a call through
    /// the GitHub MCP server is judged where `gh` would be, by the answer the
    /// repository already wrote for `gh`. Not written beside either field.
    #[serde(default)]
    pub shim: Option<String>,
    /// When a rule standing at a publishing seam applies, where the rule
    /// writes no `command.scope` of its own. As on `[[shim]]`, and `always`
    /// where neither this nor `shim` says.
    #[serde(default)]
    pub scope: Option<Scope>,
    /// What to do where `scope` could not be evaluated: `refuse` (the
    /// default) or `run`. As on `[[shim]]`.
    #[serde(default)]
    pub unresolved: Option<Unresolved>,
}

/// A pattern a load has already compiled, compiled again where it is used.
fn compiled(pattern: &str) -> Result<Regex> {
    Regex::new(pattern)
        .map_err(|error| Fatal::new(format!("`[[hook]]` pattern {pattern:?}: {error}")))
}

impl Table {
    /// The scope and `unresolved` this table's calls are judged under: the
    /// named `[[shim]]` table's, the table's own, or the defaults a `[[shim]]`
    /// has.
    pub(crate) fn answers(&self, shims: &[Shim]) -> (Scope, Unresolved) {
        self.shim.as_ref().map_or_else(
            || {
                (
                    self.scope.clone().unwrap_or_default(),
                    self.unresolved.unwrap_or_default(),
                )
            },
            |command| {
                shims
                    .iter()
                    .find(|shim| shim.command == *command)
                    .map_or_else(Default::default, |shim| {
                        (shim.scope.clone(), shim.unresolved)
                    })
            },
        )
    }

    /// Whether this table speaks for `tool`.
    pub(crate) fn names(&self, tool: &str) -> Result<bool> {
        Ok(compiled(&self.tools)?.is_match(tool))
    }

    /// Whether `tool` is one of the reads this table passes unjudged.
    pub(crate) fn skips(&self, tool: &str) -> Result<bool> {
        for pattern in &self.skip {
            if compiled(pattern)?.is_match(tool) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The table held to what a load can tell about it, as a sentence for the
    /// refusal that names the policy file.
    pub(crate) fn validate(&self) -> std::result::Result<(), String> {
        for pattern in std::iter::once(&self.tools).chain(&self.skip) {
            if let Err(error) = Regex::new(pattern) {
                return Err(format!(
                    "the `[[hook]]` for {:?} carries {pattern:?}, which is not a regular \
                     expression ({error})",
                    self.tools
                ));
            }
        }
        for (key, pointer) in [("owner", &self.owner), ("repo", &self.repo)] {
            if let Some(pointer) = pointer
                && !pointer.starts_with('/')
            {
                return Err(format!(
                    "the `[[hook]]` for {:?} writes {key} = {pointer:?}, which is not a JSON \
                     pointer into the call's input. Write it as RFC 6901 spells one: \"/{key}\"",
                    self.tools
                ));
            }
        }
        let declared = [
            self.forge.is_some(),
            self.owner.is_some(),
            self.repo.is_some(),
        ];
        match self.target {
            Target::ForgeRepo if declared.contains(&false) => Err(format!(
                "the `[[hook]]` for {:?} says `target = \"forge-repo\"` without all of \
                 `forge`, `owner` and `repo`. A destination is a forge and a repository on it; \
                 write the three, or take `target` off",
                self.tools
            )),
            Target::None if declared.contains(&true) => Err(format!(
                "the `[[hook]]` for {:?} writes `forge`, `owner` or `repo` without `target = \
                 \"forge-repo\"`, so nothing reads them. Add the target, or take them off",
                self.tools
            )),
            Target::GitRemote => Err(format!(
                "the `[[hook]]` for {:?} says `target = \"git-remote\"`. A tool call has no \
                 remote; it is `forge-repo` or `none`",
                self.tools
            )),
            _ if self.shim.is_some() && (self.scope.is_some() || self.unresolved.is_some()) => {
                Err(format!(
                    "the `[[hook]]` for {:?} writes `shim` beside `scope` or `unresolved`. \
                     `shim` takes both from that command's `[[shim]]` table; write one or the \
                     other",
                    self.tools
                ))
            }
            _ => match self.scope {
                Some(Scope::PublicRegistry) => Err(format!(
                    "the `[[hook]]` for {:?} says `scope = \"public-registry\"`, which reads an \
                     npm command line a tool call does not have",
                    self.tools
                )),
                _ => Ok(()),
            },
        }
    }

    /// `owner/repo` as the call names it, or why it names none.
    fn destination(&self, input: Option<&Value>) -> std::result::Result<(Forge, String), String> {
        let (Target::ForgeRepo, Some(forge), Some(owner), Some(repo)) =
            (self.target, self.forge, &self.owner, &self.repo)
        else {
            return Err(format!(
                "the `[[hook]]` for {:?} names no destination, so whether the \
                 `public-target` checks apply could not be established",
                self.tools
            ));
        };
        let read = |pointer: &str| -> std::result::Result<String, String> {
            let value = input
                .and_then(|input| input.pointer(pointer))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "the call carries no string at {pointer:?}, where its `[[hook]]` table \
                         says the destination is, so whether the `public-target` checks apply \
                         could not be established"
                    )
                })?;
            // The value goes into a forge API path. A segment that is empty, a
            // dot path, or carries a character no forge name has is a request
            // for some other endpoint, and is not asked.
            if value.split('/').all(|segment| {
                !segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
            }) {
                Ok(value.to_owned())
            } else {
                Err(format!(
                    "{value:?} at {pointer:?} is not a repository name, so whether the \
                     `public-target` checks apply could not be established"
                ))
            }
        };
        Ok((forge, format!("{}/{}", read(owner)?, read(repo)?)))
    }
}

/// One tool call's scope answers, each predicate asked at most once: the
/// hook's counterpart of the shim's `CommandContext`.
pub(crate) struct Scoping<'a> {
    table: Option<&'a Table>,
    /// The table's scope and `unresolved`, read once. See [`Table::answers`].
    answering: Option<(Scope, Unresolved)>,
    tool: &'a str,
    input: Option<&'a Value>,
    root: &'a Path,
    destination: OnceCell<std::result::Result<(Forge, String), String>>,
    answers: BTreeMap<String, Standing>,
}

impl<'a> Scoping<'a> {
    pub(crate) fn new(
        table: Option<&'a Table>,
        shims: &[Shim],
        tool: &'a str,
        input: Option<&'a Value>,
        root: &'a Path,
    ) -> Self {
        Self {
            table,
            answering: table.map(|table| table.answers(shims)),
            tool,
            input,
            root,
            destination: OnceCell::new(),
            answers: BTreeMap::new(),
        }
    }

    fn resolved(&self) -> &std::result::Result<(Forge, String), String> {
        self.destination.get_or_init(|| {
            self.table.map_or_else(
                || Err(self.unnamed()),
                |table| table.destination(self.input),
            )
        })
    }

    fn unnamed(&self) -> String {
        format!(
            "no `[[hook]]` table names {}, so where it publishes is unknown",
            self.tool
        )
    }

    /// `owner/repo` the call publishes to, where its table says. Handed to the
    /// text guards, which exempt the destination's own name, as at the shim.
    pub(crate) fn destination(&self) -> Option<&str> {
        self.resolved()
            .as_ref()
            .ok()
            .map(|(_, target)| target.as_str())
    }

    /// Whether `rule` applies to this call.
    ///
    /// Only a rule standing at a publishing seam -- one with a `command`
    /// section -- has a scope a table speaks for. A git-hook guard or a
    /// literal rule reached here was never scoped by anybody, and reading a
    /// table at it would stand down a check nobody scoped, which is the line
    /// the shim draws for a rule its consultation reaches.
    pub(crate) fn holds(&mut self, rule: &Rule) -> Result<bool> {
        let Some(command) = &rule.command else {
            return Ok(true);
        };
        let scope = command
            .scope
            .clone()
            .or_else(|| self.answering.as_ref().map(|(scope, _)| scope.clone()));
        let standing = match scope {
            Some(scope) => self.standing(&scope)?,
            None => Standing::CouldNotTell(self.unnamed()),
        };
        let unresolved = self
            .answering
            .as_ref()
            .map_or_else(Unresolved::default, |(_, unresolved)| *unresolved);
        match standing {
            Standing::Holds => Ok(true),
            Standing::DoesNotHold => Ok(false),
            Standing::CouldNotTell(why) => match unresolved {
                Unresolved::Refuse => Err(Fatal::new(format!(
                    "uphold hook: {why}. A check that could not look is not a check that \
                     passed, so the call was refused. Give {} a `[[hook]]` table that names \
                     its destination, or skips it as a read, or write `unresolved = \"run\"` on \
                     that table to let it through unchecked",
                    self.tool
                ))),
                Unresolved::Run => {
                    if self
                        .answers
                        .insert(String::from("unresolved"), Standing::DoesNotHold)
                        .is_none()
                    {
                        eprintln!(
                            "uphold hook: {why}, and the call went ahead with its \
                             destination-scoped checks stood down. This is not a pass."
                        );
                    }
                    Ok(false)
                }
            },
        }
    }

    fn standing(&mut self, scope: &Scope) -> Result<Standing> {
        let key = match scope {
            Scope::Always => return Ok(Standing::Holds),
            Scope::PublicTarget => String::from("public-target"),
            Scope::PublicRegistry => {
                return Ok(Standing::CouldNotTell(String::from(
                    "a `public-registry` scope reads an npm command line, which a tool call \
                     does not have",
                )));
            }
            Scope::Command { command } => format!("command:{command}"),
        };
        if let Some(answer) = self.answers.get(&key) {
            return Ok(answer.clone());
        }
        let answer = match scope {
            Scope::Command { command } => {
                crate::shim::command_standing("uphold hook", command, self.root)?
            }
            _ => match self.resolved() {
                Ok((forge, target)) => crate::shim::named_standing(*forge, target),
                Err(why) => Standing::CouldNotTell(why.clone()),
            },
        };
        self.answers.insert(key, answer.clone());
        Ok(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn github() -> Table {
        toml::from_str(
            r#"
            tools = "^mcp__github__"
            skip = ["__(get|list|search)_"]
            target = "forge-repo"
            forge = "github"
            owner = "/owner"
            repo = "/repo"
            shim = "gh"
            "#,
        )
        .unwrap()
    }

    #[test]
    fn a_read_is_skipped_and_a_write_is_not() {
        let table = github();
        assert!(table.names("mcp__github__get_file_contents").unwrap());
        assert!(table.skips("mcp__github__get_file_contents").unwrap());
        assert!(!table.skips("mcp__github__create_issue").unwrap());
        assert!(!table.names("mcp__slack__search").unwrap());
    }

    #[test]
    fn the_destination_is_read_at_the_pointers() {
        let input = serde_json::json!({"owner": "acme", "repo": "widget"});
        let (forge, target) = github().destination(Some(&input)).unwrap();
        assert_eq!((forge, target.as_str()), (Forge::GitHub, "acme/widget"));
    }

    /// A destination the call does not carry, or carries in a shape no forge
    /// name has, is no destination -- never a path handed to the forge API.
    #[test]
    fn a_missing_or_malformed_destination_is_unresolved() {
        for input in [
            serde_json::json!({"owner": "acme"}),
            serde_json::json!({"owner": "acme", "repo": 7}),
            serde_json::json!({"owner": "..", "repo": "widget"}),
            serde_json::json!({"owner": "acme", "repo": "widget?per_page=1"}),
        ] {
            assert!(github().destination(Some(&input)).is_err(), "{input}");
        }
    }

    #[test]
    fn a_table_the_load_cannot_read_is_refused_naming_why() {
        let refused = |edit: fn(&mut Table), why: &str| {
            let mut table = github();
            edit(&mut table);
            let error = table.validate().unwrap_err();
            assert!(error.contains(why), "{error}");
        };
        refused(|table| table.forge = None, "without all of");
        refused(|table| table.target = Target::None, "nothing reads them");
        refused(
            |table| table.owner = Some(String::from("owner")),
            "JSON pointer",
        );
        refused(
            |table| table.skip = vec![String::from("(")],
            "regular expression",
        );
        refused(
            |table| table.scope = Some(Scope::Always),
            "one or the other",
        );
        assert!(github().validate().is_ok());
    }
}
