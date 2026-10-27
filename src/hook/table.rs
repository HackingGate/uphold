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

/// One `[[hook]]` table as the policy file writes it. Read by [`Written::load`]
/// and by nothing else: what the rest of the crate holds is a [`Table`].
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(rename = "Hook")]
pub(crate) struct Written {
    /// A regular expression searched for in the call's tool name. The first
    /// table whose `tools` matches speaks for the call; the repository's own
    /// tables are read before the compiled-in ones.
    tools: String,
    /// Regular expressions searched for in the tool name of a call that
    /// reads. A call matching one is not judged at all.
    #[serde(default)]
    skip: Vec<String>,
    /// `forge-repo`, where the call names its repository in `owner` and
    /// `repo`; `none` (the default), where it names none.
    #[serde(default)]
    target: Target,
    /// The forge `owner/repo` is on, and the one asked about it. Required
    /// with `target = "forge-repo"`: a tool name says nothing about a host,
    /// and asking GitHub about a GitLab path answers about a stranger.
    #[serde(default)]
    forge: Option<HookForge>,
    /// RFC 6901 JSON pointer into the call's input, to the owner.
    #[serde(default)]
    owner: Option<String>,
    /// RFC 6901 JSON pointer into the call's input, to the repository.
    #[serde(default)]
    repo: Option<String>,
    /// The command these calls are the same act as, whose `[[shim]]` table
    /// in this repository supplies `scope` and `unresolved`: a call through
    /// the GitHub MCP server is judged where `gh` would be, by the answer the
    /// repository already wrote for `gh`. Not written beside either field.
    #[serde(default)]
    shim: Option<String>,
    /// When a rule standing at a publishing seam applies, where the rule
    /// writes no `command.scope` of its own. As on `[[shim]]`, and `always`
    /// where neither this nor `shim` says.
    #[serde(default)]
    scope: Option<Scope>,
    /// What to do where `scope` could not be evaluated: `refuse` (the
    /// default) or `run`. As on `[[shim]]`.
    #[serde(default)]
    unresolved: Option<Unresolved>,
}

/// The forges a `[[hook]]` destination may be on: github.com, asked by name.
///
/// Not GitLab. A GitLab project is on whichever instance its server publishes
/// to, nothing in a table names that host, and `glab` asked without one
/// answers for the instance it is configured for -- whose same-named private
/// project would stand a `public-target` rule down for a public one. A
/// GitLab destination waits for a field that names its host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum HookForge {
    GitHub,
}

/// Where a table's calls name their repository: the JSON pointers to the
/// owner and the repository in the call's input, on github.com.
#[derive(Debug, Clone)]
struct Pointers {
    owner: String,
    repo: String,
}

/// Where a table's scope and `unresolved` come from.
#[derive(Debug, Clone)]
pub(crate) enum Answers {
    /// The `[[shim]]` table for this command, in the repository's policy.
    Shim(String),
    /// The table's own, each defaulting as on `[[shim]]`.
    Own {
        scope: Option<Scope>,
        unresolved: Option<Unresolved>,
    },
}

/// One `[[hook]]` table, held to what a load can tell about it: its patterns
/// compiled, its destination whole or absent, and one source for its answers.
#[derive(Debug, Clone)]
pub(crate) struct Table {
    tools: Regex,
    skip: Vec<Regex>,
    destination: Option<Pointers>,
    pub(crate) answers: Answers,
}

impl Written {
    /// The table parsed into the shape that carries its checks, or the
    /// sentence for the refusal that names the policy file.
    pub(crate) fn load(self) -> std::result::Result<Table, String> {
        let tools_text = self.tools.clone();
        let compile = |pattern: &str| {
            Regex::new(pattern).map_err(|error| {
                format!(
                    "the `[[hook]]` for {tools_text:?} carries {pattern:?}, which is not a \
                     regular expression ({error})"
                )
            })
        };
        let tools = compile(&self.tools)?;
        let skip = self
            .skip
            .iter()
            .map(|pattern| compile(pattern))
            .collect::<std::result::Result<Vec<Regex>, String>>()?;
        for (key, pointer) in [("owner", &self.owner), ("repo", &self.repo)] {
            if let Some(pointer) = pointer
                && !pointer.starts_with('/')
            {
                return Err(format!(
                    "the `[[hook]]` for {tools_text:?} writes {key} = {pointer:?}, which is not a \
                     JSON pointer into the call's input. Write it as RFC 6901 spells one: \
                     \"/{key}\""
                ));
            }
        }
        let destination = match (self.target, self.forge, self.owner, self.repo) {
            (Target::ForgeRepo, Some(HookForge::GitHub), Some(owner), Some(repo)) => {
                Some(Pointers { owner, repo })
            }
            (Target::ForgeRepo, ..) => {
                return Err(format!(
                    "the `[[hook]]` for {tools_text:?} says `target = \"forge-repo\"` without all \
                     of `forge`, `owner` and `repo`. A destination is a forge and a repository on \
                     it; write the three, or take `target` off"
                ));
            }
            (Target::GitRemote, ..) => {
                return Err(format!(
                    "the `[[hook]]` for {tools_text:?} says `target = \"git-remote\"`. A tool \
                     call has no remote; it is `forge-repo` or `none`"
                ));
            }
            (Target::None, None, None, None) => None,
            (Target::None, ..) => {
                return Err(format!(
                    "the `[[hook]]` for {tools_text:?} writes `forge`, `owner` or `repo` without \
                     `target = \"forge-repo\"`, so nothing reads them. Add the target, or take \
                     them off"
                ));
            }
        };
        let answers = match (self.shim, self.scope, self.unresolved) {
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                return Err(format!(
                    "the `[[hook]]` for {tools_text:?} writes `shim` beside `scope` or \
                     `unresolved`. `shim` takes both from that command's `[[shim]]` table; write \
                     one or the other"
                ));
            }
            (_, Some(Scope::PublicRegistry), _) => {
                return Err(format!(
                    "the `[[hook]]` for {tools_text:?} says `scope = \"public-registry\"`, which \
                     reads an npm command line a tool call does not have"
                ));
            }
            (Some(command), None, None) => Answers::Shim(command),
            (None, scope, unresolved) => Answers::Own { scope, unresolved },
        };
        Ok(Table {
            tools,
            skip,
            destination,
            answers,
        })
    }
}

impl Table {
    /// The `tools` pattern as written, for a sentence that names the table.
    pub(crate) fn tools(&self) -> &str {
        self.tools.as_str()
    }

    /// The scope and `unresolved` this table's calls are judged under: the
    /// named `[[shim]]` table's, the table's own, or the defaults a `[[shim]]`
    /// has.
    fn answered(&self, shims: &[Shim]) -> (Scope, Unresolved) {
        match &self.answers {
            Answers::Shim(command) => shims
                .iter()
                .find(|shim| shim.command == *command)
                .map_or_else(Default::default, |shim| {
                    (shim.scope.clone(), shim.unresolved)
                }),
            Answers::Own { scope, unresolved } => (
                scope.clone().unwrap_or_default(),
                unresolved.unwrap_or_default(),
            ),
        }
    }

    /// Whether this table speaks for `tool`.
    pub(crate) fn names(&self, tool: &str) -> bool {
        self.tools.is_match(tool)
    }

    /// Whether `tool` is one of the reads this table passes unjudged.
    pub(crate) fn skips(&self, tool: &str) -> bool {
        self.skip.iter().any(|pattern| pattern.is_match(tool))
    }

    /// `owner/repo` as the call names it, or why it names none.
    fn destination(&self, input: Option<&Value>) -> std::result::Result<String, String> {
        let Some(Pointers { owner, repo }) = &self.destination else {
            return Err(format!(
                "the `[[hook]]` for {:?} names no destination, so whether the \
                 `public-target` checks apply could not be established",
                self.tools()
            ));
        };
        // One segment each: `owner = "acme/widget"` is not a GitHub owner, and
        // with `repo = "issues"` it would ask the forge about another path.
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
            if crate::shim::name_segment(value) {
                Ok(value.to_owned())
            } else {
                Err(format!(
                    "{value:?} at {pointer:?} is not a repository name, so whether the \
                     `public-target` checks apply could not be established"
                ))
            }
        };
        Ok(format!("{}/{}", read(owner)?, read(repo)?))
    }
}

/// One tool call's scope answers, each predicate asked at most once: the
/// hook's counterpart of the shim's `CommandContext`.
pub(crate) struct Scoping<'a> {
    table: Option<&'a Table>,
    /// The table's scope and `unresolved`, read once. See [`Table::answered`].
    answering: Option<(Scope, Unresolved)>,
    tool: &'a str,
    input: Option<&'a Value>,
    root: &'a Path,
    destination: OnceCell<std::result::Result<String, String>>,
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
            answering: table.map(|table| table.answered(shims)),
            tool,
            input,
            root,
            destination: OnceCell::new(),
            answers: BTreeMap::new(),
        }
    }

    fn resolved(&self) -> &std::result::Result<String, String> {
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
        self.resolved().as_ref().ok().map(String::as_str)
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
                    "uphold hook: {why}, so whether rule {:?} applies could not be asked. A \
                     check that could not look is not a check that passed, so the call was \
                     refused. Give {} a `[[hook]]` table that names its destination, or skips \
                     it as a read, or write `unresolved = \"run\"` on that table to let it \
                     through unchecked",
                    rule.id, self.tool
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
            // Not refused at load: the scope is right at the shim, and a policy
            // that loads at every other seam is not broken for this one's sake.
            Scope::PublicRegistry => {
                return Ok(Standing::CouldNotTell(String::from(
                    "a `public-registry` scope reads an npm command line, which a tool call \
                     does not have (a pattern or prose rule stays off this seam with `seams = \
                     [\"shim\"]`)",
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
                Ok(target) => crate::shim::named_standing(Forge::GitHub, target),
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

    fn written() -> Written {
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

    fn github() -> Table {
        written().load().unwrap()
    }

    #[test]
    fn a_read_is_skipped_and_a_write_is_not() {
        let table = github();
        assert!(table.names("mcp__github__get_file_contents"));
        assert!(table.skips("mcp__github__get_file_contents"));
        assert!(!table.skips("mcp__github__create_issue"));
        assert!(!table.names("mcp__slack__search"));
    }

    #[test]
    fn the_destination_is_read_at_the_pointers() {
        let input = serde_json::json!({"owner": "acme", "repo": "widget"});
        assert_eq!(github().destination(Some(&input)).unwrap(), "acme/widget");
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
            serde_json::json!({"owner": "acme/widget", "repo": "issues"}),
            serde_json::json!({"owner": "acme", "repo": "widget/issues"}),
        ] {
            assert!(github().destination(Some(&input)).is_err(), "{input}");
        }
    }

    #[test]
    fn a_table_the_load_cannot_read_is_refused_naming_why() {
        let refused = |edit: fn(&mut Written), why: &str| {
            let mut table = written();
            edit(&mut table);
            let error = table.load().unwrap_err();
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
        assert!(written().load().is_ok());
    }
}
