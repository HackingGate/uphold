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
use crate::error::Result;
use crate::shim::{Forge, Scope, Shim, Standing, Unresolved};

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
    /// The tools that read, each named exactly as the server names it: the
    /// whole of the tool name after where `tools` matched it. A call naming
    /// one publishes no text, so only rules about its tool name are asked.
    /// Names, not patterns: a tool nobody listed is judged in full, so a
    /// server's next tool is checked whatever its name looks like.
    #[serde(default)]
    skip: Vec<String>,
    /// `forge-repo`, where the call names its repository in `owner` and
    /// `repo`; `none` (the default), where it names none.
    #[serde(default)]
    target: HookTarget,
    /// The forge `owner/repo` is on, and the one asked about it. Required
    /// with `target = "forge-repo"`: a tool name says nothing about a host,
    /// and asking GitHub about a GitLab path answers about a stranger.
    #[serde(default)]
    forge: Option<HookForge>,
    /// JSON pointer (RFC 6901) into the call's input, to the owner. Not the
    /// empty pointer, which names the whole input: an object is never an
    /// owner's name.
    #[serde(default)]
    owner: Option<String>,
    /// JSON pointer (RFC 6901) into the call's input, to the repository. Not
    /// the empty pointer, as for `owner`.
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

/// Where a `[[hook]]` table's calls are going: the `[[shim]]` targets a tool
/// call can have. Not `git-remote`: a tool call has no remote, and a type of
/// its own keeps that out of the published schema as well as the load.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HookTarget {
    /// The call names its repository at `owner` and `repo`.
    ForgeRepo,
    /// The call names no destination.
    #[default]
    None,
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

/// One `[[hook]]` table, held to what a load can tell about it: its pattern
/// compiled, its reads named, its destination whole or absent, and one source
/// for its answers.
#[derive(Debug, Clone)]
pub(crate) struct Table {
    tools: Regex,
    skip: std::collections::BTreeSet<String>,
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
        if let Some(name) = self.skip.iter().find(|name| {
            name.contains("__")
                || name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
        }) {
            return Err(format!(
                "the `[[hook]]` for {tools_text:?} skips {name:?}, which is not a tool's name. \
                 `skip` names each read exactly as the server does, after the server's prefix \
                 that `tools` matches: \"get_file_contents\", not a pattern"
            ));
        }
        let skip = self.skip.into_iter().collect();
        for (key, pointer) in [("owner", &self.owner), ("repo", &self.repo)] {
            let Some(pointer) = pointer else {
                continue;
            };
            // RFC 6901 section 5 allows the empty pointer, naming the whole
            // document. Here that is the call's input, an object and never a
            // name, so this table takes the standard less that one pointer.
            if pointer.is_empty() {
                return Err(format!(
                    "the `[[hook]]` for {tools_text:?} writes {key} = \"\", the JSON pointer to \
                     the whole of the call's input. That is an object and never a name, so a \
                     `[[hook]]` table does not take it; point at the field: \"/{key}\""
                ));
            }
            // RFC 6901 section 3: otherwise a pointer starts with `/`, and `~`
            // is only ever the start of `~0` or `~1`.
            if !pointer.starts_with('/')
                || pointer
                    .split('~')
                    .skip(1)
                    .any(|rest| !rest.starts_with(['0', '1']))
            {
                return Err(format!(
                    "the `[[hook]]` for {tools_text:?} writes {key} = {pointer:?}, which is not a \
                     JSON pointer (RFC 6901): one starts with `/`, and writes `~` only as `~0` or \
                     `~1`. Point at the field: \"/{key}\""
                ));
            }
        }
        let destination = match (self.target, self.forge, self.owner, self.repo) {
            (HookTarget::ForgeRepo, Some(HookForge::GitHub), Some(owner), Some(repo)) => {
                Some(Pointers { owner, repo })
            }
            (HookTarget::ForgeRepo, ..) => {
                return Err(format!(
                    "the `[[hook]]` for {tools_text:?} says `target = \"forge-repo\"` without all \
                     of `forge`, `owner` and `repo`. A destination is a forge and a repository on \
                     it; write the three, or take `target` off"
                ));
            }
            (HookTarget::None, None, None, None) => None,
            (HookTarget::None, ..) => {
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

    /// Whether `tool` is one of the reads this table names: the whole of the
    /// tool name after where `tools` matched it, so `create_issue__get_file_contents`
    /// is not `get_file_contents`. A `tools` pattern that stops short of the
    /// separator leaves a remainder no name equals, and the call is judged.
    pub(crate) fn skips(&self, tool: &str) -> bool {
        self.tools
            .find(tool)
            .and_then(|found| tool.get(found.end()..))
            .is_some_and(|name| self.skip.contains(name))
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
        if rule.command.is_none() {
            return Ok(true);
        }
        let scope = crate::shim::own_scope(rule)
            .or_else(|| self.answering.as_ref().map(|(scope, _)| scope))
            .cloned();
        let answer = self.standing(scope.as_ref())?;
        crate::shim::runs(answer, self.unresolved(), |why| {
            format!(
                "uphold hook: {why}, so whether rule {:?} applies could not be asked. A check \
                 that could not look is not a check that passed, so the call was refused. Give \
                 {} a `[[hook]]` table that names its destination, or skips it as a read, or \
                 write `unresolved = \"run\"` on that table to let it through unchecked",
                rule.id, self.tool
            )
        })
    }

    /// The table's `unresolved`, and the default where no table names the call.
    fn unresolved(&self) -> Unresolved {
        self.answering
            .as_ref()
            .map_or_else(Unresolved::default, |(_, unresolved)| *unresolved)
    }

    /// The predicate's own answer, asked once per call. `None` is the scope of
    /// a rule no table speaks for. The `run` half of `unresolved` says its
    /// piece here, once per predicate, as the shim's memo does.
    fn standing(&mut self, scope: Option<&Scope>) -> Result<Standing> {
        let key = match scope {
            Some(Scope::Always) => return Ok(Standing::Holds),
            Some(Scope::PublicTarget) => String::from("public-target"),
            Some(Scope::PublicRegistry) => String::from("public-registry"),
            Some(Scope::Command { command }) => format!("command:{command}"),
            None => String::from("unnamed"),
        };
        if let Some(answer) = self.answers.get(&key) {
            return Ok(answer.clone());
        }
        let answer = match scope {
            Some(Scope::Command { command }) => {
                crate::shim::command_standing("uphold hook", command, self.root)?
            }
            // Not refused at load: the scope is right at the shim, and a policy
            // that loads at every other seam is not broken for this one's sake.
            Some(Scope::PublicRegistry) => Standing::CouldNotTell(String::from(
                "a `public-registry` scope reads an npm command line, which a tool call does \
                 not have (a pattern or prose rule stays off this seam with `seams = \
                 [\"shim\"]`)",
            )),
            None => Standing::CouldNotTell(self.unnamed()),
            _ => match self.resolved() {
                Ok(target) => crate::shim::named_standing(Forge::GitHub, target),
                Err(why) => Standing::CouldNotTell(why.clone()),
            },
        };
        if let (Standing::CouldNotTell(why), Unresolved::Run) = (&answer, self.unresolved()) {
            crate::shim::ran_unchecked("uphold hook", why);
        }
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
            tools = '^mcp__(plugin_[a-z0-9_-]+_)?github__'
            skip = ["get_file_contents", "issue_read"]
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
        assert!(table.skips("mcp__plugin_engineering_github__issue_read"));
        // A name nobody listed is judged, whatever it looks like, and so is
        // one that only ends in a listed name.
        assert!(!table.skips("mcp__github__create_issue__get_file_contents"));
        assert!(!table.skips("mcp__github__get_something_new"));
        assert!(!table.skips("mcp__github__mark_all_notifications_read"));
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
        refused(
            |table| table.target = HookTarget::None,
            "nothing reads them",
        );
        refused(
            |table| table.owner = Some(String::from("owner")),
            "JSON pointer",
        );
        refused(
            |table| table.owner = Some(String::from("/owner~2")),
            "JSON pointer",
        );
        refused(
            |table| table.owner = Some(String::new()),
            "the whole of the call's input",
        );
        refused(
            |table| table.skip = vec![String::from("(get|list)_")],
            "not a tool's name",
        );
        refused(
            |table| table.scope = Some(Scope::Always),
            "one or the other",
        );
        assert!(written().load().is_ok());
    }

    /// The pointers RFC 6901 section 5 gives as examples, less the empty one,
    /// load; and each reads the value the RFC says it does from the RFC's own
    /// document, through the same `Value::pointer` the hook reads a call with.
    #[test]
    fn the_rfc_6901_examples_load_and_resolve() {
        let document = serde_json::json!({
            "foo": ["bar", "baz"], "": 0, "a/b": 1, "c%d": 2, "e^f": 3, "g|h": 4,
            "i\\j": 5, "k\"l": 6, " ": 7, "m~n": 8,
        });
        for (pointer, expected) in [
            ("/foo", serde_json::json!(["bar", "baz"])),
            ("/foo/0", serde_json::json!("bar")),
            ("/", serde_json::json!(0)),
            ("/a~1b", serde_json::json!(1)),
            ("/c%d", serde_json::json!(2)),
            ("/e^f", serde_json::json!(3)),
            ("/g|h", serde_json::json!(4)),
            ("/i\\j", serde_json::json!(5)),
            ("/k\"l", serde_json::json!(6)),
            ("/ ", serde_json::json!(7)),
            ("/m~0n", serde_json::json!(8)),
        ] {
            let mut table = written();
            table.owner = Some(pointer.to_owned());
            assert!(table.load().is_ok(), "{pointer}");
            assert_eq!(document.pointer(pointer), Some(&expected), "{pointer}");
        }
    }
}
