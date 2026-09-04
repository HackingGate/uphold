//! `uphold shim` -- the guard on the path a git hook cannot reach.
//!
//! A pull-request body is typed into a CLI and goes straight to a public API
//! without passing a single hook. So does an issue title, a release note, a
//! branch name, and a commit message written under `--no-verify` -- which is the
//! one path that exists precisely to skip `commit-msg`.
//!
//! The shim runs UNDER the command's own name, checks what the invocation is
//! about to publish, and execs through. Which is why this is a multicall
//! binary: `argv[0]` decides. That ends `install.sh` and the sibling-checkout
//! coupling, where a shim shelled into adjacent clones of two other
//! repositories to find its checkers.
//!
//! Where those links live, and what puts them within a shell's reach, is
//! `install`. This module is what happens once one is reached.
//!
//! ## Most of a spec was already data
//!
//! `SPEC_MATCH` and the `SPEC_*_FLAGS` were space-separated lists in a bash
//! file, so they are lists in a TOML table now and nothing was lost. Only two
//! functions carried logic, and reading all four specs confirms what became of
//! them:
//!
//! * `spec_target` is a forge API call in two specs and git-remote-URL parsing
//!   in the third. Both are built-in resolvers -- URL parsing is engine work
//!   anyway, and every spec that wanted it wrote the same thing.
//! * `spec_in_scope` is exactly `visibility == "public"` in the gh, glab and git
//!   specs. **npm is the exception**, and it is why `scope` is an enum rather
//!   than a boolean: npm asks whether the registry is the public one and
//!   whether `package.json` says `"private": true`. There is no repository, no
//!   owner and no visibility endpoint anywhere in that sentence, and bending a
//!   forge's question to fit is how a framework quietly becomes the shape of its
//!   first two examples.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;

use crate::config::{Policy, Rule};
use crate::error::{Exit, Fatal, Result};
use crate::git;

/// Where an invocation is going, when that is a meaningful question at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Target {
    /// Ask the command itself which repository it is operating on.
    ForgeRepo,
    /// Parse it out of a git remote URL.
    GitRemote,
    /// The command has no notion of a destination.
    #[default]
    None,
}

/// Whether this invocation publishes to somewhere that matters.
#[derive(Debug, Clone, Deserialize, serde::Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Scope {
    /// `visibility == "public"` on the target repository. `internal` is
    /// deliberately NOT counted: it is not public to the internet but is public
    /// to everyone with an account, which is not a distinction worth betting a
    /// private repository's name on.
    PublicTarget,
    /// The public package registry, and a package not marked private.
    PublicRegistry,
    /// Always in scope. The right default for a command with no destination:
    /// a spec that HAS a scope predicate says so, rather than inheriting a
    /// forge's idea of the question.
    #[default]
    Always,
    /// An escape hatch, for a command whose question is neither of the above.
    /// Exit 0 to be in scope.
    Command { command: String },
}

/// Whether one scope predicate holds, or could not be asked at all.
///
/// The third answer is the whole of this type. `PublicTarget` asks a forge, and
/// a forge that cannot be reached -- no `gh`, no credentials, a rate limit, a
/// repository with no `origin` -- answers nothing. That was folded into "does
/// not hold", which reads at every call site as "the policy decided these
/// checks do not apply here", and the caller then skips the checkers. One of
/// those checkers is [`crate::guard::target_refusal`], whose own contract is
/// exit `2` on a destination it could not resolve, so the fold turned a
/// documented refusal into a silent exec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Standing {
    /// The predicate was asked and said yes.
    Holds,
    /// The predicate was asked and said no. A decision, not a gap.
    DoesNotHold,
    /// Nothing here could say, and the sentence explaining why.
    CouldNotTell(String),
}

/// What a shim does with a scope predicate that could not be asked.
///
/// `refuse` is the default and the reading the rest of this tool takes: an
/// unobserved property must not resolve to success. `run` is the older
/// behaviour, kept as an opt-in for a workspace whose forge is routinely
/// unreachable and who would rather have the command than the answer -- it
/// still says on stderr that no checker ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Unresolved {
    /// Refuse the invocation with exit 2, having published nothing.
    #[default]
    Refuse,
    /// Run the command, saying on stderr that this is not a pass.
    Run,
}

/// How this command's subjects are found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Collect {
    /// Walk argv once, reading the flags the table names.
    #[default]
    Flags,
    /// Branch and tag names, which are positional. `git push origin
    /// fix/acme-outage` puts that name on a public forge, in the ref list, in
    /// the pull request it suggests, and in every notification -- and pre-push
    /// is handed the refs, but the guards that read them judge the DESTINATION
    /// and never the name itself.
    GitRefs,
    /// A package's metadata and its tree. What `npm publish` sends is a FILE
    /// TREE -- README, description, keywords, everything not excluded -- so the
    /// subject kinds are `text` for the metadata and `path` for the tree.
    NpmPackage,
}

/// A flag vocabulary that holds only for the verbs it names.
///
/// One command does not have one grammar. `-c` on `gh pr review` is a boolean
/// -- "Comment on a pull request" -- and `-c` on `gh issue close` takes a value
/// -- "Leave a closing comment". A single `text_flags` cannot hold both: name
/// `-c` there and a review's `-c` swallows the flag after it, so the body that
/// review is publishing goes unread. Leave it out and a closing comment is
/// published with nothing in front of it. Both are false negatives in the seam
/// that exists to prevent exactly that.
///
/// The lists here REPLACE the table's for the verbs this entry names rather
/// than adding to them, which is the rule `allowed_scripts` already follows for
/// the same reason: what is declared beside the narrower thing is the whole
/// truth for it, and a union would mean a vocabulary nobody wrote.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerbFlags {
    /// `verb:noun` or `verb:*`, in the spelling the table's own `match` uses.
    /// Every entry must also be matched by the table, because a vocabulary for
    /// a verb the shim does not stand in front of is read by nothing.
    #[serde(default, rename = "match")]
    pub match_: Vec<String>,
    #[serde(default)]
    pub text_flags: Vec<String>,
    #[serde(default)]
    pub title_flags: Vec<String>,
    #[serde(default)]
    pub file_flags: Vec<String>,
    #[serde(default)]
    pub path_flags: Vec<String>,
    #[serde(default)]
    pub skip_flags: Vec<String>,
    #[serde(default)]
    pub web_flags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Shim {
    /// The command this stands in front of.
    pub command: String,
    /// `verb:noun`, `verb:*`, or `*`. Named rather than pattern-matched: a shim
    /// that guesses which subcommands carry text is one release away from
    /// either missing a new one in silence or blocking one that never carried
    /// any, and only the first failure is visible.
    #[serde(default, rename = "match")]
    pub match_: Vec<String>,
    #[serde(default)]
    pub text_flags: Vec<String>,
    /// Flags whose value is a TITLE -- a name the forge shows above the body.
    /// A separate kind rather than more `text_flags`, for both directions of
    /// the difference: a format rule about titles must not be asked about a
    /// body, and a title given alone must not read as "the body was supplied"
    /// -- which is what `text_flags` marks, and what used to close the editor
    /// checkpoint over the body the command was about to open an editor for.
    #[serde(default)]
    pub title_flags: Vec<String>,
    #[serde(default)]
    pub file_flags: Vec<String>,
    #[serde(default)]
    pub path_flags: Vec<String>,
    #[serde(default)]
    pub target_flags: Vec<String>,
    /// Flags that mean a body was supplied from somewhere already checked.
    #[serde(default)]
    pub skip_flags: Vec<String>,
    #[serde(default)]
    pub web_flags: Vec<String>,
    #[serde(default)]
    pub argv_subject: bool,
    /// The environment variable this command reads to find its editor.
    ///
    /// Declared so the shim can stand in the one place argv cannot reach: no
    /// body on the command line, no `--web`, and a command about to open an
    /// editor. What gets typed there has not been written yet, so the shim puts
    /// itself in this variable, runs the user's real editor, and reads the file
    /// back -- the checkpoint `commit-msg` is for a commit.
    #[serde(default)]
    pub editor_env: Option<String>,
    #[serde(default)]
    pub target: Target,
    #[serde(default)]
    pub scope: Scope,
    /// What to do where `scope` could not be evaluated at all.
    ///
    /// `refuse` (the default) or `run`. Only `public-target` can reach this: it
    /// is the one predicate that asks somebody else, and a forge that cannot be
    /// asked has said nothing. Refused at load beside a table no reading of
    /// which can produce that answer, because a parameter nothing reads is
    /// configuration that looks like it works.
    #[serde(default)]
    pub unresolved: Unresolved,
    #[serde(default)]
    pub collect: Collect,
    /// Flag vocabularies for verbs whose grammar differs from the table's.
    ///
    /// `target_flags` is deliberately not overridable: `-R`/`--repo` means the
    /// same thing on every verb of a command, and a per-verb answer to "which
    /// repository is this going to" would be a way to publish somewhere the
    /// table did not expect.
    #[serde(default, rename = "verbs")]
    pub verbs: Vec<VerbFlags>,
}

/// One thing about to be published, and what kind of thing it is.
///
/// The kind is not decoration. A checker that greps prose for a private name
/// and one that judges a branch name are not the same checker, and only the
/// kind tells them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Subject {
    pub kind: &'static str,
    pub value: String,
}

fn in_list(list: &[String], needle: &str) -> bool {
    list.iter().any(|item| item == needle)
}

/// Commands whose verb may be a name the command itself expands.
///
/// Grammar rather than policy, beside [`VALUE_OPTIONS`] and for the same
/// reason: nothing in a `[[shim]]` says that `git` reads `alias.*` out of its
/// config, and no policy author should have to write it there to be guarded.
const ALIAS_COMMANDS: &[&str] = &["git", "gh", "glab"];

/// Commands whose `api` verb is the whole forge behind one word.
///
/// Grammar rather than policy, beside [`ALIAS_COMMANDS`] and for the same
/// reason. `gh pr edit --body ...` is a verb a `match` list can name; `gh api
/// -X PATCH repos/OWNER/REPO/pulls/N -F body=@file` publishes the same body
/// through the same account, and every table this tool ships named the first
/// and not the second -- so an agent whose token could not run `gh pr edit`
/// reached for `gh api` and the shim exec'd it with nothing printed. The hole
/// is not that `api` was forgotten: it is that ONE verb is both the read side
/// and the write side of a forge, so naming it in a `match` list the way
/// `pr:create` is named would stand in front of every `gh api` GET on the
/// machine -- including [`Shim::visibility`], which is this shim asking a forge
/// a question. Which half an invocation is, is a question about its argv, and
/// that is what [`ApiCall`] reads.
const FORGE_API_COMMANDS: &[&str] = &["gh", "glab"];

/// The `api` options that name the HTTP method.
const API_METHOD_FLAGS: &[&str] = &["-X", "--method"];

/// The `api` options that carry one `key=value` of a body.
///
/// Both commands spell the typed field and the raw one differently -- `gh` has
/// `-F/--field` typed and `-f/--raw-field` raw, `glab` has `-f/--field` -- and
/// this list deliberately does not try to tell them apart. A field is a field:
/// its value is published either way, and reading all four spellings the same
/// way costs a subject nobody minds being asked about, while telling them apart
/// wrongly costs a body nobody read.
const API_FIELD_FLAGS: &[&str] = &["-f", "--field", "-F", "--raw-field"];

/// The `api` option that names a file holding the whole body.
const API_INPUT_FLAGS: &[&str] = &["--input"];

/// Every other `api` option that takes the word after it.
///
/// Listed for the sake of the words they would otherwise leave loose: the
/// endpoint path is positional, and an option whose value nothing here
/// classifies would be read as the path -- which is the destination this seam
/// resolves the repository from.
const API_OTHER_VALUE_FLAGS: &[&str] = &[
    "-H",
    "--header",
    "-q",
    "--jq",
    "-t",
    "--template",
    "--cache",
    "--hostname",
    "-p",
    "--preview",
];

/// One `gh api` or `glab api` invocation, read off the words after the verb.
///
/// Read with the `api` verb's own grammar rather than through the table's flag
/// lists, and the two cannot be merged: `-F` is `--body-file` on `gh pr create`
/// and `--field` on `gh api`, so one vocabulary answering for both would read a
/// `key=@file` pair as a path or a body file as a field. `[[shim.verbs]]` is
/// the policy-level shape of the same fact; this is the shape it takes when the
/// grammar belongs to the command rather than to a repository's reading of it.
#[derive(Debug, Default)]
struct ApiCall {
    /// Every word that is neither an option nor an option's value. The endpoint
    /// path is the first of them.
    positional: Vec<String>,
    /// What `-X` named, where it was given.
    method: Option<String>,
    /// The flag and the `key=value` of every field, in the order they were
    /// given. The flag is kept because a refusal names the flag a reader has to
    /// go and fix.
    fields: Vec<(String, String)>,
    /// The file `--input` named.
    input: Option<String>,
}

impl ApiCall {
    /// The words after `api`, read as that verb's grammar.
    fn of(rest: &[String]) -> Self {
        let mut call = Self::default();
        let mut index = 0;
        while let Some(argument) = rest.get(index) {
            index += 1;
            // `--` ends the options; what follows is positional however it is
            // spelt.
            if argument == "--" {
                call.positional
                    .extend(rest.get(index..).unwrap_or_default().iter().cloned());
                break;
            }
            if !argument.starts_with('-') || argument == "-" {
                call.positional.push(argument.clone());
                continue;
            }
            let (flag, inline) = match argument.split_once('=') {
                Some((flag, value)) if argument.starts_with("--") => {
                    (flag.to_owned(), Some(value.to_owned()))
                }
                _ => (argument.clone(), None),
            };
            let name = flag.as_str();
            if !(API_METHOD_FLAGS.contains(&name)
                || API_FIELD_FLAGS.contains(&name)
                || API_INPUT_FLAGS.contains(&name)
                || API_OTHER_VALUE_FLAGS.contains(&name))
            {
                // `--paginate`, `--silent`, `-i`, `--slurp`: options that take
                // nothing, and the word after one of them is the next word.
                continue;
            }
            let Some(value) = inline.or_else(|| {
                // The word after it, where there is one. An option at the end
                // of argv took nothing whatever its grammar says.
                let next = rest.get(index).cloned();
                index += usize::from(next.is_some());
                next
            }) else {
                continue;
            };
            if API_METHOD_FLAGS.contains(&name) {
                call.method = Some(value);
            } else if API_FIELD_FLAGS.contains(&name) {
                call.fields.push((flag, value));
            } else if API_INPUT_FLAGS.contains(&name) {
                call.input = Some(value);
            }
        }
        call
    }

    /// Whether this call carries a body at all.
    ///
    /// The read half of the verb is left alone deliberately. `gh api
    /// repos/OWNER/REPO` fetches, publishes nothing, and is what
    /// [`Shim::visibility`] runs to answer the `public-target` question -- so a
    /// shim that stood in front of it would be a shim standing in front of its
    /// own lookup. A method other than GET is the explicit half; a field or an
    /// `--input` is the implicit one, because `gh` switches to POST the moment
    /// either is given.
    fn publishes(&self) -> bool {
        if !self.fields.is_empty() || self.input.is_some() {
            return true;
        }
        self.method
            .as_deref()
            .is_some_and(|method| !method.eq_ignore_ascii_case("GET"))
    }

    /// The repository this call is aimed at, where the path names one.
    ///
    /// The same `owner/repo` the `--repo` of every other verb resolves to, so
    /// `prevent-unowned-target` and a `public-target` scope read a `gh api`
    /// destination exactly as they read a `gh pr create` one. A path that names
    /// no repository -- `gh api graphql`, `gh api user` -- resolves to nothing
    /// here and falls through to the table's own resolver, which is the bound
    /// on this: the destination of a GraphQL mutation is inside its query, and
    /// nothing in a path can say.
    fn target(&self) -> Option<String> {
        self.positional
            .iter()
            .find_map(|word| repo_in_api_path(word))
    }
}

/// `OWNER/REPO` out of a forge API path, in either forge's spelling.
///
/// GitHub puts it in the path (`repos/OWNER/REPO/pulls/1`); GitLab addresses a
/// project by one url-encoded id (`projects/OWNER%2FREPO`), which is the same
/// two names with the separator escaped.
fn repo_in_api_path(path: &str) -> Option<String> {
    // A whole URL is a legal endpoint, and a query string is no part of any
    // name: `repos/o/r/issues?state=open` names the same repository as
    // `https://api.github.com/repos/o/r`.
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let path = match path.split_once("://") {
        Some((_, rest)) => rest.split_once('/').map_or("", |(_, rest)| rest),
        None => path,
    };
    let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    for (index, segment) in segments.iter().enumerate() {
        if *segment == "repos" {
            if let (Some(owner), Some(repo)) = (segments.get(index + 1), segments.get(index + 2)) {
                return Some(format!("{owner}/{repo}"));
            }
        }
        if *segment == "projects" {
            if let Some(id) = segments.get(index + 1) {
                let decoded = id.replace("%2F", "/").replace("%2f", "/");
                // A numeric project id names a project this cannot resolve to
                // an owner, and guessing one would be a destination nobody
                // wrote.
                if decoded.contains('/') {
                    return Some(decoded);
                }
            }
        }
    }
    None
}

/// Every string in a JSON document, or nothing where the text is not one.
///
/// An `--input` file is a body, and a body that happens to be JSON hides its
/// text from a checker behind the encoding: `"body": "Generated with X\n"` is
/// one escaped string, and a prose rule reading the raw document reads the
/// escapes rather than the sentence. So the values are judged one at a time,
/// the way a `--field` value is. A file that is NOT JSON is judged whole, which
/// is what it is.
fn json_strings(text: &str) -> Option<Vec<String>> {
    // Deliberately strict, and deliberately not the YAML reader the rest of
    // this file uses on forge responses: YAML 1.2 is a superset of JSON, so an
    // ordinary Markdown body with a `Note: something` line parses as a mapping
    // and would be read for its "values" -- most of the body then reaching no
    // checker at all. A body is JSON when somebody wrote JSON.
    let trimmed = text.trim_start();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return None;
    }
    let parsed = serde_json::from_str::<serde_json::Value>(text).ok()?;
    let mut found = Vec::new();
    push_json_strings(&parsed, &mut found);
    Some(found)
}

fn push_json_strings(value: &serde_json::Value, into: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => into.push(text.clone()),
        serde_json::Value::Array(items) => {
            for item in items {
                push_json_strings(item, into);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                push_json_strings(item, into);
            }
        }
        _ => {}
    }
}

/// An `alias.<name>` set with `-c` on the command line, which outranks config.
fn command_line_alias(argv: &[String], word: &str) -> Option<String> {
    let wanted = format!("alias.{word}=");
    let mut index = 0;
    while let Some(argument) = argv.get(index) {
        index += 1;
        // `-c` takes the word after it. `git` accepts no `-c=<setting>`, so
        // the pair is the only spelling there is.
        if argument != "-c" {
            continue;
        }
        if let Some(setting) = argv.get(index) {
            index += 1;
            if let Some(value) = setting.strip_prefix(&wanted) {
                return Some(value.to_owned());
            }
        }
    }
    None
}

/// One alias out of what `gh alias list` or `glab alias list` printed.
///
/// Both print one alias per line as a name and an expansion, and neither
/// promises which separator: `co: pr checkout`, `co\tpr checkout` and
/// `co=pr checkout` have all been shipped. Splitting on the first of the three
/// reads every one of them, and a line that carries none is not an alias.
fn alias_in_list(text: &str, word: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (name, expansion) = line.split_once([':', '\t', '='])?;
        (name.trim() == word).then(|| expansion.trim().to_owned())
    })
}

/// A ref as a person reads it: `refs/heads/` off, and nothing where the name
/// was empty.
fn shortened(refname: &str) -> Option<&str> {
    let name = refname
        .strip_prefix("refs/heads/")
        .or_else(|| refname.strip_prefix("refs/tags/"))
        .unwrap_or(refname);
    (!name.is_empty()).then_some(name)
}

/// The names one reading of a `git push` command line would publish.
///
/// The subcommand, then the remote, then the refspecs: both leading words are
/// positions rather than names, since `push` is the verb the shim matched on
/// and a remote is a local nickname that is not itself published.
fn refspec_names(positional: &[&str]) -> Vec<String> {
    let mut names = Vec::new();
    for argument in positional.iter().skip(2) {
        // `+topic:topic` is `topic:topic`, forced. The `+` is grammar and no
        // part of any name, and leaving it on is a name no rule recognises: a
        // pattern standing in front of `fix/acme-outage` saw `+fix/acme-outage`
        // and reported clean, so the force-push was the way past it.
        let spec = argument.strip_prefix('+').unwrap_or(argument);
        // A refspec is `src:dst`; both halves are published, and `refs/heads/`
        // is noise rather than name.
        names.extend(spec.split(':').filter_map(shortened).map(str::to_owned));
    }
    names
}

/// Global options that take the word AFTER them, per command.
///
/// Grammar rather than policy, which is why it lives here and not in a
/// `[[shim]]` table: a table names the flags whose values this shim publishes,
/// and nothing in one says what `git -c` does. Skipping only the table's own
/// flags left `git -c user.name=x push origin topic` reading `user.name=x` as
/// the verb and `push` as the noun -- a pair no `match` list contains, so the
/// shim decided a push to a public forge was none of its business and exec'd it
/// unexamined, printing nothing and exiting 0.
///
/// `--git-dir`, `--work-tree`, `--namespace` and `--config-env` are documented
/// with an `=` and accepted both ways by `git.c`, so both spellings are here:
/// the `=` form is split off before this table is consulted.
///
/// The `push` half of git's vocabulary is here for a second reason, and it is
/// the collector's rather than the matcher's: `collect_git_refs` reads the
/// refspecs out of the POSITIONS, and an option between `push` and its refspecs
/// that nothing can classify shifts every one of them by one. The two readings
/// then disagree about which words are being published, which is a
/// could-not-look and is reported as one -- so `git push -f origin topic`,
/// which nobody would call ambiguous, has to be a word this table knows.
const VALUE_OPTIONS: &[(&str, &[&str])] = &[
    (
        "git",
        &[
            "-c",
            "-C",
            "--git-dir",
            "--work-tree",
            "--namespace",
            "--config-env",
            "--super-prefix",
            // Value-taking globals git documents with a following word. Their
            // absence was not theoretical: `git --attr-source HEAD push origin`
            // read `origin` as the refspec and the branch actually going out
            // was checked nowhere.
            "--attr-source",
            "--list-cmds",
            // `git push`'s own value-taking options.
            "--repo",
            "-o",
            "--push-option",
            "--receive-pack",
            "--exec",
        ],
    ),
    ("gh", &["-R", "--repo"]),
    ("glab", &["-R", "--repo"]),
];

/// Global options that take nothing, per command.
///
/// Listed for the sake of the ones that are NOT listed. An option neither table
/// knows leaves the word after it ambiguous, and an ambiguity is reported out
/// loud -- so `git --no-pager status` would warn about a line with no
/// subcommand this shim wants, every time it is typed, if the harmless half of
/// git's grammar were left out.
///
/// `--exec-path` with no `=` prints a path and exits rather than taking a
/// value, which is why it is on this side.
const BARE_OPTIONS: &[(&str, &[&str])] = &[
    (
        "git",
        &[
            "-v",
            "--version",
            "-h",
            "--help",
            "-p",
            "--paginate",
            "-P",
            "--no-pager",
            "--bare",
            "--exec-path",
            "--html-path",
            "--man-path",
            "--info-path",
            "--no-replace-objects",
            "--no-lazy-fetch",
            "--no-optional-locks",
            "--no-advice",
            "--literal-pathspecs",
            "--no-literal-pathspecs",
            "--glob-pathspecs",
            "--noglob-pathspecs",
            "--icase-pathspecs",
            "--no-icase-pathspecs",
            // `git push`'s own options that take nothing, for the reason the
            // table above gives: a refspec whose position an unclassified
            // option shifted is a refspec two readings disagree about, and
            // `git push -f origin topic` is not an invocation anybody should
            // have to hear a doubt about. Where one of these words means
            // something else under another verb -- `-n` takes a count on `git
            // log` -- the pair both readings land on is unnamed either way, so
            // the collision costs nothing this shim reads.
            "--all",
            "--mirror",
            "--tags",
            "--follow-tags",
            "-f",
            "--force",
            "--force-with-lease",
            "--no-force-with-lease",
            "--force-if-includes",
            "--no-force-if-includes",
            "-u",
            "--set-upstream",
            "-d",
            "--delete",
            "-n",
            "--dry-run",
            "--porcelain",
            "--prune",
            "--atomic",
            "--no-atomic",
            "--thin",
            "--no-thin",
            "--signed",
            "--no-signed",
            "--verify",
            "--no-verify",
            "--recurse-submodules",
            "--progress",
            "--no-progress",
            "-q",
            "--quiet",
            "--verbose",
            "-4",
            "--ipv4",
            "-6",
            "--ipv6",
        ],
    ),
    ("gh", &["--help", "--version"]),
    ("glab", &["--help", "--version"]),
];

fn listed(table: &[(&str, &[&str])], command: &str, flag: &str) -> bool {
    table
        .iter()
        .any(|(name, flags)| *name == command && flags.contains(&flag))
}

/// Whether an option before the subcommand takes the word after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arity {
    /// It takes none, so the next word is the next word.
    Bare,
    /// It takes the word after it, which is therefore not a subcommand.
    Value,
    /// Nothing here can say, so both readings are possible and the shim has to
    /// answer for both.
    Unknown,
}

/// One reading of argv: the first two words that are neither an option nor an
/// option's value, and the first option that could have been read either way.
#[derive(Debug)]
struct Words {
    verb: String,
    noun: String,
    unclear: Option<String>,
    /// How many options this table could not classify.
    ///
    /// Kept beside `unclear`, which names only the first, because the two
    /// answer different questions. The name is for the reader of a refusal; the
    /// count is what says whether the two readings `reading()` tries are the
    /// WHOLE space. `words()` applies `unknown_takes_value` uniformly, so one
    /// unclassified option has exactly two readings and both are tried, while N
    /// of them have 2^N and two are.
    unclear_count: usize,
}

/// One walk of argv: the positional words it found, and what it could not
/// classify on the way. `Words` is the first two of them named; a positional
/// collector is all of them.
#[derive(Debug)]
struct Scanned<'a> {
    positional: Vec<&'a str>,
    /// Where in argv the first positional word was, which is the one an alias
    /// mechanism expands. A name is not enough to put an expansion back: the
    /// words before it are the command's global options and have to stay in
    /// front of whatever the alias turns out to be.
    first: Option<usize>,
    unclear: Option<String>,
    unclear_count: usize,
}

/// What a shim can say about an invocation from argv alone.
#[derive(Debug)]
enum Reading {
    /// A `match` entry names it, under a reading of the options this shim can
    /// defend.
    Named,
    /// No entry names it, and every word before the subcommand was accounted
    /// for.
    Absent,
    /// The subcommand could not be located. This option sits before it, nothing
    /// here says whether the word after it is its value, and the two readings
    /// disagree about which word the subcommand even is -- neither of them
    /// matching. Not the same answer as `Absent`, and folding it into one is
    /// how a guard reports a pass over an invocation it never identified.
    Unclear(String),
}

impl Shim {
    /// Whether a flag this table names takes the word after it as its value.
    fn takes_value(&self, flag: &str) -> bool {
        in_list(&self.target_flags, flag)
            || in_list(&self.text_flags, flag)
            || in_list(&self.file_flags, flag)
            || in_list(&self.path_flags, flag)
    }

    /// What this option does to the word after it.
    fn arity(&self, flag: &str) -> Arity {
        if self.takes_value(flag) || listed(VALUE_OPTIONS, &self.command, flag) {
            Arity::Value
        } else if in_list(&self.skip_flags, flag)
            || in_list(&self.web_flags, flag)
            || listed(BARE_OPTIONS, &self.command, flag)
        {
            Arity::Bare
        } else {
            Arity::Unknown
        }
    }

    /// The verb and the noun of an invocation, under one reading of the options
    /// nothing here can classify.
    ///
    /// Reading `argv[0]` and `argv[1]` is not the same question. Every one of
    /// these CLIs takes options before the subcommand, and `gh --repo
    /// owner/name issue create -t ...` positionally yields the pair
    /// `--repo:owner/name` -- which no `match` list contains, so the shim
    /// decides the invocation is none of its business and execs a publishing
    /// command unexamined. Nothing is printed and the exit code is 0, which is
    /// the shape of failure this tool exists to refuse.
    ///
    /// `unknown_takes_value` is the reading applied to an option neither this
    /// table nor the grammar above names, and it is a parameter because neither
    /// answer is safe alone: assume it takes nothing and `git -c user.name=x
    /// push` loses `push`; assume it takes the next word and `gh --draft pr
    /// create` loses `pr`. Both readings are tried, and where they disagree the
    /// caller hears that rather than a verdict.
    fn words(&self, argv: &[String], unknown_takes_value: bool) -> Words {
        let scanned = self.scan(argv, unknown_takes_value, 2);
        let mut found = scanned.positional.into_iter();
        Words {
            verb: found.next().unwrap_or_default().to_owned(),
            noun: found.next().unwrap_or_default().to_owned(),
            unclear: scanned.unclear,
            unclear_count: scanned.unclear_count,
        }
    }

    /// One walk of argv, stopping once `stop_after` positional words are found.
    fn scan<'a>(
        &self,
        argv: &'a [String],
        unknown_takes_value: bool,
        stop_after: usize,
    ) -> Scanned<'a> {
        let mut found: Vec<&str> = Vec::new();
        let mut first: Option<usize> = None;
        let mut unclear: Option<String> = None;
        let mut unclear_count = 0usize;
        let mut index = 0;
        while let Some(argument) = argv.get(index) {
            index += 1;
            // `--` ends the options. Everything after it is positional however
            // it is spelt.
            if argument == "--" {
                if first.is_none() && argv.get(index).is_some() {
                    first = Some(index);
                }
                found.extend(
                    argv.get(index..)
                        .unwrap_or_default()
                        .iter()
                        .map(String::as_str),
                );
                break;
            }
            if argument.starts_with('-') && argument != "-" {
                // `--flag=value` carries its value in the same word; `--flag
                // value` takes the next one.
                let inline = argument.starts_with("--") && argument.contains('=');
                let flag = if inline {
                    argument
                        .split_once('=')
                        .map_or(argument.as_str(), |(flag, _)| flag)
                } else {
                    argument.as_str()
                };
                if !inline {
                    match self.arity(flag) {
                        Arity::Value => index += 1,
                        Arity::Bare => {}
                        Arity::Unknown => {
                            // Only where there IS a word after it. An option at
                            // the end of argv took nothing whatever its grammar
                            // says, and `gh --version` is not an invocation
                            // whose subcommand went missing.
                            if argv.get(index).is_some() {
                                unclear_count += 1;
                                if unclear.is_none() {
                                    unclear = Some(flag.to_owned());
                                }
                                if unknown_takes_value {
                                    index += 1;
                                }
                            }
                        }
                    }
                }
                continue;
            }
            if first.is_none() {
                first = Some(index - 1);
            }
            found.push(argument);
            if found.len() >= stop_after {
                break;
            }
        }
        Scanned {
            positional: found,
            first,
            unclear,
            unclear_count,
        }
    }

    /// Whether a `match` entry names the pair one reading found.
    fn names(&self, words: &Words) -> bool {
        in_list(&self.match_, &format!("{}:{}", words.verb, words.noun))
            || in_list(&self.match_, &format!("{}:*", words.verb))
    }

    /// Whether this invocation is one the shim has anything to say about, and
    /// where it cannot tell, that it cannot tell.
    fn reading(&self, argv: &[String]) -> Reading {
        if in_list(&self.match_, "*") {
            return Reading::Named;
        }
        let bare = self.words(argv, false);
        if self.names(&bare) {
            return Reading::Named;
        }
        // One reading found nothing; the other is what an option that DOES take
        // a value would have left, and a `match` hit under it is a hit. Matching
        // under either reading errs towards checking, which is the direction
        // this whole seam exists to err in.
        let valued = self.words(argv, true);
        if self.names(&valued) {
            return Reading::Named;
        }
        // Nothing was read either way, so the answer is the answer.
        let Some(flag) = bare.unclear else {
            return Reading::Absent;
        };
        // EXACTLY ONE unclassified option and the two readings above were the
        // whole space, so "no checker ran" is a conclusion rather than a doubt.
        // `words` applies `unknown_takes_value` uniformly: with one such option
        // the only readings are "it took the next word" and "it did not", both
        // were asked, and both said no. With two or more there are 2^N and only
        // two were tried, which is where the doubt is real.
        if bare.unclear_count <= 1 {
            return Reading::Absent;
        }
        // Past one, the readings are a sample rather than the space, so the
        // older test stands: they leave the SUBCOMMAND in doubt only where they
        // disagree about which word it is. `git log -1 --oneline` is `log`
        // whether `-1` swallows the word after it or not, and `-1` sits after
        // the subcommand besides.
        if bare.verb == valued.verb && bare.noun == valued.noun {
            return Reading::Absent;
        }
        Reading::Unclear(flag)
    }

    /// argv as the command itself will read it, with an alias in the verb
    /// position expanded once.
    ///
    /// `Ok(None)` where the word is not an alias, or where this command has no
    /// alias mechanism at all. `Err` where the word MIGHT be one and nothing
    /// here could say -- a `!shell` alias, an alias list that could not be
    /// read -- because "could not look" is not "no alias", and the difference
    /// is a push.
    ///
    /// The gap this closes. A `match` list names verbs literally, and every one
    /// of these commands lets a person rename a verb: `git -c alias.p=push p
    /// origin HEAD:refs/heads/x` and a persisted `[alias] p = push` both
    /// present the verb `p`, which no list contains -- so the shim decided a
    /// push to a public forge was none of its business, printed nothing, and
    /// exited 0. Reproduced against the built binary on PATH.
    ///
    /// Asked only where nothing matched, so an ordinary `git push` pays no
    /// process for it, and the expansion is asked of the REAL command rather
    /// than of whatever PATH resolves: the shim is what PATH resolves, and
    /// asking it would be this function calling itself without bound.
    fn expand_alias(&self, root: &Path, argv: &[String]) -> Result<Option<Vec<String>>> {
        if !ALIAS_COMMANDS.contains(&self.command.as_str()) {
            return Ok(None);
        }
        let scanned = self.scan(argv, false, 1);
        let (Some(index), Some(word)) = (scanned.first, scanned.positional.first().copied()) else {
            return Ok(None);
        };
        let Some(expansion) = self.alias_expansion(root, argv, word)? else {
            return Ok(None);
        };
        // `!` is git's and gh's spelling for "run this through a shell", and
        // what the shell then runs is not a verb any table can match. It may
        // well be a push. Naming it as unreadable is the only honest answer.
        if expansion.starts_with('!') {
            return Err(Fatal::new(format!(
                "{}: {word:?} is an alias for a shell command ({expansion:?}), and what a shell \
                 runs is not an invocation this shim can read. Nothing was published; run the \
                 command the alias stands for, or take the alias off",
                self.command
            )));
        }
        let mut words: Vec<String> = argv.get(..index).unwrap_or_default().to_vec();
        let expanded: Vec<String> = expansion
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<String>>();
        if expanded.is_empty() {
            return Err(Fatal::new(format!(
                "{}: {word:?} is an alias for nothing, so which invocation this is could not be \
                 established. Nothing was published",
                self.command
            )));
        }
        words.extend(expanded);
        words.extend(argv.get(index + 1..).unwrap_or_default().iter().cloned());
        Ok(Some(words))
    }

    /// What this command says one word expands to, asked of the real command.
    fn alias_expansion(&self, root: &Path, argv: &[String], word: &str) -> Result<Option<String>> {
        // A `-c alias.p=push` on the command line outranks the config file,
        // and reading it costs no process. The persisted alias below is the
        // case that needs one.
        if self.command == "git" {
            if let Some(value) = command_line_alias(argv, word) {
                return Ok(Some(value));
            }
        }
        let own = std::env::current_exe().ok();
        let Some(real) = real_command(&self.command, own.as_deref()) else {
            return Err(Fatal::new(format!(
                "{0}: {word:?} names no subcommand this shim stands in front of, and whether it \
                 is an alias for one could not be asked -- there is no {0} on PATH but this \
                 shim. Nothing was published",
                self.command
            )));
        };
        let query: &[&str] = if self.command == "git" {
            &["config", "--get"]
        } else {
            &["alias", "list"]
        };
        let mut command = Command::new(&real);
        command.args(query).current_dir(root);
        if self.command == "git" {
            command.arg(format!("alias.{word}"));
        }
        let output = command.output().map_err(|error| {
            Fatal::new(format!(
                "{}: could not ask whether {word:?} is an alias ({error}). Nothing was published",
                self.command
            ))
        })?;
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        if self.command == "git" {
            // `--get` exits 1 for a key that is not set, which is an answer:
            // this word is not an alias. Anything else is git failing to look.
            return match output.status.code() {
                Some(0) => Ok(Some(text.trim().to_owned())),
                Some(1) => Ok(None),
                _ => Err(Fatal::new(format!(
                    "{}: `git config --get alias.{word}` failed, so whether {word:?} is an alias \
                     for a subcommand this shim checks could not be established. Nothing was \
                     published",
                    self.command
                ))),
            };
        }
        if !output.status.success() {
            return Err(Fatal::new(format!(
                "{0}: `{0} alias list` failed, so whether {word:?} is an alias for a subcommand \
                 this shim checks could not be established. Nothing was published",
                self.command
            )));
        }
        Ok(alias_in_list(&text, word))
    }

    /// This table, with the flag lists of whichever `[[shim.verbs]]` entry
    /// names the verb being invoked.
    ///
    /// Resolved AFTER the verb is identified, and that ordering is what makes
    /// the whole thing possible. `reading` locates the subcommand by trying
    /// both arities for every option it does not know and matching under
    /// either -- "matching under either reading errs towards checking" -- so it
    /// never needed the vocabulary it is about to select. Only collection does.
    ///
    /// Borrowed when no entry matches, which is every table written before this
    /// existed.
    fn for_verb(&self, argv: &[String]) -> std::borrow::Cow<'_, Self> {
        if self.verbs.is_empty() {
            return std::borrow::Cow::Borrowed(self);
        }
        let words = self.words(argv, false);
        let exact = format!("{}:{}", words.verb, words.noun);
        let any = format!("{}:*", words.verb);
        let Some(entry) = self
            .verbs
            .iter()
            .find(|entry| in_list(&entry.match_, &exact) || in_list(&entry.match_, &any))
        else {
            return std::borrow::Cow::Borrowed(self);
        };
        let mut effective = self.clone();
        effective.text_flags.clone_from(&entry.text_flags);
        effective.title_flags.clone_from(&entry.title_flags);
        effective.file_flags.clone_from(&entry.file_flags);
        effective.path_flags.clone_from(&entry.path_flags);
        effective.skip_flags.clone_from(&entry.skip_flags);
        effective.web_flags.clone_from(&entry.web_flags);
        std::borrow::Cow::Owned(effective)
    }

    /// Walk argv once, reading the flags this table names.
    fn collect_flags(&self, argv: &[String]) -> Result<Collected> {
        let mut collected = Collected::default();

        let mut index = 0;
        while let Some(argument) = argv.get(index) {
            // `--flag=value` and `--flag value` are the same flag. Splitting
            // here means every list a table writes is written once, in the
            // spelling a person would use.
            let (flag, value, paired) = match argument.split_once('=') {
                Some((flag, value)) if argument.starts_with("--") => {
                    (flag.to_owned(), value.to_owned(), true)
                }
                _ => (
                    argument.clone(),
                    argv.get(index + 1).cloned().unwrap_or_default(),
                    false,
                ),
            };

            // Whether this branch read the lookahead `value`. A flag that
            // takes no value (`--fill`, `--web`) must not swallow whatever
            // argument follows it -- that argument may be the very flag whose
            // value is about to be published.
            let took_value = if in_list(&self.target_flags, &flag) {
                collected.target = Some(value);
                true
            } else if in_list(&self.text_flags, &flag) {
                collected.subjects.push(Subject {
                    kind: "text",
                    value,
                });
                collected.body_given = true;
                true
            } else if in_list(&self.title_flags, &flag) {
                // NOT `body_given`. A title is a subject of its own, and a
                // `text_flags` title used to mark the body as given -- which
                // told the shim not to install itself as the editor, so the
                // body the command then opened an editor FOR closed unread.
                collected.subjects.push(Subject {
                    kind: "title",
                    value,
                });
                true
            } else if in_list(&self.path_flags, &flag) {
                collected.subjects.push(Subject {
                    kind: "path",
                    value,
                });
                true
            } else if in_list(&self.file_flags, &flag) {
                collected.body_given = true;
                if value == "-" {
                    // Reading stdin here means the real command can no longer
                    // read it, so the bytes are kept whole and handed back on
                    // the way through -- see `replayed`, which is where they
                    // become a descriptor the command inherits. A guard that
                    // silently eats the body it approved is worse than no
                    // guard: the invocation still runs, and what it publishes
                    // is empty.
                    let mut buffer = Vec::new();
                    std::io::stdin().read_to_end(&mut buffer)?;
                    // Not text is not a pass. A checker reads a subject as
                    // text, so bytes that are not text cannot be checked, and
                    // saying so is the only honest answer available here.
                    let text = std::str::from_utf8(&buffer)
                        .map_err(|error| {
                            Fatal::new(format!(
                                "{flag} named stdin, which is not UTF-8 text ({error}), so no \
                                 checker could read what would be published"
                            ))
                        })?
                        .to_owned();
                    collected.subjects.push(Subject {
                        kind: "text",
                        value: text,
                    });
                    collected.stdin = Some(buffer);
                } else if Path::new(&value).is_file() {
                    collected.subjects.push(Subject {
                        kind: "text",
                        value: std::fs::read_to_string(&value)
                            .map_err(|error| Fatal::at(Path::new(&value), error))?,
                    });
                } else {
                    // `body_given` was already set above, so a file that is not
                    // there used to leave the shim with a body it had been told
                    // about, no subject to check, and nothing to say -- it
                    // collected nothing and exec'd the command.
                    return Err(Fatal::new(format!(
                        "{flag} names {value:?}, which is not a file. Refusing to run the \
                         command with nothing checked when a body was named"
                    )));
                }
                true
            } else if in_list(&self.skip_flags, &flag) {
                collected.body_given = true;
                false
            } else if in_list(&self.web_flags, &flag) {
                collected.web = true;
                false
            } else {
                index += 1;
                continue;
            };
            index += if paired || !took_value { 1 } else { 2 };
        }
        Ok(collected)
    }

    /// Branch and tag names, which appear nowhere as a flag value.
    ///
    /// Read off the POSITIONS, and off the ones [`Shim::scan`] finds rather
    /// than off argv's own indices: the subcommand is not always the first word
    /// --
    /// `git -c user.name=x push` and `git -C elsewhere push` both put two
    /// before it -- and a collector that assumed it was read the option's value
    /// as the remote and `push` itself as the branch being published. That is
    /// the same reading [`VALUE_OPTIONS`] was written to end, arriving one
    /// question later: the shim MATCHED those invocations and then checked a
    /// name nobody was publishing, while the branch that was went out unread.
    ///
    /// Under BOTH readings, the way `reading` asks for both: an option this
    /// grammar cannot classify shifts every position after it by one, so
    /// reading only the bare one picks an answer where there are two. `git
    /// --attr-source HEAD push origin` reads `origin` as the refspec under one
    /// and the current branch under the other, and this collector used to
    /// publish the first without knowing there was a second.
    fn collect_git_refs(&self, root: &Path, argv: &[String]) -> Result<Vec<Subject>> {
        let bare = self.scan(argv, false, usize::MAX);
        let valued = self.scan(argv, true, usize::MAX);
        let mut names = refspec_names(&bare.positional);
        // The same question `reading` asks about the subcommand, asked one
        // question later about the refspecs. Where the two readings agree the
        // doubt is not about anything this collector reads; where they disagree
        // the words being published are one thing under one reading and another
        // under the other, and picking one is a guess about what is going onto
        // a public forge. Not `Unclear`-and-run either: this invocation IS one
        // the shim matched, so nothing here is at risk of a warning printed
        // over every ordinary command -- the whole reason that arm runs the
        // command. A matched push whose subjects could not be established is
        // the non-UTF-8 argv case in a different spelling.
        if names != refspec_names(&valued.positional) {
            let flag = bare.unclear.as_deref().unwrap_or("an option");
            return Err(Fatal::new(format!(
                "{}: {flag} sits in front of the refspecs and nothing here says whether it \
                 takes the word after it, so which names this push would publish could not be \
                 established. Nothing was published; spell the refspec after `--`, or name the \
                 option in the shim's own flag lists",
                self.command
            )));
        }
        // `--all`, `--mirror` and `--tags` name no refspec and publish many.
        // The fallback below reads HEAD, so a mirror push of forty branches was
        // checked as one -- the current one -- and the other thirty-nine went
        // out unread. What they would push is a question git itself answers.
        for (flag, pattern) in [
            ("--all", "refs/heads"),
            ("--tags", "refs/tags"),
            ("--mirror", "refs/"),
        ] {
            if !argv.iter().any(|argument| argument == flag) {
                continue;
            }
            let listed = git::try_run(root, &["for-each-ref", "--format=%(refname)", pattern])?
                .ok_or_else(|| {
                    Fatal::new(format!(
                        "{}: {flag} publishes every ref under {pattern} and they could not be \
                         listed, so nothing here could read the names going out. Nothing was \
                         published",
                        self.command
                    ))
                })?;
            names.extend(listed.lines().filter_map(shortened).map(str::to_owned));
        }
        if names.is_empty() {
            // With no refspec, git pushes the current branch, so that is the
            // name going out even though it appears nowhere in argv.
            if let Some(branch) = git::try_run(root, &["symbolic-ref", "--short", "HEAD"])? {
                let branch = branch.trim().to_owned();
                if !branch.is_empty() {
                    names.push(branch);
                }
            }
        }
        Ok(names
            .into_iter()
            .map(|value| Subject { kind: "ref", value })
            .collect())
    }

    /// A package's metadata and the tree it would send.
    #[expect(
        clippy::unused_self,
        reason = "one signature for every `collect` arm; the flags collector needs the table"
    )]
    fn collect_npm(&self, root: &Path) -> Result<Vec<Subject>> {
        let mut subjects = Vec::new();
        // Deliberately not `npm pkg get`: that runs npm, and this shim is what
        // npm is currently behind. Reading the file is also what publish does.
        let manifest = root.join("package.json");
        if let Ok(text) = std::fs::read_to_string(&manifest) {
            for field in ["name", "description"] {
                if let Some(value) = json_string_field(&text, field) {
                    subjects.push(Subject {
                        kind: "text",
                        value,
                    });
                }
            }
        }
        if let Ok(readme) = std::fs::read_to_string(root.join("README.md")) {
            subjects.push(Subject {
                kind: "text",
                value: readme,
            });
        }
        subjects.push(Subject {
            kind: "path",
            value: root.to_string_lossy().into_owned(),
        });
        Ok(subjects)
    }

    /// The words after the `api` verb, where this invocation is one.
    ///
    /// `None` for every other command and every other verb, which is what makes
    /// the whole of the `api` reading below opt-in on one word.
    ///
    /// Both readings are tried, the way [`Shim::reading`] tries both: an option
    /// in front of the verb that nothing here can classify shifts the first
    /// positional word by one, and a reading that missed `api` under one arity
    /// would silently hand this invocation back to the flag collector -- whose
    /// vocabulary means something else on this verb.
    fn api_rest<'a>(&self, argv: &'a [String]) -> Option<&'a [String]> {
        if !FORGE_API_COMMANDS.contains(&self.command.as_str()) {
            return None;
        }
        for unknown_takes_value in [false, true] {
            let scanned = self.scan(argv, unknown_takes_value, 1);
            if let (Some(index), Some("api")) = (scanned.first, scanned.positional.first().copied())
            {
                return argv.get(index + 1..);
            }
        }
        None
    }

    /// Whether a matched invocation carries anything to publish at all.
    ///
    /// True for every verb but one. `gh api` and `glab api` are the read side
    /// and the write side of a forge behind a single word, so the `match` list
    /// names the word and this answers which half was typed -- see
    /// [`ApiCall::publishes`]. A GET with no fields is left exactly where it was
    /// before this existed: unmatched, unexamined, exec'd.
    fn carries_a_body(&self, argv: &[String]) -> bool {
        self.api_rest(argv)
            .is_none_or(|rest| ApiCall::of(rest).publishes())
    }

    /// One `api` call's subjects and its destination.
    ///
    /// `body_given` is true whatever was found: `gh api` opens no editor, so
    /// there is no checkpoint here to keep open and installing one would put
    /// this shim in front of an editor the command will never run.
    fn collect_api(&self, call: &ApiCall) -> Result<Collected> {
        let mut subjects = Vec::new();
        let mut stdin = None;
        for (flag, field) in &call.fields {
            // `key=value`: the key names the field and the value is what
            // reaches the forge. A field spelt without one is passed whole,
            // because guessing which half of it was meant is not this shim's to
            // guess.
            let value = field
                .split_once('=')
                .map_or(field.as_str(), |(_, rest)| rest);
            subjects.push(Subject {
                kind: "text",
                value: self.api_value(flag, value, &mut stdin)?,
            });
        }
        if let Some(file) = &call.input {
            let text = self.api_file("--input", file, &mut stdin)?;
            match json_strings(&text) {
                Some(values) => subjects.extend(values.into_iter().map(|value| Subject {
                    kind: "text",
                    value,
                })),
                None => subjects.push(Subject {
                    kind: "text",
                    value: text,
                }),
            }
        }
        Ok(Collected {
            subjects,
            target: call.target(),
            body_given: true,
            web: false,
            stdin,
        })
    }

    /// One field value, with `@` read the way a forge CLI reads it.
    fn api_value(&self, flag: &str, value: &str, stdin: &mut Option<Vec<u8>>) -> Result<String> {
        value.strip_prefix('@').map_or_else(
            || Ok(value.to_owned()),
            |name| self.api_file(flag, name, stdin),
        )
    }

    /// The text of a file a field or `--input` named, `-` being stdin.
    fn api_file(&self, flag: &str, name: &str, stdin: &mut Option<Vec<u8>>) -> Result<String> {
        if name == "-" {
            // Read once however many places name it, and kept whole: the
            // command still has to be handed the bytes it was submitted, which
            // is what `replayed` does with them on the way through. A guard
            // that silently eats the body it approved leaves the invocation
            // publishing nothing.
            if stdin.is_none() {
                let mut buffer = Vec::new();
                std::io::stdin().read_to_end(&mut buffer)?;
                *stdin = Some(buffer);
            }
            let bytes = stdin.as_deref().unwrap_or_default();
            return Ok(std::str::from_utf8(bytes)
                .map_err(|error| {
                    Fatal::new(format!(
                        "{}: {flag} named stdin, which is not UTF-8 text ({error}), so no \
                         checker could read what would be published",
                        self.command
                    ))
                })?
                .to_owned());
        }
        if !Path::new(name).is_file() {
            // Named and absent is not the same as not named. The invocation
            // says a body is coming from there, so running it with nothing
            // checked is the one answer this seam does not have.
            return Err(Fatal::new(format!(
                "{}: {flag} names {name:?}, which is not a file. Refusing to run the command \
                 with nothing checked when a body was named",
                self.command
            )));
        }
        std::fs::read_to_string(name).map_err(|error| Fatal::at(Path::new(name), error))
    }

    pub(crate) fn collect(&self, root: &Path, argv: &[String]) -> Result<Collected> {
        // The `api` verb reads its own grammar, and the branch is here rather
        // than beside the `collect` arms because it is a property of the
        // INVOCATION and not of the table: one `[[shim]]` stands in front of
        // `gh pr create` and `gh api` both, and only argv says which this is.
        if let Some(rest) = self.api_rest(argv) {
            return self.collect_api(&ApiCall::of(rest));
        }
        // Every arm walks the flags first: the target flag and any stdin the
        // shim consumed belong to the invocation rather than to one collector,
        // and a collector that dropped the stdin it had already read would
        // leave the command publishing an empty body.
        // The verb's own vocabulary where it has one. `self` still answers
        // everything that is a property of the command rather than of the verb
        // -- the editor variable, the target, the scope, the collector.
        let effective = self.for_verb(argv);
        let mut collected = effective.collect_flags(argv)?;
        match self.collect {
            Collect::Flags => {}
            Collect::GitRefs => {
                collected.subjects = self.collect_git_refs(root, argv)?;
                // Never hand git an editor: a message written in one passes
                // through commit-msg already.
                collected.body_given = true;
                collected.web = false;
            }
            Collect::NpmPackage => {
                let dry_run = argv.iter().any(|argument| argument == "--dry-run");
                // A dry run publishes nothing, and refusing one would stop the
                // very command somebody runs to find out what they are about to
                // publish.
                collected.subjects = if dry_run {
                    Vec::new()
                } else {
                    self.collect_npm(root)?
                };
                collected.body_given = true; // npm opens no editor
                collected.web = false;
            }
        }
        if self.argv_subject {
            collected.subjects.push(Subject {
                kind: "argv",
                value: argv.join(" "),
            });
        }
        Ok(collected)
    }

    /// Whether one scope predicate holds for this invocation.
    ///
    /// The predicate is a parameter rather than the table's own, because a rule
    /// may carry its own `command.scope`: the table's answers for the command,
    /// and a rule that applies on every egress -- host identity in a
    /// pull-request body is worth refusing whatever the destination -- says so
    /// beside its `command.before` rather than inheriting the table's idea of
    /// the question.
    pub(crate) fn scope_holds(
        &self,
        scope: &Scope,
        root: &Path,
        collected: &Collected,
        argv: &[String],
    ) -> Result<Standing> {
        match scope {
            Scope::Always => Ok(Standing::Holds),
            Scope::PublicTarget => {
                let Some(target) = self.resolve_target(root, collected)? else {
                    // No answer is not "public", and it is not "not public"
                    // either. `gh` unauthenticated, rate-limited, offline, or a
                    // repository with no `origin` all land here, and what the
                    // caller does about it is the caller's decision -- see
                    // [`Unresolved`].
                    return Ok(Standing::CouldNotTell(String::from(
                        "no target could be resolved, so whether the `public-target` checks \
                         apply here could not be established",
                    )));
                };
                match self.visibility(root, &target).as_deref() {
                    Some("public") => Ok(Standing::Holds),
                    Some(_) => Ok(Standing::DoesNotHold),
                    None => Ok(Standing::CouldNotTell(format!(
                        "the forge did not say whether {target} is public, so whether the \
                         `public-target` checks apply here could not be established"
                    ))),
                }
            }
            Scope::PublicRegistry => {
                if argv.iter().any(|argument| argument == "--dry-run") {
                    return Ok(Standing::DoesNotHold);
                }
                // Two independent reasons this is nobody's business, and either
                // one is enough: a package marked private cannot be published
                // at all, and a registry that is not the public one is
                // somebody's internal infrastructure.
                if let Ok(text) = std::fs::read_to_string(root.join("package.json")) {
                    if text.contains("\"private\"") && json_bool_field(&text, "private") {
                        return Ok(Standing::DoesNotHold);
                    }
                }
                let registry = collected
                    .target
                    .clone()
                    .unwrap_or_else(|| String::from("https://registry.npmjs.org"));
                Ok(if registry.contains("registry.npmjs.org") {
                    Standing::Holds
                } else {
                    Standing::DoesNotHold
                })
            }
            Scope::Command { command } => {
                let status = Command::new("sh")
                    .arg("-c")
                    .arg(command)
                    .current_dir(root)
                    .status()
                    .map_err(|error| {
                        Fatal::new(format!("{}: scope command: {error}", self.command))
                    })?;
                Ok(if status.success() {
                    Standing::Holds
                } else {
                    Standing::DoesNotHold
                })
            }
        }
    }

    /// Which forge can answer for this repository, where that has an answer.
    fn forge(&self, root: &Path) -> Option<Forge> {
        // The command is the strongest evidence there is: somebody running
        // `glab` is publishing to GitLab whatever else is configured.
        match self.command.as_str() {
            "gh" => return Some(Forge::GitHub),
            "glab" => return Some(Forge::GitLab),
            _ => {}
        }
        // Otherwise the remote decides, which is what the `git` shim needs:
        // one shim stands in front of a command that pushes to either.
        let url = git::remote_url(root, "origin")?.to_lowercase();
        if url.contains("gitlab") {
            Some(Forge::GitLab)
        } else if url.contains("github") {
            Some(Forge::GitHub)
        } else {
            // Not a guess. An unrecognised host means no resolver applies, and
            // the caller says so rather than reporting a pass over a
            // visibility nobody read.
            None
        }
    }

    /// What the forge says the target's visibility is, in the forge's own word.
    ///
    /// Asking `gh` for every target is why the shipped `glab` shim could never
    /// resolve one: `gh api repos/<owner>/<repo>` answers about GitHub and
    /// about nothing else, so a GitLab remote fell through the `None` arm on
    /// every invocation and a shim declared `public-target` was inert.
    ///
    /// Both vocabularies come back unchanged, and GitLab's `internal` is why:
    /// it means public to everyone with an account on the instance, which is
    /// neither public to the internet nor private. Only `public` is treated as
    /// public by the caller, so a forge that grows a fourth word does not
    /// quietly become one of the three.
    fn visibility(&self, root: &Path, target: &str) -> Option<String> {
        match self.forge(root)? {
            Forge::GitHub => forge_field(
                "gh",
                &["api", &format!("repos/{target}"), "--jq", ".visibility"],
                None,
            ),
            // Deliberately not `--jq`: `glab api` is not `gh api`, and a shim
            // that is inert the day one flag differs is the defect this arm
            // exists to end. The project id is a path, so its separators are
            // escaped -- `owner/name` and `group/sub/name` are each one id.
            Forge::GitLab => forge_field(
                "glab",
                &["api", &format!("projects/{}", target.replace('/', "%2F"))],
                Some("visibility"),
            ),
        }
    }

    fn resolve_target(&self, root: &Path, collected: &Collected) -> Result<Option<String>> {
        if let Some(explicit) = collected.target.as_deref() {
            if !explicit.is_empty() {
                return Ok(Some(explicit.to_owned()));
            }
        }
        Ok(match self.target {
            Target::None => None,
            Target::GitRemote => git::remote_url(root, "origin")
                .and_then(|url| git::owner_repo(&url))
                .map(|(owner, repo)| format!("{owner}/{repo}")),
            Target::ForgeRepo => {
                // Both forge CLIs answer this, and every spec that wanted it
                // wrote the same call. The remote is the same answer without a
                // network round trip, so it is tried first.
                git::remote_url(root, "origin")
                    .and_then(|url| git::owner_repo(&url))
                    .map(|(owner, repo)| format!("{owner}/{repo}"))
            }
        })
    }
}

/// What one invocation is about to publish.
#[derive(Debug, Clone, Default)]
pub(crate) struct Collected {
    pub subjects: Vec<Subject>,
    pub target: Option<String>,
    pub body_given: bool,
    pub web: bool,
    /// The bytes this shim read off its own stdin to make a subject of them.
    ///
    /// Kept whole rather than as the subject's `String`, because what the
    /// command publishes must be what was submitted to it byte for byte, and
    /// the subject is a decoded copy.
    pub stdin: Option<Vec<u8>>,
}

/// The forges whose visibility question this tool knows how to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Forge {
    GitHub,
    GitLab,
}

/// Run a forge CLI and read one word out of what it printed.
///
/// `field` names a JSON key to pull out where the CLI cannot be asked to do it;
/// `None` means the whole of stdout is the answer.
fn forge_field(program: &str, args: &[&str], field: Option<&str>) -> Option<String> {
    let output = inner_tool(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let value = match field {
        Some(field) => json_string_field(&text, field)?,
        None => text.trim().to_owned(),
    };
    let value = value.trim().to_lowercase();
    // An empty answer is not an answer. `--jq` on a field that is not there
    // prints a blank line and exits 0, and treating that as a visibility would
    // be a lookup that did not happen wearing the face of one that did.
    (!value.is_empty() && value != "null").then_some(value)
}

/// Parse the document and read a TOP-LEVEL key, rather than scan for a needle.
///
/// These two were `text.find("\"field\"")` and a walk forwards from there, which
/// answers with the first textual occurrence of the name anywhere in the
/// document -- inside a nested object, inside a string value, inside a
/// description that happens to quote the word. On the visibility question that
/// is a `public-target` decision made from somebody else's field, and the shim
/// stands in front of publication on the strength of it. The parser is already a
/// dependency: YAML 1.2 is a superset of JSON, so `serde_yaml_ng` reads a forge
/// response without adding one.
fn json_value(text: &str) -> Option<serde_yaml_ng::Value> {
    serde_yaml_ng::from_str::<serde_yaml_ng::Value>(text).ok()
}

fn json_string_field(text: &str, field: &str) -> Option<String> {
    let parsed = json_value(text)?;
    let value = parsed.get(field)?;
    // A number or a bool spelled where a string was expected is still an answer
    // the caller can use; a nested object is not.
    match value {
        serde_yaml_ng::Value::String(found) => Some(found.clone()),
        serde_yaml_ng::Value::Number(found) => Some(found.to_string()),
        serde_yaml_ng::Value::Bool(found) => Some(found.to_string()),
        _ => None,
    }
}

fn json_bool_field(text: &str, field: &str) -> bool {
    json_value(text)
        .as_ref()
        .and_then(|parsed| parsed.get(field))
        .and_then(serde_yaml_ng::Value::as_bool)
        .unwrap_or(false)
}

/// One pattern rule's verdict over one subject.
///
/// The same engine `scan` searches files with, asked about a string that never
/// becomes one -- same regex grammar, same meaning. `require_regexp` refuses a
/// subject the pattern is absent from; `regexp` refuses one it is present in.
/// Both name the kind and the pattern, because the reader's next step is to
/// fix the text, and "refused" without which-test-failed is a round trip.
///
/// `prose_regexp` is the third, and the subject reaches it as whole-text prose:
/// a pull-request body is a document, so a fenced example in one is skipped
/// here exactly as it is in a committed document, and a sentence wrapped by
/// whatever composed the body is unwrapped before the pattern sees it. A rule
/// that refused a shape in a document and allowed it in the body announcing
/// that document would be one rule with two answers.
fn pattern_refusal(rule: &Rule, subject: &Subject) -> Result<Option<String>> {
    let multiline = rule.files().multiline;
    if let Some(pattern) = rule.prose_regexp() {
        let matcher = crate::prose::compile(pattern, &rule.id)?;
        let Some(span) = crate::prose::of_text(&subject.value)
            .into_iter()
            .find(|span| matcher.is_match(&span.text))
        else {
            return Ok(None);
        };
        return Ok(Some(format!(
            "{}: the {} subject matches {pattern:?}: {}\n{}",
            rule.id,
            subject.kind,
            span.text,
            rule.message()
        )));
    }
    if let Some(pattern) = rule.require_regexp() {
        let hits = crate::engine::search_text(
            &subject.value,
            &crate::engine::Query::regex(pattern, multiline),
            &rule.id,
        )?;
        if hits.is_empty() {
            return Ok(Some(format!(
                "{}: the {} subject does not satisfy {pattern:?}\n{}",
                rule.id,
                subject.kind,
                rule.message()
            )));
        }
        return Ok(None);
    }
    let Some(pattern) = rule.regexp() else {
        return Ok(None);
    };
    let hits = crate::engine::search_text(
        &subject.value,
        &crate::engine::Query::regex(pattern, multiline),
        &rule.id,
    )?;
    let Some(hit) = hits.first() else {
        return Ok(None);
    };
    Ok(Some(format!(
        "{}: the {} subject matches {pattern:?}: {}\n{}",
        rule.id,
        subject.kind,
        hit.text.trim_end(),
        rule.message()
    )))
}

/// Run one checker over one subject.
///
/// The contract cmd-shims documented, unchanged and now the only one: the
/// subject on stdin, its kind in the environment, 0 to pass, 1 to refuse, 2 to
/// say it could not look. A checker written in anything satisfies it.
///
/// All three pipes are worked at once, and that is not tidiness. A pipe holds
/// about 64 KiB: writing a longer subject blocks until the checker reads it,
/// and a checker that writes more than a bufferful blocks until this process
/// reads THAT. Writing the whole subject first and reading afterwards means
/// each side is waiting for the other and neither ever moves -- on exactly the
/// long bodies a guard most needs to see, and with no output at all to say
/// what happened.
fn consult(root: &Path, rule: &Rule, subject: &Subject) -> Result<Option<String>> {
    // `exec`, not `values_from`. They were one field called `run` in v2, and a
    // checker whose command reads empty passes everything it is asked about --
    // which is also why an ABSENT command is an error here rather than a
    // default: a rule mis-dispatched to this function once ran `sh -c ""`,
    // approved everything, and the pass was indistinguishable from a checker
    // that looked.
    let Some(run) = rule.exec().filter(|command| !command.trim().is_empty()) else {
        return Err(Fatal::new(format!(
            "{}: consulted as an `exec` checker while declaring no `exec` command, so \
             nothing could have been asked -- a dispatch hole, not a pass",
            rule.id
        )));
    };
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(run)
        .current_dir(root)
        .env("UPHOLD_KIND", subject.kind)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| Fatal::new(format!("{}: {error}", rule.id)))?;

    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let body = subject.value.as_bytes();

    let (written, report) =
        std::thread::scope(|scope| -> Result<(std::io::Result<()>, Vec<u8>)> {
            let writer = scope.spawn(move || -> std::io::Result<()> {
                let Some(pipe) = stdin.as_mut() else {
                    return Ok(());
                };
                pipe.write_all(body)?;
                pipe.flush()
                // Dropped on the way out of this closure, which is the end of
                // input the checker is waiting for.
            });
            // Drained rather than read: the contract puts a checker's report on
            // stderr, but a checker that writes to stdout still fills a pipe,
            // and a full pipe nobody empties is the same deadlock from the
            // other side.
            let drain = scope.spawn(move || {
                if let Some(pipe) = stdout.as_mut() {
                    drop(pipe.read_to_end(&mut Vec::new()));
                }
            });
            let mut report = Vec::new();
            if let Some(pipe) = stderr.as_mut() {
                drop(pipe.read_to_end(&mut report));
            }
            let written = writer.join().map_err(|_| {
                Fatal::new(format!(
                    "{}: the thread feeding it the subject died",
                    rule.id
                ))
            })?;
            drain.join().map_err(|_| {
                Fatal::new(format!("{}: the thread draining its output died", rule.id))
            })?;
            Ok((written, report))
        })?;

    let status = child
        .wait()
        .map_err(|error| Fatal::new(format!("{}: {error}", rule.id)))?;
    let report = String::from_utf8_lossy(&report);
    let report = report.trim();
    match (status.code(), written) {
        // A refusal stands even where the write did not finish. A checker that
        // stopped reading and then said no had already seen enough to say it,
        // and turning that into an infrastructure error would teach people to
        // re-run until the refusal went away.
        (Some(1), _) => Ok(Some(format!(
            "{} refused a {} subject: {report}",
            rule.id, subject.kind
        ))),
        // The write result is an answer, not something to drop with `.ok()`: a
        // subject that never arrived is the one case where a 0 means nothing at
        // all, because the checker approved whatever part of it got through and
        // that is not what this invocation is about to publish.
        (_, Err(error)) => Err(Fatal::new(format!(
            "{} did not take the whole {} subject ({error}), so its answer is not about what \
             would be published: {report}",
            rule.id, subject.kind
        ))),
        (Some(0), Ok(())) => Ok(None),
        // 2 is could-not-look, and it is not a pass. A checker that could not
        // read what it was handed has established nothing.
        (other, Ok(())) => Err(Fatal::new(format!(
            "{} exited {} on a {} subject: {report}",
            rule.id,
            other.unwrap_or(-1),
            subject.kind
        ))),
    }
}

/// What a file IS, not where it sits: device and inode. `canonicalize` sees
/// through symlinks but a hard link canonicalizes to its own path, so a path
/// comparison would call a hard-linked shim "the real command". Metadata
/// follows symlinks, so both spellings of a link land on the same identity.
#[cfg(unix)]
fn file_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn file_identity(path: &Path) -> Option<PathBuf> {
    path.canonicalize().ok()
}

/// How this process was reached, which is the only thing that differs when
/// nothing here declares the command.
///
/// Both are the same seam and the same reading. One is a command being run --
/// through a link named for it, on a PATH that spans the whole machine -- and
/// the other is a question asked about this repository, typed with the answer
/// in mind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Invoked {
    /// Through a link named for the command: argv[0] decided.
    AsTheCommand,
    /// As `uphold shim <command>`, with the command named as an argument.
    ByName,
    /// As the command's own EDITOR, re-entered through the variable this shim
    /// put itself in. argv here is an editor's argv -- one file path -- and the
    /// text to check is what the editor leaves in that file.
    ///
    /// A word on the command line rather than a variable in the environment, and
    /// the difference is not cosmetic. An environment is inherited by every
    /// descendant, and the checkers this pass consults run `git` and `gh` --
    /// which, on a machine that installed the shim the way `README.md` describes,
    /// ARE this binary under a link. Each of those children read the marker,
    /// decided it was somebody's editor, opened the user's editor on whatever
    /// its last argument happened to be, consulted the same checkers, and ran
    /// `git` again: a fork bomb that reached this repository's own test suite and
    /// wedged it for sixty seconds, and that on a consumer's machine sits between
    /// `gh pr create` and every process on it. A process is re-entered as an
    /// editor because it was invoked as one, and only argv can say that.
    AsEditor,
}

/// The marker one uphold process sets on the `git`, `gh` and `glab` children it
/// spawns to answer its own questions.
///
/// The shim resolves the command it stands in front of through PATH, and PATH
/// is where the shim itself is installed -- so every probe this tool makes on
/// the way to a verdict is a command that resolves back to this binary. On
/// 2026-09-02 that closed: `visibility` ran `gh api repos/<owner>/<repo> --jq
/// .visibility` to answer a `public-target` scope, the tree's policy listed
/// `api:*` in the `gh` shim's match table, and the probe matched itself. Each
/// pass asked the question again, roughly two hundred and fifty processes a
/// second, and the run ended at a load average of three thousand under
/// `kill -9` on the process group.
///
/// The trigger of that particular round is gone -- a bodyless GET is exempt
/// from the api match now -- but nothing about the shape was fixed by that: any
/// match entry, any binary and policy that disagree about which entries exist,
/// reopens it. So the loop is closed at the seam rather than at one entry. A
/// child that carries this marker is uphold asking uphold a question, and the
/// entry point hands it straight to the real command instead of judging it.
///
/// It is NOT a bypass anyone should reach for: see the notice
/// `inner_passthrough` prints, and the reference documentation beside
/// `UPHOLD_ALLOW`.
pub(crate) const INNER: &str = "UPHOLD_SHIM_INNER";

/// How many probes deep this process already is, where it is inside one at all.
///
/// The value is a depth rather than a flag, so the second layer of the fix has
/// something to count. A value that is set but is not a number is read as depth
/// one: a person exporting `UPHOLD_SHIM_INNER=1` and a person exporting
/// `UPHOLD_SHIM_INNER=yes` mean the same thing and are told the same thing.
fn inner_depth() -> Option<u32> {
    let value = nonempty_env(INNER)?;
    Some(value.trim().parse().unwrap_or(1))
}

/// How deep a probe may go before the depth itself is the finding.
///
/// Two is one more than any legitimate chain needs. A shim probes, the probe
/// execs the real command, and the real command does not probe -- so depth one
/// is the whole of the ordinary case, and depth two is the margin for a hook
/// that re-enters this tool. Past that, something is calling itself.
const INNER_LIMIT: u32 = 2;

/// A `git`, `gh` or `glab` this process is about to run to answer its OWN
/// question, marked as such.
///
/// Every internal spawn of those three goes through here, because the marker
/// has to be on the child rather than in this process's environment: setting it
/// on ourselves would hand it to the real command at the exec too, and a `git
/// push` that runs a hook that runs this tool would arrive already excused.
pub(crate) fn inner_tool(name: &str) -> Command {
    let mut command = Command::new(name);
    command.env(
        INNER,
        (inner_depth().unwrap_or(0).saturating_add(1)).to_string(),
    );
    command
}

/// The answer for an invocation that is uphold's own probe rather than a user's
/// command, where it is one.
///
/// `Ok(None)` means the marker is not set and the ordinary path applies.
///
/// Two layers, and the second is only ever reached if the first has been
/// undone. The first is the passthrough: the command runs with nothing standing
/// in front of it, which is the whole point -- a probe that is checked is a
/// probe that probes. The second is the depth: if the marker says this process
/// is further inside itself than any real chain reaches, the loop is named and
/// nothing runs, because a probe that got that far is not answering a question.
pub(crate) fn inner_passthrough(name: &str, argv: &[OsString]) -> Result<Option<Exit>> {
    let Some(depth) = inner_depth() else {
        return Ok(None);
    };
    if depth > INNER_LIMIT {
        return Err(Fatal::new(format!(
            "{name}: {INNER}={depth}, which is uphold standing in front of a command uphold \
             itself ran, {depth} levels down. A shim probes the forge through PATH and PATH is \
             where the shim lives, so a probe that reaches its own shim asks the same question \
             forever; past {INNER_LIMIT} that is what this is. Nothing was published"
        )));
    }
    eprintln!(
        "uphold shim: {name} ran unchecked, by {INNER}={depth}. Nothing here looked at what it \
         publishes. uphold sets this on the {name} it runs for its own probes; exported by hand \
         it is UPHOLD_ALLOW=all under another name."
    );
    exec_through(name, argv).map(Some)
}

/// Run the command with nothing standing in front of it.
///
/// The transparent path, for the two answers that are not "check this": no
/// policy where the command was typed, and a policy that declares no shim for
/// it. Both are readings rather than failures to read, and a shim installed for
/// the whole machine meets them constantly -- every directory outside a
/// participating repository is one of them.
///
/// No stdin is replayed because none was collected: reading it belongs to the
/// checking path, and a command whose text nothing here reads must be handed
/// the descriptor it was given rather than a copy of what this process drained
/// out of it.
pub(crate) fn exec_through(name: &str, argv: &[OsString]) -> Result<Exit> {
    let own = std::env::current_exe().ok();
    let Some(real) = real_command(name, own.as_deref()) else {
        return Err(Fatal::new(format!(
            "nothing here stands in front of {name}, and there is no {name} on PATH to run"
        )));
    };
    let mut command = Command::new(&real);
    command.args(argv);
    hand_off(&mut command, name, None)
}

/// The real command, found by walking PATH past ourselves.
///
/// "Past ourselves" is a question about the FILE, not about the directory. A
/// shim is installed as a link, and a link resolves to the binary while living
/// somewhere else entirely -- so a directory comparison skips nothing, finds
/// the link, and execs it, which is this program again. The result is not a
/// wrong answer; it is a fork bomb that ends in EAGAIN.
fn real_command(name: &str, own: Option<&Path>) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let ourselves = own.and_then(file_identity);
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if !candidate.is_file() {
            continue;
        }
        // Same identity means this is us, however the name is spelt --
        // symlink, hard link, or the binary under its own name.
        if ourselves.is_some() && file_identity(&candidate) == ourselves {
            continue;
        }
        if lands_on_uphold(&candidate) {
            continue;
        }
        return Some(candidate);
    }
    None
}

/// A link named for the command that lands on ANOTHER copy of this binary.
///
/// Identity answers for one installation and cannot answer for two. A second
/// copy -- a `cargo install` beside a packaged one, a release binary beside a
/// `target/debug` build under test, a link left by an older version -- is a
/// different file, so the identity check above passes it through as "the real
/// git". That copy then walks the same PATH, finds the first link, sees a file
/// that is not ITSELF either, and execs back. Two shims each holding the door
/// for the other is not a wrong answer that gets reported: it is an exec loop,
/// and every guard that shells out to `git` on the way round leaves a process
/// behind it. Measured, on a machine with exactly this pair installed: the run
/// stopped when the kernel ran out of process ids.
///
/// Judged by where the link LANDS, which is the shape the install documents: a
/// link named for the command, pointing at a binary named `uphold`. A copy
/// renamed to something else is not caught here and cannot be -- the honest
/// bound on this check, and the reason a shim is installed as a link rather than
/// as a copy.
///
/// `install` asks the same question of a name it is about to write, so a link
/// this tool declines to touch is a link the shim declines to exec: one answer
/// to "is that file one of ours", rather than two that agree until they do not.
///
/// A link whose target is GONE is still ours, and it has to be: `canonicalize`
/// alone answered "no" the moment the binary moved -- a `cargo install` over an
/// older path, a `target/debug` build that was cleaned -- and the whole of what
/// this tool would then say about a directory of its own dead links is that it
/// did not put them there. `--install` would refuse to repair them and
/// `--uninstall` would refuse to remove them, while every shimmed command fell
/// through to whatever PATH resolved next with nothing reporting it. So the
/// unresolved target is read when the resolved one cannot be. Nothing in the
/// exec path changes: `real_command` requires `is_file()` before it asks, and a
/// dangling link is not a file.
pub(crate) fn lands_on_uphold(candidate: &Path) -> bool {
    std::fs::canonicalize(candidate)
        .or_else(|_| std::fs::read_link(candidate))
        .is_ok_and(|target| {
            target
                .file_stem()
                .is_some_and(|stem| stem.eq_ignore_ascii_case("uphold"))
        })
}

/// The command this process was re-entered for, when it was re-entered as that
/// command's editor.
///
/// A flag and not a variable: see `Invoked::AsEditor` for what an inherited one
/// did to every `git` this pass runs.
pub(crate) const EDITOR_FLAG: &str = "--as-editor";
/// The editor the user actually has, remembered while this shim stands in the
/// variable that used to name it.
const EDITOR_REAL: &str = "UPHOLD_SHIM_EDITOR_REAL";
/// The command line the editor was opened for, so the checkers consulted on the
/// way back are the ones that stand in front of THAT command line.
const EDITOR_ARGV: &str = "UPHOLD_SHIM_EDITOR_ARGV";

/// An environment variable that is set to something, which is not the same as
/// set. `EDITOR=` is how a person turns one off.
fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// One word for a shell that is going to split what it is handed.
///
/// The editor variable holds a command LINE rather than a path -- `code --wait`
/// and `emacsclient -nw` are ordinary values -- so the command runs it through a
/// shell, and this binary's own path would otherwise arrive as two words the
/// first time somebody installs it under a directory with a space in it.
fn shell_word(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// The stdin this shim consumed, in something the real command can inherit.
///
/// A pipe cannot carry it. The bytes have to be written by somebody, and after
/// `exec` there is no somebody -- this process IS the command by then, and a
/// thread left behind to feed it does not survive the call. A file holds them
/// already, seeks back to the start, and needs nobody alive. It is unlinked the
/// moment it is open, so what the child inherits is the descriptor and the disk
/// keeps nothing, however the process ends.
fn replayed(bytes: &[u8]) -> Result<std::fs::File> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let path =
        std::env::temp_dir().join(format!("uphold-shim-stdin-{}-{stamp}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        // Never adopt a file somebody else left on this path: a shared
        // temporary directory is writable by everyone on the machine, and the
        // body of a publishing command is exactly the thing not to hand over.
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|error| Fatal::at(&path, error))?;
    drop(std::fs::remove_file(&path));
    file.write_all(bytes)
        .map_err(|error| Fatal::at(&path, error))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| Fatal::at(&path, error))?;
    Ok(file)
}

/// Become the command's editor, so the body typed into it is read after all.
///
/// This is the one case a flag table cannot see: no body in argv, no `--web`,
/// and a command about to open an editor, which is how most bodies are actually
/// written. Warning about it -- all this did before -- leaves the text
/// unchecked and tells somebody who did nothing wrong to do it differently.
/// cmd-shims installed itself in the command's own editor variable, ran the
/// user's real editor, then read the file back and consulted the same checkers;
/// that is the checkpoint `commit-msg` is for a commit, and none of it survived
/// the port. It does now.
fn install_editor(
    command: &mut Command,
    name: &str,
    variable: &str,
    own: Option<&Path>,
    argv: &[String],
) -> Result<()> {
    let Some(exe) = own else {
        // Refused, not warned. This printed the sentence below and then returned,
        // and the caller went on to exec the command -- so the one path the
        // editor re-entry exists to close stayed open, and the run that could
        // not check the text still published it. The warning even said "This is
        // not a pass" while exiting 0, which is the shape `explicit-unknown`
        // names. There is no safe way to continue: the body does not exist yet,
        // so it cannot be checked now, and after the hand-off there is no
        // process left here to check it later.
        return Err(Fatal::new(format!(
            "{name}: the body will be composed in an editor, and this shim could not find its \
             own path to stand in front of that editor. Nothing was published, because \
             nothing could be checked."
        )));
    };
    let editor = nonempty_env(variable)
        .or_else(|| nonempty_env("GIT_EDITOR"))
        .or_else(|| nonempty_env("VISUAL"))
        .or_else(|| nonempty_env("EDITOR"))
        .unwrap_or_else(|| String::from("vi"));
    command.env(EDITOR_REAL, editor);
    // Only the words that decide WHICH checkers stand in front of this command
    // line. They are matched as a subsequence and never re-executed, so joining
    // them is enough and quoting them would be pretending otherwise.
    command.env(EDITOR_ARGV, argv.join(" "));
    // These two are data the editor pass reads, and neither one routes anything:
    // a `git` that inherits them is a `git` that does nothing with them. What
    // says "you are the editor" is the flag below, which only the process the
    // command actually launches as its editor is given. See `Invoked::AsEditor`.
    command.env(
        variable,
        format!(
            "{} shim {EDITOR_FLAG} {}",
            shell_word(&exe.to_string_lossy()),
            shell_word(name)
        ),
    );
    eprintln!(
        "{name}: the body will be composed in an editor, so the editor is the checkpoint: what \
         it leaves in the file is checked when it closes."
    );
    Ok(())
}

/// The scope one rule is judged under: its own where it wrote one, the
/// table's where it did not.
fn effective_scope<'a>(rule: &'a Rule, shim: &'a Shim) -> &'a Scope {
    rule.command
        .as_ref()
        .and_then(|where_| where_.scope.as_ref())
        .unwrap_or(&shim.scope)
}

/// One invocation's scope answers, each predicate evaluated at most once.
///
/// A memo rather than a per-rule call, because `public-target` asks a forge
/// and three rules behind one table would ask it three times -- and because
/// the could-not-resolve arm says its piece on stderr, which said three times
/// reads as three failures.
#[derive(Default)]
struct ScopeMemo {
    answers: BTreeMap<String, Standing>,
}

impl ScopeMemo {
    /// Whether this scope holds, with a predicate that could not be asked
    /// answered by the table's `unresolved`.
    ///
    /// The conversion lives here rather than at each call site because there
    /// are six of them and one of them forgetting is the whole defect: a
    /// could-not-tell read as "does not hold" skips the checkers, and the
    /// destination guard behind them promises exit 2 on exactly that.
    fn holds(
        &mut self,
        shim: &Shim,
        scope: &Scope,
        root: &Path,
        collected: &Collected,
        argv: &[String],
    ) -> Result<bool> {
        match self.standing(shim, scope, root, collected, argv)? {
            Standing::Holds => Ok(true),
            Standing::DoesNotHold => Ok(false),
            Standing::CouldNotTell(why) => match shim.unresolved {
                Unresolved::Refuse => Err(Fatal::new(format!(
                    "{}: {why}. A check that could not look is not a check that passed, so \
                     nothing was published. Name the destination explicitly, run this where \
                     the repository has a remote and the forge can be reached, or write \
                     `unresolved = \"run\"` on this `[[shim]]` table to run the command \
                     unchecked instead",
                    shim.command
                ))),
                Unresolved::Run => Ok(false),
            },
        }
    }

    /// The predicate's own answer, asked once per invocation.
    ///
    /// The `run` half of `unresolved` says its piece here rather than in
    /// `holds`, so a table that stands three rules down over one unreachable
    /// forge prints one line and not three.
    fn standing(
        &mut self,
        shim: &Shim,
        scope: &Scope,
        root: &Path,
        collected: &Collected,
        argv: &[String],
    ) -> Result<Standing> {
        let key = match scope {
            Scope::Always => return Ok(Standing::Holds),
            Scope::PublicTarget => String::from("public-target"),
            Scope::PublicRegistry => String::from("public-registry"),
            Scope::Command { command } => format!("command:{command}"),
        };
        if let Some(answer) = self.answers.get(&key) {
            return Ok(answer.clone());
        }
        let answer = shim.scope_holds(scope, root, collected, argv)?;
        if let (Standing::CouldNotTell(why), Unresolved::Run) = (&answer, shim.unresolved) {
            eprintln!("uphold shim: {why}, and the command ran anyway. This is not a pass.");
        }
        self.answers.insert(key, answer.clone());
        Ok(answer)
    }
}

/// Run the user's editor, then judge what it produced.
///
/// Refusing here is what makes it a checkpoint rather than a report: `gh` and
/// `glab` abandon what they were doing when their editor exits non-zero,
/// exactly as git abandons a commit when `commit-msg` does.
fn edit_and_check(root: &Path, policy: &Policy, name: &str, argv: &[String]) -> Result<Exit> {
    // The command appends the file it wants written to the editor command line,
    // so the last word is that path however this process was routed back here.
    let Some(file) = argv.last() else {
        return Err(Fatal::new(format!(
            "{name}: re-entered as an editor with no file to edit"
        )));
    };
    let editor = nonempty_env(EDITOR_REAL).unwrap_or_else(|| String::from("vi"));
    // Through a shell, exactly the way the command would have run it, and with
    // the marker removed: the child here is the user's own editor, and a second
    // pass through this function is not what it is being asked for.
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("sh")
        .arg(file)
        .current_dir(root)
        .env_remove(EDITOR_REAL)
        .env_remove(EDITOR_ARGV)
        .status()
        .map_err(|error| Fatal::new(format!("{name}: editor: {error}")))?;
    if !status.success() {
        // The editor is how the text was going to be written, so an editor that
        // failed is neither a clean pass nor a violation: nothing was looked at,
        // and the command aborts on any non-zero anyway.
        eprintln!("{name}: the editor exited without success, so nothing was checked.");
        return Ok(Exit::Broken);
    }
    let path = Path::new(file);
    if !path.is_file() {
        // No file means nothing was written, which is nothing to publish.
        return Ok(Exit::Clean);
    }
    let text = std::fs::read_to_string(path).map_err(|error| Fatal::at(path, error))?;
    if text.trim().is_empty() {
        return Ok(Exit::Clean);
    }

    let opened_for: Vec<String> = nonempty_env(EDITOR_ARGV)
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let subject = Subject {
        kind: "text",
        value: text,
    };
    // The same kinds `run` consults, and for the reason the dispatch there
    // gives: a guard cannot judge a body typed into an editor one way and the
    // same body given with `--body` another under one id. Reading only `exec`
    // here meant a policy whose checker for this command is a BUILT-IN had a
    // checkpoint that opened an editor, read the file back, consulted nobody and
    // exited 0.
    //
    // Asked of `stands_in_front_of_a_command` rather than spelled out, which is
    // the fourth reader of that question and the reason it is one function: this
    // list and the one in `run` were the same four arms written twice, and a
    // kind added to one of them is a checker the editor checkpoint does not
    // consult -- the editor pass then reads the body back and finds nobody
    // standing at it.
    let named: Vec<&Rule> = policy
        .before_command(name, &opened_for)
        .filter(|rule| rule.stands_in_front_of_a_command())
        .collect();
    if named.is_empty() {
        // Nothing to consult, and the text exists now: this is a checkpoint
        // with nobody standing at it. Exit 2 rather than 0, because the command
        // abandons what it was doing on any non-zero -- and a body that reached
        // an editor installed by this shim and was then read by nothing must not
        // leave here looking like a body that passed.
        return Err(Fatal::new(format!(
            "{name}: the editor closed on a body to publish, and no rule stands in front of \
             `{}` -- no `command.before` names it. Nothing was published, because nothing \
             would have been checked",
            opened_for.join(" ")
        )));
    }
    // The same per-rule scopes the argv pass judges under. The editor was
    // installed because SOME rule's scope held; which ones consult the text is
    // answered here again, so a rule whose scope is the table's `public-target`
    // is not asked about a body bound for a private repository just because a
    // wider rule kept the checkpoint open.
    // Kept past the filter below, because the consultations ask it too: a
    // `text-guards` rule whose own scope held runs other rules, and each of
    // those is judged under its own scope off this same memo.
    let mut scoping = match policy.shims.iter().find(|shim| shim.command == name) {
        Some(shim) => Some((shim, shim.collect(root, &opened_for)?, ScopeMemo::default())),
        None => None,
    };
    let checkers: Vec<&Rule> = match &mut scoping {
        Some((shim, collected, scopes)) => {
            let shim = *shim;
            let mut kept: Vec<&Rule> = Vec::new();
            for rule in &named {
                if scopes.holds(
                    shim,
                    effective_scope(rule, shim),
                    root,
                    collected,
                    &opened_for,
                )? {
                    kept.push(*rule);
                }
            }
            if kept.is_empty() {
                // The policy answered: none of these checks applies to this
                // destination. That is a decision, not a gap.
                return Ok(Exit::Clean);
            }
            kept
        }
        // Cloned rather than moved: `named` is read again below, to tell a
        // rule this command names from one a consultation merely reaches.
        None => named.clone(),
    };
    let mut refusals: Vec<String> = Vec::new();
    for rule in checkers {
        if crate::guard::bypassed(&rule.id) {
            continue;
        }
        if !rule.selects_subject(subject.kind) {
            continue;
        }
        // The same dispatch the argv pass runs, off the same table. It was two
        // hand-written chains, and they had already drifted: this one tested
        // `regexp` and `require_regexp` and left a `prose_regexp` rule to fall
        // through to the `exec` consultation, which refused it as a dispatch
        // hole -- a body that reached an editor and was then read by nobody.
        let Some(kind) = crate::text::Judged::of(rule) else {
            continue;
        };
        if !crate::text::Seam::Command.consults(kind) {
            continue;
        }
        match kind {
            crate::text::Judged::Prose | crate::text::Judged::Patterns => {
                if let Some(refusal) = pattern_refusal(rule, &subject)? {
                    refusals.push(refusal);
                }
            }
            crate::text::Judged::Guards => {
                // As in `run`: a rule this consultation reaches keeps its own
                // effective scope, answered off the memo the filter above
                // already used.
                let mut in_scope = |inner: &Rule| match &mut scoping {
                    // As in `run`: only a rule this command names carries a
                    // scope written about it here.
                    _ if !named.iter().any(|stands| stands.id == inner.id) => Ok(true),
                    Some((shim, collected, scopes)) => scopes.holds(
                        shim,
                        effective_scope(inner, shim),
                        root,
                        collected,
                        &opened_for,
                    ),
                    // No `[[shim]]` table names this command, so there is no
                    // scope to judge under and nothing to stand down for.
                    None => Ok(true),
                };
                if let Some(refusal) = crate::guard::text_refusal(
                    root,
                    policy,
                    rule,
                    subject.kind,
                    &subject.value,
                    &mut in_scope,
                )? {
                    refusals.push(refusal.report);
                }
            }
            crate::text::Judged::Consultation => {
                if let Some(refusal) = consult(root, rule, &subject)? {
                    refusals.push(format!("{refusal}\n{}", rule.message()));
                }
            }
            // Not consulted here, and skipped above: a policy reaches the
            // literal rules from this seam through the `text-literals`
            // built-in, which arrives as `Guards`.
            crate::text::Judged::Literals => {}
        }
    }
    if refusals.is_empty() {
        return Ok(Exit::Clean);
    }
    for refusal in &refusals {
        eprintln!("{name}: {refusal}");
    }
    eprintln!(
        "Nothing was published, and what you wrote is still in {file}. Fix it there, or \
         override once with UPHOLD_ALLOW."
    );
    Ok(Exit::Violations)
}

/// Hand the process over to the real command.
///
/// A real `exec`, not a spawn and a wait. The shim is not a supervisor: exec
/// keeps the pid, the process group, terminal control and every signal
/// disposition the command was started with, and the status the caller reads is
/// the command's own. Waiting on a child and calling
/// `exit(status.code().unwrap_or(1))` loses all of it -- `code()` is `None` for
/// every death by a signal, so a command killed by SIGINT reported a plain exit
/// 1, which in this tool's own vocabulary is a policy violation.
#[cfg(unix)]
fn hand_off(command: &mut Command, name: &str, stdin: Option<&[u8]>) -> Result<Exit> {
    use std::os::unix::process::CommandExt;
    // A file rather than a pipe, and only here. After `exec` there is no process
    // left to feed a pipe, so the bytes have to be somewhere the kernel can hand
    // over on its own -- and the file is unlinked while still open, which leaves
    // the contents reachable through the descriptor and through no name at all.
    if let Some(bytes) = stdin {
        command.stdin(Stdio::from(replayed(bytes)?));
    }
    // `arg0` so the command sees the name it was invoked under rather than the
    // path this shim found it at.
    let error = command.arg0(name).exec();
    Err(Fatal::new(format!("{name}: {error}")))
}

#[cfg(not(unix))]
fn hand_off(command: &mut Command, name: &str, stdin: Option<&[u8]>) -> Result<Exit> {
    // A pipe rather than a file, and for a reason that is not symmetry: this
    // branch does not exec, it spawns and waits, so there IS a process left to
    // write the bytes -- and unlink-on-open is a Unix property. Windows refuses
    // to remove a file while a handle is open, so the temp file the Unix branch
    // relies on would survive the run holding the exact body the command
    // published, in a directory every account on the machine can read.
    let fed = stdin.is_some();
    if fed {
        command.stdin(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .map_err(|error| Fatal::new(format!("{name}: {error}")))?;
    if let (true, Some(bytes)) = (fed, stdin) {
        let mut sink = child
            .stdin
            .take()
            .ok_or_else(|| Fatal::new(format!("{name}: no stdin to replay the body into")))?;
        let owned = bytes.to_vec();
        std::thread::spawn(move || {
            sink.write_all(&owned).ok();
        });
    }
    // No exec to hand off to, so the closest thing: run it and carry its code
    // out. What this platform cannot preserve, it cannot preserve.
    let status = child
        .wait()
        .map_err(|error| Fatal::new(format!("{name}: {error}")))?;
    std::process::exit(status.code().unwrap_or(1));
}

/// Stand in front of one command.
///
/// argv arrives as bytes and LEAVES as bytes. On Unix an argument is an
/// arbitrary byte string -- a file named in latin-1 is a perfectly good
/// argument to `git add` -- and this binary is installed in front of `git`,
/// `gh` and `npm` precisely where such paths are typed. Converting the whole of
/// argv to text on the way in meant one of two failures: a panic at exit 101 on
/// a code path designed to be transparent, or a lossy conversion that execs a
/// command DIFFERENT from the one that was typed. So the words below are a
/// lossy copy used only to decide things -- which subcommand this is, which
/// flags were given -- while `command.args(argv)` hands the original bytes to
/// the exec. The two cannot disagree about a decision, because every string
/// this shim compares against is ASCII, and lossy conversion only ever replaces
/// a sequence that was not text to begin with.
pub(crate) fn run(
    root: &Path,
    policy: &Policy,
    name: &str,
    argv: &[OsString],
    invoked: Invoked,
) -> Result<Exit> {
    let words: Vec<String> = argv
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();

    // Re-entered as the command's own editor, which is answered before anything
    // else: in this pass argv is an editor's argv -- one file path -- and none
    // of the flag reading below applies to it.
    if invoked == Invoked::AsEditor {
        return edit_and_check(root, policy, name, &words);
    }

    let shims: BTreeMap<&str, &Shim> = policy
        .shims
        .iter()
        .map(|shim| (shim.command.as_str(), shim))
        .collect();
    let Some(shim) = shims.get(name) else {
        // Nothing here declares this command. The reading is the same either
        // way -- an absent declaration is a place the rule does not run, the
        // same way an absent `[git]` table is, and it is not a could-not-look,
        // so it is not exit 2 by the rule that governs those. What differs is
        // what was asked.
        //
        // Run AS the command, the answer lets it run. The link is on PATH for
        // the whole machine while a `[[shim]]` is a line in one repository's
        // policy, so refusing an undeclared command meant `git` exiting 2 in
        // every repository that had not declared one, and in every directory
        // that is not a repository at all. What gets installed after that is
        // nothing, which loses the seam everywhere rather than where it was
        // undeclared.
        //
        // Asked for BY NAME, the answer is an error: `uphold shim faux ...`
        // names a shim this repository does not have, nothing is standing in
        // front of anything, and the caller is entitled to hear that rather
        // than watch a typo run.
        return match invoked {
            Invoked::AsTheCommand => exec_through(name, argv),
            Invoked::ByName => Err(Fatal::new(format!(
                "no shim declares the command {name:?}; this policy declares {}",
                if shims.is_empty() {
                    String::from("none")
                } else {
                    shims.keys().copied().collect::<Vec<&str>>().join(", ")
                }
            ))),
            // The editor pass answered at the top of this function and never
            // reaches the shim table. Stated as a refusal rather than as an
            // `unreachable!`, because the two are only kept in step by the early
            // return above, and a panic here would be a shim killing a command.
            Invoked::AsEditor => Err(Fatal::new(format!(
                "{name}: an editor pass reached the shim table, which is answered \
                 before it. Nothing was published"
            ))),
        };
    };

    // An alias is a word the command expands before it decides anything, so a
    // shim that reads argv without expanding it is reading a different command
    // line from the one that runs. Asked only where nothing matched: a `match`
    // hit is already the answer, and the lookup is a process.
    let words = match shim.reading(&words) {
        Reading::Absent => shim.expand_alias(root, &words)?.unwrap_or(words),
        _ => words,
    };

    // Only the rules that name THIS command line. Selecting a checker by
    // anything coarser -- a `kind` saying it stands in front of some command,
    // without saying which -- asks a check written for a pull-request body
    // about a branch name on `git push` and a tarball on `npm publish`.
    // Two kinds stand in front of a command, and both are scoped by the same
    // `command.before`. An `exec` checker is a program this repository names.
    // A text-capable BUILT-IN is one the binary already carries -- and a
    // repository that wanted `no-private-repo-names` over a pull-request body
    // had no way to say so: the guard reads a commit message at every git hook,
    // which refuses the issue citations a repository's own prose is full of, so
    // the seam it belongs at is this one and only this one. Three repositories
    // wrote `command.before` on the built-in independently and the loader
    // refused all three, on the true-but-unhelpful grounds that a built-in is
    // not an `exec`. The field means what they meant now.
    //
    // One predicate, and `validate` refuses `command.before` on every rule it
    // answers no for -- so filtering here on the same question can drop nothing
    // a policy was allowed to load, and cannot fall behind a kind added to it.
    let checkers: Vec<&Rule> = policy
        .before_command(name, &words)
        .filter(|rule| rule.stands_in_front_of_a_command())
        .collect();
    let mut refusals: Vec<String> = Vec::new();
    // Whether any refusal below is about WHERE this would publish rather than
    // what it would say. The closing line tells the reader what to fix, and
    // telling someone to fix the text when the text was never the problem
    // sends them to reread a body that is fine while the destination stays
    // wrong. Counted rather than flagged, because a single run can refuse at
    // both seams, and a reader told only one of the two goes and fixes half of
    // what is holding the command.
    let mut destination_refusals = 0usize;

    let mut collected = Collected::default();
    let mut any_applies = false;
    let mut scopes = ScopeMemo::default();
    let reading = shim.reading(&words);
    if let Reading::Unclear(flag) = &reading {
        // Said out loud, and for the same reason the unresolvable-target arm in
        // `scope_holds` says its piece: the decision to run the command anyway is
        // deliberate, and making it in silence is not available. Refusing here
        // would stop every invocation carrying an option a release added to a
        // command this shim stands in front of machine-wide; running one whose
        // subcommand was never identified without a word about it is the shape
        // of failure this tool refuses.
        eprintln!(
            "uphold shim: {name}: {flag} sits before the subcommand and nothing here says \
             whether it takes the word after it, so which subcommand this is could not be \
             established and no checker ran. This is not a pass."
        );
    }
    // A `match` entry names the verb; whether THIS invocation of it publishes
    // anything is a second question, and exactly one verb has to be asked it --
    // see [`Shim::carries_a_body`]. Asked here rather than folded into
    // `reading`, because a matched verb that publishes nothing must stay
    // `Named`: an `Absent` reading sends the shim off to expand aliases, which
    // is a process per `gh api` GET and a refusal wherever the lookup fails.
    if matches!(reading, Reading::Named) && shim.carries_a_body(&words) {
        // The one place the bytes have to be text. This invocation is one the
        // shim reads values out of, and a value that is not UTF-8 cannot be
        // read as text -- checking the lossy copy would report a pass over
        // U+FFFD where the bytes were. Exit 2 rather than a lossy check, and
        // rather than a refusal: nothing was found, the subject could not be
        // looked at. An invocation the shim has nothing to say about is not
        // affected, which is what keeps `git add <latin1-name>` working.
        if let Some(bytes) = argv.iter().find(|argument| argument.to_str().is_none()) {
            return Err(Fatal::new(format!(
                "{name}: the argument {:?} is not UTF-8 text, and this invocation is one whose \
                 text is checked before it is published. No checker can read bytes that are not \
                 text, so nothing here can be called clean",
                bytes.to_string_lossy()
            )));
        }
        collected = shim.collect(root, &words)?;
        let in_scope = scopes.holds(shim, &shim.scope, root, &collected, &words)?;
        for rule in &checkers {
            if scopes.holds(shim, effective_scope(rule, shim), root, &collected, &words)? {
                any_applies = true;
            }
        }
        // A `[[shim]]` that named this invocation and a policy with no rule
        // standing in front of it: the shim collects the body, consults nobody,
        // execs the command and exits 0 -- which is indistinguishable from a
        // body every checker approved, and is the one outcome this tool exists
        // to make impossible. `[[shim]]` says which command lines are checked
        // before they are published; `command.before` says who checks them, and
        // neither implies the other. The load refuses a `[[shim]]` whose command
        // no rule names at all; this is the same reading one invocation later,
        // where the rules that name the command do not name THIS command line.
        //
        // Out of scope is not this case: there the policy answered, and the
        // answer was that these checks do not apply to this destination.
        if in_scope && checkers.is_empty() {
            return Err(Fatal::new(format!(
                "{name}: `{}` is an invocation this repository's `[[shim]]` says is checked \
                 before it is published, and no rule stands in front of it -- no \
                 `command.before` names it. Nothing was published, because nothing would have \
                 been checked",
                words.join(" ")
            )));
        }
        // Where a checker judges the DESTINATION rather than the text.
        //
        // This is the seam's other question, and for a long time it had no
        // asker: `[[shim]]` answered "is this text safe to publish?" and
        // `prevent-public-push` answered "may this push go to this owner?",
        // while a forge CLI told to publish clean prose to a repository this
        // workspace does not own satisfied both and published. An agent did
        // exactly that. The destination is a property of the INVOCATION and not
        // of any subject it carries, so it is asked once per run, outside the
        // subject loop, and asked even where the invocation collected no
        // subject at all.
        //
        // Resolved ONCE, before the loop, and only where some rule judges a
        // destination. `resolve_target` reads `--repo`/`-R` off argv and
        // otherwise `git remote get-url origin`; it asks no forge. Only
        // `Scope::PublicTarget`'s `visibility()` reaches a network, and this
        // consultation never calls it -- so a repository that adds this rule
        // pays no round trip on an ordinary invocation. That is worth stating,
        // because this repository's own argument against a check is that it
        // makes every invocation wait on somebody else's service, and a seam
        // that does is a seam somebody takes off PATH.
        if checkers.iter().any(|rule| {
            rule.builtin()
                .is_some_and(|builtin| crate::guard::TARGET_GUARDS.contains(&builtin))
        }) {
            let target = shim.resolve_target(root, &collected)?;
            for rule in &checkers {
                if crate::guard::bypassed(&rule.id) {
                    continue;
                }
                // The rule's own scope where it wrote one, the table's where it
                // did not -- the same reading the text path takes, answered
                // from the same memo.
                if !scopes.holds(shim, effective_scope(rule, shim), root, &collected, &words)? {
                    continue;
                }
                if let Some(refusal) =
                    crate::guard::target_refusal(root, policy, rule, target.as_deref())?
                {
                    destination_refusals += 1;
                    refusals.push(refusal.report);
                }
            }
        }

        if any_applies {
            for subject in &collected.subjects {
                // An empty subject is not a subject a checker can read: a
                // program handed "" on stdin, or a text guard asked whether ""
                // names a private repository, is being asked to judge text that
                // was never published. So the skip stands -- but it used to
                // stand out here, in front of every kind of checker, and it was
                // written when `exec` was the only kind there was.
                //
                // A pattern is the one kind an empty subject is an answer for,
                // and `require_regexp` is why. Its whole claim is that the
                // subject MUST look a certain way, and "" looks no way at all,
                // so skipping it turns the one check that would have refused
                // into one that reports clean: `--title ""` walked past a
                // release-title policy and published a release with no title.
                // An absent flag is genuinely different and stays different --
                // no subject of that kind is collected at all, so no rule is
                // asked, and the command supplies whatever default it has. This
                // is the case where the flag WAS given and what it named is
                // empty, which is a published subject like any other.
                let empty = subject.value.trim().is_empty();
                for rule in &checkers {
                    if crate::guard::bypassed(&rule.id) {
                        continue;
                    }
                    // The rule's own scope where it wrote one, the table's
                    // where it did not -- answered from the memo, so a
                    // destination is looked up once however many rules ask.
                    if !scopes.holds(shim, effective_scope(rule, shim), root, &collected, &words)? {
                        continue;
                    }
                    // `subjects` narrows every kind of checker the same way:
                    // a rule about titles is not asked about a body, whichever
                    // field does its checking.
                    if !rule.selects_subject(subject.kind) {
                        continue;
                    }
                    // What kind of rule this is, and whether this seam consults
                    // it, both answered from the one table in `text` -- so a
                    // rule kind cannot be added to three seams and left dark in
                    // the fourth, which is how the prose rules missed `hook`.
                    let Some(kind) = crate::text::Judged::of(rule) else {
                        continue;
                    };
                    if !crate::text::Seam::Command.consults(kind) {
                        continue;
                    }
                    match kind {
                        crate::text::Judged::Prose | crate::text::Judged::Patterns => {
                            if let Some(refusal) = pattern_refusal(rule, subject)? {
                                refusals.push(refusal);
                            }
                        }
                        // A subject that was named and left empty is still a
                        // published subject, and a pattern rule judges it above
                        // -- `require_regexp` is about what is NOT there. There
                        // is nothing in it for a guard or a checker to read.
                        _ if empty => {}
                        // The same dispatch `uphold guard --text` runs, so a
                        // guard cannot judge a commit message one way and a
                        // pull-request body another under one id.
                        crate::text::Judged::Guards => {
                            // The consultation gets the same memo the loop
                            // above asks: a rule this guard runs on its behalf
                            // is judged under its own effective scope, exactly
                            // as if `command.before` had brought the shim to it
                            // directly. So a `public-target` rule behind an
                            // `always` consultation is asked about a public
                            // destination and no other.
                            let mut inner_in_scope = |inner: &Rule| {
                                // Only a rule this invocation's own
                                // `command.before` names has a scope written
                                // about it here. A guard the consultation
                                // reaches that stands at a git hook and
                                // nowhere else -- or that names another
                                // command -- was never a rule the table's
                                // scope spoke for, and reading the table at it
                                // would stand down a check nobody scoped.
                                if !checkers.iter().any(|named| named.id == inner.id) {
                                    return Ok(true);
                                }
                                scopes.holds(
                                    shim,
                                    effective_scope(inner, shim),
                                    root,
                                    &collected,
                                    &words,
                                )
                            };
                            if let Some(refusal) = crate::guard::text_refusal(
                                root,
                                policy,
                                rule,
                                subject.kind,
                                &subject.value,
                                &mut inner_in_scope,
                            )? {
                                refusals.push(refusal.report);
                            }
                        }
                        crate::text::Judged::Consultation => {
                            if let Some(refusal) = consult(root, rule, subject)? {
                                refusals.push(format!("{refusal}\n{}", rule.message()));
                            }
                        }
                        // See the editor pass: reached from here through the
                        // `text-literals` built-in, which arrives as `Guards`.
                        crate::text::Judged::Literals => {}
                    }
                }
            }
        }
    }

    if !refusals.is_empty() {
        for refusal in &refusals {
            eprintln!("{name}: {refusal}");
        }
        let what = if destination_refusals == 0 {
            "the text"
        } else if destination_refusals == refusals.len() {
            "the destination"
        } else {
            "the text and the destination"
        };
        eprintln!("Nothing was published. Fix {what}, or override once with UPHOLD_ALLOW.");
        return Ok(Exit::Violations);
    }

    // Exec through. A shim that checked and then did not run the command is a
    // shim that broke the command.
    let own = std::env::current_exe().ok();
    let Some(real) = real_command(name, own.as_deref()) else {
        return Err(Fatal::new(format!(
            "checked {name} and then could not find the real one on PATH"
        )));
    };
    let mut command = Command::new(&real);
    command.args(argv);
    // Everything the command needs that this shim took from it, arranged before
    // the hand-off because after it there is no arranging anything: the body
    // read off stdin, and the editor it is about to open.
    // `any_applies`, not the table's answer: the editor exists to be read by
    // the rules, and what decides whether anything will read it is whether any
    // rule's scope holds -- a rule that applies on every egress keeps the
    // checkpoint open where the table alone would have stood down.
    let editor_env = shim
        .editor_env
        .as_deref()
        .filter(|_| any_applies && !collected.body_given && !collected.web);
    if let Some(variable) = editor_env {
        install_editor(&mut command, name, variable, own.as_deref(), &words)?;
    }
    hand_off(&mut command, name, collected.stdin.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Check, CheckKind};

    fn gh() -> Shim {
        Shim {
            command: String::from("gh"),
            match_: vec!["pr:create".into(), "issue:*".into()],
            text_flags: vec!["-t".into(), "--title".into(), "-b".into(), "--body".into()],
            title_flags: Vec::new(),
            file_flags: vec!["-F".into(), "--body-file".into()],
            path_flags: Vec::new(),
            target_flags: vec!["-R".into(), "--repo".into()],
            skip_flags: vec!["--fill".into()],
            web_flags: vec!["-w".into(), "--web".into()],
            argv_subject: false,
            editor_env: Some(String::from("GH_EDITOR")),
            target: Target::ForgeRepo,
            scope: Scope::PublicTarget,
            // The default, which is what the shipped policy leaves it at.
            unresolved: Unresolved::Refuse,
            collect: Collect::Flags,
            // No verb differs from the table here; every shim written
            // before `[[shim.verbs]]` existed is this case.
            verbs: Vec::new(),
        }
    }

    /// A `git` shim as the shipped policy declares it: positional text, and
    /// none of git's global grammar written into the table.
    fn git_push() -> Shim {
        Shim {
            command: String::from("git"),
            match_: vec!["push:*".into()],
            text_flags: Vec::new(),
            title_flags: Vec::new(),
            file_flags: Vec::new(),
            path_flags: Vec::new(),
            target_flags: Vec::new(),
            skip_flags: Vec::new(),
            web_flags: Vec::new(),
            argv_subject: false,
            editor_env: None,
            target: Target::GitRemote,
            scope: Scope::PublicTarget,
            // The default, which is what the shipped policy leaves it at.
            unresolved: Unresolved::Refuse,
            collect: Collect::GitRefs,
            // No verb differs from the table here; every shim written
            // before `[[shim.verbs]]` existed is this case.
            verbs: Vec::new(),
        }
    }

    fn argv(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    fn named(shim: &Shim, line: &str) -> bool {
        matches!(shim.reading(&argv(line)), Reading::Named)
    }

    #[test]
    fn a_named_subcommand_matches_and_an_unnamed_one_does_not() {
        // Named rather than pattern-matched: a shim that guesses which
        // subcommands carry text is one release away from missing a new one in
        // silence.
        assert!(named(&gh(), "pr create"));
        assert!(named(&gh(), "issue comment"));
        assert!(!named(&gh(), "pr checkout"));
        assert!(!named(&gh(), "repo clone"));
    }

    #[test]
    fn a_git_global_option_does_not_switch_the_push_shim_off() {
        // The grammar a `[[shim]]` table does not carry and should not have to.
        // Skipping only the flags the table names, `git -c user.name=x push
        // origin topic` reads `user.name=x` as the verb -- no `match` entry
        // contains that, so a push to a public forge exec'd unexamined, silently
        // and with an exit code of 0.
        for line in [
            "-c user.name=x push origin topic",
            "-C /somewhere/else push origin topic",
            "--git-dir /elsewhere/.git push",
            "--git-dir=/elsewhere/.git push",
            "--no-pager push origin topic",
            "-c a=b -C /elsewhere --no-pager push",
        ] {
            assert!(named(&git_push(), line), "{line}");
        }
        // And the half a looser matcher would lose. `Absent` rather than merely
        // unnamed: knowing git's grammar is what makes this a decision instead
        // of an ambiguity, so `-c` swallowing a value spelled like a subcommand
        // is answered rather than warned about.
        for line in ["-c user.name=push status", "-C /elsewhere log"] {
            assert!(
                matches!(git_push().reading(&argv(line)), Reading::Absent),
                "{line}"
            );
        }
    }

    #[test]
    fn an_option_nothing_can_classify_is_unclear_rather_than_absent() {
        // A guard that could not tell which subcommand it was looking at has
        // not established that this is none of its business. Both readings are
        // tried first -- one of them matching IS an answer -- and only a line
        // no reading names lands here.
        //
        // TWO unclassified options, because that is what makes the two readings
        // a sample rather than the space. `words` applies `unknown_takes_value`
        // uniformly, so N of them have 2^N readings and exactly two are tried.
        // Here `--fic-a --fic-b` reads `x`/`y` bare and `status` valued, and
        // neither is named, but the two readings not tried were never asked.
        assert!(matches!(
            git_push().reading(&argv("--fic-a x --fic-b y status")),
            Reading::Unclear(flag) if flag == "--fic-a"
        ));
        // And ONE is the whole space, so both readings missing is a conclusion
        // rather than a doubt. This line asserted `Unclear` until #56, and what
        // that cost was measured: on a git shim declaring `push:*`, 9 of 16
        // ordinary invocations printed the could-not-look refusal -- `git show
        // --stat HEAD`, `git commit -F -`, `git checkout -b <name>`, `git reset
        // --hard HEAD` among them -- while `git push` itself was quiet. A
        // warning printed over every command this shim exists to stay out of
        // the way of trains the reader to ignore the one invocation where the
        // doubt is real, which is the failure the whole arm was written to
        // avoid. Nothing about safety moved: `Unclear` runs no checker and
        // collects nothing, so it and `Absent` differ in the message alone.
        assert!(matches!(
            git_push().reading(&argv("--fictional-option value status")),
            Reading::Absent
        ));
        // A word that follows nothing took nothing, whatever its grammar says:
        // `gh --version` is not an invocation whose subcommand went missing.
        assert!(matches!(
            gh().reading(&argv("--fictional-option")),
            Reading::Absent
        ));
        // And an option a reading DOES resolve into a match is a match, not an
        // ambiguity: erring towards checking is the direction this seam exists
        // to err in.
        assert!(named(
            &git_push(),
            "--fictional-option value push origin topic"
        ));
    }

    #[test]
    fn an_option_after_the_subcommand_does_not_make_the_subcommand_unclear() {
        // The doubt an unclassifiable option raises is doubt about WHICH WORD
        // the subcommand is. An option that cannot move it -- because the
        // subcommand was already read, or because swallowing the next word
        // leaves the same pair -- raises none, and saying otherwise puts a
        // could-not-look line on the terminal for `git log -1 --oneline`. A
        // refusal a reader sees on every ordinary command is a refusal they
        // stop reading, which costs the one invocation where it was true.
        for line in [
            "log -1 --oneline",
            "status --short --branch",
            "diff --stat --cached",
            "log --format=%H -5",
        ] {
            assert!(
                matches!(git_push().reading(&argv(line)), Reading::Absent),
                "{line}"
            );
        }
    }

    #[test]
    fn a_flag_is_read_in_both_spellings() {
        let collected = gh()
            .collect(Path::new("."), &argv("pr create --title=Hello -b Body"))
            .unwrap();
        let values: Vec<&str> = collected
            .subjects
            .iter()
            .map(|subject| subject.value.as_str())
            .collect();
        assert_eq!(values, vec!["Hello", "Body"]);
    }

    #[test]
    fn the_target_flag_overrides_the_resolver() {
        let collected = gh()
            .collect(Path::new("."), &argv("pr create -R acme/widget -t x"))
            .unwrap();
        assert_eq!(collected.target.as_deref(), Some("acme/widget"));
    }

    #[test]
    fn a_skip_flag_supplies_the_body_without_becoming_a_subject() {
        // `--fill` takes the body from commit messages, which commit-msg
        // already guarded on the way in. Checking it again would refuse text
        // that is already published and cannot be edited.
        let collected = gh()
            .collect(Path::new("."), &argv("pr create --fill"))
            .unwrap();
        assert!(collected.subjects.is_empty());
        assert!(collected.body_given);
    }

    #[test]
    fn a_valueless_flag_does_not_swallow_the_flag_after_it() {
        // `--fill` takes no value. A walker that consumed one anyway would
        // step over `--title`, and the one string this shim exists to check
        // would exec through unread.
        let collected = gh()
            .collect(Path::new("."), &argv("pr create --fill --title Hello"))
            .unwrap();
        let values: Vec<&str> = collected
            .subjects
            .iter()
            .map(|subject| subject.value.as_str())
            .collect();
        assert_eq!(values, vec!["Hello"]);

        let web_collected = gh()
            .collect(Path::new("."), &argv("pr create -w -t Hello"))
            .unwrap();
        assert!(web_collected.web);
        assert_eq!(web_collected.subjects.len(), 1);
    }

    #[test]
    fn a_hard_link_carries_the_identity_of_its_target() {
        // A hard link canonicalizes to its own path, so a path comparison
        // would exec it as "the real command" -- this program again, forever.
        let dir = crate::fixture::scratch("shim-link");
        std::fs::create_dir_all(&dir).unwrap();
        let original = dir.join("uphold");
        std::fs::write(&original, "binary").unwrap();
        let link = dir.join("gh");
        if link.is_file() {
            std::fs::remove_file(&link).unwrap();
        }
        std::fs::hard_link(&original, &link).unwrap();
        assert!(file_identity(&link).is_some());
        assert_eq!(file_identity(&link), file_identity(&original));
    }

    #[test]
    fn npm_is_out_of_scope_when_the_package_says_private() {
        // The reason `scope` is an enum and not a boolean: there is no
        // repository, no owner and no visibility endpoint in npm's question.
        let dir = crate::fixture::scratch("shim");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("package.json"), r#"{"private": true}"#).unwrap();
        let mut npm = gh();
        npm.command = String::from("npm");
        npm.scope = Scope::PublicRegistry;
        assert_eq!(
            npm.scope_holds(
                &Scope::PublicRegistry,
                &dir,
                &Collected::default(),
                &argv("publish")
            )
            .unwrap(),
            Standing::DoesNotHold
        );
    }

    #[test]
    fn a_dry_run_publishes_nothing_and_is_out_of_scope() {
        // Refusing one would stop the very command somebody runs to find out
        // what they are about to publish.
        let mut npm = gh();
        npm.scope = Scope::PublicRegistry;
        assert_eq!(
            npm.scope_holds(
                &Scope::PublicRegistry,
                Path::new("."),
                &Collected::default(),
                &argv("publish --dry-run")
            )
            .unwrap(),
            Standing::DoesNotHold
        );
    }

    #[test]
    fn a_global_option_does_not_shift_which_word_the_branch_is() {
        // One grammar, read once. `reading` learned that `-c` takes the word
        // after it -- which is what made `git -c user.name=x push` match at all
        // -- and the collector was still counting argv positions, so it read
        // `user.name=x` as the remote and `push` as the branch. The name being
        // published was checked nowhere, and the fallback that reads it off
        // HEAD was skipped by the word the misreading had collected.
        let push = git_push();
        let names = |line: &str| -> Vec<String> {
            push.collect(Path::new("."), &argv(line))
                .unwrap()
                .subjects
                .into_iter()
                .map(|subject| subject.value)
                .collect()
        };
        for line in [
            "push origin topic",
            "-c user.name=x push origin topic",
            "-C elsewhere push origin topic",
            "--git-dir /elsewhere/.git push origin topic",
            "--no-pager push origin topic",
        ] {
            assert_eq!(names(line), vec![String::from("topic")], "{line}");
        }
    }

    #[test]
    fn a_refspec_publishes_both_halves_of_its_name() {
        let mut push = gh();
        push.collect = Collect::GitRefs;
        push.match_ = vec!["push:*".into()];
        let collected = push
            .collect(
                Path::new("."),
                &argv("push origin refs/heads/fix/thing:published"),
            )
            .unwrap();
        let values: Vec<&str> = collected
            .subjects
            .iter()
            .map(|subject| subject.value.as_str())
            .collect();
        assert_eq!(values, vec!["fix/thing", "published"]);
        assert!(collected
            .subjects
            .iter()
            .all(|subject| subject.kind == "ref"));
    }

    #[test]
    fn an_option_before_the_subcommand_does_not_disable_the_shim() {
        // The defect this pair exists for: read positionally, `gh --repo
        // acme/widget issue create` has the verb `--repo` and the noun
        // `acme/widget`, no `match` entry contains that pair, and a publishing
        // command execs unexamined with nothing printed and an exit code of 0.
        for line in [
            "--repo acme/widget issue create",
            "-R acme/widget pr create",
            "--repo=acme/widget pr create",
            "-w issue comment",
            "-- pr create",
        ] {
            assert!(named(&gh(), line), "{line}");
        }
        // And it still says no to what it has nothing to say about, which is
        // the half a looser matcher would lose.
        for line in [
            "--repo acme/widget pr checkout",
            "-R acme/widget repo clone",
        ] {
            assert!(!named(&gh(), line), "{line}");
        }
    }

    #[test]
    fn a_flags_value_is_never_read_as_a_subcommand() {
        // `--title pr` puts the word `pr` in argv without the invocation being
        // about a pull request, and only this table knows that `--title` took
        // it.
        let words = gh().words(&argv("--title pr create issue"), false);
        assert_eq!(
            (words.verb.as_str(), words.noun.as_str()),
            ("create", "issue")
        );
    }

    #[test]
    fn the_visibility_question_goes_to_the_forge_that_can_answer_it() {
        // Asking `gh` about a GitLab remote is why the shipped `glab` shim
        // could never resolve a target: `gh api repos/<owner>/<repo>` answers
        // about GitHub and about nothing else.
        let mut glab = gh();
        glab.command = String::from("glab");
        assert_eq!(glab.forge(Path::new(".")), Some(Forge::GitLab));
        assert_eq!(gh().forge(Path::new(".")), Some(Forge::GitHub));
    }

    #[test]
    fn a_word_with_a_quote_in_it_survives_the_shell_that_splits_it() {
        // The editor variable is handed to a shell, so this binary's own path
        // has to arrive as one word whatever is in it.
        assert_eq!(shell_word("/opt/my tools/uphold"), "'/opt/my tools/uphold'");
        assert_eq!(shell_word("it's"), r"'it'\''s'");
    }

    #[test]
    fn the_stdin_a_shim_ate_is_handed_back_whole() {
        // Well past a pipe's 64 KiB, because a pipe is exactly what cannot
        // carry this: after `exec` there is nobody left to write into one.
        let body: Vec<u8> = std::iter::repeat_n(b"ordinary text\n", 20_000)
            .flatten()
            .copied()
            .collect();
        let mut file = replayed(&body).unwrap();
        let mut read_back = Vec::new();
        std::io::copy(&mut file, &mut read_back).unwrap();
        assert_eq!(read_back, body);
    }

    #[test]
    fn a_private_field_that_is_false_does_not_make_a_package_private() {
        assert!(json_bool_field(r#"{"private": true}"#, "private"));
        assert!(!json_bool_field(r#"{"private": false}"#, "private"));
        assert!(!json_bool_field(r#"{"name": "x"}"#, "private"));
    }

    #[test]
    fn a_star_match_names_every_invocation_without_walking_argv() {
        // The answer a whole-command table gives, read before argv is walked at
        // all: a command whose every subcommand publishes has no pair to list,
        // and a `*` reached through the pair list would only ever match the
        // literal words `*` and nothing.
        let mut every = gh();
        every.match_ = vec!["*".into()];
        assert!(named(&every, "repo clone"));
        assert!(named(&every, "pr create"));
        assert!(named(&every, ""));
        // And the table that did not write it still says no to what it does not
        // name, which is the half a looser matcher would lose.
        assert!(!named(&gh(), "repo clone"));
    }

    #[test]
    fn two_unclassifiable_options_that_leave_the_same_pair_are_not_unclear() {
        // Past one unclassified option the two readings are a sample rather
        // than the space, so the older test stands: they leave the SUBCOMMAND
        // in doubt only where they DISAGREE about which word it is. Reporting
        // could-not-look on a pair both readings agree about puts the refusal
        // on ordinary commands, and a refusal a reader sees everywhere is one
        // they stop reading.
        assert!(matches!(
            gh().reading(&argv("--fic-a --fic-b pr checkout")),
            Reading::Absent
        ));
        // The same two options with a word between them do move the pair, and
        // that is the doubt this arm exists to say out loud.
        assert!(matches!(
            gh().reading(&argv("--fic-a x --fic-b y pr checkout")),
            Reading::Unclear(flag) if flag == "--fic-a"
        ));
    }

    #[test]
    fn a_path_flag_collects_a_path_rather_than_a_body() {
        // The kind is not decoration: a checker that greps prose for a private
        // name and one that judges a tree are not the same checker, and only
        // the kind tells them apart. Nor is a path a body -- marking one
        // `body_given` would close the editor checkpoint over the text the
        // command is about to open an editor for.
        let mut with_paths = gh();
        with_paths.path_flags = vec!["-p".into(), "--path".into()];
        let collected = with_paths
            .collect(
                Path::new("."),
                &argv("pr create -p src/lib.rs --path=README.md"),
            )
            .unwrap();
        let subjects: Vec<(&str, &str)> = collected
            .subjects
            .iter()
            .map(|subject| (subject.kind, subject.value.as_str()))
            .collect();
        assert_eq!(
            subjects,
            vec![("path", "src/lib.rs"), ("path", "README.md")]
        );
        assert!(!collected.body_given);
    }

    #[test]
    fn a_body_file_that_is_not_there_is_refused_rather_than_run_unchecked() {
        // `body_given` is set before the file is read, so a `-F` naming a file
        // that is not there left the shim with a body it had been told about,
        // no subject to check and nothing to say: it collected nothing and
        // exec'd the command, which is a pass over text no checker saw.
        let missing = crate::fixture::scratch("shim-missing-body").join("body.md");
        let report = gh()
            .collect(
                Path::new("."),
                &argv(&format!("pr create -F {}", missing.display())),
            )
            .unwrap_err()
            .to_string();
        assert!(report.contains("which is not a file"), "{report}");
        assert!(report.contains("nothing checked"), "{report}");
    }

    /// The `npm` table as the shipped policy declares it: a tree rather than a
    /// flag value, and a registry rather than a repository.
    fn npm() -> Shim {
        let mut npm = gh();
        npm.command = String::from("npm");
        npm.match_ = vec!["publish:*".into()];
        npm.collect = Collect::NpmPackage;
        npm.scope = Scope::PublicRegistry;
        npm.target = Target::None;
        npm
    }

    #[test]
    fn an_npm_package_publishes_its_metadata_its_readme_and_its_tree() {
        // What `npm publish` sends is a FILE TREE, so the subject kinds are
        // `text` for the metadata and `path` for the tree. Read off the file
        // rather than out of `npm pkg get`: that runs npm, and this shim is
        // what npm is currently behind.
        let dir = crate::fixture::scratch("shim-npm");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            r#"{"name": "widget", "description": "a widget"}"#,
        )
        .unwrap();
        std::fs::write(dir.join("README.md"), "the readme\n").unwrap();

        let collected = npm().collect(&dir, &argv("publish")).unwrap();
        let subjects: Vec<(&str, &str)> = collected
            .subjects
            .iter()
            .map(|subject| (subject.kind, subject.value.as_str()))
            .collect();
        assert_eq!(
            subjects,
            vec![
                ("text", "widget"),
                ("text", "a widget"),
                ("text", "the readme\n"),
                ("path", dir.to_string_lossy().as_ref()),
            ]
        );
        // npm opens no editor and has no web form, so neither seam is left
        // open behind this collector.
        assert!(collected.body_given);
        assert!(!collected.web);

        // A dry run publishes nothing, and refusing one would stop the very
        // command somebody runs to find out what they are about to publish.
        let dry = npm().collect(&dir, &argv("publish --dry-run")).unwrap();
        assert!(dry.subjects.is_empty());
    }

    #[test]
    fn an_argv_subject_carries_the_whole_command_line() {
        // For the rule whose subject is the invocation itself rather than
        // anything it names, and it is collected BESIDE the flag values rather
        // than instead of them.
        let mut whole = gh();
        whole.argv_subject = true;
        let collected = whole
            .collect(Path::new("."), &argv("pr create -t Hello"))
            .unwrap();
        let last = collected.subjects.last().unwrap();
        assert_eq!(
            (last.kind, last.value.as_str()),
            ("argv", "pr create -t Hello")
        );
        assert_eq!(collected.subjects.len(), 2);
    }

    #[test]
    fn a_scope_of_always_holds_without_asking_anything() {
        // The right default for a command with no destination. Asked directly,
        // because every other caller reaches it through the memo, which
        // answers `always` before the predicate is consulted at all.
        assert_eq!(
            gh().scope_holds(
                &Scope::Always,
                Path::new("."),
                &Collected::default(),
                &argv("pr create")
            )
            .unwrap(),
            Standing::Holds
        );
    }

    #[test]
    fn a_target_that_could_not_be_resolved_is_not_a_pass() {
        // No answer is not "public": refusing a push because a lookup was
        // unavailable would make the guard the reason work stops. Falling open
        // is the decision; doing it in SILENCE was not, and silence looks
        // exactly like a checker that ran and approved.
        let mut nowhere = gh();
        // Neither forge CLI, so nothing here reaches a network.
        nowhere.command = String::from("faux");
        nowhere.target = Target::None;
        assert!(matches!(
            nowhere
                .scope_holds(
                    &Scope::PublicTarget,
                    Path::new("."),
                    &Collected::default(),
                    &argv("pr create")
                )
                .unwrap(),
            Standing::CouldNotTell(why) if why.contains("no target could be resolved")
        ));
    }

    #[test]
    fn a_target_on_a_host_no_resolver_knows_is_not_a_pass_either() {
        // `-R acme/widget` answers WHICH repository without answering whose
        // forge it is, and an unrecognised host means no resolver applies. The
        // caller says so rather than reporting a pass over a visibility nobody
        // read.
        let dir = crate::fixture::scratch("shim-no-forge");
        std::fs::create_dir_all(&dir).unwrap();
        let mut unknown_host = gh();
        // Not `gh` or `glab`: those name their forge by being run at all, and
        // asking one would reach the network.
        unknown_host.command = String::from("faux");
        let collected = Collected {
            target: Some(String::from("acme/widget")),
            ..Collected::default()
        };
        assert_eq!(unknown_host.forge(&dir), None);
        assert!(matches!(
            unknown_host
                .scope_holds(&Scope::PublicTarget, &dir, &collected, &argv("pr create"))
                .unwrap(),
            Standing::CouldNotTell(why) if why.contains("did not say whether acme/widget is public")
        ));
    }

    #[test]
    fn a_package_that_is_not_private_is_judged_by_the_registry_it_names() {
        // Two independent reasons npm's question is nobody's business, and
        // either one is enough. `"private": false` is not one of them -- the
        // field is WRITTEN, so a scan for the word alone would stand the whole
        // check down -- so the registry decides.
        let dir = crate::fixture::scratch("shim-registry");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            r#"{"name": "widget", "private": false}"#,
        )
        .unwrap();
        assert_eq!(
            npm()
                .scope_holds(
                    &Scope::PublicRegistry,
                    &dir,
                    &Collected::default(),
                    &argv("publish")
                )
                .unwrap(),
            Standing::Holds
        );
        // A registry that is not the public one is somebody's internal
        // infrastructure, whatever the package says about itself.
        let internal = Collected {
            target: Some(String::from("https://npm.acme.example/")),
            ..Collected::default()
        };
        assert_eq!(
            npm()
                .scope_holds(&Scope::PublicRegistry, &dir, &internal, &argv("publish"))
                .unwrap(),
            Standing::DoesNotHold
        );
    }

    #[test]
    fn one_scope_predicate_is_asked_once_however_many_rules_ask_it() {
        // `public-target` asks a forge, and three rules behind one table would
        // ask it three times -- and the could-not-resolve arm says its piece on
        // stderr, which said three times reads as three failures.
        let dir = crate::fixture::scratch("shim-memo");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("package.json"), r#"{"private": true}"#).unwrap();
        let asked = dir.join("asked");
        let scope = Scope::Command {
            command: format!("echo asked >> {}", asked.display()),
        };
        let mut memo = ScopeMemo::default();
        for _ in 0..3 {
            assert!(memo
                .holds(
                    &npm(),
                    &scope,
                    &dir,
                    &Collected::default(),
                    &argv("publish")
                )
                .unwrap());
            // A different predicate is a different key, and is not answered
            // out of the first one's memo.
            assert!(!memo
                .holds(
                    &npm(),
                    &Scope::PublicRegistry,
                    &dir,
                    &Collected::default(),
                    &argv("publish")
                )
                .unwrap());
        }
        assert_eq!(
            std::fs::read_to_string(&asked).unwrap().lines().count(),
            1,
            "the scope command was run more than once"
        );
    }

    #[test]
    fn a_field_spelled_as_a_number_or_a_bool_is_still_an_answer() {
        // A forge that answers with a number has answered, and a caller that
        // dropped it would treat a lookup that happened as one that did not.
        assert_eq!(
            json_string_field(r#"{"visibility": "public"}"#, "visibility").as_deref(),
            Some("public")
        );
        assert_eq!(
            json_string_field(r#"{"id": 42}"#, "id").as_deref(),
            Some("42")
        );
        assert_eq!(
            json_string_field(r#"{"private": true}"#, "private").as_deref(),
            Some("true")
        );
        // A nested object is not an answer the caller can use, and -- the
        // reason this is a parser rather than a scan for `"visibility"` -- a
        // field found INSIDE one is somebody else's field. The shim stands in
        // front of publication on the strength of this value.
        assert_eq!(
            json_string_field(r#"{"owner": {"login": "acme"}}"#, "owner"),
            None
        );
        assert_eq!(
            json_string_field(r#"{"owner": {"visibility": "public"}}"#, "visibility"),
            None
        );
    }

    /// A pattern rule the config would accept, in whichever direction.
    fn pattern_rule(check: CheckKind, pattern: &str) -> Rule {
        let selected = if check == CheckKind::RequireRegexp {
            Check::RequireRegexp {
                require_regexp: pattern.to_owned(),
            }
        } else {
            Check::Regexp {
                regexp: pattern.to_owned(),
            }
        };
        let mut rule = Rule::synthetic("pattern-rule", selected);
        rule.message = Some(String::from("fix the text"));
        rule
    }

    #[test]
    fn a_pattern_rule_names_the_kind_the_pattern_and_what_it_found() {
        // The reader's next step is to fix the text, so "refused" without
        // which-test-failed is a round trip.
        let title = Subject {
            kind: "title",
            value: String::from("Generated with Claude Code"),
        };
        let refusal = pattern_refusal(&pattern_rule(CheckKind::Regexp, "Claude Code"), &title)
            .unwrap()
            .unwrap();
        for wanted in [
            "pattern-rule",
            "title subject",
            "Claude Code",
            "fix the text",
        ] {
            assert!(
                refusal.contains(wanted),
                "{wanted} is missing from {refusal}"
            );
        }
    }

    #[test]
    fn a_pattern_that_is_satisfied_refuses_nothing_in_either_direction() {
        // The half that is easy to lose: a checkpoint that refuses everything
        // is not a checkpoint. Both directions, because they are opposite
        // tests over one engine -- `regexp` refuses a subject the pattern is
        // present in, `require_regexp` one it is absent from.
        let ordinary = Subject {
            kind: "title",
            value: String::from("v2.0.0"),
        };
        assert!(
            pattern_refusal(&pattern_rule(CheckKind::Regexp, "Claude Code"), &ordinary)
                .unwrap()
                .is_none()
        );
        assert!(pattern_refusal(
            &pattern_rule(CheckKind::RequireRegexp, r"^v[0-9]+\.[0-9]+\.[0-9]+$"),
            &ordinary
        )
        .unwrap()
        .is_none());
        // And a rule carrying neither pattern says nothing rather than
        // refusing a subject no pattern was ever written for.
        assert!(pattern_refusal(
            &Rule::synthetic("no-pattern", Check::empty(CheckKind::Builtin)),
            &ordinary
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn a_checker_consulted_without_an_exec_command_is_a_dispatch_hole_not_a_pass() {
        // `exec` and `values_from` were one field called `run` in v2, and a
        // rule mis-dispatched to this function once ran `sh -c ""`, approved
        // everything it was asked about, and the pass was indistinguishable
        // from a checker that looked.
        let subject = Subject {
            kind: "text",
            value: String::from("anything at all"),
        };
        let blank = Rule::synthetic(
            "blank-exec",
            Check::Exec {
                exec: String::from("   "),
            },
        );
        for rule in [
            Rule::synthetic("no-exec", Check::empty(CheckKind::Builtin)),
            blank,
        ] {
            let report = consult(Path::new("."), &rule, &subject)
                .unwrap_err()
                .to_string();
            assert!(report.contains("a dispatch hole, not a pass"), "{report}");
        }
    }

    #[test]
    fn a_checker_that_stopped_reading_the_subject_has_not_answered_about_it() {
        // The one case where a 0 means nothing at all: the checker approved
        // whatever part of the subject got through, and that is not what this
        // invocation is about to publish. Well past a pipe's 64 KiB, because
        // inside one the write completes and the question never arises.
        let deaf = Rule::synthetic(
            "reads-nothing",
            Check::Exec {
                exec: String::from("exit 0"),
            },
        );
        let subject = Subject {
            kind: "text",
            value: "ordinary text\n".repeat(80_000),
        };
        let report = consult(Path::new("."), &deaf, &subject)
            .unwrap_err()
            .to_string();
        assert!(
            report.contains("did not take the whole text subject"),
            "{report}"
        );
    }

    #[test]
    fn the_real_command_is_never_this_binary_under_the_commands_name() {
        // "Past ourselves" is a question about the FILE, not the directory: a
        // shim is a link, and a link resolves to the binary while living
        // somewhere else entirely. A directory comparison skips nothing, finds
        // the link, and execs it -- which is this program again, forever.
        let Some(shell) = real_command("sh", None) else {
            return;
        };
        let told_it_is_itself = real_command("sh", Some(&shell));
        assert_ne!(
            told_it_is_itself.as_deref().and_then(file_identity),
            file_identity(&shell),
            "PATH resolution handed back the very file it was told was itself"
        );
        // And a name nothing on PATH spells has no real command at all, which
        // is what keeps the transparent path from running something else.
        assert_eq!(real_command("uphold-no-such-command-4b1f", None), None);
    }

    #[test]
    fn a_command_that_is_on_no_path_is_reported_rather_than_quietly_not_run() {
        // The transparent path still has to be a path. A link left behind
        // after the real command was uninstalled has nothing to exec, and
        // exiting 0 there is a shim reporting a command ran when none did.
        let report = exec_through("uphold-no-such-command-4b1f", &[])
            .unwrap_err()
            .to_string();
        assert!(
            report.contains("nothing here stands in front of"),
            "{report}"
        );
    }

    #[test]
    fn an_editor_this_shim_cannot_point_at_itself_is_refused_rather_than_warned_about() {
        // This printed a warning and returned, and the caller went on to exec
        // the command -- so the one path the editor re-entry exists to close
        // stayed open, and the run that could not check the text published it.
        // The warning even said "This is not a pass" while exiting 0.
        let mut command = Command::new("true");
        let report = install_editor(
            &mut command,
            "faux",
            "FAUX_EDITOR",
            None,
            &argv("pr create"),
        )
        .unwrap_err()
        .to_string();
        assert!(report.contains("could not find its own path"), "{report}");
        assert!(
            command.get_envs().next().is_none(),
            "an editor was installed for a command that is not going to run"
        );
    }

    #[test]
    fn the_editor_variable_names_this_binary_and_remembers_the_users_own() {
        // The command runs its editor through a shell, so the variable holds a
        // command LINE. What says "you are the editor" is the flag, which only
        // the process the command launches as its editor is given: an
        // environment reaches every descendant, and the descendants of a
        // checking pass include the `git` that IS this binary under a link.
        let mut command = Command::new("true");
        install_editor(
            &mut command,
            "faux",
            "FAUX_EDITOR",
            Some(Path::new("/opt/my tools/uphold")),
            &argv("pr create"),
        )
        .unwrap();
        let environment: BTreeMap<String, String> = command
            .get_envs()
            .filter_map(|(name, value)| {
                Some((
                    name.to_string_lossy().into_owned(),
                    value?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        let installed = &environment["FAUX_EDITOR"];
        assert_eq!(
            installed, "'/opt/my tools/uphold' shim --as-editor 'faux'",
            "the editor line has to survive a shell that splits it"
        );
        // The command line the editor was opened FOR, so the pass on the way
        // back consults the checkers that stand in front of that line.
        assert_eq!(
            environment.get(EDITOR_ARGV).map(String::as_str),
            Some("pr create")
        );
        // And the user's own editor, which this variable no longer names.
        assert!(environment.contains_key(EDITOR_REAL));
    }
}
