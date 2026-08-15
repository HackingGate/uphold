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

use crate::config::{Check, Policy, Rule};
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
#[derive(Debug, Clone, Deserialize, Default)]
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
    #[serde(default)]
    pub collect: Collect,
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
        let mut found: Vec<&str> = Vec::new();
        let mut unclear: Option<String> = None;
        let mut index = 0;
        while let Some(argument) = argv.get(index) {
            index += 1;
            // `--` ends the options. Everything after it is positional however
            // it is spelt.
            if argument == "--" {
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
            found.push(argument);
            if found.len() == 2 {
                break;
            }
        }
        let mut found = found.into_iter();
        Words {
            verb: found.next().unwrap_or_default().to_owned(),
            noun: found.next().unwrap_or_default().to_owned(),
            unclear,
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
        // An option neither reading can classify leaves the SUBCOMMAND in doubt
        // only where the two readings disagree about which word it is. `git log
        // -1 --oneline` is `log` whether `-1` swallows the word after it or not,
        // and `-1` sits after the subcommand besides. Reporting that as a
        // could-not-look prints the refusal line over every ordinary command
        // this shim exists to stay out of the way of -- which trains the reader
        // to ignore the one invocation where the doubt is real.
        if bare.verb == valued.verb && bare.noun == valued.noun {
            return Reading::Absent;
        }
        Reading::Unclear(flag)
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
    #[expect(
        clippy::unused_self,
        reason = "one signature for every `collect` arm; the flags collector needs the table"
    )]
    fn collect_git_refs(&self, root: &Path, argv: &[String]) -> Result<Vec<Subject>> {
        let mut names = Vec::new();
        let mut seen_remote = false;
        for argument in argv.iter().skip(1) {
            if argument.starts_with('-') {
                continue;
            }
            if !seen_remote {
                seen_remote = true;
                continue;
            }
            // A refspec is `src:dst`; both halves are published, and
            // `refs/heads/` is noise rather than name.
            for half in argument.split(':') {
                let name = half
                    .strip_prefix("refs/heads/")
                    .or_else(|| half.strip_prefix("refs/tags/"))
                    .unwrap_or(half);
                if !name.is_empty() {
                    names.push(name.to_owned());
                }
            }
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

    pub(crate) fn collect(&self, root: &Path, argv: &[String]) -> Result<Collected> {
        // Every arm walks the flags first: the target flag and any stdin the
        // shim consumed belong to the invocation rather than to one collector,
        // and a collector that dropped the stdin it had already read would
        // leave the command publishing an empty body.
        let mut collected = self.collect_flags(argv)?;
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

    /// Whether this invocation publishes somewhere that matters.
    pub(crate) fn in_scope(
        &self,
        root: &Path,
        collected: &Collected,
        argv: &[String],
    ) -> Result<bool> {
        match &self.scope {
            Scope::Always => Ok(true),
            Scope::PublicTarget => {
                let Some(target) = self.resolve_target(root, collected)? else {
                    // No answer is not "public". Refusing a push because a
                    // lookup was unavailable would make the guard the reason
                    // work stops.
                    //
                    // Said out loud, though. The decision to fall open here is
                    // deliberate; doing it in silence was not, and it looked
                    // exactly like a checker that ran and approved. `gh`
                    // unauthenticated, rate-limited, offline, or a repository
                    // with no `origin` all land here.
                    eprintln!(
                        "uphold shim: no target could be resolved, so the \
                         `public-target` checks did not run. This is not a pass."
                    );
                    return Ok(false);
                };
                match self.visibility(root, &target).as_deref() {
                    Some("public") => Ok(true),
                    Some(_) => Ok(false),
                    None => {
                        eprintln!(
                            "uphold shim: the forge did not say whether {target} is \
                             public, so the `public-target` checks did not run. This is \
                             not a pass."
                        );
                        Ok(false)
                    }
                }
            }
            Scope::PublicRegistry => {
                if argv.iter().any(|argument| argument == "--dry-run") {
                    return Ok(false);
                }
                // Two independent reasons this is nobody's business, and either
                // one is enough: a package marked private cannot be published
                // at all, and a registry that is not the public one is
                // somebody's internal infrastructure.
                if let Ok(text) = std::fs::read_to_string(root.join("package.json")) {
                    if text.contains("\"private\"") && json_bool_field(&text, "private") {
                        return Ok(false);
                    }
                }
                let registry = collected
                    .target
                    .clone()
                    .unwrap_or_else(|| String::from("https://registry.npmjs.org"));
                Ok(registry.contains("registry.npmjs.org"))
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
                Ok(status.success())
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
    let output = Command::new(program).args(args).output().ok()?;
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
    // checker whose command reads empty passes everything it is asked about.
    let run = rule.exec.as_deref().unwrap_or_default();
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
    // The same two kinds `run` consults, and for the reason the dispatch there
    // gives: a guard cannot judge a body typed into an editor one way and the
    // same body given with `--body` another under one id. Reading only `exec`
    // here meant a policy whose checker for this command is a BUILT-IN had a
    // checkpoint that opened an editor, read the file back, consulted nobody and
    // exited 0.
    let checkers: Vec<&Rule> = policy
        .before_command(name, &opened_for)
        .filter(|rule| rule.is(Check::Exec) || rule.is(Check::Builtin))
        .collect();
    if checkers.is_empty() {
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
    let mut refusals: Vec<String> = Vec::new();
    for rule in checkers {
        if crate::guard::bypassed(&rule.id) {
            continue;
        }
        if rule.is(Check::Builtin) {
            if let Some(refusal) =
                crate::guard::text_refusal(root, policy, rule, subject.kind, &subject.value)?
            {
                refusals.push(refusal.report);
            }
            continue;
        }
        if let Some(refusal) = consult(root, rule, &subject)? {
            refusals.push(format!("{refusal}\n{}", rule.message()));
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
    let checkers: Vec<&Rule> = policy
        .before_command(name, &words)
        .filter(|rule| rule.is(Check::Exec) || rule.is(Check::Builtin))
        .collect();
    let mut refusals: Vec<String> = Vec::new();

    let mut collected = Collected::default();
    let mut in_scope = false;
    let reading = shim.reading(&words);
    if let Reading::Unclear(flag) = &reading {
        // Said out loud, and for the same reason the unresolvable-target arm in
        // `in_scope` says its piece: the decision to run the command anyway is
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
    if matches!(reading, Reading::Named) {
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
        in_scope = shim.in_scope(root, &collected, &words)?;
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
        if in_scope {
            for subject in &collected.subjects {
                if subject.value.trim().is_empty() {
                    continue;
                }
                for rule in &checkers {
                    if crate::guard::bypassed(&rule.id) {
                        continue;
                    }
                    if rule.is(Check::Builtin) {
                        // The same dispatch `uphold guard --text` runs, so a
                        // guard cannot judge a commit message one way and a
                        // pull-request body another under one id.
                        if let Some(refusal) = crate::guard::text_refusal(
                            root,
                            policy,
                            rule,
                            subject.kind,
                            &subject.value,
                        )? {
                            refusals.push(refusal.report);
                        }
                        continue;
                    }
                    if let Some(refusal) = consult(root, rule, subject)? {
                        refusals.push(format!("{refusal}\n{}", rule.message()));
                    }
                }
            }
        }
    }

    if !refusals.is_empty() {
        for refusal in &refusals {
            eprintln!("{name}: {refusal}");
        }
        eprintln!("Nothing was published. Fix the text, or override once with UPHOLD_ALLOW.");
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
    let editor_env = shim
        .editor_env
        .as_deref()
        .filter(|_| in_scope && !collected.body_given && !collected.web);
    if let Some(variable) = editor_env {
        install_editor(&mut command, name, variable, own.as_deref(), &words)?;
    }
    hand_off(&mut command, name, collected.stdin.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gh() -> Shim {
        Shim {
            command: String::from("gh"),
            match_: vec!["pr:create".into(), "issue:*".into()],
            text_flags: vec!["-t".into(), "--title".into(), "-b".into(), "--body".into()],
            file_flags: vec!["-F".into(), "--body-file".into()],
            path_flags: Vec::new(),
            target_flags: vec!["-R".into(), "--repo".into()],
            skip_flags: vec!["--fill".into()],
            web_flags: vec!["-w".into(), "--web".into()],
            argv_subject: false,
            editor_env: Some(String::from("GH_EDITOR")),
            target: Target::ForgeRepo,
            scope: Scope::PublicTarget,
            collect: Collect::Flags,
        }
    }

    /// A `git` shim as the shipped policy declares it: positional text, and
    /// none of git's global grammar written into the table.
    fn git_push() -> Shim {
        Shim {
            command: String::from("git"),
            match_: vec!["push:*".into()],
            text_flags: Vec::new(),
            file_flags: Vec::new(),
            path_flags: Vec::new(),
            target_flags: Vec::new(),
            skip_flags: Vec::new(),
            web_flags: Vec::new(),
            argv_subject: false,
            editor_env: None,
            target: Target::GitRemote,
            scope: Scope::PublicTarget,
            collect: Collect::GitRefs,
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
        assert!(matches!(
            git_push().reading(&argv("--fictional-option value status")),
            Reading::Unclear(flag) if flag == "--fictional-option"
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
        assert!(!npm
            .in_scope(&dir, &Collected::default(), &argv("publish"))
            .unwrap());
    }

    #[test]
    fn a_dry_run_publishes_nothing_and_is_out_of_scope() {
        // Refusing one would stop the very command somebody runs to find out
        // what they are about to publish.
        let mut npm = gh();
        npm.scope = Scope::PublicRegistry;
        assert!(!npm
            .in_scope(
                Path::new("."),
                &Collected::default(),
                &argv("publish --dry-run")
            )
            .unwrap());
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
}
