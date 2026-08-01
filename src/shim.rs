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
use std::io::{Read, Write};
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
    /// Declared so the shim can tell the one case it genuinely cannot see: no
    /// body on the command line, no `--web`, and a command that is about to
    /// open an editor. What gets typed there has not been written yet.
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

impl Shim {
    /// Whether this invocation is one the shim has anything to say about.
    pub(crate) fn matches(&self, argv: &[String]) -> bool {
        let verb = argv.first().map_or("", String::as_str);
        let noun = argv.get(1).map_or("", String::as_str);
        in_list(&self.match_, "*")
            || in_list(&self.match_, &format!("{verb}:{noun}"))
            || in_list(&self.match_, &format!("{verb}:*"))
    }

    /// Walk argv once, reading the flags this table names.
    fn collect_flags(&self, argv: &[String]) -> Result<(Vec<Subject>, Option<String>, bool, bool)> {
        let mut subjects = Vec::new();
        let mut target = None;
        let mut body_given = false;
        let mut web = false;

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
                target = Some(value);
                true
            } else if in_list(&self.text_flags, &flag) {
                subjects.push(Subject {
                    kind: "text",
                    value,
                });
                body_given = true;
                true
            } else if in_list(&self.path_flags, &flag) {
                subjects.push(Subject {
                    kind: "path",
                    value,
                });
                true
            } else if in_list(&self.file_flags, &flag) {
                body_given = true;
                if value == "-" {
                    // Reading stdin here means the real command can no longer
                    // read it, so it is kept and replayed on the way through. A
                    // guard that silently eats the body it approved is worse
                    // than no guard.
                    let mut buffer = String::new();
                    std::io::stdin().read_to_string(&mut buffer)?;
                    subjects.push(Subject {
                        kind: "text",
                        value: buffer,
                    });
                } else if Path::new(&value).is_file() {
                    subjects.push(Subject {
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
                body_given = true;
                false
            } else if in_list(&self.web_flags, &flag) {
                web = true;
                false
            } else {
                index += 1;
                continue;
            };
            index += if paired || !took_value { 1 } else { 2 };
        }
        Ok((subjects, target, body_given, web))
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
        let mut collected = match self.collect {
            Collect::Flags => {
                let (subjects, target, body_given, web) = self.collect_flags(argv)?;
                Collected {
                    subjects,
                    target,
                    body_given,
                    web,
                }
            }
            Collect::GitRefs => {
                let (_, target, _, _) = self.collect_flags(argv)?;
                Collected {
                    subjects: self.collect_git_refs(root, argv)?,
                    target,
                    // Never hand git an editor: a message written in one passes
                    // through commit-msg already.
                    body_given: true,
                    web: false,
                }
            }
            Collect::NpmPackage => {
                let (_, target, _, _) = self.collect_flags(argv)?;
                let dry_run = argv.iter().any(|argument| argument == "--dry-run");
                Collected {
                    // A dry run publishes nothing, and refusing one would stop
                    // the very command somebody runs to find out what they are
                    // about to publish.
                    subjects: if dry_run {
                        Vec::new()
                    } else {
                        self.collect_npm(root)?
                    },
                    target,
                    body_given: true, // npm opens no editor
                    web: false,
                }
            }
        };
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
                match forge_visibility(&target).as_deref() {
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
}

fn forge_visibility(target: &str) -> Option<String> {
    let output = Command::new("gh")
        .args(["api", &format!("repos/{target}"), "--jq", ".visibility"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_lowercase(),
    )
}

fn json_string_field(text: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let start = text.find(&needle)? + needle.len();
    let rest = text.get(start..)?;
    let colon = rest.find(':')? + 1;
    let rest = rest.get(colon..)?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn json_bool_field(text: &str, field: &str) -> bool {
    let needle = format!("\"{field}\"");
    let Some(start) = text.find(&needle) else {
        return false;
    };
    let rest = &text[start + needle.len()..];
    let Some(colon) = rest.find(':') else {
        return false;
    };
    rest[colon + 1..].trim_start().starts_with("true")
}

/// Run one checker over one subject.
///
/// The contract cmd-shims documented, unchanged and now the only one: the
/// subject on stdin, its kind in the environment, 0 to pass, 1 to refuse, 2 to
/// say it could not look. A checker written in anything satisfies it.
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
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(subject.value.as_bytes()).ok();
    }
    let output = child
        .wait_with_output()
        .map_err(|error| Fatal::new(format!("{}: {error}", rule.id)))?;
    match output.status.code() {
        Some(0) => Ok(None),
        Some(1) => Ok(Some(format!(
            "{} refused a {} subject: {}",
            rule.id,
            subject.kind,
            String::from_utf8_lossy(&output.stderr).trim()
        ))),
        // 2 is could-not-look, and it is not a pass. A checker that could not
        // read what it was handed has established nothing.
        other => Err(Fatal::new(format!(
            "{} exited {} on a {} subject: {}",
            rule.id,
            other.unwrap_or(-1),
            subject.kind,
            String::from_utf8_lossy(&output.stderr).trim()
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
        return Some(candidate);
    }
    None
}

/// Stand in front of one command.
pub(crate) fn run(root: &Path, policy: &Policy, name: &str, argv: &[String]) -> Result<Exit> {
    let shims: BTreeMap<&str, &Shim> = policy
        .shims
        .iter()
        .map(|shim| (shim.command.as_str(), shim))
        .collect();
    let Some(shim) = shims.get(name) else {
        return Err(Fatal::new(format!(
            "no shim declares the command {name:?}; this policy declares {}",
            if shims.is_empty() {
                String::from("none")
            } else {
                shims.keys().copied().collect::<Vec<&str>>().join(", ")
            }
        )));
    };

    // Only the rules that name THIS command line. A checker used to be
    // consulted by every shim -- a check written for a pull-request body was
    // also asked about a branch name on `git push` and a tarball on `npm
    // publish` -- because the only thing selecting it was `kind = "command"`,
    // which says nothing about which command.
    let checkers: Vec<&Rule> = policy
        .before_command(name, argv)
        .filter(|rule| rule.is(Check::Exec))
        .collect();
    let mut refusals: Vec<String> = Vec::new();

    if shim.matches(argv) {
        let collected = shim.collect(root, argv)?;
        if shim.in_scope(root, &collected, argv)? {
            // The one case a shim genuinely cannot see. No body on the command
            // line, no `--web`, and a command about to open an editor: what
            // gets typed there has not been written yet, so there is nothing to
            // hand a checker. Said aloud rather than passed over -- a shim that
            // reports nothing here reports a pass over text it never saw, which
            // is the failure `explicit-unknown` names.
            if !collected.body_given && !collected.web && shim.editor_env.is_some() {
                eprintln!(
                    "{name}: the body will be composed in an editor, so nothing was checked. \
                     Pass it with a flag to have it read."
                );
            }
            for subject in &collected.subjects {
                if subject.value.trim().is_empty() {
                    continue;
                }
                for rule in &checkers {
                    if crate::guard::bypassed(&rule.id) {
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
    let status = Command::new(real)
        .args(argv)
        .status()
        .map_err(|error| Fatal::new(format!("{name}: {error}")))?;
    std::process::exit(status.code().unwrap_or(1));
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

    fn argv(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn a_named_subcommand_matches_and_an_unnamed_one_does_not() {
        // Named rather than pattern-matched: a shim that guesses which
        // subcommands carry text is one release away from missing a new one in
        // silence.
        assert!(gh().matches(&argv("pr create")));
        assert!(gh().matches(&argv("issue comment")));
        assert!(!gh().matches(&argv("pr checkout")));
        assert!(!gh().matches(&argv("repo clone")));
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
        let dir = std::env::temp_dir().join(format!("uphold-shim-link-{}", std::process::id()));
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
        let dir = std::env::temp_dir().join(format!("uphold-shim-{}", std::process::id()));
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
    fn a_private_field_that_is_false_does_not_make_a_package_private() {
        assert!(json_bool_field(r#"{"private": true}"#, "private"));
        assert!(!json_bool_field(r#"{"private": false}"#, "private"));
        assert!(!json_bool_field(r#"{"name": "x"}"#, "private"));
    }
}
