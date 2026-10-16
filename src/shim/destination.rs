//! Normalize one command destination and apply scope predicates to that same
//! observation. Grammar supplies collected targets; policy remains the caller
//! of the scope and guard decisions. No subjects or processes are handed off here.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use super::{
    Collected, Forge, Scope, Shim, Silence, Standing, Target, Unresolved, forge_field,
    json_bool_field, repository_placeholder,
};
use crate::config::{Policy, Rule};
use crate::error::{Fatal, Result};
use crate::git;

/// How the adapter selected the destination. Only Origin can describe this
/// checkout's visibility; equal repository names do not establish that fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Provenance {
    /// This command has no destination semantics.
    Absent,
    /// A command option or API path named the destination.
    Explicit,
    /// The forge client's environment selected the destination.
    Environment,
    /// The checkout's origin selected the destination.
    Origin,
}

/// One destination observation shared by scopes, ownership and text guards.
#[derive(Debug)]
pub(super) struct Destination {
    /// Canonical host-bearing repository spelling, or no resolved repository.
    pub(super) target: Option<String>,
    /// Client that can answer for the supported destination.
    pub(super) forge: Option<Forge>,
    /// Host override carried to both visibility and ownership queries.
    pub(super) hostname: Option<String>,
    provenance: Provenance,
    ambient_host: bool,
}

impl Destination {
    fn resolve(shim: &Shim, root: &Path, selected: Option<&str>) -> Result<Self> {
        let explicit = selected.filter(|value| !value.is_empty());
        let gh_repo = shim.command == "gh" && shim.target != Target::None;
        let environment = gh_repo
            .then(|| {
                std::env::var("GH_REPO")
                    .ok()
                    .filter(|value| !value.is_empty())
            })
            .flatten();
        let ambient_host =
            shim.command == "gh" && std::env::var("GH_HOST").is_ok_and(|value| !value.is_empty());
        let (target, provenance) = if let Some(named) = explicit.or(environment.as_deref()) {
            let target = if gh_repo && !repository_placeholder("gh", named)? {
                gh_repository_target(named)?
            } else {
                named.to_owned()
            };
            (
                Some(target),
                if explicit.is_some() {
                    Provenance::Explicit
                } else {
                    Provenance::Environment
                },
            )
        } else if gh_repo {
            (
                git::remote_url(root, "origin")
                    .map(|url| gh_repository_target(&url))
                    .transpose()?,
                Provenance::Origin,
            )
        } else {
            match shim.target {
                Target::None => (None, Provenance::Absent),
                Target::GitRemote | Target::ForgeRepo => (
                    git::remote_url(root, "origin")
                        .and_then(|url| git::owner_repo(&url))
                        .map(|(owner, repo)| format!("{owner}/{repo}")),
                    Provenance::Origin,
                ),
            }
        };
        let hostname = target.as_deref().and_then(git::host);
        Ok(Self {
            target,
            forge: shim.forge(root),
            hostname,
            provenance,
            ambient_host,
        })
    }
}

impl Shim {
    /// Whether one scope predicate holds for this invocation.
    ///
    /// The predicate is a parameter rather than the table's own, because a rule
    /// may carry its own `command.scope`: the table's answers for the command,
    /// and a rule that applies on every egress -- host identity in a
    /// pull-request body is worth refusing whatever the destination -- says so
    /// beside its `command.before` rather than inheriting the table's idea of
    /// the question.
    ///
    /// The policy is a parameter for the sake of one arm: `public-target` is a
    /// question this repository may already have answered in writing, and a
    /// predicate that asks a forge anyway is a network call -- and a token, and
    /// a rate limit -- spent on a fact that was sitting in `principles.toml`
    /// the whole time. See [`declared_standing`].
    fn scope_answer(
        &self,
        scope: &Scope,
        root: &Path,
        policy: &Policy,
        context: &CommandContext<'_>,
    ) -> Result<Standing> {
        match scope {
            Scope::Always => Ok(Standing::Holds),
            Scope::PublicTarget => {
                let destination = context.destination()?;
                let Some(target) = destination.target.as_deref() else {
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
                // What this repository says about itself, before anybody is
                // asked. Read here and not before the resolver, because a tree
                // with no `origin` has no destination for a declaration to be
                // about, and that is the resolver's answer above rather than
                // this one's.
                if let Some(standing) = declared_standing(root, policy, destination)? {
                    return Ok(standing);
                }
                match Self::visibility(destination).as_deref() {
                    Ok("public") => Ok(Standing::Holds),
                    Ok(_) => Ok(Standing::DoesNotHold),
                    // The cause, in the words the forge used. A rate limit, an
                    // unauthenticated `gh` and a deleted repository are three
                    // different instructions to the reader, and a refusal
                    // naming none of them is one the reader can only bypass.
                    Err(silence) => Ok(Standing::CouldNotTell(format!(
                        "the forge did not say whether {target} is public, so whether the \
                         `public-target` checks apply here could not be established. {}",
                        silence.sentence()
                    ))),
                }
            }
            Scope::PublicRegistry => {
                if context.argv.iter().any(|argument| argument == "--dry-run") {
                    return Ok(Standing::DoesNotHold);
                }
                // Two independent reasons this is nobody's business, and either
                // one is enough: a package marked private cannot be published
                // at all, and a registry that is not the public one is
                // somebody's internal infrastructure.
                if let Ok(text) = std::fs::read_to_string(root.join("package.json"))
                    && text.contains("\"private\"")
                    && json_bool_field(&text, "private")
                {
                    return Ok(Standing::DoesNotHold);
                }
                let registry = context
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
    pub(super) fn forge(&self, root: &Path) -> Option<Forge> {
        // The command is the strongest evidence there is: somebody running
        // `glab` is publishing to GitLab whatever else is configured.
        match self.command.as_str() {
            "gh" => return Some(Forge::GitHub),
            "glab" => return Some(Forge::GitLab),
            _ => {}
        }
        // Otherwise the remote decides, which is what the `git` shim needs:
        // one shim stands in front of a command that pushes to either.
        Forge::of_url(&git::remote_url(root, "origin")?)
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
    fn visibility(destination: &Destination) -> std::result::Result<String, Silence> {
        let Some(forge) = destination.forge else {
            return Err(Silence::Refused(String::from(
                "no forge client is known for that host, so there was nobody to ask",
            )));
        };
        let target = destination.target.as_deref().unwrap_or_default();
        match forge {
            Forge::GitHub => {
                let name = git::owner_repo(target).map_or_else(
                    || target.to_owned(),
                    |(owner, repo)| format!("{owner}/{repo}"),
                );
                let endpoint = format!("repos/{name}");
                let mut args = vec!["api", endpoint.as_str(), "--jq", ".visibility"];
                if let Some(host) = destination.hostname.as_deref() {
                    args.extend(["--hostname", host]);
                }
                forge_field("gh", &args, None)
            }
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

    #[cfg(test)]
    pub(crate) fn scope_holds(
        &self,
        scope: &Scope,
        root: &Path,
        policy: &Policy,
        collected: &Collected,
        argv: &[String],
    ) -> Result<Standing> {
        self.scope_answer(
            scope,
            root,
            policy,
            &CommandContext::new(self, root, collected, argv),
        )
    }
}

/// Resolve the host-bearing spellings accepted by `gh` without treating an
/// enterprise repository as its same-named github.com counterpart. Enterprise
/// support is deliberately absent here, as it is in `Forge::of_url`.
fn gh_repository_target(named: &str) -> Result<String> {
    let parts: Vec<_> = named.split('/').collect();
    let host = if named.contains("://") || named.contains(':') {
        git::host(named)
    } else if parts.len() == 3 {
        parts.first().map(|hostname| hostname.to_lowercase())
    } else {
        None
    };
    let environment_host = std::env::var("GH_HOST")
        .ok()
        .filter(|configured| !configured.is_empty());
    if let Some(hostname) = host.as_ref().or(environment_host.as_ref())
        && !matches!(
            hostname.to_lowercase().as_str(),
            "github.com" | "www.github.com"
        )
    {
        return Err(Fatal::new(format!(
            "gh: destination {named:?} uses host {hostname:?}, whose repository authority \
             cannot be verified by this shim. Nothing was published; use a supported \
             GitHub destination with a matching GH_HOST"
        )));
    }
    let path = if named.contains("://") || named.contains(':') {
        git::owner_repo(named).map(|(owner, repo)| format!("{owner}/{repo}"))
    } else {
        match parts.as_slice() {
            [owner, repo] | [_, owner, repo] => Some(format!("{owner}/{repo}")),
            _ => None,
        }
    };
    let Some(path) = path.filter(|path| {
        path.split('/').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        })
    }) else {
        return Err(Fatal::new(format!(
            "gh: destination {named:?} could not be resolved as [HOST/]OWNER/REPO. \
             Nothing was published"
        )));
    };
    Ok(match host {
        Some(hostname) => format!("https://{hostname}/{path}"),
        None => path,
    })
}

/// What the policy already says about this destination, where it speaks for it.
///
/// `Some` is a declaration that settles the question offline, and it is the same
/// declaration `guard::names::target_is_public` reads: a repository whose
/// `principles.toml` says `visibility = "private"` has stated the fact, and a
/// shim that ran `gh api repos/<owner>/<repo>` anyway needed an authenticated
/// `gh` on every `git push` to learn it a second time. When GitHub rate-limits
/// the account that lookup fails, the failure is a [`Standing::CouldNotTell`],
/// and `unresolved = "refuse"` -- the default -- stops every push in every tree
/// over a fact nobody had to ask for.
///
/// `None` sends the caller to the forge, and the narrowing that makes this safe
/// is the destination it will read the declaration for. A declaration is about
/// ONE repository, so this reads it only where the destination is the one
/// [`Destination::resolve`] took from `origin` -- which is to say where nothing
/// on the command line or in `GH_REPO` named a destination, and `GH_HOST`
/// did not change the host context. A `target_flags` value is a
/// destination somebody typed, and a typed `owner/repo` carries no host: `-R
/// acme/widget` under a `--hostname` or a `GH_HOST` is a repository on another
/// forge that happens to share a name with this one, and there is nothing in
/// two matching path segments that can tell it apart from this tree. So every
/// named destination goes to the forge exactly as it did before, including the
/// ones that name this repository, and what is bought offline is the case the
/// cost was actually in: the push that names nothing and means `origin`.
fn declared_standing(
    root: &Path,
    policy: &Policy,
    destination: &Destination,
) -> Result<Option<Standing>> {
    if destination.provenance != Provenance::Origin || destination.ambient_host {
        return Ok(None);
    }
    // Lazily, and only here. Reading it is allowed to run `visibility_from`, which
    // is a process, and a predicate that spawned one for a target the declaration
    // does not speak for would trade the lookup this exists to avoid for another
    // one.
    let Some(declared) = policy.declared_visibility(root)? else {
        return Ok(None);
    };
    // Held to the three spellings before it arrives -- a written one at load, a
    // `visibility_from` answer as it is read -- so `None` here is unreachable
    // rather than a fourth word being guessed at. It falls through to the forge
    // regardless: a word this seam cannot read is not an answer this seam may
    // invent.
    Ok(
        crate::config::visibility_is_public(&declared).map(|public| {
            if public {
                Standing::Holds
            } else {
                Standing::DoesNotHold
            }
        }),
    )
}

/// The scope one rule is judged under: its own where it wrote one, the
/// table's where it did not.
pub(super) fn effective_scope<'a>(rule: &'a Rule, shim: &'a Shim) -> &'a Scope {
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
pub(super) struct CommandContext<'a> {
    shim: &'a Shim,
    root: &'a Path,
    argv: &'a [String],
    target: Option<String>,
    answers: BTreeMap<String, Standing>,
    destination: std::cell::OnceCell<std::result::Result<Destination, String>>,
}

impl<'a> CommandContext<'a> {
    /// Bind all decisions to one collected target and canonical argument list.
    pub(super) fn new(
        shim: &'a Shim,
        root: &'a Path,
        collected: &Collected,
        argv: &'a [String],
    ) -> Self {
        Self {
            shim,
            root,
            argv,
            target: collected.target.clone(),
            answers: BTreeMap::new(),
            destination: std::cell::OnceCell::new(),
        }
    }
    /// Resolve lazily, once: an out-of-scope command keeps its previous behavior,
    /// while every consumer that needs a destination sees the same observation.
    pub(super) fn destination(&self) -> Result<&Destination> {
        self.destination
            .get_or_init(|| {
                Destination::resolve(self.shim, self.root, self.target.as_deref())
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map_err(|why| Fatal::new(why.clone()))
    }

    /// Whether this scope holds, with a predicate that could not be asked
    /// answered by the table's `unresolved`.
    ///
    /// The conversion lives here rather than at each call site because there
    /// are six of them and one of them forgetting is the whole defect: a
    /// could-not-tell read as "does not hold" skips the checkers, and the
    /// destination guard behind them promises exit 2 on exactly that.
    pub(super) fn holds(&mut self, scope: &Scope, policy: &Policy) -> Result<bool> {
        match self.standing(scope, policy)? {
            Standing::Holds => Ok(true),
            Standing::DoesNotHold => Ok(false),
            Standing::CouldNotTell(why) => match self.shim.unresolved {
                Unresolved::Refuse => Err(Fatal::new(format!(
                    "{}: {why}. A check that could not look is not a check that passed, so \
                     nothing was published. Name the destination explicitly, run this where \
                     the repository has a remote and the forge can be reached, or write \
                     `unresolved = \"run\"` on this `[[shim]]` table to run the command \
                     unchecked instead",
                    self.shim.command
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
    fn standing(&mut self, scope: &Scope, policy: &Policy) -> Result<Standing> {
        let key = match scope {
            Scope::Always => return Ok(Standing::Holds),
            Scope::PublicTarget => String::from("public-target"),
            Scope::PublicRegistry => String::from("public-registry"),
            Scope::Command { command } => format!("command:{command}"),
        };
        if let Some(answer) = self.answers.get(&key) {
            return Ok(answer.clone());
        }
        let answer = self.shim.scope_answer(scope, self.root, policy, self)?;
        if let (Standing::CouldNotTell(why), Unresolved::Run) = (&answer, self.shim.unresolved) {
            eprintln!("uphold shim: {why}, and the command ran anyway. This is not a pass.");
        }
        self.answers.insert(key, answer.clone());
        Ok(answer)
    }
}
