//! Who a `gh` write runs as, where the policy says who that must be.
//!
//! Every other guard at the command seam asks about what an invocation says or
//! where it is going. This one asks about the identity it acts under, which
//! neither question reaches: an agent session ran plain `gh` under the
//! operator's own login in a workspace whose instructions required its GitHub
//! App, and opened and merged pull requests as that person -- sixteen squash
//! commits authored under the personal account, then ninety-five merges in two
//! minutes. Every body it published was clean and every destination was the
//! workspace's own, so every check passed. Nothing asked whose credential it
//! was. The instruction that it must be the App's was prose, and prose has no
//! condition on which to fire.
//!
//! So the declaration is a rule, and the decision is made where the shim is
//! already standing: the `[[shim]]` table's `match` list is the statement of
//! which `gh` verbs write, and this guard is consulted for exactly those, by
//! `command.before`, the way the destination guard is. No second list of verbs
//! lives here.
//!
//! The decision, in order, cheapest and most certain first:
//!
//! 1. Which token `gh` will send, read the way `gh help environment` documents
//!    it: `GH_TOKEN`, then `GITHUB_TOKEN`, for github.com. Neither set means
//!    `gh` falls back to the login it has stored, which is a person's -- a
//!    refusal, without a network call and without reading `gh`'s own store.
//! 2. What kind of token that is, by the prefix GitHub gives every kind it
//!    issues. A personal kind is a refusal, without a network call.
//! 3. Whose installation token it is. An installation token's prefix says it is
//!    an App's and not which App's, so `gh` itself is asked for the GraphQL
//!    `viewer` -- which, for an installation token, is the App's bot login. It
//!    is asked of `gh` rather than of an HTTP client of this binary's own
//!    because `gh` is what will make the write: the same client resolving the
//!    same credential from the same environment, so the answer is about the
//!    token the command is about to use and not about this module's reading of
//!    which one that is. The token reaches it by that inherited environment and
//!    never on a command line.
//!
//! Anything that could not be established -- the forge unreachable, an answer
//! with no login in it, a host this guard does not answer for -- is exit `2`
//! and the command does not run. A guard whose question could not be asked has
//! not passed.

use std::ffi::OsStr;

use serde::{Serialize, Serializer};

use super::Refusal;
use crate::config::Rule;
use crate::error::{Fatal, Result};
use crate::shim::Silence;

/// The suffix GitHub gives every App's bot account, `<slug>[bot]`.
const BOT_SUFFIX: &str = "[bot]";

/// The variables `gh` reads a github.com token from, in its order of
/// precedence. A variable set to the empty string is unset to `gh`, and so
/// here.
pub(crate) const TOKEN_VARIABLES: &[&str] = &["GH_TOKEN", "GITHUB_TOKEN"];

/// The prefix every installation token carries: an App acting for itself.
const INSTALLATION_PREFIX: &str = "ghs_";

/// The token kinds that act as a PERSON, by prefix, and what each is called.
///
/// `ghu_` is here although an App issued it: a user-to-server token acts as the
/// person who authorised the App, and its writes are authored by that person.
/// `github_pat_` is listed before nothing it could shadow -- no other prefix
/// begins `gith` -- so the order is only for reading.
const PERSONAL_PREFIXES: &[(&str, &str)] = &[
    ("ghp_", "a classic personal access token"),
    ("github_pat_", "a fine-grained personal access token"),
    (
        "gho_",
        "an OAuth token, which is what `gh auth login` stores",
    ),
    (
        "ghu_",
        "a user-to-server token, which acts as the person who authorised the App",
    ),
];

/// One App's bot login, as the policy declared it and as the forge reports it.
///
/// Parsed once, at load, so a rule carrying a value that no installation
/// token's `viewer` could ever answer with is refused there rather than on the
/// first write -- where it would read as the operator's credential being wrong.
/// A user login is one of those values: no token this guard lets through acts
/// as a user, so a rule naming one refuses every write while reading as the
/// declaration of a working setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Actor(String);

impl Actor {
    /// `<slug>[bot]`, where the slug is what GitHub makes of an App's name:
    /// letters, digits, `-` and `_`, starting and ending with neither of the
    /// two. The address form `<id>+<slug>[bot]@users.noreply.github.com` is a
    /// commit author, not a login, and is refused with the login it carries.
    pub(crate) fn parse(value: &str) -> std::result::Result<Self, String> {
        // The author forms first, because they carry the right login and the
        // refusal can name it: `<id>+<slug>[bot]` and the address it opens.
        let before_at = value.split_once('@').map_or(value, |(login, _)| login);
        if let Some((_, login)) = before_at.split_once('+') {
            return Err(format!(
                "{value:?} is a commit author's address, or a part of one, and not a \
                 login; write the login it carries, `{login}`"
            ));
        }
        let Some(slug) = value.strip_suffix(BOT_SUFFIX) else {
            return Err(format!(
                "{value:?} is not an App's bot login. `actor` names the GitHub App `gh` \
                 writes must run as, in the form `<slug>[bot]` -- `example-app[bot]` -- \
                 which is the login GitHub reports for that App's installation token"
            ));
        };
        let well_formed = !slug.is_empty()
            && slug
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            && !slug.starts_with(['-', '_'])
            && !slug.ends_with(['-', '_']);
        if !well_formed {
            return Err(format!(
                "{value:?} carries {slug:?} where an App's slug goes, and a slug is \
                 letters, digits, `-` and `_`, starting and ending with a letter or a \
                 digit -- `example-app[bot]`"
            ));
        }
        Ok(Self(value.to_owned()))
    }

    /// The login as the policy wrote it.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the forge's login is this one. GitHub logins are
    /// case-insensitive, so the comparison is.
    fn is(&self, login: &str) -> bool {
        self.0.eq_ignore_ascii_case(login)
    }
}

/// Written as the string it was parsed from, so `uphold rules --sets --json`
/// writes the key a policy file writes.
impl Serialize for Actor {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// What the environment hands `gh` for github.com, before anybody is asked.
#[derive(Debug, PartialEq, Eq)]
enum Credential {
    /// No token variable is set, so `gh` uses the login it has stored.
    Stored,
    /// A token whose prefix says it acts as a person: the variable, and what
    /// kind of token it is.
    Personal(&'static str, &'static str),
    /// A token of no kind GitHub's prefixes declare: the variable.
    Unrecognised(&'static str),
    /// An installation token: the variable, and the token, which is kept only
    /// so that nothing printed can carry it.
    Installation(&'static str, String),
}

/// Which token `gh` will send to github.com, by its documented precedence.
///
/// `read` is the environment, a parameter so that every branch is reached by a
/// unit test without touching the process environment the other test threads
/// share.
fn credential(read: &dyn Fn(&str) -> Option<String>) -> Credential {
    let Some((variable, token)) = TOKEN_VARIABLES.iter().find_map(|variable| {
        read(variable)
            .filter(|token| !token.is_empty())
            .map(|token| (*variable, token))
    }) else {
        return Credential::Stored;
    };
    if token.starts_with(INSTALLATION_PREFIX) {
        return Credential::Installation(variable, token);
    }
    PERSONAL_PREFIXES
        .iter()
        .find(|(prefix, _)| token.starts_with(prefix))
        .map_or(Credential::Unrecognised(variable), |(_, kind)| {
            Credential::Personal(variable, kind)
        })
}

/// One `gh` write, as this guard is asked about it.
pub(crate) struct Attempt<'a> {
    /// What was typed, to the depth a reader recognises -- `gh pr merge`,
    /// `gh api` -- and never its arguments, which carry bodies and names.
    pub command: &'a str,
    /// The host the invocation reaches, as the shim's destination resolved it.
    pub host: &'a str,
}

/// The verdict of `prevent-actor-mismatch` on one write.
///
/// `read` is the environment and `ask` the forge -- see [`viewer_login`] for
/// the one the shim hands over. `ask` is called at most once, and only for an
/// installation token: every other answer is settled offline.
pub(crate) fn judge(
    rule: &Rule,
    attempt: &Attempt<'_>,
    read: &dyn Fn(&str) -> Option<String>,
    ask: &mut dyn FnMut(&str) -> std::result::Result<String, Silence>,
) -> Result<Option<Refusal>> {
    let id = rule.id.as_str();
    let Some(actor) = rule.actor() else {
        // `validate` refuses this built-in without one, so this is a policy
        // assembled past the loader. Said, rather than answered as a pass.
        return Err(Fatal::new(format!(
            "rule {id:?}: `prevent-actor-mismatch` was reached with no `actor`, so there \
             is nothing to compare the credential with. Nothing was published"
        )));
    };
    let Attempt { command, host } = *attempt;
    // GitHub Enterprise Server is a different forge with different Apps, and
    // `gh` reads `GH_ENTERPRISE_TOKEN` for it. An `actor` declares an App on
    // github.com; judging another host's write against it would be comparing
    // two unrelated accounts that share a spelling.
    if !crate::git::is_github_host(host) {
        return Err(Fatal::new(format!(
            "rule {id:?}: `{command}` reaches {host}, and `actor` declares the App `gh` \
             writes run as on github.com. Whose credential `gh` uses on another host is \
             not a question this guard answers, so nothing was published"
        )));
    }
    let declared = actor.as_str();
    let found = match credential(read) {
        Credential::Installation(variable, token) => {
            let login = ask(host).map_err(|silence| {
                Fatal::new(format!(
                    "rule {id:?}: {variable} holds an installation token, and whose it is \
                     could not be established: {}. A check that could not look is not a \
                     check that passed, so `{command}` did not run and nothing was \
                     published. Retry when the forge can be reached, or override once \
                     with UPHOLD_ALLOW={id}",
                    without_secret(&silence_sentence(&silence), &token)
                ))
            })?;
            if actor.is(&login) {
                return Ok(None);
            }
            // The login is the forge's own answer and not secret, but it is
            // printed, so it is held to the same rule as everything else.
            let login = without_secret(&login, &token);
            Found {
                who: login.clone(),
                why: format!(
                    "the installation token in {variable} is {login}'s, and GitHub \
                     authors every write made with it as {login}"
                ),
            }
        }
        Credential::Personal(variable, kind) => Found {
            who: String::from("a personal login"),
            why: format!(
                "{variable} holds {kind} -- its prefix says so, and an installation \
                 token's would be `{INSTALLATION_PREFIX}`"
            ),
        },
        Credential::Unrecognised(variable) => Found {
            who: String::from("an unidentified token"),
            why: format!(
                "{variable} holds a token of no kind GitHub's prefixes declare, and an \
                 installation token's prefix is `{INSTALLATION_PREFIX}`"
            ),
        },
        Credential::Stored => Found {
            who: String::from("a personal login"),
            why: format!(
                "no token is set -- neither {} -- so `gh` falls back to the login it \
                 has stored, which is a person's",
                TOKEN_VARIABLES.join(" nor ")
            ),
        },
    };
    Ok(Some(Refusal {
        id: id.to_owned(),
        report: format!(
            "`{command}` would run as {who}: {why}. This repository declares that `gh` \
             writes on github.com run as {declared}.\n\n\
             Run it with an installation token of {declared} in GH_TOKEN -- the wrapper \
             this repository's instructions name mints one -- or, where the App itself \
             changed, change `actor` on rule {id:?}.",
            who = found.who,
            why = found.why,
        ),
    }))
}

/// Who a refused write would have run as, and the sentence that says why.
struct Found {
    who: String,
    why: String,
}

/// The clause for a forge that did not answer, in this guard's terms.
///
/// Not [`Silence::sentence`], whose 404 arm is about a repository by a name: the
/// question here names no repository, and a reader told one was not found
/// would go looking for it.
fn silence_sentence(silence: &Silence) -> String {
    match silence {
        Silence::NotFound => String::from("the forge answered 404"),
        Silence::RateLimited { .. } => String::from("the forge is rate-limiting this client"),
        Silence::Refused(what) => format!("the forge was asked and said: {what}"),
    }
}

/// `text` with every occurrence of `secret` replaced.
///
/// `gh` does not print the token it sends, and nothing here asks it to. This is
/// the second layer for the day something does -- a debug variable a person
/// exported, a future error message -- because the cost of checking is one
/// search and the cost of being wrong is a credential in a terminal scrollback
/// and a CI log.
fn without_secret(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_owned();
    }
    text.replace(secret, "<token>")
}

/// The GraphQL document that names the credential's own account.
const VIEWER_QUERY: &str = "query=query { viewer { login } }";

/// Ask `gh` which account its credential for `host` is, as the shim hands
/// [`judge`] the forge.
///
/// `gh api graphql`, because for an installation token the REST `user` endpoint
/// answers 403 and GraphQL's `viewer` answers the App's bot login. Run through
/// [`crate::shim::inner_tool`], so the shim standing in front of `gh` hands this
/// probe straight through rather than judging it -- the probe is itself a
/// matched `api` call with a field. The token is not on its command line: `gh`
/// reads it from the environment it inherits, which is the environment the
/// write it is asked about will run in. `GH_DEBUG` and `DEBUG` are taken off
/// it, because `GH_DEBUG=api` prints the request's headers, and what this probe
/// prints is captured and may be quoted.
pub(crate) fn viewer_login(host: &str) -> std::result::Result<String, Silence> {
    let output = crate::shim::inner_tool("gh")
        .args(["api", "graphql", "--hostname", host, "-f", VIEWER_QUERY])
        .env_remove(OsStr::new("GH_DEBUG"))
        .env_remove(OsStr::new("DEBUG"))
        .output()
        .map_err(|error| Silence::unreachable("gh", &error))?;
    if !output.status.success() {
        return Err(Silence::of("gh", &output));
    }
    let answer: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| Silence::Refused(String::from("`gh` exited 0 and printed no JSON")))?;
    answer
        .pointer("/data/viewer/login")
        .and_then(serde_json::Value::as_str)
        .filter(|login| !login.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            Silence::Refused(String::from(
                "`gh` exited 0 and its answer carried no `data.viewer.login`",
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One rule, loaded the way the binary loads one, so the `actor` it carries
    /// is one the loader accepted.
    fn rule(name: &str, actor: &str) -> Rule {
        let root = crate::fixture::scratch(name);
        std::fs::create_dir_all(root.join("policy")).unwrap();
        let path = root.join("policy/principles.toml");
        std::fs::write(
            &path,
            format!(
                "[rule.app-actor]\nbuiltin = \"prevent-actor-mismatch\"\nactor = \"{actor}\"\n\
                 command.before = [\"gh\"]\ncommand.scope = \"always\"\n\n\
                 [[shim]]\ncommand = \"gh\"\nmatch = [\"pr:merge\"]\n"
            ),
        )
        .unwrap();
        let policy = crate::config::load(&root, &path).unwrap();
        policy.rules.into_iter().next().unwrap()
    }

    /// An environment holding exactly `pairs`.
    fn environment(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        }
    }

    const WRITE: Attempt<'static> = Attempt {
        command: "gh pr merge",
        host: "github.com",
    };

    /// The verdict, with a forge that must not be asked.
    fn offline(name: &str, pairs: &[(&str, &str)]) -> Result<Option<Refusal>> {
        judge(
            &rule(name, "example-app[bot]"),
            &WRITE,
            &environment(pairs),
            // A forge that must not be asked: were it, the answer would be
            // could-not-look, and `report` below would say so.
            &mut |_| Err(Silence::Refused(String::from("asked offline"))),
        )
    }

    fn report(answer: Result<Option<Refusal>>) -> String {
        answer
            .expect("the guard could not look")
            .expect("a write under the wrong actor was allowed")
            .report
    }

    #[test]
    fn a_bot_login_is_an_actor_and_nothing_else_is() {
        for good in ["example-app[bot]", "a[bot]", "Example_App-2[bot]"] {
            assert!(Actor::parse(good).is_ok(), "{good}");
        }
        for bad in [
            "example-user",
            "[bot]",
            "-example[bot]",
            "example-[bot]",
            "example app[bot]",
            "example/app[bot]",
            "example-app[bot] ",
            "example-app",
        ] {
            assert!(Actor::parse(bad).is_err(), "{bad} was accepted");
        }
        let address = Actor::parse("12345+example-app[bot]@users.noreply.github.com")
            .expect_err("an author address is not a login");
        assert!(address.contains("`example-app[bot]`"), "{address}");
        let prefixed = Actor::parse("12345+example-app[bot]").expect_err("an id prefix");
        assert!(prefixed.contains("`example-app[bot]`"), "{prefixed}");
    }

    #[test]
    fn no_token_is_the_stored_personal_login_and_is_refused_offline() {
        // Set and empty is unset to `gh`, so it is here.
        for pairs in [&[][..], &[("GH_TOKEN", ""), ("GITHUB_TOKEN", "")][..]] {
            let report = report(offline("actor-stored", pairs));
            assert!(report.contains("would run as a personal login"), "{report}");
            assert!(
                report.contains("neither GH_TOKEN nor GITHUB_TOKEN"),
                "{report}"
            );
            assert!(report.contains("example-app[bot]"), "{report}");
            assert!(report.contains("GH_TOKEN"), "{report}");
        }
    }

    #[test]
    fn every_personal_prefix_is_refused_offline_and_named() {
        for (prefix, kind) in PERSONAL_PREFIXES {
            let token = format!("{prefix}0123456789abcdef");
            let report = report(offline("actor-personal", &[("GH_TOKEN", &token)]));
            assert!(report.contains("would run as a personal login"), "{report}");
            assert!(report.contains(kind), "{prefix}: {report}");
            assert!(!report.contains(&token), "the token was printed: {report}");
        }
    }

    #[test]
    fn a_token_of_no_declared_kind_is_refused_offline() {
        let report = report(offline(
            "actor-unknown",
            // No prefix GitHub issues. Words rather than the forty hex digits
            // a legacy token was, which a secret scanner rightly flags.
            &[("GH_TOKEN", "no-prefix-at-all")],
        ));
        assert!(report.contains("an unidentified token"), "{report}");
    }

    #[test]
    fn gh_token_is_read_before_github_token() {
        // The personal token in the variable `gh` reads first decides, though
        // the second holds an installation token the forge would vouch for.
        let report = report(offline(
            "actor-precedence",
            &[
                ("GH_TOKEN", "ghp_personal"),
                ("GITHUB_TOKEN", "ghs_installation"),
            ],
        ));
        assert!(report.contains("GH_TOKEN holds"), "{report}");
        // And with the first empty, the second is the one `gh` sends.
        let mut asked = 0;
        let answer = judge(
            &rule("actor-precedence-second", "example-app[bot]"),
            &WRITE,
            &environment(&[("GH_TOKEN", ""), ("GITHUB_TOKEN", "ghs_installation")]),
            &mut |_| {
                asked += 1;
                Ok(String::from("example-app[bot]"))
            },
        );
        assert!(answer.unwrap().is_none());
        assert_eq!(asked, 1);
    }

    #[test]
    fn the_declared_apps_installation_token_passes() {
        let answer = judge(
            &rule("actor-pass", "example-app[bot]"),
            &WRITE,
            &environment(&[("GH_TOKEN", "ghs_installation")]),
            // Case differs: GitHub logins do not.
            &mut |host| {
                assert_eq!(host, "github.com");
                Ok(String::from("Example-App[bot]"))
            },
        );
        assert!(answer.unwrap().is_none());
    }

    #[test]
    fn another_apps_installation_token_is_refused_by_name() {
        let report = report(judge(
            &rule("actor-other", "example-app[bot]"),
            &WRITE,
            &environment(&[("GH_TOKEN", "ghs_installation")]),
            &mut |_| Ok(String::from("other-app[bot]")),
        ));
        assert!(report.contains("would run as other-app[bot]"), "{report}");
        assert!(report.contains("run as example-app[bot]"), "{report}");
        assert!(!report.contains("ghs_installation"), "{report}");
    }

    #[test]
    fn a_forge_that_could_not_be_asked_is_exit_2_and_never_a_pass() {
        for silence in [
            Silence::Refused(String::from("error connecting to api.github.com")),
            Silence::NotFound,
            Silence::RateLimited {
                resets_in_minutes: None,
            },
        ] {
            let error = judge(
                &rule("actor-silent", "example-app[bot]"),
                &WRITE,
                &environment(&[("GH_TOKEN", "ghs_installation")]),
                &mut |_| Err(silence.clone()),
            )
            .expect_err("a forge that did not answer was read as an answer");
            let text = error.to_string();
            assert!(text.contains("could not be established"), "{text}");
            assert!(text.contains("UPHOLD_ALLOW=app-actor"), "{text}");
            assert!(text.contains("nothing was published"), "{text}");
        }
    }

    #[test]
    fn a_token_quoted_back_by_the_forge_is_not_printed() {
        let error = judge(
            &rule("actor-redact", "example-app[bot]"),
            &WRITE,
            &environment(&[("GH_TOKEN", "ghs_installation")]),
            &mut |_| Err(Silence::Refused(String::from("bad token ghs_installation"))),
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("ghs_installation"), "{error}");
        assert!(error.contains("bad token <token>"), "{error}");
    }

    #[test]
    fn a_host_other_than_github_com_is_exit_2() {
        let error = judge(
            &rule("actor-host", "example-app[bot]"),
            &Attempt {
                command: "gh api",
                host: "github.example.com",
            },
            &environment(&[("GH_TOKEN", "ghs_installation")]),
            &mut |_| Err(Silence::Refused(String::from("asked offline"))),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("github.example.com"), "{error}");
        assert!(
            !error.contains("asked offline"),
            "the forge was asked: {error}"
        );
        assert!(error.contains("nothing was published"), "{error}");
    }
}
