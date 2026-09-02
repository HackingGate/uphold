//! Checking something that never becomes a file.
//!
//! A commit message, a pull-request body, a release note. Those are published
//! the moment they are written, and a file-scanning checker cannot see them at
//! all -- the content reaches a public API without passing through the tree it
//! would have been scanned in.
//!
//! Not every rule applies. A literal rule does, because its needles describe
//! the RUNNING HOST rather than a repository convention, so they mean something
//! against any text. A pattern rule is scoped by `include` and `glob` to
//! particular paths and file types; firing it at a pull-request body would be
//! guesswork, and a guard that guesses gets turned off.
//!
//! Which is why this module also holds the table of WHICH rules each seam
//! applies -- [`Judged`], [`Seam`] and [`judged`]. Four seams judge published
//! text and they were four hand-written assemblies of the same ingredients
//! until that existed; see [`Judged`] for what went dark under that
//! arrangement.

use std::io::Read;
use std::path::PathBuf;

use crate::config::{self, Check, CheckKind, Literals, Policy, Rule};
use crate::engine::{self, Query};
use crate::error::{Exit, Fatal, Result};
use crate::report::Failure;
use crate::sources;

/// The built-in literal source that reads the running host: its username, its
/// home path, its hostname. Named once, because the fallback below and the test
/// for whether anything already covers it have to mean the same string.
const RUNNING_OS_IDENTITY: &str = "running-os-identity";

/// Used when the caller's repository declares no dynamic rules of its own, or
/// has no policy file at all.
///
/// Text mode is reached from things like `gh pr create`, which runs wherever the
/// author happens to be standing: a superproject that only tracks submodules, a
/// scratch checkout, someone else's clone. Falling back to "nothing to check"
/// there would leave the guard absent in exactly the places nobody thought to
/// configure it, which is how identity gets published.
fn fallback_rule() -> Rule {
    let mut rule = Rule::synthetic(
        "no-running-os-identity-metadata",
        Check::ForbiddenLiterals {
            literals: Literals::Named {
                forbidden_literals: String::from(RUNNING_OS_IDENTITY),
            },
            ignore_literals: None,
        },
    );
    rule.message = Some(String::from(
        "Do not put identity metadata from the running OS into text that gets published. \
         The policy checker reads the current username, home path, and hostname (including \
         the identifying parts of it) at runtime, then searches the text you are about to \
         send. Use neutral placeholders such as example-user, example-host, example.test, \
         and /srv/example instead.",
    ));
    rule
}

/// The text to judge, or a refusal.
///
/// `from_utf8_lossy` stood here, and it is the quiet version of the failure
/// this whole tool is about: an invalid sequence became U+FFFD without a word,
/// so `printf 'caf\xe9 latin1\n' | uphold scan --text -` printed "policy checks
/// passed (text)" and exited 0 over bytes that were never the text they were
/// searched as. Every other reader in this binary already refuses this --
/// `scan` says "clean would mean unexamined" about a non-UTF-8 file, and
/// `guard --text` errors out -- so this is the one place the answer differed.
///
/// It is exit 2 rather than exit 1: nothing was found and nothing was cleared.
/// The bytes could not be looked at.
fn decode(bytes: Vec<u8>, source: &str) -> Result<String> {
    String::from_utf8(bytes).map_err(|error| {
        Fatal::new(format!(
            "{source}: is not UTF-8 (invalid byte at offset {}), so it cannot be searched \
             as text and \"clean\" would mean \"unexamined\". Re-encode it as UTF-8, or \
             hand this checker the text rather than the bytes",
            error.utf8_error().valid_up_to()
        ))
    })
}

fn read(source: &str) -> Result<String> {
    if source == "-" {
        let mut buffer = Vec::new();
        std::io::stdin().read_to_end(&mut buffer)?;
        return decode(buffer, "standard input");
    }
    let path = PathBuf::from(source);
    let bytes = std::fs::read(&path).map_err(|error| Fatal::at(&path, error))?;
    decode(bytes, source)
}

/// One kind of rule a piece of published text is judged by.
///
/// The list exists because there were four of it. `uphold scan --text`,
/// `uphold guard --text`, `uphold hook` and the shim each assembled their own
/// set of these by hand, out of the same ingredients, and a rule kind added to
/// three of the four was then dark in the fourth with nothing anywhere to say
/// so. That is not hypothetical: the prose rules reached three seams and never
/// reached `hook`, so every `prose_regexp` rule -- the whole bundled
/// `prose-shapes` set among them -- was silent at exactly the seam those sets
/// name `gh` for.
///
/// A fifth kind is added HERE, and every seam's answer about it is a `match`
/// arm the compiler asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Judged {
    /// The `forbidden_literals` rules, and the running-host fallback under
    /// them. They describe the machine rather than a repository convention, so
    /// they mean something against any text.
    Literals,
    /// The text-capable built-in guards -- [`crate::guard::TEXT_GUARDS`].
    Guards,
    /// The `prose_regexp` rules that stand in front of a command. A prose rule
    /// scoped only by `files.*` is left out for the reason `Patterns` is left
    /// out of every seam but the shim's.
    Prose,
    /// `regexp` and `require_regexp`. Scoped by `include` and `glob` to
    /// particular paths and file types, so firing one at text that has no path
    /// would be guesswork -- and a guard that guesses gets turned off. The one
    /// seam that runs them is the shim, where the invocation itself names the
    /// subject the rule was written about.
    Patterns,
    /// The `exec` checkers: a subject on stdin, an exit status back. Also the
    /// shim's alone, and for the same reason.
    Consultation,
}

/// Every kind, in the order a report lists them.
///
/// The order is the contract: it is what makes the literal findings precede the
/// guard refusals precede the prose findings in every report that carries more
/// than one kind.
pub(crate) const EVERY_JUDGED: &[Judged] = &[
    Judged::Literals,
    Judged::Guards,
    Judged::Prose,
    Judged::Patterns,
    Judged::Consultation,
];

impl Judged {
    /// Which kind one declared rule is judged as, or `None` for a rule that
    /// judges no published text at all.
    ///
    /// A rule reaches at most one of these: the check kinds are exclusive by
    /// `Rule::validate`, and a built-in that is not a text guard -- one that
    /// reads the index, an identity, a destination -- has nothing to say about
    /// a piece of text and is not asked.
    pub(crate) fn of(rule: &Rule) -> Option<Self> {
        if let Some(builtin) = rule.builtin() {
            return crate::guard::TEXT_GUARDS
                .contains(&builtin)
                .then_some(Self::Guards);
        }
        Some(match rule.kind() {
            CheckKind::ForbiddenLiterals => Self::Literals,
            CheckKind::ProseRegexp => Self::Prose,
            CheckKind::Regexp | CheckKind::RequireRegexp => Self::Patterns,
            CheckKind::Exec => Self::Consultation,
            _ => return None,
        })
    }
}

/// A seam a piece of published text is judged at.
///
/// Four, and they do not consult the same kinds -- which is the whole reason
/// this is a table rather than one list. `--text` is handed text that has no
/// path, so a path-scoped pattern rule fired there would be guesswork; the shim
/// is handed a named subject by an invocation that says which rules stand in
/// front of it, so the same rule is exactly in scope. What must not vary is
/// whether the answer was WRITTEN DOWN, and here it is written down once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Seam {
    /// `uphold scan --text` -- a commit message at `commit-msg`, a release
    /// note, a body piped in by hand.
    Scan,
    /// `uphold guard --text`.
    Guard,
    /// `uphold hook <harness>` -- the pending tool call, where publishing
    /// spawns no process at all.
    Hook,
    /// The shim, standing in front of a publishing command.
    Command,
}

impl Seam {
    /// What this seam consults. The one table.
    pub(crate) const fn consults_every(self) -> &'static [Judged] {
        match self {
            // The literal rules because they read the running host, and the
            // prose rules because a shape refused in the pull-request body
            // announcing a commit is refused in the commit message too.
            Self::Scan => &[Judged::Literals, Judged::Prose],
            // The guards, and the prose rules for the same reason. Not the
            // literal rules directly: a policy reaches those from here through
            // the `text-literals` built-in, which is a guard, and running them
            // twice would report each finding under two ids.
            Self::Guard => &[Judged::Guards, Judged::Prose],
            // No process to intercept and no `text-literals` declaration to
            // lean on -- this is reached from wherever a session was started,
            // frequently with no policy at all -- so it asks the literal rules
            // itself, and it asks the other two because a body an MCP server
            // posts is the same body `gh` would have posted.
            Self::Hook => &[Judged::Literals, Judged::Guards, Judged::Prose],
            // The literal rules the way a policy asks for them, through
            // `text-literals`; and the two kinds no other seam can run, because
            // the invocation names the subject they are scoped to.
            Self::Command => &[
                Judged::Guards,
                Judged::Prose,
                Judged::Patterns,
                Judged::Consultation,
            ],
        }
    }

    /// Whether this seam consults that kind of rule.
    pub(crate) fn consults(self, judged: Judged) -> bool {
        self.consults_every().contains(&judged)
    }
}

/// One thing found wrong with a piece of published text.
///
/// Two shapes and not one, because a report names them differently: a rule's
/// finding is `policy check failed`, a guard's is `guard refused`, and the
/// caller that renders them is the caller that knows which form its seam
/// speaks. Every caller handles both arms, so a change to the table above is a
/// change to WHAT prints and never to whether it does.
pub(crate) enum Verdict {
    /// A literal rule's or a prose rule's finding.
    Rule(Failure),
    /// A guard's refusal.
    Guard(crate::guard::Refusal),
}

/// Everything a piece of published text is judged by, at one seam.
///
/// The single assembly. `label` is what the subject is called in a report --
/// the tool name at the hook, the source at `--text` -- and is reported rather
/// than matched on.
pub(crate) fn judged(
    seam: Seam,
    root: &std::path::Path,
    policy: &Policy,
    label: &str,
    text: &str,
) -> Result<Vec<Verdict>> {
    let mut verdicts: Vec<Verdict> = Vec::new();
    for kind in EVERY_JUDGED {
        if !seam.consults(*kind) {
            continue;
        }
        match *kind {
            Judged::Literals => {
                verdicts.extend(
                    failures_in(root, policy, text)?
                        .into_iter()
                        .map(Verdict::Rule),
                );
            }
            Judged::Guards => {
                verdicts.extend(
                    crate::guard::over_text(root, policy, label, text)?
                        .into_iter()
                        .map(Verdict::Guard),
                );
            }
            Judged::Prose => {
                verdicts.extend(
                    crate::prose::over_text(policy, text)?
                        .into_iter()
                        .map(Verdict::Rule),
                );
            }
            // The shim's two, and the shim does not arrive here: it holds a
            // subject and a per-rule scope this function is not given, so it
            // dispatches rule by rule through `Judged::of` instead. Reached
            // only if `Seam::Command` is ever handed to this function, and
            // running a path-scoped rule over pathless text is the one thing
            // this file exists to refuse.
            Judged::Patterns | Judged::Consultation => {}
        }
    }
    Ok(verdicts)
}

pub(crate) fn check(found: Option<&(PathBuf, PathBuf)>, source: &str) -> Result<Exit> {
    let text = read(source)?;
    let (root, policy) = load_for(found)?;
    let verdicts = judged(Seam::Scan, &root, &policy, source, &text)?;

    for verdict in &verdicts {
        match verdict {
            Verdict::Rule(failure) => failure.print(),
            Verdict::Guard(refusal) => {
                eprintln!(
                    "guard refused: {}",
                    crate::guard::refused_by(&policy, refusal)
                );
                eprintln!("{}", refusal.report.trim_end());
                eprintln!();
            }
        }
    }
    if verdicts.is_empty() {
        println!("policy checks passed (text)");
        return Ok(Exit::Clean);
    }
    Ok(Exit::Violations)
}

/// The policy a text check runs under, and the root it was loaded from.
///
/// An empty policy where the caller found none, which is the fallback this
/// module exists to keep: text mode is reached from `gh pr create` wherever the
/// author happens to be standing, and "no policy here" must not mean "nothing
/// to check". The hook seam is in that case more often than not, which is why
/// this is reachable from outside the module.
pub(crate) fn load_for(found: Option<&(PathBuf, PathBuf)>) -> Result<(PathBuf, Policy)> {
    match found {
        Some((root, policy_path)) => Ok((root.clone(), config::load(root, policy_path)?)),
        None => Ok((std::env::current_dir()?, Policy::default())),
    }
}

/// The same rules over an already-loaded policy.
///
/// Split from [`failures`] for the `text-literals` built-in: a shim consulting
/// it already holds the policy that named the rule, and loading it again from
/// disk would be a second reading free to disagree with the first.
pub(crate) fn failures_in(
    root: &std::path::Path,
    policy: &Policy,
    text: &str,
) -> Result<Vec<Failure>> {
    // The test is for the identity rule itself, not for the CHECK KIND it
    // happens to use. Asking whether any `forbidden_literals` rule existed made
    // an unrelated one -- a repository's own list of literals, a command
    // source, anything at all -- silently remove the fallback, which exists per
    // its own docstring so that the guard is not absent "in exactly the places
    // nobody thought to configure it, which is how identity gets published".
    // Declaring a rule about something else is not a decision to stop checking
    // this, so both run: the declared rules, and the fallback when nothing
    // among them reads the running host's identity.
    let mut owned: Vec<Rule> = policy
        .of_check(CheckKind::ForbiddenLiterals)
        .cloned()
        .collect();
    if !owned
        .iter()
        .any(|rule| rule.forbidden_literals() == Some(RUNNING_OS_IDENTITY))
    {
        owned.push(fallback_rule());
    }

    let mut failures: Vec<Failure> = Vec::new();
    for rule in &owned {
        let needles = sources::resolve(
            // `forbidden_literals_from` IS the command source; v2 said it twice.
            if rule.forbidden_literals_from().is_some() {
                "command"
            } else {
                rule.forbidden_literals().unwrap_or_default()
            },
            rule.forbidden_literals_from(),
            root,
            rule.files().word,
            &rule.id,
            rule.ignore_literals(),
        )?;
        for needle in needles {
            let label = format!("{} ({})", rule.id, needle.label);
            let hits =
                engine::search_text(text, &Query::literal(&needle.value, needle.word), &label)?;
            if hits.is_empty() {
                continue;
            }
            let body = hits
                .iter()
                .map(|hit| {
                    let line = hit.line.unwrap_or(0);
                    if policy.redact_matches {
                        format!("line {line}: [REDACTED_MATCH]")
                    } else {
                        format!("line {line}: {}", hit.text)
                    }
                })
                .collect::<Vec<String>>()
                .join("\n");
            failures.push(Failure::new(label, rule.message(), body));
        }
    }

    Ok(failures)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one thing the table exists to keep true.
    ///
    /// A prose rule standing in front of a command is a judgement about a
    /// published sentence, and every seam here publishes sentences. It reached
    /// three of the four and missed `hook`, silently, for two releases -- which
    /// is what a hand-assembled list of rule kinds does. Written as a property
    /// over the seams rather than as one more case per seam, so a fifth seam
    /// is asked the question by existing.
    #[test]
    fn every_seam_that_judges_published_text_consults_the_prose_rules() {
        for seam in [Seam::Scan, Seam::Guard, Seam::Hook, Seam::Command] {
            assert!(seam.consults(Judged::Prose), "{seam:?}");
        }
    }

    /// And no kind is declared that nothing runs.
    ///
    /// The other direction of the same failure: a kind reachable from no seam
    /// is a rule a policy may declare, that loads, and that judges nothing.
    #[test]
    fn every_kind_of_judgement_is_reached_from_some_seam() {
        for kind in EVERY_JUDGED {
            assert!(
                [Seam::Scan, Seam::Guard, Seam::Hook, Seam::Command]
                    .iter()
                    .any(|seam| seam.consults(*kind)),
                "{kind:?}"
            );
        }
    }

    /// A built-in rule carrying no parameter, which is every one below.
    fn named_builtin(name: &str) -> Check {
        Check::Builtin {
            builtin: String::from(name),
            parameters: Box::default(),
        }
    }

    /// A rule is classified by what it declares, and a built-in that judges
    /// something other than text is classified as nothing at all.
    #[test]
    fn a_rule_is_the_kind_it_declares_and_a_non_text_builtin_is_no_kind() {
        let prose = Rule::synthetic(
            "shape",
            Check::ProseRegexp {
                prose_regexp: String::from("x"),
            },
        );
        assert_eq!(Judged::of(&prose), Some(Judged::Prose));

        let guard = Rule::synthetic("names", named_builtin("no-private-repo-names"));
        assert_eq!(Judged::of(&guard), Some(Judged::Guards));

        // Reads a push range, not a piece of text, so it is not asked about one.
        let push = Rule::synthetic("push", named_builtin("prevent-public-push"));
        assert_eq!(Judged::of(&push), None);
    }
}
