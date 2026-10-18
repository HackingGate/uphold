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
//!
//! And what each rule ANSWERED, as a list -- [`Judgment`]. A seam's report and
//! its exit code are read off that list, and so is the `JUnit` document it
//! writes, so a rule cannot be refused on stderr and passed in the file.

use std::io::Read;
use std::path::PathBuf;

use crate::config::{self, Check, CheckKind, Literals, Policy, Rule};
use crate::engine::{self, Query};
use crate::error::{Exit, Fatal, Result, verdict};
use crate::guard::Allowed;
use crate::invocation::{Invocation, Observed};
use crate::junit::Outcome;
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
            // posts is the same body `gh` would have posted. The pattern rules
            // are reached here too, but run only where a rule's own `seams`
            // names the hook -- see [`Seam::runs_by_default`].
            Self::Hook => &[
                Judged::Literals,
                Judged::Guards,
                Judged::Prose,
                Judged::Patterns,
            ],
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

    /// Whether a rule of kind `judged` that declares no `seams` runs here.
    ///
    /// Every kind this seam consults, but one. A `regexp` rule standing in
    /// front of a command was written about the subjects a shim collects -- a
    /// title, a ref, a command line -- and every such rule written before
    /// `seams` existed ran at the shim alone. Running it over every tool call
    /// the hook sees would be a refusal nobody asked for on an upgrade, so the
    /// hook runs a pattern rule only where the rule names it.
    pub(crate) fn runs_by_default(self, judged: Judged) -> bool {
        self.consults(judged) && !matches!((self, judged), (Self::Hook, Judged::Patterns))
    }

    /// What a rule's `seams` list calls this seam. The two `--text` seams are
    /// one name: they are handed the same text by the same kind of caller, and
    /// a rule that runs at one and not the other would be a distinction about
    /// which subcommand a hook file happened to spell.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Scan | Self::Guard => "text",
            Self::Hook => "hook",
            Self::Command => "shim",
        }
    }
}

/// One thing found wrong with a piece of published text.
///
/// Two shapes and not one, because a report names them differently: a rule's
/// finding is `policy check failed`, a guard's is `guard refused`, and the
/// caller that renders them is the caller that knows which form its seam
/// speaks. Every caller handles both arms, so a change to the table above is a
/// change to WHAT prints and never to whether it does.
#[derive(Debug, Clone)]
pub(crate) enum Verdict {
    /// A literal rule's or a prose rule's finding.
    Rule(Failure),
    /// A guard's refusal.
    Guard(crate::guard::Refusal),
}

/// What one rule answered, about one subject.
///
/// Five, and the dispatch used to return one of them. A rule that was not a
/// text guard, one that was bypassed and one that looked and found nothing
/// all came back as no refusal, and a record of what ran cannot be written
/// from that: the three have to be told apart, and a fifth -- a rule whose own
/// scope did not hold at this destination -- is neither a pass nor a bypass.
/// A rule that judges no text at all is not here: it is not asked, so it has
/// no answer.
#[derive(Debug, Clone)]
pub(crate) enum Answer {
    /// Looked, and found nothing.
    Pass,
    /// Looked, and refused; the report is the one a reader acts on.
    Refused(Verdict),
    /// Could not look. The seam stops here with exit 2, so this is the last
    /// answer its list holds.
    Unknown,
    /// Did not run, by `UPHOLD_ALLOW`.
    Bypass(Allowed),
    /// Did not run, because its own scope did not hold here.
    OutOfScope,
}

/// One entry in a seam's list: which rule, about which kind of subject, and
/// what it answered. The subject is its KIND -- `text`, `title`, the tool's
/// name -- and never what it said, since this is what a record is written
/// from.
#[derive(Debug, Clone)]
pub(crate) struct Judgment {
    pub id: String,
    /// The dispatch name, for a built-in; a prose or literal rule has none.
    pub builtin: Option<String>,
    /// The bundled set the rule came from.
    pub set: Option<String>,
    pub subject: Option<String>,
    pub answer: Answer,
}

impl Judgment {
    pub(crate) fn of(rule: &Rule, subject: Option<&str>, answer: Answer) -> Self {
        Self {
            id: rule.id.clone(),
            builtin: rule.builtin().map(str::to_owned),
            set: rule.origin.set().map(str::to_owned),
            subject: subject.map(str::to_owned),
            answer,
        }
    }

    /// The refusal this entry carries, if it refused.
    pub(crate) const fn refused(&self) -> Option<&Verdict> {
        match &self.answer {
            Answer::Refused(verdict) => Some(verdict),
            _ => None,
        }
    }
}

/// Anything that is one rule's answer, as the record names it. A trait so the
/// count every seam settles its exit on is one function over the real list
/// and over the model of it the proofs below reason about.
pub(crate) trait Answered {
    fn outcome(&self) -> Outcome;
}

impl Answered for Judgment {
    fn outcome(&self) -> Outcome {
        match &self.answer {
            Answer::Pass => Outcome::Pass,
            Answer::Refused(_) => Outcome::Refuse,
            Answer::Unknown => Outcome::Unknown,
            Answer::Bypass(allowed) => Outcome::Bypass(*allowed),
            Answer::OutOfScope => Outcome::OutOfScope,
        }
    }
}

/// How many answers refused: the one number a seam's exit is read from.
pub(crate) fn refusals<V: Answered>(answers: &[V]) -> usize {
    answers
        .iter()
        .filter(|answer| answer.outcome() == Outcome::Refuse)
        .count()
}

/// Ask `rule` something, and where it could not answer put that in the list
/// before the error goes up: the run stops here, and the record of it must say
/// which rule it stopped at.
pub(crate) fn asked<T>(
    ledger: &mut Vec<Judgment>,
    rule: &Rule,
    subject: Option<&str>,
    asking: Result<T>,
) -> Result<T> {
    if asking.is_err() {
        ledger.push(Judgment::of(rule, subject, Answer::Unknown));
    }
    asking
}

/// The findings a seam reports, read off its list in the order they were
/// asked. A guard asked about a body and again about each headline is one
/// refusal per rule -- see [`merged_by_rule`] -- placed where its first one
/// was.
pub(crate) fn verdicts(ledger: &[Judgment]) -> Vec<Verdict> {
    let mut found = Vec::new();
    let mut guards = Vec::new();
    let mut guards_at = None;
    for verdict in ledger.iter().filter_map(Judgment::refused) {
        match verdict {
            Verdict::Rule(failure) => found.push(Verdict::Rule(failure.clone())),
            Verdict::Guard(refusal) => {
                guards_at.get_or_insert(found.len());
                guards.push(refusal.clone());
            }
        }
    }
    if let Some(at) = guards_at {
        found.splice(
            at..at,
            merged_by_rule(guards).into_iter().map(Verdict::Guard),
        );
    }
    found
}

/// The list of one seam, given how each kind of rule it consults answered.
///
/// Every input arrives through `answer`, so nothing here reads a file, runs a
/// command or looks at a policy. That is what lets `#[cfg(kani)] mod proofs`
/// state the fail-closed property over every combination of answers rather
/// than over the rules a test can write. [`judged`] is the caller that knows
/// what each kind reads.
///
/// The list is the caller's and not a return value, because a kind that
/// could not look stops the seam and what was answered before it -- the
/// `Unknown` among it -- is still the record of the run.
pub(crate) fn over_kinds<V>(
    seam: Seam,
    ledger: &mut Vec<V>,
    mut answer: impl FnMut(Judged, &mut Vec<V>) -> Result<()>,
) -> Result<()> {
    for kind in EVERY_JUDGED {
        if seam.consults(*kind) {
            answer(*kind, ledger)?;
        }
    }
    Ok(())
}

/// One headline a seam was handed beside its prose: a title, or a commit
/// message's first line, and what the report calls it.
pub(crate) struct Headline {
    pub label: String,
    pub text: String,
}

/// Everything a piece of published text is judged by, at one seam.
///
/// The single assembly. The invocation carries report identity, observed prose
/// and separately identified headlines. Only the hook exposes that identity as
/// a `tool` subject; raw text filenames are labels. An absent prose subject
/// leaves the tool observable, while unread required prose stops judgment.
/// Checkers read prose and headlines joined; guards receive each headline
/// separately, preserving the same headline treatment as command collection.
///
/// Every rule's answer goes into `ledger`, and what the seam reports is read
/// back off it. The subject each is recorded under is the tool's name at the
/// hook and `text` elsewhere: a `--text` label is a file name, and a record
/// carries no path.
pub(crate) fn judged(
    invocation: &Invocation<'_>,
    root: &std::path::Path,
    policy: &Policy,
    ledger: &mut Vec<Judgment>,
) -> Result<Vec<Verdict>> {
    let input = invocation.text_input()?;
    let prose = input.prose.read()?.copied();
    let headlines = input.headlines;
    let seam = invocation.seam;
    let label = invocation.label;
    let recorded = |named: &'_ str| -> String {
        if seam == Seam::Hook {
            named.to_owned()
        } else {
            String::from("text")
        }
    };
    let subject = recorded(label);
    let has_text = prose.is_some() || !headlines.is_empty();
    let text = prose.unwrap_or_default();
    let joined;
    let whole = if headlines.is_empty() {
        text
    } else {
        joined = std::iter::once(text)
            .chain(headlines.iter().map(|headline| headline.text.as_str()))
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        joined.as_str()
    };
    over_kinds(seam, ledger, |kind, ledger| {
        if !has_text && kind != Judged::Patterns {
            return Ok(());
        }
        match kind {
            Judged::Literals => failures_in(root, policy, whole, Some(&subject), ledger),
            // Every inner rule is in scope here: the three seams that reach
            // this line -- `scan --text`, `guard --text`, the harness hook --
            // are handed text and no destination, so there is nothing to ask a
            // `public-target` scope about. The shim, which does have one,
            // passes its own memo.
            Judged::Guards => {
                // The prose is not a headline: what these seams are handed is a
                // body, or a tool call's strings joined, and neither says which
                // part of it is a subject. The headlines are, each on its own,
                // because a subject is judged line by line as one.
                if !text.is_empty() || headlines.is_empty() {
                    let published = crate::guard::Published {
                        label,
                        kind: &subject,
                        text,
                        added: None,
                        headline: false,
                    };
                    crate::guard::over_text(
                        root,
                        policy,
                        None,
                        &published,
                        &mut |_| Ok(true),
                        ledger,
                    )?;
                }
                for headline in headlines {
                    let headline_kind = recorded(&headline.label);
                    let published = crate::guard::Published {
                        label: &headline.label,
                        kind: &headline_kind,
                        text: &headline.text,
                        added: None,
                        headline: true,
                    };
                    crate::guard::over_text(
                        root,
                        policy,
                        None,
                        &published,
                        &mut |_| Ok(true),
                        ledger,
                    )?;
                }
                Ok(())
            }
            Judged::Prose => crate::prose::over_text(policy, seam, whole, &subject, ledger),
            // Only the hook consults these here, and only the rules whose
            // `seams` names it -- see `Seam::runs_by_default`.
            Judged::Patterns => patterns_over(
                policy,
                seam,
                invocation.tool(),
                has_text.then_some(whole),
                headlines,
                &subject,
                ledger,
            ),
            // The shim's, and the shim does not arrive here: it holds a subject
            // and a per-rule scope this function is not given, so it dispatches
            // rule by rule through `Judged::of` instead.
            Judged::Consultation => Ok(()),
        }
    })?;
    Ok(verdicts(ledger))
}

/// One refusal per rule, from the several parts of a call a rule was run over.
///
/// A rule that fires on a title and again on a body is one finding about one
/// call, and printing its block twice reads as two. A report is paragraphs: what
/// was found in which part, then what to do about it. A paragraph every report
/// of the rule shares is the rule's own advice and is printed once, after the
/// findings; the rest are kept in the order the parts were judged, each already
/// naming the part it was found in.
fn merged_by_rule(refusals: Vec<crate::guard::Refusal>) -> Vec<crate::guard::Refusal> {
    let mut grouped: Vec<(String, Vec<String>)> = Vec::new();
    for refusal in refusals {
        match grouped.iter_mut().find(|(id, _)| *id == refusal.id) {
            Some((_, reports)) => reports.push(refusal.report),
            None => grouped.push((refusal.id, vec![refusal.report])),
        }
    }
    grouped
        .into_iter()
        .map(|(id, reports)| {
            if let [report] = reports.as_slice() {
                return crate::guard::Refusal {
                    id,
                    report: report.clone(),
                };
            }
            let paragraphs: Vec<Vec<&str>> = reports
                .iter()
                .map(|report| report.trim_end().split("\n\n").collect())
                .collect();
            let shared = |paragraph: &str| paragraphs.iter().all(|each| each.contains(&paragraph));
            let mut found: Vec<&str> = Vec::new();
            for paragraph in paragraphs.iter().flatten() {
                if !shared(paragraph) && !found.contains(paragraph) {
                    found.push(paragraph);
                }
            }
            let advice = paragraphs
                .first()
                .into_iter()
                .flatten()
                .copied()
                .filter(|paragraph| shared(paragraph));
            let mut report = found
                .into_iter()
                .chain(advice)
                .collect::<Vec<_>>()
                .join("\n\n");
            report.push('\n');
            crate::guard::Refusal { id, report }
        })
        .collect()
}

/// The pattern rules a seam runs over published text, each asked about the
/// subjects its `subjects` selects.
///
/// Three kinds of subject at the hook: the call's text, as kind `text`, each
/// headline the call carried, as kind `title` under the key it was found at,
/// and what the call is called, as kind `tool`. A title-scoped rule means the
/// same here as at the shim, where `--title` is kind `title`; every headline
/// key is that one kind, a commit subject under `commit_title` included,
/// because the shim does not tell a pull-request title from a commit subject
/// either. The tool name is the hook's nearest thing to a command line -- `mcp__github__create_release` is to an MCP server what
/// `release create` is to `gh` -- and handing it over as a kind of its own lets
/// a rule refuse the call by name without also refusing every body that
/// mentions it. Which tool names mean which command is the rule's to say, in its
/// own pattern: a table of MCP names per shim verb would be a list that is
/// missing the tool a server added last week.
fn patterns_over(
    policy: &Policy,
    seam: Seam,
    tool: Option<&str>,
    text: Option<&str>,
    headlines: &[Headline],
    recorded: &str,
    ledger: &mut Vec<Judgment>,
) -> Result<()> {
    // The shim runs its pattern rules itself, over the subjects it collected,
    // and never through this function; were it ever handed here, running its
    // rules over one pathless blob is the guess this module exists to refuse.
    if seam != Seam::Hook {
        return Ok(());
    }
    // Each with the label a report names it by: the kind alone for the call's
    // own two, the key for a headline, so a finding says which field it was in.
    let mut subjects = Vec::new();
    if let Some(text) = text {
        subjects.push((
            None,
            crate::shim::Subject {
                kind: "text",
                value: text.to_owned(),
                added: None,
            },
        ));
    }
    if let Some(tool) = tool {
        subjects.push((
            None,
            crate::shim::Subject {
                kind: "tool",
                value: tool.to_owned(),
                added: None,
            },
        ));
    }
    subjects.extend(headlines.iter().map(|headline| {
        (
            Some(headline.label.as_str()),
            crate::shim::Subject {
                kind: crate::shim::Subject::HEADLINE,
                value: headline.text.clone(),
                added: None,
            },
        )
    }));
    for rule in &policy.rules {
        if !matches!(rule.kind(), CheckKind::Regexp | CheckKind::RequireRegexp)
            || rule.command.is_none()
            || !rule.judged_at(seam)
        {
            continue;
        }
        if let Some(allowed) = crate::guard::allowed(&rule.id) {
            eprintln!("uphold: {} bypassed by UPHOLD_ALLOW", rule.id);
            ledger.push(Judgment::of(rule, Some(recorded), Answer::Bypass(allowed)));
            continue;
        }
        let mut found = Vec::new();
        for (named, subject) in subjects
            .iter()
            .filter(|(_, subject)| rule.selects_subject(subject.kind))
        {
            let finding = asked(
                ledger,
                rule,
                Some(recorded),
                crate::shim::pattern_finding(rule, subject),
            )?;
            if let Some(finding) = finding {
                let at = named.map_or_else(String::new, |name| format!(" (in {name})"));
                found.push(if policy.redact_matches {
                    format!(
                        "{}: the {} subject{at}: [REDACTED_MATCH]",
                        rule.id, subject.kind
                    )
                } else {
                    format!("{finding}{at}")
                });
            }
        }
        ledger.push(Judgment::of(
            rule,
            Some(recorded),
            if found.is_empty() {
                Answer::Pass
            } else {
                Answer::Refused(Verdict::Rule(Failure::new(
                    &rule.id,
                    rule.message(),
                    found.join("\n"),
                )))
            },
        ));
    }
    Ok(())
}

pub(crate) fn check(found: Option<&(PathBuf, PathBuf)>, source: &str) -> Result<Exit> {
    let text = read(source)?;
    let (root, policy) = load_for(found)?;
    let invocation = Invocation::text(Seam::Scan, source, Observed::Present(&text), &[]);
    // `scan --text` writes no record; the list is what it reports from.
    let mut ledger = Vec::new();
    let verdicts = judged(&invocation, &root, &policy, &mut ledger)?;

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
    let exit = verdict(refusals(&ledger), 0);
    if exit == Exit::Clean {
        println!("policy checks passed (text)");
    }
    Ok(exit)
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

/// The literal rules, and the running-host fallback under them, over an
/// already-loaded policy, each answering into `ledger` once per needle found
/// or once to pass.
///
/// Over the loaded policy for the `text-literals` built-in: a shim consulting
/// it already holds the policy that named the rule, and loading it again from
/// disk would be a second reading free to disagree with the first.
pub(crate) fn failures_in(
    root: &std::path::Path,
    policy: &Policy,
    text: &str,
    recorded: Option<&str>,
    ledger: &mut Vec<Judgment>,
) -> Result<()> {
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

    for rule in &owned {
        let needles = asked(
            ledger,
            rule,
            recorded,
            sources::resolve(
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
            ),
        )?;
        let mut refused = false;
        for needle in needles {
            let label = format!("{} ({})", rule.id, needle.label);
            let hits = asked(
                ledger,
                rule,
                recorded,
                engine::search_text(text, &Query::literal(&needle.value, needle.word), &label),
            )?;
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
            refused = true;
            ledger.push(Judgment::of(
                rule,
                recorded,
                Answer::Refused(Verdict::Rule(Failure::new(label, rule.message(), body))),
            ));
        }
        if !refused {
            ledger.push(Judgment::of(rule, recorded, Answer::Pass));
        }
    }

    Ok(())
}

/// The fail-closed property of the published-text seams, over every answer.
///
/// `cargo kani`, and see CONTRIBUTING for what it costs. What a kind of rule
/// answers is left to the model checker: could not look, or one answer of the
/// five a rule gives -- passed, refused, bypassed by id or by `all`, out of
/// scope -- or none at all. The rule bodies themselves -- a regex, a literal
/// search, a command source, a guard reading the repository -- are the part no
/// harness here reaches. What is proven is that no combination of their
/// answers reaches clean except the one where every kind the seam asks looked
/// and refused nothing, and that a rule which did not run -- bypassed, or out
/// of scope -- moves the verdict neither way.
///
/// One answer per kind, and an `Unknown` after it where the kind could not
/// look, is the bound. `over_kinds` never looks inside what a kind answered: it
/// hands the list on or stops at an error, so an empty answer and a non-empty
/// one reach every branch it has, and five kinds at two each still make a list
/// longer than any one kind's.
#[cfg(kani)]
mod proofs {
    use super::{EVERY_JUDGED, Judged, Seam, load_for, over_kinds};
    use crate::config::Policy;
    use crate::error::{Exit, Fatal, Result, verdict};
    use std::path::{Path, PathBuf};

    fn any_seam() -> Seam {
        match kani::any::<u8>() % 4 {
            0 => Seam::Scan,
            1 => Seam::Guard,
            2 => Seam::Hook,
            _ => Seam::Command,
        }
    }

    /// What one kind answered, as far as the seam can tell them apart. A rule
    /// that was bypassed, by its id or by `all`, and a rule stood down at this
    /// destination are one letter here: `over_kinds`, `refusals` and `verdict`
    /// read none of them, and the proofs say what the seam does with an answer
    /// it does not read. An enum the checker picks from directly, and not a
    /// byte reduced by arithmetic, because arithmetic on a symbolic value is a
    /// circuit.
    #[derive(Clone, Copy, PartialEq, Eq, kani::Arbitrary)]
    enum Said {
        Pass,
        Refuse,
        /// Bypassed, or out of scope: did not run, and is not a refusal.
        NotRun,
        /// The kind had no rule to ask.
        Nothing,
    }

    #[derive(Clone, Copy, kani::Arbitrary)]
    struct Given {
        could_not_look: bool,
        said: Said,
    }

    impl Given {
        /// The byte `answer` records for this answer, or none where there is
        /// no rule. The checker compares bytes; an `Outcome` compared on a
        /// symbolic value is a case split per variant per entry, and that was
        /// what put these proofs past a runner's memory.
        fn code(self) -> Option<u8> {
            match self.said {
                Said::Pass => Some(0),
                Said::Refuse => Some(1),
                Said::NotRun => Some(2),
                Said::Nothing => None,
            }
        }
    }

    /// The byte for a kind that could not look.
    const UNKNOWN: u8 = 3;

    /// One entry per kind asked, and one `UNKNOWN` after the kind that could
    /// not look, which is the last one asked -- so the list never grows past
    /// this and the checker never has to model it growing.
    const LONGEST: usize = 6;

    /// What one kind answered, into a list the harness cannot look inside,
    /// counting the refusals beside it. The list is of `()`, which never
    /// allocates: `over_kinds` cannot look inside an entry, so the entry's
    /// type changes the cost of the proof and nothing about what it proves.
    /// A kind that could not look stops the seam, as every rule body does
    /// through `asked`.
    fn answer(
        given: &[Given; 5],
        kind: Judged,
        ledger: &mut Vec<()>,
        refused: &mut usize,
    ) -> Result<()> {
        let one = given[kind as usize];
        if let Some(code) = one.code() {
            ledger.push(());
            if code == 1 {
                *refused += 1;
            }
        }
        if one.could_not_look {
            ledger.push(());
            return Err(Fatal::new(String::new()));
        }
        Ok(())
    }

    /// What the list would hold, written beside it into an array the checker
    /// can read back cheaply: the byte `kind << 2 | code` per entry. The list
    /// itself stays one of `()`, pushed once per entry so its length is the
    /// array's; reading a heap vector back symbolically is what the two
    /// harnesses below could not afford.
    struct Shadow {
        codes: [u8; LONGEST],
        len: usize,
    }

    impl Shadow {
        const fn new() -> Self {
            Self {
                codes: [0; LONGEST],
                len: 0,
            }
        }

        fn push(&mut self, ledger: &mut Vec<()>, code: u8) {
            self.codes[self.len] = code;
            self.len += 1;
            ledger.push(());
        }
    }

    /// The same answer as `answer`, with its bytes recorded in the shadow.
    fn tagged(
        given: &[Given; 5],
        kind: Judged,
        ledger: &mut Vec<()>,
        shadow: &mut Shadow,
    ) -> Result<()> {
        let one = given[kind as usize];
        let tag = (kind as u8) << 2;
        if let Some(code) = one.code() {
            shadow.push(ledger, tag | code);
        }
        if one.could_not_look {
            shadow.push(ledger, tag | UNKNOWN);
            return Err(Fatal::new(String::new()));
        }
        Ok(())
    }

    fn looked_and_refused_nothing(given: &[Given; 5], seam: Seam) -> bool {
        EVERY_JUDGED.iter().all(|kind| {
            let one = given[*kind as usize];
            !seam.consults(*kind) || (!one.could_not_look && one.said != Said::Refuse)
        })
    }

    /// `clean <-> every consulted kind looked and refused nothing`, through the
    /// same `verdict` and `Exit::of` the callers settle on. Clean is a claim
    /// that every consulted kind was evaluated, not the absence of a finding
    /// -- and a rule that did not run is neither a finding nor a failure to
    /// look.
    #[kani::proof]
    #[kani::unwind(7)]
    fn clean_means_every_consulted_kind_looked_and_refused_nothing() {
        let seam = any_seam();
        let given: [Given; 5] = kani::any();
        let mut ledger = Vec::new();
        let mut refused = 0;
        let run = over_kinds(seam, &mut ledger, |kind, ledger| {
            answer(&given, kind, ledger, &mut refused)
        })
        .map(|()| verdict(refused, 0));
        let clean = Exit::of(&run) as i32 == Exit::Clean as i32;
        assert!(clean == looked_and_refused_nothing(&given, seam));
    }

    /// `a consulted kind could not look -> exit 2`, whatever the others
    /// answered. A refusal does not outrank it here, unlike in `verdict`: the
    /// seam stops at the first kind that could not look, so what it would have
    /// reported is not known.
    #[kani::proof]
    #[kani::unwind(7)]
    fn a_consulted_kind_that_could_not_look_is_broken() {
        let seam = any_seam();
        let given: [Given; 5] = kani::any();
        let broken_kind = EVERY_JUDGED
            .iter()
            .any(|kind| seam.consults(*kind) && given[*kind as usize].could_not_look);
        let mut ledger = Vec::new();
        let mut refused = 0;
        let run = over_kinds(seam, &mut ledger, |kind, ledger| {
            answer(&given, kind, ledger, &mut refused)
        })
        .map(|()| verdict(refused, 0));
        assert!(broken_kind == (Exit::of(&run) as i32 == Exit::Broken as i32));
    }

    /// Every consulted kind is asked exactly once when none could not look,
    /// no kind the seam does not consult is ever asked, and nothing a kind
    /// answered is dropped or duplicated on the way to the list the record is
    /// written from.
    #[kani::proof]
    #[kani::unwind(7)]
    fn every_consulted_kind_is_asked_once_and_every_answer_is_kept() {
        let seam = any_seam();
        let given: [Given; 5] = kani::any();
        let mut asked = [0_u8; 5];
        let mut ledger = Vec::new();
        let mut shadow = Shadow::new();
        let run = over_kinds(seam, &mut ledger, |kind, ledger| {
            asked[kind as usize] += 1;
            tagged(&given, kind, ledger, &mut shadow)
        });
        assert!(ledger.len() == shadow.len);
        for kind in EVERY_JUDGED {
            let slot = *kind as usize;
            if !seam.consults(*kind) {
                assert!(asked[slot] == 0);
            } else if run.is_ok() {
                assert!(asked[slot] == 1);
                let mut kept = 0_u8;
                let mut found = false;
                for at in 0..LONGEST {
                    if at < shadow.len && shadow.codes[at] >> 2 == *kind as u8 {
                        kept += 1;
                        found |= Some(shadow.codes[at] & 3) == given[slot].code();
                    }
                }
                match given[slot].code() {
                    Some(_) => assert!(kept == 1 && found),
                    None => assert!(kept == 0),
                }
            }
        }
    }

    /// The list is a function of the seam and the answers: every entry in it
    /// is tagged with a kind the seam consults, and says what that kind was
    /// given to say -- or that it could not look, and then it is the last
    /// entry. An answer from a kind the seam does not consult therefore has
    /// nowhere to enter it.
    #[kani::proof]
    #[kani::unwind(7)]
    fn the_list_is_a_function_of_the_consulted_answers() {
        let seam = any_seam();
        let given: [Given; 5] = kani::any();
        let mut ledger = Vec::new();
        let mut shadow = Shadow::new();
        let run = over_kinds(seam, &mut ledger, |kind, ledger| {
            tagged(&given, kind, ledger, &mut shadow)
        });
        assert!(ledger.len() == shadow.len && shadow.len <= LONGEST);
        for at in 0..LONGEST {
            if at < shadow.len {
                let entry = shadow.codes[at];
                let slot = usize::from(entry >> 2);
                assert!(seam.consults(EVERY_JUDGED[slot]));
                if entry & 3 == UNKNOWN {
                    assert!(given[slot].could_not_look);
                } else {
                    assert!(given[slot].code() == Some(entry & 3));
                }
            }
        }
        if run.is_err() {
            assert!(shadow.len > 0 && shadow.codes[shadow.len - 1] & 3 == UNKNOWN);
        }
    }

    #[expect(
        dead_code,
        reason = "reached through `kani::stub`, which rustc does not count as a use"
    )]
    fn a_policy_that_does_not_load(_root: &Path, _policy_path: &Path) -> Result<Policy> {
        Err(Fatal::new(String::new()))
    }

    /// A policy that exists and does not load is exit 2. `config::load` is replaced by one that always fails, since
    /// parsing TOML is not what is being proven; `load_for` and the exit it
    /// settles into are the real ones.
    #[kani::proof]
    #[kani::stub(crate::config::load, a_policy_that_does_not_load)]
    #[kani::unwind(3)]
    fn a_declared_policy_that_does_not_load_is_broken() {
        let found = (PathBuf::from("r"), PathBuf::from("p"));
        // Forgotten rather than dropped: the drop glue of a whole `Policy` is
        // most of what the checker would otherwise unwind, on an arm the stub
        // never takes.
        let run = load_for(Some(&found)).map(|(_, policy)| {
            core::mem::forget(policy);
            Exit::Clean
        });
        assert!(Exit::of(&run) as i32 == Exit::Broken as i32);
    }
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

    /// Three text guards and one that judges no text, with a consultation
    /// standing in front of a command.
    const ANSWERING: &str = "\
[rule.consult]
builtin = \"text-guards\"
command.before = [\"faux\"]

[rule.no-merge-commit]
builtin = \"no-merge-commit\"
git.hooks = [\"pre-commit\"]

[rule.prevent-ai-author]
builtin = \"prevent-ai-author\"
git.hooks = [\"commit-msg\"]

[rule.prevent-unusual-unicode]
builtin = \"prevent-unusual-unicode\"
git.hooks = [\"commit-msg\"]

[[shim]]
command = \"faux\"
match = [\"pr:create\"]
text_flags = [\"-b\"]
scope = \"always\"
";

    fn answering() -> Policy {
        config::load_text(
            std::path::Path::new("."),
            std::path::Path::new("ANSWERING"),
            ANSWERING,
        )
        .unwrap()
    }

    fn published(text: &str) -> crate::guard::Published<'_> {
        crate::guard::Published {
            label: "body.md",
            kind: "text",
            text,
            added: None,
            headline: false,
        }
    }

    fn answer_of(ledger: &[Judgment], id: &str) -> Vec<Outcome> {
        ledger
            .iter()
            .filter(|judgment| judgment.id == id)
            .map(Answered::outcome)
            .collect()
    }

    /// Every text guard asked answers, one of them out of scope; a built-in
    /// that judges no text is not asked and so is not in the list; and the
    /// exit is read off the same list.
    #[test]
    fn each_text_guard_answers_and_a_guard_out_of_scope_says_so() {
        let policy = answering();
        let mut ledger = Vec::new();
        crate::guard::over_text(
            std::path::Path::new("."),
            &policy,
            None,
            &published("Generated with Claude Code"),
            &mut |rule| Ok(rule.id != "prevent-unusual-unicode"),
            &mut ledger,
        )
        .unwrap();
        assert_eq!(answer_of(&ledger, "prevent-ai-author"), [Outcome::Refuse]);
        assert_eq!(
            answer_of(&ledger, "prevent-unusual-unicode"),
            [Outcome::OutOfScope]
        );
        assert_eq!(answer_of(&ledger, "no-merge-commit"), Vec::new());
        assert_eq!(answer_of(&ledger, "consult"), Vec::new());
        assert_eq!(refusals(&ledger), 1);
        assert!(
            ledger
                .iter()
                .all(|judgment| judgment.subject.as_deref() == Some("text"))
        );
    }

    /// A rule whose scope could not be told is `Unknown`, last, and the
    /// error goes up: the record ends where the run did.
    #[test]
    fn a_scope_that_could_not_be_told_is_the_last_answer() {
        let policy = answering();
        let mut ledger = Vec::new();
        let run = crate::guard::over_text(
            std::path::Path::new("."),
            &policy,
            None,
            &published("plain"),
            &mut |rule| {
                if rule.id == "prevent-ai-author" {
                    Err(Fatal::new("no destination"))
                } else {
                    Ok(true)
                }
            },
            &mut ledger,
        );
        assert!(run.is_err());
        let last = ledger.last().unwrap();
        assert_eq!(last.id, "prevent-ai-author");
        assert_eq!(last.outcome(), Outcome::Unknown);
    }

    /// A consultation answers through the rules it ran, each under its own
    /// id, and the report the caller prints for it is folded from those.
    #[test]
    fn a_consultation_answers_through_its_rules_and_is_reported_as_one() {
        let policy = answering();
        let consult = policy
            .rules
            .iter()
            .find(|rule| rule.id == "consult")
            .unwrap();
        let mut ledger = Vec::new();
        crate::guard::text_refusal(
            std::path::Path::new("."),
            &policy,
            consult,
            None,
            &published("Generated with Claude Code"),
            &mut |_| Ok(true),
            &mut ledger,
        )
        .unwrap();
        assert_eq!(answer_of(&ledger, "consult"), Vec::new());
        assert_eq!(answer_of(&ledger, "prevent-ai-author"), [Outcome::Refuse]);
        assert_eq!(
            answer_of(&ledger, "prevent-unusual-unicode"),
            [Outcome::Pass]
        );
        let told = crate::guard::told(&policy, consult, &ledger).unwrap();
        assert_eq!(told.id, "consult");
        assert!(told.report.starts_with("prevent-ai-author: "), "{told:?}");
    }

    /// A guard asked about a body and again about a headline is one finding
    /// in the report, where its first one was, between the findings of the
    /// kinds around it.
    #[test]
    fn a_guard_refused_twice_is_reported_once_in_its_place() {
        let rule = |id: &str| Judgment {
            id: id.to_owned(),
            builtin: None,
            set: None,
            subject: None,
            answer: Answer::Pass,
        };
        let refused = |id: &str, verdict: Verdict| Judgment {
            answer: Answer::Refused(verdict),
            ..rule(id)
        };
        let guard = |report: &str| {
            Verdict::Guard(crate::guard::Refusal {
                id: String::from("g"),
                report: report.to_owned(),
            })
        };
        let ledger = [
            refused("lit", Verdict::Rule(Failure::new("lit", "m", "b"))),
            refused("g", guard("in the body\n\nadvice\n")),
            rule("other"),
            refused("g", guard("in the title\n\nadvice\n")),
            refused("prose", Verdict::Rule(Failure::new("prose", "m", "b"))),
        ];
        let found = verdicts(&ledger);
        let names: Vec<&str> = found
            .iter()
            .map(|verdict| match verdict {
                Verdict::Rule(failure) => failure.label.as_str(),
                Verdict::Guard(refusal) => refusal.id.as_str(),
            })
            .collect();
        assert_eq!(names, ["lit", "g", "prose"]);
        assert_eq!(refusals(&ledger), 4);
    }
}
