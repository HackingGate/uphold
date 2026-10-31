//! `uphold guard` -- guards over what git is about to do.
//!
//! A content rule reads the tree and could run at any moment. A guard reads an
//! ACT: the message about to be recorded, the identity about to be stamped on
//! it, the range about to be pushed. It only means anything at the moment that
//! act is about to happen, which is why these are separate hook stages rather
//! than separate tools.
//!
//! All eleven ids from git-guards survive unchanged. What changed is where
//! their configuration lives: there was no configuration file, so allow-lists,
//! visibility pins and owner pins were all environment. They are rule fields
//! now, and the per-owner env-prefix scheme is gone -- it existed only because
//! configuration was environment-only while one machine holds several
//! workspaces, and a per-workspace file IS the workspace scope.

pub(crate) mod actor;
pub(crate) mod citations;
pub(crate) mod identity;
pub(crate) mod merge;
pub(crate) mod message;
pub(crate) mod names;
pub(crate) mod push;
pub(crate) mod ruling;
pub(crate) mod scope;
pub(crate) mod sets;
pub(crate) mod unicode;
pub(crate) mod visibility;

use std::collections::BTreeMap;
use std::path::Path;

use crate::config::{CheckKind, Policy, Rule};
use crate::error::{Exit, Fatal, Result};
use crate::junit::Outcome;
use crate::text::{Answer, Judgment, Verdict, asked};

/// Every built-in check this binary carries, and the only list of them.
///
/// These are the checks no regex expresses: a remote's owner against an
/// allow-list, `git ls-remote` output against a pin, Unicode Script properties,
/// a forge's answer about a name. A rule reaches one by name --
/// `builtin = "prevent-public-push"` -- and an unknown name is refused at load
/// rather than silently running nothing.
///
/// The names are the ids the eleven git-guards scripts had, deliberately: they
/// already say what they do, and renaming them would have made every existing
/// declaration wrong for no reader's benefit.
pub(crate) const EVERY_BUILTIN: &[&str] = &[
    "prevent-ai-author",
    "prevent-author-mismatch",
    "prevent-unusual-unicode",
    "prevent-unusual-unicode-in-files",
    // The typographic half `prevent-unusual-unicode` used to carry, under its
    // own name and in no bundled set: a house style for subject lines, opt in.
    // Not a text guard -- its subject is a commit's subject line, which only a
    // git hook has, and run over a pull-request body by `text-guards` it would
    // be holding the first line of prose to a rule written about commits.
    "ascii-only-commit-subject",
    "no-private-repo-names",
    "no-private-repo-names-staged",
    "no-private-repo-names-in-files",
    "prevent-public-push",
    // The same question as `prevent-public-push`, asked at the other seam and
    // answered by the same predicate. A push is not the only way text leaves
    // this workspace: `gh issue create --repo other-owner/their-repo` publishes
    // through a forge API, past every git hook, and until this existed the shim
    // asked whether the TEXT was safe and never whether the DESTINATION was
    // ours. It is dispatched from `target_refusal` rather than `evaluate`,
    // because a git hook is handed no destination to judge.
    "prevent-unowned-target",
    // The third question the command seam asks, beside what an invocation
    // says and where it goes: whose credential it runs under. Dispatched from
    // `actor_refusal`, once per invocation, because the identity is a property
    // of the invocation and not of any subject it carries -- and never at a git
    // hook, where no `gh` write is about to happen.
    "prevent-actor-mismatch",
    "no-local-merge",
    "no-merge-commit",
    "no-stale-hook-pins",
    // The only other built-in that reaches a network, and the only one whose
    // subject is a claim the POLICY makes about the repository rather than
    // about a file in it. It refuses one direction -- declared private, served
    // public -- because that is the only direction a probe can establish.
    "no-stale-visibility",
    // Reads the POLICY rather than the tree or what git is about to do: the
    // only check here whose subject is the repository's own declarations. See
    // `sets` for why that is a check at all.
    "no-hand-copied-base-rule",
    // Reads the tree rather than what git is about to do, so it never runs at a
    // hook -- but it is a check compiled in here with no regex that expresses
    // it, which is exactly what `builtin` names. It was `kind = "link"`.
    "links-resolve",
    // The same shape one step further in: `links-resolve` resolves a path a
    // reader would CLICK, this resolves a VALUE a reader would believe. Also
    // scan-dispatched, and also expressible by no regex -- the comparison is
    // against a parsed YAML/TOML/JSON document, which is by definition a check
    // a content search cannot make.
    "anchors-resolve",
    // The third resolver, for the last of the three things a document asserts
    // about a tree: `links-resolve` a path a reader would CLICK,
    // `anchors-resolve` a value a reader would BELIEVE, this a command a reader
    // would RUN. Scan-dispatched like both, and the comparison is against a
    // parsed dispatch, which no content search reaches.
    "commands-resolve",
    // The two consultations a fleet had been reaching by `exec`-ing this
    // binary from PATH: every text-capable guard the policy declares, and
    // every literal rule plus the running-host fallback. In-process rather
    // than a shipped shell line, because a bundled set that ships a shell
    // command runs that command in every inheriting repository on the strength
    // of a version bump -- the exact objection `private-names` records against
    // `private_owners_from` -- and because the subprocess answered with
    // whatever `uphold` PATH happened to reach, which is not necessarily the
    // binary that asked. They judge text and nothing else, so `command.before`
    // is the only place they run; `text-guards` runs the OTHER text guards and
    // never itself, which is what keeps the dispatch finite.
    "text-guards",
    "text-literals",
    // Text a design ruling publishes, judged against the catalog this binary
    // carries: every catalog line an `Answered:` line cites must be at the
    // revision the repository pins and must say what the answer quotes.
    "ruling-citations-resolve",
    // Text citing a numbered standard or an identifier, judged against a
    // table of families compiled in: each citation must link to the document
    // it names, and to the section where the family's anchors allow.
    "citations-linked",
    // The one built-in that reads no artifact itself. It is handed the
    // evidence every compiled-in provider reported about the change and
    // judges that -- so which parser or which diff supplied a fact is not its
    // business, and `tests/structural_evidence.rs` refuses the policy file
    // naming one. See `evidence` for the shape and docs/DESIGN.md for why a
    // policy reads evidence rather than naming its provider.
    "removed-function-named",
];

/// The built-ins `uphold scan` dispatches, rather than `guard`.
///
/// Their subject is the tree, so they run over a SELECTION the way a content
/// rule does -- which is what makes them the built-ins that read the shared
/// `files.*` vocabulary in full, `files.min_selected` included. Every other
/// built-in carrying a `[rule.files]` table is using it as a scope for one path
/// at a time (`scope::in_file_scope`), and a scope test never takes a count.
pub(crate) const SCAN_BUILTINS: &[&str] = &["links-resolve", "anchors-resolve", "commands-resolve"];

/// The moment a guard is being asked about.
///
/// Not a formality: the same guard reads a different artifact at each of these,
/// and the whole point of naming the stage is that it decides WHICH. At
/// pre-merge-commit it is the index; at pre-push it is the commit being pushed
/// together with every blob the pushed range introduces, because a file added
/// in one pushed commit and deleted in the next is on the remote permanently
/// and is in no tip tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    CommitMsg,
    PreCommit,
    PreMergeCommit,
    PrePush,
    Manual,
}

impl Stage {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "commit-msg" => Self::CommitMsg,
            "pre-commit" => Self::PreCommit,
            "pre-merge-commit" => Self::PreMergeCommit,
            "pre-push" => Self::PrePush,
            "manual" => Self::Manual,
            other => {
                return Err(Fatal::new(format!(
                    "unknown stage {other:?}; expected one of commit-msg, pre-commit, \
                     pre-merge-commit, pre-push, manual"
                )));
            }
        })
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CommitMsg => "commit-msg",
            Self::PreCommit => "pre-commit",
            Self::PreMergeCommit => "pre-merge-commit",
            Self::PrePush => "pre-push",
            Self::Manual => "manual",
        }
    }
}

/// What a guard was asked, and what it may read.
pub(crate) struct Request<'a> {
    pub root: &'a Path,
    pub rule: &'a Rule,
    /// The whole loaded policy, for the one guard whose subject IS the policy.
    /// Every other guard reads `rule` and the repository; `no-hand-copied-base-rule`
    /// asks what else this repository declared and what it inherited, and there
    /// is nowhere else to read that from.
    pub policy: &'a Policy,
    pub stage: Stage,
    /// The commit-message file, for the guards that read one.
    pub message_file: Option<&'a Path>,
    /// `<local-ref> <local-sha> <remote-ref> <remote-sha>` lines, as git feeds
    /// a pre-push hook on stdin -- or as `runner` rebuilt them from what a
    /// runner exported instead.
    pub push_refs: &'a str,
    /// Which channel supplied them, so that "this push introduces nothing" and
    /// "nobody told me what this push is" stay two different answers.
    pub push_source: crate::runner::Source,
    pub remote_name: Option<&'a str>,
    pub remote_url: Option<&'a str>,
}

/// What a guard concluded. A refusal carries the whole report, because a guard
/// that says only "refused" makes the reader go and find out what it saw.
#[derive(Debug, Clone)]
pub(crate) struct Refusal {
    pub id: String,
    pub report: String,
}

/// One uniform bypass, replacing five differently-named variables.
///
/// `GIT_GUARDS_ALLOW_PRIVATE_NAMES`, `GIT_GUARDS_ALLOW_STALE_PINS`,
/// `GIT_GUARDS_ALLOW_UNCHECKED_PINS`, `WORKSPACE_ALLOW_UNSAFE_PUSH` and
/// `<OWNER>_ALLOW_UNSAFE_PUSH` were five spellings of one idea, each learned
/// separately and each grep-able only if you already knew its name.
/// `UPHOLD_ALLOW=<id>,<id>` names the guard being bypassed, so what was
/// switched off is legible in a shell history and in CI logs.
///
/// It stays in the ENVIRONMENT and does not become a rule field, deliberately.
/// A bypass belongs to one invocation by whoever is standing there; written
/// into the policy file it would be committed, reviewed once, and permanent --
/// which is not a bypass, it is a rule that no longer applies.
pub(crate) fn bypassed(id: &str) -> bool {
    allowed(id).is_some()
}

/// What in `UPHOLD_ALLOW` switched a rule off.
///
/// The bypass is the same either way. What differs is what a reader of the
/// record may make of it: an id was a decision about this rule, and `all` was a
/// decision about the run that this rule fell under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Allowed {
    /// The rule's own id was in the list.
    Named,
    /// `all` was in the list.
    All,
}

/// Which entry of `UPHOLD_ALLOW` bypasses `id`, if any.
///
/// The id wins over `all` when both are listed, because it is the narrower
/// statement and the one that names this rule.
pub(crate) fn allowed(id: &str) -> Option<Allowed> {
    let value = std::env::var("UPHOLD_ALLOW").ok()?;
    let entries = || value.split(',').map(str::trim);
    if entries().any(|entry| entry == id) {
        Some(Allowed::Named)
    } else if entries().any(|entry| entry == "all") {
        Some(Allowed::All)
    } else {
        None
    }
}

/// Is EVERY rule bypassed for this invocation?
///
/// `UPHOLD_ALLOW=all` already means "run this unchecked": with a policy that
/// loads, every rule reports itself bypassed and the command runs. This is the
/// same question asked before the policy is read, and it exists because of the
/// one state where the two answers differed -- a policy file that cannot be
/// parsed.
///
/// There, the shim refused every invocation of the command it stands in front
/// of, including the `git checkout` that would put the file back. The refusal
/// was right and the trap was real: the tool that stops you publishing an
/// unchecked change also stopped you repairing the declaration that says what
/// checking means, and the only ways out were to know the real binary's path or
/// to take the link off PATH.
pub(crate) fn bypassed_entirely() -> bool {
    // Spelled out rather than `bypassed("")`, which would answer yes to an
    // EMPTY `UPHOLD_ALLOW=`: the empty string splits to one empty field, and a
    // variable somebody exported and then blanked would switch the whole seam
    // off while reading as though it had been cleared.
    std::env::var("UPHOLD_ALLOW").is_ok_and(|value| {
        value
            .split(',')
            .map(str::trim)
            .any(|allowed| allowed == "all")
    })
}

/// The guards that can judge arbitrary text.
///
/// Not all of them can. A guard that reads the index, an identity, or a push
/// range has nothing to say about a pull-request body; handing it one and
/// reporting a pass would be a check that did not happen. These judge text and
/// nothing else, which is exactly what a shim has to hand them. The last two
/// are consultations rather than single checks -- see [`META_TEXT_GUARDS`].
pub(crate) const TEXT_GUARDS: &[&str] = &[
    "prevent-ai-author",
    "prevent-unusual-unicode",
    "no-private-repo-names",
    "ruling-citations-resolve",
    "citations-linked",
    "text-guards",
    "text-literals",
];

/// The two text guards that run OTHER rules rather than one check of their own.
///
/// `over_text` must skip them: it is the loop `text-guards` dispatches to, and
/// a meta rule reachable from its own dispatch is not a stack overflow risk to
/// hold, it is one to make unrepresentable. Skipping them there also keeps
/// `uphold guard --text` honest -- that command already runs every text guard,
/// and a meta rule re-running them would report each refusal twice.
pub(crate) const META_TEXT_GUARDS: &[&str] = &["text-guards", "text-literals"];

/// The guards that judge a DESTINATION rather than a piece of text.
///
/// A parallel list to [`TEXT_GUARDS`], and parallel for a reason: what a shim
/// hands a checker is a subject and a destination, and those are two different
/// things to be asked about. A text guard reads what is about to be published;
/// one of these reads WHERE. Neither can answer the other's question, so a
/// guard in this list is never handed a subject and a guard in that one is
/// never handed a target.
///
/// The destination is a property of the INVOCATION and not of any subject it
/// carries, which is why these are consulted once per run rather than once per
/// subject -- and why they are consulted even where the invocation collected no
/// subject at all. `--repo other-owner/their-repo` with an empty body still
/// publishes to somewhere.
pub(crate) const TARGET_GUARDS: &[&str] = &["prevent-unowned-target"];

/// The guards that judge a `gh` INVOCATION itself rather than a subject it
/// carries or a destination: whose credential it runs under.
///
/// A third list rather than more entries in [`TARGET_GUARDS`], because the
/// question needs different inputs and fails differently: a destination guard
/// is handed a repository and refuses where it has none, while this one reads
/// the credential in the environment and the host, and has no use for a
/// repository -- `gh api graphql` names none and is a write. Consulted once per
/// run, like a destination guard, and for the same reason: the identity is a
/// property of the invocation, not of any one subject it carries.
pub(crate) const INVOCATION_GUARDS: &[&str] = &["prevent-actor-mismatch"];

/// One destination-judging guard's verdict over one invocation's destination.
///
/// The command-seam twin of [`text_refusal`], and it exists for the same
/// reason: so the shim reaches the same rule body a hook does. `prevent-public-push`
/// at `pre-push` and `prevent-unowned-target` at a `[[shim]]` are one decision
/// -- is this destination one this workspace owns -- and [`push::unowned`] is
/// the single place it is made.
///
/// The answer goes into `ledger`, as [`text_refusal`]'s does: nothing where
/// the rule judges no destination, a bypass, a pass, a refusal, or -- where the
/// rule is in scope and there was no destination to look at -- an `Unknown`
/// and an `Err`, which is the third answer and never a pass. No subject is
/// recorded: what this reads is where the text goes, and the record never
/// says where that is.
///
/// `forge` is which forge the invocation publishes to, as the shim already
/// knows it from the command's own name, and `asked` is the memo for the
/// question that reaches it -- both passed straight through to [`push::unowned`],
/// which decides whether either is consulted.
#[expect(
    clippy::too_many_arguments,
    reason = "the destination guard's own inputs and the list it answers into, from the one caller"
)]
pub(crate) fn target_refusal(
    root: &Path,
    policy: &Policy,
    rule: &Rule,
    target: Option<&str>,
    forge: Option<crate::shim::Forge>,
    hostname: Option<&str>,
    memo: &mut BTreeMap<String, push::Owned>,
    ledger: &mut Vec<Judgment>,
) -> Result<()> {
    let Some(builtin) = rule.builtin() else {
        return Ok(());
    };
    if !TARGET_GUARDS.contains(&builtin) {
        return Ok(());
    }
    if let Some(allowed) = allowed(&rule.id) {
        ledger.push(Judgment::of(rule, None, Answer::Bypass(allowed)));
        return Ok(());
    }
    let found = asked(
        ledger,
        rule,
        None,
        unowned_target(root, policy, rule, builtin, target, forge, hostname, memo),
    )?;
    ledger.push(Judgment::of(
        rule,
        None,
        found.map_or(Answer::Pass, |refusal| {
            Answer::Refused(Verdict::Guard(refusal))
        }),
    ));
    Ok(())
}

/// One invocation guard's verdict over one `gh` invocation, into `ledger`.
///
/// The twin of [`target_refusal`] for [`INVOCATION_GUARDS`]: nothing where the
/// rule is not one of them, and otherwise a bypass, a pass, a refusal, or an
/// `Unknown` and an `Err` where it could not look. The environment and the
/// forge are the process's own, read here and nowhere else, so
/// [`actor::judge`] is a function of what it is handed and every branch of it
/// is reached without a network.
pub(crate) fn invocation_refusal(
    rule: &Rule,
    attempt: &actor::Attempt<'_>,
    ledger: &mut Vec<Judgment>,
) -> Result<()> {
    let Some(builtin) = rule.builtin() else {
        return Ok(());
    };
    if !INVOCATION_GUARDS.contains(&builtin) {
        return Ok(());
    }
    if let Some(allowed) = allowed(&rule.id) {
        ledger.push(Judgment::of(rule, None, Answer::Bypass(allowed)));
        return Ok(());
    }
    let read = |name: &str| std::env::var(name).ok();
    let judged = match builtin {
        "prevent-actor-mismatch" => actor::judge(rule, attempt, &read, &mut actor::viewer_login),
        other => Err(Fatal::new(format!("no invocation guard called {other:?}"))),
    };
    let found = asked(ledger, rule, None, judged)?;
    ledger.push(Judgment::of(
        rule,
        None,
        found.map_or(Answer::Pass, |refusal| {
            Answer::Refused(Verdict::Guard(refusal))
        }),
    ));
    Ok(())
}

/// The body of [`target_refusal`] once the rule is known to judge a
/// destination and to be switched on.
#[expect(
    clippy::too_many_arguments,
    reason = "the destination guard's own inputs, passed straight through from the one caller"
)]
fn unowned_target(
    root: &Path,
    policy: &Policy,
    rule: &Rule,
    builtin: &str,
    target: Option<&str>,
    forge: Option<crate::shim::Forge>,
    hostname: Option<&str>,
    asked: &mut BTreeMap<String, push::Owned>,
) -> Result<Option<Refusal>> {
    // In scope, and nothing to judge. Exit 2 rather than a pass, and rather
    // than a refusal: nothing was found to be wrong, the subject could not be
    // looked at -- `explicit-unknown`, the same reading the editor pass and the
    // non-UTF-8 argv take. Falling open here would be the whole gap back: an
    // invocation whose `--repo` this shim could not read is exactly the one
    // that most needs asking about.
    //
    // `git::owner_repo` is the one parser, so `--repo owner/name`, a full forge
    // url and the remote all become the same pair. A value it cannot split is
    // not a destination this guard can judge.
    if let Some(named) = target
        && crate::shim::repository_placeholder("gh", named)?
    {
        return Err(Fatal::new(format!(
            "rule {:?}: this API destination contains repository placeholders whose effective \
             identity could not be established for ownership checks. Nothing was published; \
             name the destination repository directly in the API endpoint",
            rule.id
        )));
    }
    let Some((owner, repo)) = target.and_then(crate::git::owner_repo) else {
        return Err(Fatal::new(format!(
            "rule {:?}: this invocation publishes to a repository and nothing here says \
             which one -- no `--repo`/`-R` on the command line, and no remote to read one \
             off. Whether a destination belongs to this workspace cannot be answered \
             without knowing the destination, and a check that could not look is not a \
             check that passed. Nothing was published; name the destination explicitly, \
             or run this where the repository has a remote",
            rule.id
        )));
    };
    Ok(match builtin {
        "prevent-unowned-target" => push::unowned(
            root,
            policy,
            rule,
            (&owner, &repo, hostname),
            forge,
            asked,
            push::Seam::Command,
        )?,
        _ => None,
    })
}

/// How a consultation asks whether one inner rule's own scope holds here.
///
/// A predicate rather than a scope, because only the caller standing in front
/// of a command knows the destination: the seams that have none -- `scan
/// --text`, `guard --text`, the harness hook -- hand over a predicate that
/// always holds, and the shim hands over its memo.
///
/// `Err` is the third answer and not a hidden `false`: a scope that could not
/// be told is exit 2 for a rule the shim names directly, and a rule reached
/// through a consultation is judged the same way. What the shim answers for a
/// rule its `command.before` does NOT name is `true`: no scope was ever
/// written about that rule here, and reading the table's at it would stand
/// down a guard nobody scoped.
pub(crate) type ScopeAsk<'a> = &'a mut dyn FnMut(&Rule) -> Result<bool>;

/// One piece of published text, as a text guard is handed it.
///
/// `label` is what the report calls it -- the shim's subject kind, the tool
/// name at the hook, the source at `--text`. `kind` is what a record calls it,
/// which is the same but at `--text`, where the label is a file name and a
/// record carries no path. `headline` says the text is a
/// SUBJECT rather than prose: a title the shim collected, which a forge-side
/// squash merge makes a commit subject on the default branch with no local
/// hook in the way. It is set from the shim's subject kind and never read off
/// the label.
pub(crate) struct Published<'a> {
    pub label: &'a str,
    pub kind: &'a str,
    pub text: &'a str,
    /// The part of `text` an edit adds to a body the forge already stores,
    /// where the shim knows it. `prevent-unusual-unicode` reads this instead
    /// of `text`; every other guard reads the whole.
    pub added: Option<&'a str>,
    pub headline: bool,
}

/// Run every text-capable guard over one piece of text.
///
/// `in_scope` is asked about each inner rule, because a rule reached through a
/// consultation is judged under its own effective scope -- exactly as when the
/// shim reaches it directly. An outer rule scoped `always` says when the
/// CONSULTATION applies, and one answer cannot stand for every rule behind it:
/// a `public-target` rule dragged along to a private destination leaves a
/// workspace nothing to switch off but the consultation, and with it the
/// checks it was there for.
///
/// `destination` is the repository the text is published to, where the caller
/// resolved one -- passed through to [`text_refusal`].
///
/// Each text guard's answer goes into `ledger`, and a guard whose own scope
/// did not hold goes in as out of scope rather than being left out: it was
/// seen and set aside, and a reader of the record asking whether it ran on
/// this body is owed that answer. A built-in that judges no text is not asked
/// and not recorded; neither are the consultations, which this is the loop of.
pub(crate) fn over_text(
    root: &Path,
    policy: &Policy,
    destination: Option<&str>,
    published: &Published<'_>,
    in_scope: ScopeAsk<'_>,
    ledger: &mut Vec<Judgment>,
) -> Result<()> {
    for rule in policy.of_check(CheckKind::Builtin) {
        if rule.builtin().is_none_or(|builtin| {
            META_TEXT_GUARDS.contains(&builtin) || !TEXT_GUARDS.contains(&builtin)
        }) {
            continue;
        }
        if !asked(ledger, rule, Some(published.kind), in_scope(rule))? {
            ledger.push(Judgment::of(rule, Some(published.kind), Answer::OutOfScope));
            continue;
        }
        text_refusal(root, policy, rule, destination, published, in_scope, ledger)?;
    }
    Ok(())
}

/// One text-capable guard's verdict over one piece of text, into `ledger`.
///
/// Nothing where the rule is not a text guard, since it was not asked. A
/// bypass, a pass or a refusal under the rule's own id where it is one, and
/// an `Unknown` before the error where it could not look -- the three reasons
/// a caller used to receive as one `None`, told apart because a record of
/// what ran cannot be written without them. Extracted so the shim seam
/// consults exactly the same dispatch `uphold guard --text` does: a text guard
/// that judged a commit message one way and a PR body another would be two
/// rules under one id.
///
/// A consultation records the rules it ran, each under its own id, and
/// nothing under its own: it is dispatch rather than judgment, and an entry
/// for both would count one refusal twice. It is recorded under its own id
/// only where it did not run -- bypassed -- since then there is nothing else
/// to say so. What the caller reports for it is [`told`].
///
/// `destination` is the repository the text is published to, where the caller
/// resolved one. Only the shim has one; every other seam passes `None` and is
/// judged against `origin`, which is where its text is going.
pub(crate) fn text_refusal(
    root: &Path,
    policy: &Policy,
    rule: &Rule,
    destination: Option<&str>,
    published: &Published<'_>,
    in_scope: ScopeAsk<'_>,
    ledger: &mut Vec<Judgment>,
) -> Result<()> {
    let &Published {
        label,
        kind,
        text,
        added,
        headline,
    } = published;
    let Some(builtin) = rule.builtin() else {
        return Ok(());
    };
    if !TEXT_GUARDS.contains(&builtin) {
        return Ok(());
    }
    if let Some(allowed) = allowed(&rule.id) {
        ledger.push(Judgment::of(rule, Some(kind), Answer::Bypass(allowed)));
        return Ok(());
    }
    let mut single = |found: Result<Option<Refusal>>| -> Result<()> {
        let found = asked(ledger, rule, Some(kind), found)?;
        ledger.push(Judgment::of(
            rule,
            Some(kind),
            found.map_or(Answer::Pass, |refusal| {
                Answer::Refused(Verdict::Guard(refusal))
            }),
        ));
        Ok(())
    };
    match builtin {
        "prevent-ai-author" => single(Ok(message::ai_author_in(rule, label, text))),
        // The one guard whose question is what this invocation types: an
        // edit that resubmits a stored body is judged on the lines it adds,
        // so a character typed into the body long ago does not hold every
        // later edit hostage.
        "prevent-unusual-unicode" => single(message::unusual_unicode_in(
            rule,
            label,
            added.unwrap_or(text),
            headline,
        )),
        "no-private-repo-names" => {
            single(names::in_text(root, policy, rule, destination, label, text))
        }
        "ruling-citations-resolve" => single(ruling::in_text(root, rule, label, text)),
        "citations-linked" => single(Ok(citations::in_text(rule, label, text))),
        // The consultations. `over_text` skips the meta guards, so the
        // recursion is one level deep by construction.
        "text-guards" => over_text(root, policy, destination, published, in_scope, ledger),
        // No scope question fans out here. The literal rules are not a kind the
        // shim ever dispatches directly -- `Seam::Command` does not consult
        // `Judged::Literals`, it reaches them only through this built-in -- so
        // an inner literal rule has no "scope it would have been judged under
        // directly" to keep, and the running-host fallback this assembles is
        // not a policy rule at all. Gating them on the table's scope would only
        // stand the identity check down for private destinations, which is the
        // arrangement `command.scope = "always"` on this rule exists to undo.
        "text-literals" => crate::text::failures_in(root, policy, text, Some(kind), ledger),
        _ => Ok(()),
    }
}

/// What a caller reports for `rule`, read off the entries one call to
/// [`text_refusal`] or [`target_refusal`] put in the list.
///
/// A single check's report is its own refusal. A consultation's is one
/// refusal under its own id carrying every inner one, naming each inner rule,
/// so the reader is told which check refused and not only that the
/// consultation did -- and one rather than many, because the caller
/// attributes what it gets back to the rule it asked about.
pub(crate) fn told(policy: &Policy, rule: &Rule, answered: &[Judgment]) -> Option<Refusal> {
    let mut refused = answered.iter().filter_map(Judgment::refused);
    if rule
        .builtin()
        .is_some_and(|builtin| META_TEXT_GUARDS.contains(&builtin))
    {
        return fold(
            rule,
            refused.map(|verdict| match verdict {
                Verdict::Guard(refusal) => {
                    format!("{}: {}", refused_by(policy, refusal), refusal.report)
                }
                Verdict::Rule(failure) => {
                    format!("{}: {}\n{}", failure.label, failure.message, failure.body)
                }
            }),
        );
    }
    refused.next().map(|verdict| match verdict {
        Verdict::Guard(refusal) => refusal.clone(),
        Verdict::Rule(failure) => Refusal {
            id: failure.label.clone(),
            report: failure.report(),
        },
    })
}

/// What a consultation answers with: one refusal carrying every inner one.
/// `None` for none, exactly as a single check answers.
fn fold(rule: &Rule, reports: impl Iterator<Item = String>) -> Option<Refusal> {
    let joined = reports.collect::<Vec<String>>().join("\n");
    if joined.is_empty() {
        return None;
    }
    Some(Refusal {
        id: rule.id.clone(),
        report: joined,
    })
}

/// What a refusal is named by, and where the rule behind it came from.
///
/// A guard arriving from a set is a guard whose declaration is in NO file in
/// the repository it just refused: `sets = ["unreviewed-history"]` is the whole
/// of it, and a reader who greps their policy for the id that refused them
/// finds nothing. That is astonishment the moment a set carries a guard, and
/// naming the set is the cheapest possible answer to it -- `uphold rules --set
/// <name>` is then one command away from the declaration itself.
pub(crate) fn refused_by(policy: &Policy, refusal: &Refusal) -> String {
    policy.set_of(&refusal.id).map_or_else(
        || refusal.id.clone(),
        |set| format!("{} [set: {set}]", refusal.id),
    )
}

/// Run one guard.
pub(crate) fn evaluate(request: &Request<'_>) -> Result<Option<Refusal>> {
    let id = request.rule.id.as_str();
    if bypassed(id) {
        eprintln!("uphold guard: {id} bypassed by UPHOLD_ALLOW");
        return Ok(None);
    }
    // Dispatch on the BUILT-IN name, not on the rule's id. They are usually the
    // same string and they do not have to be: a repository
    // can call a rule whatever its declaration calls it and still reach the
    // check it means, which is what stops `id` from being two things at once.
    // Not `Ok(None)`. A rule reaching here without a built-in ran nothing, and
    // saying "no violation" made it indistinguishable from a check that looked
    // and found nothing -- it was then counted inside "N guard(s) passed".
    // `Rule::validate` refuses this at load, so this arm is unreachable through
    // a config file; it stays because the two would otherwise have to be kept
    // in step by memory.
    let Some(builtin) = request.rule.builtin() else {
        return Err(Fatal::new(format!(
            "rule {id:?}: declares a git hook but no `builtin`, so there is nothing \
             for this stage to run"
        )));
    };
    match builtin {
        "prevent-ai-author" => message::prevent_ai_author(request),
        "prevent-unusual-unicode" => message::prevent_unusual_unicode(request),
        "ascii-only-commit-subject" => message::ascii_only_commit_subject(request),
        "prevent-author-mismatch" => identity::prevent_author_mismatch(request),
        "no-merge-commit" => merge::no_merge_commit(request),
        "no-local-merge" => merge::no_local_merge(request),
        "prevent-unusual-unicode-in-files" => unicode::in_files(request),
        "no-private-repo-names" => names::in_message(request),
        "no-private-repo-names-staged" => names::in_staged(request),
        "no-private-repo-names-in-files" => names::in_tracked(request),
        "prevent-public-push" => push::prevent_public_push(request),
        "no-stale-hook-pins" => crate::pins::stale(request),
        "no-stale-visibility" => visibility::no_stale_visibility(request),
        "no-hand-copied-base-rule" => sets::no_hand_copied_base_rule(request),
        "removed-function-named" => {
            // `git merge` runs `commit-msg` with the merged tree in the index,
            // so the providers would report every function the other branch
            // removed and the guard would demand each be named in the merge
            // message. Those removals are recorded in the merged commits, and
            // each of those met this guard or was waived at its own
            // `commit-msg`; the merge commit removes nothing of its own. A
            // squash leaves no `MERGE_HEAD` and makes a plain commit, so its
            // removals are judged here like any other's.
            if merge::in_progress(request.root)? {
                return Ok(None);
            }
            crate::policy::removed_function_named::judge(
                request.rule,
                &crate::evidence::observe(request)?,
            )
        }
        other => Err(Fatal::new(format!("no built-in called {other:?}"))),
    }
}

/// The parameters each built-in reads, and the only statement of it.
///
/// The parameter fields sit flat on the rule struct, so without this list
/// a `private_owners` beside `regexp` -- or beside the wrong built-in --
/// loaded, looked enforced, and was read by nothing. `Rule::validate` refuses
/// a written parameter that is not in the declaring built-in's row, the same
/// way it refuses a second check field and for the same reason.
pub(crate) fn parameters(builtin: &str) -> &'static [&'static str] {
    match builtin {
        // One row for two built-ins, because they are one decision reached from
        // two seams: the fields that say who this workspace is and where it may
        // publish mean the same thing whether a push or a `gh` invocation is
        // asking.
        "prevent-public-push" | "prevent-unowned-target" => {
            &["owner", "owner_required", "allowed_owners", "allowed_repos"]
        }
        "no-private-repo-names"
        | "no-private-repo-names-staged"
        | "no-private-repo-names-in-files" => &[
            "visibility",
            "visibility_required",
            "private_owners",
            "private_owners_from",
            "private_owners_file",
            "public_repos",
            "refuse_unknown",
            "foreign_hosts",
        ],
        // `visibility` and nothing else: the rule reads the declaration and
        // compares it to the forge, and every other field in the family is
        // about judging names in text, which this one never does.
        "no-stale-visibility" => &["visibility"],
        // The App's bot login, which is the whole declaration: without it the
        // rule has nothing to compare a credential with, and `validate`
        // refuses it.
        "prevent-actor-mismatch" => &["actor"],
        // One field, two readings. The file guard takes a path glob after the
        // codepoint and lets a fixture earn an invisible; the two message
        // guards take the codepoint alone and admit no invisible whatever is
        // listed -- see `message::allowances` for why the second reading is
        // the narrower one.
        "prevent-unusual-unicode"
        | "prevent-unusual-unicode-in-files"
        | "ascii-only-commit-subject" => &["allow"],
        _ => &[],
    }
}

/// Run every guard the policy declares that has something to say at `stage`.
pub(crate) fn run(root: &Path, policy: &Policy, request: RunRequest<'_>) -> Result<Exit> {
    let RunRequest {
        stage,
        message_file,
        push_refs,
        push_source,
        remote_name,
        remote_url,
        evidence,
    } = request;
    let stage_name = stage.as_str();
    // The sink was opened by the caller before this run decided anything; the
    // suite is built here and written on every way out below, the early one
    // included, so "ran, nothing declared" is a suite of zero tests and not
    // the same absence as "never ran".
    let mut suite = evidence.map(|sink| {
        crate::junit::Suite::new(sink, crate::junit::Run::Stage(stage_name.to_owned()))
    });
    // Every rule the CONFIG puts at this hook, and nothing else decides it.
    let at_hook: Vec<&Rule> = policy.at_hook(stage_name).collect();
    if policy.at_hook_any().next().is_none() {
        written(suite)?;
        println!("no rule declares a git hook");
        return Ok(Exit::Clean);
    }

    let mut refusals: Vec<Refusal> = Vec::new();
    let mut ran = 0usize;
    let mut bypassed_here = 0usize;
    for rule in at_hook {
        let case = crate::junit::Case {
            id: &rule.id,
            builtin: rule.builtin(),
            set: policy.set_of(&rule.id),
            subjects: &[],
        };
        let mut record = |outcome| {
            if let Some(suite) = suite.as_mut() {
                suite.record(case, outcome);
            }
        };
        // Counted where the work happens, not where the loop starts. A bypassed
        // rule did not run, and folding it into the same number reported a
        // deliberately disabled check as one that passed.
        if let Some(allowed) = allowed(rule.id.as_str()) {
            eprintln!("uphold guard: {} bypassed by UPHOLD_ALLOW", rule.id);
            record(Outcome::Bypass(allowed));
            bypassed_here += 1;
            continue;
        }
        ran += 1;
        let one = Request {
            root,
            rule,
            policy,
            stage,
            message_file,
            push_refs,
            push_source,
            remote_name,
            remote_url,
        };
        match evaluate(&one) {
            Ok(Some(refusal)) => {
                record(Outcome::Refuse);
                refusals.push(refusal);
            }
            Ok(None) => record(Outcome::Pass),
            // The rule could not look, and the run ends here with exit 2. Its
            // testcase is an error and the rules after it get none; the error
            // the reader acts on is still the rule's own, with the file's
            // appended if both failed.
            Err(error) => {
                record(Outcome::Unknown);
                return Err(match written(suite) {
                    Ok(()) => error,
                    Err(also) => Fatal::new(format!("{error}\n\n{also}")),
                });
            }
        }
    }
    written(suite)?;

    for refusal in &refusals {
        eprintln!("guard refused: {}", refused_by(policy, refusal));
        eprintln!("{}", refusal.report.trim_end());
        eprintln!();
    }
    if !refusals.is_empty() {
        eprintln!(
            "Override one of these once with UPHOLD_ALLOW={}",
            refusals
                .iter()
                .map(|refusal| refusal.id.as_str())
                .collect::<Vec<&str>>()
                .join(",")
        );
        return Ok(Exit::Violations);
    }

    if bypassed_here > 0 {
        println!("{ran} guard(s) passed at {stage_name}, {bypassed_here} bypassed by UPHOLD_ALLOW");
    } else {
        println!("{ran} guard(s) passed at {stage_name}");
    }
    Ok(Exit::Clean)
}

/// Write the run's `JUnit` document, if one was asked for.
fn written(suite: Option<crate::junit::Suite<'_>>) -> Result<()> {
    suite.map_or(Ok(()), crate::junit::Suite::write)
}

#[derive(Debug)]
pub(crate) struct RunRequest<'a> {
    pub stage: Stage,
    pub message_file: Option<&'a Path>,
    pub push_refs: &'a str,
    pub push_source: crate::runner::Source,
    pub remote_name: Option<&'a str>,
    pub remote_url: Option<&'a str>,
    /// Where the run's `JUnit` document goes, opened by the caller before
    /// anything is decided; `None` when nobody asked for one. A sink and not a
    /// path, so a test can hand the run a buffer. See `junit`.
    pub evidence: Option<crate::junit::Sink<'a>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_guard_dispatches() {
        // `evaluate` matching on a string is the one place an id could be
        // added to the list and never wired up, and the catch-all arm turns
        // that into a runtime error rather than a compile one. So the arms are
        // read here: a name in the list with no arm beside it is a guard a
        // config can declare, validate, install, and never run.
        //
        // The whole FILE is read rather than one function, because a built-in
        // is dispatched from the seam that can hand it what it reads --
        // `evaluate` for a git hook, `text_refusal` for a subject,
        // `target_refusal` for a destination, `invocation_refusal` for the
        // credential a `gh` invocation runs under. Which of them carries the arm is
        // the built-in's business; that one of them does is this test's.
        let source = include_str!("mod.rs");
        for id in EVERY_BUILTIN {
            if SCAN_BUILTINS.contains(id) {
                // Read the tree rather than git, so `scan` dispatches them and
                // this match never sees them.
                continue;
            }
            assert!(
                source.contains(&format!("\"{id}\" => ")),
                "{id} is in EVERY_BUILTIN with no dispatch arm"
            );
        }
        assert_eq!(EVERY_BUILTIN.len(), 24);
    }

    #[test]
    fn a_stage_round_trips_through_its_name() {
        for stage in [
            Stage::CommitMsg,
            Stage::PreCommit,
            Stage::PreMergeCommit,
            Stage::PrePush,
            Stage::Manual,
        ] {
            assert_eq!(Stage::parse(stage.as_str()).unwrap(), stage);
        }
    }
}
