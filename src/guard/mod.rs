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

pub(crate) mod identity;
pub(crate) mod merge;
pub(crate) mod message;
pub(crate) mod names;
pub(crate) mod push;
pub(crate) mod scope;
pub(crate) mod sets;
pub(crate) mod unicode;
pub(crate) mod visibility;

use std::path::Path;

use crate::config::{Check, Policy, Rule};
use crate::error::{Exit, Fatal, Result};

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
    "no-private-repo-names",
    "no-private-repo-names-staged",
    "no-private-repo-names-in-files",
    "prevent-public-push",
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
];

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
                )))
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
    let Ok(value) = std::env::var("UPHOLD_ALLOW") else {
        return false;
    };
    value
        .split(',')
        .map(str::trim)
        .any(|allowed| allowed == id || allowed == "all")
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
/// reporting a pass would be a check that did not happen. These three judge
/// text and nothing else, which is exactly what a shim has to hand them.
pub(crate) const TEXT_GUARDS: &[&str] = &[
    "prevent-ai-author",
    "prevent-unusual-unicode",
    "no-private-repo-names",
];

/// Run every text-capable guard over one piece of text.
pub(crate) fn over_text(
    root: &Path,
    policy: &Policy,
    label: &str,
    text: &str,
) -> Result<Vec<Refusal>> {
    let mut refusals = Vec::new();
    for rule in policy.of_check(Check::Builtin) {
        if let Some(refusal) = text_refusal(root, policy, rule, label, text)? {
            refusals.push(refusal);
        }
    }
    Ok(refusals)
}

/// One text-capable guard's verdict over one piece of text.
///
/// `None` where the rule is not a text guard, or is bypassed, or found nothing
/// -- three different reasons a caller does not have to tell apart, because a
/// guard with nothing to say about a pull-request body is not a guard that
/// passed it. Extracted so the shim seam consults exactly the same dispatch
/// `uphold guard --text` does: a text guard that judged a commit message one
/// way and a PR body another would be two rules under one id.
pub(crate) fn text_refusal(
    root: &Path,
    policy: &Policy,
    rule: &Rule,
    label: &str,
    text: &str,
) -> Result<Option<Refusal>> {
    let Some(builtin) = rule.builtin() else {
        return Ok(None);
    };
    if !TEXT_GUARDS.contains(&builtin) || bypassed(&rule.id) {
        return Ok(None);
    }
    Ok(match builtin {
        "prevent-ai-author" => message::ai_author_in(rule, label, text),
        "prevent-unusual-unicode" => message::unusual_unicode_in(rule, label, text),
        "no-private-repo-names" => names::in_text(root, policy, rule, label, text)?,
        _ => None,
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
        other => Err(Fatal::new(format!("no built-in called {other:?}"))),
    }
}

/// The parameters each built-in reads, and the only statement of it.
///
/// The nine parameter fields sit flat on the rule struct, so without this list
/// a `private_owners` beside `regexp` -- or beside the wrong built-in --
/// loaded, looked enforced, and was read by nothing. `Rule::validate` refuses
/// a written parameter that is not in the declaring built-in's row, the same
/// way it refuses a second check field and for the same reason.
pub(crate) fn parameters(builtin: &str) -> &'static [&'static str] {
    match builtin {
        "prevent-public-push" => &["owner", "owner_required", "allowed_owners", "allowed_repos"],
        "no-private-repo-names"
        | "no-private-repo-names-staged"
        | "no-private-repo-names-in-files" => &[
            "visibility",
            "visibility_required",
            "private_owners",
            "private_owners_from",
            "public_repos",
            "refuse_unknown",
        ],
        // `visibility` and nothing else: the rule reads the declaration and
        // compares it to the forge, and every other field in the family is
        // about judging names in text, which this one never does.
        "no-stale-visibility" => &["visibility"],
        "prevent-unusual-unicode-in-files" => &["allow"],
        _ => &[],
    }
}

/// Run every guard the policy declares that has something to say at `stage`.
pub(crate) fn run(root: &Path, policy: &Policy, request: &RunRequest<'_>) -> Result<Exit> {
    // Every rule the CONFIG puts at this hook, and nothing else decides it.
    let at_hook: Vec<&Rule> = policy.at_hook(request.stage.as_str()).collect();
    if policy.at_hook_any().next().is_none() {
        println!("no rule declares a git hook");
        return Ok(Exit::Clean);
    }

    let mut refusals: Vec<Refusal> = Vec::new();
    let mut ran = 0usize;
    let mut bypassed_here = 0usize;
    for rule in at_hook {
        // Counted where the work happens, not where the loop starts. A bypassed
        // rule did not run, and folding it into the same number reported a
        // deliberately disabled check as one that passed.
        if bypassed(rule.id.as_str()) {
            eprintln!("uphold guard: {} bypassed by UPHOLD_ALLOW", rule.id);
            bypassed_here += 1;
            continue;
        }
        ran += 1;
        let one = Request {
            root,
            rule,
            policy,
            stage: request.stage,
            message_file: request.message_file,
            push_refs: request.push_refs,
            push_source: request.push_source,
            remote_name: request.remote_name,
            remote_url: request.remote_url,
        };
        if let Some(refusal) = evaluate(&one)? {
            refusals.push(refusal);
        }
    }

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
        println!(
            "{ran} guard(s) passed at {}, {bypassed_here} bypassed by UPHOLD_ALLOW",
            request.stage.as_str()
        );
    } else {
        println!("{ran} guard(s) passed at {}", request.stage.as_str());
    }
    Ok(Exit::Clean)
}

pub(crate) struct RunRequest<'a> {
    pub stage: Stage,
    pub message_file: Option<&'a Path>,
    pub push_refs: &'a str,
    pub push_source: crate::runner::Source,
    pub remote_name: Option<&'a str>,
    pub remote_url: Option<&'a str>,
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
        let source = include_str!("mod.rs");
        for id in EVERY_BUILTIN {
            if matches!(*id, "links-resolve" | "anchors-resolve") {
                // Read the tree rather than git, so `scan` dispatches them and
                // this match never sees them.
                continue;
            }
            assert!(
                source.contains(&format!("\"{id}\" => ")),
                "{id} is in EVERY_BUILTIN with no dispatch arm"
            );
        }
        assert_eq!(EVERY_BUILTIN.len(), 15);
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
