//! What a provider reports, and what a policy may read.
//!
//! Every other guard in this crate reads its artifact directly:
//! `prevent-ai-author` opens the message file, `no-private-repo-names-staged`
//! runs `git diff`, and each decides on the spot. That couples the rule to the
//! reader, and a rule coupled to its reader is rewritten when the reader is
//! replaced. The layer here is the seam between the two. A PROVIDER reads one
//! artifact and reports FACTS in one normalized shape; a POLICY reads the facts
//! and decides. A policy that never names a provider is a policy a better
//! provider can be slid under without touching it, and
//! `tests/structural_evidence.rs` holds the one policy here to that.
//!
//! The shape carries provenance because the facts are not equal. A parser or
//! git reporting that a function is gone is a different claim from a regex
//! having matched `fn name(` on a removed line, which is a different claim
//! again from a model asserting it. [`Strength`] is that ordering, and the
//! rules in [`Body`] are what it buys: weaker evidence may add a refusal and
//! may never supply a clean verdict where a stronger provider could not look,
//! and may never cancel a stronger provider's refusal. ADR 0003 and ADR 0004
//! measured the failure this refuses at three tiers -- a clean run over a
//! source the analyzer could not read is byte-identical to a clean run over a
//! source that complies -- and [`Observation::Unavailable`] is the provider
//! saying so itself, which ADR 0005 names as the property worth preferring a
//! provider for.
//!
//! What this is not, and each is a decision already recorded: not a rule DSL
//! over tree-sitter (ADR 0003), not a plugin API (ADR 0005). A provider is a
//! Rust type compiled into this binary, and a policy is a Rust predicate over
//! a [`Body`]. The trait is the shape of an answer to ADR 0005's third
//! question, and nothing more.

pub(crate) mod diff;
pub(crate) mod git;
pub(crate) mod syntax;

use std::collections::BTreeMap;
use std::path::Path;

use crate::error::Result;
use crate::guard::{Request, Stage};

/// How a fact was established, ranked.
///
/// The order is the whole point of the type: `Proven > Heuristic > Inferred`,
/// and [`Body::established`] reads it. A variant rather than a number so that
/// a model's assertion cannot be promoted by a confidence score into the tier
/// a parser occupies -- the issue this answers says AI confidence alone must
/// never be sufficient, and a variant is a thing no threshold can cross.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Strength {
    /// A model or an agent asserted it. Never a refusal on its own at a
    /// blocking stage, and never a cancellation of anything stronger.
    Inferred,
    /// A text pattern found it: a regex over a diff, a line shape. May add a
    /// refusal; may never stand in for a stronger provider that could not look.
    Heuristic,
    /// A parser or git reported it. What a clean verdict rests on.
    Proven,
}

/// A category of fact. Exactly the kinds a compiled-in provider produces
/// today, because a kind nothing reports is configuration nobody can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Kind {
    FunctionAdded,
    FunctionRemoved,
    SignatureChanged,
    /// The commit message: the subject line is the evidence's subject, the
    /// rest is its `body` property.
    CommitIntent,
    HumanChange,
    AgentChange,
}

impl Kind {
    /// The kind that contradicts this one on the same subject at the same
    /// revision, if one exists. A function is not both added and removed, and
    /// a change is not both human and agent.
    pub(crate) const fn opposite(self) -> Option<Self> {
        match self {
            Self::FunctionAdded => Some(Self::FunctionRemoved),
            Self::FunctionRemoved => Some(Self::FunctionAdded),
            Self::HumanChange => Some(Self::AgentChange),
            Self::AgentChange => Some(Self::HumanChange),
            Self::SignatureChanged | Self::CommitIntent => None,
        }
    }
}

/// Who reported a fact and how strongly, plus which kinds the provider
/// answers for at all.
///
/// `claims` is on the provider rather than on each observation because it is
/// a property of the reader and not of one run: it is what lets a body tell
/// "this provider read the change and reported no removal" from "no provider
/// that reports removals read the change", and the second of those must never
/// come out as clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Provider {
    pub name: &'static str,
    pub strength: Strength,
    pub claims: &'static [Kind],
}

/// One fact, with its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Evidence {
    pub kind: Kind,
    /// What the fact is about: `path::name` for a function, the subject line
    /// for a message.
    pub subject: String,
    pub properties: BTreeMap<&'static str, String>,
    pub provider: Provider,
    /// What the provider read: `index`, `HEAD`, a sha, or a comparison such as
    /// `HEAD..index`. Two facts about one subject at different revisions are
    /// not about the same thing.
    pub revision: String,
}

/// A provider's answer. It either reported facts, possibly none, or it could
/// not look -- and the second is a variant so that it can never be an empty
/// first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Observation {
    Found(Vec<Evidence>),
    Unavailable { provider: Provider, reason: String },
}

/// What a provider is handed. References into the guard's [`Request`], not
/// a copy of it, plus the two things a request carries only by path: the
/// message's text and the change's paths.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Context<'a> {
    pub root: &'a Path,
    pub stage: Stage,
    /// The commit message, where the stage has one.
    pub message: Option<&'a str>,
    /// The paths the change touches, repository-relative, or `None` where the
    /// stage has no index to compare against `HEAD`. A push has none, and an
    /// empty list there would read as a change touching nothing.
    pub changed: Option<&'a [String]>,
}

/// The property a [`Kind::FunctionRemoved`] fact carries when the whole file
/// is gone from the index, and its value. One spelling for every provider
/// that reports removals, so a policy reading it reads one thing.
pub(crate) const FILE_REMOVED: (&str, &str) = ("file", "removed");

/// A reader of one artifact.
pub(crate) trait Source {
    /// Who this is, and what it answers for.
    fn provider(&self) -> Provider;
    /// Read, and report facts or the reason none could be read. Never an
    /// error: a provider that could not look says so in its answer.
    fn observe(&self, context: &Context<'_>) -> Observation;
}

/// A provider that could not look, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unavailable {
    pub provider: Provider,
    pub reason: String,
}

/// Everything the providers reported about one change.
///
/// `read` is the third list and it is not redundant with the first two: a
/// provider that read the change and found nothing appears in neither
/// `found` nor `unavailable`, and it is exactly the provider whose silence a
/// clean verdict rests on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Body {
    pub found: Vec<Evidence>,
    pub unavailable: Vec<Unavailable>,
    /// The providers that read the change, whatever they found.
    pub read: Vec<Provider>,
}

/// Two Proven facts that cannot both hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Contradiction<'a> {
    pub first: &'a Evidence,
    pub second: &'a Evidence,
}

/// What the body establishes about one kind of fact, in the only three ways
/// it can. The policy reads this and not `found` directly, so that "the parser
/// could not look and the regex saw nothing" has no path to a clean verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Established<'a> {
    /// A Proven provider read the change. Its facts, and any Heuristic facts
    /// beside them, are the answer; an empty list is clean.
    Proven(Vec<&'a Evidence>),
    /// No Proven provider read the change, and a Heuristic one did. `found`
    /// may refuse. Whether an empty `found` is clean depends on `unread`: a
    /// Proven provider that could not look is listed there, and a heuristic
    /// finding nothing where a parser could not read is not a clean verdict.
    HeuristicOnly {
        found: Vec<&'a Evidence>,
        unread: Vec<&'a Unavailable>,
    },
    /// Nothing that could look, looked. The providers that would have.
    Unavailable(Vec<&'a Unavailable>),
}

impl<'a> Established<'a> {
    /// The facts a policy may refuse on. Never an Inferred one.
    pub(crate) fn found(&self) -> &[&'a Evidence] {
        match self {
            Self::Proven(found) | Self::HeuristicOnly { found, .. } => found,
            Self::Unavailable(_) => &[],
        }
    }

    /// The providers that would have answered and could not.
    pub(crate) fn unread(&self) -> &[&'a Unavailable] {
        match self {
            Self::Proven(_) => &[],
            Self::HeuristicOnly { unread, .. } | Self::Unavailable(unread) => unread,
        }
    }

    /// Whether the question was answered: something that could look did,
    /// and nothing stronger was refused a look. A policy that found nothing
    /// to refuse asks this before concluding anything, because "the facts I
    /// was handed are all accounted for" is not "every fact was read".
    pub(crate) const fn answered(&self) -> bool {
        match self {
            Self::Proven(_) => true,
            Self::HeuristicOnly { unread, .. } => unread.is_empty(),
            Self::Unavailable(_) => false,
        }
    }

    /// Whether this is a clean answer: answered, and nothing found. The one
    /// sanctioned way to conclude it.
    pub(crate) fn clean(&self) -> bool {
        self.answered() && self.found().is_empty()
    }
}

impl Body {
    /// Ask every source, and keep every answer.
    pub(crate) fn collect(sources: &[&dyn Source], context: &Context<'_>) -> Self {
        let mut body = Self::default();
        for source in sources {
            match source.observe(context) {
                Observation::Found(items) => {
                    body.read.push(source.provider());
                    body.found.extend(items);
                }
                Observation::Unavailable { provider, reason } => {
                    body.unavailable.push(Unavailable { provider, reason });
                }
            }
        }
        body
    }

    /// Every pair of Proven facts that cannot both hold: opposite kinds, one
    /// subject, one revision. A policy handed one of these refuses naming
    /// both providers; picking the one it likes is the failure a second
    /// checker over one answer always produces.
    pub(crate) fn contradictions(&self) -> Vec<Contradiction<'_>> {
        let mut pairs = Vec::new();
        for (index, first) in self.found.iter().enumerate() {
            if first.provider.strength != Strength::Proven {
                continue;
            }
            let Some(opposite) = first.kind.opposite() else {
                continue;
            };
            for second in self.found.iter().skip(index + 1) {
                if second.provider.strength == Strength::Proven
                    && second.kind == opposite
                    && second.subject == first.subject
                    && second.revision == first.revision
                {
                    pairs.push(Contradiction { first, second });
                }
            }
        }
        pairs
    }

    /// The strongest fact of one kind about one subject.
    pub(crate) fn strongest(&self, kind: Kind, subject: &str) -> Option<&Evidence> {
        self.found
            .iter()
            .filter(|item| item.kind == kind && item.subject == subject)
            .max_by_key(|item| item.provider.strength)
    }

    /// What is established about one kind, by the strength rule.
    ///
    /// A Proven provider that read the change decides the variant; failing
    /// that a Heuristic one; failing that nothing did. Inferred facts are in
    /// `found` for a reader to see and are in no variant here, which is how
    /// an Inferred item alone refuses nothing and cancels nothing.
    pub(crate) fn established(&self, kind: Kind) -> Established<'_> {
        let read_at = |strength: Strength| {
            self.read
                .iter()
                .any(|provider| provider.strength == strength && provider.claims.contains(&kind))
        };
        let found: Vec<&Evidence> = self
            .found
            .iter()
            .filter(|item| item.kind == kind && item.provider.strength > Strength::Inferred)
            .collect();
        let unread: Vec<&Unavailable> = self
            .unavailable
            .iter()
            .filter(|missing| {
                missing.provider.strength > Strength::Inferred
                    && missing.provider.claims.contains(&kind)
            })
            .collect();
        if read_at(Strength::Proven) {
            Established::Proven(found)
        } else if read_at(Strength::Heuristic) {
            Established::HeuristicOnly { found, unread }
        } else {
            Established::Unavailable(unread)
        }
    }
}

/// Every compiled-in provider, asked about what a guard was asked about.
///
/// The paths and the message are read here, once, and handed to each source:
/// two providers listing the staged paths for themselves would be two
/// listings free to disagree about which change they read. A message file
/// that cannot be read, or an index that cannot be listed, is an error rather
/// than an empty context -- nothing downstream should be handed "no change"
/// where the truth is "the change could not be listed".
pub(crate) fn observe(request: &Request<'_>) -> Result<Body> {
    let message = match request.stage {
        Stage::CommitMsg => Some(crate::guard::message::message_text(request)?.1),
        Stage::PreCommit | Stage::PreMergeCommit | Stage::PrePush | Stage::Manual => None,
    };
    let changed = match request.stage {
        Stage::CommitMsg | Stage::PreCommit | Stage::PreMergeCommit | Stage::Manual => {
            Some(staged_paths(request.root)?)
        }
        Stage::PrePush => None,
    };
    let context = Context {
        root: request.root,
        stage: request.stage,
        message: message.as_deref(),
        changed: changed.as_deref(),
    };
    Ok(Body::collect(
        &[&git::Messages, &syntax::Declarations, &diff::Lines],
        &context,
    ))
}

/// The paths the index changes against `HEAD`, as git lists them.
///
/// `-M` is written rather than left to `diff.renames`, because a rename read
/// as a delete and an add reports every function in the file as removed, and
/// whether that happens must not depend on whose config the hook runs under.
fn staged_paths(root: &Path) -> Result<Vec<String>> {
    crate::git::run_z(
        root,
        &[
            "-c",
            "core.quotepath=false",
            "diff",
            "--cached",
            "--name-only",
            "-M",
            "-z",
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARSER: Provider = Provider {
        name: "parser",
        strength: Strength::Proven,
        claims: &[Kind::FunctionRemoved, Kind::FunctionAdded],
    };
    const PATTERN: Provider = Provider {
        name: "pattern",
        strength: Strength::Heuristic,
        claims: &[Kind::FunctionRemoved, Kind::FunctionAdded],
    };
    const ORACLE: Provider = Provider {
        name: "oracle",
        strength: Strength::Inferred,
        claims: &[Kind::FunctionRemoved],
    };

    fn fact(provider: Provider, kind: Kind, subject: &str) -> Evidence {
        Evidence {
            kind,
            subject: subject.to_owned(),
            properties: BTreeMap::new(),
            provider,
            revision: String::from("HEAD..index"),
        }
    }

    /// A source that answers with whatever it was built to answer.
    struct Scripted(Provider, Observation);

    impl Source for Scripted {
        fn provider(&self) -> Provider {
            self.0
        }

        fn observe(&self, _: &Context<'_>) -> Observation {
            self.1.clone()
        }
    }

    fn context() -> Context<'static> {
        Context {
            root: Path::new("."),
            stage: Stage::CommitMsg,
            message: None,
            changed: None,
        }
    }

    fn body(sources: &[&dyn Source]) -> Body {
        Body::collect(sources, &context())
    }

    #[test]
    fn strength_is_ordered_proven_over_heuristic_over_inferred() {
        // The whole of `established` rests on this comparison, and a derived
        // ordering follows declaration order: a variant moved in the enum
        // would silently invert the rule.
        assert!(Strength::Proven > Strength::Heuristic);
        assert!(Strength::Heuristic > Strength::Inferred);
    }

    #[test]
    fn a_provider_that_could_not_look_is_never_an_empty_found() {
        // The failure ADR 0003 measured: silence over an unread source reads
        // as compliance. The variant is what keeps the two apart, and a body
        // keeps the reason rather than dropping it into an empty list.
        let unread = Scripted(
            PARSER,
            Observation::Unavailable {
                provider: PARSER,
                reason: String::from("a.rs:3 did not parse"),
            },
        );
        let collected = body(&[&unread]);
        assert!(collected.found.is_empty());
        assert!(collected.read.is_empty());
        assert_eq!(collected.unavailable.len(), 1);
        assert_eq!(collected.unavailable[0].reason, "a.rs:3 did not parse");
        assert_eq!(
            collected.established(Kind::FunctionRemoved),
            Established::Unavailable(vec![&collected.unavailable[0]])
        );
    }

    #[test]
    fn two_proven_providers_reporting_opposite_facts_are_a_contradiction() {
        // Picking one would be a second checker over one answer, which this
        // repository has measured disagreeing before.
        let removed = fact(PARSER, Kind::FunctionRemoved, "a.rs::go");
        let added = fact(
            Provider {
                name: "other-parser",
                ..PARSER
            },
            Kind::FunctionAdded,
            "a.rs::go",
        );
        let unrelated = fact(PARSER, Kind::FunctionAdded, "a.rs::stop");
        let collected = Body {
            found: vec![removed.clone(), added.clone(), unrelated],
            unavailable: Vec::new(),
            read: vec![PARSER],
        };
        let pairs = collected.contradictions();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].first, &removed);
        assert_eq!(pairs[0].second, &added);
    }

    #[test]
    fn a_heuristic_disagreeing_with_a_parser_is_not_a_contradiction() {
        // A regex matching `fn go(` on a removed comment line beside a parser
        // that saw the function added is the ordinary case, and the strength
        // rule handles it: the weaker fact adds and never contradicts.
        let collected = Body {
            found: vec![
                fact(PARSER, Kind::FunctionAdded, "a.rs::go"),
                fact(PATTERN, Kind::FunctionRemoved, "a.rs::go"),
            ],
            unavailable: Vec::new(),
            read: vec![PARSER, PATTERN],
        };
        assert!(collected.contradictions().is_empty());
    }

    #[test]
    fn the_strongest_fact_about_a_subject_is_the_proven_one() {
        let collected = Body {
            found: vec![
                fact(ORACLE, Kind::FunctionRemoved, "a.rs::go"),
                fact(PATTERN, Kind::FunctionRemoved, "a.rs::go"),
                fact(PARSER, Kind::FunctionRemoved, "a.rs::go"),
            ],
            unavailable: Vec::new(),
            read: vec![PARSER, PATTERN],
        };
        let strongest = collected
            .strongest(Kind::FunctionRemoved, "a.rs::go")
            .expect("three facts about it");
        assert_eq!(strongest.provider, PARSER);
        assert!(
            collected
                .strongest(Kind::FunctionAdded, "a.rs::go")
                .is_none()
        );
    }

    #[test]
    fn a_proven_provider_that_read_and_found_nothing_is_clean() {
        let collected = body(&[&Scripted(PARSER, Observation::Found(Vec::new()))]);
        let removed = collected.established(Kind::FunctionRemoved);
        assert_eq!(removed, Established::Proven(Vec::new()));
        assert!(removed.clean());
    }

    #[test]
    fn a_heuristic_may_add_a_refusal_beside_a_proven_provider() {
        let heuristic = fact(PATTERN, Kind::FunctionRemoved, "a.rs::go");
        let collected = body(&[
            &Scripted(PARSER, Observation::Found(Vec::new())),
            &Scripted(PATTERN, Observation::Found(vec![heuristic.clone()])),
        ]);
        let removed = collected.established(Kind::FunctionRemoved);
        assert_eq!(removed, Established::Proven(vec![&heuristic]));
        assert!(!removed.clean());
    }

    #[test]
    fn a_heuristic_finding_nothing_where_a_proven_provider_could_not_look_is_not_clean() {
        // The `UNKNOWN -> PASS` shape at this seam: the parser refused the
        // file, the regex saw no `fn` line, and the two together must not
        // read as a change that removes nothing.
        let collected = body(&[
            &Scripted(
                PARSER,
                Observation::Unavailable {
                    provider: PARSER,
                    reason: String::from("a.rs:3 did not parse"),
                },
            ),
            &Scripted(PATTERN, Observation::Found(Vec::new())),
        ]);
        let removed = collected.established(Kind::FunctionRemoved);
        assert!(!removed.clean());
        assert!(removed.found().is_empty());
        assert_eq!(removed.unread().len(), 1);
        assert!(matches!(removed, Established::HeuristicOnly { .. }));
    }

    #[test]
    fn a_heuristic_finding_a_removal_where_a_proven_provider_could_not_look_refuses() {
        let heuristic = fact(PATTERN, Kind::FunctionRemoved, "a.rs::go");
        let collected = body(&[
            &Scripted(
                PARSER,
                Observation::Unavailable {
                    provider: PARSER,
                    reason: String::from("a.rs:3 did not parse"),
                },
            ),
            &Scripted(PATTERN, Observation::Found(vec![heuristic.clone()])),
        ]);
        let removed = collected.established(Kind::FunctionRemoved);
        assert_eq!(removed.found(), [&heuristic]);
        assert!(!removed.clean());
    }

    #[test]
    fn a_heuristic_alone_with_no_stronger_provider_asked_stands_on_its_own() {
        // Provider substitution: a body assembled from the textual provider
        // only is judged by it, and nothing stronger was refused.
        let collected = body(&[&Scripted(PATTERN, Observation::Found(Vec::new()))]);
        let removed = collected.established(Kind::FunctionRemoved);
        assert!(removed.clean());
        assert!(removed.unread().is_empty());
    }

    #[test]
    fn an_inferred_fact_alone_establishes_nothing() {
        // A model asserting a removal, with no deterministic provider having
        // read the change, is not a refusal and not a clean verdict either.
        let inferred = fact(ORACLE, Kind::FunctionRemoved, "a.rs::go");
        let collected = body(&[&Scripted(
            ORACLE,
            Observation::Found(vec![inferred.clone()]),
        )]);
        let removed = collected.established(Kind::FunctionRemoved);
        assert_eq!(removed, Established::Unavailable(Vec::new()));
        assert!(removed.found().is_empty());
        assert!(!removed.clean());
        // Still in the body for a reader; just in no verdict.
        assert_eq!(collected.found, vec![inferred]);
    }

    #[test]
    fn an_inferred_fact_cannot_cancel_a_proven_refusal_or_supply_one() {
        let proven = fact(PARSER, Kind::FunctionRemoved, "a.rs::go");
        let denial = fact(ORACLE, Kind::FunctionAdded, "a.rs::go");
        let collected = body(&[
            &Scripted(PARSER, Observation::Found(vec![proven.clone()])),
            &Scripted(ORACLE, Observation::Found(vec![denial])),
        ]);
        assert_eq!(
            collected.established(Kind::FunctionRemoved),
            Established::Proven(vec![&proven])
        );
        assert!(collected.contradictions().is_empty());

        let assertion = fact(ORACLE, Kind::FunctionRemoved, "a.rs::stop");
        let clean = body(&[
            &Scripted(PARSER, Observation::Found(Vec::new())),
            &Scripted(ORACLE, Observation::Found(vec![assertion])),
        ]);
        assert!(clean.established(Kind::FunctionRemoved).clean());
    }
}
