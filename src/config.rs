//! The unified policy schema.
//!
//! Seven array-of-tables names became one. `[[rule]]` with `kind` as the
//! discriminant replaces `[[rule]]`, `[[dynamic_rule]]`, `[[size_rule]]`,
//! `[[path_rule]]`, `[[require_rule]]`, `[[link_rule]]` and `[[language_rule]]`.
//!
//! The collapse is not tidying. While the kinds were seven TOML table names,
//! every consumer that wanted to reason about "the rules" had to carry its own
//! list of what the names were -- and one such list, in the reconciler, was
//! short by one: it knew six and the engine had seven, so a claim naming a
//! `language_rule` was reported as enforcing nothing while it was in fact
//! enforced. Nothing could catch that, because the list was a literal in one
//! repository describing a constant in another. One enum in one crate makes the
//! whole class of drift unrepresentable, and [`Kind::ALL`] is the only list.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::error::{read_to_string, Fatal, Result};

/// The bundled base rule sets, compiled in.
///
/// They ship inside the binary rather than beside it because the old hook
/// resolved them relative to the checked-out script, which meant a consumer got
/// whichever copy their hook manager had cloned. A binary has one copy and its
/// version is the binary's version.
pub(crate) const BUNDLED: &[(&str, &str)] = &[
    // Each set is named by what it REFUSES, because the name is the only thing
    // a stranger reads before deciding to inherit it: `process-residue` and
    // `credentials` predict their rule lists where `hygiene` and `security`
    // predicted nothing a linter ecosystem agrees on. `uphold rules --set
    // <name>` prints the list, so the binary answers "what is in it" without a
    // docs round-trip.
    (
        "process-residue",
        include_str!("../policy/base/process-residue.toml"),
    ),
    (
        "credentials",
        include_str!("../policy/base/credentials.toml"),
    ),
    (
        "unmanaged-pins",
        include_str!("../policy/base/unmanaged-pins.toml"),
    ),
    (
        "host-identity",
        include_str!("../policy/base/host-identity.toml"),
    ),
    (
        "broken-links",
        include_str!("../policy/base/broken-links.toml"),
    ),
    (
        "captured-fixtures",
        include_str!("../policy/base/captured-fixtures.toml"),
    ),
    ("doc-claims", include_str!("../policy/base/doc-claims.toml")),
    // Not residue in what a repository commits, but how its CI is configured.
    // A separate name because declining it is a real decision -- a repository
    // with no workflows, or whose workflows are generated somewhere else, has
    // nothing here to enforce -- and a set nobody can decline is a default
    // wearing a set's clothes.
    (
        "default-token-grant",
        include_str!("../policy/base/default-token-grant.toml"),
    ),
    // Named for the shape it refuses rather than for `toolchain`, which would
    // have predicted a rule about which toolchain a repository uses. What it
    // refuses is an installer written by hand where a version manager was
    // available -- and declining it is a real decision, because a repository
    // that deliberately vendors its own bootstrap has an argument for exactly
    // these lines.
    (
        "hand-rolled-toolchain",
        include_str!("../policy/base/hand-rolled-toolchain.toml"),
    ),
    // The other half of `doc-claims`, and a separate name because it is a
    // separate argument. That one checks a fact somebody ANCHORED; this one
    // refuses the shape of a fact nobody can anchor -- a measurement of the
    // author's own data stated in a comment, where the record it came from is
    // not written down and never was. Declining it is a real decision: a
    // repository whose comments quote benchmark numbers on purpose, beside the
    // benchmark, has an argument for exactly these lines.
    (
        "comment-facts",
        include_str!("../policy/base/comment-facts.toml"),
    ),
    // The guard sets. They install git hooks, which the seven above do not, and
    // each is a separate name because taking one is a separate decision: what
    // it costs, when it runs, and what it will refuse are different arguments
    // for each. The `[set] stages` header in every one of them is the ceiling
    // the loader holds them to -- a guard cannot join a set that did not say it
    // carries guards, which is the constraint that makes shipping these safe at
    // all.
    (
        "commit-message-residue",
        include_str!("../policy/base/commit-message-residue.toml"),
    ),
    (
        "unreviewed-history",
        include_str!("../policy/base/unreviewed-history.toml"),
    ),
    // The identity half of the same moment `unreviewed-history` guards. Its own
    // name because the question is different -- who is writing, read off the
    // machine, rather than where a ref is going or what a message says -- and
    // because it is the one guard here that refuses the deliberate act as
    // readily as the accidental one, which a repository applying mailed patches
    // has a reason to decline.
    (
        "mismatched-author",
        include_str!("../policy/base/mismatched-author.toml"),
    ),
    (
        "invisible-characters",
        include_str!("../policy/base/invisible-characters.toml"),
    ),
    ("stale-pins", include_str!("../policy/base/stale-pins.toml")),
    // The second network set, and separate from `private-names` for the reason
    // `stale-pins` is separate from everything: a verdict that depends on
    // where the machine running it is standing is a decision a repository
    // takes on its own, not one it acquires by inheriting the family whose
    // scope condition this checks.
    (
        "stale-visibility",
        include_str!("../policy/base/stale-visibility.toml"),
    ),
    (
        "unowned-push",
        include_str!("../policy/base/unowned-push.toml"),
    ),
    // The widest ceiling of any set here -- five stages -- and the reason is
    // the finding it was promoted on: a family covering three of the four
    // seams that publish text is the shape the sweep found, in ten
    // repositories out of seventy-seven. Like `unowned-push` it refuses to run
    // until the repository has answered one question, and `visibility` is that
    // question.
    (
        "private-names",
        include_str!("../policy/base/private-names.toml"),
    ),
    // The one set whose rules run at the shim seam and nowhere else. It ships
    // checkers and never shims: every `command.before` line in it must sit
    // inside the `[set] commands` ceiling, and each names a `[[shim]]` the
    // inheriting repository has declared itself -- a repository that has not
    // put a program in front of `gh` is refused at load with the table to
    // write, not handed one by a version bump. See ADR 0006.
    (
        "published-text",
        include_str!("../policy/base/published-text.toml"),
    ),
    // The second shim-seam set, and separate from `published-text` because the
    // two answer different questions about the same body. That one asks whether
    // the text discloses something -- a host name, a private repository, a
    // refused marker -- and the answer is the same wherever the text came from.
    // This one asks how the sentence is written, which is a house-style
    // judgement a repository takes on its own: a workspace that wants its
    // disclosure checks has said nothing about whether it wants its prose
    // refused for hedging.
    (
        "prose-shapes",
        include_str!("../policy/base/prose-shapes.toml"),
    ),
];

mod rule;

pub(crate) use rule::{Check, CheckKind, Literals, Rule, Written};

/// Where a rule runs: over files, as a git hook, in front of a command.
///
/// Three tables, three vocabularies, and none of them this tool's. `[rule.git]`
/// takes hook names from githooks(5). `[rule.command]` takes command lines as
/// typed. `[rule.files]` takes ripgrep's own search scoping, because the search
/// IS ripgrep -- the crates are linked in, so a glob written here means what it
/// means to `rg --glob`.
///
/// An absent table is not a default. It is a place the rule does not run, which
/// is the whole of the configuration story and the reason "the gh shim and the
/// file scan, but install no git hook" is now something a person can write down.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Files {
    /// Search roots. `["."]` when absent.
    #[serde(default)]
    pub include: Option<Vec<String>>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub glob: Vec<String>,
    #[serde(default)]
    pub multiline: bool,
    #[serde(default)]
    pub fixed_strings: Option<bool>,
    /// Needles from this source match whole words only.
    #[serde(default)]
    pub word: bool,
    #[serde(default)]
    pub exclude_cfg_test: bool,
    #[serde(default)]
    pub baseline: Option<String>,
    /// The smallest selection this rule accepts. Fewer files than this and the
    /// rule fails, naming the count and the keys that produced it.
    ///
    /// Here rather than beside a check, and that is the whole placement
    /// argument: the count is a fact about the SELECTION, so it belongs in the
    /// shared selection vocabulary every check reads, and one implementation at
    /// the funnel covers the check kinds nobody has written yet. `min_selected`
    /// rather than a `require_selection = true` boolean, because a floor of one
    /// is a value and not a kind of floor -- a repository whose selection must
    /// cover four workflow files writes `4`, and no second field has to be
    /// invented for it.
    ///
    /// A written `0` is refused at load: it is satisfied by every selection
    /// there is, so it declares a floor and enforces nothing, which is the
    /// shape `trivial_comments = false` is refused for.
    #[serde(default)]
    pub min_selected: Option<u64>,
}

/// The five stage names a rule may run at: four of git's own, spelled as
/// githooks(5) spells them, and `manual`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Git {
    /// `pre-commit`, `commit-msg`, `pre-merge-commit`, `pre-push`, `manual`.
    ///
    /// `manual` is the one name here that is not git's: no git operation runs
    /// it, and it exists because every runner spells "run this on purpose, in
    /// CI" that way. It is where the checks too slow to sit in front of a
    /// commit go.
    #[serde(default)]
    pub hooks: Vec<String>,
}

/// The command lines a rule stands in front of.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommandWhere {
    /// `"gh pr create"`, `"git push"`, `"npm publish"` -- the command and as
    /// much of its subcommand path as should match, space-separated, as typed.
    /// `"gh"` alone matches every `gh` invocation a shim collects a subject
    /// from.
    ///
    /// Before this field, a checker rule was consulted by EVERY shim: a check
    /// written for a pull-request body was also asked about a branch name on
    /// `git push` and a tarball on `npm publish`, and there was no way to say
    /// otherwise.
    #[serde(default)]
    pub before: Vec<String>,
    /// When this rule applies, overriding the `[[shim]]` table's own `scope`
    /// for this rule alone. Absent means the table decides, which is every
    /// rule written before this field existed.
    ///
    /// The table's scope answers for the COMMAND -- is this push going
    /// somewhere public -- and one answer cannot fit every rule consulted
    /// behind it. A private-name check belongs only where the destination is
    /// public; host identity in a pull-request body is worth refusing
    /// whatever the destination, because a private forge repository is still
    /// somebody else's infrastructure with its own retention. Two workspaces
    /// held that second class of rule in a hand-rolled agent hook, standing
    /// OUTSIDE the shim to escape its table's `public-target`, re-invoking
    /// this binary for the same two rules the policy already declared --
    /// which is the same rule twice, free to disagree.
    #[serde(default)]
    pub scope: Option<crate::shim::Scope>,
}

impl CommandWhere {
    /// Does this rule stand in front of `command` invoked as `argv`?
    ///
    /// The command must be the command; the subcommand words must appear in
    /// order after it.
    ///
    /// `"gh"` catches every `gh`, `"gh pr"` catches create and edit alike, and
    /// `"gh pr create"` catches one. In ORDER rather than adjacent, because
    /// `gh -R acme/x pr create` puts two words between the command and its
    /// subcommand and a reader writing `gh pr create` should not have to know
    /// that, or where the next release will put its flags.
    pub(crate) fn matches(&self, command: &str, argv: &[String]) -> bool {
        if self.before.is_empty() {
            return false;
        }
        self.before.iter().any(|wanted| {
            let mut wanted = wanted.split_whitespace();
            // The first word is the command itself and is matched exactly. A
            // subsequence match there would let `git` satisfy a rule written
            // for `gh`.
            if wanted.next() != Some(command) {
                return false;
            }
            let mut remaining = argv.iter().filter(|word| !word.starts_with('-'));
            wanted.all(|word| remaining.any(|got| got == word))
        })
    }
}

/// What a policy inherits, named set by set.
///
/// `sets` is a list and nothing else: the old `use_default = true` shorthand
/// took every bundled set without naming one, so what a repository inherited
/// was not written in the repository. Naming the sets is cheap, and each is
/// a separate decision -- `unmanaged-pins` refuses a shape a repository that
/// vendors deliberately has on purpose, `host-identity` shells out to read the
/// running machine, and `captured-fixtures` refuses a script a parser's own
/// test corpus is made of. None of those arguments should stand between anyone
/// and `process-residue`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Inherit {
    /// Bundled rule sets, by what they refuse: `process-residue`,
    /// `credentials`, `unmanaged-pins`, `host-identity`, `broken-links`,
    /// `captured-fixtures`, `doc-claims`, `default-token-grant`. [`BUNDLED`] is the list; this is a
    /// reader's copy of it, and the error a wrong name gets is built from the
    /// array.
    #[serde(default)]
    pub sets: Vec<String>,
    /// Extra policy files, repository-relative. Merged after the bundled sets
    /// and before the repository's own rules, in the order written.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Ids dropped from everything inherited. A repository's own rule of the
    /// same id overrides instead, which is the other half of the same choice.
    #[serde(default)]
    pub disabled_rules: Vec<String>,
}

/// Where a rule in a loaded policy came from.
///
/// Not a field either -- nothing in a file says it, because a file cannot: the
/// answer is which file the loader was reading, and only the loader knows. It
/// exists because a rule with no `git.hooks` line anywhere in the repository
/// can still refuse a commit, and a refusal that cannot say where the rule came
/// from is astonishment by construction. It is also what makes a hand-copied
/// base rule detectable at all: "this id belongs to a set" and "this repository
/// wrote it out itself" are the two halves, and without provenance the second
/// half is unrepresentable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum Origin {
    /// Written in the repository's own policy file.
    #[default]
    Own,
    /// Inherited from a bundled base set, named by the set.
    Set(String),
    /// Inherited from an `inherit.paths` entry, named by the path as written.
    Path(String),
}

impl Origin {
    /// The bundled set this rule arrived from, if it arrived from one.
    pub(crate) fn set(&self) -> Option<&str> {
        match self {
            Self::Set(name) => Some(name),
            Self::Own | Self::Path(_) => None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyFile {
    /// What a BUNDLED set is allowed to install. Refused in any other file --
    /// see [`SetHeader`].
    #[serde(default)]
    pub set: Option<SetHeader>,
    /// Who this repository belongs to, declared once for the whole policy.
    ///
    /// Identity is a property of the repository and not of any one rule, and
    /// this is the field that makes that true. It exists because a rule
    /// arriving from a bundled set cannot be given a parameter -- the only way
    /// to set one is to write the rule out again, which is the transcription
    /// `no-hand-copied-base-rule` refuses. So the guard asks the POLICY who
    /// this is, and inheriting a set never decides that on the repository's
    /// behalf.
    #[serde(default)]
    pub owner: Option<String>,
    /// Whether what this repository publishes is visible to everyone, declared
    /// once for the whole policy.
    ///
    /// Here for the reason [`PolicyFile::owner`] is here, and it is the same
    /// kind of fact: a property of the repository rather than of any one rule
    /// in it, and the only form in which a rule arriving from a bundled set can
    /// be told. `public`, `private` or `internal`; anything else is refused at
    /// load rather than at the moment a guard needs it.
    ///
    /// The value that is NOT accepted is silence. A guard whose whole scope
    /// condition is "is this repository public" cannot answer from a policy
    /// that never says, and the fallback -- asking the forge -- is a network
    /// call that answers `unknown` on a train, in CI without a token, and for
    /// a repository whose visibility is about to change. See
    /// `guard::names::target_is_public`.
    #[serde(default)]
    pub visibility: Option<String>,
    /// A command whose stdout is this repository's owner.
    ///
    /// The duplication is measured rather than asserted: across one fleet, 78
    /// policy files declare an `owner` for seven distinct values -- 41 copies of
    /// one string inside a single organisation. That is a workspace fact
    /// transcribed once per repository, and it is the same shape
    /// [`PolicyFile::private_owners_from`] already answered by reading from
    /// outside the tree.
    ///
    /// It is NOT permission to derive the owner from `origin`. Deriving it is
    /// the defect rather than the fix -- repointing `origin` at somebody else's
    /// remote is the exact accident `prevent-public-push` exists to catch, and a
    /// derived allow-list is repointed by the same command. This field moves a
    /// DECLARATION out of the tree; it never reads one off the thing being
    /// guarded.
    ///
    /// Refused beside a literal `owner`, and refused in a bundled set or an
    /// inherited file. See [`refuse_two_statements_of_one_fact`] and
    /// [`refuse_inherited_declaration`].
    #[serde(default)]
    pub owner_from: Option<String>,
    /// A command whose stdout is this repository's visibility.
    ///
    /// Same mechanism as [`PolicyFile::owner_from`], for a host the built-in
    /// lookup does not speak to or a workspace that would rather answer from a
    /// cached organisation index than a request per repository. The word it
    /// prints is held to `public`, `private` or `internal` exactly as a written
    /// one is.
    ///
    /// What it must not become is a probe. This is a declaration read from
    /// somewhere else, and a command that asks a forge what a repository is
    /// TODAY hands the private-name family's one scope condition to a network
    /// call -- which answers nothing on a train, nothing in CI without a token,
    /// and answers about the visibility a repository is in the middle of
    /// changing. So a command that cannot answer must fail, and failing is exit
    /// 2: a quiet `private` would stand the whole family down, which is
    /// fail-open on the one rule family where fail-open is unacceptable.
    #[serde(default)]
    pub visibility_from: Option<String>,
    /// A command whose output lists the owners this workspace treats as
    /// private, declared once for the whole policy.
    ///
    /// The same argument again, and the measurement behind it: across the fleet
    /// this was promoted from, ten repositories declared
    /// `private_owners_from` and every one of them declared the SAME command.
    /// That is one workspace-level fact written out ten times, and a rule
    /// arriving from a set has no other way to reach it.
    #[serde(default)]
    pub private_owners_from: Option<String>,
    /// Whether the machine running this policy may legitimately not have the
    /// source `private_owners_from` names.
    ///
    /// `false` -- the default -- makes an unreadable source exit 2, because a
    /// rule with no owners refuses nothing and would report a clean tree over a
    /// list it could not read.
    ///
    /// `true` exists for one shape and should be written for no other: a policy
    /// in a repository other people CLONE, naming a source that is one
    /// operator's. There the default refuses every clone's first commit, and
    /// the usual workaround -- a command that swallows its own failure -- loses
    /// the check silently and permanently. This is the third answer: the source
    /// failing is reported, on stderr, naming the two forms that stop being
    /// checked without it.
    #[serde(default)]
    pub private_owners_optional: bool,
    /// The hosts this repository's documents cite that carry no repository the
    /// private-name guards need an answer about.
    ///
    /// A policy field rather than a rule one for the reason
    /// `private_owners_from` is: a rule arriving from a bundled set cannot be
    /// handed a parameter, and which hosts a repository's own bibliography
    /// names is a property of the repository rather than of one rule in it.
    ///
    /// Host globs, matched case-insensitively -- `"doi.org"`, `"*.sr.ht"`. What
    /// is NOT named here and is not GitHub is could-not-look and exits 2,
    /// because the tool cannot tell whether `git.acme.example/acme/secret` is
    /// private and silence would read as clean.
    #[serde(default)]
    pub foreign_hosts: Vec<String>,
    #[serde(default)]
    pub inherit: Option<Inherit>,
    /// Print the RULE and the location of each hit without the matched text.
    ///
    /// For the tree where a finding is itself the secret: a `forbidden_literals`
    /// rule refusing a hostname prints that hostname into a CI log every time it
    /// fires, and the log is read by more people than the file was. Off by
    /// default, because a finding a reader cannot see the text of is one they
    /// have to reproduce locally before they can act on it.
    #[serde(default)]
    pub redact_matches: bool,
    /// The default script constraint for every file no scoped rule selects.
    /// Values are UTS #24 script names, as `\p{Script=Latin}` spells them.
    #[serde(default)]
    pub allowed_scripts: Vec<String>,
    /// `[rule.<id>]` sections. A map rather than an array because the id IS
    /// the key: two sections with one id are a TOML parse error, and there is
    /// no `[rule.files]` floating free to bind to whatever `[[rule]]` happened
    /// to be written above it. Iteration order is id order, which is
    /// deterministic where file order was merely incidental.
    /// A rule is deserialized flat and READ as one check by `parse`, which is
    /// the first moment an id exists to name in a refusal. Nothing outside
    /// `parse` looks at this map; `rules` is what the rest of the crate reads.
    #[serde(default, rename = "rule")]
    written: BTreeMap<String, Written>,
    /// The same sections, each read as exactly one check.
    #[serde(skip)]
    pub rules: BTreeMap<String, Rule>,
    #[serde(default, rename = "shim")]
    pub shims: Vec<crate::shim::Shim>,
    /// Whether every path-baseline entry must say who excused it and why.
    ///
    /// Off by default, and the default is not neutrality -- it is what every
    /// existing baseline file already is. A repository turns it on when its
    /// baselines stop being one homogeneous debt with a header explaining all
    /// of it, and start holding entries that differ from each other. The
    /// `.ljust(` case is the shape: one call site should take the dependency
    /// and another is correct as it stands, and no pattern separates them, so
    /// the entry that excuses the second has to carry the judgement or the
    /// judgement is nowhere.
    ///
    /// Policy-level rather than per-rule, because "may an exemption be
    /// anonymous" is one answer a repository gives once. Per-rule it would be a
    /// setting every new baseline has to remember, which is the same as not
    /// having it.
    #[serde(default)]
    pub baselines_signed: bool,
}

/// The ceiling on what one bundled set may install, declared in the set.
///
/// A set ships compiled into the binary, so a rule added to one starts running
/// in every repository that inherits it with NOTHING IN ANY TREE TO REVIEW. For
/// a content rule that is a finding somebody argues about; for a guard it is a
/// commit refused in up to sixty-five repositories on the strength of a version
/// bump. The constraint that makes the difference safe -- "a new guard gets a
/// new set name rather than joining an existing one" -- was written down as a
/// risk to hold, which is another way of saying nothing enforced it.
///
/// This is the enforcement, and it is deliberately a DECLARATION rather than a
/// derivation. `stages` is what this set is permitted to install, and a rule in
/// it declaring any hook outside that list is refused at load: the set cannot
/// quietly grow a `pre-commit` guard, because doing so means editing a line
/// that says in words what the set is allowed to do. An empty list -- the
/// default -- is a content-only set, which is what seven of the twelve
/// bundled sets are.
///
/// It is refused in a repository's own policy and in an `inherit.paths` file.
/// Nothing there ships compiled in, so nothing there has the problem, and a
/// field that looks like a permission but constrains nothing is worse than no
/// field at all.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetHeader {
    /// Git hook stages the rules in this set may declare. Empty means none:
    /// the set carries content rules only.
    #[serde(default)]
    pub stages: Vec<String>,
    /// `command.before` lines the rules in this set may name, verbatim. Empty
    /// means none: the set stands in front of no command.
    ///
    /// The same ceiling as `stages`, for the seam `stages` cannot see. A rule
    /// joining a set with `command.before = ["gh"]` starts being consulted in
    /// front of a real command in every inheriting repository on the strength
    /// of a version bump, which is exactly the arrival the stage ceiling
    /// exists to make a visible diff. Verbatim lines rather than command
    /// names, because a rule's entry is a line -- `"git push"` and `"git"`
    /// are different reaches, and a ceiling that matched on the first word
    /// would let a set widen from one to the other without editing the line
    /// that says what it may do.
    ///
    /// What this ceiling deliberately does NOT grant: a shim. A set's rule
    /// reaches a command only through a `[[shim]]` the repository declared
    /// itself, and inheriting a set in a repository that has not declared one
    /// is refused at load, naming the table to write. See ADR 0006.
    #[serde(default)]
    pub commands: Vec<String>,
}

/// A loaded policy: inherited rules merged with the repository's own, ids
/// checked unique across the whole set.
#[derive(Debug, Clone, Default)]
pub(crate) struct Policy {
    /// The file this policy was loaded from, as the caller named it.
    ///
    /// Carried because [`Origin::Own`] means "written in THIS file" and one
    /// guard has to ask git what that file said before the change being
    /// checked. Deriving it from `root` would hardcode `policy/principles.toml`
    /// in a binary whose `--policy` flag exists to say otherwise.
    pub path: PathBuf,
    /// Who this repository belongs to, from the policy file's own `owner`.
    /// See [`PolicyFile::owner`].
    pub owner: Option<String>,
    /// What this repository's publications are visible to, from the policy
    /// file's own `visibility`. See [`PolicyFile::visibility`].
    pub visibility: Option<String>,
    /// Where the owner is declared when it is not written down, from the policy
    /// file's own `owner_from`. See [`PolicyFile::owner_from`].
    pub owner_from: Option<String>,
    /// Where the visibility is declared when it is not written down, from the
    /// policy file's own `visibility_from`. See [`PolicyFile::visibility_from`].
    pub visibility_from: Option<String>,
    /// What `owner_from` answered, so it is asked at most once per process.
    ///
    /// Two slots and not one map keyed by field name, deliberately: these are
    /// two facts behind two commands, and a single cache filled in one pass
    /// would run the visibility command for a caller that only asked who this
    /// repository belongs to. The resolution itself IS parameterised -- one
    /// [`declared`] reads either -- so what is duplicated here is storage, not a
    /// unit of behaviour.
    ///
    /// Per process rather than on disk. A declaration exists to avoid a stale
    /// answer, and a cache that outlives the run is a stale answer with a
    /// longer life.
    pub resolved_owner: OnceLock<String>,
    /// What `visibility_from` answered. See [`Policy::resolved_owner`].
    pub resolved_visibility: OnceLock<String>,
    /// Where the private-owner list comes from, from the policy file's own
    /// `private_owners_from`. See [`PolicyFile::private_owners_from`].
    pub private_owners_from: Option<String>,
    /// Whether an unreadable private-owner source is a reported gap rather than
    /// exit 2. See [`PolicyFile::private_owners_optional`].
    pub private_owners_optional: bool,
    /// The hosts no name lookup is owed for. See [`PolicyFile::foreign_hosts`].
    pub foreign_hosts: Vec<String>,
    /// Whether a finding prints its matched text. See
    /// [`PolicyFile::redact_matches`].
    pub redact_matches: bool,
    /// Whether every path-baseline entry must be signed. See
    /// [`PolicyFile::baselines_signed`].
    pub baselines_signed: bool,
    pub allowed_scripts: Vec<String>,
    pub rules: Vec<Rule>,
    pub shims: Vec<crate::shim::Shim>,
    /// The bundled sets this policy named, in the order it named them.
    ///
    /// Not derivable from `rules`: a set every one of whose rules the
    /// repository shadows or disables leaves no rule behind carrying its name,
    /// and "inherited and overridden" is precisely the case a check about
    /// hand-copied rules must stay silent about.
    pub inherited_sets: Vec<String>,
}

impl Policy {
    /// Who this repository belongs to, as this policy declares it.
    ///
    /// The written `owner` if there is one, else whatever `owner_from` answers,
    /// else nothing -- and "nothing" is what makes a caller fall back to the
    /// remote, which every caller of this is careful to say out loud.
    ///
    /// A rule's own `owner` is NOT consulted here. It is narrower than the
    /// policy's on purpose, so the rule reads it first and reaches this only
    /// when it has none.
    pub(crate) fn declared_owner(&self, root: &Path) -> Result<Option<String>> {
        declared(
            root,
            "owner",
            self.owner.as_deref(),
            self.owner_from.as_deref(),
            &self.resolved_owner,
        )
    }

    /// What this repository's publications are visible to, as this policy
    /// declares it, held to the three spellings whichever way it arrived.
    ///
    /// A written `visibility` was already held to them at load, where a typo is
    /// a diff somebody can fix. A command's answer cannot be checked then --
    /// there is no answer until it runs -- so it is checked here, and the
    /// refusal names the command rather than the file, because the file is
    /// right and the thing it points at is not.
    pub(crate) fn declared_visibility(&self, root: &Path) -> Result<Option<String>> {
        let value = declared(
            root,
            "visibility",
            self.visibility.as_deref(),
            self.visibility_from.as_deref(),
            &self.resolved_visibility,
        )?;
        if let Some(word) = value.as_deref() {
            if visibility_is_public(word).is_none() {
                return Err(Fatal::new(format!(
                    "`visibility_from` answered {word:?}, which is not a visibility. The \
                     command must print \"public\", \"private\" or \"internal\" -- the word \
                     decides whether the guards that fire only on a published tree fire here \
                     at all, so there is no reading of an unrecognised one that is safe to \
                     guess at."
                )));
            }
        }
        Ok(value)
    }

    /// The bundled set a rule id arrived from, for the one line a reader sees.
    ///
    /// By id, because a refusal carries the id and ids are one namespace --
    /// which is the property `validate_unique` exists to hold.
    pub(crate) fn set_of(&self, id: &str) -> Option<&str> {
        self.rules
            .iter()
            .find(|rule| rule.id == id)
            .and_then(|rule| rule.origin.set())
    }

    pub(crate) fn of_check(&self, check: CheckKind) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(move |rule| rule.is(check))
    }

    /// Whether any rule uses one check kind.
    ///
    /// Test-only, and it is worth saying why rather than deleting it. Its one
    /// caller in the binary was `text::check`, which used "does any
    /// `forbidden_literals` rule exist?" to decide whether to add the built-in
    /// host-identity fallback -- so a repository that declared a literal rule
    /// about something else silently lost the identity check. That question was
    /// the defect, and the fix asks about the identity rule itself instead.
    /// What remains is a fair question for a test about what a set inherits,
    /// and a helper that reads a policy's shape belongs beside the policy.
    #[cfg(test)]
    pub(crate) fn has_check(&self, check: CheckKind) -> bool {
        self.of_check(check).next().is_some()
    }

    /// Every rule that fires at one git hook, in git's own hook names.
    pub(crate) fn at_hook<'a>(&'a self, hook: &'a str) -> impl Iterator<Item = &'a Rule> {
        self.rules.iter().filter(move |rule| rule.runs_at(hook))
    }

    /// Every rule that declares any git hook at all.
    ///
    /// Distinct from `at_hook` returning nothing, and the distinction is the
    /// report: a repository that installed the hook and declared no rule for
    /// this stage should hear that no rule declares a hook, while one with
    /// rules at other stages should hear a clean pass over the zero that apply
    /// here.
    pub(crate) fn at_hook_any(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|rule| !rule.hooks().is_empty())
    }

    /// Every rule standing in front of `command` invoked as `argv`.
    pub(crate) fn before_command<'a>(
        &'a self,
        command: &'a str,
        argv: &'a [String],
    ) -> impl Iterator<Item = &'a Rule> {
        self.rules
            .iter()
            .filter(move |rule| rule.stands_before(command, argv))
    }
}

fn parse(path: &Path, text: &str) -> Result<PolicyFile> {
    let mut file: PolicyFile =
        toml::from_str(text).map_err(|error| Fatal::at(path, error.message()))?;
    // The id is the section header, so it exists here and not in the
    // deserializer -- which is why reading a written rule as one check happens
    // here too: every refusal below names the rule a reader has to go and edit.
    for (id, written) in std::mem::take(&mut file.written) {
        let rule = Rule::of_written(&id, written)?;
        file.rules.insert(id, rule);
    }
    Ok(file)
}

/// A file that is NOT a bundled set may not declare what a bundled set is
/// allowed to install.
///
/// The ceiling exists because a set's rules arrive with no diff in the tree
/// they run in. A repository's own policy has the opposite property -- every
/// rule in it is a line somebody committed -- so a `[set]` header there would
/// be a permission granted to the author by the author, which is not a
/// permission. Refused rather than ignored: a field read by nothing is the
/// shape this schema exists to make unrepresentable.
/// Refuse a file that states one repository fact twice.
///
/// The whole argument for reading a declaration from outside the tree is that
/// the fact has ONE place it is written. A file carrying `owner` and
/// `owner_from` has kept the copy the field exists to remove, and nothing
/// anywhere reconciles the two -- so the day they disagree is a day one of them
/// is silently wrong and the guard reading it cannot tell.
///
/// At load, like the visibility spelling above it, because it is a fact about
/// the file rather than about any run of any hook.
fn refuse_two_statements_of_one_fact(path: &Path, file: &PolicyFile) -> Result<()> {
    for (field, literal, from) in [
        ("owner", file.owner.is_some(), file.owner_from.is_some()),
        (
            "visibility",
            file.visibility.is_some(),
            file.visibility_from.is_some(),
        ),
    ] {
        if literal && from {
            return Err(Fatal::at(
                path,
                format!(
                    "`{field}` and `{field}_from` are both declared, and they are two \
                     statements of one fact -- free to disagree, with nothing here to notice \
                     when they do. Keep the one that is true of every checkout of this \
                     repository: `{field}_from` where the value belongs to the workspace, \
                     `{field}` where it belongs to the repository. Delete the other"
                ),
            ));
        }
    }
    Ok(())
}

/// Refuse a command that speaks for a repository from a file that repository
/// did not write.
///
/// `owner_from` and `visibility_from` run a shell command. A bundled set
/// carrying one would run it in every inheriting repository on the strength of a
/// version bump, with nothing in any of those trees to review -- which is the
/// reason `private-names` already gives for not shipping `private_owners_from`,
/// and it is not weakened by the command being one line shorter.
///
/// Refused rather than dropped. `owner` and `visibility` in an inherited file
/// are read by nothing and say nothing about it, which is the shape this
/// repository refuses everywhere else; those two are load-bearing in trees that
/// already exist, and these two are new and can start correct.
fn refuse_inherited_declaration(path: &Path, file: &PolicyFile, kind: &str) -> Result<()> {
    for field in ["owner_from", "visibility_from"] {
        let declared = match field {
            "owner_from" => file.owner_from.is_some(),
            _ => file.visibility_from.is_some(),
        };
        if declared {
            return Err(Fatal::at(
                path,
                format!(
                    "`{field}` runs a shell command and this file is {kind}. A command \
                     arriving that way runs in every repository that inherits it on the \
                     strength of a version bump, with nothing in any of those trees to \
                     review -- which is why a set does not ship `private_owners_from` \
                     either. Write the line in the repository's own policy file"
                ),
            ));
        }
    }
    Ok(())
}

fn refuse_set_header(path: &Path, file: &PolicyFile) -> Result<()> {
    if file.set.is_some() {
        return Err(Fatal::at(
            path,
            "`[set]` declares what a BUNDLED rule set may install, and this file is not one. \
             A rule here runs because this repository wrote it down, which is the review a \
             set header exists to stand in for. Drop the table",
        ));
    }
    Ok(())
}

/// Parse one bundled set and hold it to its own declared ceiling.
///
/// The one place a bundled set is read, so the ceiling cannot be skipped by a
/// caller that forgot it existed -- `load`, `bundled_set` and `bundled_ids` all
/// arrive here.
fn parse_bundled(name: &str, text: &str) -> Result<PolicyFile> {
    let path = Path::new("<bundled>").join(format!("{name}.toml"));
    let file = parse(&path, text)?;
    refuse_inherited_declaration(&path, &file, "a bundled set")?;
    // A set supplies checkers and never shims. A `[[shim]]` is a program
    // standing in front of a real command, and only `.rules` is adopted from a
    // set -- so a shim written here would vanish silently, which is worse than
    // either answer. The repository declares the shim; the set may only name
    // it, inside the `commands` ceiling below.
    if !file.shims.is_empty() {
        return Err(Fatal::at(
            &path,
            format!(
                "a bundled set declares {} `[[shim]]` table(s), and a set may not put a \
                 program in front of a real command. Ship the checker rule inside the \
                 `[set] commands` ceiling and let the repository declare the shim",
                file.shims.len()
            ),
        ));
    }
    let header = file.set.clone().unwrap_or_default();
    for rule in file.rules.values() {
        for line in rule.command.iter().flat_map(|where_| where_.before.iter()) {
            if !header.commands.iter().any(|entry| entry == line) {
                return Err(Fatal::at(
                    &path,
                    format!(
                        "rule {:?} names {line:?} in `command.before`, and the set's \
                         `[set] commands` admits {}. A set ships compiled in, so a rule \
                         joining one starts standing in front of a real command in every \
                         repository that inherits it with nothing in any tree to review. \
                         Give it a new set named for what it checks, or widen `commands` \
                         -- which is a line a reader of this file will see.",
                        rule.id,
                        if header.commands.is_empty() {
                            String::from("no command at all")
                        } else {
                            format!("only {}", header.commands.join(", "))
                        }
                    ),
                ));
            }
        }
    }
    let allowed = header.stages;
    for rule in file.rules.values() {
        for hook in rule.hooks() {
            if !allowed.iter().any(|stage| stage == hook) {
                return Err(Fatal::at(
                    &path,
                    format!(
                        "rule {:?} declares the {hook:?} hook, and the set's `[set] stages` \
                         admits {}. A set ships compiled in, so a guard joining one starts \
                         refusing work in every repository that inherits it with nothing in \
                         any tree to review. Give the guard a new set named for what it \
                         refuses, or widen `stages` -- which is a line a reader of this file \
                         will see.",
                        rule.id,
                        if allowed.is_empty() {
                            String::from("no hook at all")
                        } else {
                            format!("only {}", allowed.join(", "))
                        }
                    ),
                ));
            }
        }
    }
    Ok(file)
}

/// One repository-level fact, read from a command instead of written down.
///
/// Shared by `owner_from` and `visibility_from` because those differ only in
/// which fact they carry. One function, so the trimming, the refusal of a second
/// line and the words a failure prints are stated once and cannot drift into two
/// slightly different contracts.
///
/// There is deliberately no `..._optional` escape hatch here, and the asymmetry
/// with `private_owners_from` is the point. An unreadable private-owner list
/// degrades to a NARROWER check, which can be reported and lived with. An
/// unreadable owner degrades to the owner read off `origin` -- the tautology
/// `prevent-public-push` exists to refuse -- and an unreadable visibility
/// degrades to the forge's answer about a visibility that is about to change.
/// Neither of those is a degradation anybody should be able to opt into.
fn read_declaration(root: &Path, field: &str, command: &str) -> Result<String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(root)
        .output()
        .map_err(|error| Fatal::new(format!("`{field}`: could not run {command:?}: {error}")))?;
    if !output.status.success() {
        return Err(Fatal::new(format!(
            "`{field}` ran {command:?}, which exited {}: {}\n\nA source that failed declared \
             nothing, and what a missing declaration falls back to is the thing this field \
             exists to replace: the owner read off `origin`, or the forge's view of a \
             visibility that is about to change. Fix the source, or write the value down.",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // Blank lines are dropped before the count, and that is the contract rather
    // than an oversight in it: the rule is one VALUE, not one line of output. A
    // trailing blank line is what `cat` gives back for a file that ends with
    // one, and counting it would make this field refuse the exact shape it
    // exists for. Two non-empty lines are still two answers and still refused.
    let mut values = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let Some(value) = values.next() else {
        return Err(Fatal::new(format!(
            "`{field}` ran {command:?}, which exited 0 and printed nothing. Silence is not an \
             answer here: it would leave this repository having declared nothing while the \
             policy file reads as though it had declared something."
        )));
    };
    if values.next().is_some() {
        return Err(Fatal::new(format!(
            "`{field}` ran {command:?}, which printed more than one value. This is one fact \
             about one repository, and taking the first would pin the repository to whatever \
             the command happened to print first. Narrow it to the single value."
        )));
    }
    Ok(value.to_owned())
}

/// A declared fact: the written value, else the command's answer, else nothing.
///
/// The command runs on the first ask and never again, because the guards ask
/// more than once -- the private-name family asks about visibility three times,
/// once per variant -- and a workspace that answers with an organisation index
/// is paying for a forge round trip each time.
fn declared(
    root: &Path,
    field: &str,
    literal: Option<&str>,
    from: Option<&str>,
    cache: &OnceLock<String>,
) -> Result<Option<String>> {
    if let Some(value) = literal {
        return Ok(Some(value.to_owned()));
    }
    let Some(command) = from else {
        return Ok(None);
    };
    if let Some(cached) = cache.get() {
        return Ok(Some(cached.clone()));
    }
    let value = read_declaration(root, &format!("{field}_from"), command)?;
    // `set` can only lose to a caller that filled the slot first, and that
    // caller ran the same command against the same tree, so the loser's answer
    // is the winner's answer.
    Ok(Some(cache.get_or_init(|| value).clone()))
}

/// Is a declared visibility one that means "everyone can read this"?
///
/// `None` where the word is not a visibility at all. One function because the
/// spelling is checked at LOAD, where a typo is a diff somebody can fix, and
/// read again by the guard that fires on the answer -- and two readings of one
/// word are two chances for `Public` and `public` to disagree.
pub(crate) fn visibility_is_public(value: &str) -> Option<bool> {
    match value.to_lowercase().as_str() {
        "public" => Some(true),
        "private" | "internal" => Some(false),
        _ => None,
    }
}

/// Load a policy file, resolving `[inherit]` and validating the result.
pub(crate) fn load(root: &Path, policy_path: &Path) -> Result<Policy> {
    let text = read_to_string(policy_path)?;
    let file = parse(policy_path, &text)?;
    refuse_set_header(policy_path, &file)?;
    refuse_two_statements_of_one_fact(policy_path, &file)?;
    // Checked here rather than where a guard reads it. A misspelt visibility is
    // a fact about the file, and hearing about it when a hook fires means
    // hearing about it from whichever seam happened to run first, months after
    // the line was written.
    if let Some(declared) = file.visibility.as_deref() {
        if visibility_is_public(declared).is_none() {
            return Err(Fatal::at(
                policy_path,
                format!(
                    "`visibility` is {declared:?}, which is not a visibility. Write \
                     \"public\", \"private\" or \"internal\" -- the word decides whether the \
                     guards that fire only on a published tree fire here at all"
                ),
            ));
        }
    }
    let inherit = file.inherit.clone().unwrap_or_default();

    let mut inherited: Vec<Rule> = Vec::new();

    for name in &inherit.sets {
        let bundled = BUNDLED
            .iter()
            .find(|(bundled_name, _)| *bundled_name == name)
            .ok_or_else(|| {
                let known: Vec<&str> = BUNDLED.iter().map(|(bundled, _)| *bundled).collect();
                Fatal::at(
                    policy_path,
                    format!(
                        "unknown bundled rule set {name:?}; this binary ships {}",
                        known.join(", ")
                    ),
                )
            })?;
        inherited.extend(
            parse_bundled(name, bundled.1)?
                .rules
                .into_values()
                .map(|mut rule| {
                    rule.origin = Origin::Set(name.clone());
                    rule
                }),
        );
    }

    for relative in &inherit.paths {
        let path = root.join(relative);
        let extended = read_to_string(&path)?;
        let parsed = parse(&path, &extended)?;
        refuse_set_header(&path, &parsed)?;
        refuse_inherited_declaration(&path, &parsed, "an inherited file")?;
        // Refused rather than merged, and refused rather than ignored. Only
        // `.rules` is merged below, so an inherited `[[shim]]` used to vanish --
        // and vanish in the worst possible way, because the `exec` rule that
        // came with it survived, and `validate_shims` then reported that rule's
        // `command.before` as naming a shim nobody declared. The author would be
        // told to declare the shim they had in fact declared. Merging is the
        // other available answer and it is not obviously right: a shim is the
        // thing that stands in front of a command, and inheriting one silently
        // puts a program in front of `git` on the strength of a path in an
        // `[inherit]` line. Until that is a decision somebody makes on purpose,
        // say so here.
        if !parsed.shims.is_empty() {
            return Err(Fatal::at(
                policy_path,
                format!(
                    "{} declares {} `[[shim]]` table(s), and an inherited file's shims are \
                     not adopted. A shim stands in front of a real command, which is not \
                     something to acquire by inheriting a path. Move the `[[shim]]` into \
                     this file",
                    path.display(),
                    parsed.shims.len()
                ),
            ));
        }
        inherited.extend(parsed.rules.into_values().map(|mut rule| {
            rule.origin = Origin::Path(relative.clone());
            rule
        }));
    }

    // The policy-level host globs, held to the same spelling the rule-level
    // ones are held to and at the same moment. A glob that will not compile is
    // a host nobody quieted, and finding that out at a pre-push is finding it
    // out from the wrong seam.
    for host in &file.foreign_hosts {
        if let Err(error) = globset::Glob::new(&host.to_lowercase()) {
            return Err(Fatal::at(
                policy_path,
                format!(
                    "`foreign_hosts` entry {host:?} is not a host glob ({error}). Entries \
                     are hostnames, optionally globbed -- \"doi.org\", \"*.sr.ht\""
                ),
            ));
        }
    }

    let own_ids: Vec<&str> = file.rules.keys().map(String::as_str).collect();
    let disabled = &inherit.disabled_rules;

    report_reshaped_shadows(&inherited, &file.rules);

    let mut rules: Vec<Rule> = inherited
        .into_iter()
        .filter(|rule| !disabled.contains(&rule.id) && !own_ids.iter().any(|own| *own == rule.id))
        .collect();
    rules.extend(file.rules.values().cloned());

    // A permission over a source that does not exist. It reads as though the
    // policy has thought about an absent private-owner list, and there is no
    // list to be absent -- the same failure a parameter on a rule that cannot
    // read it is refused for.
    //
    // Asked HERE, after the merge, and not beside the other file-level checks
    // near the top. Up there only `file.rules` exists, so a policy that
    // declares the source on a rule inside an `inherit.paths` file was refused
    // with a sentence saying no source is declared anywhere -- which was false
    // of exactly the shape it refused. The question is about the whole resolved
    // policy, so it has to be asked of the whole resolved policy.
    if file.private_owners_optional
        && file.private_owners_from.is_none()
        && !rules
            .iter()
            .any(|rule| rule.private_owners_from().is_some())
    {
        return Err(Fatal::at(
            policy_path,
            "`private_owners_optional` is set and no `private_owners_from` is declared \
             anywhere in this policy -- not here, not in an inherited file -- so it permits \
             a failure that cannot happen. Declare the source, or drop the line",
        ));
    }

    // A disabled id that names nothing is the same failure as a stale baseline
    // entry: it reads as a decision that is doing something and it is doing
    // nothing, and it will keep reading that way after the rule it named is
    // gone.
    let inheritable: Vec<String> = {
        let mut names = Vec::new();
        for name in &inherit.sets {
            if let Some((_, bundled)) = BUNDLED.iter().find(|(bundled, _)| *bundled == name) {
                names.extend(parse_bundled(name, bundled)?.rules.into_keys());
            }
        }
        for relative in &inherit.paths {
            let path = root.join(relative);
            let extended = read_to_string(&path)?;
            names.extend(parse(&path, &extended)?.rules.into_keys());
        }
        names
    };
    for id in disabled {
        if !inheritable.contains(id) {
            return Err(Fatal::at(
                policy_path,
                format!("`inherit.disabled_rules` names {id:?}, which nothing inherited defines"),
            ));
        }
    }

    validate_unique(policy_path, &rules)?;
    for rule in &rules {
        rule.validate()?;
    }
    validate_shim_commands(policy_path, &file.shims)?;
    validate_shim_verbs(policy_path, &file.shims)?;
    validate_shim_unresolved(policy_path, &rules, &file.shims)?;
    validate_shims(policy_path, &rules, &file.shims)?;
    // Last, and after `rule.validate`, because this one reads a rule as the
    // author meant it. A rule naming two checks or carrying a parameter its
    // check cannot read is not yet a rule whose pattern means anything, and
    // reporting a self-match on one would answer a question nobody had reached
    // -- the structural refusal is the finding there, and it has to arrive
    // first.
    validate_no_self_match(root, policy_path, &rules)?;

    Ok(Policy {
        path: policy_path.to_path_buf(),
        owner: file.owner.clone(),
        visibility: file.visibility.clone(),
        owner_from: file.owner_from.clone(),
        visibility_from: file.visibility_from.clone(),
        resolved_owner: OnceLock::new(),
        resolved_visibility: OnceLock::new(),
        private_owners_from: file.private_owners_from.clone(),
        private_owners_optional: file.private_owners_optional,
        foreign_hosts: file.foreign_hosts.clone(),
        redact_matches: file.redact_matches,
        baselines_signed: file.baselines_signed,
        allowed_scripts: file.allowed_scripts,
        rules,
        shims: file.shims,
        inherited_sets: inherit.sets.clone(),
    })
}

/// Say so when a repository's own rule takes an inherited id and checks
/// something else with it.
///
/// Overriding an inherited rule is documented and supported: write the id
/// yourself and yours wins. What this reports is the narrower case where the
/// override changes the CHECK -- a `regexp` where the set ships a `builtin` --
/// because the two are not versions of one rule. The builtin is compiled in and
/// moves when the binary moves; a regex copy of it is frozen at the moment it
/// was typed, and it is invisible to every check uphold has: the id is present,
/// the claim resolves, and `uphold check` reconciles green over a rule that has
/// silently stopped being the rule it names.
///
/// A note on stderr and not a refusal, deliberately. A repository may have a
/// reason to hold a narrower copy, and turning that into a hard failure at load
/// would break the tree of anyone who has one before they have read a word
/// about why. It is the report that has to exist before a set carrying guards
/// can ship -- without it, inheriting the set hides the fork behind it.
fn report_reshaped_shadows(inherited: &[Rule], own: &BTreeMap<String, Rule>) {
    for rule in inherited {
        let Some(mine) = own.get(&rule.id) else {
            continue;
        };
        let (theirs, ours) = (rule.kind(), mine.kind());
        if theirs == ours {
            continue;
        }
        let from = match &rule.origin {
            Origin::Set(name) => format!("the bundled set {name:?}"),
            Origin::Path(path) => format!("the inherited file {path:?}"),
            Origin::Own => continue,
        };
        eprintln!(
            "uphold: {id:?} in this policy shadows {from}, which checks {theirs} where this \
             one checks {ours}. An override that changes the check is a private copy of the \
             rule, not a setting on it: the inherited one moves with the binary and this one \
             does not. Rename it, or drop it and take the inherited rule with \
             `inherit.disabled_rules` if what you want is neither.",
            id = rule.id,
        );
    }
}

/// One bundled set: its name, its ceiling, and its rules.
#[derive(Debug, Clone)]
pub(crate) struct BundledSet {
    pub name: String,
    /// The hook stages this set is allowed to install. See [`SetHeader`].
    pub stages: Vec<String>,
    /// The `command.before` lines this set is allowed to name. See
    /// [`SetHeader`].
    pub commands: Vec<String>,
    pub rules: Vec<Rule>,
}

/// The rules one bundled set ships, for `uphold rules --set <name>`.
///
/// The set names are the adoption surface: a stranger decides whether to
/// inherit one from its name, and this is what lets the binary answer "what is
/// in it" without a docs round-trip -- the name must predict the rule list,
/// and here is the rule list.
pub(crate) fn bundled_set(name: &str) -> Result<BundledSet> {
    let Some((_, bundled)) = BUNDLED
        .iter()
        .find(|(bundled_name, _)| *bundled_name == name)
    else {
        let known: Vec<&str> = BUNDLED.iter().map(|(bundled, _)| *bundled).collect();
        return Err(Fatal::new(format!(
            "no bundled rule set is called {name:?}; this binary ships {}",
            known.join(", ")
        )));
    };
    let file = parse_bundled(name, bundled)?;
    let header = file.set.clone().unwrap_or_default();
    Ok(BundledSet {
        name: name.to_owned(),
        stages: header.stages,
        commands: header.commands,
        rules: file
            .rules
            .into_values()
            .map(|mut rule| {
                rule.origin = Origin::Set(name.to_owned());
                rule
            })
            .collect(),
    })
}

/// Every bundled set, in the order the binary ships them.
///
/// The whole of what a version of this binary would install in a repository
/// that inherited everything -- which is the document `rules --sets --json`
/// prints and `policy/base/sets.lock.json` holds, so that a set changing shape
/// between two versions is a diff somebody reads rather than a behaviour change
/// with no diff anywhere.
pub(crate) fn bundled_sets() -> Result<Vec<BundledSet>> {
    BUNDLED.iter().map(|(name, _)| bundled_set(name)).collect()
}

/// Which bundled set owns each id, and what else that set brings.
///
/// The question a hand-copied rule is detected by, and it has to be asked of
/// the binary rather than of a list somebody keeps: a set gaining a rule with
/// nobody updating a table elsewhere is the drift this whole file exists to
/// make impossible.
pub(crate) fn bundled_ids() -> Result<Vec<(&'static str, Vec<String>)>> {
    BUNDLED
        .iter()
        .map(|(name, text)| {
            Ok((
                *name,
                parse_bundled(name, text)?.rules.into_keys().collect(),
            ))
        })
        .collect()
}

/// One flat namespace, checked here and nowhere else.
///
/// This is the property that let the `tier` field go. A claim named a principle,
/// a tier and that tier's own rule id, and the tier existed only to say which
/// namespace the id lived in; ids unique across every kind mean the id alone
/// resolves, so the disambiguator has nothing left to disambiguate.
///
/// Within ONE file the check has nothing left to do: `[rule.<id>]` made a
/// duplicate id a TOML parse error. What remains representable is a collision
/// ACROSS files -- two `[inherit] paths` entries defining the same id -- and
/// this is the only thing that detects it. (A repository rule sharing an
/// inherited id is not a collision; it shadows, and was filtered above.)
/// A rule whose pattern matches its own declaration.
///
/// A policy file is a tracked file, so a rule's own `regexp` is inside the
/// corpus that rule scans. An unanchored literal therefore matches the line it
/// is written on, and the run reports the policy file as violating the rule the
/// policy file defines. The report names a real path and a real line and is
/// about nothing in the tree, which is the most expensive kind of finding to
/// read: a reader has to work out that the rule is describing itself.
///
/// It is refused here rather than reported at scan time for the reason
/// [`validate_shims`] gives about its own pair -- at run time this is a
/// violation like any other, and load is the only place it can be named as what
/// it is.
///
/// **What is NOT refused, and why the scope test comes first.** Most rules
/// never select the policy file at all: an `include` of `["cmd", "internal"]`
/// with a `glob` of `["*.go"]` cannot reach it, and a pattern that matches its
/// own text under such a rule is harmless. Measured over 82 policy files and
/// 178 `regexp` rules in one workspace, 54 matched their own declaration
/// textually and none of them selected the file it was written in. Refusing on
/// the text alone would have failed 54 rules that work.
///
/// Anchored patterns are the other quiet half: `^Status:` cannot match
/// `regexp = '^Status:...'`, because that line begins with `regexp`. Nothing
/// special is done for them -- they simply do not match, and the point of
/// saying so is that a `Sta[t]us` written to dodge a self-match it never had is
/// a defensive edit this check would have told the author to delete.
///
/// Own rules only. A rule from a bundled set is declared inside this binary,
/// and a rule from `inherit.paths` in a file this rule may not select; neither
/// has a declaration in `policy_path` to match.
fn validate_no_self_match(root: &Path, policy_path: &Path, rules: &[Rule]) -> Result<()> {
    let Ok(relative) = policy_path.strip_prefix(root) else {
        // A policy outside the tree is not part of the corpus, so no rule can
        // reach it. `--policy` is free to name one.
        return Ok(());
    };
    let Ok(text) = std::fs::read_to_string(policy_path) else {
        // Unreadable here means unreadable a moment ago too, and load has
        // already failed on it with a better message than this one could give.
        return Ok(());
    };

    for rule in rules {
        if rule.origin != Origin::Own {
            continue;
        }
        // Both content searches, and the same accident reaches them in opposite
        // directions. `regexp` must find nothing, so matching its own
        // declaration is a finding that is always there. `require_regexp` must
        // find something, so matching its own declaration is a pass that is
        // always there. The second is the quieter of the two and the worse: a
        // loud finding about the wrong file gets read, and a file that has
        // exempted itself from a requirement is never mentioned again.
        let subject = match (rule.regexp(), rule.require_regexp()) {
            (Some(pattern), _) => SelfMatch::Refuses(pattern),
            (None, Some(pattern)) => SelfMatch::Requires(pattern),
            (None, None) => continue,
        };
        if !crate::selection::selects(root, rule, relative)? {
            continue;
        }
        let Some(section) = declaration_of(&text, &rule.id) else {
            continue;
        };
        let query = crate::engine::Query::from_files(subject.pattern(), rule.files());
        let hits = crate::engine::search_text(&section, &query, &rule.id)?;
        if let Some(hit) = hits.first() {
            return Err(Fatal::at(
                policy_path,
                subject.message(&rule.id, hit.text.trim()),
            ));
        }
    }
    Ok(())
}

/// Which way a rule's own declaration reaches its pattern.
enum SelfMatch<'a> {
    /// `regexp`: the match is a finding, so a self-match is a standing false one.
    Refuses(&'a str),
    /// `require_regexp`: the match is the pass, so a self-match is a standing
    /// exemption for the one file that granted it.
    Requires(&'a str),
}

impl SelfMatch<'_> {
    const fn pattern(&self) -> &str {
        match self {
            Self::Refuses(pattern) | Self::Requires(pattern) => pattern,
        }
    }

    /// The cures are the same three in both directions, and the sentence before
    /// them is not: a reader who is told the wrong thing about what goes wrong
    /// fixes the wrong rule.
    fn message(&self, id: &str, matched: &str) -> String {
        let cures = "Exclude the policy file from this rule with `files.exclude`, narrow \
                     `files.include` to what the rule is about, or anchor the pattern so it \
                     cannot match the key it is written under.";
        match self {
            Self::Refuses(_) => format!(
                "rule {id:?} matches its own declaration ({matched:?}), and it selects the file \
                 that declaration is in. Every run will report this file as violating this rule, \
                 naming a line that is the rule rather than anything in the tree. {cures}"
            ),
            Self::Requires(_) => format!(
                "rule {id:?} has a `require_regexp` that matches its own declaration \
                 ({matched:?}), and it selects the file that declaration is in. That file \
                 satisfies the requirement by naming it, so it is exempt from this rule forever \
                 -- whatever else it does or stops doing. {cures}"
            ),
        }
    }
}

/// The lines of one rule's own `[rule.<id>]` table.
///
/// Its sub-tables belong to it -- `[rule.<id>.files]` is where `exclude` is
/// written, and an author dodging a self-match often puts the pattern's own
/// text there -- so the section runs to the next table that is not one of them.
fn declaration_of(text: &str, id: &str) -> Option<String> {
    let header = format!("[rule.{id}]");
    let sub = format!("[rule.{id}.");
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.iter().position(|line| line.trim() == header)?;
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, line)| {
            let trimmed = line.trim_start();
            trimmed.starts_with('[') && !trimmed.starts_with(&sub)
        })
        .map_or(lines.len(), |(index, _)| index);
    // `get` rather than an index: `end` comes from a search that starts past
    // `start`, so the range holds -- but a slice that can panic is a slice that
    // will, and this one runs over author-written text.
    Some(lines.get(start..end)?.join("\n"))
}

fn validate_unique(policy_path: &Path, rules: &[Rule]) -> Result<()> {
    let mut seen: BTreeMap<&str, CheckKind> = BTreeMap::new();
    for rule in rules {
        if let Some(first) = seen.insert(rule.id.as_str(), rule.kind()) {
            return Err(Fatal::at(
                policy_path,
                format!(
                    "two inherited files define the id {:?} (one checks {}, the other {}). \
                     Rule ids are one namespace: a claim naming this id could not \
                     say which rule it meant.",
                    rule.id,
                    first,
                    rule.kind()
                ),
            ));
        }
    }
    Ok(())
}

/// Every shim has a checker, and every checker has a shim.
///
/// The two halves of one seam, and neither end was checked. A `[[shim]]` no
/// `exec` rule names collects the subjects of an invocation, consults an empty
/// list of checkers, refuses nothing and execs the command: a publication that
/// passed because nothing looked at it, reported as a pass. A
/// `command.before` naming a command no `[[shim]]` declares is the mirror --
/// the shim is the only thing that invokes a checker, so the rule runs nowhere,
/// and `uphold shim` refuses that command outright as undeclared.
///
/// Refused here, beside the refusal of an unknown built-in name and for the
/// same reason: a name that resolves to nothing is a decision that looks made.
/// A load-time refusal is also the only place either can be seen at all --
/// at run time both are silence.
/// One command, one `[[shim]]`.
///
/// The shims are resolved into a map keyed by command name, so a second table
/// naming a command already declared replaced the first and said nothing. Both
/// halves of that are bad and the silence is the worse one: the surviving table
/// is whichever the map happened to keep, and the lost one is a set of verbs the
/// repository believes are guarded.
///
/// Reproduced before this was written. A policy declaring `gh` twice -- once for
/// `pr:create` with `--body`, once for `issue:close` with `--comment` -- loaded
/// clean, refused the comment, and exec'd `gh pr create --body ...` unexamined.
/// Text the author had written a table for reached a forge with nothing in
/// front of it.
///
/// Refused rather than merged, because merging is a guess about which
/// vocabulary wins where the two disagree -- and they disagree exactly where it
/// matters. `-c` is a boolean on `gh pr review` and takes a value on
/// `gh issue close`, so a merged `text_flags` misreads one of them whichever way
/// it is built. One table per command makes that collision visible to whoever
/// writes the second one instead of resolving it silently.
/// Every `[[shim.verbs]]` entry names verbs the table stands in front of.
///
/// A vocabulary for a verb the shim does not match is read by nothing: the
/// invocation never reaches collection, so the flags declared beside it never
/// classify anything. That is the same shape as a `files.*` key on a check that
/// searches no files, refused for the same reason -- it looks like
/// configuration that works.
///
/// The direction matters. A table may match verbs no entry names; those use the
/// table's own lists, which is every shim written before entries existed. What
/// is refused is the reverse: an entry naming a verb the table missed, which is
/// usually a verb somebody meant to add to `match` and added here instead.
fn validate_shim_verbs(policy_path: &Path, shims: &[crate::shim::Shim]) -> Result<()> {
    for shim in shims {
        for entry in &shim.verbs {
            if entry.match_.is_empty() {
                return Err(Fatal::at(
                    policy_path,
                    format!(
                        "a `[[shim.verbs]]` under {:?} names no verb, so the flags it declares \
                         hold for nothing.",
                        shim.command
                    ),
                ));
            }
            for named in &entry.match_ {
                let covered = shim.match_.iter().any(|m| {
                    m == named
                        || m == "*"
                        || named
                            .split_once(':')
                            .is_some_and(|(verb, _)| m == &format!("{verb}:*"))
                });
                if !covered {
                    return Err(Fatal::at(
                        policy_path,
                        format!(
                            "a `[[shim.verbs]]` under {:?} names {named:?}, which the table's own \
                             `match` does not. The shim never stands in front of that \
                             invocation, so the flags declared here classify nothing -- add \
                             {named:?} to `match` if the shim should check it.",
                            shim.command
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

/// `unresolved` is read by one predicate, and only where that predicate runs.
///
/// It says what to do when a scope could not be evaluated at all, and
/// `public-target` is the only scope that can answer that way -- it is the one
/// that asks somebody else. On a table scoped `always`, or `public-registry`,
/// or to a command of its own, the field is a decision that looks made and is
/// read by nothing: the same shape a `[[shim.verbs]]` for an unmatched verb is
/// refused for, and the same shape as a `files.*` key on a check that searches
/// no files.
///
/// A rule's own `command.scope` counts, because it overrides the table's for
/// that rule and can bring `public-target` to a table that is not scoped that
/// way. So the question is whether ANY reading of this policy can reach the
/// predicate for this command, not whether the table alone does.
fn validate_shim_unresolved(
    policy_path: &Path,
    rules: &[Rule],
    shims: &[crate::shim::Shim],
) -> Result<()> {
    for shim in shims {
        if shim.unresolved == crate::shim::Unresolved::default()
            || matches!(shim.scope, crate::shim::Scope::PublicTarget)
        {
            continue;
        }
        let by_a_rule = rules
            .iter()
            .filter(|rule| rule.stands_in_front_of_a_command())
            .any(|rule| {
                rule.command.as_ref().is_some_and(|where_| {
                    matches!(where_.scope, Some(crate::shim::Scope::PublicTarget))
                        && where_.before.iter().any(|line| {
                            line.split_whitespace().next() == Some(shim.command.as_str())
                        })
                })
            });
        if !by_a_rule {
            return Err(Fatal::at(
                policy_path,
                format!(
                    "the `[[shim]]` for {:?} writes `unresolved`, which says what to do when a \
                     scope could not be evaluated -- and no scope this invocation can reach \
                     answers that way. Only `public-target` asks somebody else, so only it can \
                     fail to answer. Scope the table (or a rule that names this command) \
                     `public-target`, or take the field off.",
                    shim.command
                ),
            ));
        }
    }
    Ok(())
}

fn validate_shim_commands(policy_path: &Path, shims: &[crate::shim::Shim]) -> Result<()> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for shim in shims {
        if !seen.insert(shim.command.as_str()) {
            return Err(Fatal::at(
                policy_path,
                format!(
                    "two `[[shim]]` tables name the command {:?}. Only one of them stands in \
                     front of it -- the other is dropped, and the verbs it names are published \
                     with nothing checking them. Put every verb for one command in one table.",
                    shim.command
                ),
            ));
        }
    }
    Ok(())
}

fn validate_shims(policy_path: &Path, rules: &[Rule], shims: &[crate::shim::Shim]) -> Result<()> {
    let declared: BTreeSet<&str> = shims.iter().map(|shim| shim.command.as_str()).collect();
    // The first word of a `before` entry is the command itself; the rest is as
    // much of the subcommand path as the rule wanted to scope itself to, which
    // is not the shim's business -- `[[shim]] command = "gh"` stands in front
    // of `gh pr create` and of every other `gh`.
    // A blank entry is refused before the set is built. `["   "]` parses, and
    // `split_whitespace().next()` answers `None` for it, so it used to drop out
    // here and take its rule's whole reason for existing with it: the rule stays
    // an `exec` check, stands in front of nothing, and reports clean forever.
    // `CommandWhere::matches` can never match it either, so there is no reading
    // of a blank entry that does anything.
    //
    // Every kind the shim consults, not just `exec`. This loop asked only about
    // `exec` while the set below already counted patterns and text-capable
    // built-ins, and the gap was not academic: the blank entry vanishes from
    // the set, so the shim is caught as "named by no checker" ONLY while no
    // other rule names the same command. Name it in a second, valid rule -- the
    // ordinary shape, since a command usually has more than one thing said
    // about it -- and the policy loads, the shim reports itself checked, and
    // the pattern rule that was supposed to stand in front of it never runs.
    for rule in rules
        .iter()
        .filter(|rule| rule.stands_in_front_of_a_command())
    {
        let Some(where_) = rule.command.as_ref() else {
            continue;
        };
        for line in &where_.before {
            if line.split_whitespace().next().is_none() {
                return Err(Fatal::at(
                    policy_path,
                    format!(
                        "`command.before` on {:?} has an entry with no command in it. An \
                         empty entry names nothing, so it stands in front of nothing, and \
                         the rule reads as one that passes",
                        rule.id
                    ),
                ));
            }
        }
    }

    // Both kinds count. An `exec` checker is a program this repository names; a
    // text-capable built-in is one the binary carries, and `shim::run` consults
    // both. Counting only the first refused a policy whose shim was checked --
    // by a guard rather than by a script -- as a shim checked by nothing.
    // A map to the rule that named each command rather than a set of names,
    // because the refusal below has to say where the naming rule CAME from --
    // "drop the entry" is a cure only for a rule written in this file, and a
    // rule arriving from a bundled set has no entry here to drop.
    let mut checked: BTreeMap<&str, &Rule> = BTreeMap::new();
    for rule in rules
        .iter()
        .filter(|rule| rule.stands_in_front_of_a_command())
    {
        for name in rule
            .command
            .iter()
            .flat_map(|where_| where_.before.iter())
            .filter_map(|line| line.split_whitespace().next())
        {
            checked.entry(name).or_insert(rule);
        }
    }

    for shim in shims {
        if !checked.contains_key(shim.command.as_str()) {
            return Err(Fatal::at(
                policy_path,
                format!(
                    "the shim for {:?} is named by no checker, so that command would be \
                     collected, checked by nothing, and run anyway -- an invocation that \
                     passed because nothing looked at it. Name it in an `exec` rule's \
                     `command.before`, or delete the shim",
                    shim.command
                ),
            ));
        }
    }

    for (name, rule) in checked {
        if !declared.contains(name) {
            // Which cure applies depends on where the rule was written. A set
            // supplies the checker and never the shim, so the only cures for
            // an inherited rule are the repository's: declare the table, or
            // stop inheriting the set.
            let cure = match &rule.origin {
                Origin::Set(set) => format!(
                    "This rule arrives from the bundled set {set:?}, which supplies the \
                     checker and never the shim. Declare `[[shim]]` with \
                     `command = {name:?}`, or drop {set:?} from `[inherit] sets`"
                ),
                _ => format!("Declare `[[shim]]` with `command = {name:?}`, or drop the entry"),
            };
            return Err(Fatal::at(
                policy_path,
                format!(
                    "`command.before` on {:?} names {name:?}, which no `[[shim]]` \
                     declares. A shim is the only thing that invokes a checker, so this \
                     rule runs nowhere -- which reads exactly like a rule that passes. \
                     {cure}",
                    rule.id
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each case gets its own directory. Sharing one made the suite
    /// order-dependent: tests run in parallel threads of a single process, so a
    /// path keyed on the process id is the SAME path for all of them, and one
    /// case read the policy another had just written.
    fn policy_from(text: &str) -> Result<Policy> {
        let dir = crate::fixture::scratch("config");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rg-policy.toml");
        std::fs::write(&path, text).unwrap();
        load(&dir, &path)
    }

    /// A bundled set's own instructions name keys the schema still has.
    ///
    /// These comments are the first thing a consumer reads, and they are
    /// compiled into the binary, so a wrong one ships to everybody. All three
    /// sets kept telling people to write `extends = [...]` and
    /// `disable_rules = [...]` -- the rg-policy spelling, replaced by `[extend]`
    /// with `use_default` and `disabled_rules`. Following them verbatim is
    /// refused by `deny_unknown_fields`, so the onboarding path was the one path
    /// that could not work.
    #[test]
    fn a_bundled_set_does_not_document_a_key_the_schema_rejects() {
        for (name, text) in BUNDLED {
            for legacy in ["extends =", "extends=", "disable_rules"] {
                assert!(
                    !text.contains(legacy),
                    "{name} tells a consumer to write `{legacy}`, which the schema refuses"
                );
            }
        }
    }

    /// Every check names the field that selects it, and that field selects it.
    ///
    /// This is what replaced the discriminant round-trip. While `kind` existed,
    /// the label and the fields could disagree and the label won; now
    /// `CheckKind::as_str` is a promise that the name printed in an error is the
    /// name a reader can go and edit, and the variant a check is spelled as is
    /// what keeps the promise. `Check::empty` and `Check::kind` are the two
    /// directions, and a variant that answered for a different kind would make
    /// every report name a check the file does not carry.
    #[test]
    fn every_check_is_named_by_the_field_that_selects_it() {
        for check in CheckKind::ALL {
            let rule = Rule::synthetic("x", Check::empty(check));
            assert_eq!(
                rule.kind(),
                check,
                "synthetic {check} did not select itself"
            );
            let document = format!("[rule.x]\n{} = ", check.as_str());
            assert!(
                !document.is_empty(),
                "{check} has no field name to write down"
            );
        }
    }

    /// The field a written rule names is the variant it becomes.
    ///
    /// The other direction of the same promise, and the one the type cannot
    /// keep on its own: `Check::of_written` reads the field names, and a
    /// mis-wired arm there would load a `max_bytes` rule as a `max_lines` one
    /// with nothing to notice. Every check is spelled out here, as a file
    /// spells it, and asserted to arrive as itself.
    ///
    /// The patterns are anchored to a string no policy file contains, because
    /// a rule whose regex matches its own declaration is refused by
    /// `validate_no_self_match` before it is ever read as a check.
    #[test]
    fn the_field_a_file_writes_is_the_check_it_loads_as() {
        for (written, expected) in [
            ("regexp = '^zzq'", CheckKind::Regexp),
            ("comment_regexp = '^zzq'", CheckKind::CommentRegexp),
            ("prose_regexp = '^zzq'", CheckKind::ProseRegexp),
            ("trivial_comments = true", CheckKind::TrivialComments),
            ("path_regexp = '^zzq'", CheckKind::PathRegexp),
            ("require_regexp = '^zzq'", CheckKind::RequireRegexp),
            ("max_lines = 10", CheckKind::MaxLines),
            ("max_bytes = 10", CheckKind::MaxBytes),
            ("encoding = 'UTF-8'", CheckKind::Encoding),
            ("allowed_scripts = ['Latin']", CheckKind::AllowedScripts),
            (
                "forbidden_literals = 'running-os-identity'",
                CheckKind::ForbiddenLiterals,
            ),
            (
                "forbidden_literals_from = 'echo nothing'",
                CheckKind::ForbiddenLiterals,
            ),
        ] {
            let policy = policy_from(&format!(
                "[rule.round-trip]\nmessage = \"m\"\n{written}\nfiles.include = [\".\"]\n"
            ))
            .unwrap_or_else(|error| unreachable!("{written}: {error}"));
            assert_eq!(policy.rules[0].kind(), expected, "{written}");
        }
        let exec = policy_from(
            "[rule.round-trip]\nmessage = \"m\"\nexec = \"checker\"\n\n\
             [rule.round-trip.command]\nbefore = [\"gh\"]\n\n\
             [[shim]]\ncommand = \"gh\"\nmatch = [\"pr:create\"]\ntext_flags = [\"-b\"]\n",
        )
        .unwrap();
        assert_eq!(exec.rules[0].kind(), CheckKind::Exec);
        let builtin = policy_from(
            "[rule.round-trip]\nbuiltin = \"prevent-ai-author\"\n\n\
             [rule.round-trip.git]\nhooks = [\"commit-msg\"]\n",
        )
        .unwrap();
        assert_eq!(builtin.rules[0].kind(), CheckKind::Builtin);
    }

    /// A rule that names no place runs nowhere, and that has to be an error.
    ///
    /// It reads exactly like a rule that passes, which is the failure mode the
    /// three tables exist to make visible -- so the absence has to be refused at
    /// load rather than discovered by a clean run that checked nothing.
    #[test]
    fn a_rule_with_no_place_is_refused() {
        let error = policy_from(
            r#"
            [rule.nowhere]
            builtin = "prevent-ai-author"
            "#,
        )
        .unwrap_err();
        assert!(
            format!("{error}").contains("nothing says where it runs"),
            "{error}"
        );
    }

    /// Two checks in one rule means one of them is read by nothing.
    #[test]
    fn a_rule_naming_two_checks_is_refused() {
        let error = policy_from(
            r#"
            [rule.two]
            message = "no"
            regexp = "x"
            max_lines = 10

            [rule.two.files]
            "#,
        )
        .unwrap_err();
        assert!(
            format!("{error}").contains("a rule checks one thing"),
            "{error}"
        );
    }

    /// The stages are the config's to set, which is the whole point.
    #[test]
    fn hooks_come_from_the_file_and_an_unknown_one_is_refused() {
        let policy = policy_from(
            r#"
            [rule.author]
            builtin = "prevent-ai-author"

            [rule.author.git]
            hooks = ["commit-msg", "pre-push"]
            "#,
        )
        .unwrap();
        let rule = &policy.rules[0];
        assert!(rule.runs_at("pre-push"), "the file said pre-push");
        assert!(!rule.runs_at("pre-commit"));

        let error = policy_from(
            r#"
            [rule.author]
            builtin = "prevent-ai-author"

            [rule.author.git]
            hooks = ["post-receive"]
            "#,
        )
        .unwrap_err();
        assert!(format!("{error}").contains("unknown stage"), "{error}");
    }

    /// A checker names the commands it stands in front of, and only those.
    #[test]
    fn a_command_rule_matches_by_prefix_and_ignores_flags() {
        let policy = policy_from(
            r#"
            [rule.body]
            message = "no"
            exec = "checker"

            [rule.body.command]
            before = ["gh pr create"]

            [[shim]]
            command = "gh"
            match = ["pr:create"]
            text_flags = ["-b"]
            scope = "always"
            "#,
        )
        .unwrap();
        let rule = &policy.rules[0];
        let argv =
            |words: &[&str]| -> Vec<String> { words.iter().map(ToString::to_string).collect() };
        assert!(rule.stands_before("gh", &argv(&["pr", "create"])));
        // Flags between the words do not break the match, because a reader
        // writing "gh pr create" should not have to know where they went.
        assert!(rule.stands_before("gh", &argv(&["-R", "acme/x", "pr", "create"])));
        assert!(!rule.stands_before("gh", &argv(&["pr", "merge"])));
        // The case the scoping exists for.
        assert!(!rule.stands_before("git", &argv(&["push"])));
    }

    /// A duplicate id within one file is a TOML parse error, not a runtime
    /// check: `[rule.same]` twice is the same key defined twice. The runtime
    /// check that used to catch this now has one job left -- the collision no
    /// parser can see, across two inherited files.
    #[test]
    fn a_duplicate_id_in_one_file_cannot_even_parse() {
        let error = policy_from(
            r#"
            [rule.same]
            message = "no"
            regexp = "x"
            files.include = ["."]

            [rule.same]
            message = "no"
            regexp = "y"
            files.include = ["."]
            "#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("duplicate"), "{error}");
    }

    #[test]
    fn two_inherited_files_may_not_define_one_id() {
        let dir = crate::fixture::scratch("config-inherit");
        std::fs::create_dir_all(dir.join("policy")).unwrap();
        let same = "[rule.same]\nmessage = \"no\"\nregexp = \"x\"\nfiles.include = [\".\"]\n";
        std::fs::write(dir.join("policy/a.toml"), same).unwrap();
        std::fs::write(dir.join("policy/b.toml"), same).unwrap();
        let path = dir.join("policy/principles.toml");
        std::fs::write(
            &path,
            "[inherit]\npaths = [\"policy/a.toml\", \"policy/b.toml\"]\n",
        )
        .unwrap();
        let error = load(&dir, &path).unwrap_err();
        assert!(error.to_string().contains("one namespace"), "{error}");
    }

    #[test]
    /// `files.*` keys on a check that does not read files.
    ///
    /// The other half of the same idea as two check fields: a table read by
    /// nothing looks exactly like configuration that works.
    fn a_place_the_check_cannot_use_is_refused() {
        let error = policy_from(
            r#"
            [rule.wrong]
            message = "no"
            exec = "checker"

            [rule.wrong.files]
            glob = ["*.md"]

            [rule.wrong.command]
            before = ["gh"]
            "#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("read by nothing"), "{error}");
    }

    #[test]
    /// `git.hooks` on a check no git stage can run.
    ///
    /// The mirror of the test above, and the half that was missing. `guard`
    /// dispatches on the built-in name and answered "no violation" for a rule
    /// that has none, so this config was accepted, collected at the hook,
    /// counted, never run, and reported inside "N guard(s) passed" -- a check
    /// that did not happen, presented as one that did.
    fn a_git_hook_on_a_rule_no_stage_can_run_is_refused() {
        // A content rule carries `files.*` too: it is a rule that really
        // does run, by the scan, and the `git.hooks` beside it is the part
        // that reaches nothing.
        for check in [
            "exec = \"checker\"\n\n[rule.wrong.command]\nbefore = [\"gh\"]",
            "regexp = \"TODO\"\n\n[rule.wrong.files]\nglob = [\"*.md\"]",
        ] {
            let error = policy_from(&format!(
                "[rule.wrong]\nmessage = \"no\"\n{check}\n\n\
                 [rule.wrong.git]\nhooks = [\"pre-commit\"]\n"
            ))
            .unwrap_err();
            assert!(
                error.to_string().contains("read by nothing"),
                "{check}: {error}"
            );
        }
    }

    #[test]
    /// `command.before` on a check no shim can consult.
    ///
    /// The third member of the same family. `shim::run` consults `exec`
    /// checkers and text-capable BUILT-INS, so a rule that is neither and whose
    /// only declared place is `command.before` is consulted by nothing and runs
    /// nowhere -- and the "nothing says where it runs" refusal is satisfied by
    /// the very field that cannot be used, so the check meant to catch a rule
    /// with no place is the one this rule walked past.
    fn a_command_place_the_check_cannot_use_is_refused() {
        // A built-in that reads the index, an identity or a push range has
        // nothing to say about the text a command publishes. The pattern
        // checks are no longer in this list: a regex means the same thing
        // against a title as against a line of a file, so `command.before`
        // is a place they can use now.
        for check in [
            "builtin = \"prevent-public-push\"",
            "builtin = \"prevent-unusual-unicode-in-files\"",
        ] {
            let error = policy_from(&format!(
                "[rule.wrong]\n{check}\n\n[rule.wrong.command]\nbefore = [\"gh\"]\n"
            ))
            .unwrap_err();
            assert!(
                error.to_string().contains("read by nothing"),
                "{check}: {error}"
            );
        }

        // And a pattern rule standing in front of a command loads, with its
        // subject filter -- the release-title shape this was built for.
        let policy = policy_from(
            "[rule.release-title-is-the-tag]\nmessage = \"title a release by its tag\"\nrequire_regexp = '^v[0-9]+'\nsubjects = [\"title\"]\n\n[rule.release-title-is-the-tag.command]\nbefore = [\"gh release create\"]\n\n[[shim]]\ncommand = \"gh\"\nmatch = [\"release:create\"]\ntitle_flags = [\"-t\", \"--title\"]\n",
        )
        .unwrap();
        assert!(policy.rules[0].selects_subject("title"));
        assert!(!policy.rules[0].selects_subject("text"));
    }

    #[test]
    fn a_subjects_filter_needs_a_command_and_a_kind_that_exists() {
        // Written anywhere else it is read by nothing.
        let orphan = policy_from(
            "[rule.wrong]\nmessage = \"no\"\nregexp = \"TODO\"\nsubjects = [\"title\"]\nfiles.include = [\".\"]\n",
        )
        .unwrap_err();
        assert!(orphan.to_string().contains("command.before"), "{orphan}");

        // An empty filter selects nothing while reading as scoped.
        let empty = policy_from(
            "[rule.wrong]\nmessage = \"no\"\nregexp = \"TODO\"\nsubjects = []\n\n[rule.wrong.command]\nbefore = [\"gh\"]\n",
        )
        .unwrap_err();
        assert!(empty.to_string().contains("selects no subject"), "{empty}");

        // A kind the shim never collects is a typo, not a scope.
        let unknown = policy_from(
            "[rule.wrong]\nmessage = \"no\"\nregexp = \"TODO\"\nsubjects = [\"headline\"]\n\n[rule.wrong.command]\nbefore = [\"gh\"]\n",
        )
        .unwrap_err();
        assert!(unknown.to_string().contains("headline"), "{unknown}");
    }

    #[test]
    /// A text-capable built-in may stand in front of a command.
    ///
    /// It is the only seam some of them belong at. `no-private-repo-names`
    /// reads a commit message at every git hook, which refuses the issue
    /// citations a repository's own prose is full of -- so a repository that
    /// wants it over a pull-request body and nowhere else has no other field to
    /// say it in. Three wrote `command.before` on the built-in independently
    /// while the loader refused all three, on the true-but-unhelpful grounds
    /// that a built-in is not an `exec`.
    fn a_text_capable_builtin_may_stand_in_front_of_a_command() {
        for builtin in crate::guard::TEXT_GUARDS {
            let loaded = policy_from(&format!(
                "[[shim]]\ncommand = \"gh\"\nmatch = [\"pr:create\"]\n\
                 text_flags = [\"-b\"]\n\n\
                 [rule.stands-in-front]\nbuiltin = \"{builtin}\"\n\n\
                 [rule.stands-in-front.command]\nbefore = [\"gh\"]\n"
            ));
            assert!(loaded.is_ok(), "{builtin}: {:?}", loaded.err());
            let policy = loaded.unwrap();
            let rule = policy
                .rules
                .iter()
                .find(|rule| rule.id == "stands-in-front");
            assert!(
                rule.is_some(),
                "{builtin}: the rule did not survive the load"
            );
            assert_eq!(rule.unwrap().seams(), vec!["shim"], "{builtin}");
        }
    }

    /// A `command` table that names no command line is a place that selects
    /// nothing, and the "where does it run" check reads it as a place.
    #[test]
    fn a_command_before_that_names_nothing_is_refused() {
        let error = policy_from(
            r#"
            [rule.body]
            message = "no"
            exec = "checker"

            [rule.body.command]
            before = []
            "#,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("names no command line"),
            "{error}"
        );
    }

    /// A shim with no checker execs the command with nothing checked.
    ///
    /// Silence at run time -- the subjects are collected, the empty checker
    /// list is iterated, and the command runs -- so the only place this can be
    /// said is here, at load.
    #[test]
    fn a_shim_no_checker_names_is_refused() {
        let error = policy_from(
            r#"
            [[shim]]
            command = "gh"
            match = ["pr:create"]
            text_flags = ["-b"]
            scope = "always"
            "#,
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("named by no checker"), "{text}");
        assert!(text.contains("gh"), "{text}");
    }

    /// And the mirror: a checker standing in front of a command nothing shims
    /// is never invoked, because the shim is what invokes it.
    #[test]
    fn a_checker_naming_a_command_no_shim_declares_is_refused() {
        let error = policy_from(
            r#"
            [rule.body]
            message = "no"
            exec = "checker"

            [rule.body.command]
            before = ["gh pr create", "glab mr create"]

            [[shim]]
            command = "gh"
            match = ["pr:create"]
            text_flags = ["-b"]
            scope = "always"
            "#,
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("glab"), "{text}");
        assert!(text.contains("no `[[shim]]` declares"), "{text}");
    }

    /// A `before` entry with no command in it stands in front of nothing.
    ///
    /// `["   "]` parses, and the set of checked commands is built from
    /// `split_whitespace().next()`, which answers `None` for it -- so the entry
    /// used to fall out of the check entirely and take the rule's whole reason
    /// for existing with it. The rule stays an `exec` check, is consulted by no
    /// shim, and reports clean for good.
    #[test]
    fn a_before_entry_naming_no_command_is_refused() {
        let error = policy_from(
            r#"
            [rule.body]
            message = "no"
            exec = "checker"

            [rule.body.command]
            before = ["   "]
            "#,
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("no command in it"), "{text}");
        assert!(text.contains("body"), "{text}");
    }

    /// And on a pattern rule, which the blank-entry loop did not used to ask
    /// about.
    ///
    /// The shape that hid it: a second, valid rule names the same command, so
    /// the shim is not "named by no checker" and the policy loads. The pattern
    /// rule's own entry is blank, `CommandWhere::matches` can never match it,
    /// and the release titles it was written to hold to a format are published
    /// unread -- with every other rule at the seam still firing, so nothing
    /// about the run looks switched off.
    #[test]
    fn a_blank_before_entry_on_a_pattern_rule_is_refused() {
        let error = policy_from(
            r#"
            [rule.release-title-is-the-tag]
            message = "title a release by its tag"
            require_regexp = '^v[0-9]+\.[0-9]+\.[0-9]+$'
            subjects = ["title"]
            command.before = ["  "]

            [rule.body]
            message = "no"
            exec = "checker"
            command.before = ["gh"]

            [[shim]]
            command = "gh"
            match = ["release:create"]
            title_flags = ["-t"]
            scope = "always"
            "#,
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("no command in it"), "{text}");
        assert!(text.contains("release-title-is-the-tag"), "{text}");
    }

    /// An inherited `[[shim]]` is refused rather than dropped on the floor.
    ///
    /// Only `.rules` is merged, so the shim vanished and the `exec` rule that
    /// arrived with it did not -- and `validate_shims` then told the author that
    /// their `command.before` named a shim nobody declared, which they had in
    /// fact declared, in the file they were pointing at.
    #[test]
    fn a_shim_in_an_inherited_file_is_refused_rather_than_ignored() {
        let dir = crate::fixture::scratch("config-inherited-shim");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("shared.toml"),
            r#"
            [[shim]]
            command = "gh"
            match = ["pr:create"]
            text_flags = ["-b"]
            scope = "always"
            "#,
        )
        .unwrap();
        let path = dir.join("rg-policy.toml");
        std::fs::write(
            &path,
            r#"
            [inherit]
            paths = ["shared.toml"]
            "#,
        )
        .unwrap();

        let error = load(&dir, &path).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("`[[shim]]`"), "{text}");
        assert!(text.contains("not adopted"), "{text}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The verified bug: two parameters that look enforced, read by nothing.
    ///
    /// This exact config loaded and ran without complaint -- `allowed_owners`
    /// and `private_owners` sit flat on the rule struct, so a `regexp` rule
    /// could carry them and the author walked away believing both were
    /// enforced.
    #[test]
    fn a_builtin_parameter_on_a_rule_whose_check_never_reads_it_is_refused() {
        let error = policy_from(
            r#"
            [rule.x]
            message = "no"
            regexp = "something"
            allowed_owners = ["acme"]
            private_owners = ["secret"]

            [rule.x.files]
            "#,
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("allowed_owners"), "{text}");
        assert!(text.contains("read by nothing"), "{text}");
    }

    /// The same refusal between built-ins: each declares what it reads.
    #[test]
    fn a_parameter_belonging_to_a_different_builtin_is_refused() {
        let error = policy_from(
            r#"
            [rule.push]
            builtin = "prevent-public-push"
            private_owners = ["secret"]

            [rule.push.git]
            hooks = ["pre-push"]
            "#,
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("private_owners"), "{text}");
        // The refusal says what this built-in DOES read, so the fix is in the
        // message rather than in a docs round-trip.
        assert!(text.contains("allowed_owners"), "{text}");
    }

    #[test]
    fn a_parameter_its_builtin_reads_is_accepted() {
        let policy = policy_from(
            r#"
            [rule.push]
            builtin = "prevent-public-push"
            owner = "acme"
            allowed_repos = ["acme/thing"]

            [rule.push.git]
            hooks = ["pre-push"]
            "#,
        )
        .expect("a parameter the built-in declares is the ordinary case");
        assert_eq!(policy.rules[0].allowed_repos(), ["acme/thing"]);
    }

    /// `exclude_cfg_test` needs a matched line; only the content searches have
    /// one. It was refused on `path_regexp` alone, while `max_lines` and
    /// `require_regexp` accepted it and read nothing.
    #[test]
    fn exclude_cfg_test_is_refused_beside_a_check_with_no_matched_line() {
        for check in ["max_lines = 10", "require_regexp = \"^permissions:\""] {
            let error = policy_from(&format!(
                "[rule.x]\nmessage = \"no\"\n{check}\n\n\
                 [rule.x.files]\nexclude_cfg_test = true\n"
            ))
            .unwrap_err();
            assert!(
                error.to_string().contains("read by nothing"),
                "{check}: {error}"
            );
        }
    }

    /// `min_selected` is a floor under a COUNT, and a guard built-in's
    /// `[rule.files]` is a scope applied to one path at a time. The scan never
    /// dispatches such a rule, so nothing there would ever take the count the
    /// floor stands under.
    #[test]
    fn min_selected_is_refused_on_a_builtin_whose_files_are_a_guard_scope() {
        let error = policy_from(
            r#"
            [rule.unicode]
            builtin = "prevent-unusual-unicode-in-files"
            files.include = ["docs"]
            files.min_selected = 1

            [rule.unicode.git]
            hooks = ["pre-commit"]
            "#,
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("read by nothing"), "{text}");
        // The refusal names where the field DOES work, so the fix is in the
        // message rather than in a docs round-trip.
        assert!(text.contains("links-resolve"), "{text}");
    }

    /// The three the scan selects for read it, so the refusal above must not
    /// reach them.
    #[test]
    fn min_selected_is_accepted_on_the_builtins_the_scan_selects_for() {
        let policy = policy_from(
            r#"
            [rule.links]
            builtin = "links-resolve"
            files.glob = ["*.md"]
            files.min_selected = 3
            "#,
        )
        .expect("a floor on a scan-dispatched built-in is the ordinary case");
        assert_eq!(policy.rules[0].min_selected(), 3);
    }

    /// Every selection meets a floor of zero, the empty one included -- so the
    /// line declares a floor and enforces nothing, which is the shape
    /// `trivial_comments = false` is refused for.
    #[test]
    fn a_floor_of_zero_is_refused() {
        let error = policy_from(
            "[rule.x]\nmessage = \"no\"\nregexp = \"TODO\"\n\
             [rule.x.files]\ninclude = [\".\"]\nmin_selected = 0\n",
        )
        .unwrap_err();
        assert!(error.to_string().contains("every selection"), "{error}");
    }

    /// An unwritten floor is no floor, and it has to read as `0` rather than as
    /// a second "was it written" question at every comparison.
    #[test]
    fn an_unwritten_floor_is_no_floor() {
        assert_eq!(
            Rule::synthetic("x", Check::empty(CheckKind::RequireRegexp)).min_selected(),
            0
        );
    }

    /// The link-checker knobs sat in the shared selection table, so every rule
    /// author scrolled past fields that could not apply to their rule -- and
    /// could write them, enforced-looking, read by nothing.
    #[test]
    fn a_link_field_beside_a_check_that_reads_no_links_is_refused() {
        let error = policy_from(
            r#"
            [rule.x]
            message = "no"
            regexp = "TODO"
            require_any_link = true
            files.include = ["."]
            "#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("links-resolve"), "{error}");
    }

    #[test]
    fn a_builtin_may_still_name_a_git_hook() {
        let policy = policy_from(
            r#"
            [rule.prevent-ai-author]
            builtin = "prevent-ai-author"

            [rule.prevent-ai-author.git]
            hooks = ["commit-msg"]
            "#,
        )
        .expect("a built-in at a hook is the ordinary case");
        assert_eq!(policy.at_hook("commit-msg").count(), 1);
    }

    #[test]
    fn a_disabled_id_that_names_nothing_is_refused() {
        let error = policy_from(
            r#"
            [inherit]
            sets = ["process-residue"]
            disabled_rules = ["no-such-rule"]
            "#,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("nothing inherited defines"),
            "{error}"
        );
    }

    #[test]
    fn two_checks_on_one_rule_are_refused_however_they_are_spelled() {
        // `forbidden_literals` and `forbidden_literals_from` are ONE check
        // written two ways, so they count once; anything else beside them is a
        // second check, and a rule carrying two has one of them read by
        // nothing while its author believes both are enforced.
        let error = policy_from(
            "[rule.two]\nmessage = \"x\"\nregexp = 'a'\nmax_lines = 10\nfiles.include = [\".\"]\n",
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("regexp and max_lines"), "{text}");
        assert!(text.contains("a rule checks one thing"), "{text}");

        // The pair together is still one check and still loads.
        policy_from(
            "[rule.one]\nmessage = \"x\"\nforbidden_literals = \"running-os-identity\"\nfiles.include = [\".\"]\n",
        )
        .unwrap();

        // And the pair counts AS one rather than as none: a literals rule
        // carrying a second check is two checks, and the counter that folds
        // the two spellings together has to say so. Counted as none, this
        // loads with a `regexp` nothing reads.
        let paired = policy_from(
            "[rule.both]\nmessage = \"x\"\nforbidden_literals = \"running-os-identity\"\nregexp = 'a'\nfiles.include = [\".\"]\n",
        )
        .unwrap_err();
        let paired = paired.to_string();
        assert!(paired.contains("a rule checks one thing"), "{paired}");
    }

    #[test]
    fn a_command_checker_that_cannot_judge_text_is_refused() {
        // The shim consults `exec` checkers and the built-ins that judge
        // arbitrary text. Anything else reads an index, an identity or a push
        // range, so standing it in front of a command collects a subject and
        // checks it with nothing -- an invocation that passed because nobody
        // looked.
        let error =
            policy_from("[rule.merge]\nbuiltin = \"no-merge-commit\"\ncommand.before = [\"gh\"]\n")
                .unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains("cannot stand in front of a command"),
            "{text}"
        );
        // And it names the ones that can, so the fix is in the message.
        assert!(text.contains("prevent-ai-author"), "{text}");

        // A text-capable built-in in the same place is the documented shape.
        policy_from(
            "[rule.author]\nbuiltin = \"prevent-ai-author\"\ncommand.before = [\"gh\"]\n\n[[shim]]\ncommand = \"gh\"\nmatch = [\"pr:create\"]\ntext_flags = [\"-t\"]\n",
        )
        .unwrap();
    }

    #[test]
    fn a_builtin_that_reads_no_parameter_at_all_says_that_instead() {
        // The other arm of the same refusal, and a different sentence: a
        // built-in that reads NOTHING cannot be told "reads only ", which is
        // what the collapsed version says -- and it sends the author looking
        // for a list that is not there. The arm for a built-in that reads SOME
        // parameters is covered by
        // `a_parameter_belonging_to_a_different_builtin_is_refused`.
        let error = policy_from(
            "[rule.merge]\nbuiltin = \"no-merge-commit\"\nowner = \"acme\"\n\n[rule.merge.git]\nhooks = [\"pre-commit\"]\n",
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("reads no parameters"), "{text}");
        assert!(text.contains("owner"), "{text}");
    }

    #[test]
    fn a_check_is_named_by_the_field_that_declares_it() {
        // These strings are what a reader sees in `uphold rules --set NAME`,
        // in the lock document, and in the error a duplicate id raises. A
        // check whose name was empty or wrong would make every one of those
        // reports say nothing while still reporting.
        for (check, name) in [
            (CheckKind::Regexp, "regexp"),
            (CheckKind::PathRegexp, "path_regexp"),
            (CheckKind::Builtin, "builtin"),
            (CheckKind::Exec, "exec"),
            (CheckKind::MaxLines, "max_lines"),
            (CheckKind::MaxBytes, "max_bytes"),
            (CheckKind::ProseRegexp, "prose_regexp"),
        ] {
            assert_eq!(check.to_string(), name);
        }
        // Every kind is named, and no two share a name: `CheckKind::ALL` is the
        // only enumeration, so a new kind arriving with a duplicate spelling
        // would be invisible everywhere the name is the whole report.
        let names: BTreeSet<String> = CheckKind::ALL.iter().map(ToString::to_string).collect();
        assert_eq!(names.len(), CheckKind::ALL.len());
        assert!(!names.iter().any(String::is_empty));
    }

    /// The two size checks are two rules, never one rule with two caps.
    ///
    /// A rule bounding both would have one of the two read by nothing under
    /// whichever arm the evaluator happened to take first, which is the shape
    /// the discriminant made easy and the whole reason the field IS the check.
    #[test]
    fn a_rule_cannot_bound_lines_and_bytes_at_once() {
        let error = policy_from(
            "[rule.short]\nmessage = \"x\"\nmax_lines = 10\nmax_bytes = 400\nfiles.include = [\".\"]\n",
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("max_lines and max_bytes"), "{text}");
        assert!(text.contains("one rule per check"), "{text}");
    }

    /// A prose span is one unwrapped line by construction, so there is no
    /// second line for a multiline pattern to reach -- and a field read by
    /// nothing is refused here rather than accepted and ignored.
    #[test]
    fn multiline_beside_a_prose_rule_is_refused() {
        let error = policy_from(
            "[rule.shape]\nmessage = \"x\"\nprose_regexp = 'arguably'\nfiles.include = [\".\"]\nfiles.multiline = true\n",
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("files.multiline"), "{text}");
        assert!(text.contains("unwrapped span"), "{text}");
    }

    /// The seams a prose rule reaches, which is what `uphold check` reconciles
    /// a claim against. A rule declaring both tables runs at both, and reading
    /// it as scan-only would credit a shim-seam claim to a scan that never
    /// consults the command.
    #[test]
    fn a_prose_rule_runs_at_the_scan_and_at_the_shim() {
        let policy = policy_from(
            "[rule.shape]\nmessage = \"x\"\nprose_regexp = 'arguably'\nfiles.include = [\".\"]\n\
             command.before = [\"gh\"]\n\n[[shim]]\ncommand = \"gh\"\nmatch = [\"pr:create\"]\n",
        )
        .unwrap();
        let rule = policy.rules.first().unwrap();
        assert_eq!(rule.seams(), ["scan", "shim"]);
        assert!(rule.stands_in_front_of_a_command());
    }

    #[test]
    fn an_unwritten_parameter_reads_as_its_documented_default() {
        // The accessors fill in the default exactly once, and `Option` is what
        // lets `validate` tell WRITTEN from ABSENT. A default that drifted --
        // `refuse_unknown` defaulting to true, `allow_outside_repo` to false --
        // changes what a guard does in every repository that never wrote the
        // field, which is most of them.
        let rule = Rule::synthetic("x", Check::empty(CheckKind::Builtin));
        assert!(rule.public_repos().is_empty());
        assert!(rule.allowed_owners().is_empty());
        assert!(rule.allowed_repos().is_empty());
        assert!(rule.private_owners().is_empty());
        assert!(
            !rule.refuse_unknown(),
            "an unknown name is not private by default"
        );
        assert!(
            !rule.require_any_link(),
            "a selection yielding no links is not a finding by default"
        );
        assert!(
            !rule.allow_outside_repo(),
            "a link leaving the repository is not allowed by default"
        );
    }

    #[test]
    fn a_written_parameter_is_the_one_the_check_reads() {
        // The other half, and it is the half that catches an accessor which
        // has quietly become a constant: with the defaults tested alone, an
        // accessor returning its default ALWAYS passes every test while every
        // repository that wrote the field is silently running the default.
        let policy = policy_from(
            r#"
            [rule.names]
            builtin = "no-private-repo-names"
            public_repos = ["acme/public"]
            refuse_unknown = true

            [rule.names.git]
            hooks = ["commit-msg"]

            [rule.push]
            builtin = "prevent-public-push"
            allowed_owners = ["acme", "acme-mirror"]

            [rule.push.git]
            hooks = ["pre-push"]
            "#,
        )
        .unwrap();
        let names = policy
            .rules
            .iter()
            .find(|rule| rule.id == "names")
            .expect("the rule loaded");
        assert_eq!(names.public_repos(), ["acme/public".to_owned()]);
        assert!(names.refuse_unknown());

        let push = policy
            .rules
            .iter()
            .find(|rule| rule.id == "push")
            .expect("the rule loaded");
        assert_eq!(
            push.allowed_owners(),
            ["acme".to_owned(), "acme-mirror".to_owned()]
        );

        // The links knobs are the same pair in a different built-in, and the
        // second of them is the one a mutation run kept alive: a repository
        // that wrote `allow_outside_repo = true` and silently got `false`
        // would have every outward citation refused, with the field it wrote
        // sitting right there in the file.
        let links = policy_from(
            r#"
            [rule.links]
            builtin = "links-resolve"
            require_any_link = true
            allow_outside_repo = true
            files.include = ["docs"]
            "#,
        )
        .unwrap();
        let links = links
            .rules
            .iter()
            .find(|rule| rule.id == "links")
            .expect("the rule loaded");
        assert!(links.require_any_link());
        assert!(links.allow_outside_repo());
    }

    #[test]
    fn which_seam_runs_a_rule_is_decided_by_what_it_declares() {
        // `check` reads this to answer "which seam supplies this rule", so a
        // wrong answer here is a claim reconciled against a seam that never
        // runs it -- or an unestablished note about a rule that does.
        let mut content = Rule::synthetic(
            "content",
            Check::Regexp {
                regexp: String::from("x"),
            },
        );
        content.files = Some(Files::default());
        assert_eq!(content.seams(), vec!["scan"]);

        // A built-in that reads files AND declares hooks is the guard's, not
        // the scan's: the tree-wide unicode guard runs at four stages and the
        // scan does not dispatch it.
        let mut guard = Rule::synthetic(
            "guard",
            Check::Builtin {
                builtin: String::from("prevent-unusual-unicode-in-files"),
                parameters: Box::default(),
            },
        );
        guard.files = Some(Files::default());
        guard.git = Some(Git {
            hooks: vec![String::from("pre-commit")],
        });
        assert_eq!(guard.seams(), vec!["guard"]);

        // And one that reads files while declaring no hook is the scan's --
        // `links-resolve` is the case, and it is why the condition is an OR
        // rather than a plain "not a built-in".
        let mut hookless = Rule::synthetic(
            "links",
            Check::Builtin {
                builtin: String::from("links-resolve"),
                parameters: Box::default(),
            },
        );
        hookless.files = Some(Files::default());
        assert_eq!(hookless.seams(), vec!["scan"]);
    }

    #[test]
    fn provenance_answers_about_the_id_it_was_asked_about() {
        // A refusal names the set the rule came from, so answering with some
        // other rule's set is worse than answering nothing: the reader goes to
        // `uphold rules --set <name>` and finds no such rule there. The
        // repository's own rule has no set, and an inherited one has exactly
        // its own.
        let policy = policy_from(
            r#"
            [inherit]
            sets = ["process-residue", "credentials"]

            [rule.mine]
            message = "local"
            # Narrowed so `regexp` cannot match its own declaration. Any
            # unanchored literal written as `regexp = "X"` contains X on that
            # line, so a whole-repo fixture pattern is refused by
            # `validate_no_self_match`; what this test is about is provenance,
            # not selection.
            regexp = "local"
            files.include = ["src"]
            "#,
        )
        .unwrap();
        assert_eq!(
            policy.set_of("no-merge-conflict-markers"),
            Some("process-residue")
        );
        assert_eq!(policy.set_of("no-env-secret-values"), Some("credentials"));
        assert_eq!(
            policy.set_of("mine"),
            None,
            "a rule written here came from no set"
        );
        assert_eq!(policy.set_of("no-such-rule"), None);
    }

    #[test]
    fn a_repo_rule_shadows_the_inherited_rule_of_the_same_id() {
        let policy = policy_from(
            r#"
            [inherit]
            sets = ["process-residue"]

            [rule.no-hardcoded-home-paths]
            message = "local"
            regexp = "local"

            [rule.no-hardcoded-home-paths.files]
            # See `provenance_answers_about_the_id_it_was_asked_about`: an
            # unanchored literal fixture pattern matches its own declaration,
            # and this test is about shadowing rather than selection.
            include = ["src"]
            "#,
        )
        .unwrap();
        let shadowed: Vec<&Rule> = policy
            .rules
            .iter()
            .filter(|rule| rule.id == "no-hardcoded-home-paths")
            .collect();
        assert_eq!(shadowed.len(), 1);
        assert_eq!(shadowed[0].message(), "local");
    }

    #[test]
    fn naming_every_set_takes_every_bundled_set() {
        // There is no shorthand for "all of them": what a repository inherits
        // is written in the repository, set by set.
        let policy = policy_from(
            "[inherit]\nsets = [\"process-residue\", \"credentials\", \"unmanaged-pins\"]\n",
        )
        .unwrap();
        assert!(policy.has_check(CheckKind::Regexp));
        assert!(policy.has_check(CheckKind::PathRegexp));
        assert!(policy
            .rules
            .iter()
            .any(|rule| rule.id == "no-pinned-tool-install"));
    }

    /// A policy nobody would write, and the two answers it may never give.
    ///
    /// The fuzz target `#13` asks for wants a library to link against, and this
    /// crate is deliberately one binary -- adding a `[lib]` to make libFuzzer
    /// happy would change what the crate IS for the sake of how it is tested.
    /// What that target would assert is assertable here: throw malformed input
    /// at the loader and hold it to the two invariants that matter.
    ///
    /// 1. It never panics. `load` is reached by `uphold shim` standing in front
    ///    of `git`, so a panic here is a panic in front of every command in a
    ///    repository whose policy somebody mistyped.
    /// 2. Unparseable is never CLEAN. A `Result` is the whole answer: an `Err`
    ///    is exit 2 and a policy with no rules in it is exit 0, and the second
    ///    over a file that could not be read is the failure this repository
    ///    exists to refuse.
    ///
    /// The corpus is this repository's own policy and every bundled set, cut
    /// and corrupted mechanically. Real input mangled beats invented input:
    /// every byte offset in it means something to the parser.
    #[test]
    fn a_policy_that_was_damaged_is_never_read_as_an_empty_one() {
        let mut corpus: Vec<String> = vec![std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/policy/principles.toml"
        ))
        .expect("this repository's own policy")];
        for (_, text) in BUNDLED {
            corpus.push((*text).to_owned());
        }

        let mut checked = 0_usize;
        for source in &corpus {
            let bytes = source.as_bytes();
            // Every prefix at a step that is not a multiple of anything the
            // file is structured by, so cuts land inside keys, inside strings,
            // and inside multi-line values.
            for cut in (0..bytes.len()).step_by(97) {
                let damaged = String::from_utf8_lossy(&bytes[..cut]).into_owned();
                // The assertion is that this RETURNS -- an `Err` for a cut
                // that broke the syntax, an `Ok` for one that landed between
                // two tables. A prefix holding only comments is a policy with
                // no rules and that is correct: the file said nothing, and
                // saying nothing is not the same as being unreadable.
                if let Ok(policy) = policy_from(&damaged) {
                    for rule in &policy.rules {
                        assert!(!rule.id.is_empty(), "a rule with no id loaded");
                        assert!(
                            !rule.id.is_empty(),
                            "a rule with no check survived a truncation: {}",
                            rule.id
                        );
                    }
                }
                checked += 1;
            }

            // Bytes replaced rather than removed, which reaches the arms a
            // truncation cannot: a quote inside a value, a NUL, a brace where a
            // key was.
            for (index, byte) in b"\"\0[=\n".iter().enumerate() {
                let mut damaged = bytes.to_vec();
                for position in (index..damaged.len()).step_by(311) {
                    damaged[position] = *byte;
                }
                let damaged = String::from_utf8_lossy(&damaged).into_owned();
                // The assertion is that this returns rather than panicking, and
                // that an `Ok` is a policy somebody could have written.
                if let Ok(policy) = policy_from(&damaged) {
                    for rule in &policy.rules {
                        assert!(!rule.id.is_empty(), "a rule with no id loaded");
                    }
                }
                checked += 1;
            }
        }
        assert!(
            checked > 100,
            "the corpus produced too few cases to mean anything: {checked}"
        );
    }

    #[test]
    fn a_verb_vocabulary_for_a_verb_the_table_does_not_match_is_refused() {
        // The shim never stands in front of that invocation, so the flags
        // declared beside it classify nothing -- and it is usually a verb
        // somebody meant to add to `match` and added here instead, which is the
        // exact mistake this catches while it is still cheap.
        let error = policy_from(
            "[rule.judge]\nmessage = \"m\"\nexec = \"/bin/false\"\ncommand.before = [\"gh\"]\n\n             [[shim]]\ncommand = \"gh\"\nmatch = [\"pr:create\"]\ntext_flags = [\"-b\"]\n\n             [[shim.verbs]]\nmatch = [\"issue:close\"]\ntext_flags = [\"-c\"]\n",
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("issue:close"), "{text}");
        assert!(text.contains("classify nothing"), "{text}");

        // An entry naming no verb at all is the same defect with less to say.
        let empty = policy_from(
            "[rule.judge]\nmessage = \"m\"\nexec = \"/bin/false\"\ncommand.before = [\"gh\"]\n\n             [[shim]]\ncommand = \"gh\"\nmatch = [\"pr:create\"]\ntext_flags = [\"-b\"]\n\n             [[shim.verbs]]\nmatch = []\ntext_flags = [\"-c\"]\n",
        )
        .unwrap_err();
        assert!(empty.to_string().contains("names no verb"), "{empty}");
    }

    #[test]
    fn a_verb_vocabulary_the_table_does_match_loads_including_through_a_wildcard() {
        // A `verb:*` in the table covers a `verb:noun` entry, because that is
        // what the table's own matcher already means by it.
        policy_from(
            "[rule.judge]\nmessage = \"m\"\nexec = \"/bin/false\"\ncommand.before = [\"gh\"]\n\n             [[shim]]\ncommand = \"gh\"\nmatch = [\"issue:*\"]\ntext_flags = [\"-b\"]\n\n             [[shim.verbs]]\nmatch = [\"issue:close\"]\ntext_flags = [\"-c\"]\n",
        )
        .unwrap();
    }

    #[test]
    fn two_shim_tables_naming_one_command_are_refused() {
        // The map they resolve into is keyed by command, so the second table
        // replaced the first and said nothing. Reproduced before this was
        // written: a policy declaring `gh` twice -- `pr:create` with `--body`,
        // `issue:close` with `--comment` -- loaded clean, refused the comment,
        // and exec'd `gh pr create --body ...` unexamined.
        let error = policy_from(
            "[rule.judge]\nmessage = \"m\"\nexec = \"/bin/false\"\ncommand.before = [\"gh\"]\n\n             [[shim]]\ncommand = \"gh\"\nmatch = [\"pr:create\"]\ntext_flags = [\"-b\"]\n\n             [[shim]]\ncommand = \"gh\"\nmatch = [\"issue:close\"]\ntext_flags = [\"-c\"]\n",
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("two `[[shim]]` tables"), "{text}");
        assert!(text.contains("\"gh\""), "{text}");
        // It says what the silence cost, because "duplicate" alone reads as
        // tidiness rather than as text published unchecked.
        assert!(text.contains("nothing checking them"), "{text}");
    }

    #[test]
    fn one_shim_table_may_name_every_verb_for_its_command() {
        // The cure the refusal names, and the shape every policy already uses.
        policy_from(
            "[rule.judge]\nmessage = \"m\"\nexec = \"/bin/false\"\ncommand.before = [\"gh\"]\n\n             [[shim]]\ncommand = \"gh\"\nmatch = [\"pr:create\", \"issue:close\"]\ntext_flags = [\"-b\"]\n",
        )
        .unwrap();

        // And two tables for two DIFFERENT commands are not the same thing.
        policy_from(
            "[rule.judge]\nmessage = \"m\"\nexec = \"/bin/false\"\ncommand.before = [\"gh\", \"glab\"]\n\n             [[shim]]\ncommand = \"gh\"\nmatch = [\"pr:create\"]\ntext_flags = [\"-b\"]\n\n             [[shim]]\ncommand = \"glab\"\nmatch = [\"mr:create\"]\ntext_flags = [\"-d\"]\n",
        )
        .unwrap();
    }

    #[test]
    fn a_rule_that_matches_its_own_declaration_and_selects_it_is_refused() {
        // The report this replaces named the policy file and a line number and
        // was about nothing in the tree: the rule describing itself. There is
        // no version of that finding a reader can act on, so it is refused
        // where it can still be called what it is.
        let error = policy_from(
            "[rule.unanchored]\nregexp = 'YubiKey'\nmessage = \"m\"\n[rule.unanchored.files]\ninclude = [\".\"]\n",
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("unanchored"), "{text}");
        assert!(text.contains("matches its own declaration"), "{text}");
        // The three cures, because a refusal that does not name one is a wall.
        assert!(text.contains("files.exclude"), "{text}");
        assert!(text.contains("files.include"), "{text}");
        assert!(text.contains("anchor"), "{text}");
    }

    #[test]
    fn a_require_regexp_that_satisfies_itself_is_refused() {
        // The inverted case, and the quieter one. `regexp` matching its own
        // declaration is a finding that is always there and gets read.
        // `require_regexp` matching it is a PASS that is always there: the
        // policy file meets the requirement by naming it, so it is the one file
        // in the corpus that can never fail the rule, and nothing ever says so.
        let error = policy_from(
            "[rule.every-file]\nrequire_regexp = 'Copyright'\nmessage = \"m\"\n[rule.every-file.files]\ninclude = [\".\"]\n",
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("every-file"), "{text}");
        assert!(text.contains("require_regexp"), "{text}");
        // The message says what goes wrong HERE, which is the opposite of what
        // goes wrong for `regexp`: a reader told the wrong one fixes nothing.
        assert!(text.contains("exempt"), "{text}");
        assert!(!text.contains("violating this rule"), "{text}");
        // And the same three cures.
        assert!(text.contains("files.exclude"), "{text}");
    }

    #[test]
    fn a_requirement_the_policy_file_does_not_declare_still_loads() {
        // The narrowing that fixes it, and the case that must keep working: a
        // requirement whose pattern is nowhere in its own section has nothing
        // to exempt.
        policy_from(
            "[rule.every-file]\nrequire_regexp = 'Copyright'\nmessage = \"m\"\n[rule.every-file.files]\ninclude = [\".\"]\nexclude = [\"**/rg-policy.toml\"]\n",
        )
        .unwrap();
    }

    #[test]
    fn an_anchored_pattern_cannot_match_the_key_it_is_written_under() {
        // `^Status:` does not match `regexp = '^Status:...'` -- that line begins
        // with `regexp`. Worth a test rather than a remark, because a dodge
        // written to avoid a self-match that never existed has been transcribed
        // across three repositories, and this is the fact that makes it
        // deletable.
        policy_from(
            "[rule.anchored]\nregexp = '^Status:'\nmessage = \"m\"\n[rule.anchored.files]\ninclude = [\".\"]\n",
        )
        .unwrap();
    }

    #[test]
    fn a_self_matching_pattern_that_cannot_reach_the_policy_file_still_loads() {
        // The case that decides whether this check is usable at all. Measured
        // over 82 policy files, 54 `regexp` rules matched their own text and
        // NONE of them selected the file it was written in -- an `include` of
        // source directories does not reach `policy/`. Refusing on the text
        // alone would have failed 54 rules that work.
        for narrowing in [
            "[rule.narrow.files]\ninclude = [\"src\"]\n",
            "[rule.narrow.files]\ninclude = [\".\"]\nglob = [\"*.go\"]\n",
            "[rule.narrow.files]\ninclude = [\".\"]\nexclude = [\"**/rg-policy.toml\"]\n",
        ] {
            let text = format!("[rule.narrow]\nregexp = 'YubiKey'\nmessage = \"m\"\n{narrowing}");
            let outcome = policy_from(&text);
            assert!(
                outcome.is_ok(),
                "{narrowing:?} should still load: {:?}",
                outcome.err()
            );
        }
    }

    #[test]
    fn a_declaration_runs_to_the_next_table_that_is_not_its_own_sub_table() {
        // `[rule.x.files]` belongs to `rule.x`; `[rule.y]` does not. Getting
        // this wrong in the widening direction would read a sibling's pattern
        // as this rule's own text and refuse a rule that is fine.
        let text =
            "[rule.x]\nregexp = 'a'\n[rule.x.files]\ninclude = [\".\"]\n[rule.y]\nregexp = 'b'\n";
        let section = declaration_of(text, "x").unwrap();
        assert!(section.contains("regexp = 'a'"), "{section}");
        assert!(section.contains("include"), "{section}");
        assert!(!section.contains("regexp = 'b'"), "{section}");
        assert!(declaration_of(text, "absent").is_none());
    }

    #[test]
    fn a_policy_that_cannot_be_parsed_is_an_error_and_not_an_empty_policy() {
        // The invariant stated directly, since the sweep above can only assert
        // it over inputs that happen to be damaged the right way.
        for damaged in [
            "this is not toml [[[",
            "[rule.a]\nregexp = \"unterminated",
            "[rule.a]\n[rule.a]\n",
            "[[rule]]\nid = \"array-of-tables-is-the-old-schema\"\n",
            "\u{0}\u{0}\u{0}",
        ] {
            let outcome = policy_from(damaged);
            assert!(
                outcome.is_err(),
                "{damaged:?} loaded as a policy with {} rule(s)",
                outcome.map_or(0, |policy| policy.rules.len())
            );
        }
    }

    #[test]
    fn a_bundled_set_may_not_reach_past_the_stages_it_declares() {
        // The constraint the fleet audit could only state as a risk to hold:
        // "a new guard gets a new set name rather than joining an existing
        // one". A set's rules arrive in every inheriting repository with no
        // diff in any of them, so the permission has to be written in the set
        // -- and reaching past it has to be a load error rather than a
        // convention somebody remembers.
        let error = parse_bundled(
            "pretend",
            "[set]\nstages = [\"manual\"]\n\n[rule.thing]\nbuiltin = \"no-merge-commit\"\ngit.hooks = [\"pre-commit\"]\n",
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("pre-commit"), "{text}");
        assert!(text.contains("only manual"), "{text}");

        // The default is the strict one: a set that says nothing about stages
        // installs nothing.
        let silent = parse_bundled(
            "pretend",
            "[rule.thing]\nbuiltin = \"no-merge-commit\"\ngit.hooks = [\"pre-commit\"]\n",
        )
        .unwrap_err();
        assert!(silent.to_string().contains("no hook at all"));

        // And a set staying inside its ceiling loads.
        parse_bundled(
            "pretend",
            "[set]\nstages = [\"manual\"]\n\n[rule.thing]\nbuiltin = \"no-merge-commit\"\ngit.hooks = [\"manual\"]\n",
        )
        .unwrap();
    }

    #[test]
    fn a_bundled_set_may_not_reach_past_the_commands_it_declares() {
        // The stage ceiling's argument at the other seam: a rule joining a set
        // starts standing in front of a real command in every inheriting
        // repository, so the permission is written in the set.
        let error = parse_bundled(
            "pretend",
            "[set]\ncommands = [\"gh\"]\n\n[rule.thing]\nbuiltin = \"text-guards\"\ncommand.before = [\"git push\"]\n",
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("git push"), "{text}");
        assert!(text.contains("only gh"), "{text}");

        // The default is the strict one: a set that says nothing about
        // commands stands in front of none.
        let silent = parse_bundled(
            "pretend",
            "[rule.thing]\nbuiltin = \"text-guards\"\ncommand.before = [\"gh\"]\n",
        )
        .unwrap_err();
        assert!(silent.to_string().contains("no command at all"));

        // Verbatim lines rather than first words: `git` does not admit
        // `git push`, or the set could widen its reach without editing the
        // line that says what it may do.
        parse_bundled(
            "pretend",
            "[set]\ncommands = [\"git\"]\n\n[rule.thing]\nbuiltin = \"text-guards\"\ncommand.before = [\"git push\"]\n",
        )
        .unwrap_err();

        // And a set staying inside its ceiling loads.
        parse_bundled(
            "pretend",
            "[set]\ncommands = [\"gh\", \"git push\"]\n\n[rule.thing]\nbuiltin = \"text-guards\"\ncommand.before = [\"gh\", \"git push\"]\n",
        )
        .unwrap();
    }

    #[test]
    fn a_bundled_set_may_not_declare_a_shim() {
        // A set supplies checkers and never shims; only `.rules` is adopted at
        // load, so a `[[shim]]` here would vanish silently -- and a program in
        // front of a real command is not something to acquire from a version
        // bump even if it did not.
        let error = parse_bundled(
            "pretend",
            "[set]\ncommands = [\"gh\"]\n\n[[shim]]\ncommand = \"gh\"\nmatch = [\"pr:create\"]\ntext_flags = [\"-b\"]\n\n[rule.thing]\nbuiltin = \"text-guards\"\ncommand.before = [\"gh\"]\n",
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains("program in front of a real command"),
            "{text}"
        );
    }

    #[test]
    fn inheriting_published_text_without_the_shims_is_refused_naming_the_set() {
        // The set's whole design: it supplies the checkers, and the repository
        // that has not declared the shims is refused with the cure that is
        // actually available to it -- there is no `command.before` entry in
        // this file to drop.
        let error = policy_from("[inherit]\nsets = [\"published-text\"]\n").unwrap_err();
        let text = error.to_string();
        assert!(text.contains("published-text"), "{text}");
        assert!(text.contains("[[shim]]"), "{text}");

        // With the tables declared, the same inherit loads, and the set's
        // rules arrive carrying its name.
        let policy = policy_from(
            "[inherit]\nsets = [\"published-text\"]\n\n\
             [[shim]]\ncommand = \"gh\"\nmatch = [\"pr:create\"]\ntext_flags = [\"-b\", \"--body\"]\n\n\
             [[shim]]\ncommand = \"git\"\nmatch = [\"push:*\"]\n",
        )
        .unwrap();
        let arrived = policy
            .rules
            .iter()
            .filter(|rule| rule.origin == Origin::Set(String::from("published-text")))
            .count();
        assert_eq!(arrived, 3, "{:?}", policy.rules);
    }

    #[test]
    fn a_meta_text_guard_runs_at_the_command_seam_and_nowhere_else() {
        // At a git hook or in a scan every rule the consultation would run
        // already runs itself, so the only seam these may declare is the one
        // they exist for.
        for place in ["git.hooks = [\"commit-msg\"]", "files.include = [\".\"]"] {
            let error = policy_from(&format!(
                "[rule.consult]\nbuiltin = \"text-guards\"\n{place}\n"
            ))
            .unwrap_err();
            let text = error.to_string();
            assert!(text.contains("command.before"), "{place}: {text}");
        }
    }

    #[test]
    fn a_set_this_binary_does_not_ship_is_refused_by_name() {
        let error = policy_from(
            "[inherit]
sets = [\"invented\"]
",
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("invented"), "{text}");
        // And the error carries the list, so the cure is in the message rather
        // than in a document the reader has to go and find.
        assert!(text.contains("process-residue"), "{text}");
    }
}
