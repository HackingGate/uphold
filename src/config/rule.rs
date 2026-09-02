//! What a rule IS: one check, the knobs that check reads, and where it runs.
//!
//! Split out of `config` because the type outgrew a struct. While a rule was
//! thirty-eight `Option` fields in one flat shape, "which fields name a check"
//! was written out four times -- an array for the count, a sentence for the
//! error, a reader for the answer, a list for the parameters -- and the four
//! were free to disagree. [`Check`] is one variant per check, carrying only
//! what that check reads, so all four readings are the type and the seams that
//! used to test for a rule with two checks or a knob nobody reads have nothing
//! left to test for.
//!
//! [`Written`] is the one place the flat shape still exists: a file writes keys
//! and `parse` reads them as one check, which is the only moment a rule can
//! still say two things and the moment an id exists to name in the refusal.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use super::{CommandWhere, Files, Git, Origin};
use crate::error::{Fatal, Result};

/// What a rule checks. NOT a field -- there is nothing in the file to read it
/// from, because the field the author wrote IS the answer.
///
/// `kind` used to be that field, and it was two questions wearing one name.
/// `kind = "pattern"` said what the rule checks; `kind = "guard"` said where it
/// runs, in a word belonging to no tool a reader has met. Nothing said WHERE a
/// pattern rule ran, and nothing could say where a guard ran, because the stage
/// list was a `match` arm in this crate.
///
/// So the discriminant is gone from the file. `regexp` means a regex over file
/// contents, `max_lines` means a line-count limit, `builtin` names a check
/// compiled in here -- one field, and it is the same field the evaluator reads,
/// which is what makes a rule impossible to mislabel. Where it runs is
/// [`Rule::files`], [`Rule::git`] and [`Rule::command`], and an absent table is
/// a place the rule does not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CheckKind {
    /// `regexp`: a regex over file contents that must find zero hits.
    Regexp,
    /// `comment_regexp`: the same regex, over the COMMENTS of a parsed file
    /// rather than over its bytes. A separate check and not a `files.*` knob,
    /// because it answers a different question about a different subject: a
    /// pattern that must not appear anywhere is not the pattern that must not
    /// appear in prose a reader is asked to trust.
    CommentRegexp,
    /// `prose_regexp`: the same regex again, over the PROSE of a file rather
    /// than over its bytes or its comments. Which text counts as prose is
    /// decided by the file's kind: a document is prose apart from its code
    /// blocks, a source file's prose is its comments, a configuration file's is
    /// its `#` lines. A separate check and not a `files.*` knob for the reason
    /// `comment_regexp` is one -- the subject is different, so the pattern
    /// written against it means something different.
    ProseRegexp,
    /// `trivial_comments`: a comment that says only what the code under it
    /// already says.
    TrivialComments,
    /// `forbidden_literals` / `forbidden_literals_from`: literals produced at
    /// runtime -- a machine's own identity, or a command's output -- each of
    /// which must appear nowhere in the selected files.
    ForbiddenLiterals,
    /// `max_lines`: a line-count limit with an optional baseline ratchet.
    MaxLines,
    /// `max_bytes`: a byte-count limit with an optional baseline ratchet.
    ///
    /// A sibling of `max_lines` rather than a unit knob on it, because the two
    /// bound different things and a repository means one of them. Lines are
    /// what a reader feels, and a reflow changes them; bytes do not move when a
    /// paragraph is rewrapped, and a cap in lines is defeated by longer lines.
    /// A rule that wants both writes two rules, which is what the
    /// exactly-one-check matrix already says everywhere else.
    MaxBytes,
    /// `path_regexp`: a regex matched against tracked file paths.
    PathRegexp,
    /// `require_regexp`: a regex that must be found in every selected file.
    RequireRegexp,
    /// `encoding`: a charset the selected files must decode cleanly under.
    Encoding,
    /// `allowed_scripts`: Unicode scripts admitted for the selected files.
    AllowedScripts,
    /// `builtin`: a check compiled into this binary and named.
    Builtin,
    /// `exec`: an executable consulted about one subject, over the contract in
    /// `shim`.
    Exec,
}

impl CheckKind {
    /// Evaluation order, and the only enumeration of the checks anywhere.
    pub(crate) const ALL: [Self; 13] = [
        Self::Regexp,
        Self::CommentRegexp,
        Self::ProseRegexp,
        Self::TrivialComments,
        Self::ForbiddenLiterals,
        Self::MaxLines,
        Self::MaxBytes,
        Self::PathRegexp,
        Self::RequireRegexp,
        Self::Encoding,
        Self::AllowedScripts,
        Self::Builtin,
        Self::Exec,
    ];

    /// The FIELD NAME, not a category name. What a reader is told when a rule
    /// is wrong has to be the thing they can go and edit.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Regexp => "regexp",
            Self::CommentRegexp => "comment_regexp",
            Self::ProseRegexp => "prose_regexp",
            Self::TrivialComments => "trivial_comments",
            Self::ForbiddenLiterals => "forbidden_literals",
            Self::MaxLines => "max_lines",
            Self::MaxBytes => "max_bytes",
            Self::PathRegexp => "path_regexp",
            Self::RequireRegexp => "require_regexp",
            Self::Encoding => "encoding",
            Self::AllowedScripts => "allowed_scripts",
            Self::Builtin => "builtin",
            Self::Exec => "exec",
        }
    }

    /// Whether this check has no meaning without `[rule.files]`.
    ///
    /// `builtin` is deliberately not here and deliberately not refused either:
    /// a built-in may read files (`links-resolve` walks markdown targets), a
    /// commit message, or a push range, and which one it reads is the built-in's
    /// business. Its `[rule.files]` is optional for that reason alone.
    pub(crate) const fn requires_files(self) -> bool {
        matches!(
            self,
            Self::Regexp
                | Self::CommentRegexp
                | Self::ProseRegexp
                | Self::TrivialComments
                | Self::ForbiddenLiterals
                | Self::MaxLines
                | Self::MaxBytes
                | Self::PathRegexp
                | Self::RequireRegexp
                | Self::Encoding
                | Self::AllowedScripts
        )
    }
}

impl std::fmt::Display for CheckKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The flat shape a policy file writes, before it is read as one check.
///
/// Every field here is a key somebody types in `policy/principles.toml`, and
/// what each one MEANS is documented on the type it becomes -- [`Check`] for
/// the checks and their knobs, [`Parameters`] for the settings a built-in
/// reads. This struct is deliberately a bare list: it exists for the length of
/// one `toml::from_str`, and the moment `parse` has a rule id to name in a
/// refusal it becomes a [`Rule`], which cannot hold two checks or a knob
/// nothing reads.
///
/// `deny_unknown_fields` is here rather than on `Rule` for the reason the
/// conversion is: an unknown key is a spelling question the deserializer can
/// answer on its own, and everything the id has to appear in is answered after.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Written {
    pub message: Option<String>,
    pub regexp: Option<String>,
    pub comment_regexp: Option<String>,
    pub prose_regexp: Option<String>,
    pub trivial_comments: Option<bool>,
    pub path_regexp: Option<String>,
    pub require_regexp: Option<String>,
    pub max_lines: Option<u64>,
    pub max_bytes: Option<u64>,
    pub encoding: Option<String>,
    pub allowed_scripts: Vec<String>,
    pub exclusive: Option<bool>,
    pub forbidden_literals: Option<String>,
    pub forbidden_literals_from: Option<String>,
    pub ignore_literals: Option<Vec<String>>,
    pub builtin: Option<String>,
    pub exec: Option<String>,
    pub files: Option<Files>,
    pub git: Option<Git>,
    pub command: Option<CommandWhere>,
    pub subjects: Option<Vec<String>>,
    pub require_any_link: Option<bool>,
    pub allow_outside_repo: Option<bool>,
    pub require_any_anchor: Option<bool>,
    pub command_sources: Option<Vec<String>>,
    pub private_owners: Option<Vec<String>>,
    pub private_owners_from: Option<String>,
    pub public_repos: Option<Vec<String>>,
    pub refuse_unknown: Option<bool>,
    pub foreign_hosts: Option<Vec<String>>,
    pub visibility: Option<String>,
    pub owner: Option<String>,
    pub owner_required: Option<bool>,
    pub allowed_owners: Option<Vec<String>>,
    pub allowed_repos: Option<Vec<String>>,
    pub visibility_required: Option<bool>,
    pub allow: Option<Vec<String>>,
}

/// The literals a `forbidden_literals` rule searches for, and where they come
/// from.
///
/// Two spellings of one check -- a named built-in source, or a command
/// producing the same lines -- so they are one variant with two arms rather
/// than two checks. A rule carrying both used to be refused by a validator
/// reading two `Option`s; here there is one field and no such rule.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub(crate) enum Literals {
    /// A named built-in source of literals describing the running machine --
    /// `running-os-identity`, `running-os-metadata`, `running-default-route`.
    /// The name says what fails: a literal describing THIS machine, found in
    /// content.
    Named { forbidden_literals: String },
    /// A command whose stdout carries one literal per line.
    ///
    /// This is what replaced `policy/sources.py`. A repository that needed a
    /// custom source used to ship a Python module the engine imported, which
    /// made every consumer of the engine a Python host and made the plugin's
    /// `Needle` a different class than the engine's. A command has neither
    /// problem and can be written in anything.
    From { forbidden_literals_from: String },
}

/// The settings a built-in reads, and the only place they can be written.
///
/// These were environment variables, every one of them, because git-guards had
/// no configuration file at all. The per-owner prefix scheme --
/// `<OWNER>_ALLOWED_PUSH_OWNERS` beside `WORKSPACE_ALLOWED_PUSH_OWNERS` --
/// existed only because configuration was environment-only while one machine
/// holds several workspaces, and a per-workspace FILE is the workspace scope.
///
/// They live inside [`Check::Builtin`] because a built-in is the only thing
/// that reads any of them: written beside a `regexp` there is no field to put
/// them in. Which BUILT-IN reads which is a question about a name rather than
/// about a type, so [`Parameters::written`] and `guard::parameters` still meet
/// at load -- that refusal is a name check and stays one.
///
/// Each is `Option` rather than defaulted, because WRITTEN and ABSENT are
/// different facts to that check. A defaulted field could not be refused: an
/// explicit `allowed_owners = []` on a built-in that reads none would be
/// indistinguishable from the field never having been written, and it is
/// exactly the thing that looks enforced while read by nothing.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct Parameters {
    /// Owners whose repositories are private regardless of what a forge says.
    ///
    /// Writing them here is right for a repository staying private and wrong
    /// for one about to be published: the list of names that must not be
    /// published is itself a list of private names, so a public repository
    /// cannot hold it. `uphold audit --for-publication` reports a literal
    /// list as a finding for exactly that reason, and `private_owners_from` is
    /// the way out.
    pub private_owners: Option<Vec<String>>,
    /// A command whose stdout is one private owner per line.
    pub private_owners_from: Option<String>,
    /// Names to treat as public without asking a forge.
    pub public_repos: Option<Vec<String>>,
    /// Treat a name whose visibility could not be determined as private.
    pub refuse_unknown: Option<bool>,
    /// This rule's own `foreign_hosts`, replacing the policy's for this rule.
    ///
    /// Written where one rule reads a corner of the tree with its own citation
    /// habits -- a bibliography under `docs/` that the tree-wide rule need not
    /// quiet everywhere. Replaces rather than extends, for the reason a scoped
    /// `allowed_scripts` list does: what is declared beside the rule is the
    /// whole truth for that rule, and nothing invisible reaches in.
    pub foreign_hosts: Option<Vec<String>>,
    /// This repository's visibility, when it should not be looked up.
    pub visibility: Option<String>,
    /// The owner this workspace belongs to. Was `WORKSPACE_PINNED_OWNER`.
    pub owner: Option<String>,
    /// Refuse to run this guard in the mode where it works out the owner for
    /// itself.
    ///
    /// The field a BUNDLED set needs. A set that carried `prevent-public-push`
    /// with no owner would be deciding, on behalf of every repository that
    /// inherits it, that origin is who they are -- which is the tautology the
    /// guard's own documentation warns about, shipped as a default. With this
    /// set, a repository that has not said who it is hears so, once, instead of
    /// being told its pushes are fine by a rule that read the answer off the
    /// thing it is guarding.
    pub owner_required: Option<bool>,
    /// Owners this repository may push to.
    pub allowed_owners: Option<Vec<String>>,
    /// Repositories, by `owner/name`, this repository may push to.
    pub allowed_repos: Option<Vec<String>>,
    /// Refuse to run until this repository has said whether it is published.
    ///
    /// The `owner_required` argument, transposed to the other fact a set cannot
    /// be handed. The private-name guards fire only on a PUBLIC tree, so a
    /// repository that has declared nothing has the whole family fall back to
    /// asking the forge -- which answers `unknown` with no token, on no
    /// network, and for the repository whose visibility is the thing about to
    /// change. Without this, a set carrying these rules would be deciding on
    /// every inheriting repository's behalf that a network answer is good
    /// enough for the one condition the guard fires under.
    ///
    /// Exit 2 and not a refusal, for the reason `owner_required` is: "this text
    /// is wrong" and "nothing here can tell whether it is" are different
    /// answers, and only one of them is fixed by editing the text.
    pub visibility_required: Option<bool>,
    /// Codepoints admitted, optionally under one path glob:
    /// `"U+00A0:tests/fixtures/**"`, or `"U+3000"` for the whole tree.
    ///
    /// An entry can GRANT a character and never revoke one, which is what makes
    /// the list safe to extend without re-reading it: adding a line cannot
    /// tighten the check on anybody else's file.
    pub allow: Option<Vec<String>>,
    /// links-resolve: refuse a selection that yields no links at all.
    pub require_any_link: Option<bool>,
    /// links-resolve: let a link resolve outside the repository.
    pub allow_outside_repo: Option<bool>,
    /// anchors-resolve: refuse a selection that carries no anchor at all.
    ///
    /// Deliberately not the mirror of `require_any_link`, and the asymmetry is
    /// the point. There, zero links means the selection was narrowed out from
    /// under the rule. Here, zero anchors is the GOAL STATE -- every fact
    /// rendered or read at runtime, no sentence needing one pinned -- so a
    /// floor on by default would refuse the best outcome the check can
    /// produce. A repository whose anchors are load-bearing opts in.
    pub require_any_anchor: Option<bool>,
    /// commands-resolve: where a command's own sources live, as globs in which
    /// `{}` stands for the command's name.
    ///
    /// A PATTERN and not a table of names, and the difference is the whole
    /// design. `["*/cmd/{}/**/*.go"]` says what a command looks like in this
    /// tree; a list of command names would be a second copy of the tree, free to
    /// go stale, which is the class of defect this rule exists to refuse. The
    /// convention stays in the repository that has one, and nothing about one
    /// workspace's layout is compiled into the binary.
    ///
    /// The capture also BOUNDS the union. A command's verbs are read from the
    /// files its own pattern selects and no others, so a sibling binary in the
    /// same repository cannot lend it verbs -- a widening that read the whole
    /// repository resolved a flag-only command to its neighbour's verbs, and a
    /// document naming one of them would have passed.
    pub command_sources: Option<Vec<String>>,
}

impl Parameters {
    /// The parameter fields this rule writes, by field name.
    ///
    /// The one list of what a built-in may be handed, and the only one: the
    /// refusal below reads it, and `guard::parameters` says which names each
    /// built-in answers to. Written on a rule that is not a built-in at all,
    /// these have no field to sit in, so that half is refused where a written
    /// file becomes a [`Check`] and never reaches here.
    fn written(&self) -> Vec<&'static str> {
        [
            self.owner.is_some().then_some("owner"),
            self.owner_required.is_some().then_some("owner_required"),
            self.allowed_owners.is_some().then_some("allowed_owners"),
            self.allowed_repos.is_some().then_some("allowed_repos"),
            self.private_owners.is_some().then_some("private_owners"),
            self.private_owners_from
                .is_some()
                .then_some("private_owners_from"),
            self.public_repos.is_some().then_some("public_repos"),
            self.refuse_unknown.is_some().then_some("refuse_unknown"),
            self.foreign_hosts.is_some().then_some("foreign_hosts"),
            self.visibility.is_some().then_some("visibility"),
            self.visibility_required
                .is_some()
                .then_some("visibility_required"),
            self.allow.is_some().then_some("allow"),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// Refuse every setting written here that nothing would read.
    ///
    /// The one place that question is answered, for both halves of it. A rule
    /// that runs no built-in has no field for any of these -- `builtin` is
    /// `None` and the check's own name is what the refusal quotes -- and a rule
    /// that runs the WRONG built-in is the same defect one level in. Written
    /// once because the sentences have to agree: each names where the field
    /// does work, which is what makes the refusal a fix rather than a docs
    /// round-trip.
    fn refuse_unread(&self, id: &str, check: &str, builtin: Option<&str>) -> Result<()> {
        if builtin != Some("links-resolve") {
            let link_fields: Vec<&str> = [
                self.require_any_link
                    .is_some()
                    .then_some("require_any_link"),
                self.allow_outside_repo
                    .is_some()
                    .then_some("allow_outside_repo"),
            ]
            .into_iter()
            .flatten()
            .collect();
            if !link_fields.is_empty() {
                return Err(Fatal::new(format!(
                    "rule {id:?}: {} read(s) links, and only the `links-resolve` built-in \
                     reads any -- on this rule the field would be read by nothing and \
                     would look like configuration that works",
                    link_fields.join(" and ")
                )));
            }
        }
        if builtin != Some("anchors-resolve") && self.require_any_anchor.is_some() {
            return Err(Fatal::new(format!(
                "rule {id:?}: `require_any_anchor` is read by the `anchors-resolve` built-in \
                 and nothing else -- on this rule the field would be read by nothing and \
                 would look like configuration that works"
            )));
        }
        if builtin != Some("commands-resolve") && self.command_sources.is_some() {
            return Err(Fatal::new(format!(
                "rule {id:?}: `command_sources` is read by the `commands-resolve` built-in \
             and nothing else -- on this rule the field would be read by nothing and \
             would look like configuration that works"
            )));
        }

        let written = self.written();
        if written.is_empty() {
            return Ok(());
        }
        // Which BUILT-IN reads which is a question about a name rather than
        // about a type, and `guard::parameters` is the one answer to it.
        let reads = builtin.map_or::<&[&str], _>(&[], crate::guard::parameters);
        let foreign: Vec<&str> = written
            .into_iter()
            .filter(|parameter| !reads.contains(parameter))
            .collect();
        if foreign.is_empty() {
            return Ok(());
        }
        let reader = match builtin {
            Some(name) if reads.is_empty() => format!("built-in {name:?} reads no parameters"),
            Some(name) => format!("built-in {name:?} reads only {}", reads.join(", ")),
            None => format!("`{check}` reads no built-in parameters"),
        };
        Err(Fatal::new(format!(
            "rule {id:?}: {} would be read by nothing -- {reader}. A parameter \
             read by nothing looks enforced and is not; delete it, or move it \
             to the rule whose built-in reads it",
            foreign.join(" and ")
        )))
    }
}

/// What a rule checks, carrying the knobs that check reads and no others.
///
/// The field was the discriminant; now the TYPE is. A rule holds one variant,
/// so "two fields say what it checks", "`exclusive` beside a check that reads
/// no scripts", "`ignore_literals` beside a check that searches for no
/// literals" and "a built-in parameter on a `regexp` rule" are not states a
/// loaded rule can be in -- which is why the three lists that used to
/// transcribe "which fields name a check" are gone and only the reading in
/// [`Check::of_written`] remains.
///
/// Serialized untagged, so `uphold rules --sets --json` writes the flat keys a
/// policy file writes: the document that exists to be diffed between two
/// binaries says what the file says, and no writer names the fields by hand.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub(crate) enum Check {
    /// `regexp`: a regex over file contents that must find zero hits.
    Regexp { regexp: String },
    /// `comment_regexp`: the same regex, over the COMMENTS of a parsed file
    /// rather than over its bytes. The text is the comment with its markers
    /// stripped, so a pattern never has to know whether the language spells one
    /// `//` or `#`, and `let marker = "// TODO";` is not a comment however it
    /// reads.
    ///
    /// A separate check and not a `files.*` knob, because it answers a
    /// different question about a different subject: a pattern that must not
    /// appear anywhere is not the pattern that must not appear in prose a
    /// reader is asked to trust.
    ///
    /// Documentation comments are excluded. `///` is an artefact rustdoc
    /// publishes, not a remark about the code, and a rule that cannot tell the
    /// two apart is one whose fix deletes a public item's documentation.
    CommentRegexp { comment_regexp: String },
    /// `prose_regexp`: the same regex again, over the PROSE of a file -- the
    /// sentences, with whatever is not prose left out and whatever is wrapped
    /// unwrapped into one line, so a pattern never has to know that a paragraph
    /// was rewrapped or that a comment is spelled `//` here and `#` there.
    ///
    /// The extractor is chosen by the file's kind -- a document minus its code
    /// blocks, a source file's comments, a configuration file's `#` lines --
    /// and a file of no kind this binary reads prose from contributes nothing.
    /// That silence is why a `prose_regexp` rule is the one most worth giving a
    /// `files.min_selected`: a selection narrowed to file kinds with no
    /// extractor reports a pass over prose nobody read.
    ///
    /// Documentation comments ARE prose and are included, which is the one
    /// place this parts company with `comment_regexp`. That check excludes them
    /// because acting on its findings deletes a public item's documentation;
    /// this one is about how a sentence is written, and a published sentence is
    /// exactly the one a style rule is for.
    ProseRegexp { prose_regexp: String },
    /// `trivial_comments`: a comment that contributes no word the code beneath
    /// it does not already name. There is no pattern to write: the check
    /// compares the comment against the identifiers and literals of the
    /// statement it introduces.
    TrivialComments { trivial_comments: bool },
    /// `path_regexp`: a regex matched against tracked file PATHS rather than
    /// their contents.
    PathRegexp { path_regexp: String },
    /// `require_regexp`: a regex that must be found in every selected file.
    RequireRegexp { require_regexp: String },
    /// `max_lines`: a line-count limit with an optional baseline ratchet.
    MaxLines { max_lines: u64 },
    /// `max_bytes`: a byte-count limit with an optional baseline ratchet.
    ///
    /// A sibling of `max_lines` rather than a unit knob on it, because the two
    /// bound different things and a repository means one of them. Lines are
    /// what a reader feels, and a reflow changes them; bytes do not move when a
    /// paragraph is rewrapped, and a cap in lines is defeated by longer lines.
    /// A rule that wants both writes two rules, which is what one variant per
    /// check already says everywhere else.
    MaxBytes { max_bytes: u64 },
    /// `encoding`: a charset the selected files must decode cleanly under,
    /// named by its WHATWG label: `"Shift_JIS"` here means what it means to
    /// every browser.
    ///
    /// Encoding is a property of the BYTES where `allowed_scripts` is a
    /// property of the decoded text -- one field fusing them could not say
    /// "UTF-8 file containing Japanese" and "Shift-JIS file containing
    /// Japanese" apart, and those are different declarations about different
    /// layers.
    Encoding { encoding: String },
    /// `allowed_scripts`: Unicode scripts admitted for the selected files, as
    /// UTS #24 spells them -- `allowed_scripts = ["Hiragana"]` admits exactly
    /// what `\p{Script=Hiragana}` matches. The list is the WHOLE truth for the
    /// files this rule selects: it replaces the top-level declaration rather
    /// than unioning with it, so what is declared beside the path is what holds
    /// for the path.
    AllowedScripts {
        allowed_scripts: Vec<String>,
        /// The reverse direction: these scripts are ALSO refused in every file
        /// this rule does not select. `false` (the default) is the
        /// forward-only check; both directions together are the
        /// if-and-only-if. It sits here, in the one variant that reads
        /// scripts, so `exclusive` beside a check that reads none has nowhere
        /// to be written.
        exclusive: Option<bool>,
    },
    /// `forbidden_literals` / `forbidden_literals_from`: literals produced at
    /// runtime -- a machine's own identity, or a command's output -- each of
    /// which must appear nowhere in the selected files.
    ForbiddenLiterals {
        #[serde(flatten)]
        literals: Literals,
        /// Literals never searched for, extending the documented default
        /// ignore list (generic hostname words such as "server", "laptop" --
        /// the full list is in REFERENCE.md). The defaults were hard-coded and
        /// invisible; this is the same suppression, written where an operator
        /// can see and extend it, and it sits in the one variant that has
        /// needles to suppress.
        ignore_literals: Option<Vec<String>>,
    },
    /// `builtin`: a check compiled into this binary, by name.
    ///
    /// These are the checks no regex can express: a remote's owner against an
    /// allow-list, `git ls-remote` output against a pin, Unicode Script
    /// properties, a forge's answer about a name's visibility. There is no
    /// upstream vocabulary to borrow for them, because the check belongs to
    /// this tool -- so they are named, and an unknown name is refused at load
    /// rather than silently running nothing.
    Builtin {
        builtin: String,
        #[serde(flatten)]
        parameters: Box<Parameters>,
    },
    /// `exec`: an executable consulted about one subject.
    ///
    /// The contract is deliberately the only one: any executable, the subject
    /// on stdin, its kind in `UPHOLD_KIND`, 0 to pass, 1 to refuse, 2 to say it
    /// could not look.
    Exec { exec: String },
}

impl Check {
    /// Which check this is, for the readers that only need to know that.
    pub(crate) const fn kind(&self) -> CheckKind {
        match self {
            Self::Regexp { .. } => CheckKind::Regexp,
            Self::CommentRegexp { .. } => CheckKind::CommentRegexp,
            Self::ProseRegexp { .. } => CheckKind::ProseRegexp,
            Self::TrivialComments { .. } => CheckKind::TrivialComments,
            Self::ForbiddenLiterals { .. } => CheckKind::ForbiddenLiterals,
            Self::MaxLines { .. } => CheckKind::MaxLines,
            Self::MaxBytes { .. } => CheckKind::MaxBytes,
            Self::PathRegexp { .. } => CheckKind::PathRegexp,
            Self::RequireRegexp { .. } => CheckKind::RequireRegexp,
            Self::Encoding { .. } => CheckKind::Encoding,
            Self::AllowedScripts { .. } => CheckKind::AllowedScripts,
            Self::Builtin { .. } => CheckKind::Builtin,
            Self::Exec { .. } => CheckKind::Exec,
        }
    }

    /// A check of `kind` with nothing written in it, for a rule this binary
    /// composes rather than reads from a file.
    pub(crate) fn empty(kind: CheckKind) -> Self {
        match kind {
            CheckKind::Regexp => Self::Regexp {
                regexp: String::new(),
            },
            CheckKind::CommentRegexp => Self::CommentRegexp {
                comment_regexp: String::new(),
            },
            CheckKind::ProseRegexp => Self::ProseRegexp {
                prose_regexp: String::new(),
            },
            CheckKind::TrivialComments => Self::TrivialComments {
                trivial_comments: true,
            },
            CheckKind::PathRegexp => Self::PathRegexp {
                path_regexp: String::new(),
            },
            CheckKind::RequireRegexp => Self::RequireRegexp {
                require_regexp: String::new(),
            },
            CheckKind::MaxLines => Self::MaxLines { max_lines: 0 },
            CheckKind::MaxBytes => Self::MaxBytes { max_bytes: 0 },
            CheckKind::Encoding => Self::Encoding {
                encoding: String::new(),
            },
            CheckKind::AllowedScripts => Self::AllowedScripts {
                allowed_scripts: vec![String::new()],
                exclusive: None,
            },
            CheckKind::ForbiddenLiterals => Self::ForbiddenLiterals {
                literals: Literals::Named {
                    forbidden_literals: String::new(),
                },
                ignore_literals: None,
            },
            CheckKind::Builtin => Self::Builtin {
                builtin: String::new(),
                parameters: Box::default(),
            },
            CheckKind::Exec => Self::Exec {
                exec: String::new(),
            },
        }
    }

    /// The one reading of which written fields name a check.
    ///
    /// This is where "two checks in one rule" and "no check at all" are
    /// refused, and the last place either can be spelled: everything after it
    /// holds one variant. The table below is the single list -- it says which
    /// field names a check, in the order a reader is offered them, and both the
    /// count and the sentence naming the alternatives are read off it. There
    /// used to be four such lists in this file and they were free to disagree.
    fn of_written(id: &str, written: &mut Written) -> Result<Self> {
        let named: Vec<&'static str> = [
            written.regexp.is_some().then_some("regexp"),
            written.comment_regexp.is_some().then_some("comment_regexp"),
            written.prose_regexp.is_some().then_some("prose_regexp"),
            written
                .trivial_comments
                .is_some()
                .then_some("trivial_comments"),
            written.path_regexp.is_some().then_some("path_regexp"),
            written.require_regexp.is_some().then_some("require_regexp"),
            written.max_lines.is_some().then_some("max_lines"),
            written.max_bytes.is_some().then_some("max_bytes"),
            written.encoding.is_some().then_some("encoding"),
            (!written.allowed_scripts.is_empty()).then_some("allowed_scripts"),
            written
                .forbidden_literals
                .is_some()
                .then_some("forbidden_literals"),
            written
                .forbidden_literals_from
                .is_some()
                .then_some("forbidden_literals_from"),
            written.builtin.is_some().then_some("builtin"),
            written.exec.is_some().then_some("exec"),
        ]
        .into_iter()
        .flatten()
        .collect();

        if named.is_empty() {
            return Err(Fatal::new(format!(
                "rule {id:?}: nothing says what it checks. Set one of: {}",
                Self::EVERY_FIELD.join(", ")
            )));
        }
        // `forbidden_literals` and `forbidden_literals_from` are two spellings
        // of one check -- a named source or a command producing the same
        // literals -- so they count as one here and are refused together below.
        let distinct = named
            .iter()
            .filter(|field| !matches!(**field, "forbidden_literals" | "forbidden_literals_from"))
            .count()
            + usize::from(
                written.forbidden_literals.is_some() || written.forbidden_literals_from.is_some(),
            );
        if distinct > 1 {
            return Err(Fatal::new(format!(
                "rule {id:?}: {} say what it checks, and a rule checks one thing. Split it \
                 into one rule per check, or delete the field that is not meant",
                named.join(" and ")
            )));
        }
        if written.forbidden_literals.is_some() && written.forbidden_literals_from.is_some() {
            return Err(Fatal::new(format!(
                "rule {id:?}: `forbidden_literals` names a built-in source and \
                 `forbidden_literals_from` names a command; one rule cannot have both"
            )));
        }

        let parameters = Parameters {
            private_owners: written.private_owners.take(),
            private_owners_from: written.private_owners_from.take(),
            public_repos: written.public_repos.take(),
            refuse_unknown: written.refuse_unknown.take(),
            foreign_hosts: written.foreign_hosts.take(),
            visibility: written.visibility.take(),
            owner: written.owner.take(),
            owner_required: written.owner_required.take(),
            allowed_owners: written.allowed_owners.take(),
            allowed_repos: written.allowed_repos.take(),
            visibility_required: written.visibility_required.take(),
            allow: written.allow.take(),
            require_any_link: written.require_any_link.take(),
            allow_outside_repo: written.allow_outside_repo.take(),
            require_any_anchor: written.require_any_anchor.take(),
            command_sources: written.command_sources.take(),
        };

        // Writing the field is what declares the check, so `false` is a rule
        // that names a check and switches it off -- which reads as enforcement
        // in `upheld.toml` and enforces nothing. Deleting the rule is the way
        // to not run it.
        if written.trivial_comments == Some(false) {
            return Err(Fatal::new(format!(
                "rule {id:?}: `trivial_comments = false` declares the check and then runs \
                 nothing. Delete the rule instead, so no claim can name it"
            )));
        }

        let check = if let Some(builtin) = written.builtin.take() {
            Self::Builtin {
                builtin,
                parameters: Box::new(parameters),
            }
        } else {
            // Every knob above belongs to a built-in, and this rule is not one,
            // so there is no field on it for any of them to sit in. Refused
            // here rather than carried: a parameter read by nothing looks
            // enforced and is not.
            parameters.refuse_unread(id, named.first().copied().unwrap_or_default(), None)?;
            Self::one_of(written)
        };

        // Two knobs belong to one check each, and `one_of` took each where it
        // belongs. Anything still written here was written beside a check that
        // does not read it -- the last state of that shape a file can reach,
        // because after this the knob lives inside the variant that reads it.
        let kind = check.kind();
        if written.ignore_literals.is_some() {
            return Err(Fatal::new(format!(
                "rule {id:?}: `ignore_literals` drops literals from the search, and \
                 `{kind}` searches for no literals, so the field would be read by \
                 nothing"
            )));
        }
        if written.exclusive.is_some() {
            return Err(Fatal::new(format!(
                "rule {id:?}: `exclusive` reverses `allowed_scripts` -- these scripts \
                 only under these paths -- and `{kind}` reads no scripts, so the \
                 field would be read by nothing"
            )));
        }
        Ok(check)
    }

    /// The alternatives a rule with no check is offered, in the order it is
    /// offered them.
    const EVERY_FIELD: [&'static str; 14] = [
        "regexp",
        "comment_regexp",
        "prose_regexp",
        "trivial_comments",
        "path_regexp",
        "require_regexp",
        "max_lines",
        "max_bytes",
        "encoding",
        "allowed_scripts",
        "forbidden_literals",
        "forbidden_literals_from",
        "builtin",
        "exec",
    ];

    /// The variant the one written check field selects.
    ///
    /// Reached only with exactly one of them written, which `of_written` has
    /// just established, so the last arm is the impossible one and says so.
    fn one_of(written: &mut Written) -> Self {
        if let Some(regexp) = written.regexp.take() {
            return Self::Regexp { regexp };
        }
        if let Some(comment_regexp) = written.comment_regexp.take() {
            return Self::CommentRegexp { comment_regexp };
        }
        if let Some(prose_regexp) = written.prose_regexp.take() {
            return Self::ProseRegexp { prose_regexp };
        }
        if let Some(trivial_comments) = written.trivial_comments.take() {
            return Self::TrivialComments { trivial_comments };
        }
        if let Some(path_regexp) = written.path_regexp.take() {
            return Self::PathRegexp { path_regexp };
        }
        if let Some(require_regexp) = written.require_regexp.take() {
            return Self::RequireRegexp { require_regexp };
        }
        if let Some(max_lines) = written.max_lines.take() {
            return Self::MaxLines { max_lines };
        }
        if let Some(max_bytes) = written.max_bytes.take() {
            return Self::MaxBytes { max_bytes };
        }
        if let Some(encoding) = written.encoding.take() {
            return Self::Encoding { encoding };
        }
        if !written.allowed_scripts.is_empty() {
            return Self::AllowedScripts {
                allowed_scripts: std::mem::take(&mut written.allowed_scripts),
                exclusive: written.exclusive.take(),
            };
        }
        if let Some(forbidden_literals) = written.forbidden_literals.take() {
            return Self::ForbiddenLiterals {
                literals: Literals::Named { forbidden_literals },
                ignore_literals: written.ignore_literals.take(),
            };
        }
        if let Some(forbidden_literals_from) = written.forbidden_literals_from.take() {
            return Self::ForbiddenLiterals {
                literals: Literals::From {
                    forbidden_literals_from,
                },
                ignore_literals: written.ignore_literals.take(),
            };
        }
        if let Some(exec) = written.exec.take() {
            return Self::Exec { exec };
        }
        unreachable!("of_written counted exactly one written check field before calling this")
    }
}

/// One rule: what it checks, and where it runs.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Rule {
    /// Which file this rule was read from, filled in by [`load`] and by nothing
    /// else. `#[serde(skip)]` for the reason [`Rule::id`] is not deserialized:
    /// a rule that could declare its own provenance could declare a false one.
    #[serde(skip)]
    pub origin: Origin,

    /// The section header, not a field: `[rule.no-conflict-markers]` names the
    /// rule, and `parse` copies the key here so every consumer keeps reading
    /// `rule.id`.
    ///
    /// While the id WAS a field, `[rule.files]` bound to the most recent
    /// `[[rule]]` above it -- a fact TOML defines and the file never showed, so
    /// a sub-table drifting away from its rule during an edit changed meaning
    /// silently. With the id as the header, everything about a rule lives
    /// inside its section, and a duplicate id is a TOML parse error rather than
    /// a runtime check.
    pub id: String,

    /// What a reader should do about a hit. Required for every check that can
    /// fail against a specific file; `allowed_scripts` composes its own,
    /// because the useful half of that report is the script and the declaration
    /// it is missing from, and a hand-written message would only repeat it.
    pub message: Option<String>,

    /// What is checked, and the knobs that check reads. Exactly one, by
    /// construction.
    #[serde(flatten)]
    pub check: Check,

    // -- where it runs. An absent table is a place it does not run ----------
    pub files: Option<Files>,
    pub git: Option<Git>,
    pub command: Option<CommandWhere>,
    /// Which subject kinds of an invocation this rule is asked about --
    /// `"title"`, `"text"`, `"path"`, `"ref"`, `"argv"`. Absent means every
    /// subject the shim collected, which is every rule written before this
    /// existed. Only meaningful beside `command.before`: nothing else hands a
    /// rule a subject that HAS a kind, so writing it anywhere else is refused
    /// as configuration read by nothing.
    pub subjects: Option<Vec<String>>,
}

impl Rule {
    /// A rule this binary composes rather than reads from a file.
    ///
    /// A constructor rather than a struct literal at each call site: a literal
    /// has to name every field, so adding one to the schema breaks each of them
    /// and gets fixed by copying whatever the neighbour said. That is how a
    /// synthesised rule quietly acquires a setting nobody chose for it.
    pub(crate) fn synthetic(id: &str, check: Check) -> Self {
        let files = check.kind().requires_files().then(Files::default);
        Self {
            origin: Origin::Own,
            id: id.to_owned(),
            message: None,
            check,
            files,
            git: None,
            command: None,
            subjects: None,
        }
    }

    /// A rule read from a bare `[rule.<id>]` body, through the deserializer a
    /// policy file goes through.
    ///
    /// The id is the section header, so a body on its own has no spelling for
    /// it and it is handed in the way `parse` hands it in. Here for the guards'
    /// own tests, which have to assert about a rule the config would accept
    /// rather than one a struct literal composed.
    #[cfg(test)]
    pub(crate) fn from_toml(id: &str, body: &str) -> Result<Self> {
        let written: Written =
            toml::from_str(body).map_err(|error| Fatal::new(error.message().to_owned()))?;
        Self::of_written(id, written)
    }

    /// The rule a policy file wrote under `id`.
    ///
    /// The one conversion, and the only place a written file can still say two
    /// things about what it checks.
    pub(super) fn of_written(id: &str, mut written: Written) -> Result<Self> {
        let check = Check::of_written(id, &mut written)?;
        Ok(Self {
            origin: Origin::Own,
            id: id.to_owned(),
            message: written.message,
            check,
            files: written.files,
            git: written.git,
            command: written.command,
            subjects: written.subjects,
        })
    }

    /// What this rule checks.
    pub(crate) const fn kind(&self) -> CheckKind {
        self.check.kind()
    }

    pub(crate) fn is(&self, check: CheckKind) -> bool {
        self.kind() == check
    }

    /// The name of the built-in this rule runs, if it runs one.
    pub(crate) fn builtin(&self) -> Option<&str> {
        match &self.check {
            Check::Builtin { builtin, .. } => Some(builtin),
            _ => None,
        }
    }

    /// The settings this rule's built-in was handed, if it is a built-in.
    pub(crate) fn parameters(&self) -> Option<&Parameters> {
        match &self.check {
            Check::Builtin { parameters, .. } => Some(parameters),
            _ => None,
        }
    }

    /// The same, to be edited -- `audit` composes a rule that differs from a
    /// declared one in one parameter, and this is where it says so.
    pub(crate) fn parameters_mut(&mut self) -> Option<&mut Parameters> {
        match &mut self.check {
            Check::Builtin { parameters, .. } => Some(parameters),
            _ => None,
        }
    }

    /// Whether `shim::run` can consult this rule at a command seam.
    ///
    /// Three places ask this question and they have to agree. `validate`
    /// refuses `command.before` on a rule the shim cannot consult;
    /// `validate_shims` refuses a blank entry on a rule it CAN; and the same
    /// function builds the set of commands some checker names, which is what
    /// decides whether a `[[shim]]` is standing in front of anything. Written
    /// out three times, the three drifted: the blank-entry loop was still
    /// asking only about `CheckKind::Exec` after the other two had learned
    /// about patterns, so a whitespace-only entry on a `regexp` rule loaded
    /// clean and the rule stood in front of nothing. One predicate is the fix,
    /// because the failure was never the reading -- it was that there were
    /// three.
    ///
    /// The kinds, and why each is here:
    ///
    /// * `exec` -- the original contract. A program this repository names,
    ///   handed the subject on stdin.
    /// * a pattern -- `regexp`, `require_regexp` and `prose_regexp` are
    ///   text-capable by construction, since a regex means the same thing
    ///   against a pull-request title as against a line of a file. What they
    ///   lack at this seam is a default place, which `command.before` supplies.
    ///   A `prose_regexp` reads the subject as whole-text prose, which is what
    ///   a pull-request body is.
    /// * a text-capable built-in -- one the binary carries. This seam is the
    ///   ONLY one some of them belong at: `no-private-repo-names` reads a
    ///   commit message at every git hook, which refuses the issue citations a
    ///   repository's own prose is full of, so a repository that wants it over
    ///   a pull-request body and nowhere else has no other field to say it in.
    /// * a DESTINATION-judging built-in -- one that reads where the invocation
    ///   was told to publish rather than what. This seam is the only one it
    ///   belongs at, and in the other direction: a git hook is handed no
    ///   destination for a command, so `command.before` is the whole of where
    ///   it can run.
    ///
    /// Anything else reads an index, an identity or a push range, and has
    /// nothing to say about a pull-request body.
    pub(crate) fn stands_in_front_of_a_command(&self) -> bool {
        matches!(
            self.kind(),
            CheckKind::Exec | CheckKind::Regexp | CheckKind::RequireRegexp | CheckKind::ProseRegexp
        ) || self.builtin().is_some_and(|builtin| {
            crate::guard::TEXT_GUARDS.contains(&builtin)
                || crate::guard::TARGET_GUARDS.contains(&builtin)
        })
    }

    // -- the built-in parameters, absent-as-default --------------------------
    //
    // The fields are `Option` so the load-time check can tell WRITTEN from
    // ABSENT; every reader wants the default filled in, and these are where it
    // is filled in exactly once. A rule that is not a built-in reads the same
    // default, because it has no parameters at all.
    pub(crate) fn private_owners(&self) -> &[String] {
        self.parameters()
            .and_then(|parameters| parameters.private_owners.as_deref())
            .unwrap_or(&[])
    }

    pub(crate) fn private_owners_from(&self) -> Option<&str> {
        self.parameters()
            .and_then(|parameters| parameters.private_owners_from.as_deref())
    }

    pub(crate) fn public_repos(&self) -> &[String] {
        self.parameters()
            .and_then(|parameters| parameters.public_repos.as_deref())
            .unwrap_or(&[])
    }

    pub(crate) fn refuse_unknown(&self) -> bool {
        self.parameters()
            .and_then(|parameters| parameters.refuse_unknown)
            .unwrap_or(false)
    }

    pub(crate) fn foreign_hosts(&self) -> Option<&[String]> {
        self.parameters()
            .and_then(|parameters| parameters.foreign_hosts.as_deref())
    }

    pub(crate) fn visibility(&self) -> Option<&str> {
        self.parameters()
            .and_then(|parameters| parameters.visibility.as_deref())
    }

    pub(crate) fn visibility_required(&self) -> bool {
        self.parameters()
            .and_then(|parameters| parameters.visibility_required)
            .unwrap_or(false)
    }

    pub(crate) fn owner(&self) -> Option<&str> {
        self.parameters()
            .and_then(|parameters| parameters.owner.as_deref())
    }

    pub(crate) fn owner_required(&self) -> bool {
        self.parameters()
            .and_then(|parameters| parameters.owner_required)
            .unwrap_or(false)
    }

    pub(crate) fn allowed_owners(&self) -> &[String] {
        self.parameters()
            .and_then(|parameters| parameters.allowed_owners.as_deref())
            .unwrap_or(&[])
    }

    pub(crate) fn allowed_repos(&self) -> &[String] {
        self.parameters()
            .and_then(|parameters| parameters.allowed_repos.as_deref())
            .unwrap_or(&[])
    }

    pub(crate) fn allow(&self) -> &[String] {
        self.parameters()
            .and_then(|parameters| parameters.allow.as_deref())
            .unwrap_or(&[])
    }

    pub(crate) fn require_any_link(&self) -> bool {
        self.parameters()
            .and_then(|parameters| parameters.require_any_link)
            .unwrap_or(false)
    }

    pub(crate) fn allow_outside_repo(&self) -> bool {
        self.parameters()
            .and_then(|parameters| parameters.allow_outside_repo)
            .unwrap_or(false)
    }

    pub(crate) fn require_any_anchor(&self) -> bool {
        self.parameters()
            .and_then(|parameters| parameters.require_any_anchor)
            .unwrap_or(false)
    }

    /// The `command_sources` patterns, empty where none were written.
    pub(crate) fn command_sources(&self) -> &[String] {
        self.parameters()
            .and_then(|parameters| parameters.command_sources.as_deref())
            .unwrap_or_default()
    }

    // -- the checks' own values, for the seams that evaluate them ------------
    /// The charset an `encoding` rule declares.
    pub(crate) fn encoding(&self) -> Option<&str> {
        match &self.check {
            Check::Encoding { encoding } => Some(encoding),
            _ => None,
        }
    }

    /// The scripts an `allowed_scripts` rule admits.
    pub(crate) fn allowed_scripts(&self) -> &[String] {
        match &self.check {
            Check::AllowedScripts {
                allowed_scripts, ..
            } => allowed_scripts,
            _ => &[],
        }
    }

    /// Whether an `allowed_scripts` rule runs in both directions.
    pub(crate) fn exclusive(&self) -> bool {
        match &self.check {
            Check::AllowedScripts { exclusive, .. } => exclusive.unwrap_or(false),
            _ => false,
        }
    }

    /// The line cap a `max_lines` rule sets.
    pub(crate) const fn max_lines(&self) -> Option<u64> {
        match &self.check {
            Check::MaxLines { max_lines } => Some(*max_lines),
            _ => None,
        }
    }

    /// The byte cap a `max_bytes` rule sets.
    pub(crate) const fn max_bytes(&self) -> Option<u64> {
        match &self.check {
            Check::MaxBytes { max_bytes } => Some(*max_bytes),
            _ => None,
        }
    }

    /// The named literal source a `forbidden_literals` rule reads.
    pub(crate) fn forbidden_literals(&self) -> Option<&str> {
        match &self.check {
            Check::ForbiddenLiterals {
                literals: Literals::Named { forbidden_literals },
                ..
            } => Some(forbidden_literals),
            _ => None,
        }
    }

    /// The command a `forbidden_literals_from` rule takes its literals from.
    pub(crate) fn forbidden_literals_from(&self) -> Option<&str> {
        match &self.check {
            Check::ForbiddenLiterals {
                literals:
                    Literals::From {
                        forbidden_literals_from,
                    },
                ..
            } => Some(forbidden_literals_from),
            _ => None,
        }
    }

    /// The literals this rule never searches for.
    pub(crate) fn ignore_literals(&self) -> &[String] {
        match &self.check {
            Check::ForbiddenLiterals {
                ignore_literals, ..
            } => ignore_literals.as_deref().unwrap_or(&[]),
            _ => &[],
        }
    }

    /// The program an `exec` rule consults.
    pub(crate) fn exec(&self) -> Option<&str> {
        match &self.check {
            Check::Exec { exec } => Some(exec),
            _ => None,
        }
    }

    /// The `regexp` pattern, where that is the check.
    pub(crate) fn regexp(&self) -> Option<&str> {
        match &self.check {
            Check::Regexp { regexp } => Some(regexp),
            _ => None,
        }
    }

    /// The `prose_regexp` pattern, where that is the check.
    pub(crate) fn prose_regexp(&self) -> Option<&str> {
        match &self.check {
            Check::ProseRegexp { prose_regexp } => Some(prose_regexp),
            _ => None,
        }
    }

    /// The `require_regexp` pattern, where that is the check.
    pub(crate) fn require_regexp(&self) -> Option<&str> {
        match &self.check {
            Check::RequireRegexp { require_regexp } => Some(require_regexp),
            _ => None,
        }
    }

    /// The search scoping, or ripgrep's defaults where the table is absent.
    pub(crate) fn files(&self) -> &Files {
        static DEFAULTS: OnceLock<Files> = OnceLock::new();
        self.files
            .as_ref()
            .map_or_else(|| DEFAULTS.get_or_init(Files::default), |files| files)
    }

    /// Whether this rule searches files at all. Absent `files.*` keys are the
    /// answer, not a default to fill in.
    pub(crate) const fn reads_files(&self) -> bool {
        self.files.is_some()
    }

    /// Whether this rule is asked about a subject of one kind. Absent means
    /// every kind, which is every rule written before `subjects` existed.
    pub(crate) fn selects_subject(&self, kind: &str) -> bool {
        self.subjects
            .as_ref()
            .is_none_or(|kinds| kinds.iter().any(|named| named == kind))
    }

    /// The git hooks this rule fires at, in git's own names.
    ///
    /// Empty where `git.hooks` is absent, which means no git hook runs it.
    /// Before this, the list was a `match` arm in `guard::stages` -- so a
    /// repository could not add a stage, could not drop one, and could not see
    /// from its own configuration which stages it had.
    pub(crate) fn hooks(&self) -> &[String] {
        match &self.git {
            Some(git) => &git.hooks,
            None => &[],
        }
    }

    pub(crate) fn runs_at(&self, hook: &str) -> bool {
        self.hooks().iter().any(|name| name == hook)
    }

    /// Which seams run this rule: `scan`, `guard`, `shim`, in that order.
    ///
    /// The question `git.hooks` alone cannot answer. A rule with no hooks is
    /// either a content rule the scan owns or a checker standing in front of a
    /// command, and the two are not the same place -- but an empty hook list
    /// looked identical for both, so every reader downstream had to guess, and
    /// the reconciler guessed `scan`. A claim on a shim-only rule then
    /// reconciled green in a repository where the scan never touches it.
    ///
    /// Answered here rather than derived by a caller, for the reason
    /// `effective_rules_command` gives: every second reader of these fields is
    /// a reader free to disagree with the engine about which rules run.
    ///
    /// Empty is a real answer and not a gap: it means nothing runs the rule.
    /// `validate` refuses that at load, so it should not be reachable -- and it
    /// is spelled out rather than folded into one of the three, because a rule
    /// nobody runs must not read as a rule the scan runs.
    pub(crate) fn seams(&self) -> Vec<&'static str> {
        let mut seams = Vec::new();
        // The scan's own filter, in `scan::Scan::run`: a built-in is the scan's
        // only when it reads files, and every other check that reads files is.
        if self.reads_files() && (self.kind() != CheckKind::Builtin || self.hooks().is_empty()) {
            seams.push("scan");
        }
        if !self.hooks().is_empty() {
            seams.push("guard");
        }
        // `shim::run` consults the rules `stands_in_front_of_a_command` names,
        // and `validate` refuses `command.before` on anything else.
        if self.command.is_some() {
            seams.push("shim");
        }
        seams
    }

    /// Whether this rule stands in front of `command` invoked as `argv`.
    pub(crate) fn stands_before(&self, command: &str, argv: &[String]) -> bool {
        self.command
            .as_ref()
            .is_some_and(|where_| where_.matches(command, argv))
    }

    pub(crate) fn include(&self) -> &[String] {
        const ROOT: &[String] = &[];
        match &self.files().include {
            Some(include) => include,
            None => ROOT,
        }
    }

    /// The floor this rule sets under its own selection.
    ///
    /// `0` is the absence of a floor and is the only way to spell it, because a
    /// written `0` is refused at load -- so a caller comparing a count against
    /// this needs no second question about whether a floor was declared.
    pub(crate) fn min_selected(&self) -> u64 {
        self.files().min_selected.unwrap_or(0)
    }

    /// Whether `uphold scan` takes a count of what this rule selects.
    ///
    /// The three tree-reading built-ins select the way a content rule does;
    /// every other built-in's `[rule.files]` is a scope the guard applies one
    /// path at a time, and answering "is this path in scope" never produces a
    /// count for a floor to stand under.
    fn selection_is_counted(&self) -> bool {
        match &self.check {
            Check::Builtin { builtin, .. } => {
                crate::guard::SCAN_BUILTINS.contains(&builtin.as_str())
            }
            other => other.kind().requires_files(),
        }
    }

    /// The message, or the empty string where a check composes its own report.
    pub(crate) fn message(&self) -> &str {
        self.message.as_deref().unwrap_or("")
    }

    /// The regex this rule searches with, whichever check carries one.
    pub(crate) fn expression(&self) -> Option<&str> {
        match &self.check {
            Check::Regexp { regexp } => Some(regexp),
            Check::CommentRegexp { comment_regexp } => Some(comment_regexp),
            Check::ProseRegexp { prose_regexp } => Some(prose_regexp),
            Check::PathRegexp { path_regexp } => Some(path_regexp),
            Check::RequireRegexp { require_regexp } => Some(require_regexp),
            _ => None,
        }
    }

    fn refuse(&self, condition: bool, complaint: &str) -> Result<()> {
        if !condition {
            return Ok(());
        }
        Err(Fatal::new(format!("rule {:?}: {complaint}", self.id)))
    }

    /// Reject a rule that describes one check in a place it cannot run.
    ///
    /// What is NOT here any more is everything the type now says: a rule with
    /// no check field, a rule with two, a knob beside a check that reads none,
    /// a built-in parameter on a rule that runs no built-in. Those are refused
    /// once, in [`Check::of_written`], and afterwards there is no such rule to
    /// find. What is left is what a type cannot decide -- whether a NAME
    /// resolves, whether a value is in range, and whether the places a rule
    /// declares are places its check can use.
    pub(super) fn validate(&self) -> Result<()> {
        let check = self.kind();

        // A pattern rule standing in front of a command searches that
        // command's subjects instead of the tree, so `command.before` is the
        // other way for it to say where -- with neither, it searches nothing.
        let pattern_at_command = matches!(
            check,
            CheckKind::Regexp | CheckKind::RequireRegexp | CheckKind::ProseRegexp
        ) && self.command.is_some();
        if check.requires_files() && self.files.is_none() && !pattern_at_command {
            return Err(Fatal::new(format!(
                "rule {:?}: `{check}` searches files, so it needs `files.*` keys \
                 saying which -- or, for the two pattern checks, `command.before` \
                 naming the invocation whose subjects it searches. Write \
                 `files.include = [\".\"]` for the whole tree",
                self.id
            )));
        }
        if !check.requires_files() && check != CheckKind::Builtin && self.files.is_some() {
            return Err(Fatal::new(format!(
                "rule {:?}: `{check}` does not search files, so its `files.*` keys would \
                 be read by nothing and would look like configuration that works",
                self.id
            )));
        }

        // `exclude_cfg_test` drops hits that sit inside a `#[cfg(test)]` block,
        // which needs a LINE in a searched file. Only the content searches --
        // `regexp` and `values` -- produce one; a path rule's finding is the
        // path itself, a size rule's is a count, a require rule's is an
        // absence. On any of those the field was accepted here and read by
        // nothing.
        if self.files().exclude_cfg_test
            && !matches!(check, CheckKind::Regexp | CheckKind::ForbiddenLiterals)
        {
            return Err(Fatal::new(format!(
                "rule {:?}: `exclude_cfg_test` drops content hits inside a `#[cfg(test)]` \
                 block, and a `{check}` finding has no matched line to be inside one, so \
                 the field would be read by nothing. Narrow this rule with `exclude` \
                 instead",
                self.id
            )));
        }

        self.validate_prose(check)?;
        self.validate_selection_floor()?;

        // The label is resolved at load, so a typo is a refusal here and not a
        // rule that fails every file it selects.
        if let Some(label) = self.encoding() {
            if encoding_rs::Encoding::for_label(label.as_bytes()).is_none() {
                return Err(Fatal::new(format!(
                    "rule {:?}: {label:?} names no encoding the WHATWG registry carries. \
                     Labels are the ones browsers accept -- \"UTF-8\", \"Shift_JIS\", \
                     \"EUC-JP\", \"windows-1252\"",
                    self.id
                )));
            }
        }

        // Every declared private owner becomes a pattern, and a pattern that
        // will not compile is a declaration this policy cannot honour. Refused
        // at load rather than dropped mid-search: an owner the search silently
        // omits is an operator's list saying one thing while the guard looks
        // for another, with nothing printed either way. The owner is escaped
        // before it is a pattern, so a failure here is a name no regex can
        // hold.
        for owner in self.private_owners() {
            if let Err(error) = regex::Regex::new(&regex::escape(owner)) {
                return Err(Fatal::new(format!(
                    "rule {:?}: private owner {owner:?} is a name no pattern can be built \
                     for ({error}), so the guard would run without it",
                    self.id
                )));
            }
        }

        // The same argument for the host globs: a glob nobody could compile is
        // a host nobody quieted, and the run that drops it looks exactly like
        // the run where the declaration worked.
        for host in self.foreign_hosts().unwrap_or_default() {
            if let Err(error) = globset::Glob::new(&host.to_lowercase()) {
                return Err(Fatal::new(format!(
                    "rule {:?}: `foreign_hosts` entry {host:?} is not a host glob \
                     ({error}). Entries are hostnames, optionally globbed -- \
                     \"doi.org\", \"*.sr.ht\"",
                    self.id
                )));
            }
        }

        self.validate_parameters()?;
        self.validate_command_sources()?;

        // A built-in that reads files and names a hook belongs to the guard:
        // `seams()` routes it there, and `guard::evaluate` has no arm for this
        // one. It would be installed, collected by `at_hook`, counted inside
        // "N guard(s) passed", and never run -- the same defect the refusals
        // below name, arriving through the one door they leave open.
        if matches!(self.builtin(), Some("anchors-resolve" | "commands-resolve"))
            && !self.hooks().is_empty()
        {
            return Err(Fatal::new(format!(
                "rule {:?}: `{}` reads the tree rather than what git is about \
                 to do, so it runs in `uphold scan` and at no git hook. `git.hooks` here \
                 would install a seam that never dispatches it, and the rule would be \
                 counted as having passed.\n\
                 Drop `git.hooks`; the `uphold-scan` hook is what runs it at a hook.",
                self.id,
                self.builtin().unwrap_or_default()
            )));
        }

        // The mirror of the `files.*` refusal above, and it was missing.
        // `guard::evaluate` dispatches on the BUILT-IN name and returns "no
        // violation" for a rule that has none, so a `regexp` or `exec` rule
        // wired to a hook was collected by `at_hook`, counted by `ran`, never
        // run, and reported inside "N guard(s) passed". Config that is accepted
        // and does nothing is bad; config that is accepted, does nothing, and
        // is counted as having passed is worse.
        if check != CheckKind::Builtin && self.git.is_some() {
            return Err(Fatal::new(format!(
                "rule {:?}: only a `builtin` runs at a git hook, so `git.hooks` on a \
                 `{check}` rule would be read by nothing and would look like \
                 configuration that works.\n\
                 A rule that searches the tree says so with `files.*`, and the \
                 `uphold-scan` hook is what runs it at a hook.",
                self.id
            )));
        }

        // And the third place, missing for exactly the reason the second one
        // was. `shim::run` filters the rules it consults, so a built-in -- or a
        // regexp, or anything else -- whose only declared place is
        // `command.before` is consulted by nothing, runs nowhere, and reports
        // clean. The refusal below makes it worse rather than catching it:
        // "nothing says where it runs" is SATISFIED by the very field that
        // cannot be used, so the one check that exists to find a rule with no
        // place is the check this rule slips past.
        // Three wrote `command.before` on a text-capable built-in independently
        // while this refused all three; `stands_in_front_of_a_command` is where
        // the kinds that may are named, once, for this refusal and for the two
        // in `validate_shims` that have to agree with it.
        if !self.stands_in_front_of_a_command() && self.command.is_some() {
            let built_in_note = if check == CheckKind::Builtin {
                format!(
                    "\nThe built-ins that can judge the text a command publishes are {}, \
                     and the ones that can judge where it publishes are {}; any other reads \
                     an index, an identity or a push range, and has nothing to say about a \
                     pull-request body.",
                    crate::guard::TEXT_GUARDS.join(", "),
                    crate::guard::TARGET_GUARDS.join(", ")
                )
            } else {
                String::new()
            };
            return Err(Fatal::new(format!(
                "rule {:?}: a `{check}` rule cannot stand in front of a command, so \
                 `command.before` here would be read by nothing and would look like \
                 configuration that works.\n\
                 A rule that searches the tree says so with `files.*`, and a built-in \
                 that fires at a git hook says so with `git.hooks`.{built_in_note}",
                self.id
            )));
        }

        // The same idea one level down: a `command` table that names no command
        // line stands in front of nothing, because `CommandWhere::matches`
        // answers false for an empty list -- while the refusal below reads the
        // table as a declared place and lets the rule through.
        if self
            .command
            .as_ref()
            .is_some_and(|where_| where_.before.is_empty())
        {
            return Err(Fatal::new(format!(
                "rule {:?}: `command.before` names no command line, so this rule stands \
                 in front of nothing. Name the command as typed -- \
                 `command.before = [\"gh pr create\"]`",
                self.id
            )));
        }

        self.validate_subjects()?;

        if self.files.is_none() && self.git.is_none() && self.command.is_none() {
            return Err(Fatal::new(format!(
                "rule {:?}: nothing says where it runs, so it runs nowhere -- which \
                 reads exactly like a rule that passes. Add `files.*`, `git.hooks` \
                 or `command.before`",
                self.id
            )));
        }

        for hook in self.hooks() {
            crate::guard::Stage::parse(hook)
                .map_err(|error| Fatal::new(format!("rule {:?}: git.hooks {error}", self.id)))?;
        }

        self.validate_builtin_name()?;

        // A message is what a reader acts on. The checks that compose their own
        // report are the two whose useful half is the finding itself -- the
        // script and the declaration it is missing from, the character and its
        // Unicode name -- and a hand-written message there only repeats it.
        if !matches!(check, CheckKind::AllowedScripts | CheckKind::Builtin)
            && self.message.is_none()
        {
            return Err(Fatal::new(format!(
                "rule {:?}: `{check}` needs a `message` saying what to do about a hit",
                self.id
            )));
        }

        Ok(())
    }

    /// The half of "a parameter is read or it is refused" that a type cannot
    /// keep: WHICH built-in reads which is a question about a name.
    ///
    /// The other half is gone, because [`Parameters`] now exists only inside
    /// [`Check::Builtin`]: a `require_any_link` or an `allowed_owners` beside a
    /// `regexp` has no field to be written in, and `Check::of_written` refuses
    /// it through this same sentence before a rule is built at all.
    fn validate_parameters(&self) -> Result<()> {
        let Some(parameters) = self.parameters() else {
            return Ok(());
        };
        parameters.refuse_unread(&self.id, self.kind().as_str(), self.builtin())
    }

    /// Hold `commands-resolve` to the one field it cannot work without.
    ///
    /// Separate from `validate_parameters` rather than folded into it, because
    /// it is the only one of the three resolver knobs that is REQUIRED: the
    /// others are refused where they are WRITTEN beside something that cannot
    /// read them, and this is refused where it is missing as well.
    fn validate_command_sources(&self) -> Result<()> {
        // The command resolver's own knob, and unlike the two above it is
        // REQUIRED rather than merely exclusive. A `commands-resolve` with no
        // pattern discovers no command, judges nothing, and reports a clean
        // tree -- which is the shape every check here is written to refuse.
        if self.builtin() == Some("commands-resolve") {
            let patterns = self.command_sources();
            if patterns.is_empty() {
                return Err(Fatal::new(format!(
                    "rule {:?}: `commands-resolve` needs `command_sources`, one or more \
                 globs in which `{{}}` stands for a command's name -- \
                 `command_sources = [\"*/cmd/{{}}/**/*.go\"]`. Without one it \
                 discovers no command, judges nothing, and reports a clean tree.",
                    self.id
                )));
            }
            for pattern in patterns {
                if pattern.matches("{}").count() != 1 {
                    return Err(Fatal::new(format!(
                        "rule {:?}: `command_sources` entry {pattern:?} does not contain \
                     exactly one `{{}}`. The placeholder is what names the command, and \
                     a pattern without one selects files belonging to no command while \
                     a pattern with two names two.",
                        self.id
                    )));
                }
                // The pattern is read TWICE -- once as a glob, to select the
                // files, and once as a regex, to read the command's name out of
                // the path each one has. Only `*`, `**`, `/` and literal text
                // mean the same thing to both. A `?`, a bracket class or a brace
                // alternation would select a file the second reading cannot
                // name, and that file would then vanish out of the discovered
                // count with nothing said -- which is the failure this rule
                // exists to refuse, arriving through its own configuration.
                //
                // Refused rather than translated. Teaching the regex the rest of
                // globset's syntax is a second implementation of somebody else's
                // grammar, free to disagree with it on the next version.
                let outside_placeholder = pattern.replacen("{}", "", 1);
                if let Some(unsupported) = ['?', '[', ']']
                    .into_iter()
                    .find(|character| pattern.contains(*character))
                    .or_else(|| {
                        ['{', '}']
                            .into_iter()
                            .find(|brace| outside_placeholder.contains(*brace))
                    })
                {
                    return Err(Fatal::new(format!(
                        "rule {:?}: `command_sources` entry {pattern:?} uses {unsupported:?}, \
                         which this field does not accept. The pattern selects the files as \
                         a glob AND names the command as a regex, and only `*`, `**`, `/` \
                         and literal text mean the same thing to both -- anything else \
                         would select a source whose command could not be named, and drop \
                         it out of the count in silence.",
                        self.id
                    )));
                }
            }
        }
        Ok(())
    }

    /// The `prose_regexp` half of [`Rule::validate`]: a pattern over prose is
    /// handed one unwrapped span at a time, so there is no second line for
    /// `files.multiline` to reach.
    ///
    /// The extractor collapses a paragraph, a run of comments or a block of `#`
    /// lines into ONE line before the regex sees it -- which is what makes a
    /// pattern about a sentence match a sentence somebody rewrapped -- so a
    /// multiline pattern has no line boundary left to cross. Accepted, the field
    /// would be read by nothing and would look like configuration that works.
    fn validate_prose(&self, check: CheckKind) -> Result<()> {
        self.refuse(
            check == CheckKind::ProseRegexp && self.files().multiline,
            "`files.multiline` spans the lines of a file, and `prose_regexp` is handed one \
             unwrapped span at a time -- a paragraph, a run of comments, a block of `#` \
             lines -- so a wrapped sentence already matches and there is no line boundary \
             left to span. Drop the key",
        )
    }

    /// The `files.min_selected` half of [`Rule::validate`]: a floor needs a
    /// count under it, and a floor of zero is not a floor.
    fn validate_selection_floor(&self) -> Result<()> {
        let Some(floor) = self.files().min_selected else {
            return Ok(());
        };
        // A guard built-in's `[rule.files]` is a scope rather than a selection
        // -- `scope::in_file_scope` asks whether ONE path is in it -- and the
        // scan never dispatches the rule, so the field would sit in the file
        // looking like a floor with nothing measured against it.
        if !self.selection_is_counted() {
            return Err(Fatal::new(format!(
                "rule {:?}: `files.min_selected` is a floor under the number of files \
                 `uphold scan` selects, and built-in {:?} runs at a git hook over the bytes \
                 git is about to record -- its `files.*` keys scope that guard one path at a \
                 time, and a scope test produces no count for a floor to stand under. On this \
                 rule the field would be read by nothing and would look like configuration \
                 that works. The built-ins the scan selects for are {}",
                self.id,
                self.builtin().unwrap_or_default(),
                crate::guard::SCAN_BUILTINS.join(", ")
            )));
        }
        // Every selection there is meets a floor of zero, so writing one
        // declares a floor and enforces nothing -- the objection
        // `trivial_comments = false` is refused for. One is the smallest claim
        // the field can make: this rule still selects something.
        self.refuse(
            floor == 0,
            "`files.min_selected = 0` is met by every selection, including the empty one the \
             field exists to catch. Write `1` for \"this rule still selects something\", or \
             delete the line",
        )
    }

    /// The `subjects` half of [`Rule::validate`]: the filter names kinds a
    /// shim collects, beside the one table that hands this rule a subject.
    fn validate_subjects(&self) -> Result<()> {
        const KINDS: [&str; 5] = ["text", "title", "path", "ref", "argv"];
        let Some(kinds) = self.subjects.as_ref() else {
            return Ok(());
        };
        if self.command.is_none() {
            return Err(Fatal::new(format!(
                "rule {:?}: `subjects` filters the subjects of a command invocation, and \
                 only `command.before` hands this rule one -- written anywhere else it is \
                 read by nothing. Add `command.before`, or drop it",
                self.id
            )));
        }
        if kinds.is_empty() {
            return Err(Fatal::new(format!(
                "rule {:?}: `subjects = []` selects no subject at all, so the rule runs \
                 on nothing while reading as though it had been scoped",
                self.id
            )));
        }
        for kind in kinds {
            if !KINDS.contains(&kind.as_str()) {
                return Err(Fatal::new(format!(
                    "rule {:?}: no subject kind is called {kind:?}. A shim collects {}",
                    self.id,
                    KINDS.join(", ")
                )));
            }
        }
        Ok(())
    }

    /// The `builtin` half of [`Rule::validate`]: the name resolves, and a
    /// consultation is not declared at a seam whose rules it would re-run.
    fn validate_builtin_name(&self) -> Result<()> {
        let Some(name) = self.builtin() else {
            return Ok(());
        };
        if !crate::guard::EVERY_BUILTIN.contains(&name) {
            return Err(Fatal::new(format!(
                "rule {:?}: no built-in is called {name:?}. This binary carries: {}",
                self.id,
                crate::guard::EVERY_BUILTIN.join(", ")
            )));
        }
        // The consultations run OTHER rules, and every rule they run already
        // declares its own hooks and its own files. At a git hook or in a scan
        // they would report each of those rules' findings a second time under
        // a second id, so the one seam they exist for is the one they may
        // declare.
        if crate::guard::META_TEXT_GUARDS.contains(&name)
            && (self.git.is_some() || self.files.is_some())
        {
            return Err(Fatal::new(format!(
                "rule {:?}: {name:?} consults the rules this policy already runs, and \
                 at a git hook or in a scan each of those rules runs itself -- this \
                 rule there would report every finding twice. `command.before` is the \
                 seam it exists for; declare that and nothing else",
                self.id
            )));
        }
        // The same shape for the other direction. A destination-judging
        // built-in reads the repository an INVOCATION was told to publish to,
        // and nothing hands it one at a git hook or in a scan: there it would
        // run over no destination and report clean, which is the shape of
        // configuration that looks enforced and is not. `prevent-public-push`
        // is the rule for a push, reached by the same predicate, so nothing is
        // lost by refusing this one there.
        if crate::guard::TARGET_GUARDS.contains(&name)
            && (self.git.is_some() || self.files.is_some())
        {
            return Err(Fatal::new(format!(
                "rule {:?}: {name:?} judges the repository a command was told to publish \
                 to, and a git hook or a scan is handed no such destination -- there this \
                 rule would look at nothing and report clean. `command.before` is the seam \
                 it exists for; declare that and nothing else, and use \
                 `prevent-public-push` for a push",
                self.id
            )));
        }
        Ok(())
    }
}
