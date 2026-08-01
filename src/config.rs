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

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

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
];

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
pub(crate) enum Check {
    /// `regexp`: a regex over file contents that must find zero hits.
    Regexp,
    /// `forbidden_literals` / `forbidden_literals_from`: literals produced at
    /// runtime -- a machine's own identity, or a command's output -- each of
    /// which must appear nowhere in the selected files.
    ForbiddenLiterals,
    /// `max_lines`: a line-count limit with an optional baseline ratchet.
    MaxLines,
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

impl Check {
    /// Evaluation order, and the only enumeration of the checks anywhere.
    pub(crate) const ALL: [Self; 9] = [
        Self::Regexp,
        Self::ForbiddenLiterals,
        Self::MaxLines,
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
            Self::ForbiddenLiterals => "forbidden_literals",
            Self::MaxLines => "max_lines",
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
                | Self::ForbiddenLiterals
                | Self::MaxLines
                | Self::PathRegexp
                | Self::RequireRegexp
                | Self::Encoding
                | Self::AllowedScripts
        )
    }
}

impl std::fmt::Display for Check {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

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
#[derive(Debug, Clone, Default, Deserialize)]
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
}

/// git's own hook names, as written in githooks(5).
#[derive(Debug, Clone, Default, Deserialize)]
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
#[derive(Debug, Clone, Default, Deserialize)]
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
    /// `captured-fixtures`. [`BUNDLED`] is the list; this is a reader's copy of
    /// it, and the error a wrong name gets is built from the array.
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rule {
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
    #[serde(skip)]
    pub id: String,

    /// What a reader should do about a hit. Required for every check that can
    /// fail against a specific file; `allowed_scripts` composes its own, because the
    /// useful half of that report is the script and the declaration it is
    /// missing from, and a hand-written message would only repeat it.
    #[serde(default)]
    pub message: Option<String>,

    // -- what is checked. Exactly one of these ------------------------------
    //
    // The field IS the discriminant. Setting two is refused at load, because a
    // rule that names two checks has one of them read by nothing -- which is
    // the failure the old `kind` made easy: a `max_lines` beside
    // `kind = "pattern"` looked like a limit and was not one.
    /// A regex over file contents that must find zero hits.
    #[serde(default)]
    pub regexp: Option<String>,
    /// A regex matched against tracked file PATHS rather than their contents.
    #[serde(default)]
    pub path_regexp: Option<String>,
    /// A regex that must be found in every selected file.
    #[serde(default)]
    pub require_regexp: Option<String>,
    /// A line-count limit.
    #[serde(default)]
    pub max_lines: Option<u64>,
    /// A charset the selected files must decode cleanly under, named by its
    /// WHATWG label: `"Shift_JIS"` here means what it means to every browser.
    /// Encoding is a property of the BYTES where `allowed_scripts` is a
    /// property of the decoded text -- one field fusing them could not say
    /// "UTF-8 file containing Japanese" and "Shift-JIS file containing
    /// Japanese" apart, and those are different declarations about different
    /// layers.
    #[serde(default)]
    pub encoding: Option<String>,
    /// Unicode scripts admitted for the selected files, as UTS #24 spells
    /// them: `allowed_scripts = ["Hiragana"]` admits exactly what
    /// `\p{Script=Hiragana}` matches. The list is the WHOLE truth for the
    /// files this rule selects -- it replaces the top-level declaration rather
    /// than unioning with it, so what is declared beside the path is what
    /// holds for the path.
    #[serde(default)]
    pub allowed_scripts: Vec<String>,
    /// The reverse direction: these scripts are ALSO refused in every file
    /// this rule does not select. `false` (the default) is the forward-only
    /// check; both directions together are the if-and-only-if. `Option` so a
    /// WRITTEN `exclusive` beside a check that does not read it is refused.
    #[serde(default)]
    pub exclusive: Option<bool>,
    /// A named built-in source of literals that must appear nowhere --
    /// `running-os-identity`, `running-os-metadata`, `running-default-route`.
    /// The name says what fails: a literal describing THIS machine, found in
    /// content.
    #[serde(default)]
    pub forbidden_literals: Option<String>,
    /// A command whose stdout carries one literal per line.
    ///
    /// This is what replaced `policy/sources.py`. A repository that needed a
    /// custom source used to ship a Python module the engine imported, which
    /// made every consumer of the engine a Python host and made the plugin's
    /// `Needle` a different class than the engine's. A command has neither
    /// problem and can be written in anything.
    #[serde(default)]
    pub forbidden_literals_from: Option<String>,
    /// Literals never searched for, extending the documented default ignore
    /// list (generic hostname words such as "server", "laptop" -- the full
    /// list is in REFERENCE.md). The defaults were hard-coded and invisible;
    /// this is the same suppression, written where an operator can see and
    /// extend it. `Option` so a WRITTEN list beside a check that reads no
    /// literals is refused.
    #[serde(default)]
    pub ignore_literals: Option<Vec<String>>,
    /// A check compiled into this binary, by name.
    ///
    /// These are the checks no regex can express: a remote's owner against an
    /// allow-list, `git ls-remote` output against a pin, Unicode Script
    /// properties, a forge's answer about a name's visibility. There is no
    /// upstream vocabulary to borrow for them, because the check belongs to
    /// this tool -- so they are named, and an unknown name is refused at load
    /// rather than silently running nothing.
    #[serde(default)]
    pub builtin: Option<String>,
    /// An executable consulted about one subject.
    ///
    /// The contract is deliberately the only one: any executable, the subject
    /// on stdin, its kind in `UPHOLD_KIND`, 0 to pass, 1 to refuse, 2 to
    /// say it could not look.
    #[serde(default)]
    pub exec: Option<String>,

    // -- where it runs. An absent table is a place it does not run ----------
    #[serde(default)]
    pub files: Option<Files>,
    #[serde(default)]
    pub git: Option<Git>,
    #[serde(default)]
    pub command: Option<CommandWhere>,

    // -- knobs of the links-resolve built-in ---------------------------------
    //
    // Rule-level fields rather than `files.*` keys, because `files.*` is the
    // shared selection vocabulary: a knob only one check reads, sitting where
    // every rule author scrolls past it, is a field that looks applicable and
    // is not. `Option` so `validate` can refuse a WRITTEN one beside a check
    // that reads no links, same as the built-in parameters above.
    /// links-resolve: refuse a selection that yields no links at all.
    #[serde(default)]
    pub require_any_link: Option<bool>,
    /// links-resolve: let a link resolve outside the repository.
    #[serde(default)]
    pub allow_outside_repo: Option<bool>,

    // -- settings the built-ins read ----------------------------------------
    //
    // These were environment variables, every one of them, because git-guards
    // had no configuration file at all. The per-owner prefix scheme --
    // `<OWNER>_ALLOWED_PUSH_OWNERS` beside `WORKSPACE_ALLOWED_PUSH_OWNERS` --
    // existed only because configuration was environment-only while one machine
    // holds several workspaces, and a per-workspace FILE is the workspace scope.
    //
    // Each is `Option` rather than defaulted, because WRITTEN and ABSENT are
    // different facts to `validate`: every built-in declares which of these it
    // reads (`guard::parameters`), and one written on a rule whose check does
    // not read it is refused at load. Defaulted fields could not be refused --
    // an explicit `allowed_owners = []` on a `regexp` rule would be
    // indistinguishable from the field never having been written, and it is
    // exactly the thing that looks enforced while read by nothing.
    /// Owners whose repositories are private regardless of what a forge says.
    ///
    /// Writing them here is right for a repository staying private and wrong
    /// for one about to be published: the list of names that must not be
    /// published is itself a list of private names, so a public repository
    /// cannot hold it. `uphold audit --for-publication` reports a literal
    /// list as a finding for exactly that reason, and `private_owners_from` is
    /// the way out.
    #[serde(default)]
    pub private_owners: Option<Vec<String>>,
    /// A command whose stdout is one private owner per line.
    #[serde(default)]
    pub private_owners_from: Option<String>,
    /// Names to treat as public without asking a forge.
    #[serde(default)]
    pub public_repos: Option<Vec<String>>,
    /// Treat a name whose visibility could not be determined as private.
    #[serde(default)]
    pub refuse_unknown: Option<bool>,
    /// This repository's visibility, when it should not be looked up.
    #[serde(default)]
    pub visibility: Option<String>,
    /// The owner this workspace belongs to. Was `WORKSPACE_PINNED_OWNER`.
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub allowed_owners: Option<Vec<String>>,
    #[serde(default)]
    pub allowed_repos: Option<Vec<String>>,
    /// Codepoints admitted, optionally under one path glob:
    /// `"U+00A0:tests/fixtures/**"`, or `"U+3000"` for the whole tree.
    ///
    /// An entry can GRANT a character and never revoke one, which is what makes
    /// the list safe to extend without re-reading it: adding a line cannot
    /// tighten the check on anybody else's file.
    #[serde(default)]
    pub allow: Option<Vec<String>>,
}

impl Rule {
    /// A rule this binary composes rather than reads from a file.
    ///
    /// A constructor rather than a struct literal at each call site: a literal
    /// has to name every field, so adding one to the schema breaks each of them
    /// and gets fixed by copying whatever the neighbour said. That is how a
    /// synthesised rule quietly acquires a setting nobody chose for it.
    pub(crate) fn synthetic(id: &str, check: Check) -> Self {
        let mut rule = Self {
            id: id.to_owned(),
            message: None,
            regexp: None,
            path_regexp: None,
            require_regexp: None,
            max_lines: None,
            encoding: None,
            allowed_scripts: Vec::new(),
            exclusive: None,
            forbidden_literals: None,
            forbidden_literals_from: None,
            ignore_literals: None,
            builtin: None,
            exec: None,
            files: check.requires_files().then(Files::default),
            git: None,
            command: None,
            require_any_link: None,
            allow_outside_repo: None,
            private_owners: None,
            private_owners_from: None,
            public_repos: None,
            refuse_unknown: None,
            visibility: None,
            owner: None,
            allowed_owners: None,
            allowed_repos: None,
            allow: None,
        };
        // A synthetic rule still has to answer `check()` the way a parsed one
        // does, and `check()` reads the fields. So the field is set here rather
        // than a discriminant stored beside it: one source of truth, and a
        // synthetic rule that forgot to set it fails the same way a written one
        // would instead of quietly becoming a different check.
        match check {
            Check::Regexp => rule.regexp = Some(String::new()),
            Check::PathRegexp => rule.path_regexp = Some(String::new()),
            Check::RequireRegexp => rule.require_regexp = Some(String::new()),
            Check::MaxLines => rule.max_lines = Some(0),
            Check::Encoding => rule.encoding = Some(String::new()),
            Check::AllowedScripts => rule.allowed_scripts = vec![String::new()],
            Check::ForbiddenLiterals => rule.forbidden_literals = Some(String::new()),
            Check::Builtin => rule.builtin = Some(String::new()),
            Check::Exec => rule.exec = Some(String::new()),
        }
        rule
    }

    /// What this rule checks, read off the field the author wrote.
    ///
    /// `None` where no check field is set, which `validate` refuses -- but the
    /// accessor stays total so a caller iterating rules never has to unwrap.
    pub(crate) const fn check(&self) -> Option<Check> {
        if self.regexp.is_some() {
            return Some(Check::Regexp);
        }
        if self.path_regexp.is_some() {
            return Some(Check::PathRegexp);
        }
        if self.require_regexp.is_some() {
            return Some(Check::RequireRegexp);
        }
        if self.max_lines.is_some() {
            return Some(Check::MaxLines);
        }
        if self.encoding.is_some() {
            return Some(Check::Encoding);
        }
        if !self.allowed_scripts.is_empty() {
            return Some(Check::AllowedScripts);
        }
        if self.forbidden_literals.is_some() || self.forbidden_literals_from.is_some() {
            return Some(Check::ForbiddenLiterals);
        }
        if self.builtin.is_some() {
            return Some(Check::Builtin);
        }
        if self.exec.is_some() {
            return Some(Check::Exec);
        }
        None
    }

    pub(crate) fn is(&self, check: Check) -> bool {
        self.check() == Some(check)
    }

    /// The name of the built-in this rule runs, if it runs one.
    pub(crate) fn builtin(&self) -> Option<&str> {
        self.builtin.as_deref()
    }

    // -- the built-in parameters, absent-as-default --------------------------
    //
    // The fields are `Option` so `validate` can tell WRITTEN from ABSENT;
    // every reader wants the default filled in, and these are where it is
    // filled in exactly once.
    pub(crate) fn private_owners(&self) -> &[String] {
        self.private_owners.as_deref().unwrap_or(&[])
    }

    pub(crate) fn public_repos(&self) -> &[String] {
        self.public_repos.as_deref().unwrap_or(&[])
    }

    pub(crate) fn refuse_unknown(&self) -> bool {
        self.refuse_unknown.unwrap_or(false)
    }

    pub(crate) fn allowed_owners(&self) -> &[String] {
        self.allowed_owners.as_deref().unwrap_or(&[])
    }

    pub(crate) fn allowed_repos(&self) -> &[String] {
        self.allowed_repos.as_deref().unwrap_or(&[])
    }

    pub(crate) fn allow(&self) -> &[String] {
        self.allow.as_deref().unwrap_or(&[])
    }

    pub(crate) fn require_any_link(&self) -> bool {
        self.require_any_link.unwrap_or(false)
    }

    pub(crate) fn allow_outside_repo(&self) -> bool {
        self.allow_outside_repo.unwrap_or(false)
    }

    /// The built-in parameters this rule writes, by field name.
    fn written_parameters(&self) -> Vec<&'static str> {
        [
            self.owner.is_some().then_some("owner"),
            self.allowed_owners.is_some().then_some("allowed_owners"),
            self.allowed_repos.is_some().then_some("allowed_repos"),
            self.private_owners.is_some().then_some("private_owners"),
            self.private_owners_from
                .is_some()
                .then_some("private_owners_from"),
            self.public_repos.is_some().then_some("public_repos"),
            self.refuse_unknown.is_some().then_some("refuse_unknown"),
            self.visibility.is_some().then_some("visibility"),
            self.allow.is_some().then_some("allow"),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    /// The search scoping, or ripgrep's defaults where the table is absent.
    pub(crate) fn files(&self) -> &Files {
        static DEFAULTS: std::sync::OnceLock<Files> = std::sync::OnceLock::new();
        self.files
            .as_ref()
            .map_or_else(|| DEFAULTS.get_or_init(Files::default), |files| files)
    }

    /// Whether this rule searches files at all. Absent `files.*` keys are the
    /// answer, not a default to fill in.
    pub(crate) const fn reads_files(&self) -> bool {
        self.files.is_some()
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

    /// The message, or the empty string where a check composes its own report.
    pub(crate) fn message(&self) -> &str {
        self.message.as_deref().unwrap_or("")
    }

    /// The regex this rule searches with, whichever field carries it.
    pub(crate) fn expression(&self) -> Option<&str> {
        self.regexp
            .as_deref()
            .or(self.path_regexp.as_deref())
            .or(self.require_regexp.as_deref())
    }

    fn refuse(&self, condition: bool, complaint: &str) -> Result<()> {
        if !condition {
            return Ok(());
        }
        Err(Fatal::new(format!("rule {:?}: {complaint}", self.id)))
    }

    /// Reject a rule whose fields do not describe one check in one place.
    ///
    /// Three things are refused, and the second is the one that used to be
    /// unrepresentable. A rule with no check field checks nothing. A rule with
    /// TWO has one of them read by nothing, and the author walks away believing
    /// both are enforced -- which is why the discriminant had to go rather than
    /// be renamed: while `kind` decided, `max_lines` beside `kind = "pattern"`
    /// was a limit that looked enforced and was not. And a rule that names no
    /// place runs nowhere, which reads exactly like a rule that passes.
    fn validate(&self) -> Result<()> {
        let set: Vec<&str> = [
            self.regexp.is_some().then_some("regexp"),
            self.path_regexp.is_some().then_some("path_regexp"),
            self.require_regexp.is_some().then_some("require_regexp"),
            self.max_lines.is_some().then_some("max_lines"),
            self.encoding.is_some().then_some("encoding"),
            (!self.allowed_scripts.is_empty()).then_some("allowed_scripts"),
            self.forbidden_literals
                .is_some()
                .then_some("forbidden_literals"),
            self.forbidden_literals_from
                .is_some()
                .then_some("forbidden_literals_from"),
            self.builtin.is_some().then_some("builtin"),
            self.exec.is_some().then_some("exec"),
        ]
        .into_iter()
        .flatten()
        .collect();

        let Some(check) = self.check() else {
            return Err(Fatal::new(format!(
                "rule {:?}: nothing says what it checks. Set one of: regexp, \
                 path_regexp, require_regexp, max_lines, encoding, allowed_scripts, \
                 forbidden_literals, forbidden_literals_from, builtin, exec",
                self.id
            )));
        };

        // `forbidden_literals` and `forbidden_literals_from` are two spellings
        // of one check -- a named source or a command producing the same
        // literals -- so they are one entry here and refused together below.
        let distinct = set
            .iter()
            .filter(|field| !matches!(**field, "forbidden_literals" | "forbidden_literals_from"))
            .count()
            + usize::from(
                self.forbidden_literals.is_some() || self.forbidden_literals_from.is_some(),
            );
        self.refuse(
            distinct > 1,
            &format!(
                "{} say what it checks, and a rule checks one thing. Split it into \
                 one rule per check, or delete the field that is not meant",
                set.join(" and ")
            ),
        )?;
        self.refuse(
            self.forbidden_literals.is_some() && self.forbidden_literals_from.is_some(),
            "`forbidden_literals` names a built-in source and `forbidden_literals_from` \
             names a command; one rule cannot have both",
        )?;

        if check.requires_files() && self.files.is_none() {
            return Err(Fatal::new(format!(
                "rule {:?}: `{check}` searches files, so it needs `files.*` keys \
                 saying which. Write `files.include = [\".\"]` for the whole tree",
                self.id
            )));
        }
        if !check.requires_files() && check != Check::Builtin && self.files.is_some() {
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
            && !matches!(check, Check::Regexp | Check::ForbiddenLiterals)
        {
            return Err(Fatal::new(format!(
                "rule {:?}: `exclude_cfg_test` drops content hits inside a `#[cfg(test)]` \
                 block, and a `{check}` finding has no matched line to be inside one, so \
                 the field would be read by nothing. Narrow this rule with `exclude` \
                 instead",
                self.id
            )));
        }

        // The label is resolved at load, so a typo is a refusal here and not a
        // rule that fails every file it selects.
        if let Some(label) = self.encoding.as_deref() {
            if encoding_rs::Encoding::for_label(label.as_bytes()).is_none() {
                return Err(Fatal::new(format!(
                    "rule {:?}: {label:?} names no encoding the WHATWG registry carries. \
                     Labels are the ones browsers accept -- \"UTF-8\", \"Shift_JIS\", \
                     \"EUC-JP\", \"windows-1252\"",
                    self.id
                )));
            }
        }

        // `ignore_literals` suppresses needles, and only the literal check
        // has needles to suppress.
        if self.ignore_literals.is_some() && check != Check::ForbiddenLiterals {
            return Err(Fatal::new(format!(
                "rule {:?}: `ignore_literals` drops literals from the search, and \
                 `{check}` searches for no literals, so the field would be read by \
                 nothing",
                self.id
            )));
        }

        // `exclusive` is the reverse direction of the script check and of
        // nothing else.
        if self.exclusive.is_some() && check != Check::AllowedScripts {
            return Err(Fatal::new(format!(
                "rule {:?}: `exclusive` reverses `allowed_scripts` -- these scripts \
                 only under these paths -- and `{check}` reads no scripts, so the \
                 field would be read by nothing",
                self.id
            )));
        }

        // Same mechanism for the link-checker knobs: they are read by the
        // `links-resolve` built-in and nothing else. They used to sit in the
        // shared `files.*` selection vocabulary, where every check accepted
        // them; they are rule-level fields now, refused where no links are
        // read.
        if self.builtin() != Some("links-resolve") {
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
                    "rule {:?}: {} read(s) links, and only the `links-resolve` built-in \
                     reads any -- on this rule the field would be read by nothing and \
                     would look like configuration that works",
                    self.id,
                    link_fields.join(" and ")
                )));
            }
        }

        // The mirror of the `files.*` refusal above, and it was missing.
        // `guard::evaluate` dispatches on the BUILT-IN name and returns "no
        // violation" for a rule that has none, so a `regexp` or `exec` rule
        // wired to a hook was collected by `at_hook`, counted by `ran`, never
        // run, and reported inside "N guard(s) passed". Config that is accepted
        // and does nothing is bad; config that is accepted, does nothing, and
        // is counted as having passed is worse.
        if check != Check::Builtin && self.git.is_some() {
            return Err(Fatal::new(format!(
                "rule {:?}: only a `builtin` runs at a git hook, so `git.hooks` on a \
                 `{check}` rule would be read by nothing and would look like \
                 configuration that works.\n\
                 A rule that searches the tree says so with `files.*`, and the \
                 `uphold-scan` hook is what runs it at a hook.",
                self.id
            )));
        }

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

        if let Some(name) = self.builtin() {
            if !crate::guard::EVERY_BUILTIN.contains(&name) {
                return Err(Fatal::new(format!(
                    "rule {:?}: no built-in is called {name:?}. This binary carries: {}",
                    self.id,
                    crate::guard::EVERY_BUILTIN.join(", ")
                )));
            }
        }

        // Each built-in declares the parameters it reads; a parameter beside a
        // check that does not read it is refused exactly as a second check
        // field is, and for the same reason. The nine sit flat on this struct,
        // so before this check an `allowed_owners` beside `regexp` loaded,
        // looked enforced, and was read by nothing.
        let written = self.written_parameters();
        if !written.is_empty() {
            const NONE: &[&str] = &[];
            let reads = self.builtin().map_or(NONE, crate::guard::parameters);
            let foreign: Vec<&str> = written
                .into_iter()
                .filter(|parameter| !reads.contains(parameter))
                .collect();
            if !foreign.is_empty() {
                let reader = match self.builtin() {
                    Some(name) if reads.is_empty() => {
                        format!("built-in {name:?} reads no parameters")
                    }
                    Some(name) => format!("built-in {name:?} reads only {}", reads.join(", ")),
                    None => format!("`{check}` reads no built-in parameters"),
                };
                return Err(Fatal::new(format!(
                    "rule {:?}: {} would be read by nothing -- {reader}. A parameter \
                     read by nothing looks enforced and is not; delete it, or move it \
                     to the rule whose built-in reads it",
                    self.id,
                    foreign.join(" and ")
                )));
            }
        }

        // A message is what a reader acts on. The checks that compose their own
        // report are the two whose useful half is the finding itself -- the
        // script and the declaration it is missing from, the character and its
        // Unicode name -- and a hand-written message there only repeats it.
        if !matches!(check, Check::AllowedScripts | Check::Builtin) && self.message.is_none() {
            return Err(Fatal::new(format!(
                "rule {:?}: `{check}` needs a `message` saying what to do about a hit",
                self.id
            )));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyFile {
    #[serde(default)]
    pub inherit: Option<Inherit>,
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
    #[serde(default, rename = "rule")]
    pub rules: BTreeMap<String, Rule>,
    #[serde(default, rename = "shim")]
    pub shims: Vec<crate::shim::Shim>,
}

/// A loaded policy: inherited rules merged with the repository's own, ids
/// checked unique across the whole set.
#[derive(Debug, Clone, Default)]
pub(crate) struct Policy {
    pub redact_matches: bool,
    pub allowed_scripts: Vec<String>,
    pub rules: Vec<Rule>,
    pub shims: Vec<crate::shim::Shim>,
}

impl Policy {
    pub(crate) fn of_check(&self, check: Check) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(move |rule| rule.is(check))
    }

    pub(crate) fn has_check(&self, check: Check) -> bool {
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
    for (id, rule) in &mut file.rules {
        rule.id.clone_from(id);
    }
    Ok(file)
}

/// Load a policy file, resolving `[inherit]` and validating the result.
pub(crate) fn load(root: &Path, policy_path: &Path) -> Result<Policy> {
    let text = read_to_string(policy_path)?;
    let file = parse(policy_path, &text)?;
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
        let virtual_path = Path::new("<bundled>").join(format!("{name}.toml"));
        inherited.extend(parse(&virtual_path, bundled.1)?.rules.into_values());
    }

    for relative in &inherit.paths {
        let path = root.join(relative);
        let extended = read_to_string(&path)?;
        inherited.extend(parse(&path, &extended)?.rules.into_values());
    }

    let own_ids: Vec<&str> = file.rules.keys().map(String::as_str).collect();
    let disabled = &inherit.disabled_rules;

    let mut rules: Vec<Rule> = inherited
        .into_iter()
        .filter(|rule| !disabled.contains(&rule.id) && !own_ids.iter().any(|own| *own == rule.id))
        .collect();
    rules.extend(file.rules.values().cloned());

    // A disabled id that names nothing is the same failure as a stale baseline
    // entry: it reads as a decision that is doing something and it is doing
    // nothing, and it will keep reading that way after the rule it named is
    // gone.
    let inheritable: Vec<String> = {
        let mut names = Vec::new();
        for name in &inherit.sets {
            if let Some((_, bundled)) = BUNDLED.iter().find(|(bundled, _)| *bundled == name) {
                let path = Path::new("<bundled>").join(format!("{name}.toml"));
                names.extend(parse(&path, bundled)?.rules.into_keys());
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

    Ok(Policy {
        redact_matches: file.redact_matches,
        allowed_scripts: file.allowed_scripts,
        rules,
        shims: file.shims,
    })
}

/// The rules one bundled set ships, for `uphold rules --set <name>`.
///
/// The set names are the adoption surface: a stranger decides whether to
/// inherit one from its name, and this is what lets the binary answer "what is
/// in it" without a docs round-trip -- the name must predict the rule list,
/// and here is the rule list.
pub(crate) fn bundled_set(name: &str) -> Result<Vec<Rule>> {
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
    let path = Path::new("<bundled>").join(format!("{name}.toml"));
    Ok(parse(&path, bundled)?.rules.into_values().collect())
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
fn validate_unique(policy_path: &Path, rules: &[Rule]) -> Result<()> {
    let mut seen: BTreeMap<&str, Option<Check>> = BTreeMap::new();
    for rule in rules {
        if let Some(first) = seen.insert(rule.id.as_str(), rule.check()) {
            let named = |check: Option<Check>| {
                check.map_or_else(|| String::from("nothing"), |kind| kind.to_string())
            };
            return Err(Fatal::at(
                policy_path,
                format!(
                    "two inherited files define the id {:?} (one checks {}, the other {}). \
                     Rule ids are one namespace: a claim naming this id could not \
                     say which rule it meant.",
                    rule.id,
                    named(first),
                    named(rule.check())
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
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "uphold-config-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
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
    /// `Check::as_str` is a promise that the name printed in an error is the
    /// name a reader can go and edit, and `check()` reading that same field is
    /// what keeps the promise.
    #[test]
    fn every_check_is_named_by_the_field_that_selects_it() {
        for check in Check::ALL {
            let rule = Rule::synthetic("x", check);
            assert_eq!(
                rule.check(),
                Some(check),
                "synthetic {check} did not select itself"
            );
            let document = format!("[rule.x]\n{} = ", check.as_str());
            assert!(
                !document.is_empty(),
                "{check} has no field name to write down"
            );
        }
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
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "uphold-config-inherit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
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
    fn a_repo_rule_shadows_the_inherited_rule_of_the_same_id() {
        let policy = policy_from(
            r#"
            [inherit]
            sets = ["process-residue"]

            [rule.no-hardcoded-home-paths]
            message = "local"
            regexp = "local"

            [rule.no-hardcoded-home-paths.files]
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
        assert!(policy.has_check(Check::Regexp));
        assert!(policy.has_check(Check::PathRegexp));
        assert!(policy
            .rules
            .iter()
            .any(|rule| rule.id == "no-pinned-tool-install"));
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
