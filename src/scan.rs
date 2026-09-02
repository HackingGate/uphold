//! The seven rule kinds.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use unicode_script::{Script, UnicodeScript};

use crate::config::{Check, CheckKind, Files, Policy, Rule};
use crate::engine::{self, Hit, Query};
use crate::error::{Fatal, Result};
use crate::report::{body_for, Failure};
use crate::selection::{normalize_rel, not_text_paths, Selection};

/// The command name a `command_sources` pattern captures out of a path.
///
/// Built from the two halves the placeholder splits the pattern into, so the
/// name is read from the same string that selected the file. `*` and `**` become
/// what they mean to a glob rather than what they mean to a regex, and the
/// placeholder becomes one path segment -- a command's name is a directory or a
/// file stem, never a path.
fn command_name_pattern(before: &str, after: &str) -> Option<Regex> {
    fn as_regex(part: &str) -> String {
        let mut out = String::new();
        let mut rest = part;
        while let Some(index) = rest.find('*') {
            if let Some(literal) = rest.get(..index) {
                out.push_str(&regex::escape(literal));
            }
            let doubled = rest.get(index..index + 2) == Some("**");
            out.push_str(if doubled { ".*" } else { "[^/]*" });
            let Some(remainder) = rest.get(index + if doubled { 2 } else { 1 }..) else {
                return out;
            };
            rest = remainder;
        }
        out.push_str(&regex::escape(rest));
        out
    }
    Regex::new(&format!("^{}([^/]+){}$", as_regex(before), as_regex(after))).ok()
}

/// Explains a baseline entry that no longer matches.
///
/// Separate from the rule's own message, which explains the prohibition -- a
/// stale entry is a different problem, and telling someone the prohibition again
/// does not help them fix it.
const STALE_BASELINE: &str = "This rule's baseline lists paths that no longer match it. Delete \
them: an entry that no longer describes the tree is the rule switched off for that path, and it \
will stay off if the file ever regains a match.";

/// The must-find counterpart. A `require` baseline lists paths allowed to be
/// MISSING the pattern, so an entry goes stale the other way round: the path
/// acquired what the rule requires, the debt is paid, and the entry now only
/// hides the file losing it again.
const STALE_REQUIRE_BASELINE: &str = "This rule's baseline lists paths that no longer need the \
exemption -- they satisfy the rule now, or they are gone. Delete them: an entry that no longer \
describes the tree is the requirement switched off for that path if the pattern ever disappears \
again.";

/// Explains a selection that came in under the floor its rule declared.
///
/// Separate from the rule's own message, which explains the prohibition -- and
/// deliberately so, because nothing in the tree violated it. What is wrong is
/// the selection, and printing "resolve the conflict" over a rule that read no
/// files sends the reader to look for a hit that is not there.
const BELOW_SELECTION_FLOOR: &str = "This rule selected fewer files than it declared it must. \
`files.min_selected` is the claim that the rule still covers something, and an include root that \
moved, a glob that stopped matching or an exclude that widened all leave it reporting a pass over \
files it never read -- which is indistinguishable, in every report, from a clean tree.";

/// What a size rule measures, and the word its report uses.
///
/// One check with a measure rather than two implementations, because
/// everything around the number is the same in both: the same selection, the
/// same `path count` baseline file, the same ratchet, the same staleness
/// report. Two copies would be two places for the ratchet to be got wrong, and
/// only one of them would have a test that noticed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Measure {
    Lines,
    Bytes,
}

impl Measure {
    /// The unit as a report spells it, and as a baseline file's own error
    /// message spells it. A reader who is told "8 lines" over a byte cap goes
    /// looking for a file that is not there.
    const fn unit(self) -> &'static str {
        match self {
            Self::Lines => "lines",
            Self::Bytes => "bytes",
        }
    }

    /// The measure in the singular, for the sentences that name a COUNT of it:
    /// "no line count after the path" reads, "no lines count" does not.
    const fn singular(self) -> &'static str {
        match self {
            Self::Lines => "line",
            Self::Bytes => "byte",
        }
    }

    /// The number this measure reads off a file's bytes.
    fn of(self, bytes: &[u8]) -> u64 {
        match self {
            // Newline count, matching `wc -l`.
            #[expect(
                clippy::naive_bytecount,
                reason = "a SIMD line-counting dependency is not worth its supply-chain surface for one pass per file"
            )]
            Self::Lines => bytes.iter().filter(|byte| **byte == b'\n').count() as u64,
            Self::Bytes => bytes.len() as u64,
        }
    }
}

/// One `encoding` rule's declaration: the files it selects, and the charset it
/// says their bytes are in.
type Declared = (BTreeSet<String>, &'static encoding_rs::Encoding);

/// One scoped `allowed_scripts` rule, resolved: the files it selects, the
/// scripts it admits there, and whether it claims them exclusively.
struct Scoped {
    id: String,
    files: BTreeSet<String>,
    names: Vec<String>,
    scripts: Vec<Script>,
    exclusive: bool,
}

pub(crate) struct Scan<'a> {
    root: &'a Path,
    policy: &'a Policy,
    not_text: Vec<String>,
    /// Every path any rule's selection knew about and could not open.
    ///
    /// Interior mutability because `run` takes `&self` and every check arm
    /// under it does too, and because this is the one thing a scan accumulates
    /// that is not a finding. A `BTreeSet` because the rules overlap: one
    /// unreadable file is one line in the report however many rules selected
    /// it, and sorted because a report whose order depends on rule order diffs
    /// against itself between runs.
    unreadable: RefCell<BTreeSet<String>>,
    /// Findings from the `files.min_selected` floors, waiting for the rule that
    /// earned them to finish.
    ///
    /// Interior mutability for the reason `unreadable` has it, and gathered at
    /// the same one place. The floor is a claim about the SELECTION rather than
    /// about any one check's findings, so implementing it inside a check arm
    /// would be implementing it once per kind -- which is how `require_regexp`
    /// came to have none while `links-resolve` and `anchors-resolve` each grew
    /// their own.
    ///
    /// Keyed by rule id, and the value is taken out rather than removed, for
    /// the reason `unreadable` is a set: one rule below its floor is one
    /// finding however many times its count was taken, and some rules are
    /// selected for twice -- `script_failures` builds an `encoding` rule's
    /// selection to learn how to decode a file, and the encoding check then
    /// builds it again. The emptied key is what stops the second one repeating
    /// the finding under a later check's heading.
    below_floor: RefCell<BTreeMap<String, Option<Failure>>>,
    /// Which files each `encoding` rule selects, built once on first use.
    ///
    /// The declarations are what turn "these bytes are not UTF-8" from a
    /// could-not-look into a decoding, so every check needs them and none of
    /// them may build its own answer: two readings of the same selection are
    /// two rules free to disagree about whether a file is readable. Built
    /// through `Selection` directly rather than through `select`, because the
    /// selection floor belongs to the rule whose check is running and not to
    /// whichever check happened to ask about encodings first.
    declared_encodings: RefCell<Option<Vec<Declared>>>,
}

impl<'a> Scan<'a> {
    pub(crate) fn new(root: &'a Path, policy: &'a Policy) -> Self {
        // A `.gitattributes` question that could not be answered is seeded into
        // the unreadable list rather than dropped, because the scan continues
        // either way and the reader has to be told which of the two answers they
        // are holding: nothing is declared not-text, or nobody could find out.
        let (not_text, unmeasured) = not_text_paths(root);
        let mut unreadable = BTreeSet::new();
        if let Some(reason) = unmeasured {
            unreadable.insert(reason);
        }
        Self {
            root,
            policy,
            not_text,
            unreadable: RefCell::new(unreadable),
            below_floor: RefCell::new(BTreeMap::new()),
            declared_encodings: RefCell::new(None),
        }
    }

    pub(crate) fn not_text(&self) -> &[String] {
        &self.not_text
    }

    /// The paths this scan could not read, each with its reason.
    ///
    /// Reported beside the findings rather than instead of them, and that is
    /// the point of collecting rather than failing: a tree with one unreadable
    /// path still has an answer for every other rule, and refusing to give it
    /// makes the fix for the unreadable path the only thing anybody ever sees.
    /// Non-empty is exit 2 -- "could not look" is not a pass -- but every rule
    /// has already reported by the time the caller asks.
    pub(crate) fn unreadable(&self) -> Vec<String> {
        self.unreadable.borrow().iter().cloned().collect()
    }

    /// Evaluate every rule that declares `[rule.files]`, in check order.
    ///
    /// The table is the filter, and that is the change: a rule used to be here
    /// because its KIND was one of the seven the scan owned, so "search the
    /// tree with this, but install no git hook" was not a thing a rule could
    /// say. It says it by writing `[rule.files]` and no `[rule.git]`.
    pub(crate) fn run(&self) -> Result<Vec<Failure>> {
        let mut failures = Vec::new();
        for check in CheckKind::ALL {
            // A built-in with `[rule.files]` reads the tree; one without reads
            // a message or a push, and belongs to `guard`. The table decides.
            if check == CheckKind::Builtin {
                for rule in self.policy.of_check(check) {
                    if !rule.reads_files() {
                        continue;
                    }
                    let found = match rule.builtin().unwrap_or_default() {
                        "links-resolve" => self.link_failures(rule)?,
                        "anchors-resolve" => self.anchor_failures(rule)?,
                        "commands-resolve" => self.command_failures(rule)?,
                        // A guard built-in's `[rule.files]` is not read by
                        // nothing: `guard::scope::in_file_scope` reads it, to
                        // scope the guard to part of the tree. So the question
                        // is which seam owns the rule, and `git.hooks` answers
                        // it -- a rule that names a hook runs there, and this
                        // scan is not its seam to fail from.
                        //
                        // Aborting here regardless is what made scoping a guard
                        // -- the supported way to narrow one -- kill content
                        // scanning for the WHOLE repository at exit 2, with a
                        // diagnosis that was not true of the rule it named.
                        _ if !rule.hooks().is_empty() => continue,
                        // With no hook either, nothing runs it and the keys
                        // really are read by nothing. Silently passing over
                        // that would report a check that did not happen as one
                        // that did.
                        other => {
                            return Err(Fatal::new(format!(
                                "rule {:?}: built-in {other:?} does not read files and names \
                                 no `git.hooks`, so nothing runs it and its `files.*` keys \
                                 would be read by nothing",
                                rule.id
                            )))
                        }
                    };
                    failures.extend(self.take_floor_failures());
                    failures.extend(found);
                }
                continue;
            }
            if !check.requires_files() {
                continue;
            }
            if check == CheckKind::AllowedScripts {
                // Script rules interact -- a scoped list replaces the global
                // one for its files, and an exclusive rule speaks about files
                // it does not select -- so they are evaluated once as a
                // policy rather than independently.
                let found = self.script_failures()?;
                failures.extend(self.take_floor_failures());
                failures.extend(found);
                continue;
            }
            for rule in self.policy.of_check(check) {
                if !rule.reads_files() {
                    continue;
                }
                let found = match check {
                    CheckKind::Regexp => self.pattern_failures(rule)?,
                    CheckKind::CommentRegexp => self.comment_pattern_failures(rule)?,
                    CheckKind::ProseRegexp => self.prose_pattern_failures(rule)?,
                    CheckKind::TrivialComments => self.trivial_comment_failures(rule)?,
                    CheckKind::ForbiddenLiterals => self.literal_failures(rule)?,
                    CheckKind::MaxLines => self.size_failures(rule, Measure::Lines)?,
                    CheckKind::MaxBytes => self.size_failures(rule, Measure::Bytes)?,
                    CheckKind::PathRegexp => self.path_failures(rule)?,
                    CheckKind::RequireRegexp => self.require_failures(rule)?,
                    CheckKind::Encoding => self.encoding_failures(rule)?,
                    CheckKind::AllowedScripts | CheckKind::Builtin | CheckKind::Exec => {
                        unreachable!("filtered above")
                    }
                };
                failures.extend(self.take_floor_failures());
                failures.extend(found);
            }
        }
        Ok(failures)
    }

    /// The charset one `encoding` rule declares for this path, if one covers it.
    fn declared_encoding(&self, relative: &str) -> Result<Option<&'static encoding_rs::Encoding>> {
        if self.declared_encodings.borrow().is_none() {
            let mut declared: Vec<Declared> = Vec::new();
            for rule in self.policy.of_check(CheckKind::Encoding) {
                let label = rule.encoding().unwrap_or_default();
                // A label the registry does not carry is refused at load and
                // again in `encoding_failures`. Here it is simply not a
                // declaration, so the file it selects stays undeclared rather
                // than being decoded as something nobody wrote.
                if let Some(encoding) = encoding_rs::Encoding::for_label(label.as_bytes()) {
                    let selection = Selection::build(self.root, rule, &self.not_text)?;
                    self.unreadable
                        .borrow_mut()
                        .extend(selection.unreadable().iter().cloned());
                    declared.push((selection.files().into_iter().collect(), encoding));
                }
            }
            *self.declared_encodings.borrow_mut() = Some(declared);
        }
        Ok(self
            .declared_encodings
            .borrow()
            .as_ref()
            .and_then(|declared| {
                declared
                    .iter()
                    .find(|(files, _)| files.contains(relative))
                    .map(|(_, encoding)| *encoding)
            }))
    }

    /// One selected file as the text every check reads, or nothing and why.
    ///
    /// The one place in the scan that decides what a file's bytes say, and it
    /// was three places: `allowed_scripts` decoded under the declared charset
    /// and stopped the run where nothing declared one, while `regexp`,
    /// `forbidden_literals` and `require_regexp` handed the raw bytes to a
    /// lossy sink and reported whatever came out. A UTF-16 file was exit 2 for
    /// one check and clean for the other three, in the same run, over the same
    /// bytes.
    ///
    /// `None` is "there is no text here", which is the one honest skip: a
    /// binary file has no lines for a pattern to be found on. A file that is
    /// text except for the bytes nobody declared is not a skip -- it goes into
    /// `unreadable`, which is exit 2 beside the findings rather than instead of
    /// them.
    ///
    /// Valid UTF-8 is answered before anything else is consulted, which is the
    /// whole of the cost this adds to an ordinary tree: one `from_utf8` over
    /// bytes that were about to be searched anyway.
    fn text_of(&self, relative: &str) -> Result<Option<String>> {
        let path = self.root.join(relative);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                // Recorded and carried past, the way every other reader here
                // does it: one missing path must not hide every finding the
                // remaining rules had.
                self.unreadable
                    .borrow_mut()
                    .insert(format!("{}: could not be read ({error})", path.display()));
                return Ok(None);
            }
        };
        if let Ok(text) = std::str::from_utf8(&bytes) {
            return Ok(Some(text.to_owned()));
        }
        // What the policy DECLARED, before any guess about the bytes. A
        // declaration is not a guess, and where there is one it answers first.
        if let Some(encoding) = self.declared_encoding(relative)? {
            let (decoded, _, had_errors) = encoding.decode(&bytes);
            if had_errors {
                // Not even its declared encoding. The `encoding` check reports
                // this file by name in the same run, and there is no text here
                // for anything else to read.
                self.unreadable.borrow_mut().insert(format!(
                    "{relative}: does not decode as the {} its `encoding` rule declares",
                    encoding.name()
                ));
                return Ok(None);
            }
            return Ok(Some(decoded.into_owned()));
        }
        // The same three-answer reader the guards use, so the two seams cannot
        // disagree about whether a blob has text in it: a byte-order mark is
        // consulted before the NUL test, because a UTF-16 file is full of NULs
        // and dismissing it as an image takes an ordinary document out of the
        // scan while looking exactly like a skipped binary.
        match crate::guard::scope::decode(&bytes) {
            crate::guard::scope::Decoded::Text(text) => Ok(Some(text)),
            crate::guard::scope::Decoded::Binary => Ok(None),
            crate::guard::scope::Decoded::Unreadable(why) => {
                self.unreadable.borrow_mut().insert(format!(
                    "{relative}: cannot be read as text ({why}), so \"clean\" here would \
                     mean \"unexamined\". Declare its charset with an `encoding` rule \
                     selecting it, exclude it from the rules that select it, or mark it \
                     not text in .gitattributes"
                ));
                Ok(None)
            }
        }
    }

    fn select(&self, rule: &Rule) -> Result<Vec<String>> {
        let selection = Selection::build(self.root, rule, &self.not_text)?;
        // Gathered here, at the one place every rule's selection passes
        // through, so no future check kind can acquire its own way of dropping
        // a path it could not open.
        self.unreadable
            .borrow_mut()
            .extend(selection.unreadable().iter().cloned());
        let files = selection.files();
        // And the floor is measured here for the same reason. Every check kind
        // reaches the tree through this function, so a kind added tomorrow
        // enforces `files.min_selected` without its author having to know the
        // field exists.
        if let Some(failure) = below_floor_failure(rule, files.len()) {
            self.below_floor
                .borrow_mut()
                .entry(rule.id.clone())
                .or_insert(Some(failure));
        }
        Ok(files)
    }

    /// The floor findings gathered since the last rule was asked for.
    ///
    /// Drained per rule rather than at the end of the run, so the report reads
    /// "this rule selected nothing" beside that rule's own findings instead of
    /// in a block after every other rule has spoken.
    fn take_floor_failures(&self) -> Vec<Failure> {
        self.below_floor
            .borrow_mut()
            .values_mut()
            .filter_map(Option::take)
            .collect()
    }

    const fn redact(&self) -> bool {
        self.policy.redact_matches
    }

    // -- pattern ------------------------------------------------------------

    fn pattern_failures(&self, rule: &Rule) -> Result<Vec<Failure>> {
        let files = self.select(rule)?;
        let pattern = rule.expression().unwrap_or_default();
        let query = Query::from_files(pattern, rule.files());
        // One file at a time, so a tree the size of a monorepo is one decoded
        // file in memory rather than all of them.
        let mut hits: Vec<Hit> = Vec::new();
        for file in &files {
            if let Some(text) = self.text_of(file)? {
                hits.extend(engine::search_in(file, &text, &query, &rule.id)?);
            }
        }
        if rule.files().exclude_cfg_test {
            hits = self.drop_cfg_test_hits(hits);
        }

        let mut failures = Vec::new();
        let baseline = self.load_path_baseline(rule.files().baseline.as_deref())?;
        if !baseline.is_empty() {
            let seen: BTreeSet<String> = hits
                .iter()
                .map(|hit| normalize_rel(&hit.path).to_owned())
                .filter(|path| baseline.contains(path))
                .collect();
            hits.retain(|hit| !baseline.contains(normalize_rel(&hit.path)));
            failures.extend(baseline.unsigned_failure(rule, self.policy.baselines_signed));
            failures.extend(stale_baseline_failure(
                rule,
                &baseline.paths,
                &seen,
                STALE_BASELINE,
            ));
        }

        if !hits.is_empty() {
            failures.push(Failure::new(
                &rule.id,
                rule.message(),
                body_for(&hits, self.redact()),
            ));
        }
        Ok(failures)
    }

    // -- comments -----------------------------------------------------------

    /// Every comment in the files a rule selects, with the ones the language
    /// cannot be read for left out.
    ///
    /// A selected file in a language no grammar here knows is skipped and not
    /// reported: `files.include = ["src"]` on a mixed tree is a normal thing to
    /// write, and a Markdown file under it is not an unreadable one. What IS
    /// reported is a rule that selects nothing parseable at all, because that is
    /// a rule whose author believes it runs.
    fn comments_of(&self, rule: &Rule) -> Result<Vec<(String, crate::comments::Comment)>> {
        let files = self.select(rule)?;
        let mut parsed = 0_usize;
        let mut found = Vec::new();
        for file in &files {
            let Some(language) = crate::comments::Language::for_path(file) else {
                continue;
            };
            // Through the one reader, so a source file in a declared charset
            // is parsed rather than recorded as unreadable: `read_to_string`
            // stood here and knew nothing about the `encoding` rules.
            let Some(source) = self.text_of(file)? else {
                continue;
            };
            parsed += 1;
            for comment in crate::comments::collect(&source, language) {
                found.push((file.clone(), comment));
            }
        }
        if parsed == 0 && !files.is_empty() {
            return Err(Fatal::new(format!(
                "rule {:?}: selects {} file(s) and none of them is Rust, Python or Go, so \
                 the check reads no comments at all. Narrow `files.glob` to the languages \
                 it is meant for",
                rule.id,
                files.len()
            )));
        }
        Ok(found)
    }

    fn comment_pattern_failures(&self, rule: &Rule) -> Result<Vec<Failure>> {
        let pattern = rule.expression().unwrap_or_default();
        let matcher = Regex::new(pattern)
            .map_err(|error| Fatal::new(format!("rule {:?}: {error}", rule.id)))?;
        let hits: Vec<Hit> = self
            .comments_of(rule)?
            .into_iter()
            .filter(|(_, comment)| !comment.doc && matcher.is_match(&comment.text))
            .map(|(path, comment)| Hit {
                path,
                line: Some(comment.line),
                text: comment.text,
            })
            .collect();
        if hits.is_empty() {
            return Ok(Vec::new());
        }
        Ok(vec![Failure::new(
            &rule.id,
            rule.message(),
            body_for(&hits, self.redact()),
        )])
    }

    // -- prose ---------------------------------------------------------------

    /// Every prose rule's hits: the regex over the SENTENCES of each selected
    /// file, with the extractor chosen by the file's kind.
    ///
    /// A selected file this binary reads no prose from is skipped and not
    /// reported, for the reason `comments_of` gives about a Markdown file under
    /// `files.include = ["src"]`: a mixed tree is the normal thing to select,
    /// and a PNG in it is not a document somebody wrote badly. What separates
    /// that from a rule whose whole selection has no prose in it is
    /// `files.min_selected`, which is where a floor belongs.
    ///
    /// The kind is decided from the PATH, before the file is opened. Reading a
    /// captured artifact as text to discover it has no sentences in it would
    /// make every binary in a tree an unreadable-path finding.
    fn prose_pattern_failures(&self, rule: &Rule) -> Result<Vec<Failure>> {
        let matcher = crate::prose::compile(rule.prose_regexp().unwrap_or_default(), &rule.id)?;
        let mut hits: Vec<Hit> = Vec::new();
        for file in self.select(rule)? {
            if !crate::prose::reads(&file) {
                continue;
            }
            // The same accounting every other check here keeps, in the one
            // reader that keeps it: a file of a kind that HAS prose and could
            // not be decoded is recorded rather than skipped, because a checker
            // that passes over what it could not open is claiming a tree it
            // never examined.
            let Some(source) = self.text_of(&file)? else {
                continue;
            };
            for span in crate::prose::of(&file, &source) {
                if matcher.is_match(&span.text) {
                    hits.push(Hit {
                        path: file.clone(),
                        line: Some(span.line),
                        text: span.text,
                    });
                }
            }
        }
        if hits.is_empty() {
            return Ok(Vec::new());
        }
        Ok(vec![Failure::new(
            &rule.id,
            rule.message(),
            body_for(&hits, self.redact()),
        )])
    }

    fn trivial_comment_failures(&self, rule: &Rule) -> Result<Vec<Failure>> {
        let hits: Vec<Hit> = self
            .comments_of(rule)?
            .into_iter()
            .filter(|(_, comment)| crate::comments::is_trivial(comment))
            .map(|(path, comment)| Hit {
                path,
                line: Some(comment.line),
                text: comment.text,
            })
            .collect();
        if hits.is_empty() {
            return Ok(Vec::new());
        }
        Ok(vec![Failure::new(
            &rule.id,
            rule.message(),
            body_for(&hits, self.redact()),
        )])
    }

    // -- forbidden literals -------------------------------------------------

    fn literal_failures(&self, rule: &Rule) -> Result<Vec<Failure>> {
        let files = self.select(rule)?;
        if files.is_empty() {
            return Ok(Vec::new());
        }
        // `forbidden_literals_from` IS the command source. v2 spelled it
        // `source = "command"` beside `run`, which made the pair say one thing
        // twice and let them disagree; the field carrying the command is the
        // whole declaration now.
        let source = if rule.forbidden_literals_from().is_some() {
            "command"
        } else {
            rule.forbidden_literals().unwrap_or_default()
        };
        let needles = crate::sources::resolve(
            source,
            rule.forbidden_literals_from(),
            self.root,
            rule.files().word,
            &rule.id,
            rule.ignore_literals(),
        )?;

        // The file loop is outside the needle loop, which is the other way
        // round from how this read before: a file is decoded once and every
        // needle is asked of the text, rather than the file being opened once
        // per needle. The findings are still grouped by needle, because the
        // label a reader acts on is the literal that was found.
        let mut found: BTreeMap<usize, Vec<Hit>> = BTreeMap::new();
        let queries: Vec<(String, Query)> = needles
            .iter()
            .map(|needle| {
                (
                    format!("{} ({})", rule.id, needle.label),
                    Query::literal(&needle.value, needle.word),
                )
            })
            .collect();
        for file in &files {
            let Some(text) = self.text_of(file)? else {
                continue;
            };
            for (index, (label, query)) in queries.iter().enumerate() {
                let hits = engine::search_in(file, &text, query, label)?;
                if !hits.is_empty() {
                    found.entry(index).or_default().extend(hits);
                }
            }
        }

        let mut failures = Vec::new();
        for (index, (label, _)) in queries.into_iter().enumerate() {
            let Some(mut hits) = found.remove(&index) else {
                continue;
            };
            if rule.files().exclude_cfg_test {
                hits = self.drop_cfg_test_hits(hits);
            }
            if !hits.is_empty() {
                failures.push(Failure::new(
                    label,
                    rule.message(),
                    body_for(&hits, self.redact()),
                ));
            }
        }
        Ok(failures)
    }

    // -- size ---------------------------------------------------------------

    fn size_failures(&self, rule: &Rule, measure: Measure) -> Result<Vec<Failure>> {
        let limit = match measure {
            Measure::Lines => rule.max_lines(),
            Measure::Bytes => rule.max_bytes(),
        }
        .unwrap_or_default();
        let unit = measure.unit();
        let baseline = self.load_size_baseline(rule.files().baseline.as_deref(), measure)?;
        let mut violations: Vec<String> = Vec::new();
        // Which baselined paths this run actually looked at. A size baseline had
        // no staleness check at all while the path baselines have had one since
        // they were written -- and `STALE_BASELINE` says exactly what a stale
        // entry is: the rule switched off for that path. A file listed at 9000
        // lines that has since been renamed away leaves an allowance nothing
        // reports, and it applies again in full the day something takes the name
        // back.
        let mut baselined_seen: BTreeSet<String> = BTreeSet::new();
        for relative in self.select(rule)? {
            if baseline.contains_key(normalize_rel(&relative)) {
                baselined_seen.insert(normalize_rel(&relative).to_owned());
            }
            // An unreadable file is not a short file. `engine::search_files`
            // makes precisely this fatal -- "a checker that skips what it could
            // not open is claiming a tree it never examined" -- and this loop
            // was quietly stepping over it.
            let bytes = std::fs::read(self.root.join(&relative))
                .map_err(|error| Fatal::at(&self.root.join(&relative), error))?;
            let count = measure.of(&bytes);
            match baseline.get(normalize_rel(&relative)) {
                None if count > limit => {
                    violations.push(format!("{relative}: {count} {unit} (limit {limit})"));
                }
                Some(allowed) if count > *allowed => {
                    violations.push(format!(
                        "{relative}: {count} {unit} (baseline {allowed}; must not grow)"
                    ));
                }
                _ => {}
            }
        }
        let mut failures = Vec::new();
        if !baseline.is_empty() {
            let listed: BTreeSet<String> = baseline.keys().cloned().collect();
            failures.extend(stale_baseline_failure(
                rule,
                &listed,
                &baselined_seen,
                STALE_BASELINE,
            ));
        }
        if !violations.is_empty() {
            violations.sort();
            failures.push(Failure::new(
                &rule.id,
                rule.message(),
                violations.join("\n"),
            ));
        }
        Ok(failures)
    }

    // -- path ---------------------------------------------------------------

    fn path_failures(&self, rule: &Rule) -> Result<Vec<Failure>> {
        let pattern = rule.expression().unwrap_or_default();
        let matcher = Regex::new(pattern)
            .map_err(|error| Fatal::new(format!("rule {:?}: {error}", rule.id)))?;
        let hits: Vec<Hit> = self
            .select(rule)?
            .into_iter()
            .filter(|path| matcher.is_match(path))
            .map(|path| Hit {
                path,
                line: None,
                text: String::new(),
            })
            .collect();
        // `baseline` was accepted on a path rule and read by nothing, so a
        // grandfathered path stayed a finding however it was written down. That
        // is the quiet direction of the same defect the other kinds had: config
        // that parses, validates, and does not happen. It fails toward MORE
        // findings rather than fewer, which is why it survived -- nobody chases
        // a check that is too loud in the way they chase one that is wrong.
        let mut failures = Vec::new();
        let mut hits = hits;
        let baseline = self.load_path_baseline(rule.files().baseline.as_deref())?;
        if !baseline.is_empty() {
            let seen: BTreeSet<String> = hits
                .iter()
                .map(|hit| normalize_rel(&hit.path).to_owned())
                .filter(|path| baseline.contains(path))
                .collect();
            hits.retain(|hit| !baseline.contains(normalize_rel(&hit.path)));
            failures.extend(baseline.unsigned_failure(rule, self.policy.baselines_signed));
            failures.extend(stale_baseline_failure(
                rule,
                &baseline.paths,
                &seen,
                STALE_BASELINE,
            ));
        }
        if hits.is_empty() {
            return Ok(failures);
        }
        // A path rule's whole finding IS the path, so there is nothing left to
        // redact -- printing `[REDACTED_MATCH]` beside it would withhold nothing
        // while claiming to.
        failures.push(Failure::new(
            &rule.id,
            rule.message(),
            hits.iter()
                .map(|hit| hit.path.clone())
                .collect::<Vec<String>>()
                .join("\n"),
        ));
        Ok(failures)
    }

    // -- require ------------------------------------------------------------

    fn require_failures(&self, rule: &Rule) -> Result<Vec<Failure>> {
        let files = self.select(rule)?;
        if files.is_empty() {
            return Ok(Vec::new());
        }
        let pattern = rule.expression().unwrap_or_default();
        let query = Query::from_files(pattern, rule.files());

        let mut missing: Vec<String> = Vec::new();
        for file in &files {
            // A file that could not be decoded is NOT a file missing the
            // marker, and this is the direction where the lossy read was worst:
            // it turned a file nobody could read into a violation about a
            // marker that may well be in it. `text_of` has already put the path
            // in the unreadable list, which is exit 2, and this leaves it out
            // of the findings.
            let Some(text) = self.text_of(file)? else {
                continue;
            };
            if !engine::text_matches(&text, &query, &rule.id)? {
                missing.push(file.clone());
            }
        }

        let mut failures = Vec::new();
        let baseline = self.load_path_baseline(rule.files().baseline.as_deref())?;
        if !baseline.is_empty() {
            let still_missing: BTreeSet<String> = missing
                .iter()
                .map(|path| normalize_rel(path).to_owned())
                .collect();
            failures.extend(baseline.unsigned_failure(rule, self.policy.baselines_signed));
            failures.extend(stale_baseline_failure(
                rule,
                &baseline.paths,
                &still_missing,
                STALE_REQUIRE_BASELINE,
            ));
            missing.retain(|path| !baseline.contains(normalize_rel(path)));
        }

        if !missing.is_empty() {
            missing.sort();
            let body = missing
                .iter()
                .map(|path| format!("{path}: required pattern not found"))
                .collect::<Vec<String>>()
                .join("\n");
            failures.push(Failure::new(&rule.id, rule.message(), body));
        }
        Ok(failures)
    }

    // -- link ---------------------------------------------------------------

    fn link_failures(&self, rule: &Rule) -> Result<Vec<Failure>> {
        let files = self.select(rule)?;
        let mut hits: Vec<Hit> = Vec::new();
        let mut detailed: Vec<String> = Vec::new();
        let mut checked = 0usize;
        let canonical_root = self
            .root
            .canonicalize()
            .unwrap_or_else(|_| self.root.to_path_buf());

        for relative in &files {
            let text = match std::fs::read_to_string(self.root.join(relative)) {
                Ok(text) => text,
                // Not UTF-8 is not a document: there are no links and no
                // language in bytes that are not text, and skipping is the
                // right answer. An I/O failure is a file NOBODY READ, which is
                // a different fact that used to wear the same clothes -- and
                // `engine::search_files` calls that one fatal for the stated
                // reason that a checker skipping what it could not open is
                // claiming a tree it never examined.
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => continue,
                Err(error) => return Err(Fatal::at(&self.root.join(relative), error)),
            };
            for (line, target) in link_targets(&text) {
                checked += 1;
                let resolved = resolve_link(self.root, &target, relative);
                let canonical = resolved
                    .canonicalize()
                    .unwrap_or_else(|_| lexically_normalize(&resolved));
                let inside = canonical.starts_with(&canonical_root);
                if !inside {
                    if rule.allow_outside_repo() {
                        continue;
                    }
                    hits.push(Hit {
                        path: relative.clone(),
                        line: Some(line),
                        text: target.clone(),
                    });
                    detailed.push(format!(
                        "{relative}:{line}: {target} -> outside the repository"
                    ));
                } else if !resolved.exists() {
                    hits.push(Hit {
                        path: relative.clone(),
                        line: Some(line),
                        text: target.clone(),
                    });
                    detailed.push(format!("{relative}:{line}: {target} -> no such file"));
                }
            }
        }

        if rule.require_any_link() && checked == 0 {
            // An opt-in floor. A selection that yields no links at all is
            // usually a narrowed glob rather than a repository that stopped
            // linking, and a rule covering nothing reports success exactly as
            // loudly as one that works.
            //
            // The file count is deliberately NOT required to be non-zero.
            // Requiring it meant the floor fired when the glob still matched
            // documents but none of them linked, and was skipped entirely when
            // the glob matched NOTHING -- which is the most complete form of the
            // narrowing this floor exists to catch, and the likeliest, since a
            // glob typo selects zero files rather than the wrong ones.
            return Ok(vec![Failure::new(
                &rule.id,
                rule.message(),
                format!(
                    "selected {} file(s) and found no resolvable link; the selection no longer \
                     covers anything",
                    files.len()
                ),
            )]);
        }

        if hits.is_empty() {
            return Ok(Vec::new());
        }
        let body = if self.redact() {
            crate::report::redacted_body(&hits)
        } else {
            detailed.join("\n")
        };
        Ok(vec![Failure::new(&rule.id, rule.message(), body)])
    }

    // -- documented commands ------------------------------------------------

    /// The sources of every command one `command_sources` pattern discovers.
    ///
    /// The pattern selects the files and the `{}` names the command, so the two
    /// halves cannot disagree: a file is a command's source exactly when the
    /// pattern that named the command selected it. A table of names beside a
    /// glob would be two statements of one fact, which is the shape this rule
    /// exists to refuse in documents.
    fn command_sources(&self, rule: &Rule) -> Result<BTreeMap<String, Vec<(String, String)>>> {
        let mut discovered: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
        for pattern in rule.command_sources() {
            let Some((before, after)) = pattern.split_once("{}") else {
                continue;
            };
            // The concrete glob the selection machinery is asked for, with the
            // placeholder widened to one path segment. Selection is reused
            // rather than reimplemented so a source file is found under the
            // same ignore rules, the same symlink policy and the same
            // unreadable-path accounting as every other file this scan reads.
            let mut probe = Rule::synthetic(&rule.id, Check::empty(CheckKind::Builtin));
            probe.files = Some(Files {
                glob: vec![format!("{before}*{after}")],
                ..Files::default()
            });
            let name_of = command_name_pattern(before, after);
            for relative in self.select(&probe)? {
                let Some(name) = name_of
                    .as_ref()
                    .and_then(|matcher| matcher.captures(&relative))
                    .and_then(|captured| captured.get(1))
                    .map(|found| found.as_str().to_owned())
                else {
                    continue;
                };
                let text = match std::fs::read_to_string(self.root.join(&relative)) {
                    Ok(text) => text,
                    // A source that is not text declares no dispatch. An I/O
                    // failure is a file NOBODY READ, which `link_failures`
                    // separates here for the same reason.
                    Err(error) if error.kind() == std::io::ErrorKind::InvalidData => continue,
                    Err(error) => return Err(Fatal::at(&self.root.join(&relative), error)),
                };
                discovered.entry(name).or_default().push((relative, text));
            }
        }
        Ok(discovered)
    }

    /// Fail every document that tells a reader to run a verb no command offers.
    ///
    /// The agreement gate is the half that decides whether this is usable at
    /// all. A command judges documents only when its dispatch and its own usage
    /// block tell the same story; when they disagree the parse is not trusted
    /// and the command is counted, named and skipped. That count is printed
    /// every run, because a check that read four commands out of a hundred and
    /// says nothing about the other ninety-six reads exactly like one that read
    /// them all.
    fn command_failures(&self, rule: &Rule) -> Result<Vec<Failure>> {
        let discovered = self.command_sources(rule)?;
        let mut trusted: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut skipped: Vec<String> = Vec::new();

        for (name, sources) in &discovered {
            let dispatched = crate::commands::dispatched(sources);
            if dispatched.is_empty() {
                skipped.push(format!("{name} (no dispatch this parse can read)"));
                continue;
            }
            let disagreed: Vec<String> = crate::commands::documented(name, sources)
                .into_iter()
                .filter(|verb| !dispatched.contains(verb))
                .collect();
            if !disagreed.is_empty() {
                skipped.push(format!(
                    "{name} (its own usage names {}, which its parsed dispatch does not offer)",
                    disagreed.join(", ")
                ));
                continue;
            }
            trusted.insert(name.clone(), dispatched);
        }

        // Said on every run, clean or not. The denominator is the difference
        // between "every documented verb resolves" and "every documented verb
        // this could read resolves", and only one of those is what happened.
        println!(
            "{}: {} command(s) discovered, {} judged, {} skipped",
            rule.id,
            discovered.len(),
            trusted.len(),
            skipped.len()
        );
        for note in &skipped {
            println!("{}: not judged: {note}", rule.id);
        }

        if trusted.is_empty() {
            // Not a pass. Zero commands judged is the state a broken pattern, a
            // renamed directory and a grammar that stopped matching all arrive
            // in, and it is indistinguishable from a clean tree without this.
            return Ok(vec![Failure::new(
                &rule.id,
                rule.message(),
                format!(
                    "discovered {} command(s) and could read the verbs of none, so no \
                     document was judged. Either `command_sources` no longer describes \
                     this tree, or every dispatch it found is in a form this parse cannot \
                     read -- both of which report a clean tree while checking nothing.",
                    discovered.len()
                ),
            )]);
        }

        let files = self.select(rule)?;
        let mut hits: Vec<Hit> = Vec::new();
        let mut detailed: Vec<String> = Vec::new();
        for relative in &files {
            let text = match std::fs::read_to_string(self.root.join(relative)) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => continue,
                Err(error) => return Err(Fatal::at(&self.root.join(relative), error)),
            };
            for mention in crate::commands::mentions(&text, &trusted) {
                let Some(offered) = trusted.get(&mention.command) else {
                    continue;
                };
                if offered.contains(&mention.verb) {
                    continue;
                }
                let listed: Vec<&str> = offered.iter().map(String::as_str).collect();
                hits.push(Hit {
                    path: relative.clone(),
                    line: Some(mention.line),
                    text: format!("{} {}", mention.command, mention.verb),
                });
                detailed.push(format!(
                    "{relative}:{}: tells a reader to run `{} {}`, and {} dispatches on: {}",
                    mention.line,
                    mention.command,
                    mention.verb,
                    mention.command,
                    listed.join(", ")
                ));
            }
        }

        if hits.is_empty() {
            return Ok(Vec::new());
        }
        let body = if self.redact() {
            crate::report::redacted_body(&hits)
        } else {
            detailed.join("\n")
        };
        Ok(vec![Failure::new(&rule.id, rule.message(), body)])
    }

    // -- anchors ------------------------------------------------------------

    /// Fail every anchor whose source is gone, whose key is gone, or whose
    /// stated value has moved.
    ///
    /// Three findings, one defect in three costumes: the document is wrong in
    /// exactly the same way in each, and reads exactly as confident.
    fn anchor_failures(&self, rule: &Rule) -> Result<Vec<Failure>> {
        let files = self.select(rule)?;
        let mut hits: Vec<Hit> = Vec::new();
        let mut detailed: Vec<String> = Vec::new();
        let mut checked = 0usize;

        for relative in &files {
            let text = match std::fs::read_to_string(self.root.join(relative)) {
                Ok(text) => text,
                // Bytes that are not text declare no anchor, and a sweep that
                // died on the first PNG would report a clean tree by never
                // reaching the rest. An I/O failure is a file NOBODY READ,
                // which is the different fact `link_failures` separates here
                // for the same reason.
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => continue,
                Err(error) => return Err(Fatal::at(&self.root.join(relative), error)),
            };
            for anchor in crate::anchors::parse(&text) {
                checked += 1;
                let Some(finding) = crate::anchors::resolve(&anchor, self.root) else {
                    continue;
                };
                hits.push(Hit {
                    path: relative.clone(),
                    line: Some(anchor.line),
                    text: anchor.source.clone(),
                });
                detailed.push(format!("{relative}:{}: {finding}", anchor.line));
            }
        }

        if rule.require_any_anchor() && checked == 0 {
            // Off by default, and the asymmetry with `require_any_link` is
            // stated where the field is declared: zero anchors is the goal
            // state here, not a narrowed selection. This fires only for a
            // repository that has decided otherwise.
            return Ok(vec![Failure::new(
                &rule.id,
                rule.message(),
                format!(
                    "selected {} file(s) and found no anchor; this repository declared its \
                     anchors load-bearing with `require_any_anchor`",
                    files.len()
                ),
            )]);
        }

        if hits.is_empty() {
            return Ok(Vec::new());
        }
        let body = if self.redact() {
            crate::report::redacted_body(&hits)
        } else {
            detailed.join("\n")
        };
        Ok(vec![Failure::new(&rule.id, rule.message(), body)])
    }

    // -- encoding -----------------------------------------------------------

    /// Fail every selected file that does not decode cleanly under the
    /// declared charset.
    ///
    /// Encoding is a property of the BYTES; `allowed_scripts` is a property of
    /// the decoded text. Keeping them separate is what lets a policy say
    /// "UTF-8 file containing Japanese" and "Shift-JIS file containing
    /// Japanese" as the two different declarations they are.
    fn encoding_failures(&self, rule: &Rule) -> Result<Vec<Failure>> {
        let label = rule.encoding().unwrap_or_default();
        // Validated at load; refused again here rather than defaulted, so a
        // synthetic rule that skipped validation cannot decode as the wrong
        // thing.
        let Some(encoding) = encoding_rs::Encoding::for_label(label.as_bytes()) else {
            return Err(Fatal::new(format!(
                "rule {:?}: {label:?} names no encoding the WHATWG registry carries",
                rule.id
            )));
        };
        let mut violations: Vec<String> = Vec::new();
        for relative in self.select(rule)? {
            // An unreadable file is not a well-encoded file; same stance as
            // the size check.
            let bytes = std::fs::read(self.root.join(&relative))
                .map_err(|error| Fatal::at(&self.root.join(&relative), error))?;
            let (_, _, had_errors) = encoding.decode(&bytes);
            if had_errors {
                violations.push(format!(
                    "{relative}: does not decode as {}",
                    encoding.name()
                ));
            }
        }
        if violations.is_empty() {
            return Ok(Vec::new());
        }
        violations.sort();
        Ok(vec![Failure::new(
            &rule.id,
            rule.message(),
            violations.join("\n"),
        )])
    }

    // -- allowed scripts ----------------------------------------------------

    fn script_failures(&self) -> Result<Vec<Failure>> {
        let global_names: Vec<String> = self.policy.allowed_scripts.clone();
        let scoped: Vec<&Rule> = self.policy.of_check(CheckKind::AllowedScripts).collect();
        if global_names.is_empty() && scoped.is_empty() {
            return Ok(Vec::new());
        }

        let global = resolve_scripts(&global_names, "`allowed_scripts`")?;

        let mut resolved: Vec<Scoped> = Vec::new();
        for rule in &scoped {
            let scripts = resolve_scripts(rule.allowed_scripts(), &format!("rule {:?}", rule.id))?;
            resolved.push(Scoped {
                id: rule.id.clone(),
                files: self.select(rule)?.into_iter().collect(),
                names: rule.allowed_scripts().to_vec(),
                scripts,
                exclusive: rule.exclusive(),
            });
        }
        let any_exclusive = resolved.iter().any(|scope| scope.exclusive);

        // Every file this check speaks about, scanned once. A global
        // declaration constrains every file; so does an `exclusive` rule,
        // whose scripts are refused precisely in the files it does NOT select.
        // A forward-only scoped configuration constrains only what it selects.
        let mut every: BTreeSet<String> = BTreeSet::new();
        if !global_names.is_empty() || any_exclusive {
            let all = Rule::synthetic("<allowed_scripts>", Check::empty(CheckKind::AllowedScripts));
            every.extend(self.select(&all)?);
        }
        for scope in &resolved {
            every.extend(scope.files.iter().cloned());
        }

        // Findings grouped by the declaration they violate, so each failure
        // names the rule to edit.
        let mut findings: BTreeMap<(String, &'static str), Vec<String>> = BTreeMap::new();
        for relative in &every {
            let selecting: Vec<&Scoped> = resolved
                .iter()
                .filter(|scope| scope.files.contains(relative))
                .collect();
            let excluding: Vec<&Scoped> = resolved
                .iter()
                .filter(|scope| scope.exclusive && !scope.files.contains(relative))
                .collect();
            if selecting.is_empty() && global_names.is_empty() && excluding.is_empty() {
                continue;
            }
            // The same reader every other check uses. A non-UTF-8 file is
            // never silently skipped: bytes an `encoding` rule declares are
            // decoded under that declaration and their scripts read, and bytes
            // nothing declares are a file this check could not look at, which
            // `text_of` records as unreadable -- exit 2, beside the findings
            // rather than instead of them. It used to end the run here, which
            // meant one undeclared file hid every script finding behind it.
            let Some(text) = self.text_of(relative)? else {
                continue;
            };

            let declared: String = if selecting.is_empty() {
                global_names.join(", ")
            } else {
                let mut names: Vec<String> = Vec::new();
                for scope in &selecting {
                    for name in &scope.names {
                        if !names.contains(name) {
                            names.push(name.clone());
                        }
                    }
                }
                names.join(", ")
            };

            for (line_index, line) in text.split('\n').enumerate() {
                for (column, character) in line.chars().enumerate() {
                    if !character.is_alphabetic() {
                        continue;
                    }
                    let script = character.script();
                    if matches!(script, Script::Common | Script::Inherited | Script::Unknown) {
                        continue;
                    }
                    // A selecting rule's list is the whole truth for its
                    // files: what it admits is admitted, and the top-level
                    // declaration does not reach in.
                    if selecting
                        .iter()
                        .any(|scope| scope.scripts.contains(&script))
                    {
                        continue;
                    }
                    let detail = if self.redact() {
                        String::from("[REDACTED_MATCH]")
                    } else {
                        let name = unicode_names2::name(character)
                            .map_or_else(|| String::from("UNKNOWN"), |name| name.to_string());
                        format!("U+{:04X} {name}", character as u32)
                    };
                    let position =
                        format!("{relative}:{}:{}: {detail}", line_index + 1, column + 1);

                    if let Some(first) = selecting.first() {
                        findings
                            .entry((first.id.clone(), "scoped"))
                            .or_default()
                            .push(format!(
                                "{position} -- script {} is not in the allowed_scripts \
                                 declared for this path ({declared})",
                                script.full_name()
                            ));
                        continue;
                    }

                    // A script admitted where it stands is admitted:
                    // `exclusive` elsewhere does not revoke an explicit
                    // top-level grant. What it adds is refusals where NOTHING
                    // admits the script -- which is how "Latin, Hiragana,
                    // Katakana, Han here, exclusively" coexists with a
                    // top-level "Latin": Latin passes everywhere on the grant,
                    // and the kana leak outside these paths fails on the
                    // exclusivity rather than passing on the absence of a
                    // constraint.
                    if global.contains(&script) {
                        continue;
                    }
                    if let Some(owner) = excluding
                        .iter()
                        .find(|scope| scope.scripts.contains(&script))
                    {
                        findings
                            .entry((owner.id.clone(), "exclusive"))
                            .or_default()
                            .push(format!(
                                "{position} -- script {} is exclusive to the files this rule \
                                 selects, and this file is not one of them",
                                script.full_name()
                            ));
                    } else if !global_names.is_empty() {
                        findings
                            .entry((String::from("allowed_scripts"), "global"))
                            .or_default()
                            .push(format!(
                                "{position} -- script {} is not in the top-level \
                                 allowed_scripts ({declared})",
                                script.full_name()
                            ));
                    }
                }
            }
        }

        Ok(findings
            .into_iter()
            .map(|((id, direction), lines)| {
                let message = match direction {
                    "exclusive" => {
                        "A script this rule declares exclusive to its paths appears outside \
                         them. Move the text under the rule's paths, or drop `exclusive` if \
                         the script belongs elsewhere too."
                    }
                    "scoped" => {
                        "A visible letter uses a Unicode script outside those declared for \
                         its path. The rule's allowed_scripts list is the whole truth for \
                         the files it selects; add the script there when the text is \
                         intentional."
                    }
                    _ => {
                        "A visible letter uses a Unicode script outside the top-level \
                         allowed_scripts. Add the script there, or declare a scoped rule \
                         for the paths that carry it."
                    }
                };
                Failure::new(id, message, lines.join("\n"))
            })
            .collect())
    }

    // -- shared helpers -----------------------------------------------------

    /// Drop hits that fall inside a `#[cfg(test)]` region.
    fn drop_cfg_test_hits(&self, hits: Vec<Hit>) -> Vec<Hit> {
        let mut cache: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
        hits.into_iter()
            .filter(|hit| {
                if !Path::new(&hit.path)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
                {
                    return true;
                }
                let Some(line) = hit.line else { return true };
                let lines = cache
                    .entry(hit.path.clone())
                    .or_insert_with(|| cfg_test_lines(&self.root.join(&hit.path)));
                !lines.contains(&line)
            })
            .collect()
    }

    /// A path-only baseline: one repository-relative path per line, optionally
    /// signed.
    ///
    /// Paths rather than counts, deliberately. A count baseline is stricter, but
    /// a reformat moves a match count without anything real changing, and a rule
    /// whose baseline churns on unrelated edits is one people stop reading. A
    /// listed path may get worse internally; what it cannot do is let a NEW path
    /// start.
    ///
    /// A line may carry a signature after the path:
    ///
    /// ```text
    /// src/cli/top.py | alice | a two-column key/value list; a table reads worse
    /// ```
    ///
    /// Optional here and required where the policy says so, because the two
    /// things a baseline holds are not the same. A file listing eight modules
    /// that have not been migrated yet needs one reason at the top and none per
    /// line -- every entry is the same debt and the file's header says so. A
    /// file listing the places a rule is WRONG needs one reason per line, and
    /// nothing in the format could say it: the whole line was the path, so a
    /// judgement about why this instance is the exception had nowhere to go
    /// except a comment nothing associates with an entry.
    ///
    /// The separator is `|` rather than whitespace or `#`. Whitespace is the
    /// size baseline's separator and a path may hold it; `#` at line start
    /// already means a comment and overloading it would change what an existing
    /// file means.
    fn load_path_baseline(&self, relative: Option<&str>) -> Result<Baseline> {
        let Some(relative) = relative else {
            return Ok(Baseline::default());
        };
        let text = crate::error::read_to_string(&self.root.join(relative))?;
        let mut baseline = Baseline {
            file: relative.to_owned(),
            ..Baseline::default()
        };
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split('|').map(str::trim);
            let raw = parts.next().unwrap_or_default();
            if raw.is_empty() {
                // A signature with nothing to sign. Same class as a malformed
                // size entry: it reads as an entry and excuses no path.
                return Err(Fatal::at(
                    &self.root.join(relative),
                    format!(
                        "line {}: no path before the signature\n  {line}\n\nA baseline entry \
                         is `<path>` or `<path> | <owner> | <reason>`.",
                        index + 1
                    ),
                ));
            }
            let path = normalize_rel(raw).to_owned();
            let owner = parts.next().unwrap_or_default();
            let reason = parts.next().unwrap_or_default();
            if owner.is_empty() || reason.is_empty() {
                baseline.unsigned.push(path.clone());
            }
            baseline.paths.insert(path);
        }
        Ok(baseline)
    }

    fn load_size_baseline(
        &self,
        relative: Option<&str>,
        measure: Measure,
    ) -> Result<BTreeMap<String, u64>> {
        let Some(relative) = relative else {
            return Ok(BTreeMap::new());
        };
        let text = crate::error::read_to_string(&self.root.join(relative))?;
        let mut baseline = BTreeMap::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Refused rather than skipped, and this is the sibling of the
            // refusal a few lines down in `size_failures`: "an unreadable file
            // is not a short file". An unreadable ENTRY is not an absent one
            // either, and skipping it is worse than skipping a file, because
            // the failure is silent in the direction that matters.
            //
            // A size baseline is a ratchet: a file held at 8 lines under a limit
            // of 10 may not grow to 9. Drop the entry and the file is checked
            // against the limit instead, so it may now grow to 10 -- the ratchet
            // is gone and nothing reports it. The staleness check cannot see it
            // either: a dropped entry is not in the map, so it is not "listed",
            // and the mechanism that exists to notice a baseline which stopped
            // describing the tree is blind to one that never loaded.
            //
            // Reproduced before this was written: `src/big.py 8` holds the file
            // at 8 and growing it fails; `src/big.py 8x` passes the same tree.
            let unit = measure.unit();
            let singular = measure.singular();
            let malformed = |what: &str| {
                Fatal::at(
                    &self.root.join(relative),
                    format!(
                        "line {}: {what}\n  {line}\n\nA size baseline entry is \
                         `<path> <{unit}>`. This line was skipped silently until now, which \
                         removes the ratchet it was written to hold and reports nothing.",
                        index + 1
                    ),
                )
            };
            let Some((path, count)) = line.rsplit_once(' ') else {
                return Err(malformed(&format!("no {singular} count after the path")));
            };
            let Ok(count) = count.trim().parse::<u64>() else {
                return Err(malformed(&format!("the {singular} count is not a number")));
            };
            if path.trim().is_empty() {
                return Err(malformed(&format!("no path before the {singular} count")));
            }
            baseline.insert(normalize_rel(path).to_owned(), count);
        }
        Ok(baseline)
    }
}

/// One rule's baseline: the paths it excuses, and which of them are unsigned.
///
/// `file` is carried so a finding can name the file to edit. A report that says
/// "three entries are unsigned" and not where they are is a report whose reader
/// has to go looking for the thing it just read.
#[derive(Debug, Default)]
struct Baseline {
    file: String,
    paths: BTreeSet<String>,
    unsigned: Vec<String>,
}

impl Baseline {
    fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    fn contains(&self, path: &str) -> bool {
        self.paths.contains(path)
    }

    /// The entries carrying no owner and reason, when the policy asks for them.
    ///
    /// A finding rather than a load refusal, because a baseline is read here
    /// and not at load: the path comes from the rule and the file from the
    /// tree, and neither exists as text the loader has seen. It sits at the
    /// same tier as a stale entry for the same reason -- both are a baseline
    /// that has stopped describing a decision somebody made.
    fn unsigned_failure(&self, rule: &Rule, required: bool) -> Vec<Failure> {
        if !required || self.unsigned.is_empty() {
            return Vec::new();
        }
        let body = self
            .unsigned
            .iter()
            .map(|path| format!("{path}: no owner and reason"))
            .collect::<Vec<String>>()
            .join("\n");
        vec![Failure::new(
            format!("{} (unsigned baseline)", rule.id),
            format!(
                "This policy requires every baseline entry to say who excused it and why, and \
                 these say neither. Write them as `path | owner | reason` in {}.\n\nA path on \
                 its own records that a rule was switched off there and nothing about the \
                 judgement behind it -- which is the difference between debt somebody is \
                 carrying and a finding somebody silenced.",
                self.file
            ),
            body,
        )]
    }
}

fn stale_baseline_failure(
    rule: &Rule,
    baseline: &BTreeSet<String>,
    seen: &BTreeSet<String>,
    message: &str,
) -> Vec<Failure> {
    let stale: Vec<&String> = baseline.difference(seen).collect();
    if stale.is_empty() {
        return Vec::new();
    }
    let suffix = if message == STALE_REQUIRE_BASELINE {
        "satisfied or gone (drop from baseline)"
    } else {
        "no longer matches (drop from baseline)"
    };
    let body = stale
        .iter()
        .map(|path| format!("{path}: {suffix}"))
        .collect::<Vec<String>>()
        .join("\n");
    vec![Failure::new(
        format!("{} (stale baseline)", rule.id),
        message,
        body,
    )]
}

/// The finding for a rule whose selection came in under `files.min_selected`.
///
/// `None` where no floor was declared -- an unwritten floor reads as zero, and
/// a written zero is refused at load, so one comparison answers both.
///
/// The body names the count, the floor and the keys that produced the count,
/// because those three are what the reader edits. A report saying only that the
/// floor was missed sends them to the rule to find out what it selects, which is
/// the question they just asked.
fn below_floor_failure(rule: &Rule, selected: usize) -> Option<Failure> {
    let floor = rule.min_selected();
    if floor == 0 || u64::try_from(selected).unwrap_or(u64::MAX) >= floor {
        return None;
    }
    let files = rule.files();
    let mut keys = vec![match rule.include() {
        [] => String::from("include = [\".\"] (the default)"),
        include => format!("include = {include:?}"),
    }];
    if !files.glob.is_empty() {
        keys.push(format!("glob = {:?}", files.glob));
    }
    if !files.exclude.is_empty() {
        keys.push(format!("exclude = {:?}", files.exclude));
    }
    Some(Failure::new(
        format!("{} (selection floor)", rule.id),
        BELOW_SELECTION_FLOOR,
        format!(
            "selected {selected} file(s), and `files.min_selected = {floor}` requires at least \
             {floor}.\nThe keys that selected them: {}",
            keys.join(", ")
        ),
    ))
}

/// 1-based line numbers inside any `#[cfg(test)]` item.
fn cfg_test_lines(path: &Path) -> BTreeSet<u64> {
    static CFG_TEST: OnceLock<Regex> = OnceLock::new();
    let cfg_test = CFG_TEST.get_or_init(|| engine::literal_pattern(r"^#\[cfg\([^)]*\btest\b"));

    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeSet::new();
    };
    let lines: Vec<&str> = text.lines().collect();
    let mut test_lines = BTreeSet::new();
    let count = lines.len();
    let mut index = 0;
    while let Some(line_text) = lines.get(index) {
        if !cfg_test.is_match(line_text.trim_start()) {
            index += 1;
            continue;
        }
        let mut depth: i64 = 0;
        let mut opened = false;
        let mut end = index;
        while let Some(code_line) = lines.get(end) {
            let code = code_line.split("//").next().unwrap_or("");
            let opens = i64::try_from(code.matches('{').count()).unwrap_or(i64::MAX);
            let closes = i64::try_from(code.matches('}').count()).unwrap_or(i64::MAX);
            depth += opens - closes;
            if code.contains('{') {
                opened = true;
            }
            if opened && depth <= 0 {
                break;
            }
            end += 1;
        }
        for line in index..=end.min(count.saturating_sub(1)) {
            test_lines.insert(u64::try_from(line).unwrap_or(u64::MAX).saturating_add(1));
        }
        index = end + 1;
    }
    test_lines
}

/// `(line_number, target)` for every resolvable link in a Markdown document.
///
/// Skips fenced code blocks, external schemes, and pure fragments. A link inside
/// a fence is an illustration rather than a reference, and resolving one would
/// fail on every README that documents a link.
fn link_targets(text: &str) -> Vec<(u64, String)> {
    static INLINE: OnceLock<Regex> = OnceLock::new();
    static REFERENCE: OnceLock<Regex> = OnceLock::new();
    static FENCE: OnceLock<Regex> = OnceLock::new();
    static SCHEME: OnceLock<Regex> = OnceLock::new();

    let inline = INLINE.get_or_init(|| {
        engine::literal_pattern(r"!?\[[^\]]*\]\(\s*(?:<(?P<angled>[^>]*)>|(?P<bare>[^()\s]+))")
    });
    let reference = REFERENCE.get_or_init(|| {
        engine::literal_pattern(r"^\s{0,3}\[[^\]]+\]:\s*(?:<(?P<angled>[^>]*)>|(?P<bare>\S+))")
    });
    let fence_re = FENCE.get_or_init(|| engine::literal_pattern(r"^\s{0,3}(?P<fence>`{3,}|~{3,})"));
    // A target with a scheme is out of scope. Resolving it would need the
    // network, which a commit-time check must not touch, and a check that
    // silently skips what it claims to cover is worse than one that says where
    // its boundary is.
    let scheme = SCHEME.get_or_init(|| engine::literal_pattern(r"^[A-Za-z][A-Za-z0-9+.-]*:"));

    let mut found = Vec::new();
    let mut fence: Option<String> = None;
    for (index, line) in text.lines().enumerate() {
        let line_number = index as u64 + 1;
        if let Some(opener) = fence_re.captures(line) {
            let marker = opener
                .name("fence")
                .map(|m| m.as_str().to_owned())
                .unwrap_or_default();
            match &fence {
                None => {
                    fence = Some(marker);
                }
                Some(open) => {
                    if marker.starts_with(&open[0..1]) && marker.len() >= open.len() {
                        fence = None;
                    }
                }
            }
            continue;
        }
        if fence.is_some() {
            continue;
        }

        let mut targets: Vec<String> = Vec::new();
        if let Some(captures) = reference.captures(line) {
            targets.push(capture_target(&captures));
        }
        for captures in inline.captures_iter(line) {
            targets.push(capture_target(&captures));
        }
        for target in targets {
            let target = target.trim().to_owned();
            // A pure fragment points inside this same document; an empty target
            // is not a reference to anything.
            if target.is_empty() || target.starts_with('#') || scheme.is_match(&target) {
                continue;
            }
            found.push((line_number, target));
        }
    }
    found
}

fn capture_target(captures: &regex::Captures<'_>) -> String {
    captures
        .name("angled")
        .or_else(|| captures.name("bare"))
        .map(|m| m.as_str().to_owned())
        .unwrap_or_default()
}

/// Resolve a link target to a filesystem path.
///
/// Relative to the containing file's directory, which is how every Markdown
/// renderer reads it. A leading `/` is repository-root-relative, which is how
/// the common hosting services render it -- not filesystem-absolute, and
/// treating it as absolute would send the check outside the repository.
fn resolve_link(root: &Path, target: &str, containing: &str) -> PathBuf {
    let cleaned = target
        .split('#')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("");
    let cleaned = percent_decode(cleaned);
    if let Some(rooted) = cleaned.strip_prefix('/') {
        return root.join(rooted);
    }
    match root.join(containing).parent() {
        Some(parent) => parent.join(cleaned),
        None => root.join(cleaned),
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let high = bytes
                .get(index + 1)
                .and_then(|digit| char::from(*digit).to_digit(16));
            let low = bytes
                .get(index + 2)
                .and_then(|digit| char::from(*digit).to_digit(16));
            if let (Some(high), Some(low)) = (high, low) {
                // Both digits are below 16, so the byte cannot overflow; the
                // fallback keeps the escape verbatim rather than inventing one.
                out.push(u8::try_from(high * 16 + low).unwrap_or(byte));
                index += 3;
                continue;
            }
        }
        out.push(byte);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Collapse `..` without touching the filesystem, so a target that does not
/// exist can still be judged for whether it escapes the repository.
fn lexically_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Resolve UTS #24 script names, spelled as regex engines spell them:
/// `"Hiragana"` names exactly what `\p{Script=Hiragana}` matches. An engineer
/// who knows regex already knows the whole namespace, which is why no table of
/// language codes stands in front of it -- a hand-enumerated subset of a
/// standard namespace is the failure `parameterize-do-not-enumerate` names.
fn resolve_scripts(names: &[String], context: &str) -> Result<Vec<Script>> {
    let mut scripts: Vec<Script> = Vec::new();
    for name in names {
        let trimmed = name.trim();
        // Punctuation, digits and combining marks are never the subject of
        // this check, so admitting them is not a thing a declaration can do --
        // accepting the name would be configuration read by nothing.
        if matches!(trimmed, "Common" | "Inherited" | "Unknown") {
            return Err(Fatal::new(format!(
                "{context}: {trimmed:?} is never the subject of this check -- punctuation, \
                 digits and combining marks are always admitted -- so declaring it would be \
                 read by nothing"
            )));
        }
        let Some(script) = Script::from_full_name(trimmed) else {
            let suggestion = Script::from_full_name(&standard_spelling(trimmed))
                .map_or_else(String::new, |meant| {
                    format!("; the standard spelling is {:?}", meant.full_name())
                });
            return Err(Fatal::new(format!(
                "{context} names unknown script {trimmed:?}. Values are Unicode script names \
                 (UTS #24), spelled as `\\p{{Script=Latin}}` spells them{suggestion}"
            )));
        };
        if !scripts.contains(&script) {
            scripts.push(script);
        }
    }
    Ok(scripts)
}

/// The UTS #24 spelling of a name somebody almost wrote: segments split on
/// space, hyphen or underscore, each capitalized, joined with underscores --
/// so `"latin"`, `"old italic"` and `"OLD-ITALIC"` all propose the name the
/// standard uses.
fn standard_spelling(name: &str) -> String {
    name.split(['_', '-', ' '])
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            let mut characters = segment.chars();
            characters.next().map_or_else(String::new, |first| {
                let mut spelled: String = first.to_uppercase().collect();
                spelled.push_str(&characters.as_str().to_lowercase());
                spelled
            })
        })
        .collect::<Vec<String>>()
        .join("_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_inside_a_fence_is_an_illustration() {
        let text = "```\n[a](missing.md)\n```\n[b](real.md)\n";
        let targets = link_targets(text);
        assert_eq!(targets, vec![(4, "real.md".to_owned())]);
    }

    #[test]
    fn a_scheme_and_a_bare_fragment_are_out_of_scope() {
        let text = "[a](https://example.test/x) [b](#section) [c](d.md)\n";
        let targets = link_targets(text);
        assert_eq!(targets, vec![(1, "d.md".to_owned())]);
    }

    #[test]
    fn an_angle_bracketed_target_keeps_its_space() {
        let targets = link_targets("[a](<my file.md>)\n");
        assert_eq!(targets, vec![(1, "my file.md".to_owned())]);
    }

    #[test]
    fn a_reference_definition_is_a_link() {
        let targets = link_targets("[id]: docs/page.md \"Title\"\n");
        assert_eq!(targets, vec![(1, "docs/page.md".to_owned())]);
    }

    #[test]
    fn a_percent_escape_resolves_to_the_real_name() {
        let resolved = resolve_link(Path::new("/repo"), "my%20file.md", "README.md");
        assert_eq!(resolved, Path::new("/repo/my file.md"));
    }

    #[test]
    fn a_rooted_target_is_repository_relative_and_not_filesystem_absolute() {
        let resolved = resolve_link(Path::new("/repo"), "/docs/a.md", "sub/README.md");
        assert_eq!(resolved, Path::new("/repo/docs/a.md"));
    }

    #[test]
    fn a_script_name_is_the_regex_spelling_and_nothing_else() {
        let scripts = resolve_scripts(&["Hiragana".to_owned()], "test").unwrap();
        assert_eq!(scripts, vec![Script::Hiragana]);
    }

    #[test]
    fn a_miscased_script_name_is_refused_with_the_standard_spelling() {
        let error = resolve_scripts(&["latin".to_owned()], "test").unwrap_err();
        assert!(error.to_string().contains("\"Latin\""), "{error}");
        let spaced = resolve_scripts(&["old italic".to_owned()], "test").unwrap_err();
        assert!(spaced.to_string().contains("Old_Italic"), "{spaced}");
    }

    #[test]
    fn a_name_that_is_never_the_subject_is_refused() {
        let error = resolve_scripts(&["Common".to_owned()], "test").unwrap_err();
        assert!(error.to_string().contains("never the subject"), "{error}");
    }

    #[test]
    fn an_unknown_script_names_the_namespace() {
        let error = resolve_scripts(&["Klingon".to_owned()], "test").unwrap_err();
        assert!(error.to_string().contains("UTS #24"), "{error}");
    }
}
