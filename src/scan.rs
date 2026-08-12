//! The seven rule kinds.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use unicode_script::{Script, UnicodeScript};

use crate::config::{Check, Policy, Rule};
use crate::engine::{self, Hit, Query};
use crate::error::{Fatal, Result};
use crate::report::{body_for, Failure};
use crate::selection::{normalize_rel, not_text_paths, Selection};

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
        for check in Check::ALL {
            // A built-in with `[rule.files]` reads the tree; one without reads
            // a message or a push, and belongs to `guard`. The table decides.
            if check == Check::Builtin {
                for rule in self.policy.of_check(check) {
                    if !rule.reads_files() {
                        continue;
                    }
                    failures.extend(match rule.builtin().unwrap_or_default() {
                        "links-resolve" => self.link_failures(rule)?,
                        // Every other built-in reads something that is not the
                        // tree. Silently passing over it here would report a
                        // check that did not happen as one that did.
                        other => {
                            return Err(Fatal::new(format!(
                                "rule {:?}: built-in {other:?} does not read files, so \
                                 its `files.*` keys would be read by nothing",
                                rule.id
                            )))
                        }
                    });
                }
                continue;
            }
            if !check.requires_files() {
                continue;
            }
            if check == Check::AllowedScripts {
                // Script rules interact -- a scoped list replaces the global
                // one for its files, and an exclusive rule speaks about files
                // it does not select -- so they are evaluated once as a
                // policy rather than independently.
                failures.extend(self.script_failures()?);
                continue;
            }
            for rule in self.policy.of_check(check) {
                if !rule.reads_files() {
                    continue;
                }
                failures.extend(match check {
                    Check::Regexp => self.pattern_failures(rule)?,
                    Check::ForbiddenLiterals => self.literal_failures(rule)?,
                    Check::MaxLines => self.size_failures(rule)?,
                    Check::PathRegexp => self.path_failures(rule)?,
                    Check::RequireRegexp => self.require_failures(rule)?,
                    Check::Encoding => self.encoding_failures(rule)?,
                    Check::AllowedScripts | Check::Builtin | Check::Exec => {
                        unreachable!("filtered above")
                    }
                });
            }
        }
        Ok(failures)
    }

    fn select(&self, rule: &Rule) -> Result<Vec<String>> {
        let selection = Selection::build(self.root, rule, &self.not_text)?;
        // Gathered here, at the one place every rule's selection passes
        // through, so no future check kind can acquire its own way of dropping
        // a path it could not open.
        self.unreadable
            .borrow_mut()
            .extend(selection.unreadable().iter().cloned());
        Ok(selection.files())
    }

    const fn redact(&self) -> bool {
        self.policy.redact_matches
    }

    // -- pattern ------------------------------------------------------------

    fn pattern_failures(&self, rule: &Rule) -> Result<Vec<Failure>> {
        let files = self.select(rule)?;
        let pattern = rule.expression().unwrap_or_default();
        let mut hits = engine::search_files(
            self.root,
            &files,
            &Query::from_files(pattern, rule.files()),
            &rule.id,
        )?;
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
            failures.extend(stale_baseline_failure(
                rule,
                &baseline,
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
        let source = if rule.forbidden_literals_from.is_some() {
            "command"
        } else {
            rule.forbidden_literals.as_deref().unwrap_or_default()
        };
        let needles = crate::sources::resolve(
            source,
            rule.forbidden_literals_from.as_deref(),
            self.root,
            rule.files().word,
            &rule.id,
            rule.ignore_literals.as_deref().unwrap_or(&[]),
        )?;

        let mut failures = Vec::new();
        for needle in needles {
            let label = format!("{} ({})", rule.id, needle.label);
            let mut hits = engine::search_files(
                self.root,
                &files,
                &Query::literal(&needle.value, needle.word),
                &label,
            )?;
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

    fn size_failures(&self, rule: &Rule) -> Result<Vec<Failure>> {
        let max_lines = rule.max_lines.unwrap_or_default();
        let baseline = self.load_size_baseline(rule.files().baseline.as_deref())?;
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
            // Newline count, matching `wc -l`.
            #[expect(
                clippy::naive_bytecount,
                reason = "a SIMD line-counting dependency is not worth its supply-chain surface for one pass per file"
            )]
            let count = bytes.iter().filter(|byte| **byte == b'\n').count() as u64;
            match baseline.get(normalize_rel(&relative)) {
                None if count > max_lines => {
                    violations.push(format!("{relative}: {count} lines (limit {max_lines})"));
                }
                Some(allowed) if count > *allowed => {
                    violations.push(format!(
                        "{relative}: {count} lines (baseline {allowed}; must not grow)"
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
            failures.extend(stale_baseline_failure(
                rule,
                &baseline,
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
            if !engine::file_matches(self.root, file, &query, &rule.id)? {
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
            failures.extend(stale_baseline_failure(
                rule,
                &baseline,
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

    // -- encoding -----------------------------------------------------------

    /// Fail every selected file that does not decode cleanly under the
    /// declared charset.
    ///
    /// Encoding is a property of the BYTES; `allowed_scripts` is a property of
    /// the decoded text. Keeping them separate is what lets a policy say
    /// "UTF-8 file containing Japanese" and "Shift-JIS file containing
    /// Japanese" as the two different declarations they are.
    fn encoding_failures(&self, rule: &Rule) -> Result<Vec<Failure>> {
        let label = rule.encoding.as_deref().unwrap_or_default();
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
        let scoped: Vec<&Rule> = self.policy.of_check(Check::AllowedScripts).collect();
        if global_names.is_empty() && scoped.is_empty() {
            return Ok(Vec::new());
        }

        let global = resolve_scripts(&global_names, "`allowed_scripts`")?;

        let mut resolved: Vec<Scoped> = Vec::new();
        for rule in &scoped {
            let scripts = resolve_scripts(&rule.allowed_scripts, &format!("rule {:?}", rule.id))?;
            resolved.push(Scoped {
                id: rule.id.clone(),
                files: self.select(rule)?.into_iter().collect(),
                names: rule.allowed_scripts.clone(),
                scripts,
                exclusive: rule.exclusive.unwrap_or(false),
            });
        }
        let any_exclusive = resolved.iter().any(|scope| scope.exclusive);

        // The declared encodings, so a non-UTF-8 file whose bytes ARE declared
        // can still have its scripts read: the declaration says how to decode
        // it, and the two checks stay about their own layers.
        let mut declared_encodings: Vec<(BTreeSet<String>, &'static encoding_rs::Encoding)> =
            Vec::new();
        for rule in self.policy.of_check(Check::Encoding) {
            let label = rule.encoding.as_deref().unwrap_or_default();
            if let Some(encoding) = encoding_rs::Encoding::for_label(label.as_bytes()) {
                declared_encodings.push((self.select(rule)?.into_iter().collect(), encoding));
            }
        }

        // Every file this check speaks about, scanned once. A global
        // declaration constrains every file; so does an `exclusive` rule,
        // whose scripts are refused precisely in the files it does NOT select.
        // A forward-only scoped configuration constrains only what it selects.
        let mut every: BTreeSet<String> = BTreeSet::new();
        if !global_names.is_empty() || any_exclusive {
            let all = Rule::synthetic("<allowed_scripts>", Check::AllowedScripts);
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
            let bytes = std::fs::read(self.root.join(relative))
                .map_err(|error| Fatal::at(&self.root.join(relative), error))?;
            let text = match String::from_utf8(bytes) {
                Ok(text) => text,
                // A non-UTF-8 file used to be SILENTLY SKIPPED here -- a file
                // nobody read, reported as clean, which is the
                // `explicit-unknown` failure by name. Now: bytes an `encoding`
                // rule declares are decoded under that declaration and their
                // scripts read; bytes nothing declares are a file this check
                // cannot look at, which is exit-2 territory, never a pass.
                Err(error) => {
                    let raw = error.into_bytes();
                    let covering = declared_encodings
                        .iter()
                        .find(|(files, _)| files.contains(relative));
                    let Some((_, encoding)) = covering else {
                        return Err(Fatal::new(format!(
                            "{relative}: is not UTF-8, so its scripts cannot be read and \
                             \"clean\" would mean \"unexamined\". Declare its charset with \
                             an `encoding` rule selecting it, exclude it from the script \
                             declaration, or mark it not text in .gitattributes"
                        )));
                    };
                    let (decoded, _, had_errors) = encoding.decode(&raw);
                    if had_errors {
                        // Not even its declared encoding: the encoding rule
                        // reports this file in the same run, and there is no
                        // text here for THIS check to judge.
                        continue;
                    }
                    decoded.into_owned()
                }
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

    /// A path-only baseline: one repository-relative path per line.
    ///
    /// Paths rather than counts, deliberately. A count baseline is stricter, but
    /// a reformat moves a match count without anything real changing, and a rule
    /// whose baseline churns on unrelated edits is one people stop reading. A
    /// listed path may get worse internally; what it cannot do is let a NEW path
    /// start.
    fn load_path_baseline(&self, relative: Option<&str>) -> Result<BTreeSet<String>> {
        let Some(relative) = relative else {
            return Ok(BTreeSet::new());
        };
        let text = crate::error::read_to_string(&self.root.join(relative))?;
        Ok(text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| normalize_rel(line).to_owned())
            .collect())
    }

    fn load_size_baseline(&self, relative: Option<&str>) -> Result<BTreeMap<String, u64>> {
        let Some(relative) = relative else {
            return Ok(BTreeMap::new());
        };
        let text = crate::error::read_to_string(&self.root.join(relative))?;
        let mut baseline = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((path, count)) = line.rsplit_once(' ') else {
                continue;
            };
            let Ok(count) = count.trim().parse::<u64>() else {
                continue;
            };
            baseline.insert(normalize_rel(path).to_owned(), count);
        }
        Ok(baseline)
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
