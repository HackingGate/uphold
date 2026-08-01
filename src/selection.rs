//! Which files a rule looks at.
//!
//! The old engine answered this twice. Line mode handed `--glob` flags to
//! ripgrep and let ripgrep decide; redacted mode re-implemented the same
//! question in Python with `fnmatch`, plus a documented retry that stripped a
//! leading `**/` because `fnmatch` does not model a glob matching zero leading
//! directories. The two were kept "aligned" by hand, which is the arrangement
//! where a rule quietly means something different depending on an unrelated
//! top-level flag.
//!
//! There is one implementation now, and it is ripgrep's: the `ignore` crate's
//! `Override`, which is the exact type ripgrep builds its own `--glob` handling
//! on, including the rule that the LAST matching glob wins.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use ignore::overrides::{Override, OverrideBuilder};
use ignore::WalkBuilder;

use crate::config::Rule;
use crate::error::{Fatal, Result};

/// Paths this repository declares are NOT TEXT in `.gitattributes`.
///
/// `-text` is git's own way of saying so, and a repository that tracks captured
/// artifacts has a real use for it: a page kept byte-for-byte in the encoding
/// its venue served, where the bytes are the evidence. Content rules are about
/// text somebody here wrote, so these are skipped -- and counted, because "we
/// did not check these" and "these were clean" must never look the same on the
/// way out.
pub(crate) fn not_text_paths(root: &Path) -> Vec<String> {
    let listed = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output();
    let Ok(listed) = listed else {
        // No git, or no repository. The declaration is optional, and its absence
        // means nothing is declared -- not that something failed.
        return Vec::new();
    };
    if !listed.status.success() || listed.stdout.is_empty() {
        return Vec::new();
    }

    let Ok(mut child) = Command::new("git")
        .args(["check-attr", "--stdin", "-z", "text"])
        .current_dir(root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return Vec::new();
    };
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin.write_all(&listed.stdout).ok();
    }
    let Ok(output) = child.wait_with_output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    // `check-attr -z` emits path, attribute, value as three NUL-separated fields.
    let fields: Vec<&[u8]> = output.stdout.split(|byte| *byte == 0).collect();
    let mut found = Vec::new();
    for chunk in fields.chunks(3) {
        let [path, _, value] = chunk else {
            continue;
        };
        if *value == b"unset" {
            found.push(String::from_utf8_lossy(path).into_owned());
        }
    }
    found
}

/// The files one rule searches, and the globs that chose them.
pub(crate) struct Selection {
    root: PathBuf,
    roots: Vec<PathBuf>,
    overrides: Override,
}

impl Selection {
    pub(crate) fn build(root: &Path, rule: &Rule, not_text: &[String]) -> Result<Self> {
        let mut builder = OverrideBuilder::new(root);
        for glob in &rule.files().glob {
            builder.add(glob).map_err(|error| {
                Fatal::new(format!("rule {:?}: glob {glob:?}: {error}", rule.id))
            })?;
        }
        for glob in &rule.files().exclude {
            builder.add(&format!("!{glob}")).map_err(|error| {
                Fatal::new(format!("rule {:?}: exclude {glob:?}: {error}", rule.id))
            })?;
        }
        // LAST, because the last matching glob wins: an exclusion placed first is
        // undone by any later glob the file happens to match. The old engine
        // carried the same ordering and the same comment, found by a test that
        // reported a file as skipped and searched it anyway. Everything below
        // this line is unconditional, which is why it goes here and not above.
        for path in not_text {
            builder
                .add(&format!("!{path}"))
                .map_err(|error| Fatal::new(format!("not-text path {path:?}: {error}")))?;
        }
        // The object store is not repository content. It holds every version of
        // every file, so a rule that fired on a line somebody deleted years ago
        // would report a violation with no working-tree fix.
        builder
            .add("!.git/**")
            .map_err(|error| Fatal::new(format!("{error}")))?;
        let overrides = builder
            .build()
            .map_err(|error| Fatal::new(format!("rule {:?}: {error}", rule.id)))?;

        let include = rule.include();
        let roots = if include.is_empty() {
            vec![root.to_path_buf()]
        } else {
            include
                .iter()
                .map(|spec| {
                    if spec == "." {
                        root.to_path_buf()
                    } else {
                        root.join(spec)
                    }
                })
                .collect()
        };

        // An `include` root that is not there searched nothing and said nothing.
        // `files()` skips a missing root, so a rule whose directory had since
        // been renamed selected no files and reported `policy checks passed` --
        // indistinguishable from a rule that looked everywhere and found
        // nothing.
        //
        // Reported rather than refused, and the difference is that this tool
        // cannot tell the two cases apart: a root that was renamed away leaves a
        // rule silently dead, and a root that is genuinely optional leaves a
        // rule legitimately inactive. Both are `include` naming a path that is
        // not there. Refusing would make the second one a config that will not
        // load, so the tool says what it saw and lets the author decide which
        // it is.
        //
        // The default root is the repository itself, so this can only fire on an
        // `include` somebody wrote.
        for (spec, search_root) in rule.include().iter().zip(&roots) {
            if !search_root.exists() {
                eprintln!(
                    "rule {:?}: `files.include` names {spec:?}, which does not \
                     exist -- that root selected no files. If the directory moved, \
                     this rule is not running.",
                    rule.id
                );
            }
        }

        Ok(Self {
            root: root.to_path_buf(),
            roots,
            overrides,
        })
    }

    /// Repository-relative paths, sorted, deduplicated.
    ///
    /// Sorted because a report whose order depends on directory iteration is a
    /// report that diffs against itself between runs, and deduplicated because
    /// overlapping `include` roots would otherwise search a file twice and
    /// report it twice.
    pub(crate) fn files(&self) -> Vec<String> {
        let mut found: BTreeSet<String> = BTreeSet::new();
        for search_root in &self.roots {
            if !search_root.exists() {
                continue;
            }
            let mut walker = WalkBuilder::new(search_root);
            walker
                .overrides(self.overrides.clone())
                // Dotfiles ARE repository content. ripgrep skips them by
                // default and the old engine inherited that, so the security
                // base set's `.env` rules -- whose globs are `.env`, `.env.*` --
                // could not match the files they name, while `path` and
                // `require` rules, which enumerated through `git ls-files`
                // instead, saw them. One engine has to pick, and skipping
                // `.github/workflows` and `.env` is not a policy anyone would
                // write down; it is a terminal-ergonomics default arriving
                // where it was never meant to decide anything.
                .hidden(false)
                .git_ignore(true)
                .git_global(true)
                .git_exclude(true)
                .parents(true);
            for entry in walker.build().flatten() {
                if !entry.file_type().is_some_and(|kind| kind.is_file()) {
                    continue;
                }
                if let Ok(relative) = entry.path().strip_prefix(&self.root) {
                    found.insert(relative.to_string_lossy().into_owned());
                }
            }
        }
        found.into_iter().collect()
    }
}

/// Strip the `./` the old engine's file listing could emit.
///
/// `rg --files` echoed the search roots it was given, so one file was
/// `TEST_SCENARIOS.md` under `include = ["src"]` and `./TEST_SCENARIOS.md` under
/// the default `include = ["."]`. A baseline keyed the obvious way matched
/// nothing, and the ratchet silently did not apply -- every grandfathered file
/// reported as a fresh violation, whose natural "fix" is to raise the limit and
/// switch the rule off for everyone. Nothing here emits the `./` form any more;
/// this stays because baselines written against the old engine still carry it.
pub(crate) fn normalize_rel(path: &str) -> &str {
    let mut normalized = path.trim();
    while let Some(rest) = normalized.strip_prefix("./") {
        normalized = rest;
    }
    normalized
}
