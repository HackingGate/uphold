//! Hook pins, and the two opposite questions to ask about one.
//!
//! The `rev` a repository pins is the only version of a hook it actually runs,
//! and nothing else asks whether it is the current one. What used to ask was a
//! dependency updater whose default release-cooldown filter kept the old
//! version, said so only in a job log, and raised no pull request -- so the pins
//! rotted while every surface said healthy.
//!
//! Two predicates, and neither implies the other:
//!
//! * **Behind.** The pin names a tag, and the upstream has a newer one. This is
//!   `no-stale-hook-pins`.
//! * **Forward.** The pin names a tag that was never cut. That fails at
//!   hook-init, as a clone error, before any hook runs -- which is why nothing
//!   can report it after the fact.
//!
//! A pin ahead of every tag that exists has not fallen behind, so the first
//! question answers `pass` for it. Both are asked here.
//!
//! And a THIRD state, which is neither: a pin whose remote could not be reached
//! is not up to date, it is unestablished. That exits 2, the same way
//! `audit --for-publication` exits 2 over a surface it could not read, because
//! the alternative -- what this did -- is to print the pin to stderr and exit 0
//! with the guard counted among the ones that passed.
//!
//! Both managers are read. pre-commit writes `repos:` with a `rev:`; lefthook
//! writes `remotes:` with a `ref:`, and that entry is the single version a
//! lefthook consumer pins. It was read by nothing here and there is no
//! Dependabot ecosystem for it either, so it was the one pin in the tree with
//! nobody watching it at all.
//!
//! The configuration is parsed rather than scanned. A line regex over
//! `.pre-commit-config.yaml` reads the block form and silently yields nothing
//! for a flow-style file -- an absent pin and an unreadable one looking the
//! same, which is the failure `explicit-unknown` names. The old guard scanned
//! lines because it shipped as `language: script` and could have no
//! dependencies; a binary has no such constraint.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use ignore::WalkBuilder;
use serde::Deserialize;

use crate::error::{read_to_string, Fatal, Result};
use crate::guard::{Refusal, Request};

#[derive(Debug, Deserialize)]
struct HookConfig {
    /// `Option`, not `#[serde(default)]`, and the difference is a whole
    /// finding. A file with no `repos:` in it deserialized as a config with no
    /// repositories in it, so a `.pre-commit-config.yaml` whose top-level key
    /// had been renamed, indented into another mapping, or typed as `repo:`
    /// reported zero pins and passed. Zero pins and "this is not a file I can
    /// read pins out of" are different answers, and only one of them is
    /// something a reader can act on.
    repos: Option<Vec<RepoEntry>>,
}

#[derive(Debug, Deserialize)]
struct RepoEntry {
    repo: String,
    #[serde(default)]
    rev: Option<String>,
}

/// lefthook's own remote-config block: another repository's hook definitions,
/// fetched at run time.
#[derive(Debug, Deserialize)]
struct LefthookConfig {
    #[serde(default)]
    remotes: Vec<LefthookRemote>,
    /// lefthook's older singular spelling, still accepted by lefthook and still
    /// in the wild. Read for the reason the plural one is: the pin a consumer
    /// wrote is the pin that runs, whichever key they wrote it under.
    #[serde(default)]
    remote: Option<LefthookRemote>,
}

#[derive(Debug, Deserialize)]
struct LefthookRemote {
    git_url: String,
    /// `ref` is a keyword here and a field name there.
    #[serde(rename = "ref", default)]
    reference: Option<String>,
}

/// One pin, as written, and the file it was written in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pin {
    pub repo: String,
    pub rev: String,
    /// Repository-relative, because a report that says a pin is behind without
    /// saying which file holds it sends the reader looking through a tree that
    /// may hold several.
    pub source: String,
}

/// Every pin in the tree, and what could not be read while collecting them.
#[derive(Debug)]
pub(crate) struct Pins {
    pub pins: Vec<Pin>,
    /// Facts about coverage rather than about pins: which of the two hook
    /// managers this tree even uses. Said aloud, never counted as a pass.
    pub notes: Vec<String>,
}

const PRE_COMMIT_CONFIG: &str = ".pre-commit-config.yaml";

/// The names lefthook itself looks for. Enumerated because lefthook's loader
/// enumerates them; there is no pattern to parameterize over.
const LEFTHOOK_CONFIGS: &[&str] = &[
    "lefthook.yml",
    "lefthook.yaml",
    ".lefthook.yml",
    ".lefthook.yaml",
];

/// Every hook configuration in the WORK TREE, sorted.
///
/// The tree, not the root. This read `root/.pre-commit-config.yaml` and nothing
/// else, where the guard it replaced read every `.pre-commit-config.yaml` under
/// the tree on the stated grounds that a pin in `sub/.pre-commit-config.yaml` is
/// a pin a run touches -- a monorepo with a config per package had exactly one
/// of them checked, and which one depended on where the file happened to sit.
///
/// gitignored files are skipped, since a config no commit carries is not one a
/// reviewer can see or a runner will find in a fresh clone. Sorted, because a
/// report whose order depends on directory iteration diffs against itself
/// between two runs that found the same thing.
fn hook_configs(root: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();
    let mut walker = WalkBuilder::new(root);
    walker
        // Hook configuration is dotted by convention -- `.pre-commit-config.yaml`
        // is the whole point of this walk -- so the default that skips hidden
        // files would skip everything being looked for.
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .parents(true)
        .filter_entry(|entry| {
            // The object database is not the work tree. With `hidden` off the
            // walk would descend into `.git` and read a few thousand files that
            // no hook manager has ever looked at.
            if entry.file_name() == std::ffi::OsStr::new(".git") {
                return false;
            }
            // A submodule is another repository, and its pins are its own. The
            // name test above does not stop the walk entering one: an
            // initialized submodule carries `.git` as a FILE, so excluding that
            // name excludes the file and leaves the directory around it
            // traversable. The walk then read the submodule's configs and this
            // guard asked a remote about every pin in them -- work charged to
            // the wrong repository, and a stale pin reported against a tree that
            // does not own it. A gitlink is what git itself calls the boundary.
            if entry.depth() > 0 && entry.file_type().is_some_and(|kind| kind.is_dir()) {
                let dot_git = entry.path().join(".git");
                if dot_git.is_file() {
                    return false;
                }
            }
            true
        });
    // Not `.flatten()`. A directory the walk cannot enter yields an `Err` and
    // nothing else, so flattening it away hid a configuration behind a
    // permission and let this guard report a clean pin set for a tree it had not
    // finished reading. That is the same defect `selection::by_walking` carries
    // a note about, and the same answer: a walk that did not finish is a
    // could-not-look, not a pass.
    for result in walker.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                unreadable.push(error.to_string());
                continue;
            }
        };
        if !entry.file_type().is_some_and(|kind| kind.is_file()) {
            continue;
        }
        let Some(name) = entry.file_name().to_str() else {
            continue;
        };
        if name == PRE_COMMIT_CONFIG || LEFTHOOK_CONFIGS.contains(&name) {
            found.push(entry.into_path());
        }
    }
    if !unreadable.is_empty() {
        return Err(Fatal::new(format!(
            "{} director{} under {} could not be read, so the hook configurations inside \
             them were never looked for and no pin in them was checked:\n  {}",
            unreadable.len(),
            if unreadable.len() == 1 { "y" } else { "ies" },
            root.display(),
            unreadable.join("\n  ")
        )));
    }
    found.sort();
    Ok(found)
}

/// A `rev:` that names nothing is not a pin, in either manager's spelling.
fn unpinned(path: &Path, repo: &str, field: &str) -> Fatal {
    // Dropped here by a `?`, once per manager, so the one state this guard
    // exists to catch -- a hook repository nothing pins -- was the one state it
    // could not see. It is not a stale pin; it is no pin, which is strictly
    // worse, and it read as a config with one fewer repository in it.
    Fatal::at(
        path,
        format!(
            "{repo} is listed with no `{field}:`. An unpinned hook repository is not a pin \
             this guard can check -- it is code that can change under you between two runs \
             with no diff anywhere"
        ),
    )
}

fn pre_commit_pins(path: &Path, source: &str, text: &str) -> Result<Vec<Pin>> {
    let config: HookConfig =
        serde_yaml_ng::from_str(text).map_err(|error| Fatal::at(path, error))?;
    let Some(repos) = config.repos else {
        return Err(Fatal::at(
            path,
            "has no top-level `repos:` key, so this is not a file pins can be read out of. \
             Reporting zero pins here would be an empty answer where the honest one is \
             could-not-look",
        ));
    };
    let mut pins = Vec::new();
    for entry in repos {
        // `repo: local` and `repo: meta` name no remote and carry no rev.
        if entry.repo == "local" || entry.repo == "meta" {
            continue;
        }
        let Some(rev) = entry.rev else {
            return Err(unpinned(path, &entry.repo, "rev"));
        };
        pins.push(Pin {
            repo: entry.repo,
            rev,
            source: source.to_owned(),
        });
    }
    Ok(pins)
}

/// lefthook's `remotes:` are pins, and nothing was reading them.
///
/// A lefthook consumer pins exactly one thing -- the remote config they inherit
/// their hooks from -- and it was invisible to this guard and to Dependabot
/// alike, which has no ecosystem for a lefthook remote. So the single version a
/// whole class of consumers pins was the one version nobody watched.
///
/// An ABSENT `remotes:` is not the ambiguity a missing `repos:` is: it is
/// optional in lefthook and a config without one is an ordinary local
/// configuration, so it reads as zero pins rather than as unreadable.
fn lefthook_pins(path: &Path, source: &str, text: &str) -> Result<Vec<Pin>> {
    let config: LefthookConfig =
        serde_yaml_ng::from_str(text).map_err(|error| Fatal::at(path, error))?;
    let mut pins = Vec::new();
    for remote in config.remotes.into_iter().chain(config.remote) {
        // No `ref:` means lefthook takes the remote's default branch, which is
        // the moving-target state the `rev:` arm above refuses in the same
        // words. Refused here rather than reported as a pin naming a branch,
        // because there is no branch written down to report.
        let Some(reference) = remote.reference else {
            return Err(unpinned(path, &remote.git_url, "ref"));
        };
        pins.push(Pin {
            repo: remote.git_url,
            rev: reference,
            source: source.to_owned(),
        });
    }
    Ok(pins)
}

pub(crate) fn read_pins(root: &Path) -> Result<Pins> {
    let mut pins = Vec::new();
    let mut notes = Vec::new();
    let mut saw_pre_commit = false;
    for path in hook_configs(root)? {
        let source = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let text = read_to_string(&path)?;
        if path
            .file_name()
            .is_some_and(|name| name == PRE_COMMIT_CONFIG)
        {
            saw_pre_commit = true;
            pins.extend(pre_commit_pins(&path, &source, &text)?);
        } else {
            pins.extend(lefthook_pins(&path, &source, &text)?);
        }
    }
    // An absent file, reported as a fact rather than as an io error. This
    // opened `root/.pre-commit-config.yaml` unconditionally and `read_to_string`
    // turns ENOENT into a `Fatal`, so this guard exited 2 -- "could not look" --
    // on every consumer who followed the documented lefthook-only install path.
    // They have no pre-commit config because they were told not to make one, and
    // that is an answer, not a failure to obtain one.
    if !saw_pre_commit {
        notes.push(format!(
            "no `{PRE_COMMIT_CONFIG}` anywhere in this tree, so there are no pre-commit pins \
             to check. That is the documented lefthook-only install path, not a hole in the \
             answer; any `remotes:` a lefthook config pins were read."
        ));
    }
    Ok(Pins { pins, notes })
}

/// Compare two tags the way a person reads them.
///
/// Numeric runs compare as numbers so `v10` sorts above `v9`, which a string
/// comparison gets backwards -- and getting it backwards means reporting a
/// current pin as stale, which is how a check earns a blanket opt-out.
fn version_key(tag: &str) -> (Vec<(u64, String)>, u64, String) {
    let trimmed = tag.trim_start_matches('v');
    // Semver's rule, and the reason it is here: a prerelease PRECEDES the
    // release it leads to. Scanned as one string, `v1.0.0-rc1` produced a longer
    // key with an equal prefix and sorted ABOVE `v1.0.0`, so a repository
    // correctly pinned to the newest stable tag was reported as behind a release
    // candidate -- told to move onto software its author had not released yet.
    //
    // Wrong in the noisy direction rather than the silent one, which is worse
    // than it sounds: the comment above says getting staleness backwards is how
    // a check earns a blanket opt-out, and a guard that is demonstrably wrong
    // once is a guard whose other findings get argued with.
    let (release, prerelease) = match trimmed.split_once('-') {
        Some((release, prerelease)) => (release, Some(prerelease.to_owned())),
        None => (trimmed, None),
    };
    let rank = u64::from(prerelease.is_none());
    let mut key = Vec::new();
    let mut digits = String::new();
    let mut text = String::new();
    for character in release.chars() {
        if character.is_ascii_digit() {
            if !text.is_empty() {
                key.push((0, std::mem::take(&mut text)));
            }
            digits.push(character);
        } else {
            if !digits.is_empty() {
                key.push((digits.parse().unwrap_or(0), String::new()));
                digits.clear();
            }
            text.push(character);
        }
    }
    if !digits.is_empty() {
        key.push((digits.parse().unwrap_or(0), String::new()));
    }
    if !text.is_empty() {
        key.push((0, text));
    }
    // `rank` before the prerelease text so every prerelease of one version
    // sorts under its release, and `rc2` still sorts above `rc1`.
    (key, rank, prerelease.unwrap_or_default())
}

/// What the remote has: tags newest last, and branch names.
///
/// Branches are read because `--tags` alone made this guard say something
/// untrue. A `rev:` naming a branch produced "pins main, which names no tag on
/// the remote" and the report went on to explain that the pin fails at
/// hook-init as a clone error -- which it does not. A runner resolves a branch
/// perfectly well; the problem with it is the opposite one, that it MOVES, and
/// that is a different finding needing different words.
#[derive(Clone)]
struct Refs {
    tags: Vec<String>,
    heads: Vec<String>,
}

fn remote_refs(repo: &str) -> Result<Option<Refs>> {
    let output = Command::new("git")
        .args(["ls-remote", "--refs", repo])
        .output()
        .map_err(|error| Fatal::new(format!("git ls-remote {repo}: {error}")))?;
    if !output.status.success() {
        // Unreachable is not up-to-date. The caller decides whether that is
        // fatal; it is never a pass.
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let collect = |prefix: &str| -> Vec<String> {
        text.lines()
            .filter_map(|line| line.split(prefix).nth(1))
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty())
            .collect()
    };
    let mut tags = collect("refs/tags/");
    tags.sort_by_key(|tag| version_key(tag));
    Ok(Some(Refs {
        tags,
        heads: collect("refs/heads/"),
    }))
}

/// Both questions, over every pin.
pub(crate) fn stale(request: &Request<'_>) -> Result<Option<Refusal>> {
    let Pins { pins, notes } = read_pins(request.root)?;
    for note in &notes {
        println!("{}: {note}", request.rule.id);
    }
    let mut behind: Vec<String> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    let mut unchecked: Vec<String> = Vec::new();
    let mut cache: BTreeMap<String, Option<Refs>> = BTreeMap::new();

    for pin in &pins {
        let refs = if let Some(cached) = cache.get(&pin.repo) {
            cached.clone()
        } else {
            let looked = remote_refs(&pin.repo)?;
            cache.insert(pin.repo.clone(), looked.clone());
            looked
        };
        let Some(Refs { tags, heads }) = refs else {
            unchecked.push(format!(
                "{} (pinned in {}): could not reach the remote, so neither question was \
                 answered about it",
                pin.repo, pin.source
            ));
            continue;
        };
        // A branch resolves; it just does not stay put. Reported as its own
        // finding rather than folded into "names no tag", which was both wrong
        // about what happens and wrong about what to do.
        if heads.contains(&pin.rev) {
            missing.push(format!(
                "{} pins {}, which is a BRANCH on the remote and moves. A pin that \
                 moves is not a pin: the hook you reviewed and the hook that runs \
                 next month are different code. Name a tag or a sha (in {})",
                pin.repo, pin.rev, pin.source
            ));
            continue;
        }
        // A pin that is a sha rather than a tag is not behind anything a tag
        // list can express, and it is not missing either.
        let looks_like_a_sha = pin.rev.len() >= 7 && pin.rev.chars().all(|c| c.is_ascii_hexdigit());
        if looks_like_a_sha && !tags.contains(&pin.rev) {
            continue;
        }
        if !tags.contains(&pin.rev) {
            missing.push(format!(
                "{} pins {}, which names no tag on the remote (in {})",
                pin.repo, pin.rev, pin.source
            ));
            continue;
        }
        if let Some(newest) = tags.last() {
            if newest != &pin.rev {
                behind.push(format!(
                    "{} pins {}, and {} is newer (in {})",
                    pin.repo, pin.rev, newest, pin.source
                ));
            }
        }
    }

    let mut report = String::new();
    if !missing.is_empty() {
        report.push_str(&missing.join("\n"));
        report.push_str(
            "\n\nA rev that names no ref fails at hook-init, as a clone error, before any \
             hook runs.",
        );
    }
    if !behind.is_empty() {
        if !report.is_empty() {
            report.push_str("\n\n");
        }
        report.push_str(&behind.join("\n"));
        report.push_str("\n\nThe upstream tag owns the version; a `rev:` here is a copy of it.");
    }
    if !report.is_empty() {
        // Said aloud beside the violation. The refusal below exits 1 on what was
        // checked, and a reader has to know that number was measured over fewer
        // pins than the file holds.
        if !unchecked.is_empty() {
            eprintln!(
                "{}: {} pin(s) could not be checked, on top of the finding(s) below:\n{}",
                request.rule.id,
                unchecked.len(),
                unchecked.join("\n")
            );
        }
        return Ok(Some(Refusal {
            id: request.rule.id.clone(),
            report,
        }));
    }

    // COULD NOT LOOK, which is exit 2 and never exit 0.
    //
    // `remote_refs` returns `Ok(None)` for a remote it could not reach, and the
    // whole weight of that answer rests here: a pin in `unchecked` has to reach
    // the caller as a failure to establish anything. Report it to stderr and
    // return `Ok(None)` instead and `guard::run` counts this guard among the
    // ones that passed -- which turns a network that is down, a token that has
    // expired and a remote nobody can resolve into a pin that is up to date.
    //
    // A `Fatal` rather than a `Refusal`, because this is not a violation: the
    // repository may be perfectly pinned. It is this run failing to establish
    // that, which is the same thing `audit --for-publication` reports with
    // `Exit::Broken` over a surface it could not read.
    if !unchecked.is_empty() {
        return Err(Fatal::new(format!(
            "{}: {} pin(s) could not be checked, so this guard established nothing about \
             them:\n{}\n\nCould not look is not a pass. Restore the remote's reachability, \
             or bypass this run deliberately with UPHOLD_ALLOW={}.",
            request.rule.id,
            unchecked.len(),
            unchecked.join("\n"),
            request.rule.id
        )));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ten_is_newer_than_nine() {
        // A string comparison gets this backwards, and getting it backwards
        // reports a current pin as stale.
        let mut tags = ["v9.0.0".to_owned(), "v10.0.0".to_owned()];
        tags.sort_by_key(|tag| version_key(tag));
        assert_eq!(tags.last().unwrap(), "v10.0.0");
    }

    /// A directory of its own per test, since `read_pins` now walks one.
    fn tree(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("uphold-pins-{name}-{}", std::process::id()));
        if dir.exists() {
            std::fs::remove_dir_all(&dir).unwrap();
        }
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, relative: &str, contents: &str) {
        let path = dir.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn a_flow_style_config_parses_rather_than_reading_as_empty() {
        let dir = tree("flow");
        write(
            &dir,
            ".pre-commit-config.yaml",
            "{repos: [{repo: \"https://example.test/a\", rev: v1.0.0, hooks: [{id: x}]}]}\n",
        );
        assert_eq!(
            read_pins(&dir).unwrap().pins,
            vec![Pin {
                repo: "https://example.test/a".to_owned(),
                rev: "v1.0.0".to_owned(),
                source: PRE_COMMIT_CONFIG.to_owned(),
            }]
        );
    }

    /// A submodule's pins are the submodule's, and asking about them here spends
    /// a network round trip per pin on a tree this repository does not own -- and
    /// reports the answer against the wrong repository.
    ///
    /// The walk excluded the NAME `.git`, which is a directory in an ordinary
    /// checkout and a FILE in an initialized submodule. Excluding the file left
    /// the directory around it perfectly traversable, so the walk went straight
    /// in. `.git` as a file is what git itself calls the boundary.
    #[test]
    fn a_submodules_configs_belong_to_the_submodule() {
        let dir = tree("gitlink");
        write(
            &dir,
            ".pre-commit-config.yaml",
            "repos:\n  - repo: https://example.test/a\n    rev: v1.0.0\n    hooks:\n      - id: x\n",
        );
        write(&dir, "vendored/.git", "gitdir: ../.git/modules/vendored\n");
        write(
            &dir,
            "vendored/.pre-commit-config.yaml",
            "repos:\n  - repo: https://example.test/b\n    rev: v2.0.0\n    hooks:\n      - id: y\n",
        );

        let found = read_pins(&dir).unwrap().pins;
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].repo, "https://example.test/a");
    }

    /// A directory the walk cannot enter is a could-not-look, not a clean tree.
    ///
    /// `walker.build().flatten()` dropped the `Err` and the walk carried on, so a
    /// configuration behind a permission was never found and this guard reported
    /// every pin it did manage to read as the whole answer.
    #[test]
    #[cfg(unix)]
    fn a_directory_that_cannot_be_entered_is_not_a_clean_pin_set() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tree("unreadable");
        write(
            &dir,
            ".pre-commit-config.yaml",
            "repos:\n  - repo: https://example.test/a\n    rev: v1.0.0\n    hooks:\n      - id: x\n",
        );
        write(
            &dir,
            "closed/.pre-commit-config.yaml",
            "repos:\n  - repo: https://example.test/b\n    rev: v2.0.0\n    hooks:\n      - id: y\n",
        );
        let closed = dir.join("closed");
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();

        let read = read_pins(&dir);
        // Root, or a filesystem that ignores the mode, can read it anyway; there
        // is nothing to assert about a walk that did in fact finish.
        if std::fs::read_dir(&closed).is_ok() {
            std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).ok();
            return;
        }
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).ok();

        let error = read.expect_err("an unreadable directory read as a complete answer");
        assert!(error.to_string().contains("could not be read"), "{error}");
    }

    #[test]
    fn a_local_repo_has_no_pin_to_check() {
        let dir = tree("local");
        write(
            &dir,
            ".pre-commit-config.yaml",
            "repos:\n  - repo: local\n    hooks:\n      - id: x\n",
        );
        assert!(read_pins(&dir).unwrap().pins.is_empty());
    }

    /// The documented lefthook-only install path is not a broken repository.
    ///
    /// `read_pins` opened `root/.pre-commit-config.yaml` unconditionally and
    /// `read_to_string` turns ENOENT into a `Fatal`, so this guard exited 2 for
    /// every consumer who installed the way the documentation tells them to.
    #[test]
    fn an_absent_pre_commit_config_is_an_answer_and_not_an_error() {
        let dir = tree("absent");
        let read = read_pins(&dir).unwrap();
        assert!(read.pins.is_empty());
        assert_eq!(read.notes.len(), 1, "{:?}", read.notes);
        assert!(
            read.notes
                .first()
                .is_some_and(|note| note.contains("lefthook")),
            "{:?}",
            read.notes
        );
    }

    /// A pin in `sub/` is a pin a run touches.
    ///
    /// The retired upstream read every `.pre-commit-config.yaml` in the work
    /// tree and this read only the root one, so a monorepo with a config per
    /// package had exactly one of them checked.
    #[test]
    fn a_config_below_the_root_is_read_too() {
        let dir = tree("nested");
        write(
            &dir,
            ".pre-commit-config.yaml",
            "repos:\n  - repo: https://example.test/a\n    rev: v1.0.0\n    hooks:\n      - id: x\n",
        );
        write(
            &dir,
            "sub/.pre-commit-config.yaml",
            "repos:\n  - repo: https://example.test/b\n    rev: v2.0.0\n    hooks:\n      - id: y\n",
        );
        let pins = read_pins(&dir).unwrap().pins;
        assert_eq!(pins.len(), 2, "{pins:?}");
        assert!(
            pins.iter()
                .any(|pin| pin.repo == "https://example.test/b" && pin.source.contains("sub")),
            "{pins:?}"
        );
    }

    /// A config with no `repos:` is not a config with no pins in it.
    #[test]
    fn a_config_without_a_repos_key_is_unreadable_rather_than_empty() {
        let dir = tree("norepos");
        write(
            &dir,
            ".pre-commit-config.yaml",
            "default_stages: [commit]\n",
        );
        let error = read_pins(&dir).unwrap_err().to_string();
        assert!(error.contains("repos"), "{error}");
        assert!(error.contains("could-not-look"), "{error}");
    }

    /// The one version a lefthook consumer pins, which nothing read.
    #[test]
    fn a_lefthook_remote_is_a_pin() {
        let dir = tree("lefthook");
        write(
            &dir,
            "lefthook.yml",
            "remotes:\n  - git_url: https://example.test/hooks\n    ref: v1.2.3\n    configs:\n      - lefthook.yml\n",
        );
        let read = read_pins(&dir).unwrap();
        assert_eq!(
            read.pins,
            vec![Pin {
                repo: "https://example.test/hooks".to_owned(),
                rev: "v1.2.3".to_owned(),
                source: "lefthook.yml".to_owned(),
            }]
        );
    }

    /// A lefthook remote with no `ref:` follows the default branch, which is the
    /// moving target the `rev:` arm refuses in the same words.
    #[test]
    fn a_lefthook_remote_with_no_ref_is_not_a_pin() {
        let dir = tree("lefthook-unpinned");
        write(
            &dir,
            "lefthook.yml",
            "remotes:\n  - git_url: https://example.test/hooks\n    configs:\n      - lefthook.yml\n",
        );
        let error = read_pins(&dir).unwrap_err().to_string();
        assert!(error.contains("no `ref:`"), "{error}");
    }

    /// A prerelease precedes the release it leads to.
    ///
    /// Scanned as one string, `v1.0.0-rc1` made a longer key with an equal
    /// prefix and sorted ABOVE `v1.0.0`, so a repository pinned to the newest
    /// stable tag was told it was behind a release candidate -- pushed onto
    /// software its author had not released.
    #[test]
    fn a_release_candidate_does_not_outrank_its_release() {
        let mut tags = vec![
            String::from("v1.0.0"),
            String::from("v1.0.0-rc1"),
            String::from("v1.0.0-rc2"),
        ];
        tags.sort_by_key(|tag| version_key(tag));
        assert_eq!(tags.last().map(String::as_str), Some("v1.0.0"), "{tags:?}");
        assert_eq!(
            tags.first().map(String::as_str),
            Some("v1.0.0-rc1"),
            "{tags:?}"
        );
    }

    /// The behaviour the numeric key was written for, unchanged.
    #[test]
    fn ten_is_still_newer_than_nine() {
        let mut tags = [String::from("v9"), String::from("v10")];
        tags.sort_by_key(|tag| version_key(tag));
        assert_eq!(tags.last().map(String::as_str), Some("v10"), "{tags:?}");

        let mut patches = [String::from("v1.0.1"), String::from("v1.0.0")];
        patches.sort_by_key(|tag| version_key(tag));
        assert_eq!(patches.last().map(String::as_str), Some("v1.0.1"));
    }
}
