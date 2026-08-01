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
//! The configuration is parsed rather than scanned. A line regex over
//! `.pre-commit-config.yaml` reads the block form and silently yields nothing
//! for a flow-style file -- an absent pin and an unreadable one looking the
//! same, which is the failure `explicit-unknown` names. The old guard scanned
//! lines because it shipped as `language: script` and could have no
//! dependencies; a binary has no such constraint.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

use crate::error::{read_to_string, Fatal, Result};
use crate::guard::{Refusal, Request};

#[derive(Debug, Deserialize)]
struct HookConfig {
    #[serde(default)]
    repos: Vec<RepoEntry>,
}

#[derive(Debug, Deserialize)]
struct RepoEntry {
    repo: String,
    #[serde(default)]
    rev: Option<String>,
}

/// One pin, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pin {
    pub repo: String,
    pub rev: String,
}

pub(crate) fn read_pins(root: &Path) -> Result<Vec<Pin>> {
    let path = root.join(".pre-commit-config.yaml");
    let text = read_to_string(&path)?;
    let config: HookConfig =
        serde_yaml_ng::from_str(&text).map_err(|error| Fatal::at(&path, error))?;
    let mut pins = Vec::new();
    for entry in config.repos {
        // `repo: local` and `repo: meta` name no remote and carry no rev.
        if entry.repo == "local" || entry.repo == "meta" {
            continue;
        }
        // A remote with no `rev:` was dropped here by a `?`, so the one state
        // this guard exists to catch -- a hook repository nothing pins -- was
        // the one state it could not see. It is not a stale pin; it is no pin,
        // which is strictly worse, and it read as a config with one fewer repo
        // in it.
        let Some(rev) = entry.rev else {
            return Err(Fatal::at(
                &path,
                std::io::Error::other(format!(
                    "{} is listed with no `rev:`. An unpinned hook repository is not a \
                     pin this guard can check -- it is code that can change under you \
                     between two runs with no diff anywhere",
                    entry.repo
                )),
            ));
        };
        pins.push(Pin {
            repo: entry.repo,
            rev,
        });
    }
    Ok(pins)
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
    let pins = read_pins(request.root)?;
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
            unchecked.push(format!("{}: could not reach the remote", pin.repo));
            continue;
        };
        // A branch resolves; it just does not stay put. Reported as its own
        // finding rather than folded into "names no tag", which was both wrong
        // about what happens and wrong about what to do.
        if heads.contains(&pin.rev) {
            missing.push(format!(
                "{} pins {}, which is a BRANCH on the remote and moves. A pin that \
                 moves is not a pin: the hook you reviewed and the hook that runs \
                 next month are different code. Name a tag or a sha",
                pin.repo, pin.rev
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
                "{} pins {}, which names no tag on the remote",
                pin.repo, pin.rev
            ));
            continue;
        }
        if let Some(newest) = tags.last() {
            if newest != &pin.rev {
                behind.push(format!(
                    "{} pins {}, and {} is newer",
                    pin.repo, pin.rev, newest
                ));
            }
        }
    }

    // Said aloud whatever else happened. A pin nobody could check is a hole in
    // the answer, and reporting it only when something else also failed makes
    // the hole invisible exactly when the rest is clean.
    if !unchecked.is_empty() {
        eprintln!(
            "{}: {} pin(s) could not be checked:\n{}",
            request.rule.id,
            unchecked.len(),
            unchecked.join("\n")
        );
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
    if report.is_empty() {
        return Ok(None);
    }
    Ok(Some(Refusal {
        id: request.rule.id.clone(),
        report,
    }))
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

    #[test]
    fn a_flow_style_config_parses_rather_than_reading_as_empty() {
        let dir = std::env::temp_dir().join(format!("uphold-pins-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".pre-commit-config.yaml"),
            "{repos: [{repo: \"https://example.test/a\", rev: v1.0.0, hooks: [{id: x}]}]}\n",
        )
        .unwrap();
        let pins = read_pins(&dir).unwrap();
        assert_eq!(
            pins,
            vec![Pin {
                repo: "https://example.test/a".to_owned(),
                rev: "v1.0.0".to_owned()
            }]
        );
    }

    #[test]
    fn a_local_repo_has_no_pin_to_check() {
        let dir = std::env::temp_dir().join(format!("uphold-pins-l-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".pre-commit-config.yaml"),
            "repos:\n  - repo: local\n    hooks:\n      - id: x\n",
        )
        .unwrap();
        assert!(read_pins(&dir).unwrap().is_empty());
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
