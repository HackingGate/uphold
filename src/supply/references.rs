//! What in a `uv export` guarddog can look up, and what it cannot.
//!
//! `guarddog pypi verify` looks every requirement up on `PyPI` by name. A
//! requirement that is a DIRECT REFERENCE -- PEP 508 `name @ <url>`, which is
//! how `uv export` spells a uv git source, a direct URL and a `file://` path --
//! names something `PyPI` never held, so guarddog answers a 404, and the section
//! read that as could-not-look. Every repository depending on its own
//! first-party package through a git source was exit 2 on every push, for a
//! question addressed to the wrong registry.
//!
//! So the export is sorted before guarddog sees it, and nothing is dropped
//! silently. What resolves from an index goes to guarddog unchanged. A path
//! inside the tree -- a workspace member, the project itself -- goes to it
//! unchanged too, as it always did. A git source on the repository's own forge,
//! under the owner the policy DECLARES, is asked of its remote instead: the
//! locked commit must be what some ref there points at, and a tag the lock
//! names must point at that commit. Everything else is refused by name: a git
//! source under anybody else, a direct URL, a path outside the tree. Those are
//! dependencies no scanner here can vouch for, and skipping them would be a
//! pass nobody earned.
//!
//! The owner is the policy's declared one and never `origin`'s, for the reason
//! [`crate::config::PolicyFile::owner`] gives: a first-party set read off the
//! remote is repointed by the same command that repoints the remote.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;

/// The forge a first-party git source lives on where the policy names none.
pub(super) const DEFAULT_FORGE_HOST: &str = "github.com";

/// One git source out of the export, with what the lock says it was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GitPin {
    /// The package, as the export names it.
    pub name: String,
    /// The remote, as git is handed it: the export's URL without `git+`, the
    /// revision or a fragment.
    pub remote: String,
    /// The commit the lock holds.
    pub commit: String,
    /// The tag the lock's source names, where it names one.
    pub tag: Option<String>,
}

/// One `uv export`, sorted.
#[derive(Debug, Default)]
pub(super) struct Sorted {
    /// The export with every direct reference outside the tree taken out: what
    /// guarddog is handed.
    pub kept: String,
    /// How many of the kept lines are requirements an index resolves, which is
    /// what guarddog can look up. Zero is a run with nothing to ask it.
    pub indexed: usize,
    /// Git sources, for the owner check and the remote.
    pub git: Vec<GitPin>,
    /// Direct references refused as they stand, each a line naming it.
    pub refused: Vec<String>,
}

/// Sort an export taken in `directory` of a repository rooted at `root`.
///
/// `lock` is the text of the `uv.lock` beside it, where it could be read: only
/// the tag a git source names is taken from it, and a lock that does not say
/// leaves the tag unknown rather than failing the sort.
pub(super) fn sort(export: &str, directory: &Path, root: &Path, lock: Option<&str>) -> Sorted {
    let tags = lock.map(tags_in_lock).unwrap_or_default();
    let mut sorted = Sorted::default();
    for line in export.lines() {
        let trimmed = line.trim();
        let keep = if trimmed.is_empty() || trimmed.starts_with('#') || line.starts_with(' ') {
            true
        } else if let Some(path) = trimmed.strip_prefix("-e ").map(str::trim) {
            path_inside(path, directory, root, &mut sorted)
        } else if trimmed.starts_with('-') {
            true
        } else if is_path(trimmed) {
            path_inside(trimmed, directory, root, &mut sorted)
        } else if let Some((name, reference)) = direct_reference(trimmed) {
            by_reference(name, reference, directory, root, &tags, &mut sorted)
        } else {
            sorted.indexed += 1;
            true
        };
        if keep {
            sorted.kept.push_str(line);
            sorted.kept.push('\n');
        }
    }
    sorted
}

/// A direct reference, sorted: whether its line stays in what guarddog reads.
fn by_reference(
    name: &str,
    reference: &str,
    directory: &Path,
    root: &Path,
    tags: &BTreeMap<(String, String), String>,
    sorted: &mut Sorted,
) -> bool {
    if let Some(git) = reference.strip_prefix("git+") {
        match split_git(git) {
            Some((remote, commit)) => {
                let tag = tags.get(&(normalise(name), commit.clone())).cloned();
                sorted.git.push(GitPin {
                    name: name.to_owned(),
                    remote,
                    commit,
                    tag,
                });
            }
            None => sorted.refused.push(format!(
                "{name} is a git source whose URL names no commit ({reference}), so there is \
                 no pin to check"
            )),
        }
        return false;
    }
    if let Some(path) = reference.strip_prefix("file://") {
        return path_inside(path, directory, root, sorted);
    }
    sorted.refused.push(format!(
        "{name} is a direct URL ({reference}): no index holds it, so guarddog cannot look it \
         up and nothing here vouches for it"
    ));
    false
}

/// Whether a path requirement stays: inside the tree it does, as it always
/// did; outside, it is refused by name.
fn path_inside(path: &str, directory: &Path, root: &Path, sorted: &mut Sorted) -> bool {
    let resolved = lexical(&directory.join(path));
    if resolved.starts_with(lexical(root)) {
        return true;
    }
    sorted.refused.push(format!(
        "{path} is a path dependency outside this repository ({}): no index holds it and no \
         scanner here reads it",
        resolved.display()
    ));
    false
}

/// A path with `.` and `..` taken out without asking the filesystem, which a
/// dependency that is not there cannot answer.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// A requirement line spelled as a path, the way `uv export` writes a
/// non-editable path source.
fn is_path(line: &str) -> bool {
    line.starts_with("./") || line.starts_with("../") || line.starts_with('/')
}

/// `name @ reference` out of a requirement line, markers and extras left off.
fn direct_reference(line: &str) -> Option<(&str, &str)> {
    let requirement = line.split(" ;").next().unwrap_or(line);
    let (name, reference) = requirement.split_once(" @ ")?;
    let name = name.split('[').next().unwrap_or(name).trim();
    Some((name, reference.trim()))
}

/// The remote and the commit out of what follows `git+`: `<scheme>://<authority>
/// <path>@<rev>[#fragment]`. The revision is the last `@` in the PATH, because
/// an ssh authority carries one of its own.
fn split_git(url: &str) -> Option<(String, String)> {
    let url = url.split('#').next().unwrap_or(url);
    let (scheme, rest) = url.split_once("://")?;
    let slash = rest.find('/')?;
    let (authority, path) = rest.split_at(slash);
    let (path, rev) = path.rsplit_once('@')?;
    if rev.is_empty() {
        return None;
    }
    Some((format!("{scheme}://{authority}{path}"), rev.to_owned()))
}

/// PEP 503's normalised name, which is how the lock and the export agree.
fn normalise(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut run = false;
    for character in name.chars() {
        if matches!(character, '-' | '_' | '.') {
            if !run {
                out.push('-');
            }
            run = true;
        } else {
            out.extend(character.to_lowercase());
            run = false;
        }
    }
    out
}

/// `(name, commit) -> tag` for every git source in a `uv.lock` whose URL names
/// a tag: `git = "<remote>?tag=<tag>#<commit>"`.
fn tags_in_lock(lock: &str) -> BTreeMap<(String, String), String> {
    let mut tags = BTreeMap::new();
    let Ok(parsed) = lock.parse::<toml::Table>() else {
        return tags;
    };
    let Some(packages) = parsed.get("package").and_then(toml::Value::as_array) else {
        return tags;
    };
    for package in packages {
        let name = package.get("name").and_then(toml::Value::as_str);
        let git = package
            .get("source")
            .and_then(|source| source.get("git"))
            .and_then(toml::Value::as_str);
        let (Some(name), Some(git)) = (name, git) else {
            continue;
        };
        let Some((before, commit)) = git.rsplit_once('#') else {
            continue;
        };
        let Some((_, query)) = before.split_once('?') else {
            continue;
        };
        if let Some(tag) = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("tag="))
            .filter(|tag| !tag.is_empty())
        {
            tags.insert((normalise(name), commit.to_owned()), tag.to_owned());
        }
    }
    tags
}

/// Who counts as first party, as the policy declared it.
#[derive(Debug)]
pub(super) struct FirstParty<'a> {
    /// The declared owner; `Err` where `owner_from` could not answer, with
    /// what it said.
    pub owner: Result<Option<String>, String>,
    /// The forge host a first-party source lives on.
    pub host: &'a str,
}

/// What checking one git source established.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Checked {
    /// First party, and its remote holds the pin; described.
    Holds(String),
    /// Refused, described.
    Refused(String),
    /// Nobody could answer, described.
    Unread(String),
}

/// Check one git source: first party or refused, and for first party, the pin
/// against the remote.
///
/// `remotes` holds what `git ls-remote` answered per remote in this run, so a
/// remote named by several packages is asked once.
pub(super) fn check(
    pin: &GitPin,
    first_party: &FirstParty<'_>,
    directory: &Path,
    remotes: &mut BTreeMap<String, Result<String, String>>,
) -> Checked {
    let name = &pin.name;
    let owner = match &first_party.owner {
        Ok(Some(owner)) => owner,
        Ok(None) => {
            return Checked::Refused(format!(
                "{name} is a git source ({}), and this policy declares no `owner`, so no git \
                 source is first party here and nothing vouches for this one",
                pin.remote
            ));
        }
        Err(said) => {
            return Checked::Unread(format!(
                "{name} is a git source, and whether it is first party could not be asked: \
                 {said}"
            ));
        }
    };
    let host = crate::git::host(&pin.remote);
    let under = owner_of(&pin.remote);
    let ours = host
        .as_deref()
        .is_some_and(|host| host.eq_ignore_ascii_case(first_party.host))
        && under.is_some_and(|under| under.eq_ignore_ascii_case(owner));
    if !ours {
        return Checked::Refused(format!(
            "{name} is a git source under {}/{}, not under {}/{owner}, which is this \
             repository's declared owner: PyPI does not hold it, so guarddog cannot look it \
             up, and nothing here vouches for it",
            host.as_deref().unwrap_or("no host"),
            under.unwrap_or("no owner"),
            first_party.host
        ));
    }
    let answer = remotes
        .entry(pin.remote.clone())
        .or_insert_with(|| ls_remote(&pin.remote, directory));
    match answer {
        Ok(refs) => against_refs(pin, refs),
        Err(said) => Checked::Unread(format!(
            "git ls-remote could not answer for {name} at {}: {said}",
            pin.remote
        )),
    }
}

/// The first path segment of a remote URL: the owner a forge files it under.
fn owner_of(remote: &str) -> Option<&str> {
    let (_, rest) = remote.split_once("://")?;
    let (_, path) = rest.split_once('/')?;
    path.split('/').next().filter(|owner| !owner.is_empty())
}

/// The pin read against what `git ls-remote` listed.
fn against_refs(pin: &GitPin, refs: &str) -> Checked {
    let name = &pin.name;
    let commit = &pin.commit;
    let mut pointed: BTreeMap<&str, &str> = BTreeMap::new();
    for line in refs.lines() {
        let Some((sha, reference)) = line.split_once('\t') else {
            continue;
        };
        pointed.insert(reference.trim(), sha.trim());
    }
    if let Some(tag) = &pin.tag {
        let full = format!("refs/tags/{tag}");
        let peeled = format!("{full}^{{}}");
        let at = pointed
            .get(peeled.as_str())
            .or_else(|| pointed.get(full.as_str()));
        return match at {
            None => Checked::Refused(format!(
                "{name} is locked to tag {tag}, and {} has no such tag",
                pin.remote
            )),
            Some(at) if !at.eq_ignore_ascii_case(commit) => Checked::Refused(format!(
                "{name} is locked to tag {tag} at {commit}, and {} has {tag} at {at}: the tag \
                 moved, or the lock was taken from somewhere else",
                pin.remote
            )),
            Some(_) => Checked::Holds(format!(
                "{name}: tag {tag} on {} is {commit}, the commit the lock holds",
                pin.remote
            )),
        };
    }
    // A branch or a tag names the commit better than `HEAD`, which is whatever
    // the remote's default branch is today.
    let mut tips: Vec<&str> = pointed
        .iter()
        .filter(|(_, sha)| sha.eq_ignore_ascii_case(commit))
        .map(|(reference, _)| reference.trim_end_matches("^{}"))
        .collect();
    tips.sort_by_key(|reference| !reference.starts_with("refs/"));
    let Some(reference) = tips.first() else {
        return Checked::Refused(format!(
            "{name} is locked to {commit}, and no branch or tag on {} points at it: a commit \
             no ref names can be rewritten out from under the pin",
            pin.remote
        ));
    };
    Checked::Holds(format!("{name}: {commit} is {reference} on {}", pin.remote))
}

/// `git ls-remote <remote>`, read-only, with no prompt to hang on.
fn ls_remote(remote: &str, directory: &Path) -> Result<String, String> {
    if !crate::probe::on_path("git") {
        return Err(String::from("git is not on PATH"));
    }
    let mut command = crate::shim::inner_tool("git");
    command
        .args(["ls-remote", remote])
        .current_dir(directory)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null());
    // A remote, not the hooked repository: the hook's `GIT_DIR` has nothing to
    // say about it.
    for variable in crate::git::REPOSITORY_ENVIRONMENT {
        command.env_remove(variable);
    }
    let output = command
        .output()
        .map_err(|error| format!("git could not be started: {error}"))?;
    if !output.status.success() {
        return Err(super::first_said(&String::from_utf8_lossy(&output.stderr)).to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::{Checked, GitPin, against_refs, normalise, sort, split_git, tags_in_lock};
    use std::path::Path;

    const COMMIT: &str = "53b5755d35af9bb71e6266a45c487682d1884130";
    const OTHER: &str = "0000000000000000000000000000000000000001";

    #[test]
    fn an_export_is_sorted_into_index_tree_git_and_refused() {
        let export = format!(
            "# header\n-e .\n-e ./packages/member\n    # via proj\n./libs/inner\n\
             -e ../../elsewhere\nrequests==2.32.0\ncolorama==0.4.6 ; sys_platform == 'win32'\n\
             example-kit @ git+https://github.com/example-org/example-kit@{COMMIT}\n\
             wheel-dep @ https://example.test/wheel-dep-1.0-py3-none-any.whl\n\
             local-dep @ file:///repo/service/vendor-copy\n"
        );
        let sorted = sort(
            &export,
            Path::new("/repo/service"),
            Path::new("/repo"),
            None,
        );
        assert_eq!(sorted.indexed, 2);
        assert!(sorted.kept.contains("-e ./packages/member"));
        assert!(sorted.kept.contains("./libs/inner"));
        assert!(sorted.kept.contains("local-dep @ file://"));
        assert!(!sorted.kept.contains("example-kit"));
        assert!(!sorted.kept.contains("wheel-dep"));
        assert!(!sorted.kept.contains("elsewhere"));
        assert_eq!(
            sorted.git,
            vec![GitPin {
                name: String::from("example-kit"),
                remote: String::from("https://github.com/example-org/example-kit"),
                commit: String::from(COMMIT),
                tag: None,
            }]
        );
        assert_eq!(sorted.refused.len(), 2, "{:?}", sorted.refused);
        assert!(sorted.refused.iter().any(|said| said.contains("wheel-dep")));
        assert!(sorted.refused.iter().any(|said| said.contains("elsewhere")));
    }

    #[test]
    fn the_revision_is_the_last_at_in_the_path_not_the_ssh_user() {
        assert_eq!(
            split_git(&format!(
                "ssh://git@github.com/example-org/example-kit.git@{COMMIT}#subdirectory=py"
            )),
            Some((
                String::from("ssh://git@github.com/example-org/example-kit.git"),
                String::from(COMMIT)
            ))
        );
        assert_eq!(
            split_git("https://github.com/example-org/example-kit"),
            None
        );
    }

    #[test]
    fn the_lock_supplies_the_tag_a_git_source_names() {
        let lock = format!(
            "version = 1\n[[package]]\nname = \"Example_Kit\"\nversion = \"0.1.0\"\n\
             source = {{ git = \"https://github.com/example-org/example-kit?tag=v0.1.0#{COMMIT}\" }}\n"
        );
        let tags = tags_in_lock(&lock);
        assert_eq!(
            tags.get(&(normalise("example-kit"), String::from(COMMIT))),
            Some(&String::from("v0.1.0"))
        );
        assert!(tags_in_lock("not toml [").is_empty());
    }

    fn pin(tag: Option<&str>) -> GitPin {
        GitPin {
            name: String::from("example-kit"),
            remote: String::from("https://github.com/example-org/example-kit"),
            commit: String::from(COMMIT),
            tag: tag.map(String::from),
        }
    }

    #[test]
    fn a_peeled_annotated_tag_is_read_through_to_its_commit() {
        let refs = format!(
            "{OTHER}\trefs/heads/main\n{OTHER}\trefs/tags/v0.1.0\n{COMMIT}\trefs/tags/v0.1.0^{{}}\n"
        );
        assert!(matches!(
            against_refs(&pin(Some("v0.1.0")), &refs),
            Checked::Holds(_)
        ));
        assert!(matches!(against_refs(&pin(None), &refs), Checked::Holds(_)));
    }

    #[test]
    fn a_tag_that_moved_or_is_missing_and_an_unnamed_commit_are_refused() {
        let moved = format!("{OTHER}\trefs/tags/v0.1.0\n{COMMIT}\trefs/heads/main\n");
        assert!(matches!(
            against_refs(&pin(Some("v0.1.0")), &moved),
            Checked::Refused(said) if said.contains("the tag moved")
        ));
        assert!(matches!(
            against_refs(&pin(Some("v0.2.0")), &moved),
            Checked::Refused(said) if said.contains("no such tag")
        ));
        let elsewhere = format!("{OTHER}\trefs/heads/main\n");
        assert!(matches!(
            against_refs(&pin(None), &elsewhere),
            Checked::Refused(said) if said.contains("no branch or tag")
        ));
    }
}
