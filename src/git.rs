//! The git calls the guards share.
//!
//! Every one of these reports the failure rather than swallowing it. A guard
//! that cannot ask git what it is about to do has not established that the act
//! is safe; it has established nothing, and returning an empty answer would
//! make that look like a pass.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Fatal, Result};

/// Run git, returning stdout. `Ok(None)` where git itself said no -- a ref that
/// does not exist, a config key that is unset -- which is an answer.
pub(crate) fn try_run(root: &Path, args: &[&str]) -> Result<Option<String>> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| Fatal::new(format!("git {}: {error}", args.join(" "))))?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
}

pub(crate) fn run(root: &Path, args: &[&str]) -> Result<String> {
    try_run(root, args)?.ok_or_else(|| {
        Fatal::new(format!(
            "git {} failed; the guard cannot see what it is being asked about",
            args.join(" ")
        ))
    })
}

/// NUL-separated output, for the paths git will not quote.
pub(crate) fn run_z(root: &Path, args: &[&str]) -> Result<Vec<String>> {
    Ok(run(root, args)?
        .split('\0')
        .filter(|field| !field.is_empty())
        .map(str::to_owned)
        .collect())
}

pub(crate) fn dir(root: &Path) -> Result<PathBuf> {
    let raw = run(root, &["rev-parse", "--git-dir"])?;
    let trimmed = raw.trim();
    let path = PathBuf::from(trimmed);
    Ok(if path.is_absolute() {
        path
    } else {
        root.join(path)
    })
}

pub(crate) fn config_global(key: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["config", "--global", key])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!value.is_empty()).then_some(value)
}

/// `Name <address>`, split.
pub(crate) fn split_ident(ident: &str) -> (String, String) {
    let name = ident.split(" <").next().unwrap_or("").trim().to_owned();
    let email = ident
        .split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .map(|(address, _)| address.trim().to_owned())
        .unwrap_or_default();
    (name, email)
}

/// The remote url for a name, or the name itself when it already is one.
pub(crate) fn remote_url(root: &Path, remote: &str) -> Option<String> {
    if remote.contains("://") || remote.contains('@') {
        return Some(remote.to_owned());
    }
    try_run(root, &["remote", "get-url", remote])
        .ok()
        .flatten()
        .map(|url| url.trim().to_owned())
        .filter(|url| !url.is_empty())
}

/// `owner/repo` from any spelling of a forge url.
pub(crate) fn owner_repo(url: &str) -> Option<(String, String)> {
    let trimmed = url.trim().trim_end_matches('/');
    let without_git = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    // scp-like (`git@host:owner/repo`) and url forms both end in owner/repo.
    let tail = without_git
        .rsplit_once(':')
        .map(|(_, tail)| tail)
        .filter(|tail| !tail.starts_with("//") && tail.contains('/'))
        .unwrap_or(without_git);
    let mut parts = tail.rsplit('/');
    let repo = parts.next()?.to_owned();
    let owner = parts.next()?.to_owned();
    if owner.is_empty() || repo.is_empty() || owner.contains("://") {
        return None;
    }
    Some((owner, repo))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_and_repo_come_out_of_every_url_spelling() {
        for url in [
            "https://github.com/acme/widget.git",
            "https://github.com/acme/widget",
            "git@github.com:acme/widget.git",
            "ssh://git@github.com/acme/widget.git",
            "https://github.com/acme/widget/",
        ] {
            assert_eq!(
                owner_repo(url),
                Some(("acme".to_owned(), "widget".to_owned())),
                "{url}"
            );
        }
    }

    #[test]
    fn an_ident_splits_into_its_two_halves() {
        assert_eq!(
            split_ident("Ada Lovelace <ada@example.test> 1700000000 +0000"),
            ("Ada Lovelace".to_owned(), "ada@example.test".to_owned())
        );
    }
}
