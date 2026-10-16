//! Rules from another repository are read as blobs, never checked out or run.
//! The commit is the pin: a branch or tag cannot substitute new policy under
//! the same configuration. Fetch failure never falls back to another revision.

use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};

use crate::error::{Fatal, Result};

/// A consumer-selected policy blob, identified by GitHub repository, immutable
/// commit and path. The loader also uses this exact tuple as rule provenance.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Remote {
    /// GitHub repository in `owner/name` form.
    pub repo: String,
    /// Full commit object ID, never a movable branch or tag.
    pub rev: String,
    /// Regular policy blob relative to that commit's tree.
    pub path: String,
}

impl Remote {
    /// Repository, commit and path as one diagnostic source name.
    pub(crate) fn label(&self) -> String {
        format!("{}@{}:{}", self.repo, self.rev, self.path)
    }

    fn validate(&self, policy: &Path) -> Result<()> {
        let parts: Vec<_> = self.repo.split('/').collect();
        if parts.len() != 2
            || parts.iter().any(|part| {
                part.is_empty()
                    || matches!(*part, "." | "..")
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
            })
        {
            return Err(Fatal::at(
                policy,
                "`inherit.remote.repo` must name a GitHub repository as `owner/name`",
            ));
        }
        if self.rev.len() != 40 || !self.rev.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Fatal::at(
                policy,
                "`inherit.remote.rev` must be a full 40-character commit ID; branches and tags can move, so resolve the intended revision to its immutable commit first",
            ));
        }
        if self.path.is_empty()
            || self.path.split('/').any(|part| matches!(part, "." | ".."))
            || self.path.chars().any(char::is_control)
            || Path::new(&self.path)
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(Fatal::at(
                policy,
                "`inherit.remote.path` must be a nonempty repository-relative file path without `.` or `..` components",
            ));
        }
        Ok(())
    }

    /// Fetch and read this exact blob, or refuse without a substitute policy.
    pub(crate) fn read(&self, policy: &Path) -> Result<String> {
        self.validate(policy)?;
        let directory = Repository::new()?;
        let fail = || {
            Fatal::at(
                policy,
                format!(
                    "could not read remote policy {} at its pinned commit; nothing was inherited",
                    self.label()
                ),
            )
        };
        crate::git::run_elsewhere(&directory.0, &["init", "--bare", "--quiet", "--template="])?;
        let url = format!("https://github.com/{}.git", self.repo);
        // No checkout, submodule recursion, hooks or repository-supplied config.
        // Git's normal credentials and URL rewrites remain available, including
        // credentials for an organization's private policy repository.
        let mut fetch = crate::shim::inner_tool("git");
        fetch
            .current_dir(&directory.0)
            .args([
                "-c",
                "fetch.recurseSubmodules=false",
                "fetch",
                "--quiet",
                "--depth=1",
                "--no-tags",
                "--",
                &url,
                &self.rev,
            ])
            // Hook and agent invocations cannot answer credential prompts.
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "")
            .env("GIT_HTTP_LOW_SPEED_LIMIT", "1")
            .env("GIT_HTTP_LOW_SPEED_TIME", "30")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if !crate::git::elsewhere(&mut fetch)
            .status()
            .map_err(|_| fail())?
            .success()
        {
            return Err(fail());
        }
        let resolved = crate::git::try_run_elsewhere(
            &directory.0,
            &["rev-parse", "--verify", "FETCH_HEAD^{commit}"],
        )?
        .ok_or_else(fail)?;
        if !resolved.trim().eq_ignore_ascii_case(&self.rev) {
            return Err(fail());
        }
        // The checked mode, exact literal path and content must all name the
        // same tree entry. Pathspec magic must not check one file and then
        // read another, and `-z` prevents filename quoting from changing it.
        let entry = crate::git::try_run_elsewhere(
            &directory.0,
            &[
                "--literal-pathspecs",
                "ls-tree",
                "-z",
                &self.rev,
                "--",
                &self.path,
            ],
        )?
        .ok_or_else(fail)?;
        let record = entry
            .strip_suffix('\0')
            .filter(|record| !record.contains('\0'))
            .ok_or_else(fail)?;
        let (metadata, path) = record.split_once('\t').ok_or_else(fail)?;
        let mut fields = metadata.split(' ');
        let mode = fields.next().ok_or_else(fail)?;
        let kind = fields.next().ok_or_else(fail)?;
        let object = fields.next().ok_or_else(fail)?;
        if fields.next().is_some()
            || !matches!(mode, "100644" | "100755")
            || kind != "blob"
            || path != self.path
            || object.len() != 40
            || !object.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(fail());
        }
        let mut command = crate::shim::inner_tool("git");
        command
            .current_dir(&directory.0)
            .args(["cat-file", "blob", object]);
        let output = crate::git::elsewhere(&mut command)
            .output()
            .map_err(|_| fail())?;
        if !output.status.success() {
            return Err(fail());
        }
        String::from_utf8(output.stdout).map_err(|_| {
            Fatal::at(
                policy,
                format!("remote policy {} is not UTF-8", self.label()),
            )
        })
    }
}

/// An exclusive scratch object store. It is never shared by repositories or
/// reused after a fetch failure, and is removed on both success and failure.
struct Repository(PathBuf);

impl Repository {
    fn new() -> Result<Self> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "uphold-remote-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(Fatal::at(&path, error)),
            }
        }
    }
}

impl Drop for Repository {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}
