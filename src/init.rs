//! `uphold init` -- a first policy, written from the two facts only the person
//! running it can state.
//!
//! Repositories were being set up by hand-copying another repository's policy,
//! hook configuration and shim block, and a copy carries the other
//! repository's `owner` along with everything else. What this writes is the
//! minimum that loads and reconciles: four bundled sets, the `gh` and `git`
//! shim tables the `published-text` set needs, two claims those sets supply,
//! and the hook ids that run them at the version of this binary.
//!
//! `owner` and `visibility` are arguments, never read off `origin`. Reading the
//! owner from the remote is the circularity `prevent-public-push` documents: an
//! allow-list derived from `origin` permits whatever `origin` currently is.
//!
//! It refuses a tree that already has a policy, and never rewrites an existing
//! hook configuration: those are decisions somebody already made, and a merge
//! this binary guessed at would be a change nobody reviewed. The block it would
//! have written is printed instead.

use std::fmt::Write as _;
use std::path::Path;

use crate::error::{Exit, Fatal, Result};

/// The sets a first policy inherits. Each needs nothing the person has not
/// just stated: `unowned-push` and `published-text` read `owner`, and the
/// private-name guards in `published-text` read `visibility`.
const SETS: &[(&str, &str)] = &[
    (
        "process-residue",
        "conflict markers, home paths, tracker references in documents",
    ),
    (
        "commit-message-residue",
        "authorship markers and unusual characters in a commit message",
    ),
    (
        "unowned-push",
        "a push to an owner this policy does not name",
    ),
    (
        "published-text",
        "the same checks over what `gh` and `git push` publish",
    ),
];

/// The shim tables `published-text` is refused without. The flag lists are the
/// ones a consumer workspace runs for `gh`, including the per-verb vocabulary
/// for `-c`, which is a boolean on `pr review` and takes a value on
/// `issue close`.
const SHIMS: &str = r#"[[shim]]
command = "gh"
match = [
  "pr:create", "pr:edit", "pr:comment", "pr:review", "pr:merge",
  "pr:close", "pr:reopen",
  "issue:create", "issue:edit", "issue:comment", "issue:close", "issue:reopen",
  "release:create", "release:edit", "gist:create",
  "api:*",
]
text_flags = ["-t", "--title", "-b", "--body", "-n", "--notes"]
file_flags = ["-F", "--body-file", "--notes-file"]
target_flags = ["-R", "--repo"]
skip_flags = ["--fill", "--fill-first", "--fill-verbose"]
web_flags = ["-w", "--web"]
editor_env = "GH_EDITOR"
target = "forge-repo"
scope = "public-target"

  [[shim.verbs]]
  match = ["issue:close", "pr:close", "issue:reopen", "pr:reopen"]
  text_flags = ["-c", "--comment"]

[[shim]]
command = "git"
match = ["push:*"]
collect = "git-refs"
target = "git-remote"
scope = "public-target"
"#;

/// Two claims, each on a rule the sets above ship and the hook ids below run.
const CLAIMS: &str = r#"# What enforces which principle here. `uphold check` refuses a claim whose
# rule stops running. Add one only for a rule that already fires.

[[enforce]]
principle = "complete-mediation"
rule = "prevent-ai-author"

[[enforce]]
principle = "least-privilege"
rule = "prevent-public-push"
"#;

fn policy(owner: &str, visibility: &str) -> String {
    // The quotes, the comma and one space past the longest name.
    let width = SETS.iter().map(|(name, _)| name.len()).max().unwrap_or(0) + 4;
    let mut sets = String::new();
    for (name, why) in SETS {
        writeln!(sets, "    {:<width$}# {why}", format!("\"{name}\",")).ok();
    }
    format!(
        "# Written by `uphold init` at v{version}. Every line is now this\n\
         # repository's to keep or change; each field is described in\n\
         # docs/REFERENCE.md at {upstream}.\n\
         \n\
         owner = \"{owner}\"\n\
         visibility = \"{visibility}\"\n\
         \n\
         [inherit]\n\
         sets = [\n{sets}]\n\
         \n\
         # The programs `published-text` stands behind. A bundled set never\n\
         # declares a shim, so a repository that inherits it declares these.\n\
         {SHIMS}",
        version = env!("CARGO_PKG_VERSION"),
        upstream = env!("CARGO_PKG_REPOSITORY"),
    )
}

fn pre_commit() -> String {
    format!(
        "default_install_hook_types: [pre-commit, commit-msg, pre-merge-commit, pre-push]\n\
         repos:\n  \
           - repo: {upstream}\n    \
             rev: v{version}\n    \
             hooks:\n      \
               - id: uphold-check\n      \
               - id: uphold-scan\n      \
               - id: uphold-scan-text\n      \
               - id: uphold-guard\n      \
               - id: uphold-guard-commit-msg\n      \
               - id: uphold-guard-merge\n      \
               - id: uphold-guard-push\n      \
               - id: uphold-guard-manual\n",
        upstream = env!("CARGO_PKG_REPOSITORY"),
        version = env!("CARGO_PKG_VERSION"),
    )
}

fn lefthook() -> String {
    format!(
        "remotes:\n  \
           - git_url: {upstream}\n    \
             ref: v{version}\n    \
             configs:\n      \
               - hooks/lefthook.yml\n",
        upstream = env!("CARGO_PKG_REPOSITORY"),
        version = env!("CARGO_PKG_VERSION"),
    )
}

/// Which hook manager to write for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Runner {
    PreCommit,
    Lefthook,
}

/// `uphold init --owner OWNER --visibility public|private [--lefthook]`, at the
/// root of the repository it writes into.
pub(crate) fn run(root: &Path, owner: &str, visibility: &str, runner: Runner) -> Result<Exit> {
    if owner.trim().is_empty() || owner.contains(['/', '"', '\\', '\n']) {
        return Err(Fatal::new(format!(
            "--owner {owner:?} is not an owner name. Name the user or organization this \
             repository's pushes may go to, as it appears in `owner/repo`"
        )));
    }
    if !matches!(visibility, "public" | "private" | "internal") {
        return Err(Fatal::new(format!(
            "--visibility {visibility:?}: say `public`, `private` or `internal`. It is \
             declared rather than looked up, so it has to be stated"
        )));
    }
    let directory = root.join("policy");
    for name in ["principles.toml", "rg-policy.toml", "upheld.toml"] {
        let existing = directory.join(name);
        if existing.exists() {
            return Err(Fatal::at(
                &existing,
                "exists, so this repository already has a policy. `uphold init` writes a \
                 first one and never merges into a policy somebody wrote",
            ));
        }
    }

    let (hook_file, hook_text) = match runner {
        Runner::PreCommit => (".pre-commit-config.yaml", pre_commit()),
        Runner::Lefthook => ("lefthook.yml", lefthook()),
    };
    let hook_path = root.join(hook_file);
    let write_hooks = !hook_path.exists();

    std::fs::create_dir_all(&directory).map_err(|error| Fatal::at(&directory, error))?;
    let policy_path = directory.join("principles.toml");
    let claims_path = directory.join("upheld.toml");
    let mut written = vec![policy_path.clone(), claims_path.clone()];
    std::fs::write(&policy_path, policy(owner, visibility))
        .map_err(|error| Fatal::at(&policy_path, error))?;
    std::fs::write(&claims_path, CLAIMS).map_err(|error| Fatal::at(&claims_path, error))?;
    if write_hooks {
        std::fs::write(&hook_path, &hook_text).map_err(|error| Fatal::at(&hook_path, error))?;
        written.push(hook_path);
    }

    // Loaded before anything is reported as written. A first policy this binary
    // cannot load is a defect here, and leaving it on disk would hand the
    // person a tree whose every hook exits 2.
    if let Err(error) = crate::config::load(root, &policy_path) {
        for path in &written {
            std::fs::remove_file(path).ok();
        }
        return Err(Fatal::new(format!(
            "the policy `uphold init` composed does not load, so nothing was written: {error}"
        )));
    }

    for path in &written {
        let shown = path.strip_prefix(root).unwrap_or(path);
        println!("wrote {}", shown.display());
    }
    if !write_hooks {
        println!(
            "\n{hook_file} exists and was left as it is. The two claims in \
             policy/upheld.toml reconcile only where it runs these hooks:\n\n{hook_text}"
        );
    }
    println!(
        "\nNext: install the hooks (`prek install` or `pre-commit install`, or `lefthook \
         install`), then `uphold check` and `uphold scan`."
    );
    Ok(Exit::Clean)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hook_config_pins_the_ids_the_manifest_publishes() {
        // An id the manifest does not publish is a clone error at hook-init,
        // before any hook runs.
        let manifest = include_str!("../.pre-commit-hooks.yaml");
        for line in pre_commit().lines() {
            if let Some(id) = line.trim().strip_prefix("- id: ") {
                assert!(
                    manifest.contains(&format!("- id: {id}\n")),
                    "{id} is not in .pre-commit-hooks.yaml"
                );
            }
        }
    }

    #[test]
    fn every_set_named_is_bundled() {
        for (name, _) in SETS {
            assert!(
                crate::config::BUNDLED
                    .iter()
                    .any(|(bundled, _)| bundled == name),
                "{name} is not a bundled set"
            );
        }
    }
}
