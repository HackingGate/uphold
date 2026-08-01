//! The identity a commit is about to be stamped with.

use std::fmt::Write as _;

use super::{Refusal, Request};
use crate::error::Result;
use crate::git;

/// Refuse a commit whose identity does not match the global one.
///
/// The identity git is about to record, resolved through `git var`, which
/// reflects `--author`, a repository-local `user.email`, and any `GIT_AUTHOR_*`
/// or `GIT_COMMITTER_*` in the environment. That is the point: the case this
/// guards against is an agent that runs `git init` and commits under a stray
/// local identity, and every one of those routes arrives through `git var`.
pub(crate) fn prevent_author_mismatch(request: &Request<'_>) -> Result<Option<Refusal>> {
    let expected_email = git::config_global("user.email");
    // Nothing to enforce if no global identity is configured. The ADDRESS is
    // the part that has to be there: it is what a forge keys attribution on,
    // and it is the half an agent gets wrong.
    let Some(expected_email) = expected_email else {
        // Said out loud, because this is the shape of the very case the guard
        // names: a container or an agent that ran `git init`, has no global
        // identity to compare against, and commits under whatever local one it
        // set. There is genuinely nothing to check here -- the rule has no
        // field carrying an expected identity, so the global config IS the
        // expectation -- but a guard that quietly declines to run in exactly
        // its own scenario should at least say which of the two happened.
        eprintln!(
            "{}: no global `user.email` is configured, so there is no identity to \
             compare against and this guard did not run.",
            request.rule.id
        );
        return Ok(None);
    };
    let expected_name = git::config_global("user.name");

    let author = git::try_run(request.root, &["var", "GIT_AUTHOR_IDENT"])?;
    // If git cannot resolve an identity at all, let `git commit` surface that.
    let Some(author) = author
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let committer = git::try_run(request.root, &["var", "GIT_COMMITTER_IDENT"])?
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());

    let mut mismatches: Vec<String> = Vec::new();
    let mut check = |role: &str, ident: &str| {
        let (name, email) = git::split_ident(ident);
        let wrong_address = !email.eq_ignore_ascii_case(&expected_email);
        // Half a configured identity is enforced as half. Dropping the check
        // because no name is set would be the fail-open -- the address is still
        // declared, and a stray address is the case this exists for -- while
        // comparing an empty expectation against whatever git resolved would
        // refuse every commit in every repository holding one, offering
        // `git config user.name ""` as the only remedy, which git will not
        // accept either.
        let wrong_name = expected_name
            .as_deref()
            .is_some_and(|expected| name != expected);
        if wrong_address || wrong_name {
            mismatches.push(format!("  {role}: {name} <{email}>"));
        }
    };
    check("author", &author);
    if let Some(committer) = committer.as_deref() {
        check("committer", committer);
    }

    if mismatches.is_empty() {
        return Ok(None);
    }

    let mut report = String::from("the commit identity does not match your global one\n\n");
    report.push_str(&mismatches.join("\n"));
    report.push_str("\n\nExpected (from ~/.gitconfig):\n");
    match expected_name.as_deref() {
        Some(name) => {
            writeln!(report, "  {name} <{expected_email}>").ok();
        }
        None => {
            write!(
                report,
                "  <{expected_email}>\n  (no user.name is set globally, so only the address \
                 was compared)\n"
            )
            .ok();
        }
    }
    report.push_str("\nFix this repository's identity with:\n");
    // Only the halves actually declared: printing `git config user.name ""`
    // turns a remedy into a dead end.
    if let Some(name) = expected_name.as_deref() {
        writeln!(report, "  git config user.name  \"{name}\"").ok();
    }
    write!(report, "  git config user.email \"{expected_email}\"").ok();

    Ok(Some(Refusal {
        id: request.rule.id.clone(),
        report,
    }))
}
