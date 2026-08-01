//! `uphold audit --for-publication`.
//!
//! Every guard across every seam conditions on *is the target public NOW*.
//! `no-private-repo-names` reads current visibility; the cmd-shims `gh` spec's
//! scope condition is literally `visibility == "public"`. So content written
//! into a private repository is correctly allowed at write time, and nothing
//! re-examines that decision when the repository later goes public.
//!
//! A private-to-public flip is a BULK REPUBLICATION EVENT. It covers the tree,
//! every commit message, and every issue and comment at once, and no tier has a
//! trigger for it -- which is the gap that let two findings through the last
//! time this repository was audited by hand.
//!
//! So this scans those surfaces under the visibility the repository is ABOUT to
//! have rather than the one it has. One shot, not a hook: the event it fires on
//! happens once and is not a commit.
//!
//! ## What it cannot see, and says so
//!
//! Two surfaces survive a history rewrite and are readable by anyone once the
//! repository is public:
//!
//! * `refs/pull/<n>/head`. A forge retains pull-request head refs permanently
//!   and renders them on the closed pull request's commit list. Rewriting the
//!   default branch does not touch them.
//! * Comment EDIT HISTORY. Editing a comment does not remove what it said; the
//!   previous revision stays readable, and there is no API route to delete one.
//!
//! The first is scanned. The second cannot be, and is reported as unreadable
//! rather than passed over, because a clean report over a surface nobody looked
//! at is the `explicit-unknown` failure on this tool's own output.

use std::path::Path;
use std::process::Command;

use crate::config::{Check, Policy, Rule};
use crate::error::{Exit, Fatal, Result};
use crate::guard::{names, Refusal};

/// One place a private name could already be written.
struct Surface {
    label: String,
    text: String,
}

/// The rule to judge with, forced to the visibility being flipped TO.
///
/// This is the whole mechanism. The rule is the repository's own
/// `no-private-repo-names`, with one field overridden -- so what counts as a
/// private name here is what counts everywhere else, and this cannot drift into
/// a second definition of the same rule.
fn as_published(rule: &Rule) -> Rule {
    let mut published = rule.clone();
    published.visibility = Some(String::from("public"));
    published
}

fn git_lines(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| Fatal::new(format!("git {}: {error}", args.join(" "))))?;
    if !output.status.success() {
        return Err(Fatal::new(format!(
            "git {} failed; the audit cannot see what it claims to check",
            args.join(" ")
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Every commit message the REMOTE holds.
///
/// Remote-tracking refs, pruned first, and deliberately not `--all --reflog`.
/// A flip republishes what the forge has; a local backup ref, a `refs/original`
/// left by a rewrite, and a reflog entry are all on this machine and on no
/// other. Reporting them produces findings whose only fix is to delete
/// something the reader would then discover was never published -- and a report
/// that cries wolf about the unpublishable is one nobody finishes reading.
fn history(root: &Path) -> Result<Vec<Surface>> {
    // Pruned, because a remote-tracking ref for a branch deleted upstream still
    // exists locally and would be read as something the forge still serves.
    Command::new("git")
        .args(["fetch", "-q", "--prune", "origin"])
        .current_dir(root)
        .output()
        .ok();
    let listed = git_lines(root, &["log", "--remotes=origin", "--format=%H%x1f%B%x1e"])?;
    let mut surfaces = Vec::new();
    for record in listed.split('\u{1e}') {
        let record = record.trim_start_matches('\n');
        let Some((sha, body)) = record.split_once('\u{1f}') else {
            continue;
        };
        if sha.trim().is_empty() {
            continue;
        }
        surfaces.push(Surface {
            label: format!("commit {}", &sha.trim()[..sha.trim().len().min(8)]),
            text: body.to_owned(),
        });
    }
    Ok(surfaces)
}

/// Commit messages on refs a forge keeps forever.
///
/// Fetched explicitly, because a rewrite of the default branch leaves them
/// untouched and a clone does not carry them by default -- so an audit that
/// only read local refs would report clean over exactly the surface that
/// survives the fix.
fn retained_pull_refs(root: &Path) -> Result<(Vec<Surface>, Vec<String>)> {
    let mut surfaces = Vec::new();
    let mut unreadable = Vec::new();
    let fetched = Command::new("git")
        .args([
            "fetch",
            "-q",
            "origin",
            "+refs/pull/*/head:refs/audit/pull/*",
        ])
        .current_dir(root)
        .output();
    match fetched {
        Ok(output) if output.status.success() => {}
        _ => {
            unreadable.push(String::from(
                "refs/pull/*/head could not be fetched. A forge retains pull-request head \
                 refs permanently and renders them on the closed pull request, and a rewrite \
                 of the default branch does not touch them.",
            ));
            return Ok((surfaces, unreadable));
        }
    }
    // `--glob=`, not a bare pattern. git does not expand a wildcard in a
    // revision argument: `refs/audit/pull/*` resolves to nothing and `git log`
    // walks HEAD instead, so the audit read the branch it had already scanned
    // and reported the retained refs as clean without opening one of them.
    let listed = git_lines(
        root,
        &["log", "--format=%H%x1f%B%x1e", "--glob=refs/audit/pull/*"],
    )?;
    if listed.trim().is_empty() {
        unreadable.push(String::from(
            "refs/pull/*/head fetched no commits. Either the forge retains none, or the              fetch matched nothing -- and those are different facts.",
        ));
    }
    for record in listed.split('\u{1e}') {
        let record = record.trim_start_matches('\n');
        let Some((sha, body)) = record.split_once('\u{1f}') else {
            continue;
        };
        if sha.trim().is_empty() {
            continue;
        }
        surfaces.push(Surface {
            label: format!(
                "retained pull ref {}",
                &sha.trim()[..8.min(sha.trim().len())]
            ),
            text: body.to_owned(),
        });
    }
    Ok((surfaces, unreadable))
}

/// Issue and pull-request bodies and comments.
fn forge_conversations(root: &Path) -> Result<(Vec<Surface>, Vec<String>)> {
    let mut surfaces = Vec::new();
    let mut unreadable = Vec::new();

    for kind in ["issue", "pr"] {
        let listed = Command::new("gh")
            .args([
                kind, "list", "--state", "all", "--limit", "200", "--json", "number",
            ])
            .current_dir(root)
            .output();
        let Ok(listed) = listed else {
            unreadable.push(format!("{kind}s could not be listed: gh is not available"));
            continue;
        };
        if !listed.status.success() {
            unreadable.push(format!(
                "{kind}s could not be listed: {}",
                String::from_utf8_lossy(&listed.stderr).trim()
            ));
            continue;
        }
        let text = String::from_utf8_lossy(&listed.stdout);
        for number in text
            .split("\"number\":")
            .skip(1)
            .filter_map(|tail| tail.trim_start().split(['}', ',']).next())
            .map(str::trim)
        {
            let viewed = Command::new("gh")
                .args([
                    kind,
                    "view",
                    number,
                    "--json",
                    "body,comments",
                    "--jq",
                    ".body, (.comments[]? | .body)",
                ])
                .current_dir(root)
                .output();
            match viewed {
                Ok(output) if output.status.success() => surfaces.push(Surface {
                    label: format!("{kind} #{number}"),
                    text: String::from_utf8_lossy(&output.stdout).into_owned(),
                }),
                _ => unreadable.push(format!("{kind} #{number} could not be read")),
            }
        }
    }

    // No route exists to read it, so it is named rather than counted clean.
    unreadable.push(String::from(
        "comment edit history could not be read. Editing a comment does not remove what it \
         said -- the previous revision stays readable to anyone who can read the comment, \
         and there is no API route to delete one.",
    ));

    Ok((surfaces, unreadable))
}

/// Every tracked file, as committed.
fn tree(root: &Path) -> Result<(Vec<Surface>, Vec<String>)> {
    let listed = git_lines(root, &["ls-tree", "-r", "-z", "--name-only", "HEAD"])?;
    let mut surfaces = Vec::new();
    let mut unreadable = Vec::new();
    for path in listed.split('\0').filter(|path| !path.is_empty()) {
        let blob = Command::new("git")
            .args(["show", &format!("HEAD:{path}")])
            .current_dir(root)
            .output()
            .map_err(|error| Fatal::new(format!("git show HEAD:{path}: {error}")))?;
        // A file the audit could not open is not a file the audit found clean.
        // It used to be dropped here with a bare `continue`, which kept it out
        // of the "could NOT be read" list -- the list that drives this
        // subcommand's exit code and the paragraph telling the reader their
        // coverage is incomplete. A submodule gitlink is the ordinary case; a
        // missing object is the one that matters.
        if !blob.status.success() {
            unreadable.push(format!(
                "{path} is in HEAD's tree and `git show HEAD:{path}` exited {} -- it was \
                 not read, and it is not covered by the count below.",
                blob.status.code().unwrap_or(-1)
            ));
            continue;
        }
        surfaces.push(Surface {
            label: path.to_owned(),
            text: String::from_utf8_lossy(&blob.stdout).into_owned(),
        });
    }
    Ok((surfaces, unreadable))
}

pub(crate) fn for_publication(root: &Path, policy: &Policy) -> Result<Exit> {
    // The rule is the repository's own. An audit that invented its own idea of
    // a private name would be a second definition of a rule that already
    // exists, disagreeing with the first exactly when it mattered.
    let rules: Vec<&Rule> = policy
        .of_check(Check::Builtin)
        .filter(|rule| rule.id.starts_with("no-private-repo-names"))
        .collect();
    let Some(rule) = rules.first() else {
        return Err(Fatal::new(
            "no `no-private-repo-names` guard is declared, so there is no rule saying what \
             counts as a private name here. Declare one before auditing for publication.",
        ));
    };
    // The owner list comes from ALL of them, not from whichever `[[rule]]` the
    // file happens to list first.
    //
    // There are three variants -- the message one, the staged one, the tracked
    // one -- and only one of them usually carries `private_owners_from`; the
    // others say `visibility` and nothing else. So `rules.first()` made the
    // audit's entire idea of a private owner depend on the ORDER of two tables
    // in a config file. Measured on a repository whose only finding is a
    // declared owner: two findings with the owner-carrying rule written first,
    // zero with the same two rules swapped.
    let mut owners: Vec<String> = Vec::new();
    for candidate in &rules {
        owners.extend(names::declared_owners(root, candidate)?);
    }
    owners.sort();
    owners.dedup();
    let mut published = as_published(rule);
    // Already resolved above, across every variant. Left in place it would run
    // again and answer for one rule only.
    published.private_owners = Some(owners);
    published.private_owners_from = None;

    println!("audit --for-publication in {}", root.display());
    println!(
        "Judged under the visibility this repository is ABOUT to have (public), not the one \
         it has."
    );

    let (mut surfaces, tree_unreadable) = tree(root)?;
    surfaces.extend(history(root)?);
    let (retained, mut unreadable) = retained_pull_refs(root)?;
    unreadable.extend(tree_unreadable);
    surfaces.extend(retained);
    let (conversations, more) = forge_conversations(root)?;
    surfaces.extend(conversations);
    unreadable.extend(more);

    let mut refusals: Vec<Refusal> = Vec::new();

    // The list of names that must not be published is itself a list of private
    // names. Written literally into a file that a flip would publish, it is the
    // disclosure the rule exists to prevent, arriving through the rule.
    //
    // Reported here rather than found by the scan below, because the scan would
    // report it as an ordinary mention in an ordinary file and the reader would
    // fix it by deleting the declaration -- which switches the rule off.
    if !rule.private_owners().is_empty() {
        refusals.push(Refusal {
            id: rule.id.clone(),
            report: format!(
                "the rule declares {} private owner(s) literally, in a file this flip \
                 would publish. A public repository cannot hold the list of what must not \
                 be published. Move them out with `private_owners_from = \"...\"`, a \
                 command whose stdout is one owner per line, and keep the rule committed \
                 without the names.",
                rule.private_owners().len()
            ),
        });
    }

    for surface in &surfaces {
        if let Some(refusal) = names::in_text(root, &published, &surface.label, &surface.text)? {
            refusals.push(refusal);
        }
    }

    println!("{} surface(s) read", surfaces.len());
    for refusal in &refusals {
        eprintln!("would be republished: {}", refusal.report.trim_end());
        eprintln!();
    }

    if !unreadable.is_empty() {
        // SAID ALOUD, ALWAYS, and this is the half that matters most. The point
        // of an audit before a flip is that it covers the surfaces the flip
        // republishes; a surface it could not read is not one of them being
        // clean, and printing a total without saying so is a coverage claim
        // nobody measured.
        println!();
        println!("{} surface(s) could NOT be read:", unreadable.len());
        for note in &unreadable {
            println!("  - {note}");
        }
    }

    if !refusals.is_empty() {
        return Ok(Exit::Violations);
    }
    if !unreadable.is_empty() {
        // Not clean. Nothing was found in what could be read, and something
        // could not be read.
        println!();
        println!(
            "Nothing found in what could be read. That is not the same as clean: see the \
             unreadable surfaces above."
        );
        return Ok(Exit::Broken);
    }
    println!("every surface a flip would republish is clean");
    Ok(Exit::Clean)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_audit_rule_is_the_repositorys_own_with_one_field_moved() {
        let mut rule = Rule::synthetic("no-private-repo-names", Check::Builtin);
        rule.private_owners = Some(vec!["acme".to_owned()]);
        rule.visibility = Some(String::from("private"));

        let published = as_published(&rule);
        assert_eq!(published.visibility.as_deref(), Some("public"));
        // Everything that decides what a private name IS travels unchanged, so
        // the audit cannot become a second definition of the same rule.
        assert_eq!(published.private_owners, rule.private_owners);
        assert_eq!(published.id, rule.id);
    }
}
