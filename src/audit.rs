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
//! The first is scanned. The second cannot be scanned by anyone, from anywhere,
//! and so it is printed as a STANDING CAVEAT in every report rather than counted
//! as a surface this run failed to read.
//!
//! That difference is the whole exit code. Pushed into the unreadable list, a
//! caveat true of every run made that list non-empty on every run: this
//! subcommand returned 2 unconditionally, the clean arm at the bottom of
//! `for_publication` was unreachable code, and the reference documentation went
//! on describing an exit 0 nobody could ever observe. A permanent property of
//! the tool and a surface that went unread TODAY are different facts and a
//! reader acts on them differently -- the first is worth knowing once, the
//! second is worth fixing before the flip. So `unreadable`, and with it exit 2,
//! is reserved for what this run actually failed to open, and a clean report
//! still carries the caveat in its body.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use crate::config::{Check, Policy, Rule};
use crate::error::{Exit, Fatal, Result};
use crate::git;
use crate::guard::{names, Refusal};

/// True of every run of this subcommand, on every repository, forever.
///
/// Printed in the body of every report, including a clean one. Not in the
/// unreadable list: see the module docstring -- a caveat that never varies
/// carries no information about THIS run, and putting it there made the one
/// exit code that means "something went unread today" fire on every run and
/// therefore mean nothing.
const STANDING_CAVEATS: &[&str] = &[
    "comment edit history cannot be read, by this audit or by anything else. Editing a \
     comment does not remove what it said -- the previous revision stays readable to anyone \
     who can read the comment, and there is no API route to delete one. A name published \
     there is published; the fix is the forge's support desk, not a rewrite.",
];

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
/// Bring the remote-tracking refs up to date before anything reads them.
///
/// This lived inside `history`, which runs after `reachable_blobs`, so the
/// object walk read a ref set that had not been fetched and had not been pruned:
/// an object the forge holds but this clone had never seen was missed entirely,
/// and a branch deleted upstream was still walked as something the forge serves.
/// Both readings are about what publication exposes, so both need the same
/// answer, which means the fetch belongs before either of them rather than
/// inside whichever happens to run first.
/// A failure is not fatal and is not silent: it comes back as a note the caller
/// puts in `unreadable`, which is what turns the run into an exit 2. Offline,
/// the audit still has every ref this clone already holds and is worth running,
/// so refusing outright would make the pre-publication check unavailable exactly
/// when somebody reaches for it. What it must not do is answer "clean" about a
/// forge it could not reach -- and returning `()` while the doc comment claimed
/// the caller reported the staleness is how it did precisely that.
fn refresh_origin(root: &Path) -> Option<String> {
    // Pruned, because a remote-tracking ref for a branch deleted upstream still
    // exists locally and would be read as something the forge still serves.
    let stale = |reason: String| {
        Some(format!(
            "git fetch --prune origin: {reason}. Every reading below is of the refs this \
             clone already had, so an object the forge holds and this clone has never seen \
             was not walked, and a branch deleted upstream was still read as one the forge \
             serves."
        ))
    };
    match Command::new("git")
        .args(["fetch", "-q", "--prune", "origin"])
        .current_dir(root)
        .output()
    {
        Ok(output) if output.status.success() => None,
        Ok(output) => stale(format!("exited {}", output.status.code().unwrap_or(-1))),
        Err(error) => stale(error.to_string()),
    }
}

fn history(root: &Path) -> Result<Vec<Surface>> {
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
///
/// Pruned, for the reason `refresh_origin` states about branches and this half
/// did not honour: `refs/audit/pull/*` is a local destination that nothing else
/// writes and nothing else deletes, so a ref left by an earlier run outlives the
/// pull request it named -- and outlives the remote it came from, if `origin`
/// was ever repointed. Every commit under it was then read as one this forge
/// serves and reported as `would be republished`, which is the "cries wolf about
/// the unpublishable" failure named a few lines up: findings whose only fix is
/// to delete something the reader would discover was never published there.
/// `--prune` with an explicit refspec prunes that refspec's destination, so a
/// stale ref goes on the next run rather than being audited forever.
fn retained_pull_refs(root: &Path) -> Result<(Vec<Surface>, Vec<String>)> {
    let mut surfaces = Vec::new();
    let mut unreadable = Vec::new();
    let fetched = Command::new("git")
        .args([
            "fetch",
            "-q",
            "--prune",
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
        // Asked, rather than assumed either way. "The forge retains none" and
        // "the fetch matched nothing" produce the identical empty log, and the
        // difference between them is this subcommand's whole exit code: the
        // first is a fact about a repository with no pull requests, the second
        // is a surface nobody read. Pushing both into `unreadable` made exit 0
        // unreachable for every repository that has never opened one -- a check
        // that always says "could not look" is one nobody can act on, which is
        // the same defect from the other side.
        if let Some(note) = no_pull_refs(root) {
            unreadable.push(note);
        }
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

/// Whether the forge holds no pull-request head refs, or the fetch missed them.
///
/// `ls-remote` answers the question the empty log cannot: it lists what the
/// forge has under `refs/pull/*/head` without bringing any of it down. An empty
/// listing from a remote that answered is the fact "there are none", and there
/// is nothing there to audit -- so `None`, and the run may still reach exit 0.
/// Anything else is a surface this audit did not read, and it says so.
///
/// Through git rather than through `gh`, because the audit's other half already
/// reaches the forge through `gh` and this one must stay answerable for a remote
/// `gh` does not serve. A GitLab remote publishes merge-request refs under a
/// different namespace, which `ls-remote` reports as an empty match here: that
/// is honestly "this reader found none", and a note about a fetch that matched
/// nothing is the correct thing for it to leave behind.
fn no_pull_refs(root: &Path) -> Option<String> {
    let unread = |detail: &str| {
        Some(format!(
            "refs/pull/*/head fetched no commits, and {detail}. A forge retains \
             pull-request head refs permanently and renders them on the closed pull \
             request, so this is a published surface that went unread rather than one \
             that is empty."
        ))
    };
    match Command::new("git")
        .args(["ls-remote", "origin", "refs/pull/*/head"])
        .current_dir(root)
        .output()
    {
        Ok(output) if output.status.success() => {
            if output.stdout.iter().all(u8::is_ascii_whitespace) {
                None
            } else {
                unread("the forge lists some under that namespace")
            }
        }
        Ok(output) => unread(&format!(
            "git ls-remote origin exited {}, so whether the forge retains any is unknown",
            output.status.code().unwrap_or(-1)
        )),
        Err(error) => unread(&format!(
            "git ls-remote origin could not be run ({error}), so whether the forge retains \
             any is unknown"
        )),
    }
}

/// How many issues or pull requests one `gh list` is asked for.
///
/// High on purpose, and compared against rather than trusted: see
/// `forge_conversations`. `gh` has no "all of them" for these listings, so the
/// only honest thing an audit can do is ask for more than any repository is
/// likely to hold and then say so out loud when the answer comes back at exactly
/// the number it asked for.
const FORGE_LIMIT: usize = 5000;

/// Run `gh`, keeping the reason a call failed rather than the fact that it did.
///
/// `Err` carries what the reader has to act on -- not logged in, no such
/// repository, rate limited -- because "could not be read" with nothing beside
/// it is a line nobody can do anything about.
fn gh(root: &Path, args: &[&str]) -> std::result::Result<String, String> {
    let output = Command::new("gh")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| format!("gh is not available: {error}"))?;
    if !output.status.success() {
        let reason = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(if reason.is_empty() {
            format!(
                "gh {} exited {}",
                args.join(" "),
                output.status.code().unwrap_or(-1)
            )
        } else {
            reason
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Every field a forge renders on one issue or pull request.
///
/// The TITLE is read, and its absence was the largest hole in this subcommand.
/// `-t/--title` is the exact field the `gh` cmd-shim guards on `gh issue
/// create`, so a title is text this repository already refuses to publish
/// knowingly -- and a visibility flip republishes it in the same breath as the
/// body it sits above. Asking for `body,comments` and then printing the
/// conversation as read was a coverage claim over a field nobody opened.
///
/// REVIEWS and REVIEW-THREAD COMMENTS are separate objects from issue comments
/// and arrive on neither `.body` nor `.comments`. A review body is where the
/// reasoning goes on a pull request -- which is to say where a private sibling
/// gets named -- and a review comment is pinned to a diff line, which is exactly
/// the context in which someone quotes a path, a host or an internal repository.
fn read_conversation(
    root: &Path,
    kind: &str,
    number: &str,
    surfaces: &mut Vec<Surface>,
    unreadable: &mut Vec<String>,
) {
    match gh(
        root,
        &[
            kind,
            "view",
            number,
            "--json",
            "title,body,comments",
            "--jq",
            ".title, .body, (.comments[]? | .body)",
        ],
    ) {
        Ok(text) => surfaces.push(Surface {
            label: format!("{kind} #{number} title, body and comments"),
            text,
        }),
        Err(reason) => unreadable.push(format!("{kind} #{number} could not be read: {reason}")),
    }
    if kind != "pr" {
        return;
    }
    match gh(
        root,
        &[
            "pr",
            "view",
            number,
            "--json",
            "reviews",
            "--jq",
            ".reviews[]? | .body",
        ],
    ) {
        Ok(text) => surfaces.push(Surface {
            label: format!("pr #{number} review bodies"),
            text,
        }),
        Err(reason) => unreadable.push(format!(
            "pr #{number} review bodies could not be read: {reason}"
        )),
    }
    // Through the API, because `gh pr view` has no field for the comments on a
    // review thread. `{owner}` and `{repo}` are gh's own placeholders, resolved
    // from the repository this audit is standing in, so the route cannot drift
    // from the remote the rest of the audit reads.
    let route = format!("repos/{{owner}}/{{repo}}/pulls/{number}/comments");
    match gh(root, &["api", &route, "--paginate", "--jq", ".[].body"]) {
        Ok(text) => surfaces.push(Surface {
            label: format!("pr #{number} review-thread comments"),
            text,
        }),
        Err(reason) => unreadable.push(format!(
            "pr #{number} review-thread comments could not be read: {reason}"
        )),
    }
}

/// Issue and pull-request conversations, and what could not be listed.
fn forge_conversations(root: &Path) -> (Vec<Surface>, Vec<String>) {
    let mut surfaces = Vec::new();
    let mut unreadable = Vec::new();
    let cap = FORGE_LIMIT.to_string();

    for kind in ["issue", "pr"] {
        let listed = match gh(
            root,
            &[
                kind,
                "list",
                "--state",
                "all",
                "--limit",
                &cap,
                "--json",
                "number",
                "--jq",
                ".[].number",
            ],
        ) {
            Ok(text) => text,
            Err(reason) => {
                unreadable.push(format!("{kind}s could not be listed: {reason}"));
                continue;
            }
        };
        let numbers: Vec<&str> = listed
            .lines()
            .map(str::trim)
            .filter(|number| !number.is_empty())
            .collect();
        // A truncated listing and a short one used to produce the same output.
        // At `--limit 200` the two hundred and first issue was not read, not
        // counted and not mentioned: the audit reported over whatever fell
        // inside a number nobody had chosen for this repository. The cap cannot
        // be removed -- the forge paginates -- so it is compared against
        // instead. A listing that comes back at exactly the cap was cut off, and
        // where it was cut is unknown.
        if numbers.len() >= FORGE_LIMIT {
            unreadable.push(format!(
                "the {kind} listing came back with {} item(s), which is exactly the --limit \
                 of {FORGE_LIMIT} it was asked for -- so it was TRUNCATED, and every {kind} \
                 past that cap was neither listed nor read.",
                numbers.len()
            ));
        }
        for number in numbers {
            read_conversation(root, kind, number, &mut surfaces, &mut unreadable);
        }
    }

    (surfaces, unreadable)
}

/// Every blob a flip would serve, not every path HEAD still names.
///
/// This read `git ls-tree -r HEAD` and `git show HEAD:<path>`, which is the tree
/// as it stands and not what publication exposes. A flip republishes every
/// REACHABLE object: a name or a credential committed on Monday and deleted on
/// Tuesday is still in Monday's commit, is served forever from the forge's blob
/// route by sha, and -- this is the half that matters -- SURVIVES the
/// default-branch rewrite this audit exists to trigger. Reporting clean over it
/// is precisely the failure that rewrite was supposed to fix.
///
/// The ref set is `history`'s, plus HEAD and the retained pull refs already
/// fetched: what the forge holds, not what this machine happens to have. A
/// `refs/original` left by a rewrite and a local backup branch are on no other
/// computer, and findings whose only fix is deleting something that was never
/// published are how a report earns a reader who skims it.
///
/// Deduplicated by sha rather than by path, because one blob reachable under
/// five paths and forty commits is one piece of content and reads once.
fn reachable_blobs(root: &Path) -> Result<(Vec<Surface>, Vec<String>)> {
    let listed = git_lines(
        root,
        &[
            "rev-list",
            "--objects",
            "HEAD",
            "--remotes=origin",
            "--glob=refs/audit/pull/*",
        ],
    )?;
    // `rev-list --objects` names an object and a path it once appeared at, and
    // no mode. A gitlink cannot arrive here mislabelled as a blob regardless:
    // `cat-file` calls it a commit, and only what it calls a blob is read.
    let mut shas: Vec<String> = Vec::new();
    let mut paths: BTreeMap<String, String> = BTreeMap::new();
    for line in listed.lines() {
        // A commit is listed with no path beside it; a tree and a blob both
        // carry one, which is why `cat-file` still has to say which is which.
        let Some((sha, path)) = line.split_once(' ') else {
            continue;
        };
        if path.is_empty() || paths.contains_key(sha) {
            continue;
        }
        paths.insert(sha.to_owned(), path.to_owned());
        shas.push(sha.to_owned());
    }

    let mut surfaces = Vec::new();
    let mut unreadable = Vec::new();
    let total = shas.len();
    let mut read = 0_usize;
    announce(total);
    // One `git cat-file --batch` for the whole reachable set, and the kind and
    // the content in the same answer -- so the pass that asked which objects are
    // blobs is the pass that reads them. This spawned two processes per object
    // and printed nothing between the first and the last, which on a repository
    // of any size is a run indistinguishable from a hung one.
    let absent = git::each_blob(root, &shas, |sha, bytes| {
        read += 1;
        progress(read, total);
        surfaces.push(Surface {
            label: format!(
                "{} (blob {})",
                paths.get(sha).map_or("?", String::as_str),
                &sha[..8.min(sha.len())]
            ),
            text: String::from_utf8_lossy(bytes).into_owned(),
        });
    })?;
    // An object the audit could not open is not an object the audit found clean.
    // The path this replaces dropped one with a bare `continue`, which kept it
    // out of the "could NOT be read" list -- the list that drives this
    // subcommand's exit code and the paragraph telling the reader their coverage
    // is incomplete. A missing object in a shallow or partial clone is the
    // ordinary case here, and it is exactly the case where a reader has to know
    // the audit answered about less than the whole repository.
    for (sha, verdict) in absent {
        unreadable.push(format!(
            "{} (blob {sha}) is reachable and could not be read: git cat-file says {verdict}",
            paths.get(&sha).map_or("?", String::as_str)
        ));
    }
    Ok((surfaces, unreadable))
}

/// How many objects have to be read before the run says so.
///
/// Above the count where a machine takes long enough that a reader starts
/// wondering, and above every fixture in the test suite, so the suite's expected
/// output does not become a transcript of its own progress.
const NOISY: usize = 2000;

/// What is about to be read, before the first object rather than after the last.
fn announce(total: usize) {
    if total >= NOISY {
        eprintln!("audit: reading {total} reachable object(s)");
    }
}

/// That the run is moving.
///
/// On stderr, because stdout is the report and a report is something a reader
/// pipes. The line exists so that "slow" and "hung" stop looking alike: an audit
/// that has said nothing for ten minutes offers its reader no move except to
/// kill it, and killing it answers nothing.
fn progress(read: usize, total: usize) {
    if total >= NOISY && read.is_multiple_of(1000) {
        eprintln!("audit: read {read}/{total} object(s)");
    }
}

/// The exit code this run owes its reader, in one place.
///
/// A function rather than three bare `return`s so that the clean answer is
/// something a test can reach at all. It was unreachable in practice and there
/// was no way to say so short of standing in front of a forge: `unreadable`
/// carried a caveat true of every run, so the branch above it always won.
const fn verdict(refusals: usize, unreadable: usize) -> Exit {
    if refusals > 0 {
        Exit::Violations
    } else if unreadable > 0 {
        Exit::Broken
    } else {
        Exit::Clean
    }
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

    // Every read below is about what the forge will serve, so every read below
    // wants the same ref set: fetched, and pruned of branches the forge no
    // longer has. This ran inside `history`, three lines further down, which
    // left `reachable_blobs` walking whatever the last fetch happened to leave.
    let stale_refs = refresh_origin(root);

    // The pull refs are fetched FIRST, because `reachable_blobs` walks them:
    // a blob that only ever existed on a pull-request head is served by the
    // forge for good, and it is in no branch this clone has otherwise.
    let (retained, mut unreadable) = retained_pull_refs(root)?;
    // Ahead of the readings it qualifies, because it qualifies all of them: what
    // follows is an audit of the refs this clone happens to hold rather than of
    // what the forge will serve.
    unreadable.extend(stale_refs);
    let (mut surfaces, blob_unreadable) = reachable_blobs(root)?;
    unreadable.extend(blob_unreadable);
    surfaces.extend(history(root)?);
    surfaces.extend(retained);
    let (conversations, more) = forge_conversations(root);
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
    //
    // Every variant, not `rules.first()`. The owner LIST was taken off all of
    // them forty lines above, for the reason written there -- the three variants
    // carry different fields and which one a file lists first is not a decision
    // anybody made. This check kept reading only the first, so a literal owner
    // written into the second or the third was scanned FOR and never refused:
    // the audit went looking for names it had just been handed, in a file it
    // declined to object to.
    for candidate in &rules {
        let literal = candidate.private_owners();
        if literal.is_empty() {
            continue;
        }
        refusals.push(Refusal {
            id: candidate.id.clone(),
            report: format!(
                "the rule declares {} private owner(s) literally, in a file this flip \
                 would publish. A public repository cannot hold the list of what must not \
                 be published. Move them out with `private_owners_from = \"...\"`, a \
                 command whose stdout is one owner per line, and keep the rule committed \
                 without the names.",
                literal.len()
            ),
        });
    }

    for surface in &surfaces {
        if let Some(refusal) =
            names::in_text(root, policy, &published, &surface.label, &surface.text)?
        {
            refusals.push(refusal);
        }
    }

    println!("{} surface(s) read", surfaces.len());
    for refusal in &refusals {
        eprintln!("would be republished: {}", refusal.report.trim_end());
        eprintln!();
    }

    // Printed in every report, clean or not, and deliberately NOT counted as a
    // surface this run failed to read. A reader needs both facts and they are
    // not the same fact: this one is a property of every audit anyone will ever
    // run, and the list below it is what went wrong today.
    println!();
    println!(
        "{} standing caveat(s), true of every run and not measured here:",
        STANDING_CAVEATS.len()
    );
    for caveat in STANDING_CAVEATS {
        println!("  - {caveat}");
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

    let exit = verdict(refusals.len(), unreadable.len());
    match exit {
        Exit::Violations => {}
        Exit::Broken => {
            // Not clean. Nothing was found in what could be read, and something
            // could not be read.
            println!();
            println!(
                "Nothing found in what could be read. That is not the same as clean: see the \
                 unreadable surfaces above."
            );
        }
        // Every surface this run could name, it opened. The caveats above still
        // stand, and the sentence says so rather than letting a green exit read
        // as a claim about the one surface nothing can reach.
        Exit::Clean => println!(
            "every surface a flip would republish was read, and every one of them is clean, \
             subject to the standing caveat(s) above"
        ),
    }
    Ok(exit)
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

    /// Exit 0 exists.
    ///
    /// It did not: a caveat true of every run sat in the unreadable list, that
    /// list decided the exit code, and so `audit --for-publication` returned 2
    /// on a repository with nothing wrong with it -- while the reference
    /// documentation described a 0 the code could not produce. A check that
    /// cannot pass gets read as noise and then gets switched off.
    #[test]
    fn a_run_that_read_everything_and_found_nothing_exits_clean() {
        assert_eq!(verdict(0, 0), Exit::Clean);
        assert_eq!(verdict(0, 3), Exit::Broken);
        // A violation outranks an unread surface: something WAS found, and the
        // reader has a fix to make either way.
        assert_eq!(verdict(1, 3), Exit::Violations);
        assert_eq!(verdict(1, 0), Exit::Violations);
    }

    /// The caveat is a caveat, not a measurement.
    ///
    /// Stated as a test because the two lists are ordinary `Vec<String>`s and
    /// nothing in the type system stops the next person from pushing a standing
    /// caveat back into the measured one -- which is exactly how this subcommand
    /// came to have an unreachable clean arm.
    #[test]
    fn the_standing_caveats_are_not_surfaces_this_run_failed_to_read() {
        assert!(!STANDING_CAVEATS.is_empty());
        for caveat in STANDING_CAVEATS {
            assert!(
                caveat.contains("cannot"),
                "a standing caveat states what is impossible, not what went wrong today: \
                 {caveat}"
            );
        }
        // The exit code is decided by the measured list alone, so a report
        // carrying only caveats is a clean one.
        assert_eq!(verdict(0, 0), Exit::Clean);
    }
}
