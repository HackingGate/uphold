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
//!
//! What the globs are applied TO is git's index. A content rule is a claim
//! about what this repository carries, and what it carries is what git tracks:
//! a tracked file that some ignore pattern also matches -- a `.gitignore` line,
//! a `.git/info/exclude` entry, or the operator's own global ignore file, which
//! is not in the repository at all -- is still tracked, still pushed, and still
//! read by everyone who clones it. Git ignore rules do not apply to a file git
//! already tracks; a walker's do, so a walk cannot see that file, and a rule
//! that cannot see a file reports it clean. Where there is no index to read,
//! the tree is walked with no ignore rules consulted at all, which selects a
//! SUPERSET of what is tracked -- over-reporting is the direction a checker is
//! allowed to fail in, and hiding a file is not.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::Once;

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
///
/// The second half of the answer is the reason it could not be given. An empty
/// list means the repository declares nothing `-text`; a `Some` reason means the
/// question was never answered, and the two must not arrive looking alike --
/// `index_bytes` in this same module carries a note saying exactly that about
/// `None` and an empty list, and this function used to break the rule its
/// neighbour states. The consequence of folding them was not a missed finding
/// but an invented one: a declared binary file stops being excluded, so an
/// `encoding` or `allowed_scripts` rule reports on bytes nobody wrote as text.
/// That is the safe direction to fail in and still an unmeasured claim.
pub(crate) fn not_text_paths(root: &Path) -> (Vec<String>, Option<String>) {
    let Some(listed) = index_bytes(root) else {
        // No git, or no repository. The declaration is optional, and its absence
        // means nothing is declared -- not that something failed.
        return (Vec::new(), None);
    };
    if listed.is_empty() {
        return (Vec::new(), None);
    }

    let unmeasured = |reason: &str| {
        (
            Vec::new(),
            Some(format!(
                ".gitattributes: {reason}, so which paths this repository declares are not \
                 text is unknown. Every tracked path was treated as text, which means a \
                 declared binary file was searched by the content rules rather than skipped."
            )),
        )
    };

    let Ok(mut child) = crate::shim::inner_tool("git")
        .args(["check-attr", "--stdin", "-z", "text"])
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return unmeasured("git check-attr could not be started");
    };
    let (Some(mut sink), Some(mut source)) = (child.stdin.take(), child.stdout.take()) else {
        return unmeasured("git check-attr gave no pipe to speak to");
    };

    // The two pipes move at the same time, on two threads, and that is not a
    // style preference. `check-attr` answers each path as it reads it, so on a
    // repository with a few thousand tracked files it fills its stdout pipe --
    // 64 KiB on Linux -- long before it has read the last path off stdin. A
    // parent that writes the whole list before reading a byte is then blocked
    // in `write_all` on a full stdin pipe while the child is blocked writing to
    // a stdout pipe nobody is draining, and neither ever moves again: the check
    // hangs with no output, no exit code, and nothing in a log to say why.
    let mut answered: Vec<u8> = Vec::new();
    let drained = std::thread::scope(|scope| {
        scope.spawn(move || {
            // Whatever git makes of the list, the handle is dropped when this
            // closure ends, and closing stdin is what tells `--stdin` the list
            // is finished.
            sink.write_all(&listed).ok();
        });
        source.read_to_end(&mut answered)
    });
    // Reaped either way. The child holds a slot in the process table until
    // somebody waits for it, and its status is the only thing that separates a
    // complete answer from a truncated one.
    let finished = child.wait();
    if drained.is_err() {
        return unmeasured("its answer could not be read to the end");
    }
    match finished {
        Ok(status) if status.success() => {}
        Ok(status) => {
            return unmeasured(&format!(
                "git check-attr exited {}",
                status.code().unwrap_or(-1)
            ))
        }
        Err(error) => {
            return unmeasured(&format!("git check-attr could not be waited for: {error}"))
        }
    }

    // `check-attr -z` emits path, attribute, value as three NUL-separated fields.
    let fields: Vec<&[u8]> = answered.split(|byte| *byte == 0).collect();
    let mut found = Vec::new();
    for chunk in fields.chunks(3) {
        let [path, _, value] = chunk else {
            continue;
        };
        if *value == b"unset" {
            found.push(String::from_utf8_lossy(path).into_owned());
        }
    }
    (found, None)
}

/// Every path in git's index, NUL separated, exactly as git wrote them.
///
/// `None` where there is no index to read: no git on PATH, or a directory that
/// is not a repository. That is a different answer from `Some` of an empty
/// list, which is a repository tracking nothing -- and the two must not fold
/// together, because one of them means this tool could not ask the question.
fn index_bytes(root: &Path) -> Option<Vec<u8>> {
    let listed = crate::shim::inner_tool("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .stderr(Stdio::null())
        .output()
        .ok()?;
    listed.status.success().then_some(listed.stdout)
}

/// The same listing, decoded. A path git cannot spell in UTF-8 keeps a lossy
/// name rather than disappearing: the readers downstream open it by that name
/// and report the failure, where dropping it here would report nothing at all.
fn index_paths(root: &Path) -> Option<Vec<String>> {
    Some(
        index_bytes(root)?
            .split(|byte| *byte == 0)
            .filter(|field| !field.is_empty())
            .map(|field| String::from_utf8_lossy(field).into_owned())
            .collect(),
    )
}

/// The files one rule searches, chosen once, at build time.
///
/// Chosen at build time because every way choosing them can fail -- an
/// `include` that points outside the tree, a directory the walk could not read
/// -- and a list of file names has no way to say anything but "these". A short
/// list that lost a subtree on the way in is exactly "could not look" wearing
/// "looked and found nothing"'s clothes, and this tool exists to keep those two
/// apart.
///
/// The two failures are carried differently, and the difference is what a
/// reader can do about them. An `include` outside the repository is a policy
/// that cannot mean anything, so it is a `Fatal` from `build` and the run stops
/// -- there is no partial answer to report. A path that could not be READ is a
/// fact about this tree rather than about the policy, so it rides out beside
/// the files as `unreadable`: every other rule still runs and still reports,
/// and the caller prints the list and exits 2. Failing the whole run at the
/// first unreadable path would hide every finding the remaining rules had.
#[derive(Debug)]
pub(crate) struct Selection {
    files: Vec<String>,
    unreadable: Vec<String>,
}

impl Selection {
    pub(crate) fn build(root: &Path, rule: &Rule, not_text: &[String]) -> Result<Self> {
        let overrides = overrides_for(root, rule, not_text)?;
        let roots = search_roots(root, rule)?;
        // An index if there is one, and a walk only where there is not.
        let (files, unreadable) = index_paths(root).map_or_else(
            || by_walking(root, &roots, &overrides),
            |tracked| from_index(root, &roots, &overrides, &tracked),
        );
        Ok(Self { files, unreadable })
    }

    /// Repository-relative paths, sorted, deduplicated.
    ///
    /// Sorted because a report whose order depends on directory iteration is a
    /// report that diffs against itself between runs, and deduplicated because
    /// overlapping `include` roots would otherwise search a file twice and
    /// report it twice.
    pub(crate) fn files(&self) -> Vec<String> {
        self.files.clone()
    }

    /// Paths this selection knows about and could not open, each with the
    /// reason. Never empty for a reason that is not worth exit 2.
    pub(crate) fn unreadable(&self) -> &[String] {
        &self.unreadable
    }
}

/// The rule's globs, as ripgrep would read them.
fn overrides_for(root: &Path, rule: &Rule, not_text: &[String]) -> Result<Override> {
    let mut builder = OverrideBuilder::new(root);
    for glob in &rule.files().glob {
        builder
            .add(glob)
            .map_err(|error| Fatal::new(format!("rule {:?}: glob {glob:?}: {error}", rule.id)))?;
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
    // Escaped, because these are PATHS and not patterns. The globs above are
    // author-written and their metacharacters are meant; these come back from
    // `git check-attr` and are literal names, so a tracked file called
    // `page[1].html` or `data{1,2}.bin` was read as a character class or an
    // alternation. Each way it went wrong is worse than the last: the class did
    // not match its own name, so a file declared not-text was searched AND
    // listed as skipped in the same report; the alternation matched two files
    // nobody declared, removing them from every rule silently; and an unclosed
    // class was a parse error that took the whole run to exit 2.
    for path in not_text {
        let literal = globset::escape(path);
        builder
            .add(&format!("!{literal}"))
            .map_err(|error| Fatal::new(format!("not-text path {path:?}: {error}")))?;
    }
    // The object store is not repository content. It holds every version of
    // every file, so a rule that fired on a line somebody deleted years ago
    // would report a violation with no working-tree fix. git never lists it in
    // the index either; the glob is what keeps the walk honest where there is
    // no index to read.
    builder
        .add("!.git/**")
        .map_err(|error| Fatal::new(format!("{error}")))?;
    builder
        .build()
        .map_err(|error| Fatal::new(format!("rule {:?}: {error}", rule.id)))
}

/// Whether one repository-relative path is a file this rule selects.
///
/// The same two tests [`from_index`] applies to every tracked path -- under an
/// include prefix, and not matched by an exclusion -- asked about one path
/// instead of all of them. It exists so a caller that already knows the path it
/// cares about does not have to walk the tree to find out, and so that answer
/// comes from this module rather than from a second reader of `files.*` that
/// would be free to disagree with it.
///
/// The not-text list is deliberately empty. Its entries come from
/// `git check-attr` and describe files declared binary; a caller asking about a
/// path it is about to read as text has already answered that question.
pub(crate) fn selects(root: &Path, rule: &Rule, relative: &Path) -> Result<bool> {
    let prefixes = include_prefixes(rule);
    if !prefixes
        .iter()
        .any(|prefix| prefix.as_os_str().is_empty() || relative.starts_with(prefix))
    {
        return Ok(false);
    }
    let overrides = overrides_for(root, rule, &[])?;
    Ok(!overrides.matched(relative, false).is_ignore())
}

/// The repository-relative roots one rule searches under, as written.
///
/// Split out of [`search_roots`] so [`selects`] can ask the same question
/// without the side effects that belong to a real search: the warning about an
/// include that is not there, and the refusal of one that leaves the tree. Both
/// are reports about a scan that is happening, and neither is true of a caller
/// that only wants to know whether a path is in scope.
fn include_prefixes(rule: &Rule) -> Vec<PathBuf> {
    let include = rule.include();
    if include.is_empty() {
        return vec![PathBuf::new()];
    }
    include
        .iter()
        .map(|spec| {
            if spec == "." {
                PathBuf::new()
            } else {
                PathBuf::from(spec)
            }
        })
        .collect()
}

/// The roots one rule searches under, refusing any that leaves the repository.
fn search_roots(root: &Path, rule: &Rule) -> Result<Vec<PathBuf>> {
    let include = rule.include();
    if include.is_empty() {
        return Ok(vec![root.to_path_buf()]);
    }

    let mut roots: Vec<PathBuf> = Vec::new();
    for spec in include {
        let search_root = if spec == "." {
            root.to_path_buf()
        } else {
            root.join(spec)
        };

        // Refused, and refused here rather than survived downstream. A
        // selection reports repository-relative paths, so a root outside the
        // repository has no name to report a hit under: every file found there
        // was dropped for lack of one, the rule saw an empty selection, and an
        // empty selection reads as `policy checks passed`. The two ways to
        // write it are an absolute path and one that climbs out with `..`, and
        // neither is a thing a policy about this repository can mean.
        if !under(root, &search_root) {
            return Err(Fatal::new(format!(
                "rule {:?}: `files.include` names {spec:?}, which is outside {}. An include \
                 names a path inside the repository, relative to its root -- a root outside it \
                 selects files this rule cannot name, and reports them as nothing at all.",
                rule.id,
                root.display()
            )));
        }

        // An `include` root that is not there searched nothing and said nothing.
        // A rule whose directory had since been renamed selected no files and
        // reported `policy checks passed` -- indistinguishable from a rule that
        // looked everywhere and found nothing.
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
        if !search_root.exists() {
            eprintln!(
                "rule {:?}: `files.include` names {spec:?}, which does not \
                 exist -- that root selected no files. If the directory moved, \
                 this rule is not running.",
                rule.id
            );
        }
        roots.push(search_root);
    }
    Ok(roots)
}

/// Whether `candidate` is `root` itself or something under it, decided
/// lexically -- the answer must not depend on what exists yet, because a
/// missing `include` root is reported rather than refused.
fn under(root: &Path, candidate: &Path) -> bool {
    candidate
        .strip_prefix(root)
        .is_ok_and(|rest| !rest.components().any(|part| part == Component::ParentDir))
}

/// Select from what git tracks: the files, and the paths that could not be read.
fn from_index(
    root: &Path,
    roots: &[PathBuf],
    overrides: &Override,
    tracked: &[String],
) -> (Vec<String>, Vec<String>) {
    if tracked.is_empty() {
        // Said once per run, not once per rule: this is one fact about the
        // repository, and repeating it under every rule in the policy would
        // bury the findings beneath it. Said at all, because "git tracks
        // nothing here" and "every rule looked and found nothing" are the two
        // facts this tool exists to keep apart.
        static SAID: Once = Once::new();
        SAID.call_once(|| {
            eprintln!(
                "git tracks no files under {} -- every content rule selected nothing. Stage or \
                 commit the files the policy is about; an untracked file is not something this \
                 repository carries.",
                root.display()
            );
        });
        return (Vec::new(), Vec::new());
    }

    // `search_roots` has already refused anything outside `root`, so each root
    // has a repository-relative name; the empty one is the repository itself
    // and covers every tracked path.
    let prefixes: Vec<&Path> = roots
        .iter()
        .filter_map(|search_root| search_root.strip_prefix(root).ok())
        .collect();

    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut unreadable: Vec<String> = Vec::new();
    for path in tracked {
        let relative = Path::new(path);
        if !prefixes
            .iter()
            .any(|prefix| prefix.as_os_str().is_empty() || relative.starts_with(prefix))
        {
            continue;
        }
        if overrides.matched(relative, false).is_ignore() {
            continue;
        }
        match std::fs::symlink_metadata(root.join(path)) {
            Ok(entry) if entry.is_file() => {
                found.insert(path.clone());
            }
            // A gitlink is another repository's content, and a symlink is a
            // pointer rather than text somebody wrote here -- the walk yielded
            // neither, and reading one would either fail or report the target's
            // text under the link's name.
            Ok(_) => {}
            // The index names it and the tree does not have it, so this rule
            // cannot read a file the repository still carries. Collected rather
            // than dropped, because dropping it is the whole defect: the rule
            // would search everything else, find nothing, and report a tree it
            // never finished reading as clean. The wording carries the cures,
            // because the reader of this line is holding a working tree and
            // three of the four causes are things they can act on.
            Err(error) => unreadable.push(format!(
                "{path}: {error} -- git tracks it and the working tree does not have it, which \
                 is an unstaged deletion, a sparse checkout, or a directory this process may \
                 not enter. Stage the deletion, restore the file, or exclude the path from the \
                 rules that select it."
            )),
        }
    }
    (found.into_iter().collect(), unreadable)
}

/// Select by walking the tree, for a directory git has no index for.
fn by_walking(root: &Path, roots: &[PathBuf], overrides: &Override) -> (Vec<String>, Vec<String>) {
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut unreadable: Vec<String> = Vec::new();
    for search_root in roots {
        if !search_root.exists() {
            continue;
        }
        let mut walker = WalkBuilder::new(search_root);
        walker
            .overrides(overrides.clone())
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
            // No ignore file of any kind is consulted. This walk runs where
            // there is no index to contradict one, so nothing an ignore file
            // hides here could be tracked -- and what an ignore file hides is
            // precisely what a rule would then report as clean without ever
            // opening it. The operator's global ignore file is the sharpest
            // case: it is not in the repository, so nothing a reviewer can
            // read explains why a rule stopped covering a file.
            .ignore(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .parents(false);
        for entry in walker.build() {
            match entry {
                // A subtree nobody searched: a directory the process cannot
                // read, a symlink loop, an ignore file that would not parse.
                // Collected here and reported by the caller, which is exit 2 --
                // the run could not look. Dropping any one of them on the floor
                // leaves a tree half of it could not enter looking exactly like
                // a small repository, and the rules over it saying `policy
                // checks passed` at exit 0.
                Err(error) => unreadable.push(error.to_string()),
                Ok(entry) => {
                    if !entry.file_type().is_some_and(|kind| kind.is_file()) {
                        continue;
                    }
                    match entry.path().strip_prefix(root) {
                        Ok(relative) => {
                            found.insert(relative.to_string_lossy().into_owned());
                        }
                        // `search_roots` refuses an `include` that leaves the
                        // tree, so nothing should reach this arm. A path that
                        // does is still a file this selection walked and cannot
                        // name, and dropping it quietly is the defect the
                        // refusal exists to end.
                        Err(_) => unreadable.push(format!(
                            "{}: sits outside {} and has no repository-relative name",
                            entry.path().display(),
                            root.display()
                        )),
                    }
                }
            }
        }
    }
    (found.into_iter().collect(), unreadable)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    use crate::config::{Check, CheckKind, Files};

    /// A directory of this test's own, named for what the test is about so a
    /// leftover on a failure says which one left it.
    fn workspace(label: &str) -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = crate::fixture::scratch(&format!(
            "selection-{label}-{}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn git(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn repository(label: &str) -> PathBuf {
        let root = workspace(label);
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.name", "Test"]);
        git(&root, &["config", "user.email", "test@example.test"]);
        root
    }

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    fn rule(files: Files) -> Rule {
        let mut rule = Rule::synthetic("selection-test", Check::empty(CheckKind::Regexp));
        rule.files = Some(files);
        rule
    }

    fn selected(root: &Path, files: Files) -> Vec<String> {
        Selection::build(root, &rule(files), &[]).unwrap().files()
    }

    fn unreadable(root: &Path, files: Files) -> Vec<String> {
        Selection::build(root, &rule(files), &[])
            .unwrap()
            .unreadable()
            .to_vec()
    }

    #[test]
    fn a_tracked_file_an_ignore_rule_hides_is_still_selected() {
        // The rule that made this invisible is git's own: ignore patterns do
        // not apply to a file git already tracks. A walker's do, so a tracked
        // file matched by any pattern -- a `.gitignore` line here, and the
        // operator's own global ignore file in the case that named this -- was
        // searched by no content rule and reported as clean.
        let root = repository("tracked");
        write(&root, ".gitignore", "hidden.txt\n");
        write(&root, "hidden.txt", "content\n");
        write(&root, "stray.txt", "content\n");
        git(&root, &["add", "-f", ".gitignore", "hidden.txt"]);

        let files = selected(
            &root,
            Files {
                glob: vec!["*.txt".to_owned()],
                ..Files::default()
            },
        );
        assert!(files.contains(&"hidden.txt".to_owned()), "{files:?}");
        // And the other half of "what git tracks": a file nobody staged is not
        // something this repository carries, so no rule speaks about it.
        assert!(!files.contains(&"stray.txt".to_owned()), "{files:?}");
    }

    #[test]
    fn a_tracked_path_the_working_tree_does_not_have_is_named_and_not_dropped() {
        // The other end of selecting from the index: git says the repository
        // carries this file and the tree cannot produce it, so the rule reads
        // some of what is tracked and not the rest. Named -- a rule that
        // searched the remainder and found nothing would otherwise report a
        // tree it never finished reading as clean. It rides out beside the
        // files rather than ending the run, because the rest of the tree still
        // has an answer and the caller is what turns this list into exit 2.
        let root = repository("deleted");
        write(&root, "a.txt", "content\n");
        write(&root, "gone.txt", "content\n");
        git(&root, &["add", "-f", "a.txt", "gone.txt"]);
        std::fs::remove_file(root.join("gone.txt")).unwrap();

        let selection = Selection::build(&root, &rule(Files::default()), &[]).unwrap();
        let notes = selection.unreadable();
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes.iter().any(|note| note.contains("gone.txt")),
            "{notes:?}"
        );
        // And the file that IS there was still selected: the point of carrying
        // the failure alongside is that the rest of the rule still runs.
        assert_eq!(selection.files(), vec![String::from("a.txt")]);
    }

    #[test]
    fn an_include_names_a_path_inside_the_repository_or_the_rule_is_refused() {
        // Both spellings of leaving the tree. Each one selected files whose
        // paths could not be made repository-relative, so every hit was dropped
        // on the way out and the rule reported `policy checks passed` over a
        // search that produced findings.
        let root = repository("outside");
        write(&root, "a.txt", "content\n");
        git(&root, &["add", "a.txt"]);

        for spec in ["../elsewhere", "/etc"] {
            let error = Selection::build(
                &root,
                &rule(Files {
                    include: Some(vec![spec.to_owned()]),
                    ..Files::default()
                }),
                &[],
            )
            .unwrap_err();
            assert!(error.to_string().contains("outside"), "{error}");
            assert!(error.to_string().contains(spec), "{error}");
        }
    }

    #[test]
    #[cfg(unix)]
    fn a_directory_the_walk_cannot_enter_is_named_and_not_a_short_list() {
        use std::os::unix::fs::PermissionsExt;

        // No repository here on purpose: this is the walk that runs where there
        // is no index to read, and the walk is where an unreadable directory
        // arrives as an error nobody was collecting.
        let root = workspace("blocked");
        write(&root, "visible.txt", "content\n");
        write(&root, "locked/buried.txt", "content\n");
        let locked = root.join("locked");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        // A process that can read it anyway -- root, or a filesystem that does
        // not carry the mode -- is not the situation under test, and asserting
        // into it would report the harness rather than the code.
        if std::fs::read_dir(&locked).is_ok() {
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
            return;
        }

        let notes = unreadable(&root, Files::default());
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            notes.iter().any(|note| note.contains("locked")),
            "the subtree nobody could enter went unnamed: {notes:?}"
        );
    }

    #[test]
    fn a_not_text_path_holding_glob_metacharacters_excludes_only_itself() {
        // These paths come back from `git check-attr` and are literal NAMES,
        // but they were handed to the glob builder as patterns. Three ways it
        // went wrong, all in this one fixture's shape:
        //
        //   `data{1,2}.bin` read as an alternation, so `data1.bin` and
        //   `data2.bin` -- neither declared not-text -- were removed from every
        //   content rule and named in no report.
        //
        //   `page[1].html` read as a character class, which does not match its
        //   own literal name, so the file DECLARED not-text was searched while
        //   the same run listed it as skipped.
        //
        //   `capture[1.bin` is an unclosed class, a parse error that took the
        //   whole run to exit 2 with no rule having reported anything.
        let root = repository("not-text-metacharacters");
        write(&root, "data{1,2}.bin", "declared\n");
        write(&root, "data1.bin", "not declared\n");
        write(&root, "data2.bin", "not declared\n");
        write(&root, "plain.txt", "not declared\n");
        git(&root, &["add", "-f", "-A", "."]);

        let declared = vec!["data{1,2}.bin".to_owned()];
        let files = Selection::build(&root, &rule(Files::default()), &declared)
            .unwrap()
            .files();

        assert!(
            !files.iter().any(|path| path == "data{1,2}.bin"),
            "the declared path was searched anyway: {files:?}"
        );
        for undeclared in ["data1.bin", "data2.bin", "plain.txt"] {
            assert!(
                files.iter().any(|path| path == undeclared),
                "{undeclared} was excluded by a path nobody declared: {files:?}"
            );
        }
    }

    #[test]
    fn a_not_text_path_with_an_unclosed_class_is_not_a_parse_error() {
        // Exit 2 for the whole repository, because one tracked file had a `[`
        // in its name.
        let root = repository("not-text-unclosed");
        write(&root, "capture[1.bin", "declared\n");
        write(&root, "plain.txt", "not declared\n");
        git(&root, &["add", "-f", "-A", "."]);

        let declared = vec!["capture[1.bin".to_owned()];
        let files = Selection::build(&root, &rule(Files::default()), &declared)
            .expect("an unclosed class in a FILENAME is not a malformed glob")
            .files();

        assert!(
            !files.iter().any(|path| path == "capture[1.bin"),
            "{files:?}"
        );
        assert!(files.iter().any(|path| path == "plain.txt"), "{files:?}");
    }

    #[test]
    fn several_thousand_tracked_paths_are_read_without_deadlocking() {
        // The proof for the pipe, and the numbers are the proof: 3000 paths of
        // about fifty bytes is 150 KiB written to stdin, and `check-attr`
        // answers each one as it reads it, which comes to 200 KiB back. Both
        // are several times the 64 KiB a pipe holds, so a parent that wrote
        // the whole list before reading a byte stopped here and never came back.
        let root = repository("many");
        write(&root, ".gitattributes", "*.bin -text\n");
        write(&root, "capture.bin", "bytes\n");
        for index in 0..3000 {
            write(
                &root,
                &format!("tracked/fixture-with-a-name-long-enough-{index:05}.txt"),
                "content\n",
            );
        }
        git(&root, &["add", "-f", "-A", "."]);

        // On a thread with a deadline, because a test that proves a deadlock is
        // gone has to FAIL when it is not, and a test that hangs reports
        // nothing at all -- it stops the suite with no failing test named.
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            sender.send(not_text_paths(&root)).ok();
        });
        let (declared, unmeasured) = receiver
            .recv_timeout(Duration::from_secs(60))
            .expect("`git check-attr` did not answer: the pipes deadlocked");

        assert!(unmeasured.is_none(), "{unmeasured:?}");
        assert!(declared.contains(&"capture.bin".to_owned()), "{declared:?}");
        assert!(
            !declared.iter().any(|path| path.starts_with("tracked/")),
            "{declared:?}"
        );
    }
}
