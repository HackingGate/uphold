//! Where the links live, and what reaches them.
//!
//! The shim itself is per repository already: the binary discovers
//! `policy/principles.toml` from the working directory upward, stops at the
//! repository boundary, and where there is no policy it execs the real command
//! and gets out of the way. What is NOT per repository, and cannot be, is the
//! link: a file named `git` on PATH ahead of the real one is reached by every
//! `git` that shell runs, in every directory, forever. That is a property of
//! PATH rather than of this tool, and a repository cannot decide whether a link
//! on somebody else's PATH is reached -- it can only decide what happens when it
//! is, which is the `[[shim]]` block it already writes.
//!
//! So the decision this module makes is not "system-wide or configurable". It is
//! **where the links sit and who can see them**, and it has two shapes:
//!
//! * `--install` puts one link per command in ONE directory the operator adds to
//!   PATH. That makes the whole seam one entry to add, inspect, or drop, and
//!   `ls` answers "what am I standing in front of". Scattering links across
//!   `/usr/local/bin` answers neither question, and removing them is archaeology.
//! * `--hook` puts that directory on PATH only inside a tree that declares a
//!   policy, in the shape `direnv` and `mise` use. The mechanism is unchanged --
//!   the same links, the same discovery -- and what it buys is the exec this
//!   tool otherwise costs on every invocation of a shimmed command everywhere on
//!   the machine, whether or not a policy is anywhere near.
//!
//! The shells differ in one word each, so `--path` does the deciding for all of
//! them: the hook hands this binary the PATH it has and installs the PATH it is
//! given back. Recomputing that walk in three shell dialects would be three
//! readers of `discover`, free to disagree with the loader about where a
//! repository begins.
//!
//! What is deliberately not here is a mode where the links are installed and the
//! shim is told not to look. A shim that finds no policy and passes through is
//! right, and it is what happens today; a shim that finds one and decides not to
//! read it because a setting said so is a check that did not happen, reported as
//! a pass.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::{Exit, Fatal, Result};
use crate::shim;

/// Under `$HOME`, and named for the tool rather than shared with the operator's
/// own scripts.
///
/// `~/.local/bin` is the other candidate and it is the wrong one: it holds files
/// somebody else put there, so `--uninstall` would be picking through a
/// directory it does not own, and a link this tool wrote lands beside the real
/// commands rather than in a place a reader can see whole. `uv`, `rustup`,
/// `pyenv` and `volta` all keep their shims in a directory of their own for the
/// same reason.
const DIRECTORY: &str = ".local/uphold/shims";

/// The directory the links live in, or the one the operator named.
///
/// The home directory arrives as an argument rather than being read here, so
/// that the two answers this makes -- `--dir` wins, and an unset or empty `HOME`
/// is a refusal rather than links under `/.local` -- are decidable without a
/// test reaching into the process environment. Every other reader of the
/// environment in this binary is in `main`, which is where this one is too.
pub(crate) fn directory(explicit: Option<&Path>, home: Option<OsString>) -> Result<PathBuf> {
    if let Some(named) = explicit {
        return Ok(named.to_path_buf());
    }
    // `HOME=` is how a stripped environment arrives, and joining onto it puts
    // the links in `/.local/uphold/shims` -- a path the operator will not find
    // and, on most machines, cannot write.
    let home = home.filter(|home| !home.is_empty()).ok_or_else(|| {
        Fatal::new(
            "HOME is not set, so there is no home directory to keep the shim links in. \
             Name one with --dir",
        )
    })?;
    Ok(PathBuf::from(home).join(DIRECTORY))
}

/// What happened to one name in the shims directory.
#[derive(Debug)]
enum Placed {
    Linked,
    /// A link of ours that pointed at a different copy of this binary. Re-pointed
    /// rather than left alone: two copies on PATH is the exec loop `shim.rs`
    /// documents, and the one the operator just ran is the one they meant.
    Repointed(PathBuf),
    Present,
    /// Something that is not ours is already called that. Never overwritten:
    /// this command is handed a directory name, and a directory name is a thing
    /// people mistype.
    Occupied(String),
}

/// Link this binary under each command's name.
pub(crate) fn install(dir: &Path, names: &[String]) -> Result<Exit> {
    let own = std::env::current_exe().map_err(|error| {
        Fatal::new(format!("this binary's own path could not be read: {error}"))
    })?;
    std::fs::create_dir_all(dir).map_err(|error| Fatal::at(dir, error))?;

    let mut occupied: Vec<String> = Vec::new();
    println!("{}", dir.display());
    for name in names {
        match place(dir, name, &own)? {
            Placed::Linked => line("linked", name, ""),
            Placed::Repointed(was) => line("re-pointed", name, &format!("was {}", was.display())),
            Placed::Present => line("already", name, ""),
            Placed::Occupied(what) => {
                line("REFUSED", name, &what);
                occupied.push(name.clone());
            }
        }
    }
    if !occupied.is_empty() {
        return Err(Fatal::new(format!(
            "{} of the names above {} not this tool's to write: {}. Nothing there was \
             overwritten -- a shims directory holding a real command is a directory this \
             command was pointed at by mistake, and replacing a binary somebody depends on \
             is not a step to take on a guess",
            occupied.len(),
            are(occupied.len()),
            occupied.join(", ")
        )));
    }
    report_reach(dir, names)
}

/// One name, linked, left alone, or refused.
fn place(dir: &Path, name: &str, own: &Path) -> Result<Placed> {
    let at = dir.join(name);
    let Ok(existing) = std::fs::symlink_metadata(&at) else {
        make_link(own, &at)?;
        return Ok(Placed::Linked);
    };
    if !existing.is_symlink() {
        return Ok(Placed::Occupied(String::from(
            "a file that is not a link, so this tool did not put it there",
        )));
    }
    // The same question `shim::run` asks before it execs anything: does this
    // land on a copy of this binary? One answer, so a link this command declines
    // to touch is a link the shim declines to exec.
    if !shim::lands_on_uphold(&at) {
        let target = std::fs::read_link(&at).unwrap_or_else(|_| at.clone());
        return Ok(Placed::Occupied(format!(
            "a link to {}, which is not this binary",
            target.display()
        )));
    }
    let target = std::fs::read_link(&at).map_err(|error| Fatal::at(&at, error))?;
    if same_file(&target, own) {
        return Ok(Placed::Present);
    }
    std::fs::remove_file(&at).map_err(|error| Fatal::at(&at, error))?;
    make_link(own, &at)?;
    Ok(Placed::Repointed(target))
}

/// Take back what this command put there, and nothing else.
pub(crate) fn uninstall(dir: &Path) -> Result<Exit> {
    let ours = links(dir)?;
    if ours.is_empty() {
        println!("{}: no links of this tool's to remove", dir.display());
        return Ok(Exit::Clean);
    }
    println!("{}", dir.display());
    for name in &ours {
        let at = dir.join(name);
        std::fs::remove_file(&at).map_err(|error| Fatal::at(&at, error))?;
        line("removed", name, "");
    }
    // Only when nothing of anyone else's is in it. An empty directory left on
    // PATH is harmless and a directory holding somebody's file is not this
    // command's to delete.
    if std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_none()) {
        std::fs::remove_dir(dir).map_err(|error| Fatal::at(dir, error))?;
        line("removed", "the directory itself, which is now empty", "");
    }
    println!(
        "The PATH entry naming that directory is still in whatever file you added it to, and \
         removing it is the other half."
    );
    Ok(Exit::Clean)
}

/// What is linked here, and whether PATH actually reaches it.
pub(crate) fn status(dir: &Path) -> Result<Exit> {
    let ours = links(dir)?;
    if ours.is_empty() {
        println!(
            "{}: nothing is linked here, so no command on this machine is standing in front \
             of anything. `uphold shim --install` makes the links",
            dir.display()
        );
        return Ok(Exit::Clean);
    }
    println!("{}: {} link(s)", dir.display(), ours.len());
    report_reach(dir, &ours)
}

/// The half of both reports that is about PATH rather than about the directory.
///
/// Said in both places and with an exit code behind it, because "the links are
/// installed" and "the links are reached" are different facts and only the
/// second one is the seam. A link nothing reaches refuses nothing, and reporting
/// the install as done would be this tool's own failure mode: a check that does
/// not run, reported as one that passed.
fn report_reach(dir: &Path, names: &[String]) -> Result<Exit> {
    let mut unreached: Vec<String> = Vec::new();
    for name in names {
        match reach(dir, name) {
            Reach::Here => line("reached", name, ""),
            Reach::Shadowed(first) => {
                line(
                    "SHADOWED",
                    name,
                    &format!("{} comes first", first.display()),
                );
                unreached.push(name.clone());
            }
            Reach::Absent => {
                line("NOT ON PATH", name, "no directory on PATH holds it");
                unreached.push(name.clone());
            }
        }
    }
    if unreached.is_empty() {
        return Ok(Exit::Clean);
    }
    println!(
        "\n{} of the links above {} not what the shell would run, so nothing checks what \
         those commands publish. Put this directory ahead of the rest of PATH:\n\n  export \
         PATH=\"{}:$PATH\"\n\nor let a shell hook add it only inside a tree that declares a \
         policy:\n\n  uphold shim --hook bash|zsh|fish",
        unreached.len(),
        are(unreached.len()),
        dir.display()
    );
    Ok(Exit::Violations)
}

/// One line of either report, with the verdict in a column of its own.
///
/// A column because the two reports are read by scanning down them for the word
/// that is not `reached`, and a verdict that starts in a different place on
/// every line is a verdict somebody's eye skips.
fn line(verdict: &str, name: &str, note: &str) {
    if note.is_empty() {
        println!("  {verdict:<11} {name}");
    } else {
        println!("  {verdict:<11} {name}  ({note})");
    }
}

/// Agreement, because a report that says `1 of the links are` is a report
/// written by something that was not counting.
const fn are(count: usize) -> &'static str {
    if count == 1 {
        "is"
    } else {
        "are"
    }
}

/// Whether this directory is the one a shell would find the command in.
#[derive(Debug)]
enum Reach {
    Here,
    /// Another directory on PATH holds a file by that name and comes first.
    Shadowed(PathBuf),
    /// No directory on PATH holds it, this one included -- which is what an
    /// unadded directory looks like, and also what a broken link looks like.
    Absent,
}

fn reach(dir: &Path, name: &str) -> Reach {
    let Some(path) = std::env::var_os("PATH") else {
        return Reach::Absent;
    };
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if !candidate.is_file() {
            continue;
        }
        if same_file(&directory, dir) {
            return Reach::Here;
        }
        return Reach::Shadowed(candidate);
    }
    Reach::Absent
}

/// The PATH a shell should have, standing where it is standing.
///
/// The whole of the shell hook's logic, so that the hook is one line in each
/// dialect and the walk that decides whether a tree participates is the loader's
/// -- see the module note. What is asked is whether a policy is DISCOVERABLE and
/// never what it declares: reading it belongs to the invocation, and a hook that
/// parsed it would pay for the parse on every prompt and print its refusal on
/// every prompt too.
pub(crate) fn shell_path(dir: &Path) -> Result<Exit> {
    let current = std::env::var_os("PATH").unwrap_or_default();
    let mut entries: Vec<PathBuf> = std::env::split_paths(&current)
        .filter(|entry| !same_file(entry, dir))
        .collect();
    let working = std::env::current_dir()?;
    if crate::discover(&working).is_some() {
        entries.insert(0, dir.to_path_buf());
    }
    let joined = std::env::join_paths(entries)
        .map_err(|error| Fatal::new(format!("PATH could not be reassembled: {error}")))?;
    println!("{}", joined.to_string_lossy());
    Ok(Exit::Clean)
}

/// The hook that puts the directory on PATH inside a participating tree, and
/// takes it off outside one.
pub(crate) fn hook(shell: &str, dir: &Path) -> Result<Exit> {
    let own = std::env::current_exe().map_err(|error| {
        Fatal::new(format!("this binary's own path could not be read: {error}"))
    })?;
    let own = own.to_string_lossy().into_owned();
    let dir = dir.to_string_lossy().into_owned();
    let text = match shell {
        "bash" => bash_hook(&own, &dir),
        "zsh" => zsh_hook(&own, &dir),
        "fish" => fish_hook(&own, &dir),
        other => {
            return Err(Fatal::new(format!(
                "no hook for the shell {other:?}. This tool writes one for bash, zsh and fish, \
                 and a hook it has not been taught is better written by somebody who uses that \
                 shell than guessed at here: run `uphold shim --path` once per prompt and set \
                 PATH to what it prints"
            )))
        }
    };
    print!("{text}");
    Ok(Exit::Clean)
}

/// A word for a shell that is going to split what it is handed.
fn posix_word(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// The same, for fish, whose single quotes take a backslash escape rather than
/// the POSIX close-quote-and-reopen. Spelling it the POSIX way inside a fish
/// script leaves a literal backslash in the path.
fn fish_word(word: &str) -> String {
    format!("'{}'", word.replace('\\', r"\\").replace('\'', r"\'"))
}

/// The comment every dialect carries, so a reader who finds this in their
/// profile a year later can tell what it is for.
const PREAMBLE: &str = "\
# uphold: the command shims are on PATH only inside a tree that declares a
# policy. The binary is asked what PATH should be, so the walk that decides
# where a repository begins is the loader's rather than this file's.
";

/// What the hook says when the binary it was written for is not there.
///
/// Every prompt, which is a cost worth naming: a line that repeats is a line
/// people stop reading, and this one is exempted because it cannot fire on
/// legitimate work. It fires when the installation is broken, and what it
/// reports is that the shims are not on PATH -- so the commands they stand in
/// front of are running with nothing checking what they publish, which is the
/// one thing this tool will not let happen quietly. The fix is in the line.
const MISSING: &str = "uphold: this shell's hook cannot find the uphold binary it was written \
                       for, so the shims are not on PATH and nothing is checking what the \
                       commands they stand in front of publish. Re-run `uphold shim --hook` \
                       and replace the block in your shell profile.";

fn bash_hook(own: &str, dir: &str) -> String {
    // `local computed` and the assignment are two statements on purpose:
    // `local computed=$(...)` is the `local` builtin's exit status, which is 0
    // whatever the command did, so a failing binary would install its empty
    // output as the whole of PATH.
    format!(
        "{PREAMBLE}_uphold_shim_path() {{
  if [ ! -x {exe} ]; then
    printf '%s\\n' {missing} >&2
    return 0
  fi
  local computed
  computed=\"$({exe} shim --path --dir {dir})\" || return 0
  PATH=\"$computed\"
}}
case \"${{PROMPT_COMMAND-}}\" in
  *_uphold_shim_path*) ;;
  *) PROMPT_COMMAND=\"_uphold_shim_path${{PROMPT_COMMAND:+;$PROMPT_COMMAND}}\" ;;
esac
_uphold_shim_path
",
        exe = posix_word(own),
        dir = posix_word(dir),
        missing = posix_word(MISSING)
    )
}

fn zsh_hook(own: &str, dir: &str) -> String {
    format!(
        "{PREAMBLE}_uphold_shim_path() {{
  if [ ! -x {exe} ]; then
    printf '%s\\n' {missing} >&2
    return 0
  fi
  local computed
  computed=\"$({exe} shim --path --dir {dir})\" || return 0
  PATH=\"$computed\"
}}
autoload -Uz add-zsh-hook
add-zsh-hook precmd _uphold_shim_path
_uphold_shim_path
",
        exe = posix_word(own),
        dir = posix_word(dir),
        missing = posix_word(MISSING)
    )
}

fn fish_hook(own: &str, dir: &str) -> String {
    // The guard is not defensiveness shared with the others for symmetry. fish
    // reports an unknown command from inside a command substitution ITSELF, in
    // four lines with a caret diagram, and a redirect on the substitution does
    // not reach that -- so a binary that moved would draw the diagram on every
    // prompt in place of the one sentence that says what it means.
    format!(
        "{PREAMBLE}function _uphold_shim_path --on-event fish_prompt \
--description 'uphold shims on PATH inside a participating tree'
    if not test -x {exe}
        echo {missing} >&2
        return 0
    end
    set -l computed ({exe} shim --path --dir {dir})
    or return 0
    set -gx PATH (string split : -- $computed)
end
_uphold_shim_path
",
        exe = fish_word(own),
        dir = fish_word(dir),
        missing = fish_word(MISSING)
    )
}

/// The links in this directory that this tool put there.
///
/// Read off the directory rather than off any policy: what to remove and what to
/// report on is what is THERE, and the policy of the tree somebody happens to be
/// standing in names the commands one repository declares. A link installed for
/// a repository nobody is standing in is still a link on PATH.
fn links(dir: &Path) -> Result<Vec<String>> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut found: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| Fatal::at(dir, error))?;
        let path = entry.path();
        if !std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_symlink()) {
            continue;
        }
        if !shim::lands_on_uphold(&path) {
            continue;
        }
        if let Some(name) = entry.file_name().to_str() {
            found.push(name.to_owned());
        }
    }
    found.sort();
    Ok(found)
}

/// Whether two paths name the same file, spelt however they are spelt.
///
/// A PATH entry is written by a person -- `~/.local/uphold/shims`, a relative
/// entry, a symlinked home -- and a string comparison against the directory this
/// command was handed answers "different" for two spellings of one directory.
/// The consequence is not cosmetic: it is a PATH with the shims directory in it
/// twice, growing by one entry per prompt.
fn same_file(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        // A directory that is not there cannot be the one that is. Comparing the
        // unresolved spellings again would say the same thing the equality above
        // already said.
        _ => false,
    }
}

#[cfg(unix)]
fn make_link(target: &Path, at: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, at).map_err(|error| Fatal::at(at, error))
}

#[cfg(not(unix))]
fn make_link(_target: &Path, at: &Path) -> Result<()> {
    // Not a silent no-op, and not a copy. A copy of this binary under the name
    // `git` is a second copy on PATH, which is the exec loop `shim.rs`
    // documents; a link is what the whole design rests on and this platform
    // needs a privilege to make one.
    Err(Fatal::at(
        at,
        "a shim is installed as a symbolic link to this binary, and making one on this \
         platform needs a privilege this process was not given. Create the links by hand, or \
         run the shell in developer mode",
    ))
}

#[cfg(test)]
mod tests {
    use super::{are, directory, fish_word, links, place, posix_word, same_file, Placed};
    use std::ffi::OsString;
    use std::path::Path;

    /// A directory holding a copy of this binary under its own name, which is
    /// what a link has to land on to be one of ours.
    fn workspace(name: &str) -> std::path::PathBuf {
        let root = crate::fixture::scratch(name);
        std::fs::create_dir_all(root.join("shims")).unwrap();
        let binary = root.join("uphold");
        std::fs::write(&binary, "binary").unwrap();
        root
    }

    #[test]
    fn a_name_is_linked_once_and_then_left_alone() {
        let root = workspace("install");
        let dir = root.join("shims");
        let own = root.join("uphold");
        assert!(matches!(place(&dir, "git", &own).unwrap(), Placed::Linked));
        assert!(matches!(place(&dir, "git", &own).unwrap(), Placed::Present));
        assert_eq!(links(&dir).unwrap(), vec![String::from("git")]);
    }

    /// Two copies of this binary on PATH is the exec loop `shim.rs` documents,
    /// so a link of ours pointing at the other copy is re-pointed at the one
    /// that was just run rather than reported as already installed.
    #[test]
    fn a_link_to_another_copy_of_this_binary_is_repointed() {
        let root = workspace("install-repoint");
        let dir = root.join("shims");
        let other = root.join("elsewhere");
        std::fs::create_dir_all(&other).unwrap();
        let older = other.join("uphold");
        std::fs::write(&older, "an older build").unwrap();
        std::os::unix::fs::symlink(&older, dir.join("gh")).unwrap();

        let own = root.join("uphold");
        assert!(matches!(
            place(&dir, "gh", &own).unwrap(),
            Placed::Repointed(was) if was == older
        ));
        assert_eq!(std::fs::read_link(dir.join("gh")).unwrap(), own);
    }

    /// The directory name is a thing people mistype, and the file that would be
    /// overwritten is a command somebody depends on.
    #[test]
    fn nothing_that_is_not_ours_is_overwritten() {
        let root = workspace("install-occupied");
        let dir = root.join("shims");
        let own = root.join("uphold");
        std::fs::write(dir.join("git"), "the real git").unwrap();
        std::os::unix::fs::symlink("/bin/sh", dir.join("gh")).unwrap();

        assert!(matches!(
            place(&dir, "git", &own).unwrap(),
            Placed::Occupied(_)
        ));
        assert!(matches!(
            place(&dir, "gh", &own).unwrap(),
            Placed::Occupied(_)
        ));
        // And neither is listed as one of ours, so neither would be removed.
        assert!(links(&dir).unwrap().is_empty());
        assert_eq!(std::fs::read(dir.join("git")).unwrap(), b"the real git");
    }

    /// Two spellings of one directory are one directory. A comparison that says
    /// otherwise puts the shims directory on PATH once per prompt.
    #[test]
    fn one_directory_spelt_two_ways_is_one_directory() {
        let root = workspace("install-spelling");
        let dir = root.join("shims");
        let round_about = root.join("shims/../shims");
        assert!(same_file(&dir, &round_about));
        assert!(!same_file(&dir, &root.join("elsewhere")));
        // And a path that is not there is not the one that is, rather than
        // matching by having no answer.
        assert!(!same_file(Path::new("/nowhere/at/all"), &dir));
    }

    /// `--dir` wins, and a home directory that is not there is a refusal rather
    /// than a link under `/.local/uphold/shims`.
    #[test]
    fn where_the_links_go_is_the_named_directory_or_a_home_that_exists() {
        assert_eq!(
            directory(Some(Path::new("/srv/links")), None).unwrap(),
            Path::new("/srv/links")
        );
        assert_eq!(
            directory(None, Some(OsString::from("/srv/example"))).unwrap(),
            Path::new("/srv/example/.local/uphold/shims")
        );
        for absent in [None, Some(OsString::new())] {
            let error = directory(None, absent).expect_err("no home is no directory");
            assert!(error.to_string().contains("--dir"), "{error}");
        }
    }

    #[test]
    fn a_report_agrees_with_the_number_it_is_reporting() {
        assert_eq!(are(1), "is");
        assert_eq!(are(0), "are");
        assert_eq!(are(2), "are");
    }

    #[test]
    fn a_quoted_word_survives_the_shell_that_splits_it() {
        assert_eq!(posix_word("/opt/my tools/uphold"), "'/opt/my tools/uphold'");
        assert_eq!(posix_word("it's"), r"'it'\''s'");
        // fish takes a backslash escape inside single quotes, and the POSIX
        // spelling would leave a literal backslash in the path.
        assert_eq!(fish_word("it's"), r"'it\'s'");
        assert_eq!(fish_word(r"a\b"), r"'a\\b'");
    }
}
