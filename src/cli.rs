//! The command line, as data: what each subcommand accepts, parsed by clap.
//!
//! WHY A PARSER AND NOT A LOOP PER SUBCOMMAND. The loops this replaces each
//! re-decided what every command-line tool already agrees on, and each got a
//! different part of it wrong: `uphold help` was an unknown subcommand,
//! `uphold init --help` was a usage error, a flag missing its value said so
//! without saying where help was, and every usage error printed the whole
//! command list after the one line that mattered. clap answers those the way
//! the reader's other tools do, from one declaration per subcommand, so the
//! next flag added inherits the answers instead of needing them written again.
//!
//! WHAT STAYS OUTSIDE IT. Two argument lists are not this binary's to parse.
//! Invoked through a link named for a shimmed command, argv belongs to that
//! command and never reaches clap -- see `run`. And after `uphold shim
//! <command>` the words are the wrapped command's, `--help` included, so
//! [`Shim`] takes them raw and only the mode form (`uphold shim --install`) is
//! parsed, by [`ShimModes`].
//!
//! clap never writes or exits here. [`parse`] turns its answer into this
//! binary's own: help and version printed through `out`, exit 0; a usage
//! mistake as a `Fatal`, exit 2, under the `policy check error:` prefix every
//! other exit 2 carries.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::{Args, Parser, Subcommand};

use crate::error::{Fatal, Result};

/// What every page of help ends with: the parts of the contract no single
/// flag owns.
const AFTER_HELP: &str = "\
Invoked under a command's own name -- a link called `gh` on PATH ahead of the
real one -- the binary runs that command's shim directly. That is what a
multicall binary is for: argv[0] decides, and there is nothing to install but a
link. `uphold shim --install` makes those links in one directory
(`~/.local/uphold/shims` by default, `--dir` names another) so the whole seam is
one PATH entry to add, inspect or drop. What the shim then DOES is per
repository already: no policy where the command was typed and it execs the real
one and says nothing.

STAGE is one of commit-msg, pre-commit, pre-merge-commit, pre-push, manual.
`--message FILE` forwards the commit message. At pre-push the ref lines come
from git on stdin, or from what pre-commit and prek export in their place --
neither forwards git's stdin, so both channels are read and a push that reached
neither is refused rather than guessed at. Under lefthook the pre-push job needs
`use_stdin: true`.

Exit codes:
  0  every check passed
  1  one or more policy violations
  2  the check could not be made (bad policy, missing source, unreadable file,
     or a command line this binary could not read)

UPHOLD_ALLOW=<id>,<id> bypasses named guards for one invocation.
`--junit FILE` writes what a `guard --stage` run decided as `JUnit` XML.
UPHOLD_JUNIT=/abs/FILE is the same request from outside a hook's argv; the flag wins.
An existing directory instead gets one file per invocation. `guard --text` writes
the same document; the shim and `uphold hook` take only a directory.";

/// The top level: a subcommand, or one of the questions asked of the binary
/// itself.
#[derive(Parser, Debug)]
#[command(
    name = "uphold",
    bin_name = "uphold",
    version,
    about = "Refuse, before it happens, what a coding agent or a person should not do to a repository",
    after_help = AFTER_HELP
)]
pub(crate) struct Cli {
    /// Print the repository URL this binary was built from, for the OSCAL
    /// export's property namespace.
    #[arg(long, hide = true)]
    pub(crate) upstream: bool,
    /// The subcommand; none prints this help.
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

/// Every subcommand, in the order help lists them.
#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Run the content policy over this repository, or the host-identity rules over text
    Scan(Scan),
    /// Run the guards that fire at a git hook stage, or the text-capable guards over text
    Guard(Guard),
    /// Print the JSON Schema of principles.toml
    Schema,
    /// Reconcile the enforcement claims against the rules this repository runs
    Check(Check),
    /// Report what a private-to-public flip would republish
    Audit(Audit),
    /// Write a first policy, claims and hook config at a repository's root
    Init(Init),
    /// Compare repositories' hook declarations, or write the hooks git runs
    Hooks(Hooks),
    /// Origin, advisories, workflow security, git pins and committed secrets -- five scanners and a git-pin check, one verdict
    SupplyChain(SupplyChain),
    /// Drive each declared hook to a refusal, to learn whether it can refuse at all
    Probe(Probe),
    /// What a bundled rule set refuses, or every rule this repository resolves to
    Rules(Rules),
    /// Judge a pending tool call or a turn's end, read on stdin
    Hook(Hook),
    /// Check what a command would publish, then run it; or manage the links that put the shim on PATH
    Shim(Shim),
}

/// `uphold scan`.
#[derive(Args, Debug)]
pub(crate) struct Scan {
    /// The policy file to scan by, at <root>/policy/<name>.toml, in place of
    /// the one found from the working directory. A path keeps its bytes.
    #[arg(long, value_name = "PATH")]
    pub(crate) policy: Option<PathBuf>,
    /// Run the host-identity rules over this file's text, or over stdin for
    /// `-` or no value, instead of over the repository.
    #[arg(long, value_name = "FILE|-", num_args = 0..=1, default_missing_value = "-")]
    pub(crate) text: Option<String>,
}

/// `uphold guard`.
#[derive(Args, Debug)]
pub(crate) struct Guard {
    /// The git hook stage whose guards run. Required unless `--text` is given.
    #[arg(long, value_name = "STAGE")]
    pub(crate) stage: Option<String>,
    /// The commit message file git hands the commit-msg hook.
    #[arg(long, value_name = "FILE")]
    pub(crate) message: Option<PathBuf>,
    /// The remote name git hands the pre-push hook.
    #[arg(long, value_name = "NAME")]
    pub(crate) remote: Option<String>,
    /// The remote URL git hands the pre-push hook.
    #[arg(long, value_name = "URL")]
    pub(crate) remote_url: Option<String>,
    /// Run the text-capable guards over this file's text, or over stdin for
    /// `-` or no value: a pull-request body, a release note, a branch name.
    #[arg(long, value_name = "FILE|-", num_args = 0..=1, default_missing_value = "-")]
    pub(crate) text: Option<String>,
    /// Write what this run decided as `JUnit` XML, to this file or, if it is an
    /// existing directory, to one file per invocation in it.
    #[arg(long, value_name = "FILE|DIR")]
    pub(crate) junit: Option<OsString>,
}

/// `uphold check`.
#[derive(Args, Debug)]
pub(crate) struct Check {
    /// Print the reconciliation as JSON.
    #[arg(long)]
    pub(crate) json: bool,
    /// Also measure whether each claimed hook can refuse.
    #[arg(long)]
    pub(crate) probe: bool,
    /// Also refuse a claim the checkout in this directory enforced and this
    /// tree no longer does.
    #[arg(long, value_name = "DIR")]
    pub(crate) base: Option<PathBuf>,
    /// Report which rules run here and carry no principle, instead of
    /// reconciling.
    #[arg(long, conflicts_with_all = ["json", "probe", "base"])]
    pub(crate) coverage: bool,
}

/// `uphold audit`.
#[derive(Args, Debug)]
pub(crate) struct Audit {
    /// The one question this command asks; there is no default, because the
    /// one it would pick is the one nothing else asks.
    #[arg(long, required = true)]
    pub(crate) for_publication: bool,
}

/// `uphold init`.
#[derive(Args, Debug)]
pub(crate) struct Init {
    /// The repository's GitHub owner, stated rather than read from `origin`.
    #[arg(long, value_name = "OWNER", required = true)]
    pub(crate) owner: String,
    /// The repository's visibility: public, private or internal.
    #[arg(long, value_name = "VISIBILITY", required = true)]
    pub(crate) visibility: String,
    /// Write a lefthook.yml instead of a .pre-commit-config.yaml.
    #[arg(long)]
    pub(crate) lefthook: bool,
}

/// `uphold hooks`: one of two modes.
#[derive(Args, Debug)]
#[command(group = clap::ArgGroup::new("mode").required(true).args(["install", "identity"]))]
pub(crate) struct Hooks {
    /// Write the hooks git runs, as tracked files.
    #[arg(long)]
    pub(crate) install: bool,
    /// The hook runner to write hooks for: prek or pre-commit.
    #[arg(long, value_name = "NAME", requires = "install")]
    pub(crate) runner: Option<String>,
    /// The directory the hooks are written to.
    #[arg(long, value_name = "DIR", requires = "install")]
    pub(crate) dir: Option<String>,
    /// Take over a hand-written copy of the hooks.
    #[arg(long, requires = "install", conflicts_with = "check")]
    pub(crate) adopt: bool,
    /// Only report whether the hooks are current; write nothing.
    #[arg(long, requires = "install")]
    pub(crate) check: bool,
    /// Report whether these repositories declare the same hooks.
    #[arg(long, value_name = "DIR", num_args = 1..)]
    pub(crate) identity: Vec<PathBuf>,
}

/// `uphold supply-chain`.
#[derive(Args, Debug)]
pub(crate) struct SupplyChain {
    /// Every manifest and commit, not the pushed range.
    #[arg(long)]
    pub(crate) all: bool,
    /// What REV..HEAD changed, not the pushed range.
    #[arg(long, value_name = "REV")]
    pub(crate) base: Option<String>,
    /// gitleaks alone, over the staged diff. A different subject, not a
    /// narrower range, so it takes neither `--all` nor `--base`.
    #[arg(long, conflicts_with_all = ["all", "base"])]
    pub(crate) staged: bool,
}

/// `uphold probe`.
#[derive(Args, Debug)]
pub(crate) struct Probe {
    /// The hook runner to drive: prek, pre-commit or lefthook.
    #[arg(long, value_name = "NAME")]
    pub(crate) runner: Option<String>,
    /// One run's patience in whole seconds, overriding the file's.
    #[arg(long, value_name = "SECONDS")]
    pub(crate) timeout: Option<u64>,
}

/// `uphold rules`: one of three questions.
#[derive(Args, Debug)]
#[command(group = clap::ArgGroup::new("question").required(true).args(["set", "sets", "effective"]))]
pub(crate) struct Rules {
    /// What one bundled rule set refuses, rule by rule.
    #[arg(long, value_name = "NAME")]
    pub(crate) set: Option<String>,
    /// Every bundled set, field for field, so two versions of this binary can
    /// be diffed. JSON only.
    #[arg(long, requires = "json")]
    pub(crate) sets: bool,
    /// Every rule this repository resolves to, and the git hooks each one
    /// fires at.
    #[arg(long)]
    pub(crate) effective: bool,
    /// Print the answer as JSON.
    #[arg(long)]
    pub(crate) json: bool,
}

/// `uphold hook`.
#[derive(Args, Debug)]
pub(crate) struct Hook {
    /// The agent harness whose event arrives on stdin, such as claude-code or
    /// codex.
    #[arg(value_name = "HARNESS")]
    pub(crate) harness: String,
    /// Write what this run decided as `JUnit` XML, one file per invocation, into
    /// this existing directory.
    #[arg(long, value_name = "DIR")]
    pub(crate) junit: Option<OsString>,
}

/// `uphold shim`: the words after it, unparsed.
///
/// Raw because after a command name they are that command's: `uphold shim gh
/// --help` is gh's help, so neither help nor any other flag is clap's here.
/// The mode form is parsed by [`ShimModes`] once the first word says it is one.
#[derive(Args, Debug)]
#[command(disable_help_flag = true)]
pub(crate) struct Shim {
    /// A mode (--install, --uninstall, --status, --path, --hook) and its
    /// options, or the command to stand in front of and its arguments.
    #[arg(
        value_name = "COMMAND [ARGS...] | --MODE",
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 0..
    )]
    pub(crate) argv: Vec<OsString>,
}

/// `uphold shim --<mode>`: the links on PATH, made, taken back, reported on, or
/// handed to a shell.
#[derive(Parser, Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is a mode flag users already type; the `mode` group makes them exclusive"
)]
#[command(
    name = "shim",
    bin_name = "uphold shim",
    about = "Manage the links that put this binary on PATH under each shimmed command's name",
    group = clap::ArgGroup::new("mode")
        .required(true)
        .args(["install", "uninstall", "status", "path", "hook"])
)]
pub(crate) struct ShimModes {
    /// Link this binary under each named command's name, or under every
    /// command this repository's policy declares a shim for.
    #[arg(long)]
    pub(crate) install: bool,
    /// Take back the links this tool made, and nothing else.
    #[arg(long)]
    pub(crate) uninstall: bool,
    /// What is linked, and whether PATH reaches it.
    #[arg(long)]
    pub(crate) status: bool,
    /// The PATH a shell should have, standing here.
    #[arg(long)]
    pub(crate) path: bool,
    /// The shell code that puts the links on PATH only inside a policy tree.
    #[arg(long, value_name = "bash|zsh|fish")]
    pub(crate) hook: Option<String>,
    /// The links directory, in place of `~/.local/uphold/shims`.
    #[arg(long, value_name = "PATH")]
    pub(crate) dir: Option<PathBuf>,
    /// The commands to link, for `--install`.
    #[arg(value_name = "COMMAND")]
    pub(crate) names: Vec<String>,
}

/// clap's answer, once it is this binary's: arguments to run with, or a
/// request (help, version) that has already been answered.
pub(crate) enum Parsed<T> {
    /// Parsed; run with these.
    Run(T),
    /// Help or the version was asked for and printed; exit 0.
    Answered,
}

/// Parse `arguments` (argv[0] first) as `T`, without letting clap print or
/// exit.
///
/// clap's own `exit` writes past `out`, so a closed pipe would panic and a
/// failed write would go unreported, and it would exit before `main` asks
/// whether everything printed was written.
pub(crate) fn parse<T: Parser>(arguments: impl IntoIterator<Item = OsString>) -> Result<Parsed<T>> {
    match T::try_parse_from(arguments) {
        Ok(parsed) => Ok(Parsed::Run(parsed)),
        Err(error) => match error.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                print!("{}", error.render());
                Ok(Parsed::Answered)
            }
            ErrorKind::InvalidUtf8 => Err(Fatal::new(format!(
                "an argument is not valid UTF-8, and an option name, a subcommand name and a \
                 command name are all read as text\n\n{}",
                rendered(&error)
            ))),
            _ => Err(Fatal::new(rendered(&error))),
        },
    }
}

/// clap's message without its own `error: ` lead, which `main` already
/// writes as `policy check error: `.
fn rendered(error: &clap::Error) -> String {
    let text = error.render().to_string();
    let text = text.trim_end();
    text.strip_prefix("error: ").unwrap_or(text).to_owned()
}

/// The full help, for `uphold` run with nothing after it.
pub(crate) fn help() -> String {
    use clap::CommandFactory;
    Cli::command().render_long_help().to_string()
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::{Cli, ShimModes};

    /// clap's own consistency check over every declaration: a conflict or a
    /// requirement naming an argument that does not exist, two arguments with
    /// one name. It panics at the first parse otherwise, which is a user's
    /// first run rather than this test.
    #[test]
    fn the_declarations_are_consistent() {
        Cli::command().debug_assert();
        ShimModes::command().debug_assert();
    }
}
