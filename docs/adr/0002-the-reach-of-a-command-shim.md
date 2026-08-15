# ADR 0002: the reach of a command shim

Status: Accepted

This record answers a question asked of the shims: is the seam system-wide, or
can it be made configurable per repository? It carries the judgment;
[REFERENCE.md](../REFERENCE.md) documents what the commands do.

## Two things are called "the shim", and separating them answers most of it

**The link is machine-wide.** A file named `git` on PATH ahead of the real one
is reached by every `git` that shell runs, in every directory, forever. That is
a property of PATH, not of this tool.

**What it DOES is already per repository, and already opt-out by absence.** The
binary discovers `policy/principles.toml` from the working directory upward,
stopping at the repository boundary. With no policy — `/tmp`, somebody else's
checkout, a shell that never enters a participating tree — it execs the real
command and gets out of the way.

So "if a repository is not configured with `uphold`, pass the original command
as-is" is what happens, and it is deliberate: refusing there protects nothing,
breaks `git` everywhere, and gets the link removed — which loses the seam in the
repositories that *did* declare it.

What remains is narrower than "system-wide or configurable": **the cost of the
link is one process exec on every invocation of a shimmed command, everywhere,
forever, to find a policy that usually is not there.**

## How other tools handle the same problem

- **uv, rustup, pyenv, volta** put shims in a directory the user adds to PATH,
  and the shim resolves a version from the tree. Same shape as this: machine-wide
  reach, per-tree behaviour. None of them asks for a prefix.
- **direnv, mise** hook the SHELL rather than PATH: a per-directory change
  applied on `cd`, so nothing intercepts anything outside a participating tree.
  This is the "activate first" shape.
- **pre-commit and lefthook** install into `.git/hooks`, which is per repository
  and reaches only what git itself runs — and is exactly why the shim exists:
  `gh pr create`, `npm publish` and a branch name are not things git runs.
- **A prefix** (`uphold shim gh pr create …`) is what this binary already
  supports directly, and it is the shape that fails at the one job the seam has.
  The invocation nobody remembers to prefix is the invocation that publishes
  something unchecked — which includes every agent, script and muscle-memory
  `gh pr create` on the machine.

## The decision

Keep the current default, and make the reach something somebody writes down.

1. **A directory of links rather than links scattered on PATH.**
   `~/.local/uphold/shims/`, one link per shimmed command, added to PATH by the
   operator. The whole seam becomes one PATH entry to add, inspect, or drop, and
   `ls` answers "what am I standing in front of". `uphold shim --install` makes
   them, `--status` reports on them, `--uninstall` takes them back.
2. **A shell hook as an alternative install**, in the direnv shape, for whoever
   wants the shims to exist only inside participating trees. The mechanism does
   not change — the same links, on PATH only where a policy is found.
   `uphold shim --hook bash|zsh|fish` writes it.
3. **Nothing per repository beyond the policy that already exists.** A repository
   cannot decide whether a link on somebody else's PATH is reached; it can decide
   what happens when it is, and that is the `[[shim]]` block it already writes.

### Installed and reached are different facts

`--install` and `--status` both end by walking PATH for each linked name, and
both exit `1` when the shell would reach something else first. A link nothing
reaches refuses nothing, and an install that reported success over one would be
this tool's own failure mode: a check that does not run, reported as one that
passed. The report names what wins — `SHADOWED gh (/usr/local/bin/gh comes
first)` — because the fix depends on which file it is.

### One reader of the discovery walk

The hook does not decide anything. It runs `uphold shim --path` and installs the
PATH it is handed back. Re-implementing "is there a policy above here, and where
does the repository begin" in three shell dialects would be three readers of
`discover`, free to disagree with the loader — and the disagreement would be
silent, because a hook that decided wrong just leaves the shims off PATH.

The hook asks whether a policy is *discoverable*, never what it declares.
Loading it would pay for the parse on every prompt and print its refusal on
every prompt too.

## What should NOT be built

**A mode where the shim is silent about doing nothing.** A shim that finds no
policy and passes through is right; a shim that finds one and decides not to look
because a setting said so is a check that did not happen, reported as a pass.
Everywhere the shim declines to check something it says so on stderr — an
unresolvable target, an option it cannot classify, `UPHOLD_ALLOW=all` — and this
would be the one switch that turns those sentences off.

**A copy instead of a link.** Two copies of this binary on PATH read each other
as "the real `git`" and exec back and forth; `shim.rs` documents the measured
version of that, which ended when the kernel ran out of process ids. `--install`
links, and refuses to overwrite anything it did not write.

## On AI agents, since the issue asks

An agent runs `gh pr create` because that is what its instructions say. It will
not prefix, and it will not read a note asking it to — which is the argument FOR
the PATH link rather than against it: the seam has to be in the path of the
invocation somebody forgot about, and an agent is the most reliable producer of
those. The evidence is this repository's own history: every pull request in the
fleet on the day the question was asked went through `uphold shim gh pr create`,
and one was refused for naming a private organisation in a body headed for a
public repository.
