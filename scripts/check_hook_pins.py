#!/usr/bin/env python3
r"""Refuse a hook pin that names a ref its upstream does not have.

A `rev:` is resolved by the hook runner at hook-init, before any hook runs. A
pin naming a tag that was never cut therefore fails as a clone error rather
than as a policy refusal:

    error: Failed to init hooks
      caused by: Failed to clone repo `https://github.com/HackingGate/rg-policy`
      caused by: error: pathspec 'v1.1.0' did not match any file(s) known to git

Nothing in the repository can report that, because nothing in the repository
has run: every hook, including the guards that watch the pins, lives behind the
clone that just failed. The message also reads like a broken workstation rather
than a broken config, which is how a bad pin survives being seen. It blocks
every commit from the moment it lands, and it lands as a one-line diff that
looks like routine maintenance.

`no-stale-hook-pins` does not cover this and cannot be configured to. It asks
whether a pin has fallen BEHIND the upstream's newest tag; a pin bumped ahead of
a release that was never cut has not fallen behind, and comparing it against the
newest real tag says "current" -- the wrong answer, arrived at honestly. The two
questions share one `git ls-remote` and are opposite predicates over its output,
so this check runs beside that one rather than inside it.

## Three outcomes, never folded together

    exit 0  every remote pin named a ref that exists on its upstream
    exit 1  at least one pin named a ref that does not exist -- the finding
    exit 2  at least one pin could not be checked at all

Exit 2 is not exit 0. An unreachable remote, a config shape this reader does not
model, a rev that is a bare commit sha and so has no ref to look up -- none of
those is evidence that the pin resolves, and answering 0 for them would be the
silent pass this file exists to remove. `CATALOG_ALLOW_UNCHECKED_PINS=1`
downgrades exit 2 to a printed note, for the offline case, and it is a thing
somebody types on purpose. A confirmed finding outranks an unresolved one: a run
that is both missing a ref and unable to reach some other remote exits 1.

This also answers the case where nothing changed locally. A tag deleted or moved
upstream after the pin landed produces the identical clone failure from a config
nobody touched, and the only way to notice is to ask again -- which is why this
runs at pre-push and manual on every run, not on a change to the pin file.

## Why it does not parse YAML

`language: system` gives this no environment and no guaranteed PyYAML, and a
grep for `^\s*rev:` reads a `rev:` inside a hook's `args:` or inside a comment,
which is a check whose denominator nobody can state. So the reader below models
the one shape a .pre-commit-config.yaml has -- a `repos:` sequence of mappings,
each with a `repo:` and a `rev:` -- and REFUSES, by name and line number,
anything outside that model: flow style, anchors, aliases, merge keys, tabs, a
second document, a duplicate key, a pin outside the block it read. A reader that
guessed would be a second rule agreeing with the first until it did not. A
reader that stops and says so is exit 2, which is already a defined outcome.

Usage:
  check_hook_pins.py [CONFIG ...]

With no argument it reads every tracked .pre-commit-config.yaml in the work
tree, and says which files it read: a sweep that quietly fell back to one file
is a denominator nobody can see is short.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

CONFIG_NAME = ".pre-commit-config.yaml"

#: pre-commit's two non-remote repos. They pin nothing, so they are skipped --
#: and counted, because a config that is all local entries has verified nothing
#: and must say so rather than printing the "all pins resolve" a real run prints.
NON_REMOTE_REPOS = frozenset({"local", "meta"})

#: Seconds for one `git ls-remote`. An unbounded network call in a pre-push
#: hook is a hang waiting for a bad day, and a hook that hangs gets uninstalled.
TIMEOUT_SECONDS = 20.0

EXIT_OK = 0
EXIT_MISSING = 1
EXIT_UNCHECKED = 2

SHA_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")

#: YAML this reader does not model. Anchors and aliases mean a pin can be
#: written in one place and used in another, merge keys mean a mapping's keys
#: are not all on screen, and an explicit tag can change what a scalar is.
UNMODELLED = (
    ("&", "an anchor"),
    ("*", "an alias"),
    ("!", "an explicit tag"),
)


class Unreadable(Exception):
    """The config could not be read as the shape this tool models."""


class Pin(NamedTuple):
    repo: str
    rev: str
    path: Path
    line: int


class Outcome(NamedTuple):
    pin: Pin
    state: str  # "ok", "missing", or "unchecked"
    detail: str


# ---------------------------------------------------------------------------
# Reading the config
# ---------------------------------------------------------------------------


def _value_of(stripped: str) -> str:
    _, _, value = stripped.partition(":")
    value = value.strip()
    if value.startswith("#"):
        return ""
    return value.split(" #", 1)[0].strip().strip("'\"")


def _reject_unmodelled(value: str, path: Path, number: int) -> None:
    for prefix, name in UNMODELLED:
        if value.startswith(prefix):
            raise Unreadable(f"{path}:{number}: {name} is not modelled by this reader")


def read_pins(text: str, path: Path) -> list[Pin]:
    """Every (repo, rev) in one config, or Unreadable naming the line."""
    pins: list[Pin] = []
    saw_repos = False
    in_repos = False
    ended_at = 0
    item_indent: int | None = None
    entry: dict | None = None

    def flush() -> None:
        nonlocal entry
        if entry is None:
            return
        if entry["repo"] in NON_REMOTE_REPOS:
            # Kept in the list rather than dropped: a run has to be able to say
            # how many entries it did not ask about.
            pins.append(Pin(entry["repo"], "", path, entry["line"]))
        elif entry["rev"] is None:
            raise Unreadable(
                f"{path}:{entry['line']}: remote repo {entry['repo']} has no rev"
            )
        else:
            pins.append(Pin(entry["repo"], entry["rev"], path, entry["rev_line"]))
        entry = None

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        leading = line[: len(line) - len(line.lstrip())]
        if "\t" in leading:
            raise Unreadable(f"{path}:{number}: tab indentation")
        if stripped in ("---", "..."):
            if saw_repos:
                raise Unreadable(f"{path}:{number}: a second document")
            continue

        indent = len(leading)
        key = stripped.lstrip("- ").partition(":")[0].strip()

        if indent == 0 and not stripped.startswith("-"):
            if in_repos:
                in_repos = False
                ended_at = number
                flush()
            if key == "repos":
                if saw_repos:
                    raise Unreadable(f"{path}:{number}: a second `repos:` key")
                if _value_of(stripped):
                    raise Unreadable(f"{path}:{number}: flow-style `repos:`")
                saw_repos = True
                in_repos = True
            continue

        if not in_repos:
            if key in ("repo", "rev"):
                raise Unreadable(
                    f"{path}:{number}: `{key}:` outside the `repos:` block that "
                    f"ended at line {ended_at or 'nowhere this reader saw'}"
                )
            continue

        if stripped.startswith("- "):
            if item_indent is None:
                item_indent = indent
            if key == "repo":
                if indent != item_indent:
                    raise Unreadable(
                        f"{path}:{number}: `- repo:` at indent {indent}, but the "
                        f"repos list is at indent {item_indent}"
                    )
                flush()
                value = _value_of(stripped)
                _reject_unmodelled(value, path, number)
                entry = {"repo": value, "rev": None, "line": number, "rev_line": number}
            continue

        # Keys of a repos entry sit one level in from its `-`. Anything deeper
        # belongs to `hooks:`, where a literal `rev:` in an args list is data.
        if entry is not None and indent == item_indent + 2 and key == "rev":
            if entry["rev"] is not None:
                raise Unreadable(f"{path}:{number}: a second `rev:` in one entry")
            value = _value_of(stripped)
            _reject_unmodelled(value, path, number)
            if not value:
                raise Unreadable(f"{path}:{number}: empty `rev:`")
            entry["rev"] = value
            entry["rev_line"] = number

    if in_repos:
        flush()
    if not saw_repos:
        raise Unreadable(f"{path}: no `repos:` key this reader could find")
    return pins


# ---------------------------------------------------------------------------
# Asking the upstream
# ---------------------------------------------------------------------------


def git_ls_remote(args: list[str]) -> tuple[int, str, str]:
    try:
        done = subprocess.run(
            ["git", "ls-remote", *args],
            text=True,
            capture_output=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError:
        return 127, "", "git is not on PATH"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {TIMEOUT_SECONDS:g}s"
    return done.returncode, done.stdout, done.stderr.strip()


def resolve_pin(pin: Pin, run=git_ls_remote) -> Outcome:
    """Does the upstream have a ref by this name?"""
    if SHA_RE.match(pin.rev):
        code, out, err = run([pin.repo])
        if code != 0:
            return Outcome(pin, "unchecked", err or f"git ls-remote exited {code}")
        tips = {line.split("\t", 1)[0] for line in out.splitlines() if line.strip()}
        if pin.rev in tips:
            return Outcome(pin, "ok", "a ref tip")
        # Reachable-but-not-a-tip is the common, correct case for a sha pin, and
        # settling it needs a fetch. Unchecked is the honest answer.
        return Outcome(
            pin, "unchecked", "a commit sha that is not a ref tip; needs a fetch"
        )

    code, out, err = run(
        ["--refs", pin.repo, f"refs/tags/{pin.rev}", f"refs/heads/{pin.rev}"]
    )
    if code not in (0, 2):
        # 2 is ls-remote's "no matching refs", which is the finding, not a fault.
        return Outcome(pin, "unchecked", err or f"git ls-remote exited {code}")
    if out.strip():
        names = sorted(
            line.split("\t", 1)[1] for line in out.splitlines() if "\t" in line
        )
        return Outcome(pin, "ok", ", ".join(names))
    return Outcome(pin, "missing", "no tag or branch by that name on the remote")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def tracked_configs() -> tuple[list[Path], str]:
    """Every tracked config, and a sentence about how the list was found."""
    try:
        done = subprocess.run(
            ["git", "ls-files", "-z", "--", f"*{CONFIG_NAME}", CONFIG_NAME],
            text=True,
            capture_output=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        done = None
        note = f"could not sweep the work tree ({error})"
    else:
        if done.returncode == 0:
            paths = sorted({Path(name) for name in done.stdout.split("\0") if name})
            return paths, "swept with `git ls-files`"
        note = f"could not sweep the work tree ({done.stderr.strip()})"

    fallback = Path(CONFIG_NAME)
    return ([fallback] if fallback.is_file() else []), note


def main(argv: list[str]) -> int:
    if argv:
        paths, how = [Path(name) for name in argv], "named on the command line"
    else:
        paths, how = tracked_configs()

    if not paths:
        print(f"check-hook-pins: no {CONFIG_NAME} to read ({how})", file=sys.stderr)
        return EXIT_UNCHECKED

    outcomes: list[Outcome] = []
    unreadable: list[str] = []
    skipped = 0
    for path in paths:
        try:
            pins = read_pins(path.read_text(encoding="utf-8"), path)
        except OSError as error:
            unreadable.append(f"{path}: {error}")
            continue
        except Unreadable as error:
            unreadable.append(str(error))
            continue
        for pin in pins:
            if pin.repo in NON_REMOTE_REPOS:
                skipped += 1
                continue
            outcomes.append(resolve_pin(pin))

    print(f"check-hook-pins: {len(paths)} config(s) {how}")
    for outcome in outcomes:
        mark = {"ok": "ok  ", "missing": "MISS", "unchecked": "????"}[outcome.state]
        print(
            f"  {mark} {outcome.pin.repo} @ {outcome.pin.rev} "
            f"({outcome.pin.path}:{outcome.pin.line}) -- {outcome.detail}"
        )
    if skipped:
        print(f"  {skipped} local/meta entr(y|ies) pin nothing and were skipped")

    missing = [item for item in outcomes if item.state == "missing"]
    unchecked = [item for item in outcomes if item.state == "unchecked"]

    if missing:
        print("", file=sys.stderr)
        for item in missing:
            print(
                f"{item.pin.path}:{item.pin.line}: {item.pin.repo} has no ref "
                f"{item.pin.rev!r}. Nothing can run until this pin names a ref "
                f"that exists.",
                file=sys.stderr,
            )
        return EXIT_MISSING

    if unchecked or unreadable:
        for item in unreadable:
            print(f"could not read: {item}", file=sys.stderr)
        if os.environ.get("CATALOG_ALLOW_UNCHECKED_PINS") == "1":
            print(
                f"{len(unchecked) + len(unreadable)} pin(s) unchecked; "
                "CATALOG_ALLOW_UNCHECKED_PINS=1 is set, so this is a note",
                file=sys.stderr,
            )
            return EXIT_OK
        print(
            f"{len(unchecked) + len(unreadable)} pin(s) could not be checked. "
            "Cannot look is not resolves; set CATALOG_ALLOW_UNCHECKED_PINS=1 to "
            "accept that deliberately.",
            file=sys.stderr,
        )
        return EXIT_UNCHECKED

    print(f"every one of {len(outcomes)} remote pin(s) names a ref that exists")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
