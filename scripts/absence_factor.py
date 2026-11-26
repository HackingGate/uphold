#!/usr/bin/env python3
"""The CHAOSS Contributor Absence Factor of a list of commit authors.

https://chaoss.community/kb/metric-contributor-absence-factor/ defines it as
"the smallest number of contributors responsible for 50% of total
contributions". `reuse-maintained-components` reads a factor of 1 as
single-maintainer, over the commits on a component's default branch in the 12
months before the reading. This computes the factor; choosing the window and
the branch is the caller's, through git:

    git log --since='12 months ago' --format=%aE origin/HEAD \\
        | uv run --no-project scripts/absence_factor.py

Input is one author per line, as `--format=%aE` prints it; blank lines are
skipped. A contributor is a person, not an address: merge one person's
identities before the count, with a .mailmap (which `%aE` honours) or by
keying each commit on the forge's account for it. An author split across
identities can only raise the factor, so an unmerged 1 holds and an unmerged 2
may be a 1 written under several addresses.

Output is `factor N` on stdout and exit 0. A list that cannot be read, or one
with no commits, is `unknown: <why>` on stderr and exit 2: no commits in
the window says nothing about who maintains the component, so it is never
reported as a factor.

This is written by hand because, as of the reading on 2026-11-26, no
maintained tool computes the factor:

- elek/bus-factor computes the same count, its "pony factor", but has made
  one release, v1.0.0, in 2020.
- git-fame and gitinspector report each author's share, not the factor.
- Truck-Factor and truckfactor compute a file-ownership metric, not this one.
- OpenSSF Scorecard reports no per-author concentration.
- CHAOSS's GrimoireLab is a service over a collected history, and Augur is
  archived.

Every input line is counted as an author, and that includes automation and
agent accounts. Which accounts count is the caller's choice of input, made
before the count. This script does not make it.
"""

from __future__ import annotations

import sys
from collections import Counter
from collections.abc import Iterable


def absence_factor(authors: Iterable[str]) -> int | None:
    """The smallest number of authors whose commits reach half of all, or None."""
    counts = Counter(author.strip() for author in authors if author.strip())
    total = sum(counts.values())
    if total == 0:
        return None
    reached = 0
    for factor, (_, commits) in enumerate(counts.most_common(), start=1):
        reached += commits
        if 2 * reached >= total:
            return factor
    raise AssertionError("the running sum reaches the total")


def main() -> int:
    try:
        # Bytes, decoded here: a C locale reads text stdin with surrogateescape,
        # which would turn an undecodable list into authors instead of unknown.
        authors = sys.stdin.buffer.read().decode("utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        print(f"unknown: the author list could not be read: {error}", file=sys.stderr)
        return 2
    factor = absence_factor(authors)
    if factor is None:
        print("unknown: no commits in the list", file=sys.stderr)
        return 2
    print(f"factor {factor}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
