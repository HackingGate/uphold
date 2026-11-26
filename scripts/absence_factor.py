#!/usr/bin/env python3
"""The CHAOSS Contributor Absence Factor of a list of commit authors.

https://chaoss.community/kb/metric-contributor-absence-factor/ defines it as
"the smallest number of contributors responsible for 50% of total
contributions". `reuse-maintained-components` weighs the factor as evidence,
over the commits on a component's default branch in the 12 months before the
reading, and no factor excludes a component on its own. This computes the
factor; choosing the window, the branch and the list's source is the
caller's, through git:

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

CHAOSS's own tools (GrimoireLab, Augur) compute this metric as services over a
collected history; for one count over a list git already prints, they are a
deployment against a dozen lines.
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
