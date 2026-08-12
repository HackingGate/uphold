#!/usr/bin/env python3
"""The promoted base rules must still match everything the local copies matched.

WHY THIS FILE EXISTS

Rules in `policy/base/` arrived there by promotion: they were found hand-copied
into a fleet of 39 consuming repositories, and the point of promoting them is
that those copies can be deleted in favour of one `[inherit] sets` line.

That deletion is the dangerous half. A repository whose local rule matched
something the base rule does not would LOSE that coverage at the moment it
migrates, silently, because a rule that stops matching produces no output at all
-- the gate goes green and stays green, and the thing it was watching is simply
no longer watched. It is the same failure this whole tool is built around, aimed
at the tool: a check that cannot look must not read as a check that looked.

So the promotion is not trusted; it is checked. `promotion-corpus.json` beside
this file holds concrete lines derived MECHANICALLY from the alternation members
present in those local copies -- not hand-picked, because a hand-picked corpus
tests the author's memory of what the rules covered rather than what they
covered. It is a byte-for-byte copy of the corpus from the repository the rules
were promoted out of, which has since been retired; there is nowhere left to
re-derive it from, so it is evidence rather than a fixture.

WHAT A FAILURE HERE MEANS

Not "fix the corpus". It means the base rule is narrower than the copies it
replaced, and either the base pattern grows back or that repository must keep
its local rule. The corpus is the record of what the fleet was actually
protected against, and it outranks the tidiness of a merge.

WHY PYTHON RE AGAINST PATTERNS THE ENGINE COMPILES WITH RUST REGEX

The engine matches these patterns with ripgrep's search stack, and this file
matches them with `re`. That is a real difference and it is bounded on purpose:
every pattern reached here uses only syntax the two engines read the same way,
and a pattern that reached for either engine's extensions would fail to COMPILE
here rather than quietly disagree. A compile error in this file is a signal --
it says a base pattern has become one this test can no longer speak for.

The values are placeholders. A corpus of credential SHAPES cannot carry a real
credential, which is the rule every fixture in this tree follows.
"""

from __future__ import annotations

import json
import re
import tomllib
import unittest
from pathlib import Path

# The pattern-bearing fields of the unified schema. `regexp` means a regex over
# file contents, `path_regexp` one matched against tracked paths, and
# `require_regexp` one that must be FOUND in every selected file -- the field
# the author wrote is the discriminant, so this list is how a rule's pattern is
# located without a `kind` to ask.
PATTERN_FIELDS = ("regexp", "path_regexp", "require_regexp")


def repo_root() -> Path:
    """The tree this file is checked into, found by what it contains.

    Not `parents[N]`. This file has already moved once -- it was recovered from
    the repository the corpus came from -- and a hop count is the part of a path
    that goes wrong silently: it resolves to SOME directory, the glob below
    finds no packs there, and a test with nothing to check passes.
    """
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "policy" / "base").is_dir():
            return candidate
    raise AssertionError(
        "no policy/base above this file, so there are no promoted rules to check"
    )


ROOT = repo_root()
BASE_DIR = ROOT / "policy" / "base"
CORPUS = ROOT / "tests" / "fixtures" / "promotion-corpus.json"


def base_rules() -> dict[str, dict]:
    """{rule id: the whole rule} across every bundled base pack.

    The id is the SECTION HEADER here -- `[rule.no-pinned-tool-install]` -- where
    the repository this corpus came from wrote `[[rule]]` with an `id` field. A
    pattern is half of what a rule declares; the exclusions are the other half,
    and one test below reads them.
    """
    rules: dict[str, dict] = {}
    for pack in sorted(BASE_DIR.glob("*.toml")):
        policy = tomllib.loads(pack.read_text(encoding="utf-8"))
        rules.update(policy.get("rule", {}))
    return rules


def base_patterns() -> dict[str, str]:
    """{rule id: pattern}, for every base rule that carries one."""
    return {
        rule_id: rule[field]
        for rule_id, rule in base_rules().items()
        for field in PATTERN_FIELDS
        if field in rule
    }


class PromotedRulesStillMatch(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.patterns = base_patterns()

    def test_every_corpus_line_still_matches_its_rule(self) -> None:
        missed: list[str] = []
        for rule_id, lines in sorted(self.corpus.items()):
            self.assertIn(
                rule_id,
                self.patterns,
                f"{rule_id} is in the corpus and in no base pack",
            )
            rx = re.compile(self.patterns[rule_id], re.MULTILINE)
            for line in lines:
                if not rx.search(line):
                    missed.append(f"{rule_id}: {line!r}")
        self.assertEqual(
            [],
            missed,
            "the promoted rule is NARROWER than the copies it replaces; those "
            "repositories would lose this coverage on migrating:\n" + "\n".join(missed),
        )

    def test_the_corpus_is_not_empty_for_any_promoted_rule(self) -> None:
        """A rule whose corpus emptied would pass the test above vacuously.

        The same failure the test is written to catch, one level up: nothing to
        check reads exactly like nothing wrong.
        """
        for rule_id, lines in sorted(self.corpus.items()):
            self.assertTrue(lines, f"{rule_id} has an empty corpus")

    def test_the_two_promoted_key_names_are_the_reason_this_exists(self) -> None:
        """APP_ID and SUBSCRIPTION_KEY, asserted by name.

        Nine of the 39 repositories had locally redefined `no-env-secret-values`
        for the single purpose of adding APP_ID, and two for SUBSCRIPTION_KEY.
        Those are the alternatives whose loss would be invisible, so they are
        pinned here rather than left to the generated corpus alone -- a
        regenerated corpus that dropped them would take the evidence with it.
        """
        rx = re.compile(self.patterns["no-env-secret-values"], re.MULTILINE)
        for line in (
            "ESTAT_APP_ID=notarealvalue",
            "TDNET_SUBSCRIPTION_KEY=notarealvalue",
        ):
            self.assertRegex(line, rx)

    def test_a_sops_vault_is_not_flagged_as_a_committed_secret(self) -> None:
        """The exclusion half, which the first version of this file did not check.

        A corpus of PATTERNS proves the promoted rule still matches what the
        local copies matched. It proves nothing about what they DECLINED to
        match, and the fleet's local copies carried exclusions too -- nine of
        them excluded their SOPS vault by name. Migrating on a pattern-only
        proof turned a whole fleet red on ciphertext.

        The assertion is on the exclude list rather than on a match: the pattern
        SHOULD match a vault line -- that is what a vault line looks like -- and
        the file is skipped before the pattern is ever applied.
        """
        excluded = base_rules()["no-env-secret-values"]["files"]["exclude"]
        for name in ("*.enc.env", ".env.enc"):
            self.assertIn(
                name,
                excluded,
                "a secret detector that fires on the file whose purpose is to make "
                "secrets safe to commit teaches its reader to skim its findings",
            )

    def test_a_placeholder_env_line_is_still_allowed(self) -> None:
        """The rule must not fire on an empty or commented example value.

        Widening a credential pattern is the easy half; keeping `.env.example`
        legal is what stops the widening from being reverted a week later.
        """
        rx = re.compile(self.patterns["no-env-secret-values"], re.MULTILINE)
        for line in ("ESTAT_APP_ID=", "ESTAT_APP_ID=  # set me", "# ESTAT_APP_ID=x"):
            self.assertNotRegex(line, rx)

    def test_the_pins_this_repository_hands_out_are_matched(self) -> None:
        """The two pin shapes `unmanaged-pins` was widened to cover.

        Corpus lines record what the fleet's local copies matched. These two
        record something else -- what this repository's own install instructions
        create -- and they are asserted by hand rather than added to the corpus
        because the corpus is evidence from a repository that no longer exists
        and editing it would forge that evidence.

        Both are the rule's own subject and both passed it. `cargo install
        --git URL --tag vX.Y.Z` is the one cargo spelling that cannot use
        `--version`, and a lefthook `remotes: ref:` is the twin of a
        `.pre-commit-config.yaml` `rev:` that no dependency bot moves.
        """
        rx = re.compile(self.patterns["no-pinned-tool-install"], re.MULTILINE)
        for line in (
            "cargo install --git https://example.test/org/tool --tag v1.2.3",
            "      ref: v1.2.3",
            '      ref: "v1.2.3"',
        ):
            self.assertRegex(line, rx)

    def test_an_unpinned_install_line_is_still_allowed(self) -> None:
        """The widening must not have swallowed the form the rule asks for.

        A rule that refuses the fix it recommends is one a consumer disables
        wholesale, and both new alternatives are shapes whose unpinned version
        is ordinary: a floating install, and a remote tracked by branch.
        """
        rx = re.compile(self.patterns["no-pinned-tool-install"], re.MULTILINE)
        for line in (
            "cargo install --git https://example.test/org/tool",
            "      ref: main",
            "cargo install tool",
        ):
            self.assertNotRegex(line, rx)


if __name__ == "__main__":
    unittest.main()
