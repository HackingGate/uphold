"""Behaviour tests for the routing and the ceiling.

The routing decides what a reviewer is shown, and the ceiling is the half of
`enforcement-needs-a-trigger`'s carve-out that keeps this tier from becoming
prose emitted always. Both are tested for what they refuse, not only for what
they let through.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "uphold_check.py"

sys.path.insert(0, str(ROOT / "scripts"))

import review as review_mod  # noqa: E402


def record(record_id: str, automatable: str, **extra: object) -> dict:
    base = {
        "id": record_id,
        "title": record_id.replace("-", " ").title(),
        "claim": f"the {record_id} claim",
        "applies_when": ["when it applies"],
        "review_questions": ["what to ask"],
        "domains": ["software"],
        "enforcement": {"automatable": automatable},
    }
    base.update(extra)
    return base


class Routing(unittest.TestCase):
    def test_an_automatable_record_a_rule_claims_is_kept_out_of_the_review(self):
        # A reviewer repeating what a rule already refuses costs attention and
        # buys a second opinion nobody asked for.
        records = {"a": record("a", "yes")}
        for_review, errors, stale = review_mod.route(records, {"a"}, {})
        self.assertEqual(for_review, [])
        self.assertEqual(errors, [])
        self.assertEqual(stale, [])

    def test_an_automatable_record_no_rule_claims_is_an_error(self):
        records = {"a": record("a", "yes")}
        _, errors, _ = review_mod.route(records, set(), {})
        self.assertEqual(len(errors), 1)
        self.assertIn("no rule here claims it", errors[0])

    def test_a_partially_automatable_record_compiles_in_whether_or_not_it_is_claimed(
        self,
    ):
        records = {"a": record("a", "partially")}
        claimed, _, _ = review_mod.route(records, {"a"}, {})
        unclaimed, _, _ = review_mod.route(records, set(), {})
        self.assertEqual([r["id"] for r in claimed], ["a"])
        self.assertEqual([r["id"] for r in unclaimed], ["a"])

    def test_an_unautomatable_record_may_not_be_claimed(self):
        records = {"a": record("a", "no")}
        for_review, errors, _ = review_mod.route(records, set(), {})
        self.assertEqual([r["id"] for r in for_review], ["a"])
        _, errors, _ = review_mod.route(records, {"a"}, {})
        self.assertEqual(len(errors), 1)
        self.assertIn("no rule can be claimed", errors[0])

    def test_an_exemption_answers_the_error_and_goes_stale_when_a_rule_arrives(self):
        # `automatable = "yes"` is a property of the PRINCIPLE, not of the
        # repository: a catalog with no queue in it cannot carry a backpressure
        # rule however true the field is. The exemption records that, and stops
        # describing the tree the moment a rule does claim the record.
        records = {"a": record("a", "yes")}
        _, errors, stale = review_mod.route(records, set(), {"a": "no subject here"})
        self.assertEqual(errors, [])
        self.assertEqual(stale, [])

        _, _, stale = review_mod.route(records, {"a"}, {"a": "no subject here"})
        self.assertEqual(len(stale), 1)
        self.assertIn("now claimed", stale[0])

    def test_an_exemption_naming_no_record_is_stale(self):
        _, _, stale = review_mod.route({}, set(), {"gone": "reason"})
        self.assertEqual(len(stale), 1)
        self.assertIn("names no record", stale[0])

    def test_a_deprecated_record_reaches_neither_side(self):
        records = {"a": record("a", "partially", status="deprecated")}
        for_review, errors, _ = review_mod.route(records, set(), {})
        self.assertEqual(for_review, [])
        self.assertEqual(errors, [])

    def test_include_domains_narrows_what_compiles_in(self):
        records = {
            "a": record("a", "partially", domains=["security"]),
            "b": record("b", "partially", domains=["product"]),
        }
        for_review, _, _ = review_mod.route(records, set(), {}, ["security"])
        self.assertEqual([r["id"] for r in for_review], ["a"])


class Ceiling(unittest.TestCase):
    def test_a_document_within_its_ceiling_is_accepted(self):
        self.assertIsNone(review_mod.over_budget("one\ntwo\n", 10))

    def test_a_document_over_its_ceiling_is_refused_and_says_not_to_raise_it(self):
        message = review_mod.over_budget("\n".join(str(n) for n in range(50)), 10)
        self.assertIsNotNone(message)
        self.assertIn("Shorten records", message)
        # The ceiling is not a nicety to be turned up when it complains: it is
        # the half of the carve-out that keeps this tier from becoming prose
        # emitted always.
        self.assertIn("Do not raise the ceiling", message)


class Composition(unittest.TestCase):
    def test_the_preamble_names_the_static_rules_and_says_not_to_repeat_them(self):
        document = review_mod.render([], ["rule-one", "rule-two"])
        self.assertIn("Do NOT re-enforce the static rules", document)
        self.assertIn("`rule-one`", document)
        self.assertIn("`rule-two`", document)

    def test_an_entry_is_the_three_fields_that_were_already_written_as_a_prompt(self):
        document = review_mod.render([record("a", "partially")], [])
        self.assertIn("the a claim", document)
        self.assertIn("when it applies", document)
        self.assertIn("what to ask", document)

    def test_no_field_beyond_those_three_crosses_over(self):
        # Zero new schema, and zero old schema smuggled across: a reviewer that
        # is handed costs, conflicts and sources is handed the catalog.
        entry = record(
            "a",
            "partially",
            costs=["a cost nobody asked for"],
            conflicts_with=["something-else"],
            rationale="the rationale",
        )
        document = review_mod.render([entry], [])
        self.assertNotIn("a cost nobody asked for", document)
        self.assertNotIn("something-else", document)
        self.assertNotIn("the rationale", document)


class SelfApplication(unittest.TestCase):
    def test_this_repository_routes_cleanly(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--review"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_compiled_documents_are_current(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--review", "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_an_exemption_without_a_reason_is_refused(self):
        # A reason nobody wrote is one nobody can review, and it is exactly as
        # permanent as one that was argued for.
        with tempfile.TemporaryDirectory() as tmp:
            policy = Path(tmp) / "policy"
            policy.mkdir()
            (policy / "upheld.toml").write_text(
                textwrap.dedent(
                    """
                    [review]
                    no_subject_here = ["backpressure"]
                    """
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--review"],
                cwd=tmp,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("the reason", result.stderr)


if __name__ == "__main__":
    unittest.main()
