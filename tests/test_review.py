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

sys.path.insert(0, str(ROOT))

import uphold_check  # noqa: E402


def needs_the_engine(test):
    """Skip where neither a built binary nor cargo can answer.

    The same reason `test_the_two_readers_of_the_policy_agree` gives: a test
    that needs a `cargo build` to be meaningful must not report a red suite to
    somebody who has not run one, and the catalog job runs on an image with no
    Rust toolchain by design. What is skipped here is asserted in
    tests/check_cli.rs, which runs where a toolchain exists.
    """
    try:
        uphold_check.engine(ROOT, "--version")
    except uphold_check.CouldNotLook as error:
        return unittest.skip(str(error))(test)
    return test


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


class Controls(unittest.TestCase):
    """A control is what separates a quiet record from a dead one.

    Citation counting cannot: a record with no findings against it is either
    guarding a clean tree or saying nothing a reviewer could act on. So the
    refusals here are the ones `uphold probe` makes for a hook fixture, and for
    the same reason -- a control that demonstrates nothing would report a live
    record as dead, or credit a dead one with a finding nobody planted.
    """

    def control(self, **fields: object) -> list[dict]:
        base = {"record": "a", "catches": "a change it must be named for"}
        base.update(fields)
        return uphold_check.review_controls({"control": [base]})

    def test_a_control_over_a_review_carried_record_loads_and_is_counted(self):
        declared = self.control(misses="a change it must not fire on")
        records = {"a": record("a", "partially"), "b": record("b", "no")}
        for_review, _, _ = review_mod.route(records, set(), {})
        errors, uncontrolled = review_mod.audit_controls(declared, for_review, records)
        self.assertEqual(errors, [])
        self.assertEqual(uncontrolled, ["b"])

    def test_misses_is_optional_and_travels_as_an_explicit_null(self):
        # Only one direction was written down, and a harness that saw no key
        # would have to guess whether the miss was untested or untestable.
        export = review_mod.render_controls(self.control(), [])
        self.assertIn('"misses": null', export)

    def test_an_empty_catches_is_refused_because_it_demonstrates_nothing(self):
        for empty in ["", "   "]:
            with self.assertRaises(uphold_check.CouldNotLook) as raised:
                self.control(catches=empty)
            self.assertIn("empty fixture demonstrates nothing", str(raised.exception))

    def test_an_empty_misses_is_refused_from_the_other_side(self):
        # Every reviewer declines to fire on nothing, so it asserts nothing
        # while reading as though the record had been shown to be narrow.
        with self.assertRaises(uphold_check.CouldNotLook):
            self.control(misses=" ")

    def test_a_misspelled_field_is_refused_rather_than_silently_dropped(self):
        with self.assertRaises(uphold_check.CouldNotLook) as raised:
            self.control(mises="a change it must not fire on")
        self.assertIn("mises", str(raised.exception))

    def test_a_control_naming_no_record_in_the_catalog_is_refused(self):
        errors, _ = review_mod.audit_controls(self.control(), [], {})
        self.assertEqual(len(errors), 1)
        self.assertIn("the catalog does not define it", errors[0])

    def test_a_control_over_an_automatable_record_is_refused(self):
        # `route` drops such a record at "a rule enforces it; a reviewer
        # repeating it is noise", so a reviewer is never shown it: failing the
        # control would report a miss of something nobody was handed, and
        # passing it would reward a reviewer for repeating a static rule.
        records = {"a": record("a", "yes")}
        for_review, _, _ = review_mod.route(records, {"a"}, {})
        errors, uncontrolled = review_mod.audit_controls(
            self.control(), for_review, records
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("excluded from the compiled document", errors[0])
        self.assertEqual(uncontrolled, [])

    def test_a_control_over_a_record_this_repository_filters_out_is_refused(self):
        # Narrowing `include_domains` takes the entry away; the control has no
        # document to be driven against, and saying so is the whole point.
        records = {"a": record("a", "partially", domains=["product"])}
        for_review, _, _ = review_mod.route(records, set(), {}, ["security"])
        errors, _ = review_mod.audit_controls(self.control(), for_review, records)
        self.assertEqual(len(errors), 1)
        self.assertIn("does not compile into the review document", errors[0])

    def test_the_denominator_names_the_records_and_not_only_the_count(self):
        # "One record carries a control" means one thing beside two
        # review-carried records and another beside nineteen.
        note = review_mod.uncontrolled_note(["b", "c"])
        self.assertIn("2 review-carried record(s) have no control", note)
        self.assertIn("b, c", note)
        self.assertIsNone(review_mod.uncontrolled_note([]))


@needs_the_engine
class ClaimsThatEnforceNothing(unittest.TestCase):
    """A claim naming a rule no seam supplies must not silence the review.

    `route` drops an `automatable = "yes"` record from the document when a rule
    claims it -- "a rule enforces it; a reviewer repeating it is noise". A claim
    whose rule nothing here supplies enforces nothing, so it is not that case,
    and passing it in unfiltered removed the record from the human tier while
    the same document's "already active here" list -- which IS filtered by
    suppliers -- left the rule out. Enforced by nothing and reviewed by nobody,
    with the page showing no trace of either.
    """

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.tmp = Path(self._directory.name)
        self.addCleanup(self._directory.cleanup)
        (self.tmp / "policy").mkdir()

    def review(self, declaration: str, policy: str) -> subprocess.CompletedProcess:
        (self.tmp / "policy" / "upheld.toml").write_text(
            textwrap.dedent(declaration), encoding="utf-8"
        )
        (self.tmp / "policy" / "principles.toml").write_text(
            textwrap.dedent(policy), encoding="utf-8"
        )
        (self.tmp / ".pre-commit-config.yaml").write_text(
            "repos:\n"
            "  - repo: https://github.com/HackingGate/uphold\n"
            "    rev: v2.0.0\n"
            "    hooks:\n"
            "      - id: uphold-scan\n",
            encoding="utf-8",
        )
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--review"],
            cwd=self.tmp,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_a_claim_no_seam_supplies_does_not_remove_its_principle_from_review(self):
        # `fail-safe-defaults` is `automatable = "yes"` in the shipped
        # catalog, and the policy here supplies no rule by the claimed name at
        # all -- so the claim enforces nothing and the record still needs an
        # answer from somebody.
        result = self.review(
            """
            [[enforce]]
            principle = "fail-safe-defaults"
            rule = "a-rule-that-does-not-exist"
            """,
            """
            [rule.no-todo]
            message = "no TODO"
            regexp = 'TODO'
            files.include = ["."]
            # An unanchored literal contains its own text on the `regexp` line,
            # so a rule selecting the whole tree reports its own policy file and
            # the engine refuses it at load. This test is about a claim naming a
            # rule that does not exist, not about selection.
            files.exclude = ["policy/**"]
            """,
        )
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("fail-safe-defaults", result.stderr)
        self.assertIn("no rule here claims it", result.stderr)


@needs_the_engine
class Settings(unittest.TestCase):
    """`[review]` is configuration, so a field of the wrong type is exit 2.

    Two of the four fields were read by coercion -- `int(...)` and `list(...)`
    -- which turns a wrong type into a traceback and exit 1, and exit 1 in this
    tool means a claim is false. A declaration this tool could not read is
    could-not-look; see the `explicit-unknown` record.
    """

    def review(self, body: str, *args: str) -> subprocess.CompletedProcess:
        policy = Path(self.tmp) / "policy"
        policy.mkdir(exist_ok=True)
        (policy / "upheld.toml").write_text(textwrap.dedent(body), encoding="utf-8")
        # `--review` asks the binary which claims are live, and the binary needs
        # a policy to answer. A repository with no policy is could-not-look here
        # for the same reason it is for the reconcile.
        (policy / "principles.toml").write_text(
            '[rule.prevent-public-push]\nbuiltin = "prevent-public-push"\n'
            'git.hooks = ["pre-push"]\n',
            encoding="utf-8",
        )
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--review", *args],
            cwd=self.tmp,
            capture_output=True,
            text=True,
            check=False,
        )

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.tmp = self._directory.name
        self.addCleanup(self._directory.cleanup)

    def test_a_max_lines_that_is_not_a_number_is_two_not_a_traceback(self):
        result = self.review(
            """
            [review]
            max_lines = "nine hundred"
            """
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("review.max_lines", result.stderr)

    def test_a_max_lines_of_zero_is_refused_rather_than_silently_impossible(self):
        result = self.review(
            """
            [review]
            max_lines = 0
            """
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("review.max_lines", result.stderr)

    def test_include_domains_that_is_not_a_list_of_names_is_two(self):
        result = self.review(
            """
            [review]
            include_domains = "security"
            """
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("review.include_domains", result.stderr)

    def test_an_emit_entry_that_is_not_a_file_name_is_two(self):
        result = self.review(
            """
            [review]
            emit = [7]
            """
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("review.emit", result.stderr)

    def test_an_emit_name_that_escapes_the_repository_writes_nothing(self):
        """`emit` is a name from the declaration handed straight to write_text.

        `emit = ["../ESCAPED.md"]` created a file one level ABOVE the repository
        and reported "wrote ../ESCAPED.md" as though that were what was asked
        for. A hook runs this unattended; the one place it may write is the
        repository it describes.
        """
        # `include_domains` names a domain no record carries, so nothing routes
        # and nothing is refused before the write is reached.
        result = self.review(
            """
            [review]
            include_domains = ["no-such-domain"]
            emit = ["../ESCAPED.md"]
            """,
            "--emit",
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse((Path(self.tmp).parent / "ESCAPED.md").exists())
        self.assertNotIn("wrote", result.stdout)

    def test_an_absolute_emit_name_writes_nothing(self):
        target = Path(self.tmp) / "outside.md"
        result = self.review(
            f"""
            [review]
            include_domains = ["no-such-domain"]
            emit = ["{target}"]
            """,
            "--emit",
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse(target.exists())

    def test_an_emit_name_under_a_directory_that_is_not_there_is_two_not_one(self):
        """A missing parent is could-not-do-it, not a false claim."""
        result = self.review(
            """
            [review]
            include_domains = ["no-such-domain"]
            emit = ["generated/REVIEW.md"]
            """,
            "--emit",
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("could not write", result.stderr)

    def test_an_emit_name_inside_the_repository_is_written(self):
        """The refusals above are a narrower door, not a closed one."""
        result = self.review(
            """
            [review]
            include_domains = ["no-such-domain"]
            emit = ["REVIEW.md"]
            """,
            "--emit",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((Path(self.tmp) / "REVIEW.md").is_file())


@needs_the_engine
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

    def test_the_denominator_is_printed_on_a_run_that_found_nothing_wrong(self):
        # The reader who most needs it is the one skimming a green run: this
        # repository declares one control and carries nineteen records, and a
        # run that said only "19 record(s) compile" would read like coverage.
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--review"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("have no control", result.stdout)
        self.assertIn("nothing here shows they can produce a finding", result.stdout)
        # The one record that does carry a control is not in that list.
        self.assertNotIn("single-authoritative-source", result.stdout)

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
