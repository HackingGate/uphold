"""Behaviour tests for the routing and the ceiling.

The routing decides what a reviewer is shown, and the ceiling is the half of
`enforcement-needs-a-trigger`'s carve-out that keeps this tier from becoming
prose emitted always. Both are tested for what they refuse, not only for what
they let through.
"""

from __future__ import annotations

import json
import random
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import ClassVar

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "uphold_check.py"

sys.path.insert(0, str(ROOT / "scripts"))

import review as review_mod  # noqa: E402
from catalog import load_catalog  # noqa: E402
from validate import DOMAINS  # noqa: E402

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
        "domains": ["architecture"],
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

    def test_an_unclaimed_automatable_record_is_listed_apart_when_asked_to_print(self):
        records = {"a": record("a", "yes"), "b": record("b", "no")}
        unclaimed: list[dict] = []
        for_review, errors, _ = review_mod.route(records, set(), {}, None, unclaimed)
        self.assertEqual([entry["id"] for entry in for_review], ["b"])
        self.assertEqual(errors, [])
        self.assertEqual([entry["id"] for entry in unclaimed], ["a"])
        listed = review_mod.render_could_enforce(unclaimed)
        self.assertIn("- a:", listed)
        self.assertIn("no_subject_here", listed)

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
            "b": record("b", "partially", domains=["socio-technical"]),
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
        # The typing fields are the catalog's index, not review input: what an
        # entry is, where it is used, the rung a check reads it at, and the
        # tools that illustrate it are for whoever builds a check, not for the
        # reviewer asked the record's questions.
        entry = record(
            "a",
            "partially",
            costs=["a cost nobody asked for"],
            conflicts_with=["something-else"],
            rationale="the rationale",
            kind="decision-procedure",
            domains=["a-domain-of-its-own"],
            enforcement={"automatable": "partially", "rung": ["syntax-rung-marker"]},
            tools=[
                {
                    "name": "an-illustrative-tool",
                    "url": "https://tool.example/",
                    "notes": "a note about the tool",
                }
            ],
        )
        document = review_mod.render([entry], [])
        self.assertNotIn("a cost nobody asked for", document)
        self.assertNotIn("something-else", document)
        self.assertNotIn("the rationale", document)
        for value in (
            "decision-procedure",
            "a-domain-of-its-own",
            "syntax-rung-marker",
            "an-illustrative-tool",
            "https://tool.example/",
            "a note about the tool",
        ):
            with self.subTest(value=value):
                self.assertNotIn(value, document)


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
        records = {"a": record("a", "partially", domains=["socio-technical"])}
        for_review, _, _ = review_mod.route(records, set(), {}, ["security"])
        errors, _ = review_mod.audit_controls(self.control(), for_review, records)
        self.assertEqual(len(errors), 1)
        self.assertIn("does not compile into the review document", errors[0])

    def test_the_denominator_names_the_records_and_not_only_the_count(self):
        # "One record carries a control" means one thing beside two
        # review-carried records and another beside twenty-nine.
        note = review_mod.uncontrolled_note(["b", "c"])
        self.assertIn("2 review-carried record(s) have no control", note)
        self.assertIn("b, c", note)
        self.assertIsNone(review_mod.uncontrolled_note([]))


class Drive(unittest.TestCase):
    """Planting a control and scoring what the reviewer names.

    The reviewer is a command, so these drive small Python scripts that answer
    in its protocol. What is tested is the scoring and the refusals: a reviewer
    that broke the protocol has said nothing about the record, and must not be
    scored as having missed it.
    """

    CARRIED: ClassVar[dict[str, str]] = {
        "single-authoritative-source": "Single Authoritative Source"
    }

    def reviewer(self, body: str) -> list[str]:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        script = Path(tmp) / "reviewer.py"
        script.write_text(
            "import json, sys\npayload = json.load(sys.stdin)\n"
            + textwrap.dedent(body),
            encoding="utf-8",
        )
        return [sys.executable, str(script)]

    def test_a_finding_may_be_the_id_or_the_title_in_any_case(self):
        reviewer = self.reviewer(
            """
            print("single-authoritative-source")
            print()
            print("single AUTHORITATIVE source")
            """
        )
        named = review_mod.ask(reviewer, "doc", "change", self.CARRIED)
        self.assertEqual(named, {"single-authoritative-source"})

    def test_the_reviewer_is_handed_the_document_and_the_change_and_not_the_key(self):
        reviewer = self.reviewer(
            """
            assert sorted(payload) == ["change", "document"], sorted(payload)
            assert payload == {"document": "doc", "change": "plant"}, payload
            """
        )
        self.assertEqual(review_mod.ask(reviewer, "doc", "plant", self.CARRIED), set())

    def test_a_name_outside_the_document_is_refused_rather_than_scored(self):
        reviewer = self.reviewer('print("Single Authoritative Source.")')
        with self.assertRaises(review_mod.ReviewerFailed) as raised:
            review_mod.ask(reviewer, "doc", "change", self.CARRIED)
        self.assertIn("'Single Authoritative Source.'", str(raised.exception))

    def test_a_reviewer_that_exits_non_zero_is_refused_with_its_stderr(self):
        reviewer = self.reviewer('sys.exit("no API key")')
        with self.assertRaises(review_mod.ReviewerFailed) as raised:
            review_mod.ask(reviewer, "doc", "change", self.CARRIED)
        self.assertIn("exited 1", str(raised.exception))
        self.assertIn("no API key", str(raised.exception))

    def test_a_reviewer_that_stalls_is_refused_at_the_deadline(self):
        reviewer = self.reviewer("import time; time.sleep(30)")
        with self.assertRaises(review_mod.ReviewerFailed) as raised:
            review_mod.ask(reviewer, "doc", "change", self.CARRIED, timeout=1)
        self.assertIn("did not answer within 1s", str(raised.exception))

    def test_output_that_is_not_utf8_is_refused_rather_than_raised(self):
        reviewer = self.reviewer('sys.stdout.buffer.write(b"\\xff\\n")')
        with self.assertRaises(review_mod.ReviewerFailed) as raised:
            review_mod.ask(reviewer, "doc", "change", self.CARRIED)
        self.assertIn("not UTF-8", str(raised.exception))

    def test_a_reviewer_that_cannot_be_run_is_refused(self):
        with self.assertRaises(review_mod.ReviewerFailed):
            review_mod.ask(["/nonexistent/reviewer"], "doc", "change", self.CARRIED)

    def test_one_catch_in_three_is_counted_and_does_not_hold(self):
        answers = iter([{"a"}, set(), set(), set(), set(), set()])
        declared = [{"record": "a", "catches": "plant", "misses": "clean"}]
        results = review_mod.drive(
            declared, "doc", {"a": "A"}, 3, lambda *_: next(answers)
        )
        self.assertEqual(results, [{"record": "a", "caught": 1, "fired": 0}])
        self.assertFalse(review_mod.holds(results[0], 3))
        report = review_mod.render_drive(results, 3, ["rev"])
        self.assertIn("a: caught 1/3, misses fired 0/3 -- DOES NOT HOLD", report)
        self.assertIn("pass@1 0.33; pass^3 0/1", report)

    def test_the_report_names_the_reviewer_command_as_run(self):
        results = [{"record": "a", "caught": 1, "fired": None}]
        report = review_mod.render_drive(
            results, 1, ["./my-reviewer", "--model", "x y"]
        )
        self.assertEqual(
            report.splitlines()[0], "reviewer: ./my-reviewer --model 'x y'"
        )

    def test_a_ruling_report_names_the_ruler_and_the_auditor(self):
        result = {
            "question": "Q?",
            "ruled": "(a)",
            "held": 1,
            "given": ["(a)"],
            "broken": [],
            "audited": 1,
            "unsupported": 0,
        }
        lines = review_mod.render_rulings(
            [result], 1, 1, 7, ["./ruler"], ["./auditor", "-v"]
        ).splitlines()
        self.assertEqual(
            lines[:3], ["ruler: ./ruler", "auditor: ./auditor -v", lines[2]]
        )
        self.assertTrue(lines[2].startswith("seed 7"))
        unaudited = review_mod.render_rulings([result], 1, 1, 7, ["./ruler"], None)
        self.assertNotIn("auditor:", unaudited)
        self.assertIn("unaudited", unaudited)

    def test_firing_on_the_miss_breaks_a_control_that_caught_every_plant(self):
        results = review_mod.drive(
            [{"record": "a", "catches": "plant", "misses": "clean"}],
            "doc",
            {"a": "A"},
            2,
            lambda *_: {"a"},
        )
        self.assertEqual(results[0]["fired"], 2)
        self.assertFalse(review_mod.holds(results[0], 2))
        self.assertIn(
            "false positives 1.00", review_mod.render_drive(results, 2, ["rev"])
        )

    def test_an_unwritten_misses_is_unmeasured_and_not_a_rate_of_zero(self):
        calls = []

        def reviewer(document: str, change: str, carried: dict) -> set:
            calls.append(change)
            return {"a"}

        results = review_mod.drive(
            [{"record": "a", "catches": "plant"}], "doc", {"a": "A"}, 2, reviewer
        )
        self.assertEqual(calls, ["plant", "plant"])
        self.assertIsNone(results[0]["fired"])
        self.assertTrue(review_mod.holds(results[0], 2))
        report = review_mod.render_drive(results, 2, ["rev"])
        self.assertIn("misses not written", report)
        self.assertNotIn("false positives", report)


class Rulings(unittest.TestCase):
    """`--drive --rule`: a ruling control is asked k times and scored.

    The rulers here are functions and small scripts, so no model is involved:
    what is tested is the scoring, the shuffle, and the refusals.
    """

    LINES: ClassVar[dict[str, list[str]]] = {
        "fail-fast": ['id = "fail-fast"', 'title = "Fail Fast and Explicitly"']
    }
    CITED: ClassVar[list[dict]] = [
        {"record": "fail-fast", "line": 1, "quote": "fail-fast"}
    ]
    CONTROL: ClassVar[dict] = {
        "question": "Which?",
        "options": ["(a) first (recommended)", "(b) second"],
        "answer": "(b) second",
    }

    def drive(self, control: dict, ruler, auditor=None, runs: int = 3) -> dict:
        (result,) = review_mod.drive_rulings(
            [control], "doc", self.LINES, runs, random.Random(7), ruler, auditor
        )
        return result

    def always(self, option: str):
        return lambda _doc, _question, shown: {
            "kind": "answer",
            "value": next(value for value in shown if value.startswith(option)),
            "citations": self.CITED,
        }

    def test_a_ruler_that_always_answers_a_fails_a_control_ruled_b(self):
        result = self.drive(self.CONTROL, self.always("(a)"))
        self.assertEqual(result["held"], 0)
        self.assertFalse(review_mod.ruling_holds(result, 3))

    def test_a_ruler_that_always_escalates_fails_a_control_with_an_answer(self):
        def escalates(*_):
            return {"kind": "escalate", "value": "no record applies", "citations": []}

        result = self.drive(self.CONTROL, escalates)
        self.assertEqual(result["given"], ["escalate"] * 3)
        self.assertFalse(review_mod.ruling_holds(result, 3))

    def test_a_ruler_giving_the_ruling_every_run_holds(self):
        result = self.drive(self.CONTROL, self.always("(b)"))
        self.assertEqual(result["held"], 3)
        self.assertTrue(review_mod.ruling_holds(result, 3))

    def test_an_escalation_control_holds_on_escalations_alone(self):
        control = {**self.CONTROL, "escalate": True}
        del control["answer"]

        def escalates(*_):
            return {"kind": "escalate", "value": "unordered conflict", "citations": []}

        self.assertTrue(review_mod.ruling_holds(self.drive(control, escalates), 3))

    def test_two_runs_in_three_hold_only_where_agree_is_two(self):
        answers = iter(["(b)", "(a)", "(b)"])

        def ruler(doc, question, shown):
            return self.always(next(answers))(doc, question, shown)

        result = self.drive(self.CONTROL, ruler)
        self.assertEqual(result["held"], 2)
        self.assertFalse(review_mod.ruling_holds(result, 3))
        self.assertTrue(review_mod.ruling_holds(result, 2))

    def test_the_ruler_sees_shuffled_options_without_the_recommendation(self):
        seen = []

        def ruler(doc, question, shown):
            seen.append(tuple(shown))
            return self.always("(b)")(doc, question, shown)

        control = {**self.CONTROL, "options": [f"({c}) {c}" for c in "abcdef"]}
        control["answer"] = "(b) b"
        control["options"][0] += " (Recommended)"
        self.drive(control, ruler, runs=5)
        self.assertTrue(all("recommended" not in " ".join(s).lower() for s in seen))
        self.assertEqual(
            {frozenset(s) for s in seen}, {frozenset(f"({c}) {c}" for c in "abcdef")}
        )
        self.assertGreater(len(set(seen)), 1, "the order never changed across runs")

    def test_a_citation_that_does_not_resolve_breaks_the_run(self):
        for cited, says in [
            (
                {"record": "least-power", "line": 1, "quote": "x"},
                "not an adopted record",
            ),
            ({"record": "fail-fast", "line": 9, "quote": "x"}, "has no line 9"),
            ({"record": "fail-fast", "line": 2, "quote": "fail-fast"}, "does not say"),
        ]:
            with self.subTest(cited=cited):

                def ruler(_doc, _question, shown, cited=cited):
                    return {
                        "kind": "answer",
                        "value": "(b) second",
                        "citations": [cited],
                    }

                result = self.drive(self.CONTROL, ruler)
                self.assertEqual(result["held"], 0)
                self.assertIn(says, result["broken"][0])

    def test_an_answer_that_cites_nothing_breaks_the_run(self):
        def ruler(*_):
            return {"kind": "answer", "value": "(b) second", "citations": []}

        result = self.drive(self.CONTROL, ruler)
        self.assertEqual(result["held"], 0)
        self.assertIn("cites nothing", result["broken"][0])

    def test_a_none_that_cites_nothing_breaks_the_run(self):
        control = {**self.CONTROL, "none": True}
        del control["answer"]

        def ruler(*_):
            return {"kind": "none", "value": "no option works", "citations": []}

        result = self.drive(control, ruler)
        self.assertEqual(result["held"], 0)
        self.assertIn("a none that cites nothing", result["broken"][0])

    def test_a_decide_report_with_no_adopt_list_is_two_not_an_empty_policy(self):
        settings = {"rulings": [self.CONTROL]}
        driving = {"seed": 1, "timeout": 1, "auditor": None, "command": ["false"]}
        records = {record["id"]: record for record in load_catalog()}
        self.assertEqual(
            uphold_check.drive_rulings(driving, settings, {"decide": {}}, records), 2
        )

    def test_an_adopted_id_the_scripts_catalog_lacks_is_two_rather_than_dropped(self):
        settings = {"rulings": [self.CONTROL]}
        report = {
            "decide": {"adopt": ["fail-fast", "not-in-this-catalog"], "order": []}
        }
        driving = {"seed": 1, "timeout": 1, "auditor": None, "command": ["false"]}
        records = {record["id"]: record for record in load_catalog()}
        self.assertEqual(
            uphold_check.drive_rulings(driving, settings, report, records), 2
        )

    def test_one_held_answer_in_audit_every_is_audited_and_an_unsupported_one_fails(
        self,
    ):
        asked = []

        def auditor(_doc, question, options, given):
            asked.append(given)
            return "the line is about something else"

        result = self.drive(self.CONTROL, self.always("(b)"), auditor)
        self.assertEqual(result["audited"], 1)
        self.assertEqual(result["unsupported"], 1)
        self.assertEqual(sorted(asked[0]), ["citations", "kind", "value"])
        self.assertFalse(review_mod.ruling_holds(result, 2))

    def ruler_script(self, body: str) -> list[str]:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        script = Path(tmp) / "ruler.py"
        script.write_text(
            "import json, sys\npayload = json.load(sys.stdin)\n"
            + textwrap.dedent(body),
            encoding="utf-8",
        )
        return [sys.executable, str(script)]

    def test_the_ruler_reads_the_document_question_and_options_and_nothing_else(self):
        ruler = self.ruler_script(
            """
            assert sorted(payload) == ["document", "options", "question"], payload
            print(json.dumps({"answer": payload["options"][0], "citations": []}))
            """
        )
        given = review_mod.ask_ruler(ruler, "doc", "Which?", ["x", "y"])
        self.assertEqual(given, {"kind": "answer", "value": "x", "citations": []})

    def test_a_ruler_breaking_the_protocol_is_refused_rather_than_scored(self):
        for body in [
            'print("(a)")',
            'print(json.dumps({"answer": "z"}))',
            'print(json.dumps({"answer": "x", "escalate": "both"}))',
            'print(json.dumps({"escalate": "r", "citations": [{"record": "a", "line": 1, "quote": "q"}]}))',
            'print(json.dumps({"answer": "x", "citations": [{"record": "a"}]}))',
            'sys.exit("no key")',
        ]:
            with self.subTest(body=body), self.assertRaises(review_mod.RulerFailed):
                review_mod.ask_ruler(
                    self.ruler_script(body), "doc", "Which?", ["x", "y"]
                )


class RuleCommand(unittest.TestCase):
    """`--review --drive --rule` end to end, with a stub ruler and the engine."""

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.tmp = Path(self._directory.name)
        self.addCleanup(self._directory.cleanup)
        carried = {value for record in load_catalog() for value in record["domains"]}
        spare = sorted(set(DOMAINS) - carried)
        if not spare:
            self.skipTest("every domain is carried by a record; none routes nothing")
        (self.tmp / "policy").mkdir()
        (self.tmp / "policy" / "principles.toml").write_text(
            '[decide]\nadopt = ["fail-fast"]\n', encoding="utf-8"
        )
        (self.tmp / "policy" / "upheld.toml").write_text(
            textwrap.dedent(
                f"""
                [review]
                include_domains = ["{spare[0]}"]

                [[review.ruling]]
                question = "Which?"
                options = ["(a) first (recommended)", "(b) second"]
                answer = "(b) second"
                """
            ),
            encoding="utf-8",
        )

    def rule(self, ruler: str, *argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--review",
                "--drive",
                "--rule",
                *argv,
                "--",
                sys.executable,
                "-c",
                textwrap.dedent(ruler),
            ],
            cwd=self.tmp,
            capture_output=True,
            text=True,
            check=False,
        )

    ANSWERS_B = """
        import json, sys
        payload = json.load(sys.stdin)
        assert "L1: id = \\"fail-fast\\"" in payload["document"], payload["document"]
        assert payload["question"] == "Which?", payload["question"]
        answer = next(o for o in payload["options"] if o.startswith("(b)"))
        cited = [{"record": "fail-fast", "line": 1, "quote": "fail-fast"}]
        print(json.dumps({"answer": answer, "citations": cited}))
        """

    @needs_the_engine
    def test_a_ruler_giving_the_ruling_holds_and_prints_the_seed(self):
        result = self.rule(self.ANSWERS_B, "--seed", "3")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("seed 3", result.stdout)
        self.assertIn("held 3/3 (agree 3)", result.stdout)
        self.assertIn("unaudited", result.stdout)

    @needs_the_engine
    def test_what_the_review_document_would_refuse_does_not_block_a_ruling(self):
        # No include_domains: every `automatable = "yes"` record is unclaimed
        # here, which `--review` refuses. The rulings are scored regardless.
        upheld = self.tmp / "policy" / "upheld.toml"
        text = upheld.read_text(encoding="utf-8")
        upheld.write_text(
            "\n".join(
                line for line in text.splitlines() if "include_domains" not in line
            ),
            encoding="utf-8",
        )
        review = subprocess.run(
            [sys.executable, str(SCRIPT), "--review"],
            cwd=self.tmp,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(review.returncode, 1, review.stderr)
        self.assertIn("no rule here claims it", review.stderr)
        result = self.rule(self.ANSWERS_B)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("held 3/3", result.stdout)

    @needs_the_engine
    def test_a_ruler_that_always_escalates_is_one(self):
        result = self.rule(
            'import sys; sys.stdin.read(); print(\'{"escalate": "no"}\')'
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("DOES NOT HOLD", result.stdout)

    @needs_the_engine
    def test_an_auditor_that_finds_the_citations_unsupported_is_one(self):
        auditor = f'{sys.executable} -c \'print("{{\\"supported\\": false}}")\''
        result = self.rule(self.ANSWERS_B, "--auditor", auditor)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("audited 1 (1 unsupported)", result.stdout)

    def test_rule_options_outside_rule_or_out_of_range_are_usage_errors(self):
        for argv in [
            ["--agree", "4"],
            ["--auditor", ""],
            ["--audit-every", "0"],
            ["--seed", "²"],
            ["--runs", "²"],
        ]:
            result = self.rule("print(1)", *argv)
            self.assertEqual(result.returncode, 2, argv)
            self.assertIn("--drive --rule", result.stderr)
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--review",
                "--drive",
                "--agree",
                "2",
                "--",
                "true",
            ],
            cwd=self.tmp,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)

    def test_a_ruling_control_whose_answer_is_not_an_option_is_two(self):
        upheld = self.tmp / "policy" / "upheld.toml"
        upheld.write_text(
            upheld.read_text(encoding="utf-8").replace(
                'answer = "(b) second"', 'answer = "(c) third"'
            ),
            encoding="utf-8",
        )
        result = self.rule("print(1)")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("not one of its `options`", result.stderr)


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

    def routes_nothing(self) -> str:
        """A domain in the vocabulary that no record carries.

        Filtering on it routes nothing, so nothing is refused before the write
        is reached, and the emit tests below test the write. Computed here
        rather than written down, because the next record to carry it would
        otherwise turn these tests into tests of the routing.
        """
        carried = {value for record in load_catalog() for value in record["domains"]}
        spare = sorted(set(DOMAINS) - carried)
        if not spare:
            self.skipTest("every domain is carried by a record; none routes nothing")
        return spare[0]

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

    def test_include_domains_naming_an_unknown_domain_is_two(self):
        # A filter no record can match compiles an empty document, which reads
        # as a repository with nothing to review. The value is refused and
        # named, with the list it was not in.
        result = self.review(
            """
            [review]
            include_domains = ["security", "product"]
            """
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("review.include_domains", result.stderr)
        self.assertIn("'product'", result.stderr)
        self.assertNotIn("'security'", result.stderr)
        self.assertIn("socio-technical", result.stderr)

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
        result = self.review(
            f"""
            [review]
            include_domains = ["{self.routes_nothing()}"]
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
            include_domains = ["{self.routes_nothing()}"]
            emit = ["{target}"]
            """,
            "--emit",
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse(target.exists())

    def test_an_emit_name_under_a_directory_that_is_not_there_is_two_not_one(self):
        """A missing parent is could-not-do-it, not a false claim."""
        result = self.review(
            f"""
            [review]
            include_domains = ["{self.routes_nothing()}"]
            emit = ["generated/REVIEW.md"]
            """,
            "--emit",
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("could not write", result.stderr)

    def test_an_emit_name_inside_the_repository_is_written(self):
        """The refusals above are a narrower door, not a closed one."""
        result = self.review(
            f"""
            [review]
            include_domains = ["{self.routes_nothing()}"]
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

    def test_every_review_carried_record_here_carries_a_control(self):
        # A record added to the review tier without a control is one nothing
        # shows can produce a finding. The run names it; this refuses it.
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--review"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("have no control", result.stdout)
        export = json.loads((ROOT / "review-controls.json").read_text(encoding="utf-8"))
        self.assertEqual(export["uncontrolled"], [])

    def test_the_compiled_documents_are_current(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--review", "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def drive(self, *argv: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--review", "--drive", *argv],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_a_reviewer_holding_the_answer_key_holds_every_control(self):
        # Reads the export, so it stays an oracle as controls are added: what
        # this pins is the wiring from the declaration to the verdict.
        oracle = textwrap.dedent(
            """
            import json, sys
            change = json.load(sys.stdin)["change"]
            key = json.load(open("review-controls.json"))["controls"]
            print("\\n".join(c["record"] for c in key if c["catches"] == change))
            """
        )
        result = self.drive(
            "--timeout", "60", "--runs", "2", "--", sys.executable, "-c", oracle
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("single-authoritative-source: caught 2/2", result.stdout)
        self.assertIn("pass^2", result.stdout)

    def test_a_reviewer_that_names_nothing_is_reported_and_exits_1(self):
        result = self.drive("--", sys.executable, "-c", "import sys; sys.stdin.read()")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("caught 0/3", result.stdout)
        self.assertIn("DOES NOT HOLD", result.stdout)
        self.assertEqual(
            result.stdout.splitlines()[0],
            f"reviewer: {shlex.join([sys.executable, '-c', 'import sys; sys.stdin.read()'])}",
        )

    def test_drive_without_a_reviewer_is_a_usage_error(self):
        for argv in [
            (),
            ("--runs", "0", "--", "true"),
            ("--timeout", "x", "--", "true"),
            ("--runs", "2"),
            ("true",),
        ]:
            result = self.drive(*argv)
            self.assertEqual(result.returncode, 2, argv)
            self.assertIn("--drive [--runs N] [--timeout SECONDS]", result.stderr)

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
