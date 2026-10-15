"""The issue check shares this predicate between local runs and scheduled CI."""

from __future__ import annotations

import io
import json
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import design_age  # noqa: E402

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)


def issue(number: int, ruling: str, age: timedelta, **extra: object) -> dict:
    value = {
        "number": number,
        "title": f"Design record {number}",
        "state": "open",
        "created_at": (NOW - age).isoformat().replace("+00:00", "Z"),
        "labels": [
            {"name": "design"},
            {"name": ruling},
        ],
    }
    value.update(extra)
    return value


class DesignAge(unittest.TestCase):
    def test_pending_is_due_at_thirty_days_but_not_one_second_before(self):
        before = issue(1, "ruling:pending", timedelta(days=30) - timedelta(seconds=1))
        boundary = issue(2, "ruling:pending", timedelta(days=30))

        overdue, errors = design_age.audit([before, boundary], NOW)

        self.assertEqual([record["number"] for record, _ in overdue], [2])
        self.assertEqual(overdue[0][1], 30)
        self.assertEqual(errors, [])

    def test_each_final_ruling_closes_the_age_gate(self):
        issues = [
            issue(number, f"ruling:{status}", timedelta(days=90))
            for number, status in enumerate(("accepted", "rejected", "deferred"), 1)
        ]

        overdue, errors = design_age.audit(issues, NOW)

        self.assertEqual(overdue, [])
        self.assertEqual(errors, [])

    def test_invalid_or_missing_ruling_label_is_reported_immediately(self):
        missing = issue(1, "ruling:pending", timedelta(days=1))
        missing["labels"] = [{"name": "design"}]
        multiple = issue(2, "ruling:pending", timedelta(days=1))
        multiple["labels"].append({"name": "ruling:accepted"})
        unknown = issue(3, "ruling:withdrawn", timedelta(days=1))

        overdue, errors = design_age.audit([missing, multiple, unknown], NOW)

        self.assertEqual(overdue, [])
        self.assertEqual(len(errors), 3)
        self.assertIn("no ruling label", errors[0])
        self.assertIn("ruling:pending, ruling:accepted", errors[1])
        self.assertIn("ruling:withdrawn", errors[2])

    def test_closed_non_design_and_pull_request_items_are_ignored(self):
        closed = issue(1, "ruling:pending", timedelta(days=90), state="closed")
        other = issue(2, "ruling:pending", timedelta(days=90))
        other["labels"] = [{"name": "ruling:pending"}]
        pull_request = issue(3, "ruling:pending", timedelta(days=90), pull_request={})

        overdue, errors = design_age.audit([closed, other, pull_request], NOW)

        self.assertEqual(overdue, [])
        self.assertEqual(errors, [])

    def test_fetch_reads_a_second_page_before_returning(self):
        first_page = [
            issue(number, "ruling:accepted", timedelta(days=1))
            for number in range(1, 101)
        ]
        second_page = [issue(101, "ruling:pending", timedelta(days=31))]
        responses = [
            io.BytesIO(json.dumps(batch).encode())
            for batch in (first_page, second_page)
        ]

        with patch.object(design_age, "urlopen", side_effect=responses) as open_url:
            records = design_age.fetch_open_design_issues("owner/repo", "token")

        self.assertEqual(len(records), 101)
        self.assertIn("page=1", open_url.call_args_list[0].args[0].full_url)
        self.assertIn("page=2", open_url.call_args_list[1].args[0].full_url)
        overdue, errors = design_age.audit(records, NOW)
        self.assertEqual([record["number"] for record, _ in overdue], [101])
        self.assertEqual(errors, [])

    def test_main_reports_api_read_failure_as_exit_two(self):
        with (
            patch.dict(
                "os.environ",
                {"GITHUB_REPOSITORY": "owner/repo", "GITHUB_TOKEN": "token"},
            ),
            patch.object(
                design_age, "fetch_open_design_issues", side_effect=URLError("offline")
            ),
            patch("sys.stderr", new_callable=io.StringIO) as stderr,
        ):
            result = design_age.main()

        self.assertEqual(result, 2)
        self.assertIn("could not audit Design records", stderr.getvalue())

    def test_malformed_issue_response_fails_closed_without_a_traceback(self):
        malformed = issue(1, "ruling:pending", timedelta(days=1))
        malformed["created_at"] = "2026-10-01T12:00:00"
        with (
            patch.dict(
                "os.environ",
                {"GITHUB_REPOSITORY": "owner/repo", "GITHUB_TOKEN": "token"},
            ),
            patch.object(
                design_age, "fetch_open_design_issues", return_value=[malformed]
            ),
            patch("sys.stderr", new_callable=io.StringIO) as stderr,
        ):
            result = design_age.main()

        self.assertEqual(result, 2)
        self.assertIn("must include a timezone", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
