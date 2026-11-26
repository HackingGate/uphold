from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "absence_factor.py"

sys.path.insert(0, str(ROOT / "scripts"))

from absence_factor import absence_factor  # noqa: E402


def run(stdin: bytes) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=stdin,
        capture_output=True,
        check=False,
    )


class AbsenceFactorTests(unittest.TestCase):
    def test_one_author_over_half_is_one(self) -> None:
        self.assertEqual(absence_factor(["a"] * 6 + ["b"] * 3 + ["c"]), 1)

    def test_one_author_at_exactly_half_is_one(self) -> None:
        # CHAOSS counts the contributors who reach half, so half is enough.
        self.assertEqual(absence_factor(["a", "a", "b", "c"]), 1)

    def test_two_authors_needed_is_two(self) -> None:
        self.assertEqual(absence_factor(["a"] * 3 + ["b"] * 2 + ["c"] * 2), 2)

    def test_blank_lines_and_padding_are_not_authors(self) -> None:
        self.assertEqual(absence_factor(["a", " a ", "", "b", "c", "  "]), 1)

    def test_no_commits_is_unknown(self) -> None:
        self.assertIsNone(absence_factor([]))
        self.assertIsNone(absence_factor(["", " "]))

    def test_cli_prints_the_factor(self) -> None:
        result = run(b"a\nb\nb\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"factor 1\n")

    def test_cli_empty_list_is_unknown_not_a_pass(self) -> None:
        result = run(b"")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"unknown:", result.stderr)

    def test_cli_unreadable_list_is_unknown(self) -> None:
        result = run(b"\xff\xfe not utf-8\n")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"unknown:", result.stderr)


if __name__ == "__main__":
    unittest.main()
