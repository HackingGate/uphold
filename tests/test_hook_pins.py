"""Behaviour tests for the hook-pin resolvability check.

Two halves, for two different reasons.

The reader is tested in-process because its contract is "model this shape,
refuse everything else by name and line" -- a refusal that does not say where
is the same silent skip a regex would have made, so the tests assert the line
number, not just the exit.

The tool is tested through a subprocess against a real local git repository,
the way a hook runner invokes it. Local paths are remotes as far as
`git ls-remote` is concerned, so the whole path -- parse, ask, exit -- runs with
no network and no fixture pretending to be one. The exit-code contract is the
interface: 0 resolves, 1 does not exist, 2 could not look.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_hook_pins.py"

sys.path.insert(0, str(ROOT / "scripts"))

import check_hook_pins  # noqa: E402
from check_hook_pins import Pin, Unreadable, read_pins, resolve_pin  # noqa: E402

GOOD = """\
repos:
  - repo: {remote}
    rev: v1.0.0
    hooks:
      - id: something
  - repo: local
    hooks:
      - id: mine
        entry: echo
"""


def parse(text: str) -> list[Pin]:
    return read_pins(text, Path("config.yaml"))


def run(*args: str, **env: str) -> subprocess.CompletedProcess:
    environ = dict(os.environ)
    environ.update(env)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=environ,
        check=False,
    )


def git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def make_remote(directory: Path) -> Path:
    """A real repository with one tag, v1.0.0, and no v1.1.0."""
    repo = directory / "remote"
    repo.mkdir()
    git("init", "-q", "-b", "main", cwd=repo)
    git("config", "user.email", "test@example.invalid", cwd=repo)
    git("config", "user.name", "test", cwd=repo)
    (repo / "README").write_text("x", encoding="utf-8")
    git("add", "README", cwd=repo)
    git("commit", "-qm", "seed", cwd=repo)
    git("tag", "v1.0.0", cwd=repo)
    return repo


class Reader(unittest.TestCase):
    def test_reads_repo_rev_and_the_line_the_rev_is_on(self):
        pins = parse(GOOD.format(remote="https://example.invalid/a"))
        self.assertEqual(pins[0].repo, "https://example.invalid/a")
        self.assertEqual(pins[0].rev, "v1.0.0")
        self.assertEqual(pins[0].line, 3)

    def test_local_entry_is_kept_with_no_rev(self):
        """Counted, not dropped: a run must be able to state its denominator."""
        pins = parse(GOOD.format(remote="https://example.invalid/a"))
        self.assertEqual(
            [pin.repo for pin in pins], ["https://example.invalid/a", "local"]
        )
        self.assertEqual(pins[1].rev, "")

    def test_a_rev_inside_hook_args_is_not_a_pin(self):
        pins = parse(
            "repos:\n"
            "  - repo: https://example.invalid/a\n"
            "    rev: v1.0.0\n"
            "    hooks:\n"
            "      - id: x\n"
            "        args: [--rev, 'rev: v9.9.9']\n"
        )
        self.assertEqual([pin.rev for pin in pins], ["v1.0.0"])

    def test_comments_and_quotes_do_not_reach_the_rev(self):
        pins = parse(
            "repos:\n"
            "  - repo: https://example.invalid/a\n"
            "    rev: 'v1.0.0'  # pinned deliberately\n"
            "    hooks:\n"
            "      - id: x\n"
        )
        self.assertEqual(pins[0].rev, "v1.0.0")

    def test_remote_repo_without_a_rev_is_unreadable(self):
        with self.assertRaises(Unreadable) as caught:
            parse(
                "repos:\n  - repo: https://example.invalid/a\n    hooks:\n      - id: x\n"
            )
        self.assertIn("has no rev", str(caught.exception))

    def test_refusals_name_the_line(self):
        cases = {
            "flow-style": "repos: [{repo: a, rev: v1}]\n",
            "a second `repos:` key": (
                "repos:\n  - repo: a\n    rev: v1\nother: 1\nrepos:\n  - repo: b\n    rev: v2\n"
            ),
            "a second `rev:` in one entry": (
                "repos:\n  - repo: a\n    rev: v1\n    rev: v2\n"
            ),
            "an anchor": "repos:\n  - repo: a\n    rev: &pin v1\n",
            "an alias": "repos:\n  - repo: a\n    rev: *pin\n",
            "tab indentation": "repos:\n\t- repo: a\n\t  rev: v1\n",
            "a second document": "repos:\n  - repo: a\n    rev: v1\n---\nrepos:\n  - repo: b\n",
        }
        for expected, text in cases.items():
            with self.subTest(expected):
                with self.assertRaises(Unreadable) as caught:
                    parse(text)
                message = str(caught.exception)
                self.assertIn(expected, message)
                self.assertRegex(message, r"config\.yaml:\d+")

    def test_a_pin_outside_the_repos_block_is_refused_not_skipped(self):
        with self.assertRaises(Unreadable) as caught:
            parse(
                "repos:\n"
                "  - repo: https://example.invalid/a\n"
                "    rev: v1.0.0\n"
                "ci:\n"
                "  - repo: https://example.invalid/b\n"
                "    rev: v2.0.0\n"
            )
        self.assertIn("outside the `repos:` block", str(caught.exception))

    def test_a_file_with_no_repos_key_is_unreadable(self):
        with self.assertRaises(Unreadable):
            parse("fail_fast: true\n")


class Resolution(unittest.TestCase):
    """`explicit-unknown`: three answers, and unchecked is not ok."""

    pin = Pin("https://example.invalid/a", "v1.0.0", Path("config.yaml"), 3)

    def test_a_matching_ref_is_ok(self):
        outcome = resolve_pin(self.pin, lambda args: (0, "abc\trefs/tags/v1.0.0\n", ""))
        self.assertEqual(outcome.state, "ok")

    def test_no_matching_ref_is_the_finding(self):
        outcome = resolve_pin(self.pin, lambda args: (0, "", ""))
        self.assertEqual(outcome.state, "missing")

    def test_an_unreachable_remote_is_unchecked_not_missing(self):
        outcome = resolve_pin(
            self.pin, lambda args: (128, "", "could not read from remote")
        )
        self.assertEqual(outcome.state, "unchecked")
        self.assertIn("could not read", outcome.detail)

    def test_a_sha_that_is_not_a_ref_tip_is_unchecked_not_missing(self):
        pin = Pin("https://example.invalid/a", "a" * 40, Path("config.yaml"), 3)
        outcome = resolve_pin(
            pin, lambda args: (0, "b" * 40 + "\trefs/heads/main\n", "")
        )
        self.assertEqual(outcome.state, "unchecked")

    def test_a_sha_at_a_ref_tip_is_ok(self):
        pin = Pin("https://example.invalid/a", "a" * 40, Path("config.yaml"), 3)
        outcome = resolve_pin(
            pin, lambda args: (0, "a" * 40 + "\trefs/heads/main\n", "")
        )
        self.assertEqual(outcome.state, "ok")


class ExitCodeContract(unittest.TestCase):
    def config_for(self, directory: Path, remote: str, rev: str) -> Path:
        path = directory / "config.yaml"
        path.write_text(
            GOOD.format(remote=remote).replace("rev: v1.0.0", f"rev: {rev}"),
            encoding="utf-8",
        )
        return path

    def test_an_existing_tag_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            remote = make_remote(Path(tmp))
            config = self.config_for(Path(tmp), str(remote), "v1.0.0")
            result = run(str(config))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("names a ref that exists", result.stdout)

    def test_a_tag_that_was_never_cut_exits_one(self):
        """The failure from issue #6: a pin bumped ahead of any release."""
        with tempfile.TemporaryDirectory() as tmp:
            remote = make_remote(Path(tmp))
            config = self.config_for(Path(tmp), str(remote), "v1.1.0")
            result = run(str(config))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("has no ref 'v1.1.0'", result.stderr)
        self.assertIn("config.yaml:3", result.stderr)

    def test_a_deleted_tag_exits_one_with_nothing_changed_locally(self):
        with tempfile.TemporaryDirectory() as tmp:
            remote = make_remote(Path(tmp))
            config = self.config_for(Path(tmp), str(remote), "v1.0.0")
            self.assertEqual(run(str(config)).returncode, 0)
            git("tag", "-d", "v1.0.0", cwd=remote)
            result = run(str(config))
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_an_unreachable_remote_exits_two_not_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.config_for(Path(tmp), str(Path(tmp) / "nowhere"), "v1.0.0")
            result = run(str(config))
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("Cannot look is not resolves", result.stderr)

    def test_unchecked_is_downgraded_only_when_somebody_asks(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.config_for(Path(tmp), str(Path(tmp) / "nowhere"), "v1.0.0")
            result = run(str(config), CATALOG_ALLOW_UNCHECKED_PINS="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("is set, so this is a note", result.stderr)

    def test_an_unreadable_config_exits_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.yaml"
            path.write_text("repos: [{repo: a, rev: v1}]\n", encoding="utf-8")
            result = run(str(path))
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("could not read", result.stderr)

    def test_a_finding_outranks_an_unresolved_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            remote = make_remote(Path(tmp))
            path = Path(tmp) / "config.yaml"
            path.write_text(
                "repos:\n"
                f"  - repo: {remote}\n"
                "    rev: v1.1.0\n"
                f"  - repo: {Path(tmp) / 'nowhere'}\n"
                "    rev: v1.0.0\n",
                encoding="utf-8",
            )
            result = run(str(path))
        self.assertEqual(result.returncode, 1, result.stdout)

    def test_no_config_at_all_exits_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run(str(Path(tmp) / "absent.yaml"))
        self.assertEqual(result.returncode, 2, result.stdout)


class SelfApplication(unittest.TestCase):
    def test_this_repository_declares_the_pins_it_reads(self):
        """The reader must find every pin in the config this repo actually ships."""
        text = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        pins = read_pins(text, ROOT / ".pre-commit-config.yaml")
        remotes = [
            pin for pin in pins if pin.repo not in check_hook_pins.NON_REMOTE_REPOS
        ]
        self.assertTrue(remotes)
        for pin in remotes:
            self.assertTrue(pin.rev, f"{pin.repo} has an empty rev")


if __name__ == "__main__":
    unittest.main()
