"""Behaviour tests for the reconciler.

The exit-code contract is tested through a subprocess, the way a hook runner
invokes it, because the contract *is* the interface: 0 clean, 1 refused, 2 could
not look. Asserting it in-process would test the function and not the tool.
"""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "uphold_check.py"

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


# The guards are this repository's own rules now, so the seam that supplies one
# is `uphold`, and what installs it is a PUBLISHED hook id -- what a
# consumer actually writes. The fixture used to name a local hook called
# `content-policy`, which is a command in this repository's own lefthook.yml and
# in no consumer's config anywhere, so it asserted a shape only this repository
# had.
#
# One id per stage, and the fixture pins the stages the policy fixtures below
# declare. A guard id installs exactly ONE git stage, so pinning `uphold-scan`
# and `uphold-guard-push` is evidence about the file scan and about pre-push and
# about nothing else.
PRE_COMMIT_WITH_PRINCIPLES = """\
repos:
  - repo: https://github.com/HackingGate/uphold
    rev: v2.0.0
    hooks:
      - id: uphold-scan
      - id: uphold-guard-commit-msg
      - id: uphold-guard-push
  - repo: local
    hooks:
      - id: my-own-check
        name: my own check
"""

# The same repository, run by lefthook instead: no ids, no pins, just this
# repository named as a remote. The seam has to be visible from here too.
#
# The `configs:` key is the shape README.md tells every lefthook consumer to
# write, and it is a valueless mapping key at exactly the indent a command name
# sits at -- so a scan keyed on indentation read it as a command called
# `configs`, and a claim naming that rule reconciled green against a file that
# defines no such thing. The real command below is what a command name looks
# like, and the two have to be told apart from here.
LEFTHOOK_WITH_PRINCIPLES = """\
remotes:
  - git_url: https://github.com/HackingGate/uphold
    ref: v2.0.0
    configs:
      - hooks/lefthook.yml

pre-commit:
  commands:
    my-own-check:
      run: ./check.sh
"""

# One guard, declared the way a repository declares one.
GUARD_POLICY = """\
[rule.prevent-public-push]
builtin = "prevent-public-push"
git.hooks = ["pre-push"]
"""


# The content policy is this repository's own hook now, not a pinned clone of
# another repository's.
LOCAL_CONTENT_POLICY = """\
repos:
  - repo: https://github.com/HackingGate/uphold
    rev: v2.0.0
    hooks:
      - id: uphold-scan
"""

# One rule, in the unified schema, standing in for the bundled process-residue set.
HYGIENE_BASE = """\
[rule.no-merge-conflict-markers]
message = "no conflict markers"
regexp = '^<{7} '
files.include = ["."]
"""


# A repository both readers can be asked about at once: one guard whose stage a
# pinned id installs, and one content rule the pinned scan runs. Two seams, so an
# export that lost either would still look plausible on its own.
DIFFERENTIAL_DECLARATION = """
[[enforce]]
principle = "fail-safe-defaults"
rule = "prevent-public-push"

[[enforce]]
principle = "explicit-unknown"
rule = "no-merge-conflict-markers"
"""


def run(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def build(directory: Path, declaration: str, **files: str) -> None:
    (directory / "policy").mkdir(parents=True, exist_ok=True)
    (directory / "policy" / "upheld.toml").write_text(
        textwrap.dedent(declaration), encoding="utf-8"
    )
    for name, body in files.items():
        path = directory / name.replace("__", "/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")


@needs_the_engine
class NoProseInRuntime(unittest.TestCase):
    """`enforcement-needs-a-trigger`: the tool must not carry principle text."""

    def test_the_catalog_modes_carry_no_record_prose_into_a_report(self):
        # `--list` is the mode a runtime is most likely to pipe somewhere. The
        # reconcile's half of this invariant moved with the reconcile and is
        # asserted in tests/check_cli.rs.
        result = run(ROOT, "--list")
        self.assertEqual(result.returncode, 0, result.stderr)
        records = uphold_check.load_records()
        for record in records.values():
            self.assertNotIn(record["claim"], result.stdout)
            for question in record["review_questions"]:
                self.assertNotIn(question, result.stdout)

    def test_the_reconcile_still_carries_no_prose_now_that_a_review_mode_exists(self):
        """This test used to assert that `--review` did not exist at all.

        It was the right invariant while the only destinations for prose were
        static tiers: `enforcement-needs-a-trigger` refuses prose to a tool with
        no condition on which to emit it, and the reconcile is exactly such a
        tool. The record now carves out a tier that conditions on a change AND
        bounds its own length, so the mode exists -- and the invariant this
        class is named for is unchanged and still tested above: the RECONCILE
        carries no prose. The prose lives in a document `--review --emit`
        compiles, which nothing injects into a runtime.
        """
        result = run(ROOT, "--review")
        self.assertEqual(result.returncode, 0, result.stderr)
        records = uphold_check.load_records()
        # The routing REPORT is not the compiled document, and must not become
        # one by accident.
        for record in records.values():
            self.assertNotIn(record["claim"], result.stdout)

    def test_the_review_tier_may_not_exist_without_its_ceiling(self):
        """The other half of the carve-out, asserted rather than assumed.

        Without the ceiling the record refuses this tier outright, so a
        configuration that removes it must not quietly produce a document.
        """
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [review]
                max_lines = 5
                """,
                **{
                    ".pre-commit-config.yaml": PRE_COMMIT_WITH_PRINCIPLES,
                    "policy__principles.toml": GUARD_POLICY,
                },
            )
            result = run(Path(tmp), "--review")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("Do not raise the ceiling", result.stderr)


@needs_the_engine
class OscalExport(unittest.TestCase):
    """The mapping crosses to OSCAL; the records deliberately do not."""

    def setUp(self):
        result = run(ROOT, "--oscal")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.document = json.loads(result.stdout)["component-definition"]

    def test_required_oscal_fields_are_present(self):
        for field in ("uuid", "metadata", "components"):
            self.assertIn(field, self.document)
        for field in ("title", "last-modified", "version", "oscal-version"):
            self.assertIn(field, self.document["metadata"])

    def test_one_component_per_tier_with_its_claims(self):
        titles = {component["title"] for component in self.document["components"]}
        self.assertIn("local", titles)
        controls = {
            requirement["control-id"]
            for component in self.document["components"]
            for implementation in component["control-implementations"]
            for requirement in implementation["implemented-requirements"]
        }
        self.assertIn("explicit-unknown", controls)

    def test_consolidated_rules_are_requirements_of_uphold(self):
        """The former command-shim seam is supplied by Uphold now."""
        by_component = {
            component["title"]: {
                requirement["props"][0]["value"]
                for implementation in component["control-implementations"]
                for requirement in implementation["implemented-requirements"]
            }
            for component in self.document["components"]
        }
        self.assertIn("prevent-ai-author", by_component["uphold"])
        self.assertNotIn("cmd-shims", by_component)

    def test_identifiers_are_stable_across_runs(self):
        """A re-export must not be a diff with no change in it.

        OSCAL requires a uuid on every component and requirement. Generated
        randomly, every export would differ from the last while saying nothing,
        which is how a generated file stops being read.
        """
        again = json.loads(run(ROOT, "--oscal").stdout)["component-definition"]
        self.assertEqual(self.document, again)

    def test_no_record_prose_crosses_over(self):
        """`claim`, `costs` and the rest have no OSCAL home and are not smuggled in."""
        blob = json.dumps(self.document)
        for record in uphold_check.load_records().values():
            self.assertNotIn(record["claim"], blob)
            for cost in record["costs"]:
                self.assertNotIn(cost, blob)

    def test_a_refused_declaration_exports_nothing(self):
        """An export is an assertion to an outside reader; it must reconcile first."""
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "explicit-unknown"
                rule = "no-such-hook"
                """,
                **{
                    ".pre-commit-config.yaml": PRE_COMMIT_WITH_PRINCIPLES,
                    "policy__principles.toml": "",
                },
            )
            result = run(Path(tmp), "--oscal")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(result.stdout.strip(), "")


@needs_the_engine
class TheTwoReadersOfOneReport(unittest.TestCase):
    """The binary decides which rules run; the export must carry that answer whole.

    Since the reconcile moved into the loader, this script no longer derives a
    rule set of its own -- it PARSES the binary's report. That closes the old
    disagreement and opens a quieter one: a parser that stops recognising the
    report it reads produces an empty answer rather than an error, and an empty
    answer here is a component definition with no components, published at exit
    0 over a repository whose reconcile had just succeeded on every claim.
    """

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.tmp = Path(self._directory.name)
        self.addCleanup(self._directory.cleanup)
        build(
            self.tmp,
            DIFFERENTIAL_DECLARATION,
            **{
                ".pre-commit-config.yaml": PRE_COMMIT_WITH_PRINCIPLES,
                "policy__principles.toml": GUARD_POLICY + HYGIENE_BASE,
            },
        )

    def test_the_binary_and_the_export_name_the_same_rules(self):
        """The differential: one fixture, both readers, one rule set.

        The binary's half is read from its own header count and not from the
        evidence lines, so this does not check the parser against itself.
        """
        check = uphold_check.engine(self.tmp, "check")
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn("reconciled 2 enforcement claims:", check.stdout)

        exported = run(self.tmp, "--oscal")
        self.assertEqual(exported.returncode, 0, exported.stderr)
        requirements = [
            requirement
            for component in json.loads(exported.stdout)["component-definition"][
                "components"
            ]
            for implementation in component["control-implementations"]
            for requirement in implementation["implemented-requirements"]
        ]
        self.assertEqual(len(requirements), 2, exported.stdout)
        rules = {
            prop["value"]
            for requirement in requirements
            for prop in requirement["props"]
            if prop["name"] == "rule-id"
        }
        self.assertEqual(rules, {"prevent-public-push", "no-merge-conflict-markers"})

    def test_a_report_this_reader_cannot_parse_is_could_not_look(self):
        """One word of the report changes, and the reader recovers nothing.

        Before the count check this returned `{}`, which is indistinguishable
        from a repository where no claim is supplied by anything.
        """
        real = uphold_check.engine

        def drifted(root, *args):
            answered = real(root, *args)
            if args[:1] == ("check",):
                answered.stdout = answered.stdout.replace("enforced by", "supplied by")
            return answered

        with (
            mock.patch.object(uphold_check, "engine", drifted),
            self.assertRaises(uphold_check.CouldNotLook) as raised,
        ):
            uphold_check.engine_suppliers(self.tmp)
        self.assertIn("2 reconciled claim(s)", str(raised.exception))
        self.assertIn("0 evidence line(s)", str(raised.exception))

    def test_a_drifted_report_publishes_no_component_definition(self):
        """Could not look is exit 2 and no document, not exit 0 and an empty one."""
        real = uphold_check.engine

        def drifted(root, *args):
            answered = real(root, *args)
            if args[:1] == ("check",):
                answered.stdout = answered.stdout.replace("enforced by", "supplied by")
            return answered

        stdout = io.StringIO()
        with (
            contextlib.chdir(self.tmp),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(io.StringIO()),
            mock.patch.object(uphold_check, "engine", drifted),
        ):
            code = uphold_check.main(["--oscal"])
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue().strip(), "")


class AnUnreadableDeclaration(unittest.TestCase):
    """`explicit-unknown`, claimed by `catalog-tests` in policy/upheld.toml.

    The claim names this file for this assertion: a declaration this tool could
    not read exits 2. Not 0, which would be a repository reported as complying
    on a file nobody could open, and not 1 -- exit 1 in this tool means a claim
    is FALSE, and one stray byte is not an untrue claim.

    No engine is needed: the declaration is read before anything is asked of
    the binary, which is the point. The catalog job runs on an image with no
    Rust toolchain, and this assertion has to hold there too.
    """

    def setUp(self):
        self._directory = tempfile.TemporaryDirectory()
        self.tmp = Path(self._directory.name)
        self.addCleanup(self._directory.cleanup)
        (self.tmp / "policy").mkdir()

    def write_declaration(self, body: bytes) -> None:
        (self.tmp / "policy" / "upheld.toml").write_bytes(body)

    def test_a_declaration_that_is_not_utf_8_is_two_and_not_a_traceback(self):
        # `tomllib.load` takes a binary handle and decodes the bytes itself, so
        # a stray 0xff raises `UnicodeDecodeError` out of the DECODE and never
        # reaches `TOMLDecodeError`. It derives from `ValueError` and not from
        # `OSError`, which is how it escaped the handler entirely and left the
        # process on a traceback and exit 1.
        self.write_declaration(b'[[enforce]]\nprinciple = "\xff"\nrule = "x"\n')
        result = run(self.tmp, "--oscal")
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("could not look", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(result.stdout.strip(), "")

    def test_the_review_mode_reads_the_same_declaration_the_same_way(self):
        """`--review` reaches `read_toml` by its own route and owes the same answer."""
        self.write_declaration(b"[review]\nmax_lines = 900  # \xff\n")
        result = run(self.tmp, "--review")
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("could not look", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_a_declaration_that_is_not_there_is_two(self):
        """The other unreadable: nothing to read at all, from a directory with none."""
        result = run(self.tmp, "--oscal")
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(result.stdout.strip(), "")
