"""Behaviour tests for the reconciler.

The exit-code contract is tested through a subprocess, the way a hook runner
invokes it, because the contract *is* the interface: 0 clean, 1 refused, 2 could
not look. Asserting it in-process would test the function and not the tool.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "uphold_check.py"

sys.path.insert(0, str(ROOT))

import uphold_check  # noqa: E402

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
