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
import tomllib
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


class ExitCodeContract(unittest.TestCase):
    """`explicit-unknown`: could-not-look must not be reported as clean."""

    def test_missing_declaration_is_two_not_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("could not look", result.stderr)

    def test_unreadable_declaration_is_two_not_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            build(Path(tmp), "[[enforce]] this is not toml\n")
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_a_leftover_tier_field_is_two_not_one(self):
        """A declaration written for the old schema is unreadable, not false.

        `tier` said which namespace `rule` resolved in. Ignoring a leftover one
        would silently reinterpret the claim, and refusing it as a false claim
        would send the author looking for a rule that is present.
        """
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "explicit-unknown"
                tier = "local"
                rule = "my-own-check"
                """,
                **{
                    ".pre-commit-config.yaml": PRE_COMMIT_WITH_PRINCIPLES,
                    "policy__principles.toml": "",
                },
            )
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("The field is gone", result.stderr)

    def test_absent_tier_config_is_two_not_one(self):
        """No .pre-commit-config.yaml means the claim is unverifiable, not false."""
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "fail-safe-defaults"
                rule = "prevent-public-push"
                """,
            )
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("could not look", result.stderr)

    def test_a_declaration_that_is_not_utf8_is_two_not_a_traceback(self):
        """One byte that is not UTF-8 is a file this tool could not read.

        `UnicodeDecodeError` derives from `ValueError` and not from `OSError`,
        so it escaped the handler that catches an unreadable file and left the
        process on a traceback and exit 1 -- and exit 1 in this tool means a
        claim is false. A repository whose declaration is mis-encoded was
        reported as a repository that lies about what it enforces.
        """
        with tempfile.TemporaryDirectory() as tmp:
            build(Path(tmp), "# placeholder\n")
            (Path(tmp) / "policy" / "upheld.toml").write_bytes(
                b'[[enforce]]\nprinciple = "\xff"\n'
            )
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("could not look", result.stderr)

    def test_a_policy_file_that_is_not_utf8_is_two_not_a_traceback(self):
        """The same byte in the file the claim is reconciled against."""
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "fail-safe-defaults"
                rule = "prevent-public-push"
                """,
                **{".pre-commit-config.yaml": PRE_COMMIT_WITH_PRINCIPLES},
            )
            (Path(tmp) / "policy" / "principles.toml").write_bytes(
                b'[rule.prevent-public-push]\nmessage = "\xff"\n'
            )
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("could not look", result.stderr)

    def test_empty_declaration_is_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            build(Path(tmp), "# nothing enforced yet\n")
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 0, result.stderr)


class Reconciliation(unittest.TestCase):
    def test_installed_hook_reconciles(self):
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "fail-safe-defaults"
                rule = "prevent-public-push"
                """,
                **{
                    ".pre-commit-config.yaml": PRE_COMMIT_WITH_PRINCIPLES,
                    "policy__principles.toml": GUARD_POLICY,
                },
            )
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("enforced by uphold", result.stdout)

    def test_a_lefthook_consumer_reconciles_with_no_pre_commit_config(self):
        """A repository that runs lefthook has no .pre-commit-config.yaml.

        That absence used to be could-not-look, so every lefthook consumer
        exited 2 on a declaration their own config could answer -- and the
        answer was not "unknown", it was in the file the script declined to
        look for. A remote naming this repository IS the installation.
        """
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "fail-safe-defaults"
                rule = "prevent-public-push"
                """,
                **{
                    "lefthook.yml": LEFTHOOK_WITH_PRINCIPLES,
                    "policy__principles.toml": GUARD_POLICY,
                },
            )
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("enforced by uphold", result.stdout)

    def test_the_seam_is_found_by_a_published_id_not_by_one_repositorys_name(self):
        """Every published guard id has to make its own stage visible.

        The predicate was a single literal hook name that only this repository
        used, so a consumer pinning the ids this repository publishes was told
        the seam supplying every guard was absent. The manifest is the list of
        ids now, so a new id cannot be added there and forgotten here -- and the
        stage is read from the same manifest, so the pair
        `pre-push -> uphold-guard-push` cannot drift either.
        """
        scans, guards = uphold_check.published_seams()
        self.assertIn("uphold-scan", scans)
        self.assertEqual(
            guards.get("pre-push"),
            "uphold-guard-push",
            f"the published guard ids are {guards}",
        )
        for stage, hook_id in sorted(guards.items()):
            with tempfile.TemporaryDirectory() as tmp:
                build(
                    Path(tmp),
                    """
                    [[enforce]]
                    principle = "fail-safe-defaults"
                    rule = "prevent-public-push"
                    """,
                    **{
                        ".pre-commit-config.yaml": (
                            "repos:\n"
                            "  - repo: https://github.com/HackingGate/uphold\n"
                            "    rev: v2.0.0\n"
                            "    hooks:\n"
                            f"      - id: {hook_id}\n"
                        ),
                        "policy__principles.toml": (
                            "[rule.prevent-public-push]\n"
                            'builtin = "prevent-public-push"\n'
                            f'git.hooks = ["{stage}"]\n'
                        ),
                    },
                )
                result = run(Path(tmp))
            self.assertEqual(result.returncode, 0, f"{hook_id}: {result.stderr}")
            self.assertIn("enforced by uphold", result.stdout, hook_id)

    def test_the_reconciler_s_own_id_is_not_evidence_that_a_rule_runs(self):
        """`uphold-check` runs this script, which enforces nothing.

        While every id in the manifest counted as evidence, a repository that
        pinned the reconciler and nothing else was accepted as proof that every
        content rule and every guard fires here -- the reconciler certifying
        itself, and printing "reconciled 1 enforcement claims" over a repository
        running no rule at all.
        """
        self.assertNotIn("uphold-check", uphold_check.published_hook_ids())
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "fail-safe-defaults"
                rule = "prevent-public-push"
                """,
                **{
                    ".pre-commit-config.yaml": (
                        "repos:\n"
                        "  - repo: https://github.com/HackingGate/uphold\n"
                        "    rev: v2.0.0\n"
                        "    hooks:\n"
                        "      - id: uphold-check\n"
                    ),
                    "policy__principles.toml": GUARD_POLICY,
                },
            )
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("no seam here supplies", result.stderr)

    def test_a_guard_claim_fails_when_the_stage_it_fires_at_is_not_installed(self):
        """A guard id installs one stage, and `uphold-scan` installs none.

        The seam was one repository-wide yes/no, so a repository that pinned
        `uphold-scan` -- the file scan, which runs no guard -- reconciled a
        claim on a rule declaring `git.hooks = ["pre-push"]`. The rule ran
        nowhere: what installs it is `uphold-guard-push`, which nothing here
        pinned.
        """
        for hooks, expected in (("uphold-scan", 1), ("uphold-guard-push", 0)):
            with tempfile.TemporaryDirectory() as tmp:
                build(
                    Path(tmp),
                    """
                    [[enforce]]
                    principle = "fail-safe-defaults"
                    rule = "prevent-public-push"
                    """,
                    **{
                        ".pre-commit-config.yaml": (
                            "repos:\n"
                            "  - repo: https://github.com/HackingGate/uphold\n"
                            "    rev: v2.0.0\n"
                            "    hooks:\n"
                            f"      - id: {hooks}\n"
                        ),
                        "policy__principles.toml": GUARD_POLICY,
                    },
                )
                result = run(Path(tmp))
            self.assertEqual(result.returncode, expected, f"{hooks}: {result.stderr}")

    def test_a_rule_inherited_through_inherit_paths_is_supplied(self):
        """`[inherit]` has three fields and the reader used to see one.

        `inherit.paths` names the repository's own extra policy files, which
        `config::load` merges exactly as it merges the bundled sets. Reading
        only `inherit.sets` made every rule arriving that way invisible, so a
        claim on one was refused as supplied by nothing while the engine was
        running it -- and the action a person takes on that answer is to delete
        a claim that was true.
        """
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "single-authoritative-source"
                rule = "no-merge-conflict-markers"
                """,
                **{
                    ".pre-commit-config.yaml": LOCAL_CONTENT_POLICY,
                    "policy__extra.toml": HYGIENE_BASE,
                    "policy__principles.toml": (
                        '[inherit]\npaths = ["policy/extra.toml"]\n'
                    ),
                },
            )
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("enforced by uphold", result.stdout)

    def test_the_two_readers_of_the_policy_agree(self):
        """This script and the engine must resolve the same rules.

        `content_policy_rules` re-implements part of `config::load`: the bundled
        sets, `inherit.paths`, `inherit.disabled_rules`, and a repository's own
        rule shadowing an inherited id. The engine can now be asked directly --
        `uphold rules --effective --json` -- and the reason this script does not
        simply call it is written on that function: it is the hook other
        repositories install, and two of the three runners keep the binary
        inside their own environment directory rather than on PATH.

        So the duplication stays, and this is what keeps it honest. Every field
        the two readers disagree about is a rule reported to run where it does
        not, or the other way round, and the answer a person acts on is to
        delete a claim that was true. Asked of THIS repository's policy, which
        is the one tree that exercises inheritance, disabling and shadowing at
        once.

        Skipped where the binary has not been built, because a test that needs
        a `cargo build` to be meaningful must not report a red suite to somebody
        who has not run one.
        """
        binary = ROOT / "target" / "debug" / "uphold"
        if not binary.is_file():
            self.skipTest(f"{binary} is not built; `cargo build` first")
        answered = subprocess.run(
            [str(binary), "rules", "--effective", "--json"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(answered.returncode, 0, answered.stderr)
        engine = {
            entry["id"]: set(entry["git_hooks"])
            for entry in json.loads(answered.stdout)
        }
        declared, disabled, _sets, _paths = uphold_check.content_policy_rules(ROOT)
        here = {
            rule: stages for rule, stages in declared.items() if rule not in disabled
        }
        self.assertEqual(here, engine)

    def test_inherit_paths_naming_a_file_that_is_not_there_is_two_not_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "single-authoritative-source"
                rule = "no-merge-conflict-markers"
                """,
                **{
                    ".pre-commit-config.yaml": LOCAL_CONTENT_POLICY,
                    "policy__principles.toml": (
                        '[inherit]\npaths = ["policy/gone.toml"]\n'
                    ),
                },
            )
            result = run(Path(tmp))
            coverage = run(Path(tmp), "--coverage")
        # A policy file the engine merges and this reader cannot open is a seam
        # that could not be read, which is exit 2 at both ends -- and the
        # coverage report is where the file that could not be opened is named.
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("could not look", result.stderr)
        self.assertEqual(coverage.returncode, 2, coverage.stdout)
        self.assertIn("inherit.paths", coverage.stdout)

    def test_a_lefthook_key_that_is_not_a_command_is_not_a_rule(self):
        """`configs:` under `remotes:` is not a rule called `configs`.

        README.md tells every lefthook consumer to write that key, at exactly
        the indent a command name sits at, so a scan keyed on indentation
        accepted a claim on it -- a green reconcile over a rule that exists
        nowhere. What makes a command name a command name is `commands:` above
        it, which is what the scan reads now.
        """
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "fail-safe-defaults"
                rule = "configs"
                """,
                **{
                    "lefthook.yml": LEFTHOOK_WITH_PRINCIPLES,
                    "policy__principles.toml": GUARD_POLICY,
                },
            )
            refused = run(Path(tmp))

            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "fail-safe-defaults"
                rule = "my-own-check"
                """,
            )
            command = run(Path(tmp))
        self.assertEqual(refused.returncode, 1, refused.stdout)
        self.assertIn("no seam here supplies", refused.stderr)
        # The command in the same file, which is a rule, still resolves -- the
        # fix is a narrower scan and not a disabled one.
        self.assertEqual(command.returncode, 0, command.stderr)
        self.assertIn("enforced by local", command.stdout)

    def test_a_consumer_inheriting_a_bundled_base_set_can_be_read(self):
        """`inherit.sets` names a set that ships HERE, not in the consumer.

        The engine compiles the base sets into the binary with `include_str!`,
        so a consuming repository inherits rules whose file it does not have
        and never will. Resolving the name against their tree turns every such
        repository into exit 2 on a declaration that is fine.
        """
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "fail-safe-defaults"
                rule = "prevent-public-push"
                """,
                **{
                    ".pre-commit-config.yaml": PRE_COMMIT_WITH_PRINCIPLES,
                    "policy__principles.toml": (
                        '[inherit]\nsets = ["process-residue"]\n' + GUARD_POLICY
                    ),
                },
            )
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("enforced by uphold", result.stdout)

    def test_uninstalled_hook_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "fail-safe-defaults"
                rule = "no-merge-commit"
                """,
                **{
                    ".pre-commit-config.yaml": PRE_COMMIT_WITH_PRINCIPLES,
                    "policy__principles.toml": "",
                },
            )
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("no seam here supplies", result.stderr)

    def test_disabled_content_policy_rule_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "single-authoritative-source"
                rule = "no-merge-conflict-markers"
                """,
                **{
                    ".pre-commit-config.yaml": LOCAL_CONTENT_POLICY,
                    "policy__base__process-residue.toml": HYGIENE_BASE,
                    "policy__principles.toml": (
                        "[inherit]\n"
                        'sets = ["process-residue"]\n'
                        'disabled_rules = ["no-merge-conflict-markers"]\n'
                    ),
                },
            )
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("no seam here supplies", result.stderr)

    def test_a_language_rule_claim_resolves(self):
        """The drift this schema deleted, pinned so it cannot come back.

        The reconciler walked a hardcoded list of six array-of-tables names
        against an engine that had seven. `language_rule` was the missing one,
        so a claim naming a language rule was reported as enforcing nothing
        while it was in fact enforced -- and neither repository could catch it,
        because the list was a literal in one describing a constant in the
        other.
        """
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "least-astonishment"
                rule = "latin-only-docs"
                """,
                **{
                    ".pre-commit-config.yaml": LOCAL_CONTENT_POLICY,
                    "policy__principles.toml": (
                        "[rule.latin-only-docs]\n"
                        'allowed_scripts = ["Latin"]\n'
                        'files.glob = ["*.md"]\n'
                    ),
                },
            )
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_cmd_shims_check_must_be_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "complete-mediation"
                rule = "prevent-ai-author"
                """,
                **{
                    ".pre-commit-config.yaml": PRE_COMMIT_WITH_PRINCIPLES,
                    "policy__principles.toml": "",
                    ".cmd-shims__checks.enabled": "# only this one\nno-os-identity\n",
                },
            )
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("no seam here supplies", result.stderr)

    def test_a_rule_enforced_by_two_seams_reports_both(self):
        """A rule enforced by more than one tool is the ordinary case.

        `prevent-ai-author` is a commit-msg hook in git-guards and a checker in
        cmd-shims, because a commit message and a pull-request body are two
        paths to the same public place. A structure holding one supplier per
        rule id would have had to call one of them a duplicate, which inverts
        what the two entries mean -- and `complete-mediation` is the record
        saying a control is only as wide as the paths it mediates.
        """
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "complete-mediation"
                rule = "prevent-ai-author"
                """,
                **{
                    ".pre-commit-config.yaml": PRE_COMMIT_WITH_PRINCIPLES,
                    "policy__principles.toml": (
                        "[rule.prevent-ai-author]\n"
                        'builtin = "prevent-ai-author"\n'
                        'git.hooks = ["commit-msg"]\n'
                    ),
                    ".cmd-shims__checks.enabled": "prevent-ai-author\n",
                },
            )
            result = run(Path(tmp))
            coverage = run(Path(tmp), "--coverage")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("enforced by uphold, cmd-shims", result.stdout)
        # And it is claimed under BOTH seams in the coverage report, rather than
        # counting once and leaving the other seam's copy looking unclaimed.
        self.assertEqual(
            coverage.stdout.count("claimed    prevent-ai-author -> complete-mediation"),
            2,
            coverage.stdout,
        )

    def test_unknown_principle_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "no-such-principle"
                rule = "my-own-check"
                """,
                **{
                    ".pre-commit-config.yaml": PRE_COMMIT_WITH_PRINCIPLES,
                    "policy__principles.toml": "",
                },
            )
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("unknown principle id", result.stderr)


class NoProseInRuntime(unittest.TestCase):
    """`enforcement-needs-a-trigger`: the tool must not carry principle text."""

    def test_output_contains_no_record_prose(self):
        result = run(ROOT)
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
                    "policy__principles.toml": "",
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


class Coverage(unittest.TestCase):
    """The denominator the reconcile cannot see: rules running under no claim.

    `--coverage` counts the direction the declaration does not: it walks what the
    four tiers actually run here and reports which of those rules any claim
    names. It reports and does not refuse -- a mode that failed a build over an
    unclaimed rule would be paid for in claims written to silence it.
    """

    DECLARATION = """
        [[enforce]]
        principle = "fail-safe-defaults"
        rule = "prevent-public-push"
        """

    # Both guard stages the policy below declares are pinned, because a rule
    # whose stage nothing installs is a rule that runs nowhere and does not
    # belong in this denominator.
    PRE_COMMIT = """\
repos:
  - repo: https://github.com/HackingGate/uphold
    rev: v2.0.0
    hooks:
      - id: uphold-scan
      - id: uphold-guard
      - id: uphold-guard-push
  - repo: local
    hooks:
      - id: my-own-check
        name: my own check
"""

    POLICY = """\
[rule.prevent-public-push]
builtin = "prevent-public-push"
git.hooks = ["pre-push"]

[rule.no-merge-commit]
builtin = "no-merge-commit"
git.hooks = ["pre-commit"]
"""

    def coverage(self, tmp: str) -> subprocess.CompletedProcess:
        build(
            Path(tmp),
            self.DECLARATION,
            **{
                ".pre-commit-config.yaml": self.PRE_COMMIT,
                "policy__principles.toml": self.POLICY,
            },
        )
        return run(Path(tmp), "--coverage")

    def test_a_claimed_rule_is_reported_against_its_principle(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.coverage(tmp)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("prevent-public-push -> fail-safe-defaults", result.stdout)
        self.assertIn("uphold: 1 of 2", result.stdout)

    def test_a_rule_no_claim_names_is_reported_as_unclaimed(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.coverage(tmp)
        self.assertIn("unclaimed  no-merge-commit", result.stdout)
        self.assertIn("my-own-check", result.stdout)

    def test_a_seam_not_in_use_counts_zero_and_exits_zero(self):
        # A repository with no `.cmd-shims/checks.enabled` is not running
        # cmd-shims. That is a real zero, and it has to be told apart from the
        # hole below -- while a claim named its seam the two could be conflated
        # harmlessly, and once a claim resolves against every seam, calling
        # "not in use" unreadable makes a reconcile that can never say `false`.
        with tempfile.TemporaryDirectory() as tmp:
            result = self.coverage(tmp)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("cmd-shims: 0 of 0 rules", result.stdout)

    def test_a_seam_that_could_not_be_read_is_not_a_seam_running_nothing(self):
        # The count is `?`, not 0, and the exit code is 2: an unreadable seam is
        # a hole in the denominator, and a hole reported as zero reads as
        # coverage that was never measured.
        with tempfile.TemporaryDirectory() as tmp:
            build(Path(tmp), self.DECLARATION)  # no .pre-commit-config.yaml
            result = run(Path(tmp), "--coverage")
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("local: 0 of ? rules", result.stdout)

    def test_a_false_claim_is_reported_rather_than_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "fail-safe-defaults"
                rule = "no-such-hook"
                """,
                **{
                    ".pre-commit-config.yaml": self.PRE_COMMIT,
                    ".cmd-shims__checks.enabled": "no-os-identity\n",
                    "policy__principles.toml": "",
                },
            )
            result = run(Path(tmp), "--coverage")
            reconcile = run(Path(tmp))
        self.assertEqual(reconcile.returncode, 1, reconcile.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "claimed but supplied by nothing here: no-such-hook", result.stdout
        )

    def test_an_orphan_claim_is_not_counted_in_the_number_it_was_reported_under(self):
        """The numerator counted the orphans the same report had just named.

        `records: N of M claimable records are claimed by a rule here` is the
        one number a reader takes away, and it was computed from the claims
        rather than from what any seam supplies -- so a declaration whose only
        claim names a rule nothing runs reported one record as claimed by a rule
        here, two lines under the line saying that rule is supplied by nothing.
        """
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                """
                [[enforce]]
                principle = "fail-safe-defaults"
                rule = "no-such-hook"
                """,
                **{
                    ".pre-commit-config.yaml": self.PRE_COMMIT,
                    "policy__principles.toml": "",
                },
            )
            result = run(Path(tmp), "--coverage")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "claimed but supplied by nothing here: no-such-hook", result.stdout
        )
        self.assertIn("records: 0 of ", result.stdout)

    def test_it_counts_records_against_what_can_be_claimed(self):
        result = run(ROOT, "--coverage")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("claimable records are claimed by a rule here", result.stdout)

    def test_a_bundled_base_set_is_counted_and_named(self):
        """The one hole in this report, now closed.

        While the base set lived in another repository at a pinned rev its rules
        ran here and could not be enumerated from here, so the tier was reported
        as locally declared rules plus a note naming what could not be seen.
        The sets ship in this repository now, so they are counted -- and still
        named, because a reader has to know which ones went into the number.
        """
        with tempfile.TemporaryDirectory() as tmp:
            build(
                Path(tmp),
                "# nothing enforced yet\n",
                **{
                    ".pre-commit-config.yaml": LOCAL_CONTENT_POLICY,
                    "policy__base__process-residue.toml": HYGIENE_BASE,
                    "policy__principles.toml": (
                        '[inherit]\nsets = ["process-residue"]\n'
                    ),
                    ".cmd-shims__checks.enabled": "no-os-identity\n",
                },
            )
            result = run(Path(tmp), "--coverage")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bundled base set", result.stdout)
        self.assertIn("no-merge-conflict-markers", result.stdout)

    def test_coverage_carries_no_record_prose(self):
        result = run(ROOT, "--coverage")
        for record in uphold_check.load_records().values():
            self.assertNotIn(record["claim"], result.stdout)


class SelfApplication(unittest.TestCase):
    def test_this_repository_reconciles(self):
        result = run(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("explicit-unknown <- catalog-tests", result.stdout)

    def test_starter_declaration_is_valid_and_enforces_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            starter = run(ROOT, "--init")
            self.assertEqual(starter.returncode, 0, starter.stderr)
            build(Path(tmp), starter.stdout)
            result = run(Path(tmp))
        self.assertEqual(result.returncode, 0, result.stderr)


class UpstreamIdentity(unittest.TestCase):
    """Who this repository is, is stated once and read everywhere else.

    The reconciler has to recognise a lefthook consumer that names this
    repository under `remotes:`, and the OSCAL export has to stamp a namespace.
    Both used to spell `owner/name` out as a literal beside a `repository` field
    in Cargo.toml that already said it -- two copies of one fact, which is what
    `single-authoritative-source` refuses. The drift is the silent direction: a
    rename that lands in the manifest and not in the literal leaves the seam
    unrecognised, which reads as "no runner configuration here" rather than as a
    stale pattern, so nothing anywhere says the check stopped matching.
    """

    def test_the_slug_is_derived_from_the_cargo_manifest(self) -> None:
        cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        url = cargo["package"]["repository"]

        self.assertEqual(uphold_check.upstream_url(), url)
        self.assertEqual(uphold_check.upstream_slug(), "/".join(url.split("/")[-2:]))
        # Asserted through the reader rather than against its pattern: the
        # pattern is gone, and what the drift would break is the recognition.
        slug = uphold_check.upstream_slug()
        self.assertTrue(
            uphold_check.includes_our_lefthook_remote(
                f"remotes:\n"
                f"  - git_url: https://github.com/{slug}\n"
                f"    ref: v1.0.0\n"
                f"    configs:\n"
                f"      - hooks/lefthook.yml\n"
            )
        )

    def test_a_remote_naming_this_repository_without_an_owner_is_still_ours(
        self,
    ) -> None:
        """lefthook takes any git url, and most of them carry no `owner/name`.

        Requiring the slug rejected a clone by filesystem path, which is exactly
        what `scripts/consumer_check.sh` writes: the parity harness points the
        consumer at the checkout under test. A consumer wired the way the
        documentation describes was reported as running no seam at all, and the
        one CI job that drives a real lefthook consumer refused a clean commit.
        """
        name = uphold_check.upstream_slug().rsplit("/", 1)[-1]
        for url in (
            f"/home/runner/work/{name}/{name}",
            f"git@github.com:HackingGate/{name}.git",
            f"/tmp/mirror/{name}.git",
        ):
            with self.subTest(url=url):
                self.assertTrue(
                    uphold_check.includes_our_lefthook_remote(
                        f"remotes:\n"
                        f"  - git_url: {url}\n"
                        f"    ref: v1.0.0\n"
                        f"    configs:\n"
                        f"      - hooks/lefthook.yml\n"
                    )
                )

    def test_a_remote_is_only_ours_when_one_entry_says_both(self) -> None:
        """Neither half alone, because the branch it feeds grants every stage.

        This read as an alternation, so a fork of this repository pinning its own
        config, or an unrelated project whose config happens to carry the
        conventional filename, was credited with running every guard published
        here.
        """
        slug = uphold_check.upstream_slug()
        ours_but_another_config = (
            f"remotes:\n"
            f"  - git_url: https://github.com/{slug}\n"
            f"    configs:\n"
            f"      - hooks/something-else.yml\n"
        )
        our_filename_from_elsewhere = (
            "remotes:\n"
            "  - git_url: https://github.com/someone/unrelated\n"
            "    configs:\n"
            "      - hooks/lefthook.yml\n"
        )
        split_across_two_entries = (
            f"remotes:\n"
            f"  - git_url: https://github.com/{slug}\n"
            f"    configs:\n"
            f"      - hooks/something-else.yml\n"
            f"  - git_url: https://github.com/someone/unrelated\n"
            f"    configs:\n"
            f"      - hooks/lefthook.yml\n"
        )

        self.assertFalse(
            uphold_check.includes_our_lefthook_remote(ours_but_another_config)
        )
        self.assertFalse(
            uphold_check.includes_our_lefthook_remote(our_filename_from_elsewhere)
        )
        self.assertFalse(
            uphold_check.includes_our_lefthook_remote(split_across_two_entries)
        )

    def test_the_python_manifest_names_the_same_repository(self) -> None:
        """The one copy that survives, because no backend derives it.

        maturin reads Cargo.toml for the version and the binary, but
        `[project.urls]` is pyproject's own and nothing reconciles the two. So
        the copy is allowed and the drift is not -- this is the check that makes
        the difference.
        """
        cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

        self.assertEqual(
            pyproject["project"]["urls"]["Repository"],
            cargo["package"]["repository"],
            "pyproject.toml and Cargo.toml name different repositories; rename "
            "both in the commit that renames either",
        )


if __name__ == "__main__":
    unittest.main()
