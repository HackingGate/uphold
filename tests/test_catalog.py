from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "scripts"))

from analysis import ANALYZER, matches, normalize, tokens  # noqa: E402
from build_reference import cell  # noqa: E402
from build_reference import render as render_reference  # noqa: E402
from catalog import alias_index, load_catalog, name_entries, resolve  # noqa: E402
from validate import (  # noqa: E402
    DOMAINS,
    KINDS,
    RUNGS,
    name_collisions,
    validate_records,
)


class CatalogTests(unittest.TestCase):
    def test_catalog_validates(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/validate.py"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_quick_reference_is_current(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/build_reference.py", "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


class TextAnalysis(unittest.TestCase):
    """The key is what a search compares; these are the spellings it absorbs.

    Each case is a way one name gets typed differently from how a record wrote
    it. If a step of the chain is dropped, the pair it folded stops matching and
    exactly one of these fails.
    """

    def test_case_and_spacing_fold_into_one_key(self):
        for written, typed in (
            ("Fail fast", "FAIL FAST"),
            ("Fail fast", "  fail   fast  "),
            ("Fail-Safe Defaults", "fail safe defaults"),
            ("Parameterize, Do Not Enumerate", "parameterize do not enumerate"),
            ("Calculator with one_plus_one()", "calculator with one plus one"),
        ):
            with self.subTest(written=written, typed=typed):
                self.assertEqual(normalize(written), normalize(typed))

    def test_unicode_folds_the_way_a_paste_produces_it(self):
        self.assertEqual(normalize("naïve caching"), normalize("naive caching"))
        self.assertEqual(normalize("ﬁle handles"), normalize("file handles"))
        self.assertEqual(normalize("ＦＵＬＬＷＩＤＴＨ"), "fullwidth")
        self.assertEqual(normalize("Grüßen"), normalize("grussen"))

    def test_a_pipe_is_a_separator_not_an_escape(self):
        # The complaint that started this: a Markdown cell escapes `|` to `\|`,
        # so anything reading a rendered row back has to undo that. The key
        # never sees the character at all.
        self.assertEqual(normalize("read | write"), "read write")

    def test_a_name_with_no_searchable_characters_has_no_key(self):
        for value in ("", "   ", "---", "()"):
            with self.subTest(value=value):
                self.assertEqual(normalize(value), "")
                self.assertEqual(tokens(value), ())

    def test_tokens_keep_written_order(self):
        self.assertEqual(
            tokens("Cohesion and coupling"), ("cohesion", "and", "coupling")
        )

    def test_match_requires_every_term_the_reader_typed(self):
        name = tokens("Principle of least privilege")
        self.assertTrue(matches("least privilege", name))
        self.assertTrue(matches("PRIVILEGE, least", name))
        self.assertFalse(matches("least privilege escalation", name))
        self.assertFalse(matches("", name))

    def test_the_chain_is_versioned(self):
        self.assertEqual(ANALYZER["version"], 1)
        self.assertEqual(ANALYZER["steps"][0], "unicode-nfkc")


class TheNameIndex(unittest.TestCase):
    """A record is titled for the constraint; it is searched for by its failure.

    `aliases` holds the names people arrive with -- "combinatorial explosion",
    not "Parameterize, Do Not Enumerate" -- so the index that resolves them is a
    value the catalog holds. These assertions are against that value. Nothing
    here parses a rendering: a row's column order and its `|` escaping are
    layout decisions, and a test that asserts them makes the layout an interface
    nobody agreed to.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.records = load_catalog()
        cls.entries = name_entries(cls.records)

    def test_every_alias_resolves_to_the_record_that_wrote_it(self):
        owners = {(entry.name, entry.record_id) for entry in alias_index(self.records)}
        for record in self.records:
            for alias in record["aliases"]:
                with self.subTest(record=record["id"], alias=alias):
                    self.assertIn((alias, record["id"]), owners)

    def test_every_record_carries_at_least_one_alias(self):
        for record in self.records:
            with self.subTest(record=record["id"]):
                self.assertTrue(record["aliases"])

    def test_titles_and_aliases_are_one_namespace(self):
        fields = {entry.field for entry in self.entries}
        self.assertEqual(fields, {"title", "alias"})
        self.assertEqual(
            len(self.entries),
            sum(1 + len(record["aliases"]) for record in self.records),
        )

    def test_no_two_names_share_a_key(self):
        keys = [entry.key for entry in self.entries]
        self.assertEqual(len(keys), len(set(keys)))

    def test_entries_are_sorted_by_key(self):
        # Order is part of what makes the generated artifact a diff only when
        # the catalog changed.
        self.assertEqual(
            [entry.key for entry in self.entries],
            sorted(entry.key for entry in self.entries),
        )

    def test_an_entry_knows_the_record_path(self):
        entry = next(entry for entry in self.entries if entry.field == "title")
        self.assertEqual(entry.path, f"principles/{entry.record_id}.toml")
        self.assertTrue((ROOT / entry.path).is_file())

    def test_resolve_answers_an_exact_name(self):
        hits = resolve("combinatorial explosion", self.records)
        self.assertEqual(
            [entry.record_id for entry in hits], ["parameterize-do-not-enumerate"]
        )

    def test_resolve_answers_a_title_and_an_id_shaped_spelling(self):
        for query in ("Fail-Safe Defaults", "fail safe defaults"):
            with self.subTest(query=query):
                hits = resolve(query, self.records)
                self.assertEqual(
                    [entry.record_id for entry in hits], ["fail-safe-defaults"]
                )

    def test_resolve_falls_back_to_a_partial_name(self):
        hits = resolve("least privilege", self.records)
        self.assertEqual({entry.record_id for entry in hits}, {"least-privilege"})

    def test_resolve_prefers_an_exact_key_over_a_partial_one(self):
        # "Fail fast" is an alias of one record and a substring of another's
        # title; the exact key wins and the partial match is never consulted.
        hits = resolve("fail fast", self.records)
        self.assertEqual([entry.name for entry in hits], ["Fail fast"])

    def test_resolve_answers_nothing_for_an_unknown_or_empty_query(self):
        self.assertEqual(resolve("kubernetes upgrade", self.records), [])
        self.assertEqual(resolve("   ", self.records), [])


class TheGeneratedIndex(unittest.TestCase):
    """name-index.json is the carrier a consumer reads instead of the Markdown."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.records = load_catalog()
        cls.index = json.loads((ROOT / "name-index.json").read_text(encoding="utf-8"))
        cls.reference = (ROOT / "QUICK_REFERENCE.md").read_text(encoding="utf-8")

    def test_it_carries_every_name_the_catalog_holds(self):
        published = {
            (item["name"], item["id"], item["field"]) for item in self.index["names"]
        }
        expected = {
            (entry.name, entry.record_id, entry.field)
            for entry in name_entries(self.records)
        }
        self.assertEqual(published, expected)

    def test_it_carries_the_key_and_the_terms_a_consumer_would_compare(self):
        for item in self.index["names"]:
            with self.subTest(name=item["name"]):
                self.assertEqual(item["key"], normalize(item["name"]))
                self.assertEqual(item["tokens"], list(tokens(item["name"])))

    def test_it_describes_the_chain_that_produced_its_keys(self):
        # A consumer outside Python can only reproduce a key if the artifact
        # says how one is made; an unversioned chain silently invalidates every
        # key a reader cached.
        self.assertEqual(self.index["analyzer"], ANALYZER)

    def test_it_says_what_it_is_generated_from(self):
        self.assertEqual(self.index["generated_from"], "principles/*.toml")
        self.assertIn("generated", self.index["canonical"])

    def test_it_carries_names_and_not_the_records(self):
        # The narrow index is honest about what it is for. A second file
        # carrying prose would be the catalog in a second format, which is the
        # thing `single-authoritative-source` warns about.
        fields = {key for item in self.index["names"] for key in item}
        self.assertEqual(
            fields, {"name", "key", "tokens", "field", "id", "title", "path"}
        )

    def test_the_rendered_reference_reaches_every_alias(self):
        # Asserted through `cell()` rather than against a formatted row: the
        # fact under test is that the alias reaches the page beside its record,
        # not which column it landed in.
        for entry in alias_index(self.records):
            rendered = cell(entry.name)
            rows = [line for line in self.reference.splitlines() if rendered in line]
            with self.subTest(alias=entry.name):
                self.assertTrue(rows, f"{entry.name!r} is not in QUICK_REFERENCE.md")
                self.assertTrue(
                    any(entry.path in row for row in rows),
                    f"{entry.name!r} is not rendered beside {entry.path}",
                )


class NamesStayUnambiguous(unittest.TestCase):
    def test_two_records_may_not_claim_one_name(self):
        clash = [
            {"id": "a", "title": "One", "aliases": ["Shared name"]},
            {"id": "b", "title": "Two", "aliases": ["shared NAME"]},
        ]
        self.assertEqual(name_collisions(clash[:1]), [])
        found = name_collisions(clash)
        self.assertEqual(len(found), 1)
        self.assertIn("a, b", found[0])

    def test_names_the_index_cannot_tell_apart_are_a_collision(self):
        # Different strings, one key: a search for either one has two answers,
        # which is the condition this check exists to refuse.
        clash = [
            {"id": "a", "title": "Fail-Safe Defaults", "aliases": []},
            {"id": "b", "title": "fail safe defaults", "aliases": []},
        ]
        found = name_collisions(clash)
        self.assertEqual(len(found), 1)
        self.assertIn("a, b", found[0])

    def test_a_record_may_not_repeat_its_own_title_as_an_alias(self):
        found = name_collisions([{"id": "a", "title": "One", "aliases": ["one"]}])
        self.assertEqual(len(found), 1)
        self.assertIn("twice", found[0])

    def test_a_name_that_analyzes_to_nothing_is_refused(self):
        found = name_collisions([{"id": "a", "title": "One", "aliases": ["---"]}])
        self.assertEqual(len(found), 1)
        self.assertIn("never be searched for", found[0])


class RecordShape(unittest.TestCase):
    """A record is refused for the field it got wrong, and for nothing else.

    Each case is the real catalog with one record changed in one way, so the
    only problem `validate_records` can report is the one planted. Against a
    hand-built stub, a refusal could come from any of the fields the stub left
    out, and the test would pass for the wrong reason.
    """

    SUBJECT = "fail-fast"

    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load_catalog()

    def problems(self, mutate, subject: str | None = None) -> list[str]:
        records = copy.deepcopy(self.catalog)
        target = next(
            item for item in records if item["id"] == (subject or self.SUBJECT)
        )
        mutate(target)
        return validate_records(records)

    def assertRefused(self, found: list[str], *fragments: str) -> None:
        self.assertEqual(len(found), 1, found)
        for fragment in fragments:
            self.assertIn(fragment, found[0])

    def test_the_unchanged_catalog_has_no_problems(self):
        # The baseline every case below is measured against.
        self.assertEqual(self.problems(lambda record: None), [])

    def test_an_unknown_top_level_field_is_refused(self):
        # A misspelled `conflict_with` would otherwise read as a record with no
        # conflicts at all.
        found = self.problems(lambda record: record.update(conflict_with=["x"]))
        self.assertRefused(found, "conflict_with", "does not name")

    def test_an_unknown_enforcement_field_is_refused(self):
        found = self.problems(
            lambda record: record["enforcement"].update(rungs=["text"])
        )
        self.assertRefused(found, "[enforcement]", "rungs")

    def test_a_kind_outside_the_fifteen_is_refused(self):
        self.assertEqual(len(KINDS), 15)
        found = self.problems(lambda record: record.update(kind="guideline"))
        self.assertRefused(found, "kind must be one of")

    def test_socio_technical_law_is_not_a_kind(self):
        # "socio-technical" says where a law applies, which is `domains`.
        self.assertNotIn("socio-technical-law", KINDS)
        found = self.problems(lambda record: record.update(kind="socio-technical-law"))
        self.assertRefused(found, "kind must be one of")

    def test_every_kind_in_the_list_is_accepted(self):
        for kind in sorted(KINDS):
            with self.subTest(kind=kind):
                self.assertEqual(
                    self.problems(lambda record, kind=kind: record.update(kind=kind)),
                    [],
                )

    def test_an_unknown_domain_is_refused(self):
        # A tag outside the list is refused by name, rather than read as a
        # domain of its own that no review filter would think to name.
        found = self.problems(lambda record: record["domains"].append("operations"))
        self.assertRefused(found, "fail-fast", "'operations'", "not a domain")

    def test_an_empty_or_repeated_domains_list_is_refused(self):
        found = self.problems(lambda record: record.update(domains=[]))
        self.assertRefused(found, "domains", "at least one")
        found = self.problems(
            lambda record: record.update(domains=["reliability", "reliability"])
        )
        self.assertRefused(found, "domains repeats", "'reliability'")

    def test_every_domain_has_a_meaning(self):
        for domain, meaning in DOMAINS.items():
            with self.subTest(domain=domain):
                self.assertIsInstance(meaning, str)
                self.assertTrue(meaning.strip())
                self.assertNotIn("\n", meaning)

    def test_rung_outside_the_ladder_is_refused(self):
        for rung in (["bytes"], [], "text", ["text", 3]):
            with self.subTest(rung=rung):
                found = self.problems(
                    lambda record, rung=rung: record["enforcement"].update(rung=rung)
                )
                self.assertRefused(found, "enforcement.rung")

    def test_rung_out_of_ladder_order_or_repeated_is_refused(self):
        for rung, fragment in (
            (["syntax", "text"], "ladder order"),
            (["text", "text"], "repeats"),
        ):
            with self.subTest(rung=rung):
                found = self.problems(
                    lambda record, rung=rung: record["enforcement"].update(rung=rung)
                )
                self.assertRefused(found, fragment)

    def test_rung_on_a_record_no_machine_can_check_is_refused(self):
        def mutate(record):
            record["enforcement"].update(automatable="no", rung=["text"])

        self.assertRefused(self.problems(mutate), "automatable is 'no'")

    def test_a_tool_without_url_or_with_an_unknown_key_is_refused(self):
        well_formed = {"name": "Probe", "url": "https://example.org/", "notes": "n"}
        for tool, fragment in (
            ({"name": "Probe", "notes": "n"}, "tools[0].url"),
            ({**well_formed, "url": "ftp://example.org/"}, "HTTP(S)"),
            ({**well_formed, "version": "1"}, "version"),
        ):
            with self.subTest(tool=tool):
                found = self.problems(
                    lambda record, tool=tool: record.update(tools=[tool])
                )
                self.assertRefused(found, fragment)
        self.assertRefused(
            self.problems(lambda record: record.update(tools=[])), "non-empty"
        )

    def test_a_tool_named_like_a_record_is_refused(self):
        # Another record's title, spelled the way a search would fold it: the
        # index would answer a search for the concept with the product.
        tool = {
            "name": "information HIDING",
            "url": "https://example.org/",
            "notes": "n",
        }
        found = self.problems(lambda record: record.update(tools=[tool]))
        self.assertRefused(found, "information HIDING", "not the concept")

    def test_a_one_sided_conflict_is_refused(self):
        # unix-composability does not list fail-fast, so a reader of it is never
        # shown the trade-off; the error names both ends.
        found = self.problems(
            lambda record: record["conflicts_with"].append("unix-composability")
        )
        self.assertRefused(found, "'fail-fast'", "'unix-composability'", "two ends")

    def test_an_id_both_related_and_in_conflict_is_refused(self):
        # graceful-degradation already lists fail-fast as a conflict, so the
        # only fault planted is the second listing.
        found = self.problems(
            lambda record: record["related"].append("graceful-degradation")
        )
        self.assertRefused(found, "'fail-fast'", "'graceful-degradation'", "both")

    def test_a_one_sided_related_edge_is_allowed(self):
        # "Read this next" from fail-fast does not oblige unix-composability.
        found = self.problems(
            lambda record: record["related"].append("unix-composability")
        )
        self.assertEqual(found, [])

    def test_rung_and_tools_on_a_well_formed_record_are_accepted(self):
        def mutate(record):
            record["enforcement"]["rung"] = ["text", "semantic"]
            record["tools"] = [
                {"name": "Probe", "url": "https://example.org/", "notes": "n"}
            ]

        self.assertEqual(self.problems(mutate), [])


def schema_rows(heading: str) -> dict[str, str]:
    """The SCHEMA.md table whose header begins so, first cell to second.

    Read by the header's first cell rather than by position, so a table moved
    within the page is still found, and one renamed is a failure here rather
    than a silently empty set.
    """
    lines = (ROOT / "principles" / "SCHEMA.md").read_text(encoding="utf-8").splitlines()
    start = next(
        index for index, line in enumerate(lines) if line.startswith(f"| {heading} |")
    )
    rows = {}
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        cells = line.split("|")
        rows[cells[1].strip().strip("`")] = cells[2].strip()
    return rows


def schema_table(heading: str) -> set[str]:
    """The backticked first cells of the SCHEMA.md table whose header begins so."""
    return set(schema_rows(heading))


class TheSchemaDocumentAgrees(unittest.TestCase):
    """SCHEMA.md and validate.py hold the same vocabularies by hand.

    The validator is the authority, and the document is where a person reads
    what each value means. Two hand-written copies drift unless something
    compares them, which is what test_toolchain.py does for the MSRV and this
    does for the kinds, the rungs and the domains.
    """

    def test_schema_doc_lists_exactly_the_kinds(self):
        self.assertEqual(schema_table("kind"), KINDS)

    def test_schema_doc_lists_exactly_the_rungs(self):
        self.assertEqual(schema_table("rung"), set(RUNGS))

    def test_schema_doc_lists_exactly_the_domains(self):
        # The meaning too: a tag worded one way in the validator and another in
        # the document is two tags to whoever reads both.
        self.assertEqual(schema_rows("domain"), DOMAINS)


class TheReferenceGroups(unittest.TestCase):
    """QUICK_REFERENCE.md lists every record under its kind and each domain."""

    def test_quick_reference_groups_every_record_by_kind_and_domain(self):
        # Membership only: that a record's link reaches the line for each value
        # it carries, not how the line is laid out.
        page = render_reference()
        by_kind = page.split("## By kind", 1)[1].split("## By domain", 1)[0]
        by_domain = page.split("## By domain", 1)[1].split("\n## ", 1)[0]
        for record in load_catalog():
            path = f"principles/{record['id']}.toml"
            for section, values in (
                (by_kind, [record["kind"]]),
                (by_domain, record["domains"]),
            ):
                for value in values:
                    lines = [
                        line
                        for line in section.splitlines()
                        if f"**{cell(value)}**" in line
                    ]
                    with self.subTest(record=record["id"], value=value):
                        self.assertEqual(len(lines), 1, lines)
                        self.assertIn(path, lines[0])


if __name__ == "__main__":
    unittest.main()
