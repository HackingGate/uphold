from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT / "scripts"))

from analysis import ANALYZER, matches, normalize, tokens  # noqa: E402
from build_reference import cell  # noqa: E402
from catalog import alias_index, load_catalog, name_entries, resolve  # noqa: E402
from validate import name_collisions  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
