#!/usr/bin/env python3
"""Shared catalog loader and the name index built from it."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from analysis import matches, normalize, tokens

ROOT = Path(__file__).resolve().parents[1]
PRINCIPLES_DIR = ROOT / "principles"


def principle_paths() -> list[Path]:
    return sorted(
        path for path in PRINCIPLES_DIR.glob("*.toml") if not path.name.startswith("_")
    )


def load_catalog() -> list[dict]:
    records: list[dict] = []
    for path in principle_paths():
        with path.open("rb") as handle:
            record = tomllib.load(handle)
        record["_path"] = path
        records.append(record)
    return records


# ---------------------------------------------------------------------------
# The name index
# ---------------------------------------------------------------------------
#
# Records are titled for the constraint they assert, which is right for the
# catalog and useless for finding one: nobody searches for "Parameterize, Do Not
# Enumerate", they search for the failure in front of them -- "combinatorial
# explosion" -- which the record has held in `aliases` all along.
#
# That lookup is a mapping from a searched name to a record id, and it is built
# here as one. QUICK_REFERENCE.md renders it, name-index.json publishes it, and
# validate.py asks it for collisions; all three ask this function rather than
# each answering the question a fourth way. Nothing reads the rendering back --
# a Markdown row is a layout decision plus an escaping decision, and recovering
# a name from it means reimplementing both.
#
# Titles and aliases are one namespace here for the same reason validate.py
# treats them as one: a reader who types a name does not know, and should not
# have to know, which of the two fields they just typed.


@dataclass(frozen=True)
class NameEntry:
    """One searchable name, against the record that answers it."""

    name: str  # as the record wrote it; what a reader is shown
    key: str  # analyzed lookup key; what a search compares
    tokens: tuple[str, ...]  # the key's terms, for partial-name matching
    field: str  # "title" or "alias" -- which field carried the name
    record_id: str  # the stable id SCHEMA.md names as the API
    title: str  # the record's canonical title, for display

    @property
    def path(self) -> str:
        return f"principles/{self.record_id}.toml"


def name_entries(records: list[dict] | None = None) -> list[NameEntry]:
    """Every searchable name in the catalog, sorted by lookup key.

    Sorted by the key rather than by the written name, because the key is what a
    reader arrives with once the spelling differences are folded out; ties break
    on the record id so the order is total and a regenerated artifact is a diff
    only when the catalog changed.
    """
    if records is None:
        records = load_catalog()

    entries: list[NameEntry] = []
    for record in records:
        record_id = record.get("id")
        title = record.get("title")
        if not isinstance(record_id, str) or not isinstance(title, str):
            continue
        aliases = record.get("aliases")
        names = [("title", title)]
        if isinstance(aliases, list):
            names += [("alias", item) for item in aliases if isinstance(item, str)]
        for field, name in names:
            entries.append(
                NameEntry(
                    name=name,
                    key=normalize(name),
                    tokens=tokens(name),
                    field=field,
                    record_id=record_id,
                    title=title,
                )
            )

    return sorted(entries, key=lambda entry: (entry.key, entry.record_id, entry.field))


def alias_index(records: list[dict] | None = None) -> list[NameEntry]:
    """The alias half of the index: the names people arrive with."""
    return [entry for entry in name_entries(records) if entry.field == "alias"]


def resolve(query: str, records: list[dict] | None = None) -> list[NameEntry]:
    """Names matching `query`, exact key first, partial only if nothing is exact.

    Two stages, in the order a search engine runs them: a `term` lookup on the
    analyzed key, and -- only when that finds nothing -- a `match` over the
    terms, so a reader who typed part of a name still lands somewhere. A partial
    query is allowed to be ambiguous; returning every hit lets the caller say so
    instead of picking one and calling it the answer.
    """
    entries = name_entries(records)
    key = normalize(query)
    if not key:
        return []
    exact = [entry for entry in entries if entry.key == key]
    if exact:
        return exact
    return [entry for entry in entries if matches(query, entry.tokens)]
