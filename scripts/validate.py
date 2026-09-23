#!/usr/bin/env python3
"""Validate principle records and their relationships."""

from __future__ import annotations

import re
import sys
from collections import Counter

from analysis import normalize
from catalog import load_catalog, name_entries

ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
# What an entry IS, from a closed list. Where it is used is `domains`, and how a
# check sees it is `enforcement.rung`: three questions and three fields, so none
# of them is made to answer another (ADR 0011). principles/SCHEMA.md carries
# the meaning of each; a test holds the two lists equal.
KINDS = {
    "law",
    "theorem",
    "principle",
    "heuristic",
    "philosophy",
    "pattern",
    "anti-pattern",
    "tactic",
    "practice",
    "method",
    "model",
    "property",
    "representation",
    "metric",
    "decision-procedure",
}
STATUSES = {"seed", "reviewed", "deprecated"}
LEVELS = {"informational", "review", "lint", "test", "runtime", "governance"}
AUTOMATABLE = {"no", "partially", "yes"}
# The observation ladder docs/COVERAGE.md defines under "Rungs", in its order.
# No code in the engine reads a record's rung, so this tuple is the one place
# the vocabulary is held, and its order is the order a record writes it in.
RUNGS = ("text", "syntax", "semantic", "proof")

REQUIRED_STRINGS = {
    "id",
    "title",
    "kind",
    "status",
    "summary",
    "claim",
    "problem",
    "rationale",
}
REQUIRED_LISTS = {
    "aliases",
    "domains",
    "applies_when",
    "does_not_mean",
    "benefits",
    "costs",
    "failure_when_overapplied",
    "conflicts_with",
    "related",
    "review_questions",
}
# Every field a record may carry. A field outside these is refused rather than
# ignored: a misspelled `conflict_with` would otherwise pass as a record with no
# conflicts, and a field nothing reads is a claim nothing keeps true.
TOP_LEVEL_FIELDS = (
    REQUIRED_STRINGS | REQUIRED_LISTS | {"enforcement", "sources", "tools"}
)
ENFORCEMENT_FIELDS = {"level", "automatable", "observable", "checks", "limits", "rung"}
SOURCE_FIELDS = ("title", "url", "type", "notes")
TOOL_FIELDS = ("name", "url", "notes")
# Put on each record by `catalog.load_catalog`; no file writes it.
LOADER_FIELDS = {"_path"}


def error(errors: list[str], path: str, message: str) -> None:
    errors.append(f"{path}: {message}")


def name_collisions(records: list[dict]) -> list[str]:
    """Titles and aliases share one namespace, and it has to be unambiguous.

    Aliases are a lookup surface: the name index resolves each of them to a
    record, so a name held by two records answers a search with an ambiguity
    rather than a record. Titles are in the same namespace because a reader who
    types a name cannot know which of the two fields they are typing.

    The comparison is the index's own lookup key, not `casefold()`, because the
    index is what has to stay unambiguous: two names that a search cannot tell
    apart -- "Fail-Safe Defaults" against "fail safe defaults" -- are a
    collision whether or not the raw strings differ. Asking `catalog` for the
    keys is also what keeps the two from drifting; a validator with its own
    notion of sameness passes catalogs the index cannot serve.
    """
    holders: dict[str, list[str]] = {}
    unsearchable: list[str] = []
    for entry in name_entries(records):
        if not entry.key:
            unsearchable.append(
                f"record {entry.record_id!r} carries the name {entry.name!r}, "
                "which analyzes to nothing and so can never be searched for"
            )
            continue
        holders.setdefault(entry.key, []).append(entry.record_id)

    collisions = []
    for name, claimants in sorted(holders.items()):
        if len(claimants) == 1:
            continue
        owners = sorted(set(claimants))
        if len(owners) > 1:
            collisions.append(
                f"name {name!r} is claimed by more than one record: {', '.join(owners)}"
            )
        else:
            collisions.append(f"record {owners[0]!r} claims the name {name!r} twice")
    return collisions + unsearchable


def record_path(record: dict) -> str:
    path = record.get("_path")
    if path is not None:
        return str(path.relative_to(path.parents[1]))
    return f"principles/{record.get('id')}.toml"


def unknown_fields(
    errors: list[str], path: str, where: str, table: dict, allowed
) -> None:
    for field in sorted(set(table) - set(allowed)):
        error(errors, path, f"{where} has a field the schema does not name: {field!r}")


def is_string_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def check_rung(errors: list[str], path: str, enforcement: dict) -> None:
    """`rung` is optional, and when present it is a ladder position, not prose.

    A record no machine can decide has no rung to be seen at: `automatable =
    "no"` and a rung together say two contradicting things about one record.
    """
    if "rung" not in enforcement:
        return
    rung = enforcement["rung"]
    if not is_string_list(rung) or not rung:
        error(errors, path, "enforcement.rung must be a non-empty array of strings")
        return
    outside = [item for item in rung if item not in RUNGS]
    if outside:
        error(
            errors,
            path,
            f"enforcement.rung names {outside} outside the ladder {list(RUNGS)}",
        )
        return
    if len(set(rung)) != len(rung):
        error(errors, path, f"enforcement.rung repeats a rung: {rung}")
    elif rung != sorted(rung, key=RUNGS.index):
        error(
            errors,
            path,
            f"enforcement.rung must be in ladder order {list(RUNGS)}, not {rung}",
        )
    if enforcement.get("automatable") == "no":
        error(
            errors,
            path,
            "enforcement.rung is set on a record whose automatable is 'no'; "
            "a record no machine can decide has no rung to be seen at",
        )


def check_tools(errors: list[str], path: str, tools: object, names: set[str]) -> None:
    """`[[tools]]` is optional; each is an example, and never the concept.

    A tool named like a record would make the index answer a search for the
    concept with the product, which is the confusion the field exists to keep
    out: the record is what is upheld, the tool is one way to observe it.
    """
    if not isinstance(tools, list) or not tools:
        error(errors, path, "tools, when present, must be a non-empty array of tables")
        return
    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            error(errors, path, f"tools[{index}] must be a table")
            continue
        unknown_fields(errors, path, f"tools[{index}]", tool, TOOL_FIELDS)
        for field in TOOL_FIELDS:
            value = tool.get(field)
            if not isinstance(value, str) or not value.strip():
                error(
                    errors, path, f"tools[{index}].{field} must be a non-empty string"
                )
        url = tool.get("url")
        if (
            isinstance(url, str)
            and url.strip()
            and not url.startswith(("https://", "http://"))
        ):
            error(errors, path, f"tools[{index}].url must be HTTP(S)")
        name = tool.get("name")
        if isinstance(name, str) and normalize(name) in names:
            error(
                errors,
                path,
                f"tools[{index}].name {name!r} is the name of a record; "
                "a tool is an example of a concept, not the concept",
            )


def check_relations(records: list[dict], known_ids: set[str]) -> list[str]:
    """`conflicts_with` is symmetric; `related` is directional; never both.

    A tension between two records is one fact with two ends, so a reader of
    either record has to be shown it: a conflict listed on one side only is a
    trade-off the other record's reader is never warned of. `related` is a
    pointer to further reading and stays one-directional, since "see also" from
    A does not oblige B. An id in both lists of one record says the pair is in
    tension and merely adjacent at once, and a reader cannot act on both.
    """
    errors: list[str] = []
    conflicts: dict[str, set[str]] = {}
    for record in records:
        record_id = record.get("id")
        values = record.get("conflicts_with")
        if isinstance(record_id, str) and is_string_list(values):
            conflicts[record_id] = set(values)

    for record in records:
        record_id = record.get("id")
        path = record_path(record)
        for relation in ("related", "conflicts_with"):
            values = record.get(relation, [])
            if not isinstance(values, list):
                continue
            for target in values:
                if target not in known_ids:
                    error(errors, path, f"{relation} references unknown id {target!r}")
                if target == record_id:
                    error(errors, path, f"{relation} must not reference itself")

        if not isinstance(record_id, str):
            continue
        for target in sorted(conflicts.get(record_id, set())):
            if target in conflicts and record_id not in conflicts[target]:
                error(
                    errors,
                    path,
                    f"{record_id!r} lists {target!r} in conflicts_with but "
                    f"{target!r} does not list {record_id!r}; a conflict has two ends",
                )
        related = record.get("related")
        if is_string_list(related):
            for target in sorted(set(related) & conflicts.get(record_id, set())):
                error(
                    errors,
                    path,
                    f"{record_id!r} lists {target!r} in both related and "
                    "conflicts_with; keep it in conflicts_with",
                )
    return errors


def validate_records(records: list[dict]) -> list[str]:
    """Every problem with `records`, as one line each; empty when they are valid."""
    errors: list[str] = []

    ids = [record.get("id") for record in records]
    known_ids = {value for value in ids if isinstance(value, str)}
    duplicates = {value for value, count in Counter(ids).items() if count > 1}
    for duplicate in sorted(duplicates, key=str):
        errors.append(f"duplicate id: {duplicate!r}")

    errors.extend(name_collisions(records))
    record_names = {entry.key for entry in name_entries(records) if entry.key}

    for record in records:
        path = record_path(record)

        unknown_fields(errors, path, "record", record, TOP_LEVEL_FIELDS | LOADER_FIELDS)

        for field in sorted(REQUIRED_STRINGS):
            value = record.get(field)
            if not isinstance(value, str) or not value.strip():
                error(errors, path, f"{field} must be a non-empty string")

        for field in sorted(REQUIRED_LISTS):
            if not is_string_list(record.get(field)):
                error(errors, path, f"{field} must be an array of strings")

        record_id = record.get("id")
        if isinstance(record_id, str):
            if not ID_RE.fullmatch(record_id):
                error(errors, path, "id must be kebab-case")
            if "_path" in record and record["_path"].stem != record_id:
                error(errors, path, "filename must match id")

        if record.get("kind") not in KINDS:
            error(errors, path, f"kind must be one of {sorted(KINDS)}")
        if record.get("status") not in STATUSES:
            error(errors, path, f"status must be one of {sorted(STATUSES)}")

        enforcement = record.get("enforcement")
        if not isinstance(enforcement, dict):
            error(errors, path, "missing [enforcement] table")
        else:
            unknown_fields(
                errors, path, "[enforcement]", enforcement, ENFORCEMENT_FIELDS
            )
            if enforcement.get("level") not in LEVELS:
                error(
                    errors, path, f"enforcement.level must be one of {sorted(LEVELS)}"
                )
            if enforcement.get("automatable") not in AUTOMATABLE:
                error(
                    errors,
                    path,
                    f"enforcement.automatable must be one of {sorted(AUTOMATABLE)}",
                )
            for field in ("observable", "checks", "limits"):
                if not is_string_list(enforcement.get(field)):
                    error(
                        errors, path, f"enforcement.{field} must be an array of strings"
                    )
            check_rung(errors, path, enforcement)

        sources = record.get("sources")
        if not isinstance(sources, list) or not sources:
            error(errors, path, "at least one [[sources]] entry is required")
        else:
            for index, source in enumerate(sources):
                if not isinstance(source, dict):
                    error(errors, path, f"sources[{index}] must be a table")
                    continue
                unknown_fields(errors, path, f"sources[{index}]", source, SOURCE_FIELDS)
                for field in SOURCE_FIELDS:
                    value = source.get(field)
                    if not isinstance(value, str) or not value.strip():
                        error(errors, path, f"sources[{index}].{field} is required")
                url = source.get("url")
                if isinstance(url, str) and not url.startswith(("https://", "http://")):
                    error(errors, path, f"sources[{index}].url must be HTTP(S)")

        if "tools" in record:
            check_tools(errors, path, record["tools"], record_names)

    errors.extend(check_relations(records, known_ids))
    return errors


def main() -> int:
    records = load_catalog()
    errors = validate_records(records)

    if errors:
        print("catalog validation failed:", file=sys.stderr)
        for item in errors:
            print(f"- {item}", file=sys.stderr)
        return 1

    print(f"validated {len(records)} principle records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
