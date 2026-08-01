#!/usr/bin/env python3
"""Validate principle records and their relationships."""

from __future__ import annotations

import re
import sys
from collections import Counter

from catalog import load_catalog, name_entries

ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
KINDS = {
    "law",
    "principle",
    "heuristic",
    "philosophy",
    "tactic",
    "pattern",
    "socio-technical-law",
    "anti-pattern",
}
STATUSES = {"seed", "reviewed", "deprecated"}
LEVELS = {"informational", "review", "lint", "test", "runtime", "governance"}
AUTOMATABLE = {"no", "partially", "yes"}

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


def main() -> int:
    records = load_catalog()
    errors: list[str] = []

    ids = [record.get("id") for record in records]
    known_ids = {value for value in ids if isinstance(value, str)}
    duplicates = {value for value, count in Counter(ids).items() if count > 1}
    for duplicate in sorted(duplicates, key=str):
        errors.append(f"duplicate id: {duplicate!r}")

    errors.extend(name_collisions(records))

    for record in records:
        path = str(record["_path"].relative_to(record["_path"].parents[1]))

        for field in sorted(REQUIRED_STRINGS):
            value = record.get(field)
            if not isinstance(value, str) or not value.strip():
                error(errors, path, f"{field} must be a non-empty string")

        for field in sorted(REQUIRED_LISTS):
            value = record.get(field)
            if not isinstance(value, list) or not all(
                isinstance(item, str) for item in value
            ):
                error(errors, path, f"{field} must be an array of strings")

        record_id = record.get("id")
        if isinstance(record_id, str):
            if not ID_RE.fullmatch(record_id):
                error(errors, path, "id must be kebab-case")
            if record["_path"].stem != record_id:
                error(errors, path, "filename must match id")

        if record.get("kind") not in KINDS:
            error(errors, path, f"kind must be one of {sorted(KINDS)}")
        if record.get("status") not in STATUSES:
            error(errors, path, f"status must be one of {sorted(STATUSES)}")

        enforcement = record.get("enforcement")
        if not isinstance(enforcement, dict):
            error(errors, path, "missing [enforcement] table")
        else:
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
                value = enforcement.get(field)
                if not isinstance(value, list) or not all(
                    isinstance(item, str) for item in value
                ):
                    error(
                        errors, path, f"enforcement.{field} must be an array of strings"
                    )

        sources = record.get("sources")
        if not isinstance(sources, list) or not sources:
            error(errors, path, "at least one [[sources]] entry is required")
        else:
            for index, source in enumerate(sources):
                if not isinstance(source, dict):
                    error(errors, path, f"sources[{index}] must be a table")
                    continue
                for field in ("title", "url", "type", "notes"):
                    value = source.get(field)
                    if not isinstance(value, str) or not value.strip():
                        error(errors, path, f"sources[{index}].{field} is required")
                url = source.get("url")
                if isinstance(url, str) and not url.startswith(("https://", "http://")):
                    error(errors, path, f"sources[{index}].url must be HTTP(S)")

        for relation in ("related", "conflicts_with"):
            values = record.get(relation, [])
            if not isinstance(values, list):
                continue
            for target in values:
                if target not in known_ids:
                    error(errors, path, f"{relation} references unknown id {target!r}")
                if target == record_id:
                    error(errors, path, f"{relation} must not reference itself")

    if errors:
        print("catalog validation failed:", file=sys.stderr)
        for item in errors:
            print(f"- {item}", file=sys.stderr)
        return 1

    print(f"validated {len(records)} principle records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
