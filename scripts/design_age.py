#!/usr/bin/env python3
"""Report open Design records that have stayed pending past the ruling window."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

RULINGS = {"ruling:pending", "ruling:accepted", "ruling:rejected", "ruling:deferred"}
DESIGN_LABEL = "design"
RULING_WINDOW_DAYS = 30
PAGE_SIZE = 100


def _label_names(issue: dict) -> list[str]:
    labels = issue["labels"]
    if not isinstance(labels, list):
        raise ValueError("GitHub issue labels must be a list")
    names = []
    for label in labels:
        if isinstance(label, str):
            names.append(label)
        elif isinstance(label, dict) and isinstance(label.get("name"), str):
            names.append(label["name"])
        else:
            raise ValueError("GitHub issue contains a malformed label")
    return names


def _created_at(issue: dict) -> datetime:
    created = issue["created_at"]
    if not isinstance(created, str):
        raise ValueError("GitHub issue created_at must be a timestamp")
    parsed = datetime.fromisoformat(created.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("GitHub issue created_at must include a timezone")
    return parsed


def audit(
    issues: list[dict], now: datetime, window_days: int = RULING_WINDOW_DAYS
) -> tuple[list[tuple[dict, int]], list[str]]:
    """Return overdue pending records and malformed design-record labels."""
    overdue: list[tuple[dict, int]] = []
    errors: list[str] = []

    for issue in issues:
        if not isinstance(issue, dict):
            raise ValueError("GitHub issues API returned a malformed issue")
        labels = _label_names(issue)
        if DESIGN_LABEL not in labels or issue.get("state", "open") != "open":
            continue
        # The issues endpoint also returns pull requests. They are not design
        # records even if somebody copies the label onto one.
        if "pull_request" in issue:
            continue
        rulings = [label for label in labels if label.startswith("ruling:")]
        number = issue.get("number", "?")
        title = issue.get("title", "(untitled)")
        if len(rulings) != 1 or rulings[0] not in RULINGS:
            errors.append(
                f"#{number} {title}: expected exactly one of "
                f"{', '.join(sorted(RULINGS))}; found "
                f"{', '.join(rulings) if rulings else 'no ruling label'}."
            )
            continue
        if rulings[0] != "ruling:pending":
            continue
        age = now - _created_at(issue)
        age_days = age.days
        if age >= timedelta(days=window_days):
            overdue.append((issue, age_days))

    overdue.sort(key=lambda item: (item[0].get("number", 0), item[0].get("title", "")))
    return overdue, errors


def fetch_open_design_issues(repository: str, token: str) -> list[dict]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or any(
        part in {".", ".."} for part in repository.split("/")
    ):
        raise ValueError("GITHUB_REPOSITORY must have the form owner/repository")
    issues: list[dict] = []
    page = 1
    while True:
        query = urlencode(
            {
                "state": "open",
                "labels": DESIGN_LABEL,
                "per_page": PAGE_SIZE,
                "page": page,
            }
        )
        request = Request(
            f"https://api.github.com/repos/{repository}/issues?{query}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "uphold-design-age-check",
            },
        )
        with urlopen(request, timeout=20) as response:
            batch = json.load(response)
        if not isinstance(batch, list):
            raise ValueError("GitHub issues API returned a non-list response")
        for issue in batch:
            if not isinstance(issue, dict) or DESIGN_LABEL not in _label_names(issue):
                raise ValueError(
                    "GitHub issues API returned an item without the design label"
                )
        issues.extend(batch)
        if len(batch) < PAGE_SIZE:
            return issues
        page += 1


def main() -> int:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("set GH_TOKEN or GITHUB_TOKEN to read Design records", file=sys.stderr)
        return 2
    try:
        issues = fetch_open_design_issues(repository, token)
        overdue, errors = audit(issues, datetime.now(UTC))
    except (
        HTTPError,
        URLError,
        TimeoutError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        json.JSONDecodeError,
    ) as error:
        print(f"could not audit Design records: {error}", file=sys.stderr)
        return 2

    if not overdue and not errors:
        print(f"Design records are ruled within {RULING_WINDOW_DAYS} days.")
        return 0
    for message in errors:
        print(message, file=sys.stderr)
    for issue, age_days in overdue:
        print(
            f"#{issue['number']} {issue['title']}: ruling:pending for "
            f"{age_days} days (limit {RULING_WINDOW_DAYS}); rule it or label it "
            "ruling:deferred.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
