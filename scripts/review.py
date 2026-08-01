"""Route records to a static rule or to a reviewer, and compile the remainder.

`enforcement.automatable` was a claimability gate and nothing else: `"no"`
refused a claim, and `yes` and `partially` were indistinguishable to the
reconcile. It routes now.

    value         static                              review tier
    ------------  ----------------------------------  ---------------------
    "yes"         MUST carry a claim; unclaimed is     excluded -- a rule
                  an error rather than a statistic     already enforces it
    "partially"   may carry claims                     the remainder compiles in
    "no"          must carry NO claim                  compiles in

Zero new schema. The compiled entry is `claim`, `applies_when` and
`review_questions`, three fields that were already written as a prompt -- the
constraint, when it binds, and what to ask -- and nothing here was designed for
this.

WHY THIS IS NOT THE THING `enforcement-needs-a-trigger` REFUSES. That record
argues a tool holding prose has no condition on which to emit it, so it emits it
always and is skipped, or never and enforces nothing. A reviewer reading a
change HAS a condition: the change. The failure arrives instead through LENGTH,
because guidance long enough to be skimmed is guidance emitted always -- so the
ceiling below is not a nicety, it is the other half of the carve-out. The record
was amended to say exactly this, and it refuses the tier without the ceiling.

The ceiling is deterministic and fails the build. A ranking heuristic that
quietly drops the tail is the same always-emitted failure with a scoreboard on
it: the reader cannot tell a short document from a truncated one.
"""

from __future__ import annotations

#: Against an observed degradation range of roughly 800 to 1,000 lines, below
#: the bottom of it. A limit set at the top of a range is a limit that reaches
#: the failure it was measured against.
DEFAULT_MAX_LINES = 900

#: The standing asymmetry, and it points one way on purpose: a static rule has
#: no length ceiling and a prompt rule does, so every mechanizable rule is
#: cheaper to push down into a static tier than to leave here.
PREAMBLE = """\
# Review

Read this when reviewing a change to this repository. It carries the part of
each principle that no rule here can decide -- the judgment -- and nothing that
a rule already refuses.

Do NOT re-enforce the static rules. They run on every change and they run
first; repeating their findings costs a reviewer's attention and buys a second
opinion nobody asked for. The rules already active here are:

{active}

Everything below is a constraint whose remainder is a judgment. For each, the
claim is what it asserts, the scope says when it binds, and the questions are
what to ask of a change.
"""


def _sorted_records(records: dict[str, dict], include_domains: list[str]) -> list[dict]:
    chosen = []
    for record in records.values():
        if record.get("status") == "deprecated":
            continue
        if include_domains and not set(record.get("domains", [])) & set(
            include_domains
        ):
            continue
        chosen.append(record)
    return sorted(chosen, key=lambda record: record["id"])


def route(
    records: dict[str, dict],
    claimed: set[str],
    exempt: dict[str, str],
    include_domains: list[str] | None = None,
) -> tuple[list[dict], list[str], list[str]]:
    """Return (records for review, errors, stale exemptions).

    `exempt` maps a record id to the reason this repository has no subject for
    it. It exists because `automatable = "yes"` is a property of the PRINCIPLE
    and not of this repository: `backpressure` says a machine can check bounded
    queues, and a catalog with no queue in it cannot carry that rule however
    true the field is. Recording that as an exemption with a reason keeps the
    error meaningful for every record that does have a subject here.

    Amending the record instead would be worse and was the first thing tried: it
    would make the catalog describe this repository rather than the principle,
    and the next consumer would read `partially` and believe it.
    """
    include_domains = include_domains or []
    for_review: list[dict] = []
    errors: list[str] = []

    for record in _sorted_records(records, include_domains):
        automatable = record.get("enforcement", {}).get("automatable")
        record_id = record["id"]
        if automatable == "yes":
            if record_id in claimed:
                continue  # a rule enforces it; a reviewer repeating it is noise
            if record_id in exempt:
                continue
            errors.append(
                f'{record_id}: enforcement.automatable = "yes" and no rule here '
                f"claims it. Build the rule, or record why this repository has no "
                f"subject for it under [review].no_subject_here."
            )
            continue
        if automatable == "no" and record_id in claimed:
            errors.append(
                f'{record_id}: enforcement.automatable = "no", so no rule can be '
                f"claimed to enforce it, and one is."
            )
            continue
        for_review.append(record)

    # An exemption that no longer describes the tree is the check switched off
    # for that record, and it will stay off. Same failure as a stale baseline,
    # reported the same way.
    known = set(records)
    stale = [
        f"{record_id}: {'now claimed by a rule' if record_id in claimed else 'names no record'}"
        for record_id in sorted(exempt)
        if record_id in claimed or record_id not in known
    ]
    return for_review, errors, stale


def render(for_review: list[dict], active_rules: list[str]) -> str:
    active = (
        "\n".join(f"- `{rule}`" for rule in sorted(active_rules))
        if active_rules
        else "- (none)"
    )
    parts = [PREAMBLE.format(active=active)]
    for record in for_review:
        parts.append(f"\n## {record['title']}\n")
        parts.append(f"{record['claim']}\n")
        applies = record.get("applies_when", [])
        if applies:
            parts.append("\n**Applies when**\n")
            for entry in applies:
                parts.append(f"- {entry}\n")
        questions = record.get("review_questions", [])
        if questions:
            parts.append("\n**Ask**\n")
            for entry in questions:
                parts.append(f"- {entry}\n")
    return "".join(parts)


def over_budget(document: str, max_lines: int) -> str | None:
    lines = len(document.splitlines())
    if lines <= max_lines:
        return None
    return (
        f"the compiled review is {lines} lines against a ceiling of {max_lines}. "
        f"Shorten records or narrow [review].include_domains. Do not raise the "
        f"ceiling: it is the half of `enforcement-needs-a-trigger`'s carve-out "
        f"that keeps this tier from becoming prose emitted always."
    )
