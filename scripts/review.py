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

WHAT THE COMPILED DOCUMENT STILL CANNOT SAY is whether any entry in it can
produce a finding at all. A record nobody has ever been asked about and a
record that says nothing a reviewer could act on are the same silence, in every
report anybody reads, for as long as nobody plants what the record is supposed
to catch. `uphold probe` exists because a git hook has that defect. A control is
the same fixture one tier up, and `audit_controls` below is what reads it.
`drive` is what plants it: it hands a reviewer the compiled document and each
control's change, and scores what comes back against the answer key.
"""

from __future__ import annotations

import json
import random
import re
import shlex
import subprocess
from collections.abc import Callable
from pathlib import Path

#: Below the bottom of the range in which review quality was observed to
#: degrade. A limit set at the top of a range is a limit that reaches the
#: failure it was measured against.
DEFAULT_MAX_LINES = 900

#: A reviewer that catches a plant one time in three is not a control, and one
#: run cannot tell it from a reviewer that catches it every time.
DEFAULT_RUNS = 3

#: Seconds one reviewer invocation may take. A model call answers in seconds;
#: a reviewer that has not answered in five minutes has stalled, and waiting on
#: it holds every control after it. A person at a prompt passes a longer one.
DEFAULT_TIMEOUT = 300

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
    unclaimed: list[dict] | None = None,
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

    `unclaimed`, when given, receives the `automatable = "yes"` records nothing
    claims and nothing exempts, and they are then not errors. Only a document
    printed for a reader (`--review --print`) passes it: a committed document
    must not carry a record a machine could check, and a document handed to a
    reviewer in a repository that has just adopted uphold has no rules yet to
    claim anything. Every other caller leaves it None and gets the refusal.
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
            if unclaimed is not None:
                unclaimed.append(record)
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


def render_could_enforce(unclaimed: list[dict]) -> str:
    """The records `--print` kept out of the document, for a caller to read apart.

    It is not part of the reviewer's instructions: a reviewer asked to judge a
    record a rule should own is the noise the preamble forbids. Each line is the
    id and the one alternative to building the rule.
    """
    lines = [
        f"{len(unclaimed)} record(s) uphold could enforce here, and no rule here "
        f"claims them yet; they are not in the document above:"
    ]
    for record in unclaimed:
        lines.append(
            f"- {record['id']}: build the rule, or record why this repository "
            f"has no subject for it under [review].no_subject_here."
        )
    return "\n".join(lines) + "\n"


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


def audit_controls(
    declared: list[dict],
    for_review: list[dict],
    records: dict[str, dict],
) -> tuple[list[str], list[str]]:
    """Return (errors, the review-carried record ids that carry no control).

    A control is a synthetic change a record MUST be named for, written beside
    the declaration by whoever is willing to say what violating that record
    looks like. It answers a question citation counting cannot: a record with
    no findings against it is either guarding a clean tree or saying nothing a
    reviewer could act on, and only a planted change separates the two. That is
    `uphold probe`'s argument for hooks, and the review tier has the same
    defect -- see `src/probe.rs`, which this borrows its shape and its refusals
    from.

    It does not measure applicability. A control is a change the record's
    `applies_when` describes by construction, so what it establishes is
    capability: a control that is caught removes "dead" from the reasons a
    record is silent, and leaves "nothing violated it", which is the weaker
    claim the citation count can then honestly support.

    A control over an `automatable = "yes"` record is refused rather than
    counted, because such a record is NOT in the document a reviewer is handed:
    `route` above drops it at "a rule enforces it; a reviewer repeating it is
    noise". Failing that control would report a reviewer for missing something
    nobody showed them, and passing it would reward a reviewer for repeating a
    static rule -- either way it measures the harness rather than the record.
    A control over a record that is excluded for any other reason -- deprecated,
    or outside `include_domains` here -- is refused for the narrower half of
    that reason alone: the harness cannot run it against a document the record
    is not in.

    The second half of the return value is the denominator, and it is the point
    of this function as much as the errors are. A record with no control is the
    record the whole mechanism is about.
    """
    carried = {record["id"] for record in for_review}
    errors: list[str] = []
    controlled: set[str] = set()

    for control in declared:
        record_id = control["record"]
        record = records.get(record_id)
        if record is None:
            errors.append(
                f"{record_id}: a control names it and the catalog does not define "
                f"it, so nothing here can be shown to fire."
            )
            continue
        if record.get("enforcement", {}).get("automatable") == "yes":
            errors.append(
                f"{record_id}: a control names it and enforcement.automatable = "
                f'"yes", so it is excluded from the compiled document because a '
                f"static rule already refuses it. A reviewer is never shown it."
            )
            continue
        if record_id not in carried:
            errors.append(
                f"{record_id}: a control names it and it does not compile into "
                f"the review document here, so there is no entry to drive the "
                f"control against."
            )
            continue
        controlled.add(record_id)

    uncontrolled = sorted(
        record["id"] for record in for_review if record["id"] not in controlled
    )
    return errors, uncontrolled


def render_controls(declared: list[dict], uncontrolled: list[str]) -> str:
    """The controls as JSON, for a harness this repository does not contain.

    `drive` below runs a reviewer against the controls in this process; the
    export is for a harness that would rather read a file, such as one that
    batches runs or records them somewhere this repository does not. JSON rather than the TOML it was written
    in because the reader is a program: TOML is the form a person writes a
    fixture in, and `name-index.json` and `policy/base/sets.lock.json` are
    already the form a program reads one out of.

    Three fields cross over and nothing else. A harness handed the record's
    claim and questions would be carrying a second copy of what the compiled
    document already says, going stale on its own schedule -- which is the
    failure `single-authoritative-source` names. It reads the document for what
    the record says and this for what to plant.

    `uncontrolled` rides along because the denominator is part of the answer:
    an export listing two controls says one thing beside four review-carried
    records and another beside nineteen, and a harness reporting a score
    without it would be reporting coverage it never measured.
    """
    payload = {
        "controls": [
            {
                "record": control["record"],
                "catches": control["catches"],
                # Explicitly null rather than absent where only one direction
                # was written down: a harness that saw no key would have to
                # guess whether the miss was untested or untestable.
                "misses": control.get("misses"),
            }
            for control in sorted(declared, key=lambda control: control["record"])
        ],
        "uncontrolled": uncontrolled,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def uncontrolled_note(uncontrolled: list[str]) -> str | None:
    """The denominator line, in the words `uphold probe` prints its own in.

    Printed on every run rather than under a flag, and printed whatever else
    the run found. "One record carries a control" means one thing beside two
    review-carried records and another beside nineteen, and the reader who most
    needs the difference is the one skimming a green run.
    """
    if not uncontrolled:
        return None
    return (
        f"{len(uncontrolled)} review-carried record(s) have no control, so nothing "
        f"here shows they can produce a finding: {', '.join(uncontrolled)}"
    )


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


class ReviewerFailed(Exception):
    """The reviewer command did not answer in the protocol `ask` reads.

    Not a missed plant: a reviewer that exits non-zero or names something that
    is not in the document has said nothing about the record, and scoring it as
    a miss would report a live record as dead.
    """


def ask(
    reviewer: list[str],
    document: str,
    change: str,
    carried: dict[str, str],
    timeout: int = DEFAULT_TIMEOUT,
) -> set[str]:
    """Run the reviewer once and return the record ids it names.

    The reviewer reads one JSON object on stdin, `{"document": ..., "change":
    ...}`, and prints one line per record the change violates: the record's
    id, or its title as the document's heading spells it. Blank lines are
    skipped, and printing nothing says the change violates nothing. It is never told
    which record the change was planted for -- that is the answer key.

    The reviewer is a command named by the caller, so no model client, key or
    budget lives here, and any reviewer -- a model behind a wrapper script, a
    person at a prompt, a fixture in a test -- answers the same way.
    """
    by_title = {title.casefold(): record_id for record_id, title in carried.items()}
    payload = json.dumps({"document": document, "change": change}, ensure_ascii=False)
    try:
        completed = subprocess.run(
            reviewer,
            input=payload,
            capture_output=True,
            encoding="utf-8",
            timeout=timeout,
            check=False,
        )
    except OSError as error:
        raise ReviewerFailed(f"could not run {reviewer[0]!r}: {error}") from error
    except subprocess.TimeoutExpired as error:
        raise ReviewerFailed(
            f"{reviewer[0]!r} did not answer within {timeout}s; pass --timeout "
            f"for a reviewer that needs longer"
        ) from error
    except UnicodeDecodeError as error:
        raise ReviewerFailed(
            f"{reviewer[0]!r} printed output that is not UTF-8: {error}"
        ) from error
    if completed.returncode != 0:
        tail = completed.stderr.strip().splitlines()[-5:]
        raise ReviewerFailed(
            f"{reviewer[0]!r} exited {completed.returncode}"
            + (": " + " | ".join(tail) if tail else "")
        )
    named: set[str] = set()
    for line in completed.stdout.splitlines():
        finding = line.strip()
        if not finding:
            continue
        record_id = finding if finding in carried else by_title.get(finding.casefold())
        if record_id is None:
            raise ReviewerFailed(
                f"{reviewer[0]!r} named {finding!r}, which is neither the id nor "
                f"the title of a record in the compiled document. Print one id or "
                f"title per line and nothing else."
            )
        named.add(record_id)
    return named


def drive(
    declared: list[dict],
    document: str,
    carried: dict[str, str],
    runs: int,
    reviewer: Callable[[str, str, dict[str, str]], set[str]],
) -> list[dict]:
    """Plant every control `runs` times on each side and count what fired.

    `caught` is how many runs named the record against `catches`; `fired` is
    how many named it against `misses`, or None where no `misses` was written,
    because an unmeasured false-positive rate is not a rate of zero.
    """
    results = []
    for control in sorted(declared, key=lambda control: control["record"]):
        record_id = control["record"]
        caught = sum(
            record_id in reviewer(document, control["catches"], carried)
            for _ in range(runs)
        )
        misses = control.get("misses")
        fired = (
            None
            if misses is None
            else sum(
                record_id in reviewer(document, misses, carried) for _ in range(runs)
            )
        )
        results.append({"record": record_id, "caught": caught, "fired": fired})
    return results


def holds(result: dict, runs: int) -> bool:
    """pass^k on the plant, and quiet on every run against the miss."""
    return result["caught"] == runs and not result["fired"]


def render_drive(results: list[dict], runs: int, reviewer: list[str]) -> str:
    """The reviewer, one line per control, then pass@1 and pass^k over all.

    The reviewer command comes first, as run: a score pasted on its own is a
    copy of this run, and the command is the source that copy has to name. Two
    reviewers scoring the same would otherwise print the same text.

    pass@1 is the mean share of runs that caught the plant: what one review
    would be expected to do. pass^k is the share of controls caught on every
    one of the k runs, which is what a control has to be before anyone leans on
    it. Both are printed because a reviewer can score well on the first and
    still be a coin toss on the second.
    """
    lines = [f"reviewer: {shlex.join(reviewer)}"]
    for result in results:
        fired = result["fired"]
        quiet = (
            "misses not written" if fired is None else f"misses fired {fired}/{runs}"
        )
        verdict = "holds" if holds(result, runs) else "DOES NOT HOLD"
        lines.append(
            f"{result['record']}: caught {result['caught']}/{runs}, {quiet} -- {verdict}"
        )
    if results:
        pass_at_1 = sum(result["caught"] for result in results) / (len(results) * runs)
        pass_k = sum(result["caught"] == runs for result in results)
        lines.append(
            f"pass@1 {pass_at_1:.2f}; pass^{runs} {pass_k}/{len(results)} control(s)"
        )
        measured = [
            result["fired"] for result in results if result["fired"] is not None
        ]
        if measured:
            rate = sum(measured) / (len(measured) * runs)
            lines.append(
                f"false positives {rate:.2f} over {len(measured)} control(s) with a misses"
            )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Rulings
# ---------------------------------------------------------------------------
#
# A ruling has a different shape from a review: a question and its options in,
# an answer and the record lines it rests on out. The harness is the same
# argument `drive` makes one tier down -- a ruler that gives the ruled answer
# one run in three is not one anybody can lean on -- so a ruling control is
# asked k times, and holds only where enough runs give its answer.

#: How many of the k runs must give a ruling control's answer for it to hold.
#: None means all of them.
DEFAULT_AGREE = None

#: One answer in this many is handed to the auditor, when one is named.
DEFAULT_AUDIT_EVERY = 5

#: Taken off an option before a ruler sees it: the label is the proposer's
#: opinion, and a ruler that reads it is ruling on the label.
RECOMMENDED = re.compile(r"\s*\(\s*recommended\s*\)", re.IGNORECASE)

RULING_PREAMBLE = """\
# Rulings

Answer the question from the records below, which this repository adopts, and
from nothing else. Each record is its file, one line per numbered line, at the
revision this repository pins.

Print one JSON object:

- `{{"answer": "<one option, exactly as written>", "citations": [...]}}`
- `{{"none": "<why no option meets the goal>", "citations": [...]}}`
- `{{"escalate": "<reason>"}}` when no record below applies, when two that
  apply conflict and no order below settles it, or when the records do not
  decide between the options.

A citation is `{{"record": "<id>", "line": <n>, "quote": "<text on that line>"}}`.
An answer cites at least one.

## Orders

{orders}
"""


class RulerFailed(Exception):
    """The ruler or the auditor did not answer in the protocol. Exit 2."""


def present(options: list[str], rng: random.Random) -> list[str]:
    """The options as a ruler sees them: shuffled, with "(recommended)" removed."""
    shown = [RECOMMENDED.sub("", option).strip() for option in options]
    rng.shuffle(shown)
    return shown


def ruling_document(
    adopted: list[str], orders: list[dict], records: dict[str, dict]
) -> tuple[str, dict[str, list[str]]]:
    """The document a ruler reads, and each adopted record's lines.

    The whole file, numbered, rather than the compiled review entry: a ruling
    cites a line, and a line is a position in the file at the pinned revision,
    which only the file has.
    """
    listed = (
        "\n".join(
            f"- `{order['prefer']}` over `{order['over']}`: {order['why']}"
            for order in orders
        )
        or "- (none)"
    )
    parts = [RULING_PREAMBLE.format(orders=listed)]
    lines: dict[str, list[str]] = {}
    for record_id in adopted:
        path = records[record_id]["_path"]
        try:
            text = Path(path).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as error:
            raise RulerFailed(f"could not read {path}: {error}") from error
        lines[record_id] = text
        parts.append(f"\n## {record_id} (principles/{record_id}.toml)\n\n")
        parts.extend(f"L{number}: {line}\n" for number, line in enumerate(text, 1))
    return "".join(parts), lines


def _parsed(command: list[str], payload: dict, timeout: int) -> dict:
    """Run a ruler or an auditor once and return the object it printed."""
    try:
        completed = subprocess.run(
            command,
            input=json.dumps(payload, ensure_ascii=False),
            capture_output=True,
            encoding="utf-8",
            timeout=timeout,
            check=False,
        )
    except OSError as error:
        raise RulerFailed(f"could not run {command[0]!r}: {error}") from error
    except subprocess.TimeoutExpired as error:
        raise RulerFailed(
            f"{command[0]!r} did not answer within {timeout}s; pass --timeout "
            f"for one that needs longer"
        ) from error
    except UnicodeDecodeError as error:
        raise RulerFailed(
            f"{command[0]!r} printed output that is not UTF-8: {error}"
        ) from error
    if completed.returncode != 0:
        tail = completed.stderr.strip().splitlines()[-5:]
        raise RulerFailed(
            f"{command[0]!r} exited {completed.returncode}"
            + (": " + " | ".join(tail) if tail else "")
        )
    try:
        answered = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RulerFailed(
            f"{command[0]!r} printed something that is not one JSON object: {error}"
        ) from error
    if not isinstance(answered, dict):
        raise RulerFailed(f"{command[0]!r} printed JSON that is not an object")
    return answered


def ask_ruler(
    ruler: list[str],
    document: str,
    question: str,
    shown: list[str],
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """Ask once, and return the answer as `{"kind", "value", "citations"}`.

    `kind` is `answer`, `none` or `escalate`. An answer that is not one of the
    options shown, or an object holding more or less than one of the three, is
    the ruler breaking the protocol, which says nothing about the ruling.
    """
    answered = _parsed(
        ruler, {"document": document, "question": question, "options": shown}, timeout
    )
    kinds = [kind for kind in ("answer", "none", "escalate") if kind in answered]
    if len(kinds) != 1 or not set(answered) <= {
        "answer",
        "none",
        "escalate",
        "citations",
    }:
        raise RulerFailed(
            f"{ruler[0]!r} printed {sorted(answered)}; one of answer, none or "
            f"escalate is expected, with citations beside an answer or a none"
        )
    kind = kinds[0]
    value = answered[kind]
    if not isinstance(value, str) or not value.strip():
        raise RulerFailed(f"{ruler[0]!r} gave an empty {kind}")
    if kind == "answer" and value not in shown:
        raise RulerFailed(
            f"{ruler[0]!r} answered {value!r}, which is not one of the options it "
            f"was shown. Print one option exactly as written"
        )
    citations = answered.get("citations", [])
    if kind == "escalate" and citations:
        raise RulerFailed(
            f"{ruler[0]!r} escalated and cited; an escalation cites nothing"
        )
    if not isinstance(citations, list) or not all(
        isinstance(citation, dict)
        and set(citation) == {"record", "line", "quote"}
        and isinstance(citation["record"], str)
        and isinstance(citation["line"], int)
        and not isinstance(citation["line"], bool)
        and isinstance(citation["quote"], str)
        for citation in citations
    ):
        raise RulerFailed(
            f"{ruler[0]!r} printed citations that are not a list of "
            f'{{"record", "line", "quote"}} objects'
        )
    return {"kind": kind, "value": value, "citations": citations}


def unresolved(citations: list[dict], lines: dict[str, list[str]]) -> list[str]:
    """Each citation that does not say what it quotes, in the document's files."""
    found = []
    for citation in citations:
        record_id, number, quote = (
            citation["record"],
            citation["line"],
            citation["quote"],
        )
        text = lines.get(record_id)
        if text is None:
            found.append(f"{record_id} is not an adopted record")
        elif not 1 <= number <= len(text):
            found.append(f"{record_id} has no line {number}")
        elif not quote.strip() or quote not in text[number - 1]:
            found.append(f"{record_id} L{number} does not say {quote!r}")
    return found


def audit(
    auditor: list[str],
    document: str,
    question: str,
    options: list[str],
    given: dict,
    timeout: int = DEFAULT_TIMEOUT,
) -> str | None:
    """Ask a fresh auditor whether the citations support the answer.

    It is handed the answer and its citations and nothing else the ruler
    printed. Returns None where they support it, and the auditor's reason
    where they do not.
    """
    answered = _parsed(
        auditor,
        {
            "document": document,
            "question": question,
            "options": options,
            given["kind"]: given["value"],
            "citations": given["citations"],
        },
        timeout,
    )
    supported = answered.get("supported")
    if not isinstance(supported, bool):
        raise RulerFailed(f'{auditor[0]!r} printed no "supported": true or false')
    if supported:
        return None
    reason = answered.get("reason")
    return reason if isinstance(reason, str) and reason.strip() else "no reason given"


def ruled(control: dict) -> tuple[str, str | None]:
    """A control's ruling as `(kind, the option or None)`."""
    if control.get("escalate"):
        return "escalate", None
    if control.get("none"):
        return "none", None
    return "answer", RECOMMENDED.sub("", control["answer"]).strip()


def drive_rulings(
    controls: list[dict],
    document: str,
    lines: dict[str, list[str]],
    runs: int,
    rng: random.Random,
    ruler: Callable[[str, str, list[str]], dict],
    auditor: Callable[[str, str, list[str], dict], str | None] | None = None,
    audit_every: int = DEFAULT_AUDIT_EVERY,
) -> list[dict]:
    """Ask every ruling control `runs` times and count the runs that held.

    A run holds where its kind and option are the control's and every citation
    resolves. Then one held run in `audit_every`, at least one per control
    with any, is handed to the auditor, and a run it finds unsupported stops
    holding.
    """
    results = []
    for control in controls:
        kind, option = ruled(control)
        held: list[dict] = []
        broken: list[str] = []
        given_kinds: list[str] = []
        for _ in range(runs):
            shown = present(control["options"], rng)
            given = ruler(document, control["question"], shown)
            given_kinds.append(
                given["value"] if given["kind"] == "answer" else given["kind"]
            )
            if given["kind"] != kind or (kind == "answer" and given["value"] != option):
                continue
            if given["kind"] in {"answer", "none"} and not given["citations"]:
                broken.append(f"a {given['kind']} that cites nothing")
                continue
            failed = unresolved(given["citations"], lines)
            if failed:
                broken.extend(failed)
                continue
            held.append(given)
        audited = unsupported = 0
        if auditor is not None:
            answered = [given for given in held if given["kind"] != "escalate"]
            sample = (
                rng.sample(answered, -(-len(answered) // audit_every))
                if answered
                else []
            )
            for given in sample:
                audited += 1
                reason = auditor(
                    document,
                    control["question"],
                    [
                        RECOMMENDED.sub("", option).strip()
                        for option in control["options"]
                    ],
                    given,
                )
                if reason is not None:
                    unsupported += 1
                    broken.append(
                        f"the auditor found the citations unsupported: {reason}"
                    )
                    held.remove(given)
        results.append(
            {
                "question": control["question"],
                "ruled": option if kind == "answer" else kind,
                "held": len(held),
                "given": given_kinds,
                "broken": broken,
                "audited": audited,
                "unsupported": unsupported,
            }
        )
    return results


def ruling_holds(result: dict, agree: int) -> bool:
    """At least `agree` runs gave the ruling, and no audited one was unsupported."""
    return result["held"] >= agree and not result["unsupported"]


def render_rulings(
    results: list[dict],
    runs: int,
    agree: int,
    seed: int,
    ruler: list[str],
    auditor: list[str] | None,
) -> str:
    """The ruler and auditor as run, the seed to rerun, one line per control,
    then pass@1 and pass^k."""
    lines = [f"ruler: {shlex.join(ruler)}"]
    if auditor is not None:
        lines.append(f"auditor: {shlex.join(auditor)}")
    lines.append(
        f"seed {seed} (pass --seed {seed} to shuffle the options the same way)"
    )
    audited = auditor is not None
    for result in results:
        verdict = "holds" if ruling_holds(result, agree) else "DOES NOT HOLD"
        question = result["question"].splitlines()[0][:72]
        audit_note = (
            f", audited {result['audited']} ({result['unsupported']} unsupported)"
            if audited
            else ""
        )
        lines.append(
            f"{question}: ruled {result['ruled']!r}, held {result['held']}/{runs} "
            f"(agree {agree}){audit_note} -- {verdict}"
        )
        given = ", ".join(repr(value) for value in result["given"])
        lines.append(f"  given: {given}")
        lines.extend(f"  - {reason}" for reason in result["broken"])
    if results:
        pass_at_1 = sum(result["held"] for result in results) / (len(results) * runs)
        pass_k = sum(result["held"] == runs for result in results)
        lines.append(
            f"pass@1 {pass_at_1:.2f}; pass^{runs} {pass_k}/{len(results)} control(s)"
        )
    if not audited:
        lines.append(
            "no --auditor named, so whether the citations support the answers is unaudited"
        )
    return "\n".join(lines) + "\n"
