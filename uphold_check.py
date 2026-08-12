#!/usr/bin/env python3
"""The principle catalog, for a person building a rule.

The catalog says what a principle claims and what a machine could observe about
it. Turning one into a rule that fires is work a person or an agent does once,
in the seam that can observe the property. What is here is everything around
that work which is PROSE: the record itself, the alias index a reader arrives
through, the review tier for principles no rule can decide, and the OSCAL
export.

The reconcile is not here. Asking whether a claim holds means knowing which
rules this repository resolves to -- the bundled sets, `inherit.paths`,
`inherit.disabled_rules`, and a repository's own rule shadowing an inherited id
-- and answering that here meant re-implementing `config::load` in a second
program free to disagree with the first. It disagreed about the seam a hookless
rule runs at, and credited a checker standing in front of `gh` to the file scan.

    uphold check              # the claims still hold
    uphold check --coverage   # which rules here carry a principle

This script reads the catalog and never the policy, which is why it can stay a
script: a mode that cannot read the policy cannot disagree with the loader about
which rules run.

Usage::

    uphold_check.py --explain ID    # print one catalog record (an alias works too)
    uphold_check.py --list          # list catalog ids
    uphold_check.py --review        # what routes to a rule and what to a reviewer
    uphold_check.py --review --emit # write the compiled review document
    uphold_check.py --init          # print a starter declaration
    uphold_check.py --oscal         # emit the claims as OSCAL component-definition
    uphold_check.py --self-check    # validate the bundled catalog itself

Exit codes -- the same three every seam here uses, so a caller never has to
learn a second convention:

    0  the mode did what it was asked
    1  a refusal: the review document is over its ceiling, a claim is false
    2  could not look (missing declaration, unreadable catalog, no binary to ask)

Exit 2 is deliberately not exit 0. A configuration this tool could not read is
not a repository that complies; see the `explicit-unknown` record.
"""

from __future__ import annotations

import functools
import json
import subprocess
import sys
import tomllib
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))

import review as review_mod
from catalog import load_catalog, resolve

HERE = Path(__file__).resolve().parent
DECLARATION_RELPATH = Path("policy") / "upheld.toml"

# The declaration is the only file this still reads out of a consumer's tree,
# and `--oscal` is the only mode that reads it. Everything that used to be here
# -- the pre-commit and lefthook scanners, the published-id table, the content
# policy reader -- answered "which rules run here", and `uphold check` answers
# that now, out of the loader that decides it.


class Refused(Exception):
    """The reconcile said a claim is false. Exit 1, not could-not-look.

    Kept apart from `CouldNotLook` because the two are different answers about
    the world and the export owes an outside reader the difference: a claim this
    tool refused is a claim it DID evaluate.
    """


class CouldNotLook(Exception):
    """Raised where the tool cannot inspect what it claims to check (exit 2)."""


def discover_root() -> Path:
    """Walk up from cwd until the declaration is found."""
    candidate = Path.cwd().resolve()
    while True:
        if (candidate / DECLARATION_RELPATH).is_file():
            return candidate
        parent = candidate.parent
        if parent == candidate:
            return Path.cwd().resolve()
        candidate = parent


def load_records() -> dict[str, dict]:
    return {record["id"]: record for record in load_catalog()}


def read_toml(path: Path) -> dict:
    """Parse a TOML file, or say that it could not be parsed.

    `UnicodeDecodeError` for the same reason `read_text` catches it, and it
    reaches here by a route that is easy to miss: `tomllib.load` takes a binary
    handle and decodes the bytes itself, so a declaration or a policy file with
    one byte that is not UTF-8 raises out of the decode rather than out of the
    parse, and `TOMLDecodeError` never sees it.
    """
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise CouldNotLook(f"{path}: {error}") from error


def read_text(path: Path) -> str:
    """Read a configuration file, or say that it could not be read.

    `UnicodeDecodeError` is caught beside `OSError` because it is the same
    answer arriving by a different route, and it does NOT derive from it: it
    derives from `ValueError`, so a config carrying one stray 0xff byte escaped
    this handler entirely and left the process on a traceback and exit 1. Every
    caller here is a could-not-look path, and the contract reads exit 1 as "a
    claim is false" -- so an unreadable byte was reported as a repository whose
    declaration lies. See the `explicit-unknown` record.
    """
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise CouldNotLook(f"{path}: {error}") from error


# ---------------------------------------------------------------------------
# Asking the engine
# ---------------------------------------------------------------------------
#
# The reconcile moved into the binary as `uphold check`. What is left here reads
# the CATALOG and never the policy, which is the whole of why it is still
# Python: a mode that cannot read the policy cannot disagree with the loader
# about which rules run, and disagreeing about exactly that is what the two
# readers did.
#
# `--oscal` is the exception, because a component definition is an assertion to
# an outside reader and exporting an unreconciled one would publish a claim
# nobody confirmed. So it asks the binary rather than deriving the answer, and a
# binary it cannot reach is could-not-look -- exit 2, not a smaller export.


def engine(root: Path, *args: str) -> subprocess.CompletedProcess:
    """Run the binary, wherever this checkout keeps it.

    Built binary first, then PATH, then `cargo run`. The last one matters and is
    not a convenience: the modes that call this are the ones that never leave
    this repository -- `--review` is in no consumer's manifest, and `--oscal` is
    run by hand -- and the environment they run in is a pre-commit hook that has
    not built anything. Without it the review hook fails in CI on a machine that
    has cargo, a checkout, and every ingredient except the one command nobody
    ran.

    A binary that cannot be produced by any of the three is could-not-look. It
    is not a smaller answer or an older one; see the `explicit-unknown` record.
    """
    attempts: list[list[str]] = []
    for built in (
        HERE / "target" / "release" / "uphold",
        HERE / "target" / "debug" / "uphold",
    ):
        if built.is_file():
            attempts.append([str(built), *args])
    attempts.append(["uphold", *args])
    if (HERE / "Cargo.toml").is_file():
        attempts.append(
            [
                "cargo",
                "run",
                "--quiet",
                "--manifest-path",
                str(HERE / "Cargo.toml"),
                "--",
                *args,
            ]
        )

    reasons: list[str] = []
    for attempt in attempts:
        try:
            return subprocess.run(
                attempt, cwd=root, capture_output=True, text=True, check=False
            )
        except OSError as error:
            reasons.append(f"{attempt[0]}: {error}")
    raise CouldNotLook(
        f"`uphold {' '.join(args)}` could not be run, so what this repository "
        f"enforces is unknown ({'; '.join(reasons)}). Build it with "
        f"`cargo build --release`, or install it on PATH."
    )


@functools.cache
def upstream_url() -> str:
    """The `https://host/owner/name` this repository publishes itself as.

    Asked of the binary, which holds it as `package.repository` compiled in, so
    the namespace an OSCAL property is stamped with cannot drift from the crate
    that produced it. Reading `Cargo.toml` off disk beside this script worked
    only in a checkout of this repository, and this mode is meant to be run
    from a consumer's.
    """
    answered = engine(Path.cwd(), "--upstream")
    url = answered.stdout.strip()
    if answered.returncode != 0 or not url:
        raise CouldNotLook(
            "the upstream this repository publishes itself as could not be read "
            f"from the binary: {answered.stderr.strip() or 'no answer'}"
        )
    return url


def declared_claims(declaration: dict) -> list[tuple[str, str]]:
    """Return (principle, rule) per entry, without judging either of them.

    Judging them is `uphold check`. This reads the pairs so `--review` knows
    which principles a rule is claimed for, and asks the binary separately
    whether any seam supplies that rule.
    """
    entries = declaration.get("enforce", [])
    if not isinstance(entries, list):
        raise CouldNotLook("`enforce` must be an array of tables")
    claims = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise CouldNotLook(f"enforce[{index}] must be a table")
        values = tuple(entry.get(field) for field in ("principle", "rule"))
        if not all(isinstance(value, str) and value.strip() for value in values):
            raise CouldNotLook(f"enforce[{index}] needs principle and rule as strings")
        claims.append(values)
    return claims


def engine_suppliers(root: Path, *, strict: bool = True) -> dict[str, list[str]]:
    """Which seams supply each rule, as the reconcile in the binary sees it.

    `strict` is the difference between the two callers. `--oscal` publishes an
    assertion to an outside reader, so a declaration that does not reconcile has
    nothing honest to export and the refusal travels. `--review` runs over a
    declaration somebody is still writing: a claim naming a rule nothing
    supplies is exactly the state it exists to help with, and refusing there
    would take the review document away at the moment it is most wanted. The
    evidence lines for the claims that DID hold are on stdout either way.
    """
    answered = engine(root, "check")
    if answered.returncode == 2:
        raise CouldNotLook(answered.stderr.strip() or "uphold check could not look")
    if answered.returncode != 0 and strict:
        raise Refused(
            "the enforcement claims do not reconcile, so there is nothing "
            f"honest to export:\n{answered.stderr.strip()}"
        )
    suppliers: dict[str, list[str]] = {}
    for line in answered.stdout.splitlines():
        if " <- " not in line or "enforced by" not in line:
            continue
        _, rest = line.split(" <- ", 1)
        rule, by = rest.split("  enforced by ", 1)
        # Folded back to the SEAM, because an OSCAL component is a thing that
        # implements a control and the seam is that thing. `uphold check` names
        # the evidence -- which stage, which scan -- and a component per stage
        # would split one implementation across five.
        seams = []
        for part in by.split(","):
            part = part.strip()
            if not part:
                continue
            seams.append("local" if part.startswith("a hook") else "uphold")
        for seam in seams:
            if seam not in suppliers.setdefault(rule.strip(), []):
                suppliers[rule.strip()].append(seam)
    return suppliers


# ---------------------------------------------------------------------------
# Output for a person building a rule
# ---------------------------------------------------------------------------


def format_explain(record: dict) -> str:
    enforcement = record.get("enforcement", {})
    lines = [
        f"{record['title']} ({record['id']})",
        f"kind: {record['kind']}   status: {record['status']}   "
        f"enforcement: {enforcement.get('level')} / automatable={enforcement.get('automatable')}",
        "",
        f"claim: {record['claim']}",
        f"problem: {record['problem']}",
        "",
        "applies when:",
    ]
    lines += [f"  - {item}" for item in record["applies_when"]]
    lines += ["", "does not mean:"]
    lines += [f"  - {item}" for item in record["does_not_mean"]]
    lines += ["", "costs:"]
    lines += [f"  - {item}" for item in record["costs"]]
    if record.get("conflicts_with"):
        lines += ["", "conflicts with: " + ", ".join(record["conflicts_with"])]
    if enforcement.get("observable"):
        lines += ["", "what a tool can observe:"]
        lines += [f"  - {item}" for item in enforcement["observable"]]
    if enforcement.get("checks"):
        lines += ["", "candidate checks (design input, not checks):"]
        lines += [f"  - {item}" for item in enforcement["checks"]]
    if enforcement.get("limits"):
        lines += ["", "what no tool can decide:"]
        lines += [f"  - {item}" for item in enforcement["limits"]]
    lines += ["", "review questions:"]
    lines += [f"  - {item}" for item in record["review_questions"]]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# OSCAL export
# ---------------------------------------------------------------------------
#
# NIST's OSCAL component-definition model says the same thing `[[enforce]]` says:
# here is a component, and here are the controls it implements. Its ecosystem --
# compliance-trestle, Compliance-to-Policy -- already turns that into policy for
# several engines and normalizes their results back, so emitting it is worth more
# than a private format is.
#
# What does NOT convert is the catalog. An OSCAL control has no place for scope
# conditions, costs, conflicts, or a record admitting no machine can observe it;
# the closest available is an untyped `prop`, which no consumer reads and no
# schema checks. So the split is deliberate: the records stay TOML and stay
# validated here, and only the mapping crosses over.
#
# Anything of ours that survives the crossing does so as a prop in the namespace
# `upstream_url()` returns, which is where OSCAL puts what it does not model.
# That namespace is this repository's own URL, read from the manifest rather than
# written down again here -- see `CARGO_MANIFEST`.
OSCAL_VERSION = "1.1.3"

# A fixed UUIDv5 namespace, so the same declaration always produces the same
# identifiers. OSCAL requires a uuid on every component and every requirement;
# generating them randomly would make a re-export a diff with no change in it,
# which is how a generated file stops being read.
UUID_NAMESPACE = uuid.UUID("f7d4a41e-0f1a-5f0e-9c3e-4b3a2c1d0e9f")

COMPONENT_DESCRIPTIONS = {
    "uphold": "The rules this repository runs on itself: content policy over its files, and guards over what git is about to do.",
    "cmd-shims": "Guards over what a command publishes, on the paths git hooks cannot see.",
    "local": "Checks this repository defines and runs itself.",
}


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(UUID_NAMESPACE, "/".join(parts)))


def _last_modified(root: Path) -> str:
    """The declaration's last commit date, so the export is reproducible.

    A wall-clock timestamp would make every export differ from the last one
    while saying nothing changed.
    """
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%cI", "--", str(DECLARATION_RELPATH)],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        stamp = result.stdout.strip()
        if stamp:
            return stamp
    except OSError:
        pass
    # No git, or the declaration is not committed yet. Say so rather than
    # inventing a time: the field is required and a made-up value is worse.
    return "1970-01-01T00:00:00Z"


def build_oscal(root: Path, declaration: dict, records: dict[str, dict]) -> dict:
    entries = declaration.get("enforce", [])
    # The component is still the seam, because a component is a thing that
    # implements a control and the seam is that thing. It is derived from what
    # supplies the rule rather than read off the claim, so a rule enforced at
    # two seams becomes an implemented-requirement under both -- which is what
    # an outside reader of this export needs to know, and what a single `tier`
    # on the claim could never have said.
    suppliers = engine_suppliers(root)
    by_tier: dict[str, list[dict]] = {}
    for entry in entries:
        for tier in suppliers.get(entry["rule"], []):
            by_tier.setdefault(tier, []).append(entry)

    components = []
    for tier in sorted(by_tier):
        requirements = []
        for entry in by_tier[tier]:
            principle = entry["principle"]
            record = records.get(principle, {})
            enforcement = record.get("enforcement", {})
            requirements.append(
                {
                    "uuid": _uuid(
                        "requirement", root.name, tier, entry["rule"], principle
                    ),
                    "control-id": principle,
                    "description": record.get("summary", ""),
                    "props": [
                        {
                            "name": "rule-id",
                            "value": entry["rule"],
                            "ns": upstream_url(),
                        },
                        {"name": "tier", "value": tier, "ns": upstream_url()},
                        # Carried across because it is the one field that changes
                        # what a consumer may conclude from a passing check.
                        {
                            "name": "automatable",
                            "value": enforcement.get("automatable", "unknown"),
                            "ns": upstream_url(),
                        },
                        {
                            "name": "enforcement-level",
                            "value": enforcement.get("level", "unknown"),
                            "ns": upstream_url(),
                        },
                    ],
                }
            )

        components.append(
            {
                "uuid": _uuid("component", root.name, tier),
                "type": "software",
                "title": tier,
                "description": COMPONENT_DESCRIPTIONS.get(tier, tier),
                "control-implementations": [
                    {
                        "uuid": _uuid("implementation", root.name, tier),
                        "source": upstream_url(),
                        "description": (
                            f"Principles this repository holds itself to through {tier}."
                        ),
                        "implemented-requirements": requirements,
                    }
                ],
            }
        )

    return {
        "component-definition": {
            "uuid": _uuid("component-definition", root.name),
            "metadata": {
                "title": f"Engineering principles enforced in {root.name}",
                "last-modified": _last_modified(root),
                "version": "1.0.0",
                "oscal-version": OSCAL_VERSION,
            },
            "components": components,
        }
    }


STARTER = """\
# What enforces which principle in this repository.
# https://github.com/HackingGate/uphold
#
# One entry per rule that already fires. `rule` is the rule's own id, resolved
# against every seam this repository runs -- the content policy, git-guards,
# cmd-shims, and local hooks. A rule enforced at more than one seam is normal
# and every seam is reported. The entry is checked against this repo's
# configuration, so it goes stale loudly when the rule is removed or disabled.
#
# A principle with no rule yet does not belong in this file. Build the rule
# first -- `uphold_check.py --explain <id>` is the design input -- or leave
# the principle in prose, where a reader can weigh it.

# [[enforce]]
# principle = "least-privilege"
# rule = "prevent-public-push"
"""


def review_settings(declaration: dict) -> dict:
    """Read `[review]`, refusing a field whose type the rest of the mode assumes.

    All four fields are checked, because the two that were not were read by
    coercion: `int(settings.get("max_lines"))` and `list(...)` turn a wrong type
    into a ValueError or a TypeError, which leaves the process on a traceback
    and exit 1 -- and exit 1 in this tool means a claim is false. A declaration
    saying `max_lines = "nine hundred"` is one this tool could not read, which
    is exit 2 and a message naming the field. See the `explicit-unknown` record.
    """
    settings = declaration.get("review", {})
    if not isinstance(settings, dict):
        raise CouldNotLook("`review` must be a table")
    exempt = settings.get("no_subject_here", {})
    if not isinstance(exempt, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in exempt.items()
    ):
        # A reason, not a bare list. An exemption whose reason nobody wrote is
        # one nobody can review, and it is exactly as permanent as one that was
        # argued for.
        raise CouldNotLook(
            "`review.no_subject_here` maps a record id to the reason this "
            "repository has no subject for it"
        )

    # `isinstance(True, int)` is True in Python, and `max_lines = true` is a
    # ceiling of 1 rather than a configuration error, so bool is excluded by
    # hand.
    max_lines = settings.get("max_lines", review_mod.DEFAULT_MAX_LINES)
    if isinstance(max_lines, bool) or not isinstance(max_lines, int) or max_lines < 1:
        raise CouldNotLook(
            f"`review.max_lines` must be a positive integer, not {max_lines!r}"
        )

    domains = settings.get("include_domains", [])
    if not isinstance(domains, list) or not all(
        isinstance(value, str) for value in domains
    ):
        raise CouldNotLook("`review.include_domains` must be an array of domain names")

    emit = settings.get("emit", ["REVIEW.md"])
    if not isinstance(emit, list) or not all(
        isinstance(value, str) and value.strip() for value in emit
    ):
        raise CouldNotLook(
            "`review.emit` must be an array of file names to write the compiled "
            "review document to"
        )

    return {
        "max_lines": max_lines,
        "include_domains": domains,
        "emit": emit,
        "exempt": exempt,
    }


def emit_target(root: Path, name: str) -> Path:
    """Where one `review.emit` name writes to, refusing anything outside the repo.

    The name is taken from the declaration and handed to `write_text`, so
    `emit = ["../ESCAPED.md"]` created a file one level ABOVE the repository and
    reported "wrote ../ESCAPED.md" as though it had done what was asked. A
    declaration is configuration a reviewer skims and a hook runs unattended;
    the one place it may write is the repository it describes.
    """
    candidate = Path(name)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise CouldNotLook(
            f"`review.emit` names {name!r}, which is outside this repository; "
            f"the compiled document is written into the repository it describes"
        )
    target = (root / candidate).resolve()
    if not target.is_relative_to(root.resolve()):
        # A symlinked parent directory reaches outside the tree without a `..`
        # anywhere in the written name.
        raise CouldNotLook(
            f"`review.emit` names {name!r}, which resolves to {target}, outside {root}"
        )
    return target


def run_review(argv: list[str]) -> int:
    emit = argv[:1] == ["--emit"]
    check = argv[:1] == ["--check"]
    if argv and not (emit or check):
        print("usage: uphold_check.py --review [--emit|--check]", file=sys.stderr)
        return 2

    root = discover_root()
    try:
        declaration = read_toml(root / DECLARATION_RELPATH)
        settings = review_settings(declaration)
        # Resolved before anything is rendered, so a name this mode may not
        # write to is refused as unreadable configuration rather than after a
        # document exists to write.
        targets = [(name, emit_target(root, name)) for name in settings["emit"]]
        claims = declared_claims(declaration)
        suppliers = engine_suppliers(root, strict=False)
    except CouldNotLook as error:
        print(f"uphold review could not look: {error}", file=sys.stderr)
        return 2

    records = load_records()
    # Filtered by `suppliers`, exactly as `active` is on the line below. A
    # principle leaves the review document because a rule enforces it -- that is
    # the `continue` in `review.route`, "a rule enforces it; a reviewer
    # repeating it is noise" -- and a claim naming a rule no seam here supplies
    # enforces nothing. Unfiltered, such a claim removed the principle from the
    # document AND was absent from the "already active here" list the same
    # document prints, so an `automatable = "yes"` record could be enforced by
    # nothing and reviewed by nobody, with the page showing no trace of either.
    #
    # The reconcile refuses that claim outright; this mode has to survive it,
    # because `--review` runs over a declaration a person is still writing.
    claimed = {principle for principle, rule in claims if rule in suppliers}
    for_review, errors, stale = review_mod.route(
        records, claimed, settings["exempt"], settings["include_domains"]
    )
    active = sorted({rule for _, rule in claims if rule in suppliers})
    document = review_mod.render(for_review, active)

    over = review_mod.over_budget(document, settings["max_lines"])
    for message in errors + stale:
        print(f"- {message}", file=sys.stderr)
    if over:
        print(f"- {over}", file=sys.stderr)
    if errors or stale or over:
        return 1

    if emit:
        for name, path in targets:
            try:
                path.write_text(document, encoding="utf-8")
            except OSError as error:
                # A missing parent directory, a read-only tree, a name that is
                # already a directory. None of those is a false claim, so none
                # of them is exit 1.
                print(f"uphold review could not write {name}: {error}", file=sys.stderr)
                return 2
            print(f"wrote {name} ({len(document.splitlines())} lines)")
        return 0

    if check:
        for name, path in targets:
            try:
                current = read_text(path) if path.is_file() else ""
            except CouldNotLook as error:
                print(f"uphold review could not look: {error}", file=sys.stderr)
                return 2
            if current != document:
                print(
                    f"{name} is not what the catalog compiles to; run --review --emit",
                    file=sys.stderr,
                )
                return 1
        print("compiled review is current")
        return 0

    print(
        f"{len(for_review)} record(s) compile into the review tier; "
        f"{len(active)} static rule(s) are named as already enforcing"
    )
    print(
        f"{len(document.splitlines())} lines against a ceiling of {settings['max_lines']}"
    )
    return 0


def main(argv: list[str]) -> int:
    records = load_records()

    if argv[:1] == ["--list"]:
        for value, record in sorted(records.items()):
            print(f"{value:38} {record['kind']:20} {record['summary']}")
        return 0

    if argv[:1] == ["--init"]:
        print(STARTER, end="")
        return 0

    if argv[:1] == ["--explain"]:
        if len(argv) != 2:
            print("usage: uphold_check.py --explain ID|NAME", file=sys.stderr)
            return 2
        record = records.get(argv[1])
        if record is None:
            # Ids are tried first and stay the stable API; a name is how a
            # reader who has not read the catalog arrives -- "combinatorial
            # explosion", not `parameterize-do-not-enumerate`. The index that
            # answers them is the one QUICK_REFERENCE.md renders, so the two
            # cannot disagree about which record owns a name. An ambiguous
            # partial name is reported as ambiguous rather than resolved to
            # whichever entry sorted first: a tool that guesses here is a tool
            # that explains the wrong record with full confidence.
            hits = {entry.record_id for entry in resolve(argv[1])}
            if not hits:
                print(
                    f"unknown principle id or name {argv[1]!r}; "
                    "run --list for ids, or see the alias index in "
                    "QUICK_REFERENCE.md",
                    file=sys.stderr,
                )
                return 2
            if len(hits) > 1:
                print(
                    f"the name {argv[1]!r} matches more than one record: "
                    f"{', '.join(sorted(hits))}",
                    file=sys.stderr,
                )
                return 2
            record = records[hits.pop()]
        print(format_explain(record), end="")
        return 0

    if argv[:1] == ["--self-check"]:
        import validate

        return validate.main()

    if argv[:1] == ["--review"]:
        return run_review(argv[1:])

    if argv[:1] != ["--oscal"]:
        # The reconcile and the coverage report are `uphold check` and
        # `uphold check --coverage`. They were here while this script
        # re-implemented `config::load` to answer them; the loader answers now.
        print(
            "usage: uphold_check.py "
            "[--explain ID|NAME | --list | --init | --oscal | --review "
            "| --self-check]\n"
            "\n"
            "To reconcile this repository's enforcement claims:\n"
            "    uphold check              # the claims still hold\n"
            "    uphold check --coverage   # which rules here carry a principle",
            file=sys.stderr,
        )
        return 2

    root = discover_root()
    declaration_path = root / DECLARATION_RELPATH
    if not declaration_path.is_file():
        print(
            f"uphold check could not look: {declaration_path} not found "
            f"(searched upward from {Path.cwd().resolve()}).\n"
            f"Create one with: uphold_check.py --init > {DECLARATION_RELPATH}",
            file=sys.stderr,
        )
        return 2

    try:
        declaration = read_toml(declaration_path)
        # The export gates on the reconcile and only emits what held. A
        # component definition is a claim to an outside reader; exporting an
        # unreconciled one would publish an assertion nobody had confirmed.
        document = build_oscal(root, declaration, records)
    except Refused as error:
        print(f"uphold check refused: {error}", file=sys.stderr)
        return 1
    except CouldNotLook as error:
        print(f"uphold check could not look: {error}", file=sys.stderr)
        return 2

    print(json.dumps(document, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
