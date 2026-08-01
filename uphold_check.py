#!/usr/bin/env python3
"""Reconcile a repository's enforcement claims against the principle catalog.

The catalog says what a principle claims and what a machine could observe about
it. Turning one into a rule that fires is work a person or an agent does once,
in the seam that can observe the property: `uphold` over this repository's
own files and over what git is about to do, cmd-shims over what a command
publishes, or a local hook. This script is the reconcile step afterwards.

A declaration entry is a claim that a named rule is what enforces a named
principle *here*::

    # policy/upheld.toml
    [[enforce]]
    principle = "explicit-unknown"
    rule = "catalog-tests"

The claim is falsifiable from this repository's own configuration: the rule is
installed and enabled somewhere, or it is not. When it is false the principle
stopped being enforced while the declaration went on saying it was, and that is
the only thing this checks.

A rule id resolves against every seam at once. It named a tier as well until
the seams stopped being separate repositories, and a rule enforced by more than
one tool is the ordinary case rather than an ambiguity: `prevent-ai-author`
guards a commit message in git-guards and a pull-request body in cmd-shims,
because those are two paths to the same public place. The reconcile reports
every seam that supplies the rule.

It carries no prose into any runtime. A principle's text is design input for
whoever builds the rule -- read it with `--explain` -- not a value a tool
injects, because a tool holding prose has no condition on which to emit it. See
the `enforcement-needs-a-trigger` record.

Usage::

    uphold_check.py                 # reconcile the declaration (hook mode)
    uphold_check.py --explain ID    # print one catalog record (an alias works too)
    uphold_check.py --list          # list catalog ids
    uphold_check.py --coverage      # which rules here carry a principle
    uphold_check.py --review        # what routes to a rule and what to a reviewer
    uphold_check.py --review --emit # write the compiled review document
    uphold_check.py --init          # print a starter declaration
    uphold_check.py --oscal         # emit the claims as OSCAL component-definition
    uphold_check.py --self-check    # validate the bundled catalog itself

Exit codes -- the same three the other HackingGate tiers use, so a caller never
has to learn a second convention:

    0  every claim reconciles
    1  a claim is false: the rule is absent, disabled, or the principle is not one
    2  could not look (missing declaration, unparseable config, unreadable seam)

Exit 2 is deliberately not exit 0. A configuration this tool could not read is
not a repository that complies; see the `explicit-unknown` record.

`--coverage` is the one mode that reports rather than refuses: 0, or 2 where a
tier's configuration could not be read. A rule running under no claim is not a
failure -- deciding which principle a rule serves is a judgment, and a mode that
exited 1 over a missing one would be paid in claims nobody believes.
"""

from __future__ import annotations

import functools
import json
import re
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

PRE_COMMIT_CONFIG = Path(".pre-commit-config.yaml")
LEFTHOOK_CONFIG = Path("lefthook.yml")
CONTENT_POLICY = Path("policy") / "principles.toml"
CONTENT_POLICY_BASE = Path("policy") / "base"
CMD_SHIMS_CHECKS = Path(".cmd-shims") / "checks.enabled"

# `uphold` is one seam now, not two. The content rules and the guards live
# in one policy file under one id namespace and are run by one binary, so
# splitting them here would put back the boundary the merge deleted -- and
# git-guards no longer supplies anything: its eleven ids are guard rules.
TIERS = ("uphold", "cmd-shims", "local")

# `- repo: <url>` / `- id: <hook>` in a pre-commit or prek configuration. A
# line scan rather than a YAML parse: this script installs as `language: script`
# and has no dependencies. The scan sees the block form every HackingGate repo
# uses; a flow-style file yields zero repos, which is reported as could-not-look
# rather than as an absent hook.
REPO_LINE = re.compile(r"^\s*-\s*repo:\s*(\S+)")
HOOK_ID_LINE = re.compile(r"^\s*-\s*id:\s*(\S+)")
LEFTHOOK_COMMAND = re.compile(r"^\s{4}([A-Za-z0-9._-]+):\s*$")

# The ids THIS repository publishes, read from the manifest that publishes them.
#
# Written out here as a literal it would be an enumeration describing a constant
# in another file -- the exact shape of the bug `_rule_ids` was rewritten to
# delete, where a hardcoded list of six table names sat opposite an engine that
# had seven and silently under-reported. The manifest is the list; this reads it.
PUBLISHED_HOOKS = Path(".pre-commit-hooks.yaml")

# A lefthook consumer pins nothing by id. It names this repository under
# `remotes:` and lefthook merges the commands in, so the consumer's own file
# contains neither an id nor a command name -- only the repository name and,
# for anyone wiring it by hand, the command line itself.
#
# The subcommand is what is matched, not the executable. This repository runs
# its own binary out of the working tree with `cargo run -- scan`, a consumer
# runs `uphold scan` from PATH, and a third might run it by absolute path;
# all three are the same seam, and a pattern anchored on the program name would
# have recognised only the middle one.
LEFTHOOK_RUN = re.compile(r"^\s*run:\s*.*(?:\buphold|--)\s+(?:scan|guard)\b")
# Either the repository name or the config path it publishes. The path is the
# more reliable of the two: `git_url` may be a mirror, an SSH form, or a local
# clone, and none of those has to contain the repository's name -- but a remote
# that includes `hooks/lefthook.yml` is including THIS repository's config, and
# that string is what the consumer wrote down.
#
# The name carries the owner because a bare repository name is not this
# repository's to claim: a remote for someone else's `uphold-policies` would
# otherwise read as this one.
#
# Owner and name are READ rather than written down here, for the same reason
# PUBLISHED_HOOKS is read: a literal would be a second statement of a fact
# `Cargo.toml` already owns, and the copy is the one that goes stale. A rename
# that lands in the manifest and not in this line fails silently and late -- the
# seam simply stops being recognised in a lefthook consumer, which reads as "no
# runner configuration here" rather than as a stale pattern.
#
# Read from HERE rather than from the tree under check, because this names the
# UPSTREAM. The repository being reconciled is a consumer, and its own manifest
# names something else entirely.
CARGO_MANIFEST = HERE / "Cargo.toml"


@functools.cache
def upstream_url() -> str:
    """The `https://host/owner/name` this repository publishes itself as."""
    try:
        manifest = tomllib.loads(CARGO_MANIFEST.read_text(encoding="utf-8"))
        url = manifest["package"]["repository"]
    except (OSError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        raise CouldNotLook(
            f"cannot read `package.repository` from {CARGO_MANIFEST}, so the "
            f"upstream this repository is cannot be named: {error}"
        ) from error
    if not isinstance(url, str) or not url.strip():
        raise CouldNotLook(f"`package.repository` in {CARGO_MANIFEST} is empty")
    return url.strip()


@functools.cache
def upstream_slug() -> str:
    """`owner/name` -- the form a consumer's runner configuration writes down."""
    parts = upstream_url().rstrip("/").removesuffix(".git").split("/")
    if len(parts) < 2 or not all(parts[-2:]):
        raise CouldNotLook(
            f"`package.repository` in {CARGO_MANIFEST} is not an owner/name URL: "
            f"{upstream_url()}"
        )
    return "/".join(parts[-2:])


@functools.cache
def lefthook_remote() -> re.Pattern[str]:
    return re.compile(rf"{re.escape(upstream_slug())}\b|hooks/lefthook\.yml")


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
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise CouldNotLook(f"{path}: {error}") from error


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise CouldNotLook(f"{path}: {error}") from error


# ---------------------------------------------------------------------------
# Reading the tiers' own configuration
# ---------------------------------------------------------------------------


def installed_hooks(root: Path) -> dict[str, list[str]]:
    """Map hook id -> the repo urls that supply it, from .pre-commit-config.yaml."""
    path = root / PRE_COMMIT_CONFIG
    if not path.is_file():
        # A repository that runs lefthook has no .pre-commit-config.yaml and is
        # not a repository this script cannot read. Treating the absent file as
        # could-not-look made every lefthook consumer exit 2 on a declaration
        # that was in fact reconcilable from the file they do have.
        if (root / LEFTHOOK_CONFIG).is_file():
            return {}
        raise CouldNotLook(
            f"neither {PRE_COMMIT_CONFIG} nor {LEFTHOOK_CONFIG} found; "
            f"cannot tell whether a hook is installed"
        )

    hooks: dict[str, list[str]] = {}
    current = ""
    saw_repo = False
    for line in read_text(path).splitlines():
        repo = REPO_LINE.match(line)
        if repo:
            current = repo.group(1)
            saw_repo = True
            continue
        hook = HOOK_ID_LINE.match(line)
        if hook and saw_repo:
            hooks.setdefault(hook.group(1), []).append(current)

    if not saw_repo:
        raise CouldNotLook(
            f"{PRE_COMMIT_CONFIG} declares no `- repo:` entries this scan can read"
        )
    return hooks


def published_hook_ids() -> set[str]:
    """Every hook id this repository publishes, from the manifest publishing them."""
    path = HERE / PUBLISHED_HOOKS
    if not path.is_file():
        raise CouldNotLook(
            f"{PUBLISHED_HOOKS} not found beside this script; "
            f"cannot tell which hook ids run `uphold`"
        )
    return {
        match.group(1)
        for line in read_text(path).splitlines()
        if (match := HOOK_ID_LINE.match(line))
    }


def runs_principles(root: Path) -> tuple[bool, str]:
    """Does this repository actually run `uphold`, and how did we tell?

    The question used to be asked as "is there a hook called `content-policy`",
    which is the name of a command in THIS repository's own lefthook.yml. No
    consumer has that name: a pre-commit consumer pins `uphold-scan`, and a
    lefthook consumer pins nothing at all and names the repository under
    `remotes:`. So the seam that supplies every guard and every content rule
    reported itself absent in every repository except this one, and every claim
    against it was refused as enforced by nothing.

    Three ways in, one per runner, and the answer says which was taken -- a
    reconcile that passes for a reason the reader cannot see is one they cannot
    check.
    """
    published = published_hook_ids()
    pinned = sorted(published & set(installed_hooks(root)))
    if pinned:
        return True, f"{PRE_COMMIT_CONFIG} pins {', '.join(pinned)}"

    path = root / LEFTHOOK_CONFIG
    if path.is_file():
        text = read_text(path)
        if any(LEFTHOOK_RUN.match(line) for line in text.splitlines()):
            return True, f"{LEFTHOOK_CONFIG} runs the binary directly"
        if lefthook_remote().search(text):
            return True, f"{LEFTHOOK_CONFIG} includes this repository as a remote"

    return (
        False,
        "no runner configuration here runs `uphold scan` or `uphold guard`",
    )


def lefthook_commands(root: Path) -> set[str]:
    path = root / LEFTHOOK_CONFIG
    if not path.is_file():
        return set()
    return {
        match.group(1)
        for line in read_text(path).splitlines()
        if (match := LEFTHOOK_COMMAND.match(line))
    }


def _rule_ids(policy: dict) -> set[str]:
    """Every rule id in one policy document.

    ONE table name, which is the whole point. This function used to walk a
    hardcoded list of six array-of-tables names against an engine that had
    seven: `language_rule` was missing, so a claim naming a language rule was
    reported as enforcing nothing while it was in fact enforced. Nothing in
    either repository could catch that -- the list was a literal here describing
    a constant there. There is no list to be short now.

    The id is the section header -- `[rule.<id>]` -- so the ids are the keys of
    one table, and a duplicate cannot even parse.
    """
    rules = policy.get("rule", {})
    if not isinstance(rules, dict):
        raise CouldNotLook("policy: [rule] must be a table of [rule.<id>] sections")
    return set(rules)


def content_policy_rules(root: Path) -> tuple[set[str], set[str], list[str]]:
    """Return (declared rule ids, disabled rule ids, inherited base sets).

    Declared INCLUDES the inherited base sets, because they ship in this
    repository now. While the base set lived in another repository at a pinned
    rev its rules ran here and could not be enumerated from here, so the count
    was reported as locally declared rules plus a note naming the hole.

    "Right there" means beside THIS SCRIPT, not beside the consumer's policy
    file. The engine embeds the bundled sets with `include_str!`, so
    `sets = ["process-residue"]` in a consuming repository resolves to a file
    that repository does not have and never will -- and resolving it against
    their tree made every consumer that inherits a base set exit 2 on a
    declaration that was in fact fine. `HERE` is the clone a runner made of
    this repository, which is where the sets the engine compiled in are.
    """
    bundled = HERE / CONTENT_POLICY_BASE
    path = root / CONTENT_POLICY
    if not path.is_file():
        raise CouldNotLook(
            f"{CONTENT_POLICY} not found; cannot tell which rules this repo runs"
        )
    policy = read_toml(path)
    inherit = policy.get("inherit", {})
    if not isinstance(inherit, dict):
        raise CouldNotLook(f"{CONTENT_POLICY}: 'inherit' must be a table")

    names = [value for value in inherit.get("sets", []) if isinstance(value, str)]

    declared = _rule_ids(policy)
    for name in names:
        base_path = bundled / f"{name}.toml"
        if not base_path.is_file():
            raise CouldNotLook(
                f"{CONTENT_POLICY}: inherit.sets names {name!r}, "
                f"which is not a bundled base set ({base_path} does not exist)"
            )
        declared |= _rule_ids(read_toml(base_path))

    disabled = {
        value for value in inherit.get("disabled_rules", []) if isinstance(value, str)
    }
    return declared, disabled, names


def cmd_shims_checks(root: Path) -> set[str]:
    """Which cmd-shims checks are enabled, or none where the seam is not in use.

    An ABSENT file is not an unreadable one, and the difference started
    mattering when `tier` went away. While a claim named its seam, a missing
    file meant a claim pointing at cmd-shims could not be judged -- fair, the
    author had said that was where to look. A claim naming only a rule is judged
    against every seam, so treating "this repository does not use cmd-shims" as
    could-not-look made every false claim in every repository without the file
    exit 2, and a reconcile that can never say `false` is not a reconcile.

    A file that exists and cannot be read still raises: that is a seam declared
    and then unreadable, which is the case `explicit-unknown` is about.
    """
    path = root / CMD_SHIMS_CHECKS
    if not path.is_file():
        return set()
    names = set()
    for line in read_text(path).splitlines():
        stripped = line.split("#", 1)[0].strip()
        if stripped:
            names.add(stripped)
    return names


# ---------------------------------------------------------------------------
# Reconciling one claim
# ---------------------------------------------------------------------------


def reconcile(
    root: Path, declaration: dict, records: dict[str, dict]
) -> tuple[list[str], list[str]]:
    """Return (failures, evidence). Raises CouldNotLook for unreadable config."""
    entries = declaration.get("enforce", [])
    if not isinstance(entries, list):
        raise CouldNotLook("`enforce` must be an array of tables")

    failures: list[str] = []
    evidence: list[str] = []
    suppliers, unreadable = rule_suppliers(root)

    for index, entry in enumerate(entries):
        where = f"enforce[{index}]"
        if not isinstance(entry, dict):
            raise CouldNotLook(f"{where} must be a table")

        if "tier" in entry:
            raise CouldNotLook(
                f"{where} carries a `tier`. The field is gone: a rule id resolves "
                f"across every seam at once, so a claim naming one no longer has "
                f"to say which. Drop the line."
            )

        principle = entry.get("principle")
        rule = entry.get("rule")
        for field, value in (("principle", principle), ("rule", rule)):
            if not isinstance(value, str) or not value.strip():
                raise CouldNotLook(f"{where}.{field} is required and must be a string")

        record = records.get(principle)
        if record is None:
            failures.append(f"{where}: unknown principle id {principle!r}")
            continue
        if record.get("status") == "deprecated":
            failures.append(
                f"{where}: {principle!r} is deprecated; the catalog keeps it for redirects only"
            )
            continue
        if record.get("enforcement", {}).get("automatable") == "no":
            failures.append(
                f'{where}: the {principle!r} record says enforcement.automatable = "no"; '
                f"no rule can be claimed to enforce it"
            )
            continue

        held = suppliers.get(rule, [])
        if held:
            evidence.append(f"{principle} <- {rule}  enforced by {', '.join(held)}")
            continue

        if unreadable:
            # A rule absent from what could be read is not an absent rule. The
            # tiers that could not be inspected are exactly where it might be,
            # so this is could-not-look and not a false claim -- see the
            # `explicit-unknown` record.
            raise CouldNotLook(
                f"{where}: no rule {rule!r} in what could be read, and "
                f"{', '.join(unreadable)} could not be read; cannot tell whether "
                f"the claim holds"
            )

        failures.append(
            f"{where}: {principle!r} claims {rule!r}, which no seam here supplies"
        )

    return failures, evidence


# ---------------------------------------------------------------------------
# Coverage: the denominator the reconcile cannot see
# ---------------------------------------------------------------------------
#
# The reconcile walks the declaration, so its entire universe is what somebody
# already claimed. A rule that fires under no claim is invisible to it, and so is
# a record nothing here enforces -- while "reconciled 7 enforcement claims" reads
# like coverage and is not. This mode counts the other direction: every rule the
# four tiers actually run in this repository, against the claims that name one.
#
# It reports and does not refuse. An unclaimed rule is not a defect -- the
# mapping from a rule to the principle behind it is a human judgment, and a mode
# that exited 1 over a missing one would buy its own green by pushing people to
# write claims they do not believe, which is the declaration becoming decoration.
# Exit 2 stays, because a tier whose configuration could not be read is a hole in
# the denominator rather than a tier running nothing; see `explicit-unknown`.


class Inventory:
    """What one tier actually runs here, and what could not be seen of it."""

    __slots__ = ("notes", "rules", "unreadable")

    def __init__(
        self,
        rules: set[str] | None = None,
        notes: list[str] | None = None,
        unreadable: bool = False,
    ) -> None:
        self.rules = rules if rules is not None else set()
        self.notes = notes if notes is not None else []
        self.unreadable = unreadable


def inventory_principles(root: Path) -> Inventory:
    notes: list[str] = []
    try:
        in_use, how = runs_principles(root)
    except CouldNotLook as error:
        return Inventory(notes=[str(error)], unreadable=True)
    if not in_use:
        return Inventory(notes=[how])
    notes.append(how)

    try:
        declared, disabled, inherited = content_policy_rules(root)
    except CouldNotLook as error:
        return Inventory(notes=[str(error)], unreadable=True)
    if inherited:
        # This tier used to be the one hole in the coverage report: the base set
        # lived in another repository at a pinned rev, its rules ran here, and
        # they could not be enumerated from here. They ship in this repository
        # now, so the count is whole and says which sets it counted.
        notes.append(f"includes the bundled base set(s): {', '.join(inherited)}")
    if disabled:
        notes.append(f"extend.disabled_rules turns off {', '.join(sorted(disabled))}")
    return Inventory(rules=declared - disabled, notes=notes)


def inventory_cmd_shims(root: Path) -> Inventory:
    try:
        return Inventory(rules=cmd_shims_checks(root))
    except CouldNotLook as error:
        return Inventory(notes=[str(error)], unreadable=True)


def inventory_local(root: Path) -> Inventory:
    """Everything `tier = "local"` could name: this repo's hooks and commands.

    Wider than `- repo: local`, because a formatter or a linter from a
    third-party repository is a rule that fires here and can be claimed as one.
    """
    notes: list[str] = []
    unreadable = False
    rules: set[str] = set()
    try:
        hooks = installed_hooks(root)
    except CouldNotLook as error:
        notes.append(str(error))
        unreadable = True
    else:
        rules |= set(hooks)
    commands = lefthook_commands(root)
    if commands:
        notes.append(f"{LEFTHOOK_CONFIG} defines {len(commands)} command(s)")
    return Inventory(rules=rules | commands, notes=notes, unreadable=unreadable)


INVENTORIES = {
    "uphold": inventory_principles,
    "cmd-shims": inventory_cmd_shims,
    "local": inventory_local,
}


def rule_suppliers(root: Path) -> tuple[dict[str, list[str]], list[str]]:
    """Every rule id this repository runs, and every seam that supplies it.

    A MULTIMAP, and that is the whole design. One rule enforced by more than one
    tool is the normal case, not a collision to refuse: `prevent-ai-author` is a
    commit-msg hook in git-guards AND a checker in cmd-shims, because a commit
    message and a pull-request body are two paths to the same public place and
    each needs its own mediation. `complete-mediation` is the record that says
    so. A structure holding one supplier per id would have had to pick one of
    them and call the other a duplicate, which is the opposite of what the two
    entries mean.

    This is also what retired `tier` from a claim. The field existed because
    `rule` resolved in a different namespace per tier and something had to say
    which; a claim resolves against every seam at once now, and a rule with two
    suppliers reports both rather than making the author choose.

    Returns the map and the seams that could not be read -- named rather than
    folded in, because a rule absent from what could be read is not an absent
    rule.
    """
    suppliers: dict[str, list[str]] = {}
    unreadable: list[str] = []
    for tier in TIERS:
        inventory = INVENTORIES[tier](root)
        if inventory.unreadable:
            unreadable.append(tier)
        for rule in sorted(inventory.rules):
            suppliers.setdefault(rule, []).append(tier)
    return suppliers, unreadable


def declared_claims(declaration: dict) -> list[tuple[str, str]]:
    """Return (principle, rule) per entry, without judging either of them."""
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


def format_coverage(
    root: Path, declaration: dict, records: dict[str, dict]
) -> tuple[list[str], int]:
    claims = declared_claims(declaration)
    lines = [f"coverage in {root}"]
    status = 0

    # rule -> every principle claiming it. A list rather than a single value:
    # two principles may rest on one rule, and a dict keyed by rule would have
    # kept whichever claim was written last and silently dropped the other.
    claimed: dict[str, list[str]] = {}
    for principle, rule in claims:
        claimed.setdefault(rule, []).append(principle)

    supplied: set[str] = set()
    for tier in TIERS:
        inventory = INVENTORIES[tier](root)
        supplied |= inventory.rules
        held = sorted(rule for rule in inventory.rules if rule in claimed)
        unclaimed = sorted(inventory.rules - set(claimed))

        seen = "?" if inventory.unreadable else str(len(inventory.rules))
        lines.append("")
        lines.append(f"{tier}: {len(held)} of {seen} rules carry a principle")
        for rule in held:
            lines.append(f"  claimed    {rule} -> {', '.join(claimed[rule])}")
        if unclaimed:
            lines.append(f"  unclaimed  {', '.join(unclaimed)}")
        for note in inventory.notes:
            lines.append(f"  note       {note}")
        if inventory.unreadable:
            status = 2

    # A claim naming a rule no seam supplies is a repository-level fact, not a
    # per-seam one: without `tier` there is no seam it was pointing at to be
    # missing from. Reported once, and reported here because a claim pointing at
    # nothing inflates the numerator of any coverage read off this.
    orphans = sorted(rule for rule in claimed if rule not in supplied)
    if orphans:
        lines.append("")
        for rule in orphans:
            lines.append(
                f"claimed but supplied by nothing here: {rule} -> "
                f"{', '.join(claimed[rule])}"
            )

    claimable = {
        record_id: record
        for record_id, record in records.items()
        if record.get("status") != "deprecated"
        and record.get("enforcement", {}).get("automatable") != "no"
    }
    enforced = {principle for principle, _ in claims} & set(claimable)
    unclaimable = len(records) - len(claimable)
    lines.append("")
    lines.append(
        f"records: {len(enforced)} of {len(claimable)} claimable records are "
        f"claimed by a rule here"
    )
    if unclaimable:
        lines.append(
            f"  {unclaimable} record(s) are deprecated or declare "
            f'enforcement.automatable = "no" and can never be claimed'
        )
    lines.append(
        "  an unclaimed record is not a gap to close by writing a claim: a claim "
        "without a rule behind it is the failure `enforcement-needs-a-trigger` names"
    )
    return lines, status


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
    suppliers, _ = rule_suppliers(root)
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
    return {
        "max_lines": int(settings.get("max_lines", review_mod.DEFAULT_MAX_LINES)),
        "include_domains": list(settings.get("include_domains", [])),
        "emit": list(settings.get("emit", ["REVIEW.md"])),
        "exempt": exempt,
    }


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
        claims = declared_claims(declaration)
        suppliers, _ = rule_suppliers(root)
    except CouldNotLook as error:
        print(f"uphold review could not look: {error}", file=sys.stderr)
        return 2

    records = load_records()
    claimed = {principle for principle, _ in claims}
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
        for name in settings["emit"]:
            (root / name).write_text(document, encoding="utf-8")
            print(f"wrote {name} ({len(document.splitlines())} lines)")
        return 0

    if check:
        for name in settings["emit"]:
            path = root / name
            current = path.read_text(encoding="utf-8") if path.is_file() else ""
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

    oscal_mode = argv[:1] == ["--oscal"]
    if argv[:1] == ["--review"]:
        return run_review(argv[1:])

    coverage_mode = argv[:1] == ["--coverage"]
    if argv and not (oscal_mode or coverage_mode):
        print(
            "usage: uphold_check.py "
            "[--explain ID|NAME | --list | --init | --oscal | --coverage "
            "| --self-check]",
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
        # Before the reconcile, not after: coverage is a report over the
        # configuration, and a declaration with one false claim in it is exactly
        # when a reader wants to see what else is there.
        if coverage_mode:
            lines, status = format_coverage(root, declaration, records)
            print("\n".join(lines))
            return status
        failures, evidence = reconcile(root, declaration, records)
    except CouldNotLook as error:
        print(f"uphold check could not look: {error}", file=sys.stderr)
        return 2

    if failures:
        print(f"enforcement claims refused ({declaration_path}):", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    # The export runs the reconcile first and only emits what held. A component
    # definition is a claim to an outside reader; exporting an unreconciled one
    # would publish an assertion this tool had just been unable to confirm.
    if oscal_mode:
        print(json.dumps(build_oscal(root, declaration, records), indent=2))
        return 0

    print(f"reconciled {len(evidence)} enforcement claims:")
    for line in evidence:
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
