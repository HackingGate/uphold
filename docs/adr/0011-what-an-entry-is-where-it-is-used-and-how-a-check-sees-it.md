# ADR 0011: what an entry is, where it is used, and how a check sees it

Status: Accepted

The catalog asks three questions of every record, and each needs its own
answer: what the entry is, where it is used, and how a check could see it. A
single `kind` field cannot carry all three. With eight kinds, one of them
(`socio-technical-law`) named a domain, and an entry such as a type system, a
model checker or a coverage metric had no kind that said what it was.

This record fixes the three fields, the vocabulary each is drawn from, the rule
for the two relationship fields, and why no wrapper around a consumer's tool
ships from here.

## Decisions

- **`kind` says what the entry is, from a closed list of fifteen:** `law`,
  `theorem`, `principle`, `heuristic`, `philosophy`, `pattern`,
  `anti-pattern`, `tactic`, `practice`, `method`, `model`, `property`,
  `representation`, `metric`, `decision-procedure`. Each is an epistemic
  category: a law describes, a principle prescribes, a theorem is proved, a
  metric measures. `socio-technical-law` is not a kind; "socio-technical" is
  where a law applies, which is `domains`. A kind outside the list fails
  validation. [`principles/SCHEMA.md`](../../principles/SCHEMA.md) gives each
  kind's meaning, and a test holds its table equal to the validator's set.
- **`domains` says where the entry is used, from a closed list of twenty
  technical areas** in [`principles/SCHEMA.md`](../../principles/SCHEMA.md#domains),
  held equal to `DOMAINS` in `scripts/validate.py` by a test. A record's list is
  non-empty with no repeats, and a value outside the list fails validation. A
  `[review].include_domains` filter naming any other value exits 2, since a
  filter no record can match would compile an empty review document.
- **`enforcement.rung` says how a check sees the entry:** at which rungs of
  the ladder in [`docs/COVERAGE.md`](../COVERAGE.md#rungs) (`text`, `syntax`,
  `semantic`, `proof`) what `observable` lists can be read. It is optional,
  written in ladder order with no repeats, and refused on a record whose
  `automatable` is `no`.
- **`[[tools]]` names illustrative tools.** Optional, with `name`, `url` and
  `notes` only. A tool's name may not be a record's name under the index's
  lookup key: the concept is the record, and the tool is one example of
  something that observes it.
- **A field the schema does not name is refused**, at the top level and inside
  `[enforcement]`, `[[sources]]` and `[[tools]]`.

## Precedent: two questions wearing one name

[`src/config/rule.rs`](../../src/config/rule.rs) records the same split for a
rule: one discriminant answered what a rule checks and where it runs, and the
file now carries each answer in the field the evaluator reads (`regexp`,
`max_lines`, `builtin` for what; `files`, `git`, `command` for where). The
catalog's `kind` had the same fault, and this change applies the same remedy:
one question per field, so a value cannot be right for one question and wrong
for the other without anyone noticing.

## Why `rung` lives on the record, though no engine reads it

The engine reads a record's `id`, `status` and `enforcement.automatable`, and
nothing else. `rung` is not read by it either, and that is by design: like
`observable`, `checks` and `limits`, it is design input for whoever builds the
check, and it is shown to them by `uphold_check.py --explain` and in
`QUICK_REFERENCE.md`. It sits beside `observable` because the two answer one
question together: what a tool can inspect, and at what depth it has to read
to inspect it.

What holds the field honest is the validator, not a reader: `RUNGS` in
[`scripts/validate.py`](../../scripts/validate.py) is the vocabulary, in
ladder order, and a test holds the schema document's rung table equal to it.
A record that writes `rung = ["syntax", "text"]` or a rung the ladder does not
have fails validation, so the field cannot drift into prose.

## Why `related` is directional and `conflicts_with` symmetric

A conflict is one fact with two ends. If A trades against B, a reader of B is
owed the warning as much as a reader of A, and a conflict written on one side
only is a trade-off one reader is never shown. So validation refuses a
`conflicts_with` entry the other record does not repeat, and names both ids.

`related` is "read this next". A pointer from A to B does not oblige B to point
back, and requiring it would fill every record with back-references a reader
of it has no use for. It stays one-directional.

An id in both lists of one record says the pair is in tension and merely
adjacent at once. Validation refuses it; the pair belongs in `conflicts_with`.

Bringing the catalog to this rule moved three reverse edges from `related` to
`conflicts_with`, removed one id held in both lists, and added four missing
reverse conflicts. No conflict was dropped.

## Why no wrapper rules

A record whose check needs a compiler, linter or verifier is observed by a
consumer-owned external gate: the consumer imports the tool into its own hook
config and claims the record in its `policy/upheld.toml`. uphold ships the
pointer, in `[[tools]]` and in `docs/COVERAGE.md`, and no rule that runs the
tool. `docs/COVERAGE.md` states why: one tool per job, and a wrapper of the
consumer's toolchain shipped from here would be a second copy of the
consumer's gate, coupled to an uphold release.

## What this changes today

- A record with a kind outside the fifteen, a domain outside the twenty, a
  field the schema does not name, or a one-sided conflict cannot be committed.
- `QUICK_REFERENCE.md` groups every record by kind and by domain, and shows a
  record's rungs beside its enforcement level when it states them.
- `uphold_check.py --explain` prints a record's rungs and tools when it has
  them, with the tools headed as illustrative.
- No record states a rung or a tool yet. Adding them is a content change,
  record by record, with a source for each claim.
