# Principle record schema

Each `principles/*.toml` file other than this document is one canonical record.
File name and `id` must match.

## Required top-level fields

| field | type | purpose |
|---|---|---|
| `id` | string | stable kebab-case identifier |
| `title` | string | human-readable canonical name |
| `aliases` | string array | common alternative names |
| `kind` | enum | epistemic category — see below |
| `status` | enum | `seed`, `reviewed`, or `deprecated` |
| `domains` | enum array | where the entry is used — see below |
| `summary` | string | quick-reference sentence |
| `claim` | string | strongest concise formulation |
| `problem` | string | recurring failure or decision addressed |
| `rationale` | string | causal or structural reason the principle helps |
| `applies_when` | string array | scope conditions |
| `does_not_mean` | string array | common category errors and overextensions |
| `benefits` | string array | expected gains |
| `costs` | string array | trade-offs and new risks |
| `failure_when_overapplied` | string array | predictable misuse |
| `conflicts_with` | string array | record ids in tension with this one; symmetric |
| `related` | string array | record ids worth reading next; one-directional |
| `review_questions` | string array | questions for design or code review |

## Optional fields

`enforcement.rung` and `[[tools]]` may be omitted; each is described below. No
other field is accepted: a top-level, `[enforcement]`, `[[sources]]` or
`[[tools]]` key this document does not name fails validation, so a misspelled
field is refused rather than read as an absent one.

## Kind

Entries are classified by epistemic kind rather than all being called
principles. `kind` says what the entry is; `domains` says where it is used, and
`enforcement.rung` says how a check sees it. The list is closed: a kind outside
it fails validation.

| kind | meaning |
|---|---|
| `law` | a descriptive relationship that holds under stated assumptions |
| `theorem` | a formally established result or impossibility |
| `principle` | normative design guidance |
| `heuristic` | a defeasible rule of thumb |
| `philosophy` | a coherent design stance |
| `pattern` | a recurring solution structure |
| `anti-pattern` | a recurring structure with predictable failure modes |
| `tactic` | a concrete mechanism that changes a quality attribute |
| `practice` | a repeatable engineering activity |
| `method` | a systematic procedure for analysis, construction or verification |
| `model` | an abstraction used to reason about a system |
| `property` | a characteristic that can be stated or checked |
| `representation` | a structured form encoding program or system information |
| `metric` | a quantified measure |
| `decision-procedure` | an algorithmic procedure deciding a formal problem |

## Domains

`domains` says where an entry is used, as the technical areas it bears on. The
list is closed: each value is one of these, the list is non-empty, and no value
repeats. `uphold_check.py --review` refuses a `[review].include_domains` value
outside it with exit 2, since a filter no record can match would compile an
empty review document. `DOMAINS` in `scripts/validate.py` holds the same table,
and a test holds the two equal.

| domain | meaning |
|---|---|
| `architecture` | structure and modularity of a system |
| `interfaces` | APIs, protocols and contracts between parts |
| `distributed-systems` | many nodes, partial failure and coordination |
| `reliability` | keeping a service correct and available in operation |
| `security` | confidentiality, integrity, authorization and privacy |
| `data` | state, storage, consistency and derived artifacts |
| `program-representation` | syntax trees, IRs and graphs a tool reads |
| `compiler-semantics` | what a language definition and its compiler establish |
| `static-analysis` | facts derived about a program without running it |
| `formal-verification` | proof that a program meets a specification |
| `symbolic-reasoning` | execution over symbolic rather than concrete values |
| `model-checking` | exhaustive exploration of a state space |
| `constraint-solving` | SAT, SMT and related decision procedures |
| `testing` | executable checks and fuzzing |
| `runtime-analysis` | instrumentation and monitoring of a running program |
| `concurrency` | interleaving, ordering and shared state |
| `performance` | latency, throughput and scalability |
| `socio-technical` | people, teams, incentives and organizations |
| `evolution` | change, versioning, migration and deprecation |
| `ai-harness` | agents, shims and hooks that act for a person |

## Relationships

`conflicts_with` is symmetric: a tension between two records has two ends, so
if A lists B, B lists A, and validation refuses a conflict written on one side
only. `related` is one-directional: A pointing a reader at B does not oblige B
to point back. One id may not appear in both lists of the same record; a pair
in tension is kept in `conflicts_with`.

## Status

- `seed`: useful initial record; needs further source review or field experience.
- `reviewed`: scope and sources have been deliberately reviewed.
- `deprecated`: retained for redirects or historical explanation, not recommended.

## Enforcement table

```toml
[enforcement]
level = "lint"
automatable = "partially"
observable = ["...things a tool can inspect..."]
checks = ["...candidate checks..."]
limits = ["...what cannot safely be inferred..."]
rung = ["text", "syntax"]  # optional
```

`level` says where a rule *could* live, not that the record's prose may be
shipped to that tier.

| level | meaning |
|---|---|
| `informational` | review and learning only |
| `review` | prompts or checklists for a human or agent reviewer |
| `lint` | static checks over source, config, schemas, or repository structure |
| `test` | executable behavior or property tests |
| `runtime` | controls enforced during execution |
| `governance` | ownership, approval, traceability, or decision controls |

Allowed `automatable` values: `no`, `partially`, `yes`. An entry may be only
partially automatable; the record must then say what the machine can observe and
what remains a judgment.

`rung` is optional and says at which rungs of the observation ladder a check
can see what `observable` lists. The rungs are defined in
[`docs/COVERAGE.md`](../docs/COVERAGE.md#rungs):

| rung | what a check reads |
|---|---|
| `text` | the bytes, by regex |
| `syntax` | the parse tree |
| `semantic` | what a compiler or linter resolves |
| `proof` | what a verifier establishes over a stated core |

When present, `rung` is a non-empty list, in ladder order, with no repeats. A
record whose `automatable` is `no` carries no `rung`: nothing a machine can
decide has no rung to be seen at. Like the rest of the table, `rung` is design
input for whoever builds the check; no engine reads it.

## Sources

At least one source is required. A source is a pointer, not an endorsement that
the source states the record exactly as written.

```toml
[[sources]]
title = "Information Distribution Aspects of Design Methodology"
url = "https://doi.org/..."
type = "paper"
notes = "Foundational articulation of information hiding."
```

Allowed source types are currently free-form but should normally be one of:
`standard`, `paper`, `book`, `essay`, `documentation`, or `practice`.

## Tools

Optional. A tool is an example of something that observes or operationalizes
the concept; the concept is the record, and the tool is illustrative. Omit the
table when no mature tool operationalizes the concept.

```toml
[[tools]]
name = "ast-grep"
url = "https://ast-grep.github.io/"
notes = "Structural search over the parse tree; one way to observe the syntax rung."
```

`name`, `url` and `notes` are each required and are the only keys; `url` is
HTTP(S). A tool's name may not be a record's title or alias under the name
index's lookup key, so a search for the concept never answers with the product.

## Scope: a gate uphold does not ship

A record that needs a gate uphold does not ship is observed by a
consumer-owned external gate: the compiler, linter or verifier the consumer
imports into its own hook config and claims in its `policy/upheld.toml`. uphold
ships the pointer, in `[[tools]]` and in
[`docs/COVERAGE.md`](../docs/COVERAGE.md), not a wrapper around the tool.

## Compatibility rules

- IDs are stable API. Rename by deprecating the old record and adding the new one.
- Generated documents must never become the canonical source.
- Enforcement tools must consume the record rather than reinterpret its meaning.
- A checker must fail explicitly when it cannot observe the fact it claims to check.
- Relationship fields use record IDs, not display names.
