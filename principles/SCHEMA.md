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
| `domains` | string array | areas in which the entry is useful |
| `summary` | string | quick-reference sentence |
| `claim` | string | strongest concise formulation |
| `problem` | string | recurring failure or decision addressed |
| `rationale` | string | causal or structural reason the principle helps |
| `applies_when` | string array | scope conditions |
| `does_not_mean` | string array | common category errors and overextensions |
| `benefits` | string array | expected gains |
| `costs` | string array | trade-offs and new risks |
| `failure_when_overapplied` | string array | predictable misuse |
| `conflicts_with` | string array | opposing objectives or principles, by id where possible |
| `related` | string array | related record ids |
| `review_questions` | string array | questions for design or code review |

## Kind

Entries are classified by epistemic kind rather than all being called principles.

| kind | meaning |
|---|---|
| `law` | a structural, mathematical, or physical constraint under stated assumptions |
| `principle` | defeasible normative guidance |
| `heuristic` | compressed judgment useful in recurring situations |
| `philosophy` | a coherent design stance, often containing several principles |
| `tactic` | a concrete mechanism used to change a quality attribute |
| `pattern` | a reusable arrangement for a recurring problem |
| `socio-technical-law` | a recurring organizational or incentive effect |
| `anti-pattern` | a recurring structure associated with predictable harm |

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

## Compatibility rules

- IDs are stable API. Rename by deprecating the old record and adding the new one.
- Generated documents must never become the canonical source.
- Enforcement tools must consume the record rather than reinterpret its meaning.
- A checker must fail explicitly when it cannot observe the fact it claims to check.
- Relationship fields use record IDs, not display names.
