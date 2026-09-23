# Roadmap

## Catalog

- Promote seed entries to reviewed status after source and field review; every
  record is `seed`.
- State `enforcement.rung` on the machine-observable records that predate the
  field, so the by-rung index in `QUICK_REFERENCE.md` covers the whole catalog.
- Add review controls: one record carries a control, and the run names every
  review-carried record that has none.
- Fill the kinds no record uses yet only with candidates a rule can hold; a
  method, representation or metric belongs in the coverage page's rung glossary
  unless a consumer can claim it.
- Add examples from public HackingGate repositories without exposing private
  organization names or implementation details.

## Enforcement tool

`uphold check` reconciles a repository's `[[enforce]]` claims against the
catalog and against every seam the repository runs; `--coverage` reports the
other direction. Both are described in [REFERENCE](docs/REFERENCE.md) and
[DESIGN](docs/DESIGN.md#coverage-is-not-the-reconcile).

Open:

- **Ask a local provider whether a claimed id exists.** The reconciler reads
  this repository's configuration only. Rules from `policy/principles.toml` and
  from bundled sets are enumerable, but a third-party hook is counted as
  installed by its hook id, and the claim is taken at its word for what that id
  enforces. A provider whose configuration is local and readable (`deny.toml`,
  an `ast-grep` rule directory, a `zizmor.yml`, a `repo: local` hook, a lefthook
  command) can be asked whether the id is defined in it. That does not establish
  what the id means; `uphold probe` does, by driving it to a refusal. See
  [ADR 0005](docs/adr/0005-what-a-provider-must-answer.md).
- **Detect that an installed rule never fires.** A rule that cannot match is
  effectively disabled, and no config file shows it. This needs firing counts
  from the tiers themselves, and a way to tell a clean tree from a dead rule.
  See `enforcement-needs-a-trigger`, which states the same limit.

Not planned:

- **Compiling `enforcement.checks` into checks.** Those fields are English
  written for a person. Compiling them would create a second statement of the
  rule in the same record, free to disagree with the first. A rule is written
  once, in the tier that can observe the property, and then claimed.
- **Adopting OSCAL wholesale.** `--oscal` exports the mapping. The catalog
  stays TOML because an OSCAL control cannot hold a scope condition, a cost, a
  conflict or `automatable = "no"`, and a private `prop` holding them would be
  the same private format under another name. Revisit if OSCAL adds a place for
  them.
- **Shared profiles.** An earlier `profiles/*.toml` was removed: which rule
  enforces a principle is specific to one repository, so a shared profile could
  carry only principle ids with no rule behind them.

## Fleet adoption of bundled sets

The guard-carrying sets have shipped, along with the safeguards that had to
precede them: `no-hand-copied-base-rule`, the stage and command ceilings
(`[set] stages`, `[set] commands`), `policy/base/sets.lock.json`, and set
provenance in refusal output. The remaining work is per repository.

- **Delete hand-copied base rules.** A sweep of 77 repositories found roughly
  forty with at least one transcription of a bundled rule, none of them ever
  reported, because nothing ran the manual stage. `no-hand-copied-base-rule`
  now refuses a newly added copy at `pre-commit`; existing copies are removed
  repository by repository. The clearest case: no repository inherits
  `captured-fixtures`, and seventeen transcribe its one rule.
- **Adopt `host-identity`.** The bundled rule scans `["."]`, while all
  twenty-nine hand copies scan a strict subset that skips vendored trees,
  `target/` and test corpora. Adopting it widens what is scanned, so it is done
  per repository rather than as a fleet sweep.

## Evidence providers, and what issue 165 leaves open

The evidence layer ([ADR 0008](docs/adr/0008-evidence-and-what-a-policy-may-consume.md))
ships with three compiled-in providers (Git over the message, tree-sitter over
the staged trees, a pattern over the staged diff) and one policy,
`removed-function-named`, that reads them. Not yet shipped:

- **A compiler or LSP provider.** `symbol_defined`, `unresolved_reference` and
  `type_changed` are kinds the issue names and nothing reports; a kind with no
  provider would be dead configuration. ADR 0004 measured what the semantic tier
  costs before a commit, so such a provider belongs at the manual stage or
  nowhere.
- **`dependency_edge` and layer kinds.** The architectural-boundary policy the
  issue sketches needs a provider that resolves imports across modules, the
  same tier as above.
- **An `Inferred` provider.** The variant exists and is tested with a double;
  no provider produces it. Its seam is `uphold hook`, where an agent's own
  account of a change is already read. Whatever it reports is `Inferred` by
  construction: it refuses nothing at a blocking stage and overrides nothing a
  parser reported.
- **A second policy.** The next policy written against the evidence layer will
  show whether the schema generalizes beyond the first.
