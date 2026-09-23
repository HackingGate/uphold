# ADR 0009: a consumer's structural rules are ast-grep's, run from the consumer's own config

Status: Accepted

This record answers a question [ADR 0003](0003-the-structural-tier-and-what-a-clean-run-means.md)
already answered, asked again on one of its two grounds. The proposal was a
fifth pattern check in this binary: a `query` field holding a tree-sitter
query, with the parse-failure refusal the evidence provider already carries.
The argument for it was that `ast-grep` leaves the parse-failure rule to each
adopter, where this binary could refuse a recovered tree once for the fleet.

ADR 0003 stands. A consumer's structural rules are `ast-grep`'s job, and the
consumer runs `ast-grep` from its own hook configuration. uphold ships no query
form and no wrapper around `ast-grep`.

## What ast-grep does, probed

Measured on `ast-grep` 0.45.3.

**The rules the proposal named are expressible today.** "`$X.unwrap()` not
inside a `mod_item` that follows a `cfg(test)` attribute" and "an
`unsafe_block` whose preceding sibling is not a `SAFETY:` comment" are each a
few lines of relational rule (`inside`, `follows`, `stopBy`). Against a fixture
with one case of each on either side of the line, each rule reported the one it
should and exited 1.

**The rule body is strict.** A misspelled key inside `rule:` (`insde:`), an
unknown key inside a constraint, a constraint on an undefined metavariable, a
misspelled `kind:` and a misspelled `severity:` value are each refused at load,
exit 8, naming the field. A raw tree-sitter query is not: tree-sitter 0.27
applies six predicates itself and silently ignores any other, so an in-house
`query` rule with a misspelled predicate matches more than it says. Building
the query form would have meant building the predicate allow-list too, which is
a second rule engine in a binary whose rule engine is regex.

**Three edges answer "nothing to report" where the answer is "did not look".**

- *A file that only partly parsed.* `ast-grep scan` matches inside the tree the
  grammar recovered and exits by what it matched. The companion rule ADR 0003
  and ADR 0005 name, `kind: ERROR`, catches recovery that produced an ERROR
  node. It does not catch recovery that only inserted a MISSING node: for
  `fn broken( {`, tree-sitter-rust inserts the `)` and produces no ERROR node,
  and a `kind: ERROR` rule over that file exits 0. There is no `kind` for a
  MISSING node, and a rule with no `kind` is refused at load.
- *Severity.* A rule with no `severity` is a `hint`. Its findings print and the
  exit is 0, so a rule that forgets `severity: error` is a gate that cannot
  fail.
- *Top-level keys.* An unknown key at the top level of a rule, or of
  `sgconfig.yml`, is dropped without a word. `constraint:` for `constraints:`
  runs the rule without its constraint. `ruleDir:` for `ruleDirs:` runs no rule
  at all, and a project with no rule exits 0.

## Decisions

**No query form in this binary.** The example rules do not need one, and the
rule body a consumer would write here is looser than the one `ast-grep` already
checks.

**No wrapper either.** A wrapper that re-parsed every file `ast-grep` applied a
rule to, forced `--error`, and refused unknown keys was prototyped and dropped.
One tool per job: a consumer wires `ast-grep` into its own hook config the way
it wires its compiler and linter, and a copy run from uphold is a second gate
coupled to an uphold release. That is the argument that deprecated the four Go
toolchain ids, and it would be inconsistent to retire those and add this.

**The three edges are stated where an adopter reads them.** The syntax row of
[`docs/COVERAGE.md`](../COVERAGE.md) is a consumer-owned external gate for every
language, and that page carries the hook entry, the companion rule, the
`severity: error` requirement and the two gaps no rule closes. The MISSING-node
gap has a backstop one rung up, which is the reason it is tolerable: a file the
grammar had to repair is a file the compiler or linter refuses (rustc and
`go vet` do not build it, and ruff reports it as a syntax error), so the
semantic rung, at push or at commit depending on the tool, refuses what the
syntax rung let through.

**ADR 0005's pairing requirement stands, with its limit named.** A structural
provider's clean exit is evidence only when a parse-failure rule runs beside
it. For `ast-grep`, the pairing is the `kind: ERROR` rule, and it covers ERROR
recovery only. The rest is the semantic rung's.

## What this changes today

Nothing in the binary. The coverage page gains the syntax row's owner and the
adopter's checklist, and points the four example rules the per-language
follow-up proposed at the stock linter rules that already carry them.
