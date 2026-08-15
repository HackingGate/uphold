# ADR 0003: the structural tier, and what a clean run from it means

Status: Accepted

This record answers two questions asked of the structural tier: whether rules
over a syntax tree should be written here or delegated to `ast-grep`, and what a
structural rule reporting nothing is entitled to claim.

The subject is one rule, already carried in this repository:
[`tests/structural_git_env.rs`](../../tests/structural_git_env.rs) refuses a
`Command::new` in `src/probe.rs` that does not go through the helper stripping
git's environment. It is small, it is real, and both implementations of it can
be read side by side.

## The same rule, in the two places it could live

`ast-grep` states it in thirteen lines, over the same grammar this binary
already links:

```yaml
id: git-command-inherits-environment
language: rust
severity: error
message: builds a command without going through `detached`
rule:
  pattern: Command::new($ARG)
  not:
    inside:
      kind: function_item
      has:
        field: name
        regex: '^detached$'
      stopBy: end
```

Handed the fixture with the defect in it, that is the whole of the work:

```text
error[git-command-inherits-environment]: builds a command without going through `detached`
  ┌─ offending.rs:8:13
  │
8 │     let _ = Command::new("git").arg("worktree").current_dir(root).output();
  │             ^^^^^^^^^^^^^^^^^^^
```

The Rust in this repository spends about thirty-five lines on the same match --
a walk that collects call expressions, and a walk upward that names the
enclosing function -- and the rest of the file on a docstring, a negative
control, and two assertions `ast-grep` cannot make. The line count is the least
interesting of the differences.

## What delegating buys

**Diagnostics, at no cost.** The span, the line, the column, the rule id and the
severity are what a matcher produces anyway. The hand-written check produces an
assertion message, and the file and line in it are whatever the author
remembered to format into the string.

**A second language costs a rule rather than an implementation.** The same
property in Python -- a `subprocess` call whose argv begins with `git` and which
passes no `env=` -- is twenty-three lines in the same schema, and one consuming
repository states it in 492 lines of hand-written Python. That is the strongest
argument in the tier's favour and it should be said plainly.

**But it is one rule per grammar, not one rule across grammars.** Every
`ast-grep` rule names its `language:` and matches that grammar's node kinds. The
two rules above share a vocabulary and share nothing else; the property they
have in common lives in their two ids being spelled alike. So the answer to
"can one rule target equivalent constructs across several grammars" is no, and
the consolation is real: N rules in one schema, reviewed together, beats N
implementations in N languages.

## What delegating does not buy, and this is the decision

**A matcher fires on what is there. It cannot require what must be there.**
Beyond the forbidden shape, the check in this repository asserts that the helper
still calls `env_remove` and still names all eight of the variables git exports,
read out of `detached`'s own body rather than out of the file. That is a rule
about a construct that MUST exist, and a rule engine whose output is a list of
matched nodes has no way to say it: the absence of a node is not a node. This
repository already carries the same distinction one tier down, where `regexp`
refuses a file that matches and `require_regexp` refuses a file that does not. A
structural tier without the second direction can watch the calls and cannot
watch the helper they are required to go through -- which is the half that goes
quietly wrong.

Reading it off the body rather than off the file is not a detail. A
`source.contains("\"GIT_DIR\"")` is satisfied by a comment, by a message string,
and by any other function in the module; scoped to the helper, it is satisfied
only by the helper. What it still does not prove is which name reaches which
call, because `detached` hands `env_remove` a loop variable -- and following a
value into a loop is the tier above a syntax tree, which is the next section.

**A clean run means nothing on its own.** tree-sitter recovers a tree from
almost any input, so a source whose parse collapsed produces a walk that finds
nothing, which is byte-identical to the report from a source that complies.
Measured, with an unterminated string literal three lines above the defect:

```text
$ ast-grep scan -r rule.yml swallowed.rs ; echo $?
0
```

Exit 0, no output, and the `Command::new("git")` the rule exists to catch is
sitting in the file. The state is recoverable -- a second rule matching
`kind: ERROR` reports the region the grammar could not read -- but it is a
second rule, it is per adopter, and nothing anywhere requires it. A tool whose
default answer to "I could not look" is the same as its answer to "nothing to
report" is the `UNKNOWN -> PASS` shape this repository keeps finding one seam at
a time, and it is the single most useful thing this evaluation produced.

The rule here now refuses a source it could not parse, and its fixtures are two
sources one character apart with opposite verdicts.

## Decisions

**Do not adopt `ast-grep` for this rule.** Not on merit -- on duplication. The
rule already runs here, and a second checker over one answer is two answers free
to disagree. This repository has run that experiment: a Python script asking
whether a pin resolved beside a guard asking whether it was stale, and the guard
counted a pin it could not reach as passed.

**Do not build a rule DSL over tree-sitter in this binary.** Nothing in the
comparison above argues for it. A structural rule this repository needs is
cheaper as a test beside the code it constrains, and a structural rule a
consumer needs is `ast-grep`'s job, not this tool's.

**`ast-grep` is adoptable as a provider, and needs no new mechanism to be.** Its
rule ids are claimable through the local tier today, in the same way a
formatter's hook id is -- and with the same limit, which is that this tool takes
the claim's word for what the id enforces. `deny.toml` and a `zizmor` policy
land in the same place.

**A structural provider carries one requirement the others do not.** Its clean
exit is evidence only when a parse-failure rule runs beside it. That belongs in
the provider contract rather than in each adopter's memory.

## Where the tier stops

The rule stated here is "no construction outside the helper". The 492-line
Python one asks something stronger -- that the environment a call passes is
traceable to the shared helper, through wrappers, assignments and parameters --
and stops where certainty does. No pattern over one syntax tree answers that,
and the tier above is where it goes.
