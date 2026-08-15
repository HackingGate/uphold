# ADR 0004: the semantic tier, and what it costs to be sure

Status: Accepted

[ADR 0003](0003-the-structural-tier-and-what-a-clean-run-means.md) ends where a
pattern over one syntax tree stops: the rule this repository enforces is "no
command is built outside the helper", and the rule it would rather enforce is
"every command this module runs came FROM the helper". The second is a question
about values flowing between functions, and no matcher answers it.

This record is what two data-flow tools said when they were asked.

## The property

`probe` builds a throwaway worktree and drives a hook runner in it. Every child
must have git's environment taken away, because a hook runner exports `GIT_DIR`
and `GIT_INDEX_FILE` and several of them are RELATIVE to the repository the hook
fired in. `detached` is the one place that strips them.

Stated as the tier above the structural one states it: **no execution of a
command in this module may be reached by a command that did not come out of
`detached`.** That is complete mediation, written as a flow property, and it is
the shape the issue behind this work names -- a privileged operation that must
pass through one mediation point.

## Semgrep: the property is expressible, the flow is not

Semgrep's taint mode states the negative form of it in thirteen lines, and it
does something no single AST pattern does: it links a source and a sink that
are separate statements joined by a variable.

```yaml
mode: taint
pattern-sources:
  - patterns:
      - pattern: Command::new($PROGRAM)
      - pattern-not-inside: |
          fn detached(...) {
            ...
          }
pattern-sinks:
  - pattern: $C.output()
```

On a fixture where the construction and the execution are two statements in one
function, that is exactly one finding and it is the right one. Two things were
measured getting there, and both are worth carrying:

**Order matters, and the helper's own body reads as a violation without a
carve-out.** `detached` sets `current_dir` before it calls `env_remove`, so at
the moment of the earlier statement the value is not yet sanitized. That is
defensible behaviour and it is not what the rule means; `pattern-not-inside` on
the helper is the fix, and the rule has to know the helper's name.

**Nothing crosses a function boundary.** Move the construction into a wrapper --
`fn plain(program) -> Command { Command::new(program) }` -- and call the wrapper
from the function that runs the command, and Semgrep reports nothing. Not on a
fixture: on this repository's own `src/probe.rs`, with the defect planted in it
and a wrapper one function away, `semgrep --config rule.yml src/probe.rs`
printed `Findings: 0`.

Cross-function taint is the Pro engine:

```text
$ semgrep --config rule.yml --pro src/probe.rs
Run `semgrep login` before running `semgrep scan --pro`.
```

So the honest summary of the OSS tool is: it reaches one useful step past the
structural tier, and it stops one step short of the property. The step it takes
is real and cheap. The step it does not take is the one this rule is about, and
it is behind an account.

## CodeQL: the property, answered, at a price

CodeQL resolves calls rather than matching their spelling: `Command::new` in the
database is `<std::process::Command>::new`, from type inference, and `detached`
is `uphold::probe::detached`. That resolution is what lets the query state the
POSITIVE form -- the direction ADR 0003 records a matcher cannot express at all:

```ql
from Execution run, DataFlow::Node sink
where
  run.getLocation().getFile().getBaseName() = "probe.rs" and
  sink.asExpr() = run.getReceiver() and
  not Flow::flowTo(sink)
select run, "runs a command that did not come from `detached`"
```

`not Flow::flowTo(sink)` is "no value out of the helper reaches this execution".
It is a negation over a flow relation, which is a thing you can only write when
the tool computes the relation for you.

Handed the same planted defect Semgrep printed `Findings: 0` on -- construction
in a wrapper, execution one function away -- it reports the one finding and
nothing else. Over the compliant tree it reports nothing.

### Three measurements, none of them free

**The models are yours.** The first run of that query produced three findings,
all false, all of the form `detached(..).args([..]).output()`. Value flow does
not cross `Command::arg` and its neighbours, because nothing in the standard
library model says those return the same command. The query needs

```ql
predicate isAdditionalFlowStep(DataFlow::Node earlier, DataFlow::Node later) {
  exists(MethodCallExpr builder |
    builder.getStaticTarget().getCanonicalPath().matches("<std::process::Command>::%") and
    earlier.asExpr() = builder.getReceiver() and
    later.asExpr() = builder
  )
}
```

before it says anything true. That is the tier's real cost and it is not the
toolchain: an unmodelled API produces confident wrong answers, in both
directions, and the direction that produces silence is the one nobody
investigates.

**The toolchain.** The CLI is a 600 MB download; the database for this crate is
174 MB and takes about two minutes to build; the query compiles in 13 seconds
and evaluates in 4. Nothing about that belongs in front of a commit.

**A clean answer still does not mean the file was read.** This is the same
finding ADR 0003 records for `ast-grep`, and it survives the whole climb up the
cost hierarchy. With one unparseable function above the planted defect in
`src/probe.rs`:

```text
$ codeql database create ... --language=rust
Successfully created database at ...
$ codeql query run --database=... probe-env.ql
| run | col1 |
+-----+------+
```

"Successfully created", zero findings, and the defect is sitting in the file.
The state is recoverable -- the database records `parse_error` diagnostics for
`probe.rs` -- but the recovery is worse than it sounds: the clean tree already
carries 1,689 diagnostics of the same severity, mostly `macro expansion failed`
from `assert!` and `format!`. The signal that a file did not parse is four more
rows against that, at severity Warning, in a channel no result of the query
mentions. Reading it means knowing in advance which tag and which file to filter
for -- which is to say, knowing what you were about to fail to find.

## Decisions

**Neither tool is adopted here.** The property they answer is already enforced
in this repository by a structural test, at a cost of milliseconds, and the
extra thing CodeQL proves -- that no wrapper bypasses the helper -- is a case
`src/probe.rs` does not currently contain. A second checker over one answer is
two answers free to disagree, and this repository has had that once already.

**The query is kept, in this record, rather than in a file nothing runs.** It is
reproducible from what is written here, and a query in a directory with no
runner is the dead configuration this repository refuses everywhere else.

**Semgrep OSS is not the semantic tier.** It is a better structural tier: taint
within one function is genuinely more than a pattern, and it is worth reaching
for when a rule needs a construction and a use joined by a local variable. A
repository that needs the cross-function property needs CodeQL or a paid engine,
and should be told so rather than left to discover it from a green run.

**CodeQL is adoptable as a provider by a repository that has the property to
prove**, and it belongs at the manual or scheduled tier where `cargo mutants`
and `cargo deny` already are.

**One requirement follows for the provider contract, and it is now the third
tier to produce it.** A clean run from an analyzer is evidence only when
something separately establishes that the analyzer could read what it was
pointed at. `ast-grep` needs a companion `kind: ERROR` rule; CodeQL needs a
diagnostics query with a filter; a hook needs to have been driven to a refusal.
The claim `uphold` reconciles is "this rule runs here", and what these three
have shown is that "it ran and said nothing" and "it could not look" are the
same output from every tier the analysis climbs to.
