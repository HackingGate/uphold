# ADR 0007: what the surveyed orchestrators collapse

Status: Accepted

This record answers whether `uphold supply-chain` should be retired in favour of
an existing orchestrator. It is written after the field was surveyed and the
candidates were run, not from a list of tool names.
[REFERENCE.md](../REFERENCE.md) documents what the command does; this says why
it is written here rather than adopted.

The question is narrow. Orchestrating scanners is not novel work, and a
hand-written runner is a cost. The survey was run to find the tool that already
does it, and the answer is that the field collapses the one distinction this
command exists to keep.

## The contract the survey was run against

A section is one of four states, not two. `Clean` and `Failed` are the verdicts.
`CouldNotLook` is a scanner that did not read its input, and `Nothing` is a
scanner correctly given no input to read -- no lockfile moved in the range, no
vet store to consult. The two negative states are not the same fact and neither
is clean.

`verdict()` ranks them, and it is called from six sites: supply, probe, check,
audit, main and the push guard. A Kani proof holds that could-not-look never
exits `0`. The contract is repo-wide, not local to this command.

## What the candidates do with could-not-look

**reviewdog is the only real prior art, and it is about twenty lines.**
`CheckUnexpectedFailure` carries the concept verbatim: a command that failed, or
whose results could not be parsed, is not a clean run. Its guard is that the
command errored *and* produced no findings, so a scanner that reports three
findings and then dies is classed as a verdict. That is the guarddog shape this
crate already refuses, and it is the reason `guarddog` is the one place a
scanner's output is read rather than its exit code.

**trunk has the best vocabulary and the worst provenance.** Its linter schema
splits success codes from error codes from no-issues codes, and defines the
first as unrelated to whether issues were found, which is a sharper spelling of
the axis here. The orchestrator binary is closed source with no public
repository, auto-updating from a vendor endpoint, and whether it exits non-zero
on a linter's internal failure is undocumented.

**MegaLinter erases the state rather than collapsing it.** A linter absent from
the container flavour is marked inactive, and every reporter filters on that
flag, so the linter vanishes from the console table, the summary and the JSON,
and the run exits `0`. Its own error table classifies infrastructure failures
correctly as not-a-finding and then discards the classification.

**pre-commit and prek cannot express it by design.** The per-hook result is a
boolean before it reaches the merge, a missing executable returns the same code
as found-problems, and the skip mechanism sets success. The maintainer's stated
position is that pre-commit does not decode tool output and will not interpret
it. That is a defensible product boundary and it is the boundary this command
sits on the other side of.

**SARIF has the vocabulary in the standard and cannot carry it in practice.**
Execution success is the only required property on an invocation, and an absent
results array is the specified encoding of did-not-look. Both are defeated:
invocations are optional on a run, and the published schema types results as an
array, so the encoding the specification mandates fails the schema the
specification ships. None of the five scanners here emits the field usefully,
and the aggregators drop it.

## Coverage decides the same question independently

No surveyed orchestrator reaches more than two of the five scanners. The other
three would be written as integrations either way, in someone else's
configuration language, feeding a merge layer that discards the distinction.
Adoption costs the same work and loses the property.

## The idea is older than every implementation of it

XCCDF standardised nine rule-result values, and its scoring rule excludes
not-applicable and not-checked from the denominator while leaving error and
unknown inside it. An unreadable check counts against the score and never for
it. That asymmetry is what `verdict()` implements. The idea has been specified
since 2012; the implementations surveyed here collapse it.

## What was deliberately not built

No structured output. `supply-chain` prints sections and answers by exit code,
and the exit code is the whole machine-readable surface. A consumer that counts
findings from JSON would be able to read a broken scanner as clean unless
could-not-look is reified as an entry it cannot ignore, which is the pattern
golangci-lint uses for the checks it could not run. Adding output without that
entry would reintroduce the defect this record is about.

No scanner is linked. Every one is a subprocess found on PATH, and a tool that
is absent is could-not-look rather than a build failure.

## What this changes today

Nothing in the binary. The command stands as written, and the survey is recorded
so the question is not reopened from the tool names alone.

## What the survey changed, which was not the orchestration

Running the candidates meant running the five scanners too, and four of the
five turned out to confuse a verdict with a refusal in their own exit codes.
That is the same defect one layer down, and it was live here.

`cargo-vet` answers `255` both for an unvetted dependency and for a store it
could not open. `cargo-deny` returns a bitmask whose `1` is either a matched
advisory or an advisory database it could not fetch. `osv-scanner` separates
them itself, at `127` and `128`, and those were read as refusals. `zizmor`
answers by severity at `11` through `14`, and — the case that cannot be seen
from an exit code at all — skips a workflow it cannot parse, audits the rest
and exits `0`, with its SARIF asserting the run succeeded.

The worst was `guarddog`. `verify` exits `0` whether it found three
high-severity risks or none, so every finding it made was reported clean. That
one is a false negative on a malware scanner, and closing it meant reading a
scanner's findings for the first time, against the rule this command otherwise
holds. The rule survives with one stated exception, because the alternative
was running guarddog for nothing.

Each scanner now hands its exit code, stdout and stderr to a reader that may
name a could-not-look; a tool whose code already separates the two passes a
reader that never fires. `REFERENCE.md` records the four contracts.

One judgement rather than a fact, left as a judgement: of the five,
`cargo-vet` is the one whose upstream has gone quietest.
