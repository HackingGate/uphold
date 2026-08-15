# ADR 0005: what a provider must answer before a claim may name its rule

Status: Accepted

This record defines the contract an external analyzer has to satisfy to be named
in `policy/upheld.toml`. It is written last on purpose. The instruction it
follows was to define the abstraction only after the prototypes revealed the
common minimum, and not from tool names -- so what is below comes from seven
evaluations that were run rather than from a survey:

`cargo-deny`, `zizmor`, `cargo-mutants`, `cargo-fuzz`, `ast-grep`, `semgrep` and
CodeQL, plus `kani`. Two of them are adopted here, one is documented as a manual
tier, and four are not adopted at all. The contract is what all eight had in
common, and it is three questions rather than an interface.

## The three questions

### 1. Is there a name this repository can read?

A claim names a rule id. Today the reconciler takes the claim's word for what a
third-party id enforces, and [ROADMAP.md](../../ROADMAP.md) says so.

The evaluations split providers into two classes on exactly this point:

**Configuration that is local and readable.** `deny.toml`, an `ast-grep` rule
directory, a `zizmor.yml`, a `repo: local` hook, a lefthook command. For these,
"is `RUSTSEC-0000-0000` actually in the advisories list here" and "is
`unpinned-uses` actually in this policy" are questions about a file in this tree.
Answering them is a much smaller feature than a rule DSL, and it is the one this
whole exercise says is worth building.

**Configuration that lives at a pinned rev elsewhere.** A formatter or linter
from another repository. The id exists in that repository, and no amount of
reading files here will show what it enforces. What can be verified is the pin,
which is what `no-stale-hook-pins` already does.

Neither class ever tells this tool what an id MEANS. That is question 2.

### 2. Has the refusal been seen?

`uphold probe` drives a declared hook to both verdicts in a throwaway worktree:
plant what it must refuse, expect non-zero; plant a clean fixture, expect zero.

That command was written for hooks and it applies unchanged to every provider
evaluated, because the property it establishes is not about hooks. A gate whose
rejection path has never been demonstrated is not demonstrated to be a gate,
and the evaluations produced two of those on their own: a `semgrep` rule whose
sanitizer was after its sink and a CodeQL query with no model for the builder
API both ran, both reported, and neither reported the thing it was written for.

The prototypes in this repository each carry their negative control for the same
reason -- the structural rules have fixtures with the defect in them, and the
`kani` proofs were driven to a failure by a one-character mutation before being
believed.

### 3. Can it say "I could not look", and does it?

This is the question the whole exercise kept producing, at every tier, and it is
the reason this record exists at all.

| tier | what a clean run looked like over a source it could not read |
| --- | --- |
| `ast-grep` | exit 0, no output, over a file whose parse collapsed three lines above the defect |
| CodeQL | `Successfully created database`, zero rows; the `parse_error` is four rows in a channel already carrying 1,689 diagnostics at the same severity |
| a pin check | an unreachable remote counted as a pin that resolved -- this repository's own, before `no-stale-hook-pins` |
| a hook | a hook that cannot fail prints the same green tick as one that keeps finding nothing |

The pattern does not weaken as the analysis gets more expensive. It gets harder
to notice, because a 600 MB toolchain that prints "successfully" is more
convincing than a regex that printed nothing.

So: **a provider that cannot distinguish "found nothing" from "could not look"
must be paired with something that can, and the pairing is part of the claim
rather than part of the adopter's memory.** For `ast-grep` that is a companion
rule matching `kind: ERROR`. For CodeQL it is a diagnostics query with a filter
that knows which tag and which file to look for. For a hook it is a probe. A
provider that answers the question itself -- as this binary's own scan does,
exiting 2 over a path it could not open -- needs no pairing, and that is the
property worth preferring a provider for.

## What the contract is not

**Not a plugin API.** Nothing in eight evaluations asked for one. What the
providers share is three questions; they share no input format, no output
format, no configuration shape, and no execution model, and an interface
covering all of them would be an interface describing none of them.

**Not embedding.** Every tool here is better at its own job than a
reimplementation would be, and the reimplementation would then need its own
answers to all three questions above.

**Not a rule DSL over tree-sitter.** [ADR 0003](0003-the-structural-tier-and-what-a-clean-run-means.md)
records why: a structural rule this repository needs is cheaper as a test beside
the code it constrains, and a structural rule a consumer needs is `ast-grep`'s
job.

## Cost decides the seam, and the seam is part of the claim

Measured on this repository, on one machine, so the ratios are what matter:

| tier | measured |
| --- | --- |
| the content scan (this binary) | milliseconds, whole tree |
| a structural test (tree-sitter, in-tree) | 0.02 s for three rules |
| `ast-grep` over `src/` | 0.04 s |
| `semgrep` over `src/` | 1.6 s |
| `kani`, four harnesses | about a second each, after a 500 MB setup |
| `cargo deny check` | seconds, and a network round trip for advisories |
| CodeQL | 2 min database, 13 s to compile a query, 4 s to evaluate, 600 MB toolchain |
| `cargo mutants`, one module | about 8 minutes; the crate is hours |

A claim that names a rule must also name where it runs, because "this rule is
enforced here" is false when the seam it runs at is one nobody can afford to
trigger. This repository has already applied that rule to itself three times, in
the same direction each time: the network-touching pin check runs at pre-push
and manual rather than at commit; `cargo deny` is documented rather than hooked;
`cargo mutants` and `cargo kani` are manual. The pattern is that anything whose
cost a contributor would notice belongs at a seam they chose to run, because a
check somebody disables wholesale enforces nothing at all.

## What this changes today

Nothing in the binary. It names the one feature the evaluations argue for --
verifying that a claimed id is present in a provider's own local configuration
-- and records why the rest of the provider model needs no new mechanism: an
`ast-grep`, `zizmor` or `cargo-deny` rule id is claimable through the local tier
already, exactly as a formatter's hook id is.
