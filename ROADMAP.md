# Roadmap

## Catalog

- Expand foundational architecture, reliability, security, data, product, and
  AI-harness entries.
- Add explicit contradiction pairs and decision matrices.
- Promote seed entries to reviewed status after source and field review.
- Add examples from public HackingGate repositories without exposing private
  organization names or implementation details.

## Enforcement tool

`uphold_check.py` ships the reconcile step. It:

1. loads and validates the catalog;
2. reads a repository's `[[enforce]]` claims;
3. resolves each claimed rule id against every seam this repository runs -- the
   content policy and the guards, the command shims, the local hooks -- and
   names the seams that enforce it;
4. distinguishes `refused` (1) from `could not look` (2), and neither from `0`;
5. fires only when the declaration or a config it reads changes;
6. carries no record prose into any runtime.

What it deliberately does **not** do, and why:

- **Turn `enforcement.checks` into checks.** Those fields are English written
  for a person: `"Reject wildcard permissions where a narrower scope exists"`
  describes a check, it is not one. Compiling them would mean a second
  machine-readable statement of the same rule in the same record, free to
  disagree with the first. The step from a record to a rule is deliberate work
  done once, in the tier that can observe the property -- and then declared, so
  the claim can go stale loudly instead of silently.

- **Verify that a named rule exists upstream.** The reconciler reads this
  repository's configuration only. Rules declared in `policy/principles.toml`
  and rules supplied by a bundled set named in `[inherit] sets` are both
  enumerable, because those sets ship compiled into the binary rather than
  living at a pinned rev in another repository -- `uphold rules --set <name>`
  prints one. What it still cannot do is look inside a third-party hook
  repository: a formatter or linter pinned from elsewhere is counted as
  installed by its hook id, and the tool takes the claim's word for what that id
  enforces. That limit is reported, not papered over, and a repository whose
  configuration is unreadable exits 2.

  Half of it is closable, and that half is the one feature the provider
  evaluations argue for. A provider whose configuration is LOCAL and readable --
  `deny.toml`, an `ast-grep` rule directory, a `zizmor.yml`, a `repo: local`
  hook, a lefthook command -- can be asked whether the claimed id is defined in
  it, which turns "a hook id somebody pinned" into "a rule this repository can
  name". It is a much smaller feature than a rule DSL and it does not tell the
  tool what the id MEANS; `uphold probe` is what establishes that, by driving
  the id to a refusal. See [ADR 0005](docs/adr/0005-what-a-provider-must-answer.md).

- **Detect that an installed rule never fires.** A rule that cannot match is
  switched off, and no config file shows it. This needs firing counts from the
  tiers themselves, and separating "clean tree" from "dead rule" before the
  signal is worth anything. See `enforcement-needs-a-trigger`, which states the
  problem and admits the same limit.

- **Adopting OSCAL wholesale.** `--oscal` exports the mapping, and that is the
  whole of the convergence. The catalog stays TOML because an OSCAL control
  cannot hold a scope condition, a cost, a conflict, or `automatable = "no"`,
  and a private `prop` holding those is not interoperability — it is the same
  private format with more ceremony. Revisit if OSCAL grows somewhere to put
  them.

- **Shared profiles.** An earlier draft shipped `profiles/*.toml` naming sets of
  principles a class of repository should adopt. It was removed: which rule
  enforces a principle is specific to one repository, so a shared profile could
  only have carried principle ids with no rule behind them -- a list with no
  trigger, which is the failure `enforcement-needs-a-trigger` names.

### Bundled sets that carry guards

Five guard declarations are byte-identical across the consuming fleet, with
zero variation: `prevent-ai-author`, `prevent-unusual-unicode`,
`no-merge-commit`, `no-local-merge` and `prevent-public-push`. That is one
decision and sixty-four transcriptions, and it is the same argument that
promoted the content rules into `policy/base/`.

Shipped, and the order was the design -- these had to exist **before** any set
carries a guard, not alongside:

1. `no-hand-copied-base-rule`, at `manual`, in `process-residue`. A
   transcription is invisible to every other check here: the id resolves and
   the claim reconciles. This made it a report -- and **a gate at `pre-commit`
   as well now**, over the ids a change adds. See *What the report measured*
   below for what the manual-only release bought.
2. The derived-owner note on `prevent-public-push`'s **allow** path. Fifty of
   sixty-five repositories pin no `owner`, and the guard used to say so only
   when refusing -- which is never, for as long as nothing has gone wrong.
3. A load-time note when a repository shadows an inherited id with a
   **different check**. Without it, a set arriving over a forked copy hides the
   fork behind the very rule the set was added to supply.
4. Set provenance in refusal output: `refused by 'X' [set: Y]`. A guard whose
   whole declaration is one word in an `[inherit]` line is astonishment unless
   the refusal says where it came from.

Then the two constraints that had been written down as risks to hold, which is
another way of saying nothing enforced them:

5. **`[set] stages`** — each bundled set declares the hook stages it may
   install, and a rule reaching past that ceiling is refused at load. The
   content sets declare none; `process-residue` declares `pre-commit` and
   `manual` and nothing else. A guard cannot join a set without editing a line
   that says the set is allowed to carry one, and widening the line is the diff
   that says so -- which is exactly how `pre-commit` was added to it.
6. **`policy/base/sets.lock.json`** — every bundled set, field for field,
   committed, with a test that refuses a tree where it has drifted. A set
   changing shape is a diff in this repository, where it can be reviewed,
   rather than a behaviour change in sixty-five repositories with a diff in
   none of them. `uphold rules --sets --json` is the same document, so two
   versions of the binary are diffable against each other as well.

Then the sets, once the two above made them safe to ship:

7. **`commit-message-residue`**, **`unreviewed-history`**,
   **`invisible-characters`**, **`stale-pins`** and **`unowned-push`**, each a
   new name rather than a rule added to an existing set. `unowned-push` carries
   `prevent-public-push` behind `owner_required = true`, and the owner it needs
   is declared once at the top of a policy file rather than on the rule --
   inheriting a set never decides who you are, and a rule arriving from a set
   cannot be handed a parameter.
8. **`default-token-grant`** and **`private-names`**, both promoted by the same
   sweep that measured item 1. `default-token-grant` carries
   `workflow-declares-permissions`, which nine repositories had written out
   byte-identically without knowing about each other; it is a name of its own
   rather than a rule in `process-residue` because it is about how CI is
   configured rather than about what a repository commits, and declining it is
   a real decision for a repository with no workflows. `private-names` carries
   the three private-name guards behind `visibility_required = true`, in the
   shape `unowned-push` uses for `owner`: `visibility` joins `owner` and
   `private_owners_from` as a top-level policy field, so the fact a set cannot
   be handed is declared once. The sweep is the argument -- the family was
   declared in 10 of 77 repositories and **67 publish text through no seam at
   all**, after a public repository pushed a commit message and a pull-request
   body that each named a private organisation and a private repository with
   nothing in their path.

This repository inherits all seven. The seven guard declarations that stood in
its own policy were byte-identical to the sets', which is the argument the sets
were promoted on.

Its own `private_owners_from` needed a third answer rather than a choice between
two bad ones. The line reads a file outside the tree, and a missing source is an
error rather than an empty list -- so it made every clone of this repository exit
2 on its first commit, over a file that exists on one machine. Dropping it was
tried and measured, and it costs more than it looks: a forge lookup only
adjudicates names something already extracted, and a bare `owner/repo` is
extracted only for DECLARED owners and for this repository's own. Without the
list, a bare `otherowner/repo` and an organisation named on its own are not seen
at all -- and an organisation named on its own is precisely the form that got
past a hand audit here.

So the source stays, with `private_owners_optional = true` beside it: the
failure is reported on stderr, naming those two forms, and the run proceeds. A
command that swallowed its own failure would have bought the same green while
losing them in silence, in every clone, permanently.

Adopting `host-identity` is the standing evidence that a set is not a no-op:
the bundled rule scans `["."]` while all twenty-nine hand-copies scan a strict
subset, quietly avoiding vendored trees, `target/`, and test corpora. Per
repository, not a fleet sweep.

#### What the report measured

`no-hand-copied-base-rule` shipped at `manual` on purpose: a check that reports
on the SHAPE of a policy should not stand between anyone and a commit before
its false-positive behaviour has been seen in the open. A sweep of every
`policy/principles.toml` in one workspace -- **77 repositories** -- then read
what the report had been reporting, and the answer was nothing at all.

- **76 of the 77 inherit `process-residue`**, so the check was *loaded* in all
  but one of them.
- Roughly **forty carried at least one transcription**, and not one had ever
  been reported. Nothing runs a manual stage on its own: not a git hook, and
  not any CI workflow in the fleet.
- Among those findings, **no false positives**. Every id named was a genuine
  copy of a bundled rule from a set the repository did not inherit.

The sharpest single case: `captured-fixtures` ships exactly one rule,
`no-non-ascii-in-fixtures`; **no repository inherits the set** and **seventeen
transcribe its contents**.

So the manual-only release did buy the evidence it was for, and the evidence
was that being loaded is not being run. The gate that follows refuses the
ADDITION rather than the STATE -- ids absent from the policy file at `HEAD` --
because a version bump that refused the existing forty would be paid for by
being switched off, which returns coverage to the zero it started at. Deleting
the existing copies is per-repository work, and it is worth doing now that the
sweep cannot refill.
