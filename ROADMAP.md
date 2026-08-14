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
   the claim reconciles. This makes it a report.
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
   content sets declare none; `process-residue` declares `manual` and nothing
   else. A guard cannot join a set without editing a line that says the set is
   allowed to carry one.
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

This repository inherits all five. The seven guard declarations that stood in
its own policy were byte-identical to the sets', which is the argument the sets
were promoted on.

Adopting `host-identity` is the standing evidence that a set is not a no-op:
the bundled rule scans `["."]` while all twenty-nine hand-copies scan a strict
subset, quietly avoiding vendored trees, `target/`, and test corpora. Per
repository, not a fleet sweep.
