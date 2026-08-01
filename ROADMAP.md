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
