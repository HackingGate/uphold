# Design notes

Why the pieces in [the README](../README.md) are shaped the way they are. None
of this is needed to use the tool.

## Principles are defeasible constraints

Not commandments. A principle earns a place in the catalog only when it improves
a decision or exposes a predictable failure mode. A principle without scope
conditions is a slogan; a principle without trade-offs is marketing; a principle
without an enforcement path cannot be treated as policy.

The collection begins with software and systems engineering because those are
the most directly enforceable domains, but it also includes reliability,
security, data, product decisions, organizations, and AI harnesses.

## The catalog text is design input, never a payload

A principle is not a configuration value. Turning one into a rule that fires is
work you or an agent do once, in the tier that can observe the property. What
this repository ships is the step after that: a check that the rule you built is
still installed and still enabled.

Read a record with `--explain` while writing the rule. Never let a tool carry
the prose into a runtime — a tool holding prose has no condition on which to
emit it, so it emits always and is ignored, or never and enforces nothing. That
is the [`enforcement-needs-a-trigger`](../principles/enforcement-needs-a-trigger.toml)
record, and this repository is bound by it. `enforcement.checks` describes
candidate checks in English; English is not a predicate. The declaration format
carries ids and rule names only, for that reason.

An `enforcement.level` is a statement about where a rule *could* live, not a
licence to ship the record's prose to that level.

## Why the review tier is not what that record refuses

A reviewer reading a change *has* a condition: the change. The failure arrives
instead through **length** — guidance long enough to be skimmed is guidance
emitted always. So `max_lines` (default 900) is not a nicety, it is the other
half of the carve-out, and the record was amended to say so. It refuses this
tier without the ceiling.

Over budget fails the build and says to shorten records or narrow
`include_domains`. Deterministic, not a ranking heuristic: one that quietly
drops the tail is the same always-emitted failure with a scoreboard, and the
reader cannot tell a short document from a truncated one.

**The standing asymmetry points one way on purpose.** A static rule has no
length ceiling and a prompt rule does, so every mechanizable rule is cheaper to
push down into a static tier than to leave in the review tier.

The preamble names every active static rule and says not to re-enforce them.
Repeating what a rule already refuses costs a reviewer's attention and buys a
second opinion nobody asked for.

Compiled entries are `claim`, `applies_when` and `review_questions` — those
three were already written as a prompt; nothing was designed for this and it
still fits. Nothing else crosses over: a reviewer handed costs, conflicts and
sources has been handed the catalog.

### `automatable = "yes"` is a property of the principle, not the repository

`backpressure` says a machine can check bounded queues; a catalog with no queue
in it cannot carry that rule however true the field is. Hence
`[review.no_subject_here]`, which takes a reason rather than a bare list — one
nobody wrote is one nobody can review. Amending the record instead would make
the catalog describe one repository rather than the principle, and the next
consumer would read `partially` and believe it.

## Coverage is not the reconcile

The reconcile only ever sees what somebody already claimed, so `reconciled 7
enforcement claims` reads like coverage and is not: a rule firing under no claim
is invisible to it. `--coverage` counts the other direction.

```text
uphold: 4 of 24 rules carry a principle
  claimed    no-stale-hook-pins -> single-authoritative-source
  claimed    prevent-public-push -> fail-safe-defaults
  claimed    workflow-declares-permissions -> least-privilege
  unclaimed  no-local-merge, no-merge-commit, no-private-repo-names, ...
  note       includes the bundled base set(s): process-residue, host-identity

cmd-shims: 1 of 3 rules carry a principle
  claimed    prevent-ai-author -> complete-mediation
```

An unreadable tier counts `?` rather than `0`, because a hole in the denominator
reported as zero reads as coverage that was never measured. An unclaimed rule is
not a defect to fix by writing a claim; which principle a rule serves is a
judgment, and a mode that failed a build over a missing one would be paid for in
claims nobody believes.

## Why OSCAL, and why only the mapping

NIST's OSCAL component-definition model says the same thing `[[enforce]]` says:
here is a component, here are the controls it implements. Its ecosystem —
[compliance-trestle](https://github.com/oscal-compass/compliance-trestle) and
Compliance-to-Policy — already turns that into policy for several engines and
normalizes their results back, which is worth more than a private format is.

The export reconciles first and emits only what held: a component definition is
an assertion to an outside reader, and exporting an unreconciled one would
publish a claim this tool had just failed to confirm.

**The catalog does not cross over, deliberately.** An OSCAL control has no place
for `applies_when`, `costs`, `conflicts_with`, or a record admitting no machine
can observe it — the nearest available slot is an untyped `prop` that no
consumer reads and no schema checks. OSCAL models compliance requirements, and a
requirement does not have costs or conflict with another requirement. Four
fields ride along as props in this repository's namespace — the rule id, the
seam, the record's `enforcement.level` and its `automatable` — because
`automatable` is the one thing that changes what a reader may conclude from a
passing check.

## The name index is a value, not a table

Every record's `aliases` reach the generated index, because readers arrive with
the name of the catalog title (`Parameterize, Do Not Enumerate`) or with the
name of the failure (`combinatorial explosion`).

`scripts/catalog.py` builds the lookup from the records; QUICK_REFERENCE.md
renders it, `--explain` answers from it, and `name-index.json` publishes it for
anything that is not Python. Nothing reads the Markdown back — a row's column
order and its `|` escaping are layout decisions, and recovering a name from one
means undoing both.

The artifact carries each key, its terms, and a versioned description of the
analysis chain, so a consumer in another language can compute the same key
rather than guess at it. Two records may not claim one key: `scripts/validate.py`
refuses a catalog where a search would have two answers.

## One flat id namespace

It is what lets a claim name a rule by id alone. It also deletes a class of
drift that only existed while the checks were seven separate table names: any
consumer reasoning about "the rules" had to carry its own list of what those
names were, and one such list was short by one — a `language_rule` claim was
reported as enforcing nothing while it was in fact enforced, and neither side
could catch it.

## Guards: `git.hooks` is the whole registration

These lists were a `match` arm in the binary until v3, so a repository could not
add a hook, drop one it found too slow, or read its own answer out of its own
configuration. The trade-offs are lines a reader can edit rather than arguments
sealed in a source comment: the tree-wide name scan is not at `pre-commit`
because it asks the forge about every distinct name in the tree.

There was **no configuration file** for these before: allow-lists, visibility
pins and owner pins were environment variables, and the `<OWNER>_`-prefixed
scheme existed only because environment was the only surface while one machine
holds several workspaces. A per-workspace file *is* the workspace scope.

### Which bytes a guard reads

The index is the tree the next commit will have. The working tree is not: a line
staged and then edited away is in the commit and not on disk.

At a push there is no index at all — what becomes shared is a commit, and the
working tree beside it may be on another branch. So the artifact is the pushed
commit's whole tree *plus every blob the pushed range introduces*. Neither half
covers the other: the tree catches what arrived before this range, the range
catches a blob added in one pushed commit and deleted in the next, which is in
the remote's history permanently and in no tip tree.

### One override spelling

`UPHOLD_ALLOW` replaced five differently-named variables. The id is in it,
so what was switched off is legible in a shell history and in a CI log. It stays
in the environment and is deliberately not a rule field: a bypass belongs to one
invocation by whoever is standing there, and written into the policy file it
would be committed, reviewed once, and permanent — which is not a bypass.

## Shims: what is data and what is code

Most of a bash spec was already data — `SPEC_MATCH` and the `SPEC_*_FLAGS` were
space-separated lists. Only two functions carried logic:

- **`spec_target`** was a forge API call in two specs and git-remote-URL parsing
  in the third. Both are built-in resolvers now; URL parsing is engine work
  anyway, and every spec that wanted it wrote the same thing.
- **`spec_in_scope`** is exactly `visibility == "public"` in the gh, glab and
  git specs. `internal` is deliberately not counted as public.

**npm is why `scope` is an enum and not a boolean.** `npm publish` puts a
directory on a registry the whole world can read: there is no repository, no
owner and no visibility endpoint in that sentence. What decides is a field in
`package.json` and whether the registry is the public one. Bending a forge's
question to fit is how a framework quietly becomes the shape of its first two
examples.

**`git` is why a shim is not just a flag table.** Its published text is
*positional* — `git push origin fix/acme-outage` puts that name on a public
forge — so `collect = "git-refs"` replaces the argv walk rather than forking the
shim.

### `before` scopes a checker

Until v3 a checker was consulted by every declared shim: a check written for a
pull-request body was also asked about a branch name on `git push` and a tarball
on `npm publish`, and every one of those answers was a pass over a subject the
rule had nothing to say about.

The kind in `UPHOLD_KIND` is not decoration — a checker that greps prose for
a private name and one that judges a branch name are not the same checker, and
only the kind tells them apart.

## Where the private-name list lives

A public repository cannot hold the list of what must not be published, and
neither can a command string with a name written into it — it travels with the
policy exactly as a list would. So `private_owners_from` reads from outside the
tree. A literal `private_owners` list is right for a repository staying private,
and the audit reports it as a finding for one being published.

`uphold audit --for-publication` is one shot rather than a hook because the
event it fires on happens once and is not a commit.

### What the audit cannot see

- **`refs/pull/<n>/head`.** A forge retains pull-request head refs permanently
  and renders them on the closed pull request. Rewriting the default branch does
  not touch them. These *are* scanned — fetched explicitly, because a clone does
  not carry them by default and an audit reading only local refs would report
  clean over exactly the surface that survives the fix.
- **Comment edit history.** Editing a comment does not remove what it said; the
  previous revision stays readable and no API route deletes one. This cannot be
  scanned, and is reported as unreadable.

Nothing found in what could be read is *not* the same as clean, and the report
says so.

## Running the tools over this repository

It runs all three seams over itself, for the reason git-guards ran its guards
over its own source: a rule that cannot survive its own tree is one nobody
should be asked to adopt. Its own declaration is in
[`policy/upheld.toml`](../policy/upheld.toml).

This repository defines **why and when** a rule exists; the seams implement it.
The same rule should not acquire a second, drifting definition merely because it
is enforced at another seam.

`check_hook_pins.py` and `no-stale-hook-pins` ask opposite questions of the same
answer: whether a pin is behind the newest upstream tag, and whether the tag it
names exists at all. A pin bumped ahead of a release that was never cut fails at
hook-init, before any hook runs, so nothing downstream of the clone can report
it.
