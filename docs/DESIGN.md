# Design notes

Why the pieces in [the README](../README.md) are shaped the way they are. None
of this is needed to use the tool; [REFERENCE.md](REFERENCE.md) says what each
piece does.

## Principles are defeasible constraints

Principles are not commandments. A principle earns a place in the catalog only
when it improves a decision or exposes a predictable failure mode. A principle
without scope conditions is a slogan; a principle without trade-offs is
marketing; a principle without an enforcement path cannot be treated as policy.

Not every entry is a principle: the catalog is typed by epistemic kind, so a
law, a theorem, a heuristic and a metric each say what they are. The
[catalog schema](../principles/SCHEMA.md) defines each kind separately from
its domains and enforcement rungs.

The collection begins with software and systems engineering because those are
the most directly enforceable domains, but it also includes reliability,
security, data, product decisions, organizations, and AI harnesses.

## The catalog text is design input, never a payload

A principle is not a configuration value. Turning one into a rule that fires is
work a person or an agent does once, in the tier that can observe the property.
What this repository ships is the step after that: a check that the rule is
still installed and still enabled.

Read a record with `--explain` while writing the rule. Never let a tool carry
the prose into a runtime: a tool holding prose has no condition on which to
emit it, so it emits always and is ignored, or never and enforces nothing. That
is the [`enforcement-needs-a-trigger`](../principles/enforcement-needs-a-trigger.toml)
record, and this repository is bound by it. `enforcement.checks` describes
candidate checks in English, and English is not a predicate, so the declaration
format carries ids and rule names only.

## Why the review tier is not what that record refuses

A reviewer reading a change *has* a condition: the change. The failure arrives
instead through **length**, because guidance long enough to be skimmed is
guidance emitted always. So `max_lines` (default 900) is the other half of the
exception rather than a convenience, and the record was amended to say so: it
refuses this tier without the ceiling.

Over budget fails the build instead of truncating. A ranking heuristic that
quietly drops the tail is the same always-emitted failure with a score
attached, and the reader cannot tell a short document from a truncated one.

**The asymmetry is deliberate.** A static rule has no length ceiling and a
review-tier entry does, so every mechanizable rule is cheaper to move into a
static tier than to leave in the review tier.

The preamble names every active static rule and says not to re-enforce them,
because repeating what a rule already refuses costs a reviewer's attention and
buys a second opinion nobody asked for.

A compiled entry is `claim`, `applies_when` and `review_questions`: those three
fields were already written as prompts, so the tier needed no new schema.
Nothing else crosses over; a reviewer handed costs, conflicts and sources has
been handed the catalog.

### `automatable = "yes"` is a property of the principle, not the repository

`backpressure` says a machine can check bounded queues; a catalog with no queue
in it cannot carry that rule however true the field is. Hence
`[review.no_subject_here]`, which takes a reason rather than a bare list: an
exemption nobody explained is one nobody can review. Amending the record
instead would make the catalog describe one repository rather than the
principle, and the next consumer would read `partially` and believe it.

### A control is the probe fixture, one tier up

The compiled document cannot say whether any entry in it can produce a finding.
A record nobody has raised and a record that says nothing a reviewer could act
on are the same silence in every report, and counting citations does not
separate them: it needs many reviews to accumulate first, and even then answers
"was it used" rather than "could it fire".

`uphold probe` already refuses that shape for a git hook: a hook seen only
passing is indistinguishable from one that cannot fail, so a fixture it must
refuse is written down and planted. `[[review.control]]` is the same fixture for
a record (`catches`, a change the record must be named for; `misses`, a change
it must not fire on), and it borrows probe's refusals, listed in
[REFERENCE.md](REFERENCE.md#controls-can-a-record-produce-a-finding-at-all).

A control measures capability, not applicability. It is a change the record's
`applies_when` describes by construction, so a caught control removes "dead"
from the reasons a record is quiet and leaves "nothing violated it", the weaker
claim a citation count can then honestly support.

A control over an `automatable = "yes"` record is refused, because such a record
is not in the document a reviewer is handed: `route` drops it as *a rule
enforces it; a reviewer repeating it is noise*. Failing that control would
fault a reviewer for missing what nobody showed them; passing it would reward
one for repeating a static rule. Either way it would measure the harness.

The count **and the names** of review-carried records with no control print on
every run, refusal or not, in the same form probe uses for its own denominator.
One control beside twenty-nine records is a different claim from one beside
two, and the reader who most needs the difference is the one skimming a
passing run.

Controls share probe's weakness: whoever wrote the record also writes its
control, and can make it easy to pass. The mitigation is also the same: the
control lives in `policy/upheld.toml`, where a diff shows it.

Driving an actual reviewer against a control needs a model, a budget and a
verdict nothing here can make deterministic, so the harness is out of scope and
`[review] emit_controls` is the seam to it. It exports the controls and nothing
from the catalog: a harness also handed the claim and the questions would carry
a second copy of the compiled document, going stale on its own schedule, which
is the failure `single-authoritative-source` names.

### Why `emit` is still per-document and not per-record

`[review] emit` already names targets of more than one shape: `REVIEW.md` for a
person and `AGENTS.md` for an agent are two names for one compiled document,
and `emit_controls` names a machine-read export of a different kind. The field
is a list of destinations rather than a list of documents, and the
generalization under consideration, selecting which records reach which
target, changes what is *selected*, not how many things are written.

A unit emitted alone would have to carry the automatable exclusion inline. The
preamble is what says *do not re-enforce the static rules, they run first*, and
it is emitted once at the top of the whole document; a record emitted on its own
arrives without it, and its reviewer has nothing saying which findings a rule
already refuses. The exclusion is what makes the tier worth a reviewer's
attention, so losing it is not a formatting detail.

Adoption is deferred until two conditions hold together: the compiled document
approaches its `max_lines` ceiling, so selection buys something the ceiling is
otherwise about to take; and controls exist over the records that would be
selected, so a unit that is never selected fails to catch its own control and
says so. Until then a conditionally loaded unit that is never selected produces
no finding and no citation, and neither absence is distinguishable from a quiet
tree: a failure one step earlier than failing to fire, with less evidence than
the always-read document leaves.

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
not a defect to fix by writing a claim: which principle a rule serves is a
judgment, and a mode that failed the build over a missing one would be
satisfied with claims nobody believes.

## Why OSCAL, and why only the mapping

NIST's OSCAL component-definition model says what `[[enforce]]` says: here is a
component, here are the controls it implements. Its ecosystem
([compliance-trestle](https://github.com/oscal-compass/compliance-trestle) and
Compliance-to-Policy) already turns that into policy for several engines and
normalizes their results back, which a private format would forgo.

Rust evaluates reconciliation once into a report; the default human renderer
and the versioned `uphold check --json` renderer consume that same result.
Python review and OSCAL read the JSON contract, including explicit component
identities, rather than interpreting a human evidence line. A malformed report,
unknown schema version, unavailable evidence, or unexpected process status is
could-not-look. Review can still use the partial evidence from an evaluated
refusal; an export requires the whole reconciliation to hold.

The export reconciles first and emits only what held: a component definition is
an assertion to an outside reader, and exporting an unreconciled one would
publish a claim this tool had just failed to confirm.

**The catalog does not cross over, deliberately.** An OSCAL control has no place
for `applies_when`, `costs`, `conflicts_with`, or a record admitting no machine
can observe it; the nearest slot is an untyped `prop` that no consumer reads and
no schema checks. OSCAL models compliance requirements, and a requirement does
not have costs or conflict with another requirement. Of the four props the
export adds, `automatable` is the one that matters: it changes what a reader
may conclude from a passing check.

## The name index is a value, not a table

Every record's `aliases` reach the generated index, because readers arrive with
the catalog title (`Parameterize, Do Not Enumerate`) or with the name of the
failure (`combinatorial explosion`).

`scripts/catalog.py` builds the lookup from the records; QUICK_REFERENCE.md
renders it, `--explain` answers from it, and `name-index.json` publishes it for
anything that is not Python. Nothing reads the Markdown back: a row's column
order and its `|` escaping are layout decisions, and recovering a name from one
means undoing both.

The artifact carries each key, its terms, and a versioned description of the
analysis chain, so a consumer in another language can compute the same key
rather than guess at it. Two records may not claim one key: `scripts/validate.py`
refuses a catalog where a search would have two answers.

## One flat id namespace

A single namespace of rule ids lets a claim name a rule by id alone. It also
removes a class of drift that existed while the checks were seven separate
table names: any consumer reasoning about "the rules" had to carry its own list
of those names, and one such list was short by one. A `language_rule` claim was
reported as enforcing nothing while it was in fact enforced, and neither side
could catch it.

## Guards: `git.hooks` is the whole registration

The hook lists were a `match` arm in the binary until v3, so a repository could
not add a hook, drop one it found too slow, or read its own answer out of its
own configuration. The trade-offs are now lines a reader can edit rather than
arguments sealed in a source comment: for example, the tree-wide name scan is
not at `pre-commit` because it asks the forge about every distinct name in the
tree.

There was **no configuration file** for these before: allow-lists, visibility
pins and owner pins were environment variables, and the `<OWNER>_`-prefixed
scheme existed only because the environment was the only surface while one
machine holds several workspaces. A per-workspace file *is* the workspace scope.

### Which bytes a guard reads

The index is the tree the next commit will have. The working tree is not: a line
staged and then edited away is in the commit and not on disk.

At a push there is no index at all: what becomes shared is a commit, and the
working tree beside it may be on another branch. So the artifact is the pushed
commit's whole tree *plus every blob the pushed range introduces*. Neither half
covers the other: the tree catches what arrived before this range, and the
range catches a blob added in one pushed commit and deleted in the next, which
is in the remote's history permanently and in no tip tree.

The range's commit *messages* are read there as well, as a carrier of their own
rather than part of either half. `commit-msg` fires only when `git commit`
writes a message: `git commit-tree`, a rebase, a cherry-pick, `git am`,
`--no-verify`, and a fast-forward carrying somebody else's commit in from a
hookless clone all record a message no hook ever read, and everything else at
pre-push reads the tree. So a subject line naming a private repository reached
a remote with every hook passing and no override in use.

### One override spelling

`UPHOLD_ALLOW` replaced five differently named variables. The id is in it, so
what was switched off is legible in a shell history and in a CI log. It stays
in the environment and is deliberately not a rule field: a bypass belongs to one
invocation by whoever is running it, and written into the policy file it would
be committed, reviewed once, and permanent, which is not a bypass.

### uphold decides; it does not record

`--junit FILE`, or `UPHOLD_JUNIT` for a run whose command line the caller does
not own, names a file and uphold writes one JUnit document to it. The
format is not one of uphold's own because the fleet already has one evidence
format: a gate writes JUnit XML under `.test-evidence/` and a publisher turns
the directory into a report. The testcase states are the answers a
guard already gives, and one more for a rule stood down at a destination, so publishers and report tools read the file with no glue
and nothing downstream learns a second schema.

The caller names the file, rather than uphold printing to stdout or keeping a
file in a state directory. Stdout is already the prose a person reads and a
hook runner may swallow. A default path in a state directory would be shared by
every repository and every act on the machine, and would put a write somewhere
the caller did not choose. A named file lets the caller put it where its
publisher already looks, outside the tree or inside an ignored directory.

The flag is the conventional spelling and the one a gate task types. The
variable exists because a hook's command line is the hook definition's, pinned
by the repository, so a caller running `git push` has no argv to add a flag
to; the environment is the one channel that reaches through git and the runner
to the guard, which is also why `UPHOLD_ALLOW` is a variable.

A seam that runs many times in one act cannot share one file that is replaced
each time: two `gh` calls would leave the second call's record and lose the
first. So the same request may name a directory, and each invocation writes its
own file there. That is the results-directory convention JUnit tooling already
has, and a publisher that reads every XML under `.test-evidence/` needs no
change to read them. The shim and the hook accept only the directory form,
because for them the single file is a way to lose evidence without a word.

A rule stood down at a destination is recorded as a skipped testcase, while a
rule a stage never declared is not recorded at all. The second is a fact about
the policy: nothing aimed the rule there, and a reader can look that up. The
first is a decision made at run time about one invocation, and the question a
reader of a bypass log asks is whether the check ran on that body or not. The
file answers it without a second source. Leaving it out would make absence mean
"set aside, passed or never ran", the ambiguity the file exists to remove.

`git commit --no-verify` and `git push --no-verify` run no hook, so no file is
written. That needs no code here: a verifier that expects evidence on every
pushed commit sees the absence, held on the remote and out of reach of the
machine that skipped the hooks.

"Evidence" here means what it means in `.test-evidence/`. Inside uphold the word
also names a provider's facts to a policy, described in the section "Evidence:
what a provider reports and what a policy may read", and the two meanings do
not meet.

## What an external provider must establish

A trustworthy provider claim has a verifiable rule name, a demonstrated
refusal, and a way to distinguish compliant input from input the provider
could not read. `uphold probe` can demonstrate a refusal by planting invalid
and clean fixtures and checking both verdicts. Where the provider cannot
report unread input itself, a companion check must supply that evidence;
silence alone is insufficient evidence of a clean run.

These are criteria for choosing a provider. The reconciler currently credits
external hook ids from their installation and takes the claim's word for what
they enforce; inspecting a provider's local rule definitions is still planned.
Probing is opt-in, not a prerequisite enforced on every claim. Reconciliation
reports installation independently of behavior, which starts unmeasured.
`uphold check --probe` adds measurements from the same invocation without
changing the installation verdict. A bad-and-clean pair can demonstrate only
the selected manager's named hook at the captured repository revision; missing
controls, unread runs, timeouts and observed failures cannot demonstrate it.
A wrapper's result does not certify its individual engine rules or a same-named
hook supplied through another manager.

Behavioral evidence is transient. The command captures a clean committed
snapshot before loading the policy and evaluating installation, runs that
exact revision, and refuses to certify changes during measurement. Provenance
includes the hook declaration, runner, stage and fixtures, so the exercised
subject is visible. This avoids a storage format or cache whose freshness a
later invocation would have to prove. External policies, machine dependencies
and remote services remain outside that snapshot; even a qualifying pair proves
only its exercised cases.

## Evidence: what a provider reports and what a policy may read

Most guards read their own artifact and decide on the spot, and for a rule
about bytes that is the right shape. For a rule about what a change *means*
(which functions it removes, what the message says it intends) the reader is
the part most likely to be replaced, and a rule written against the reader is
rewritten with it. So there is a seam. A **provider** reads one artifact and
reports **evidence** in one normalized shape: a kind, a subject, properties,
and the provenance a reader of a refusal needs (which provider, at what
**strength**, over which **revision**). A **policy** is handed the body of
everything reported and decides. It never names a provider;
`tests/structural_evidence.rs` reads the provider names off `src/evidence/`
and refuses a policy file that spells one.

Strength is a variant, `Proven > Heuristic > Inferred`, and the three rules it
buys are methods on the body rather than conventions: weaker evidence may add a
refusal, may never supply a clean verdict where a stronger provider could not
look, and may never cancel a stronger provider's refusal. A model's assertion
is `Inferred` by construction and yields no refusal and no clean verdict on its
own; no provider produces it yet, and the variant is exercised by a test double
so the seam exists before the first one does.

A provider that could not look says so in its answer, as a variant and never as
an empty list. The parser provider answers `Unavailable` for a file with an
`ERROR` node on either side, naming the file and the line, because the
recovered tree can omit functions from the file; an empty parser result is
therefore not evidence that no function was removed. What follows is decided
the same way every time: parser unavailable and the diff pattern silent is exit 2; parser unavailable and the
diff pattern found a removal is a refusal; two `Proven` providers disagreeing
about one subject is a refusal naming both.

It is not a rule DSL and not a plugin API. A policy is a Rust predicate in this
binary dispatched like every other built-in, a provider is a Rust type compiled
in, and the trait between them distinguishes evidence from an unavailable
source. This keeps policies independent of parser details while preserving a
failure to inspect as an explicit answer.

## Shims: what is data and what is code

Most of a bash spec was already data: `SPEC_MATCH` and the `SPEC_*_FLAGS` were
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
question to fit is how a framework quietly takes the shape of its first two
examples.

**`git` is why a shim is not just a flag table.** Its published text is
*positional* (`git push origin fix/acme-outage` puts that name on a public
forge), so `collect = "git-refs"` replaces the argv walk rather than forking the
shim.

### Publication adapter boundaries

`invocation::Invocation` is the shared adapter-to-policy subject contract. It
carries the seam, report identity, and either pathless prose with separately
identified headlines or command-collected subject kinds. `Observed` distinguishes
a missing subject from a present empty string and from an unread required
surface. Tool identity remains available when a harness call has no argument
strings. `text::judged` consumes the pathless form; the shim consumes named
subjects under the same authoritative `text::Judged` and `text::Seam` table.
Passing a command's subjects to the pathless evaluator is an error.

Publication commands have additional facts that raw text cannot establish.
`shim::destination::CommandContext` binds the canonical arguments and collected
target to one invocation. It resolves the destination lazily and retains its
repository spelling, host, forge client and selection provenance. Scope,
ownership and destination-sensitive text guards consume that observation.
Local visibility is reused only for a destination selected from origin without
an ambient host override. A required destination that remains unresolved takes
the existing explicit unresolved-scope path; it cannot become a clean answer.

The command grammar and collection remain in `shim`; they do not evaluate
policy. `shim::checker` evaluates one selected rule against one subject, with
pattern or subprocess checks and the existing checker exit contract. The shim
orchestrator selects rules, asks scope, judges destination then subjects, and
hands the original arguments and any replayed stdin to the process. Editor
re-entry uses the same command context and checker implementations. These are
internal modules of the same binary, with no separate installation lifecycle.

Harness hooks collect strings and recognized headline fields. They do not
interpret arbitrary tool arguments as forge destinations; direct text checks
also have no destination supplied by their caller. The existing text guards'
repository context remains unchanged. Command normalization does not extend
that coverage to another transport or an unknown command grammar.

### `before` scopes a checker

Until v3 a checker was consulted by every declared shim: a check written for a
pull-request body was also asked about a branch name on `git push` and a tarball
on `npm publish`, and every one of those answers was a pass over a subject the
rule had nothing to say about.

`UPHOLD_KIND` carries the kind for the same reason: a checker that greps prose
for a private name and one that judges a branch name are not the same checker,
and only the kind tells them apart.

## Where the private-name list lives

A public repository cannot hold the list of what must not be published, and
neither can a command string with a name written into it: it travels with the
policy exactly as a list would. So `private_owners_file` (or the command form,
`private_owners_from`) reads from outside the tree. A literal `private_owners`
list is right for a repository staying private, and the audit reports it as a
finding for one being published.

`uphold audit --for-publication` is a one-off command rather than a hook
because the event it guards happens once and is not a commit. Pull-request head
refs are fetched and scanned, and comment edit history is reported as
unreadable; [REFERENCE.md](REFERENCE.md#uphold-audit---for-publication) covers
both. Nothing found in what could be read is *not* the same as clean, and the
report says so.

## Running the tools over this repository

This repository runs all three seams over itself, for the reason git-guards ran
its guards over its own source: a rule that cannot survive its own tree is one
nobody should be asked to adopt. Its own declaration is in
[`policy/upheld.toml`](../policy/upheld.toml).

This repository defines **why and when** a rule exists; the seams implement it.
The same rule should not acquire a second, drifting definition merely because it
is enforced at another seam.

`no-stale-hook-pins` asks both halves of one question of one answer: whether a
pin has fallen behind the newest upstream tag, and whether the ref it names
exists at all. The first half is asked of lefthook refs only; for a pre-commit
`rev:` it belongs to `prek update --check`, run by the consumer. They were
two checkers for a while (a `check_hook_pins.py` script beside the guard), and
that arrangement is the drift this section warns about: the two read the same
`rev:` lines, reached the same remote, and were free to return different
verdicts, and did. The guard counted a pin whose remote it could not reach as
passed, while the script called the same pin unresolvable, so the answer a
repository got depended on which seam ran. One `git ls-remote` now answers both,
and a pin that could not be checked is exit 2 rather than either verdict.

A pin bumped ahead of a release that was never cut still fails at hook-init,
before any hook runs, so nothing downstream of the clone can report it. That is
why the guard is installed at pre-push and at the manual stage, the last two
moments that are still upstream of somebody else's clone.
