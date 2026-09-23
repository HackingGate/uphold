# ADR 0008: evidence, and what a policy may consume

Status: Accepted

This record answers what a rule in this binary is allowed to read. Every other
guard in this crate reads its artifact directly — `prevent-ai-author` opens the
message file, `no-private-repo-names-staged` runs `git diff` — and decides on
the spot. That suffices for a rule about bytes. It is the wrong shape for a rule
about what a change *means*, because the tool that establishes meaning is the
part most likely to be replaced: a regex today, a parser tomorrow, a compiler's
graph after that.
A rule written against the reader is rewritten with it. Issue 165 asks for the
seam between the two, and this is the seam as built, with what was measured
building it.

## The separation

Three components, named as the code names them.

A **provider** reads one artifact and reports facts in one shape. Three are
compiled in: `git` over the commit message, as git records it and not as the
hook receives it, `tree-sitter` over the function declarations in the trees at
`HEAD` and in the index, and `diff-text` over the added and removed lines of
the staged diff. A provider never decides anything. Both file providers put
`file = "removed"` on each `FunctionRemoved` from a file the index no longer
holds, one spelling for the one fact, so a policy can tell a function deleted
with its file from one deleted out of a file that stays.

**Evidence** is the shape. One item is a kind, a subject, properties, a
provider and a revision:

```rust
pub(crate) struct Evidence {
    pub kind: Kind,                              // FunctionRemoved, CommitIntent, ...
    pub subject: String,                         // `lib.rs::drop_me`, or a subject line
    pub properties: BTreeMap<&'static str, String>,
    pub provider: Provider,                      // name, strength, claims
    pub revision: String,                        // `HEAD..index`, `index`, a sha
}
```

The kinds are exactly the six the three providers produce: `FunctionAdded`,
`FunctionRemoved`, `SignatureChanged`, `CommitIntent`, `HumanChange`,
`AgentChange`. The issue lists nineteen; a kind nothing reports is
configuration nobody can read, and this repository refuses that shape
everywhere else.

A **policy** is handed the body of everything the providers reported and
returns a refusal, a clean verdict, or the error that says it could not decide.
`removed-function-named` is the one policy: every function the change removes
must be named in the message. It reads `FunctionRemoved` from whoever reported
it and `CommitIntent` from whoever reported that, and it never names a provider.
`tests/structural_evidence.rs` reads the provider names off `src/evidence/` and
refuses a policy file that contains one, so the rule holds on the next edit and
not only on this one.

## Provenance, and what strength means

A fact carries who established it, how, and over what.

The **name** is for the reader of a refusal. `lib.rs: drop_me is removed by
this change and the commit message does not name it (seen by tree-sitter)` is a
sentence somebody can act on; the same sentence with the name removed is one
they have to reconstruct.

The **strength** is a variant and not a number, and its purpose is the order:

```rust
pub(crate) enum Strength { Inferred, Heuristic, Proven }   // Proven > Heuristic > Inferred
```

`Proven` is a parser or git reporting the fact. `Heuristic` is a text pattern
having matched. `Inferred` is a model or an agent asserting it. A variant rather
than a confidence score because the issue's requirement — AI confidence alone
must never be sufficient — is a thing a threshold cannot promise and a variant
cannot break: there is no value of `Inferred` that compares greater than
`Heuristic`.

The **revision** is what the provider read. Two facts about one subject at two
revisions are about two things, and the contradiction rule below is scoped to
one revision for that reason.

The rules the strength buys are three, and they are methods on the body rather
than conventions a policy is asked to remember:

1. **Weaker evidence may add a refusal.** A `Heuristic` removal beside a
   `Proven` provider that read the file and reported none is still reported to
   the policy, which refuses on it.
2. **Weaker evidence may never supply a clean verdict where a stronger
   provider could not look.** This is the rule this record exists for, and it
   is the subject of the next section.
3. **Weaker evidence may never cancel a stronger provider's refusal.** An
   `Inferred` `FunctionAdded` beside a `Proven` `FunctionRemoved` for the same
   subject changes nothing; the unit test drives exactly that pair.

The policy reads all three through one query:

```rust
pub(crate) enum Established<'a> {
    Proven(Vec<&'a Evidence>),                          // read by a parser; empty is clean
    HeuristicOnly { found: Vec<&'a Evidence>,           // read by a pattern only;
                    unread: Vec<&'a Unavailable> },     // empty is clean only if `unread` is
    Unavailable(Vec<&'a Unavailable>),                  // nobody who could look, looked
}
```

`Inferred` facts are in the body for a reader and in no variant. An `Inferred`
item alone yields `Unavailable` with nothing unread, which the policy turns
into exit 2 — nothing deterministic read the change — and never into a
refusal. No provider produces `Inferred` today. The variant is exercised by a
test double, because the seam has to exist before the first agent-native
provider arrives, not be retrofitted around it.

## What "could not look" is, measured

ADR 0003 measured `ast-grep` exiting 0 over a source whose parse collapsed, and
ADR 0004 measured CodeQL doing the same behind a `Successfully created`. Both
records end with the same requirement: a clean run is evidence only when
something separately establishes that the analyzer could read what it was
pointed at. The evidence layer is where that requirement stops being a note in
each adopter's memory.

Measured here, with the grammar this binary links, over a two-function file
with one character removed:

```text
fn keep() {          <- closing brace gone
fn drop_me() {}
```

```text
has_error=true  functions=["drop_me"]
sexp=(source_file (ERROR (identifier) (parameters) (function_item name: ...)))
```

The walk lists one function of the two the file declares; `keep` is inside an
`ERROR` node and the walk does not see it. Put that file at `HEAD` and stage a
version with `keep` deleted, and a provider that compared the two lists would
report nothing removed — `keep` was in neither list — which is the verdict
from a change that removes nothing. The same walk over the same file with an
unterminated string literal instead:

```text
has_error=true  functions=["drop_me", "keep"]
```

Both functions, this time. The recovered tree is not predictably shorter than
the file; it is unpredictably shorter, which is why the provider tests the
flag and not the count. A file with an `ERROR` or `MISSING` node on either side
makes the whole `tree-sitter` answer `Unavailable`, naming the file and the
line:

```text
tree-sitter: lib.rs:1 at the index did not parse, so the functions it declares were never read
```

`Unavailable` is a variant of the provider's answer, not an empty list of
facts, so it cannot be mistaken for one downstream.

## Deterministic fallback

What the policy does with an `Unavailable` is decided by the body and not by
the policy, and it is decided the same way every time:

- `tree-sitter` could not read a file and `diff-text` found no removal in it:
  `HeuristicOnly` with a non-empty `unread`, which is not clean. The run exits
  2, naming the file and the line. The regex's silence and the parser's
  silence do not add up to a verdict.
- `tree-sitter` could not read a file and `diff-text` found a removal in it:
  the removal is a refusal, exit 1, seen by `diff-text`. A violation outranks a
  surface that could not be read, which is `error::verdict`'s ranking and the
  property the Kani proofs hold over it.
- Two `Proven` providers report opposite kinds about one subject at one
  revision: a contradiction, refused naming both. Picking the one the policy
  prefers would be a second checker over one answer, which this repository has
  watched disagree before (`no-stale-hook-pins` and the script it replaced).
- Nothing that could look, looked: exit 2.

Each of the four is a unit test in `src/evidence.rs` or `src/policy.rs`, and
the first two are also driven through the binary in `tests/evidence_cli.rs`.

## Substitution, measured

The issue's criterion is that a provider can be replaced without the policy
being rewritten. `src/policy.rs` does the replacement: one staged removal, one
predicate, judged over a body from `git` and `tree-sitter` and then over a body
from `git` and `diff-text`.

```text
lib.rs: `drop_me` is removed by this change and the commit message does not name it (seen by tree-sitter)
lib.rs: `drop_me` is removed by this change and the commit message does not name it (seen by diff-text)
```

The reports differ in the provider's name and in nothing else, and the
structural test is what makes that a property rather than an observation: the
policy could not have been written against either provider, because the file
may not spell either one.

## How this stays inside ADR 0003 and ADR 0005

**Not a rule DSL over tree-sitter.** ADR 0003 records why: a structural rule
this repository needs is cheaper as a test beside the code it constrains, and a
consumer's is `ast-grep`'s job. Nothing here changes that. A policy is a Rust
predicate in this binary, dispatched by name from `guard::evaluate` like every
other built-in, and `removed-function-named` is a function in
`src/policy/removed_function_named.rs`. Nobody writes one in a config file.

**Not a plugin API.** ADR 0005 found that what providers share is three
questions, not an interface, and that an interface covering all of them would
describe none of them. The `Source` trait here is two methods, and it is the
shape of an answer to the third question — "can it say I could not look, and
does it" — for providers that live *inside* this binary. `ast-grep`, `zizmor`
and `cargo-deny` are still claimed through the local tier exactly as before;
nothing external implements this trait, and nothing is loaded.

**Providers are compiled in.** Adding one is a Rust type in `src/evidence/` and
a line in `evidence::observe`. That is the same arrangement `EVERY_BUILTIN` has
for guards, and for the same reason: a provider a config could name is a
provider that could be named and never run.

**One grammar table.** `tree-sitter` reads its grammars off
`comments::Language::grammar`, the table the comment rules already read. A
language added there is a language the provider reads; a second table would be
the copy that fell behind.

## Decisions

**A guard about what a change means reads evidence and not an artifact.**
`removed-function-named` is the first; the seam is what the next one is written
against.

**A fact carries its provider, its strength and its revision, and the strength
is a variant.** Weaker adds, never supplies a clean verdict where stronger could
not look, never cancels stronger.

**A provider that could not look says so in its answer, and the answer is a
variant.** A file the parser could not read makes the whole `tree-sitter`
answer `Unavailable`, naming the file and the line.

**Could-not-look exits 2, a contradiction between `Proven` providers is refused
naming both, and a policy may not name a provider.** The first two are body
methods; the third is `tests/structural_evidence.rs`.

**AI-derived evidence is `Inferred` by construction, and no provider produces
it.** The variant is tested with a double so the seam is proven before it is
needed.

## What was deliberately not built

- **The other kinds the issue lists.** `symbol_defined`, `dependency_edge`,
  `test_failed` and the rest have no provider here, so they have no variant.
  The first compiler or LSP provider brings its kinds with it.
- **A confidence number.** Three variants are what the rules need; a score
  would invite the threshold this record exists to refuse.
- **Evidence at `pre-push`.** The two file providers read the index against
  `HEAD`; a pushed range has no index, and both answer `Unavailable` there
  rather than reading the wrong tree. The set installs `commit-msg` only.
- **A second policy.** One predicate over two providers demonstrates the seam.
  The next policy is what shows the schema was not shaped around the first.

## What this changes today

One bundled set, `unnamed-removal`, carrying one guard at `commit-msg`. This
repository inherits it. `prevent-ai-author` reads its marker patterns from the
`git` provider rather than carrying its own, so the guard that refuses a marker
and the provider that reports one cannot drift into two definitions. Nothing
else in the binary is touched, and no existing verdict changes.
