# Contributing

This is a filtered collection, not a popularity list.

A proposed entry should answer four questions:

1. What recurring engineering decision or failure does it improve?
2. Under what conditions is it valid?
3. What does it cost or conflict with?
4. What, if anything, can be enforced without guessing?

## Adding an entry

1. Copy an existing TOML record.
2. Use a stable kebab-case `id` and matching filename.
3. Prefer the narrowest defensible claim.
4. Add at least one serious source.
5. Link related and conflicting entries by ID.
6. Rebuild the generated index and run everything CI runs:

```sh
python3 scripts/build_reference.py
prek run --all-files --hook-stage manual    # or: pre-commit run ...
```

## Working on the engine

The Rust side has two checks CI runs that the commit stage does not, because
both are about the host or the whole tree rather than about a staged file:

```sh
scripts/deps.sh check     # rustup, rustc >= the MSRV, python3, the coverage pair
scripts/coverage.sh       # line coverage, refused under the floor in the script
```

Both are `manual`-stage hooks under pre-commit and prek, and named groups under
lefthook (`lefthook run preflight`, `lefthook run coverage`), so whichever runner
is installed can reach them. The coverage floor lives in `scripts/coverage.sh`
and nowhere else — the workflow calls the same script, so the number that fails a
push is the number that fails locally. Raise it in the commit that earns it.

Editing anything under `policy/base/` means regenerating the set lock in the
same commit, because a bundled set ships inside the binary and its diff exists
nowhere else:

```sh
cargo run --quiet -- rules --sets --json > policy/base/sets.lock.json
```

`tests/base_set_lock.rs` refuses a tree where the two disagree. Read the diff
before you regenerate — it is what a consumer would have felt and never seen.

A rule added to a bundled set needs a line in `tests/base_set_corpus.rs`: at
least one sample it must refuse, and the forms it must let through.
`every_content_rule_in_every_bundled_set_is_in_the_corpus` fails without one.
The reason it is mandatory rather than encouraged is that a rule which stops
matching produces **no output at all** — the gate goes green and stays green,
and no report anywhere says the check has stopped working.

### Where a test's fixture lives

Every CLI test builds a real repository, under `<temp>/uphold-tests/<pid>/`, and
the first fixture in a run sweeps every sibling whose process is gone. Use
`support::scratch("name")` in `tests/`, `crate::fixture::scratch("name")` in
`src/`, and do not reach for `std::env::temp_dir()` directly.

The reason is measured rather than stylistic: the old shape cleared a fixture on
the way IN and never on the way out, which frees nothing, because the directory
name carries the pid precisely so that it cannot collide with a live run. One
working session left 84,992 directories under `/tmp`, filled 15 GB of a 16 GB
tmpfs, and killed a `cargo mutants` run with `No space left on device` -- which
that run then reported as 158 mutants "unviable". A tool reporting a measurement
it could not make is what this repository exists to refuse.

### The dependency graph

```sh
cargo install cargo-deny
cargo deny check
```

`deny.toml` says what this crate may depend on and under what terms: advisories,
licences named one at a time, no wildcard version, and crates.io as the only
source. It answers three questions no rule in `policy/principles.toml` can,
because they are facts about the dependency graph rather than about this tree's
files -- which is the boundary between a rule here and an external provider.

It is deliberately not wired into a hook. The advisory half reaches the network,
and this repository already decided where that belongs: `no-stale-hook-pins`
runs at pre-push and manual and not at every commit, because a check that adds a
network round trip to a commit is one somebody switches off.

Keep the licence allow-list to what the tree carries. `cargo deny` reports an
allowance that matched nothing, and an entry describing no dependency reads as a
decision while doing nothing.

### Mutation testing

Coverage says a line ran. It does not say a test would have noticed the line
being wrong, and the failures this repository keeps having are exactly that
shape: a check that could not look reporting a pass.

```sh
cargo install cargo-mutants
cargo mutants --file src/check.rs -j 4      # one module, minutes
cargo mutants -j 4                          # the crate, hours
```

Scope it. Measured here: `src/check.rs` is 98 mutants and about eight minutes
at `-j 4`; the crate is 1,573 mutants, which is hours. One module at a time is
the useful unit, and the modules worth starting from are the ones that decide an
exit state -- `check.rs`, `config.rs`, `guard/mod.rs`, `pins.rs` -- because the
failures this repository keeps having are `UNKNOWN -> PASS` and those are where
an unknown becomes a verdict.

A surviving mutant is a claim about the tests, not about the code: something
could be wrong here and every test would still pass. Read it before writing
anything. Some survivors are equivalent mutants and some are unreachable, and
both are worth a sentence in the commit rather than a test written to silence
them.

### Proving the exit-state ranking

```sh
cargo install --locked kani-verifier && cargo kani setup
cargo kani                                 # four harnesses, about a second each
```

`error::verdict` is the one function in this crate where an unknown becomes a
number a caller acts on, and `#[cfg(kani)] mod proofs` states what it must do
over every pair of counts rather than over the four pairs a unit test can name:
a run that could not look never exits 0, a violation outranks an unread surface,
and clean means read everything and found nothing.

The reason it is worth a model checker for this one function and for nothing
else here is measured. Change `could_not_look > 0` to `could_not_look > 1` and
every one of the 197 in-crate unit tests still passes -- including the four that
test `verdict` directly, since they name 3 and 0 and never 1. Kani refuses in
15 milliseconds, with the counterexample. The rest of this crate reads files,
runs git and formats reports, none of which CBMC can say anything useful about.

Not wired into a hook, and for the same reason as `cargo deny`: the toolchain is
half a gigabyte fetched by `cargo kani setup`, which is not something a commit
should wait for. The proofs are cheap once it is installed.

The MSRV is written twice, in `Cargo.toml` as `rust-version` and in
`toolchain.toml` as the rustc `want`, because cargo and the preflight cannot read
each other's manifest. Bump both together; `tests/test_toolchain.py` refuses a
tree where they disagree, and CI builds the crate on the declared MSRV rather
than on whatever `stable` is that week.

Write `enforcement.checks` as a brief for whoever builds the check, and
`enforcement.limits` as what that person will not be able to observe. Neither is
a check. No field of a record is ever emitted by a tool at runtime: a tool
carrying prose has no condition on which to emit it, so it emits always and
teaches readers to skip it, or never and enforced nothing. Adding an entry to
`policy/upheld.toml` requires a rule that already fires.

## Rejection criteria

An entry will normally be rejected when it is:

- a context-free slogan;
- a renamed duplicate;
- vendor marketing presented as a general law;
- impossible to distinguish from its opposite in practice;
- framed as universally correct despite known trade-offs;
- coupled to a transient framework API;
- an enforcement proposal that cannot observe the claimed property.

## Review standard

Review the semantic record before the prose. Ask whether the claim, scope,
conflicts, and enforcement limits agree. Grammar can be corrected later; an
incorrect boundary becomes policy debt.
