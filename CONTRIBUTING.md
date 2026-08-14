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
