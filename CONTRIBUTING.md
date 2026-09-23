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
6. Add the record's `include_str!` pair to `RECORDS` in `src/catalog.rs`, in
   id order. The binary carries the catalog compiled in, and `cargo test`
   refuses a tree where the list and `ls principles/` disagree.
7. Rebuild the generated index and the compiled review documents, then run
   everything CI runs:

```sh
uv run --no-project scripts/build_reference.py
uv run --no-project uphold_check.py --review --emit
prek run --all-files --hook-stage manual    # or: pre-commit run ...
```

Write `enforcement.checks` as a brief for whoever builds the check, and
`enforcement.limits` as what that person will not be able to observe. Neither is
a check. No field of a record is emitted by a tool at runtime: prose has no
condition on which to emit it, so it would be emitted always and ignored, or
never. Adding an entry to `policy/upheld.toml` requires a rule that already
fires.

## Repository facts a fork must change

`policy/principles.toml` is this repository's own policy and also the worked
example, so it declares facts about *this* checkout that a fork has to change.
Both are at the top of the file:

```toml
owner = "HackingGate"     # where this repository's pushes may go
visibility = "public"     # whether what it publishes is readable by everyone
```

`owner` is not a claim on the project. `unowned-push` requires it because the
alternative, reading the owner from `origin`, is circular for the remote most
likely to be wrong: repointing `origin` elsewhere would also repoint the
allow-list. A fork changes that line to its own owner, and
`prevent-public-push` refuses the first push until it does. That is the guard
working as intended.

`visibility` decides whether the private-name guards run at all. A private fork
sets `private` and they stand down; a public one keeps `public`.

A workspace holding many repositories repeats both lines many times; one fleet
had 78 `owner` lines with seven distinct values. `owner_from` and
`visibility_from` take a command whose stdout is the value instead, so the fact
is stored once outside the tree. Every way the command can fail to answer is
exit `2`. See
[REFERENCE.md](docs/REFERENCE.md#reading-a-repository-fact-from-a-command).

A third fact concerns *your machine* rather than your fork, and no line in the
policy file carries it. The `private-names` set reads
`$XDG_CONFIG_HOME/principles/private-owners` (else
`$HOME/.config/principles/private-owners`) for the organizations whose names
must not be published. The file is optional: without it, the guard reports on
stderr what is not being checked, and the commit proceeds. If you keep such a
list, put it at that path, or point `private_owners_file` at it from the top of
the policy file, and the two forms the note names are checked as well. See
[REFERENCE.md](docs/REFERENCE.md#where-the-owner-list-lives).

## Working on the engine

The checks run at three stages, chosen by cost. The commit stage runs what can
answer from the tree alone: `cargo fmt --check`, the catalog gates, the content
scan, and the guards registered for the stage. Nothing there compiles the test
tree or opens a socket.

The push stage builds and tests the crate:

```sh
cargo test --quiet                    # the engine suite
cargo clippy --quiet --all-targets    # the lint profile declared in Cargo.toml
```

These used to run at every commit. A full compile and test pass on every commit
costs time even on commits that touch no Rust, and encourages `--no-verify`,
which also skips the guards. At `pre-push` they still refuse before anything
leaves the machine. `uphold guard --stage pre-push` runs there with them.

The manual stage covers the host and the network:

```sh
scripts/deps.sh check          # rustup, rustc >= the MSRV, python3, the coverage pair
scripts/coverage.sh            # line coverage, refused under the floor in the script
uphold guard --stage manual    # the guards that ask a remote about a pin or a name
```

All three are `manual`-stage hooks under pre-commit and prek, and named groups
under lefthook (`lefthook run preflight`, `lefthook run coverage`,
`lefthook run uphold-manual`). The coverage floor is defined only in
`scripts/coverage.sh`; the workflow calls the same script, so CI and local runs
enforce the same number. Raise it in the commit that earns it.

Editing anything under `policy/base/` requires regenerating the set lock in the
same commit, because a bundled set ships inside the binary and would otherwise
change with no diff:

```sh
cargo run --quiet -- rules --sets --json > policy/base/sets.lock.json
```

`tests/base_set_lock.rs` refuses a tree where the two disagree. Review the
lock diff: it is the change consumers will receive.

A rule added to a bundled set needs an entry in `tests/base_set_corpus.rs`: at
least one sample it must refuse, and the forms it must let through.
`every_content_rule_in_every_bundled_set_is_in_the_corpus` fails without one.
This is mandatory because a rule that stops matching produces **no output at
all**: the gate stays green and nothing reports that the check stopped working.

The MSRV is written twice, in `Cargo.toml` as `rust-version` and in
`toolchain.toml` as the rustc `want`, because cargo and the preflight cannot read
each other's manifest. Bump both together; `tests/test_toolchain.py` refuses a
tree where they disagree. Nothing builds the crate on that version: every build
runs on the `stable` that `rust-toolchain.toml` names, and cargo uses the MSRV
when resolving dependencies.

### Where a test's fixture lives

Every CLI test builds a real repository under `<temp>/uphold-tests/<pid>/`, and
the first fixture in a run removes every sibling whose process has exited. Use
`support::scratch("name")` in `tests/`, `crate::fixture::scratch("name")` in
`src/`, and do not use `std::env::temp_dir()` directly.

The previous approach cleared a fixture on creation and never afterwards, which
freed nothing, because the directory name includes the pid so it cannot collide
with a live run. One working session left 84,992 directories under `/tmp`,
filled 15 GB of a 16 GB tmpfs, and caused a `cargo mutants` run to fail with
`No space left on device`, which it then reported as 158 mutants "unviable".

### The dependency graph

```sh
cargo install cargo-deny
cargo deny check
```

`deny.toml` defines what this crate may depend on and under what terms:
advisories, licences named one at a time, no wildcard versions, and crates.io as
the only source. These are facts about the dependency graph rather than about
the tree's files, so no rule in `policy/principles.toml` can check them.

It is not wired into a hook. The advisory check uses the network, and network
checks run at pre-push or manual, not at every commit, for the same reason
`no-stale-hook-pins` does.

Keep the license allow-list to what the tree uses. `cargo deny` reports an
allowance that matched nothing; remove such entries.

### Mutation testing

Coverage shows that a line ran, not that a test would notice the line being
wrong. The recurring failure mode here is of that kind: a check that could not
look reporting a pass.

```sh
cargo install cargo-mutants
cargo mutants --file src/check.rs -j 4      # one module, minutes
cargo mutants -j 4                          # the crate, hours
```

Run it one module at a time. Measured here: `src/check.rs` is 98 mutants and
about eight minutes at `-j 4`; the crate is 1,573 mutants, which takes hours.
Start with the modules that decide an exit state (`check.rs`, `config.rs`,
`guard/mod.rs`, `pins.rs`), because those are where an unknown becomes a
verdict.

A surviving mutant says something about the tests, not the code: the code could
be wrong here and every test would still pass. Read it before writing anything.
Some survivors are equivalent or unreachable; note those in the commit message
rather than writing a test to silence them.

### Proving the fail-closed property

```sh
cargo install --locked kani-verifier && cargo kani setup
cargo kani -j --output-format=terse        # ten harnesses, about two minutes
lefthook run proofs                        # the same, as the manual group
```

Two places in this crate turn an unknown into a number a caller acts on, and
each carries a `#[cfg(kani)] mod proofs` that states what it must do over every
input rather than over the few a unit test can name.

`error::verdict` and `Exit::of`, over every pair of counts and every run: a run
that could not look never exits 0, a violation outranks an unread surface,
clean means everything was read and nothing found, and a run that stopped on an
error exits 2. Changing `could_not_look > 0` to `could_not_look > 1` passes
every in-crate unit test, including the four that test `verdict` directly,
since they use 3 and 0 and never 1. Kani refuses it in 15 milliseconds, with the
counterexample.

`text::over_kinds`, the step every published-text seam except the shim takes
from what each kind of rule answered to the verdict, over every seam and every
combination of answers: clean exactly when every consulted kind looked and
found nothing, exit 2 whenever one could not look, each consulted kind asked
once and no other kind asked, and the same answers giving the same verdict.
`text::load_for` is proven to return an error for a policy that did not load,
with `config::load` replaced by a loader that always fails. Swallowing a kind's
error in `over_kinds`, or skipping one consulted kind, fails three of the five.

The harnesses state what they do not reach: the rule bodies (a regex, a literal
search, a command source, a guard reading the repository), the shim's per-rule
dispatch, and everything that reads a file or runs a process. Those remain
covered by tests.

The proofs run at the manual stage, not pre-push. Two of the harnesses take one
to two minutes of solver time each, and `cargo kani setup` fetches a toolchain
of about half a gigabyte. CI runs them as a separate job; locally they are
`lefthook run proofs`, or the `kani` hook at the manual stage of pre-commit and
prek.

## Cutting a release

Bump `version` in `Cargo.toml`, merge, then:

```sh
git tag vX.Y.Z && git push --tags
```

The tag is the only trigger. `.github/workflows/release.yml` is generated by
`dist` from `dist-workspace.toml` and builds the archives, the shell installer
and the GitHub Release. The release body holds the install instructions and the
artifact table; the change record is the merged pull requests between the
previous tag and this one. Edit the workflow through `dist-workspace.toml` and
`dist generate`, never by hand, because the next `dist init` rewrites it.

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
