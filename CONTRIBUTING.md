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
uv run --no-project scripts/build_reference.py
prek run --all-files --hook-stage manual    # or: pre-commit run ...
```

## Two lines in a fork that are not yours

`policy/principles.toml` is this repository's own policy, and it is also the
worked example — so it declares facts about *this* checkout that a fork has to
change. Both are at the top of the file:

```toml
owner = "HackingGate"     # where this repository's pushes may go
visibility = "public"     # whether what it publishes is readable by everyone
```

`owner` is not a claim on the project. `unowned-push` refuses to run without it
because the alternative — reading the owner off `origin` — is tautological for
the one remote most likely to be wrong: repointing `origin` at somebody else's
remote also repoints the allow-list. So a fork changes that line to its own
owner, and `prevent-public-push` refuses the first push until it does. That is
the guard working, not a misconfiguration.

`visibility` decides whether the private-name guards fire here at all. A private
fork sets `private` and they stand down; a public one leaves `public`.

A workspace holding many repositories writes both lines many times — measured
across one fleet, 78 `owner` lines for seven distinct values. `owner_from` and
`visibility_from` take a command whose stdout is the value instead, so the fact
lives once outside the tree. They move the declaration and never look it up:
every way the command can fail to answer is exit `2`, because what a missing
declaration falls back to is the owner read off `origin` and the forge's view of
a visibility that is about to change. See
[REFERENCE.md](docs/REFERENCE.md#reading-a-repository-fact-from-a-command).

A third fact is about *your machine* rather than your fork, and no line in the
policy file carries it. The `private-names` set the policy inherits reads
`$XDG_CONFIG_HOME/principles/private-owners` (else
`$HOME/.config/principles/private-owners`) for the organisations whose names
must not be published, and it says the file may be absent: on a clone without
it, the guard reports on stderr that the file is not there and what is not being
checked without it, and your commit proceeds. You do not have to create
anything. If you keep such a list, put it at that path, or point
`private_owners_file` at it from the top of the policy file, and the two forms
the note names start being checked as well. See
[REFERENCE.md](docs/REFERENCE.md#where-the-owner-list-lives).

## Working on the engine

The checks sit on three rungs, and which rung one sits on is a statement about
what it costs to run. The commit stage is what can answer from the tree in front
of it: `cargo fmt --check`, the catalog gates, the content scan, and the guards
registered for the stage. Nothing there compiles the test tree and nothing there
opens a socket.

The push stage is where the crate is built and exercised:

```sh
cargo test --quiet                    # the engine suite
cargo clippy --quiet --all-targets    # the lint profile declared in Cargo.toml
```

Both stood in front of every commit until they did not. A full compile and test
pass at every save point is how a gate teaches `--no-verify` — the cost lands on
the commits that touch no Rust as well, and a flag learned to skip a slow suite
skips the guards standing beside it. At `pre-push` the same two still refuse
before anything leaves the machine, which is the moment refusing is worth the
wait. `uphold guard --stage pre-push` runs there with them.

The manual rung is the host and the network, which neither a staged file nor a
pushed range can react to:

```sh
scripts/deps.sh check          # rustup, rustc >= the MSRV, python3, the coverage pair
scripts/coverage.sh            # line coverage, refused under the floor in the script
uphold guard --stage manual    # the guards that ask a remote about a pin or a name
```

All three are `manual`-stage hooks under pre-commit and prek, and named groups
under lefthook (`lefthook run preflight`, `lefthook run coverage`, `lefthook run
uphold-manual`), so whichever runner is installed can reach them. The coverage
floor lives in `scripts/coverage.sh` and nowhere else — the workflow calls the
same script, so the number that fails a push is the number that fails locally.
Raise it in the commit that earns it.

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

### Proving the fail-closed property

```sh
cargo install --locked kani-verifier && cargo kani setup
cargo kani -j --output-format=terse        # ten harnesses, about two minutes
lefthook run proofs                        # the same, as the manual group
```

Two places in this crate turn an unknown into a number a caller acts on, and
each carries a `#[cfg(kani)] mod proofs` that states what it must do over every
input rather than over the handful a unit test can name.

`error::verdict` and `Exit::of`, over every pair of counts and every run: a run
that could not look never exits 0, a violation outranks an unread surface,
clean means read everything and found nothing, and a run that stopped on an
error exits 2. Change `could_not_look > 0` to `could_not_look > 1` and every
in-crate unit test still passes -- including the four that test `verdict`
directly, since they name 3 and 0 and never 1. Kani refuses in 15 milliseconds,
with the counterexample.

`text::over_kinds`, the step every published-text seam but the shim takes from
what each kind of rule answered to the verdict, over every seam and every
combination of answers: clean exactly when every consulted kind looked and
found nothing, exit 2 whenever one could not look, each consulted kind asked
once and no other kind asked at all, and the same answers giving the same
verdict. `text::load_for` is proven to hand a policy that did not load on as an
error, with `config::load` replaced by a loader that always fails. Swallowing a
kind's error in `over_kinds`, or skipping one consulted kind, fails three of the
five.

What the harnesses do not reach is stated in them: the rule bodies (a regex, a
literal search, a command source, a guard reading the repository), the shim's
per-rule dispatch, and everything that reads a file or runs a process. Those
stay under the tests they have.

Manual, not pre-push. Two of the harnesses take one to two minutes of solver
time each, and the toolchain is half a gigabyte fetched by `cargo kani setup`,
which is past what a push should wait for and not something every contributor
has. CI runs them as a job of their own; locally they are `lefthook run
proofs`, or the `kani` hook at the manual stage of pre-commit and prek.

The MSRV is written twice, in `Cargo.toml` as `rust-version` and in
`toolchain.toml` as the rustc `want`, because cargo and the preflight cannot read
each other's manifest. Bump both together; `tests/test_toolchain.py` refuses a
tree where they disagree. Nothing builds the crate on that version: every build
runs on the `stable` that `rust-toolchain.toml` names, and the number's work is
done by cargo, which resolves dependencies against it.

Write `enforcement.checks` as a brief for whoever builds the check, and
`enforcement.limits` as what that person will not be able to observe. Neither is
a check. No field of a record is ever emitted by a tool at runtime: a tool
carrying prose has no condition on which to emit it, so it emits always and
teaches readers to skip it, or never and enforced nothing. Adding an entry to
`policy/upheld.toml` requires a rule that already fires.

## Cutting a release

Bump `version` in `Cargo.toml`, merge, then:

```sh
git tag vX.Y.Z && git push --tags
```

The tag is the whole trigger. `.github/workflows/release.yml` is generated by
`dist` from `dist-workspace.toml` and builds the archives, the shell installer
and the GitHub Release. The release body is the install instructions and the
artifact table; the change record is the merged pull requests between the
previous tag and this one, which git history and the compare view already
hold. Edit the workflow through `dist-workspace.toml` and `dist generate`,
never by hand: the next `dist init` rewrites it.

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
