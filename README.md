# uphold

A filtered catalog of engineering principles, and a binary that holds a
repository to the ones it claims to enforce.

Catalogs of principles are common. What is not: a file where a repository names
the *rule* enforcing each principle, checked against that repository's own
configuration, so the claim fails loudly when the rule is removed or disabled.
That file is [`policy/upheld.toml`](policy/upheld.toml). The binary that
reads it — plus the content rules, the Git guards, and the command shims — is
`uphold`. You uphold a *principle*; what does it is a *rule*, which is why every
claim in that file is an `[[enforce]]` block naming one.

- [`docs/REFERENCE.md`](docs/REFERENCE.md) — every config field, seam by seam
- [`docs/DESIGN.md`](docs/DESIGN.md) — why it is shaped this way
- [`QUICK_REFERENCE.md`](QUICK_REFERENCE.md) — the catalog, one page

## Install

**pre-commit / prek** — same manifest, no Rust toolchain needed (`language: rust`
bootstraps).

```yaml
# .pre-commit-config.yaml
default_install_hook_types: [pre-commit, commit-msg, pre-merge-commit, pre-push]
repos:
  - repo: https://github.com/HackingGate/uphold
    rev: v1.0.0
    hooks:
      - id: uphold-check            # the claims still hold
      - id: uphold-scan             # the content policy
      - id: uphold-scan-text        # ... over the commit message
      - id: uphold-guard            # the guards, one id per stage
      - id: uphold-guard-commit-msg
      - id: uphold-guard-merge
      - id: uphold-guard-push
      - id: uphold-guard-manual     # the slow ones, for CI
```

One id per stage because the stage is an argument. Pinning all five costs
nothing: which guards fire is decided by `policy/principles.toml`.

**lefthook** — no manifest format, so include the config this repo ships, then
`lefthook install`. It runs commands rather than bootstrapping a language, so
the binary must be on PATH.

```yaml
# lefthook.yml
remotes:
  - git_url: https://github.com/HackingGate/uphold
    ref: v1.0.0
    configs:
      - hooks/lefthook.yml
```

```sh
cargo install --git https://github.com/HackingGate/uphold --tag v1.0.0
```

## Declare what enforces what

```toml
# policy/upheld.toml
[[enforce]]
principle = "least-privilege"
rule = "prevent-public-push"

[[enforce]]
principle = "complete-mediation"
rule = "prevent-ai-author"
```

`rule` is the rule's own id, resolved against every seam this repo runs.

```text
reconciled 2 enforcement claims:
  least-privilege <- prevent-public-push  enforced by uphold
  complete-mediation <- prevent-ai-author  enforced by uphold
```

A rule enforced at more than one seam is the ordinary case; every seam is
reported. A claim is refused when no seam supplies the rule, or when it names a
principle the catalog does not define, or one that is deprecated or marked
`enforcement.automatable = "no"`. A seam that could not be read is reported as
could-not-look, never as a false claim.

A principle with no rule yet does not belong in this file. Build the rule first.

Exit codes, everywhere: `0` clean, `1` a claim is false / a violation, `2` could
not look — see [`explicit-unknown`](principles/explicit-unknown.toml).

## Commands

```sh
uphold scan                     # content rules over the tree
uphold scan --text -            # a commit message, release note, PR body
uphold guard --stage pre-push   # the guards for that git hook
uphold shim gh pr create ...    # stand in front of a command, then exec
uphold audit --for-publication  # before flipping private -> public

uphold_check.py --explain ID    # one record in full; also accepts a name
uphold_check.py --list          # every id in the catalog
uphold_check.py --coverage      # which rules here carry a principle
uphold_check.py --init          # a starter declaration
uphold_check.py --oscal         # OSCAL component-definition JSON
uphold_check.py --review        # what routes to the review tier
```

## The three seams

One config file, `policy/principles.toml`, one flat id namespace. A rule says
**what it checks** in the field it writes, and **where it runs** in up to three
tables — an absent table is a place the rule does not run. Full field reference:
[`docs/REFERENCE.md`](docs/REFERENCE.md).

**`uphold scan`** evaluates content rules over the repository's own files,
using ripgrep's search libraries, so a pattern written against `rg` keeps
meaning what it meant. `--text -` runs it over prose that never becomes a file.

**`uphold guard --stage STAGE`** reads an *act* rather than a tree: the
message about to be recorded, the identity about to be stamped, the range about
to be pushed. Eleven built-in guards, registered by `git.hooks`.
`UPHOLD_ALLOW=<id>` overrides one invocation.

**`uphold shim`** stands in front of a command, checks what the invocation
is about to publish, and execs through. A pull-request body reaches a public API
without passing a single hook; so does a branch name, an issue title, and a
commit written under `--no-verify`. Put a link named for the command on PATH
ahead of the real one — that is what a multicall binary is for, and why there is
no installer.

## The catalog

Canonical records are TOML under [`principles/`](principles/). Every entry must
state what it claims, the problem it addresses, where it applies and where it
does not, its costs and conflicts and failure modes, whether it is enforceable
by review/lint/test/runtime/governance, and its sources. Every field, plus the
`kind`, `status` and enforcement-level vocabularies:
[`principles/SCHEMA.md`](principles/SCHEMA.md).

```toml
id = "single-authoritative-source"
title = "Single Authoritative Source"
kind = "principle"
status = "seed"
domains = ["data", "architecture", "governance"]

summary = "One authority owns each fact; copies may exist."
claim = """
Each authoritative fact should have one designated ownership and update authority.
"""

[enforcement]
level = "governance"
automatable = "partially"
checks = ["Require an owner for every canonical data entity."]
```

Lookup takes a name or an id — both go through one analysis chain (NFKC,
casefold, drop combining marks, non-alphanumeric to separator), so
`Fail-Safe Defaults` and `fail safe defaults` are one key.
[`name-index.json`](name-index.json) publishes that mapping for non-Python
consumers.

```sh
./uphold_check.py --explain "combinatorial explosion"
./uphold_check.py --explain parameterize-do-not-enumerate
```

## Local use

Requires Python 3.11+ (`tomllib`). Everything this repository runs on itself is
listed in [`.pre-commit-config.yaml`](.pre-commit-config.yaml) and its
[`lefthook.yml`](lefthook.yml) equivalent. The two ask the same questions of the
tree, with one exception a lefthook box has to know about: the whitespace and
parse checks from `pre-commit-hooks` are Python hooks with no standalone binary,
so lefthook cannot run them and `uphold scan` does not cover them either.

```sh
prek install                                  # or: pre-commit install
prek run --all-files --hook-stage manual      # everything CI runs
```

Individual steps:

```sh
python3 scripts/validate.py           # schema and relationship validation
python3 scripts/build_reference.py    # rebuild the generated files after edits
python3 -m unittest discover -s tests
./uphold_check.py                 # this repo's own declaration
python3 scripts/check_hook_pins.py    # every rev: names a ref that exists
```

```text
principles/*.toml       canonical records
QUICK_REFERENCE.md      generated human index
REVIEW.md, AGENTS.md    generated review tier: the judgment no rule decides
name-index.json         generated lookup index: every name -> a record id
uphold_check.py     reconciler; the hook other repos install
scripts/                analysis, catalog loading, validation, generation
```

## License

Apache-2.0. Sources cited by entries retain their own copyrights and licenses.
