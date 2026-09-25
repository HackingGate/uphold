# uphold

uphold refuses, before it happens, what a coding agent or a person should not do
to a repository:

- a force-push over a remote branch — **shim**, with the `git push` rule below
- a committed credential — **scan**, with the `credentials` set below
- a commit the policy refuses, such as one carrying an AI author marker — **guard**
- an MCP tool call publishing text the policy refuses — **hook**

<!-- fact-anchor: source=docs/fleet.toml key=repositories states=88 -->
<!-- fact-anchor: source=docs/fleet.toml key=counted states=2026-09-23 -->
When last counted, on 2026-09-23, 88 repositories carried an uphold policy, all
of them maintained by one person and the coding agents working in them.

```sh
cargo install --git https://github.com/HackingGate/uphold --tag v1.21.0
```

Or pin the pre-commit or lefthook manifest under [Install](#install).

`policy/principles.toml`, inheriting one bundled set and declaring one rule:

```toml
shim = [{ command = "git", match = ["push:*"], argv_subject = true }]

[inherit]
sets = ["credentials"]

[rule.no-force-push]
message = "Push without rewriting the remote branch."
regexp = '(?:^|\s)(?:--force\S*|-\w*f\w*|\+\S+)(?:\s|$)'
subjects = ["argv"]
command.before = ["git push"]
```

- [`docs/REFERENCE.md`](docs/REFERENCE.md) — every config field, seam by seam
- [`docs/DESIGN.md`](docs/DESIGN.md) — why it is shaped this way
- [`docs/COVERAGE.md`](docs/COVERAGE.md) — which rung of checking exists for which language
- [`QUICK_REFERENCE.md`](QUICK_REFERENCE.md) — the catalog, one page

## A catalog, and the claims held against it

uphold is two things: a filtered catalog of engineering principles, and a binary
that holds a repository to the ones it claims to enforce.

The claims live in [`policy/upheld.toml`](policy/upheld.toml), where a
repository names the *rule* enforcing each principle. Each claim is checked
against that repository's own configuration, so it fails when the rule is
removed or disabled. You uphold a *principle*; what enforces it is a *rule*,
which is why every claim is an `[[enforce]]` block naming one. The binary,
`uphold`, reads the claims and also runs the rules themselves: content rules,
Git guards, command shims and the agent hook.

## Install

`uphold init --owner OWNER --visibility public|private|internal` at a
repository's root writes a first `policy/principles.toml` (four bundled sets and
the `gh` and `git` shim tables), a `policy/upheld.toml` with two claims those
sets supply, and the `.pre-commit-config.yaml` below at this binary's version
(`--lefthook` writes the `lefthook.yml` instead). It refuses a tree that already
has a policy, and leaves an existing hook config as it is, printing the block to
add. The owner and the visibility are stated, never read from `origin`.

**pre-commit / prek** — one manifest serves both, and no Rust toolchain is
needed (`language: rust` bootstraps it).

```yaml
# .pre-commit-config.yaml
default_install_hook_types: [pre-commit, commit-msg, pre-merge-commit, pre-push]
repos:
  - repo: https://github.com/HackingGate/uphold
    rev: v1.21.0
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

There is one guard id per stage because the stage is an argument. Pinning all
five is safe: which guards fire is decided by `policy/principles.toml`.

Three scanner ids are left out above because they need tools on the host:

- `uphold-supply-chain` at `pre-push`, over what the push changed;
- `uphold-supply-chain-all` at `manual`, over everything, from a scheduled job
  that installs the scanners ([recipe](docs/REFERENCE.md#a-scheduled-sweep-in-ci));
- `uphold-supply-chain-staged` at `pre-commit`, gitleaks alone over the staged
  diff.

Each scanner must be at least the release its output reader was measured
against ([floors](docs/REFERENCE.md#uphold-supply-chain--six-scanners-one-verdict));
an older one is exit 2 for its section, so an uphold upgrade that raises a floor
can newly refuse a push on a host with an old scanner.

A policy inheriting `credentials` also gets **gitleaks**, which owns secret
shapes and is the only secret-shape check. It must be on PATH at the one version
this uphold pins; a missing gitleaks or another version is exit 2 and refuses
the push. With mise:

```toml
[tools]
"aqua:gitleaks/gitleaks" = "8.30.1"
```

The `credentials` set keeps `no-env-secret-values` and
`no-browser-profile-artifacts`, which no commit scanner covers. Its three regex
shape rules, deprecated in v1.20.0, are removed; a `policy/upheld.toml` claim
still naming one is refused with a pointer to `uphold-supply-chain` and
`uphold-supply-chain-staged`, the ids to claim instead. `.gitleaks.toml`,
`.gitleaksignore` and the staged-scan fingerprint form are described in
[REFERENCE](docs/REFERENCE.md#gitleaks-which-owns-secret-shapes).

**lefthook** — lefthook has no manifest format, so include the config this
repository ships, then run `lefthook install`. It runs commands rather than
bootstrapping a language, so the binary must be on PATH, from the
`cargo install` line at the top.

```yaml
# lefthook.yml
remotes:
  - git_url: https://github.com/HackingGate/uphold
    ref: v1.21.0
    configs:
      - hooks/lefthook.yml
```

**Dependabot does not watch that `ref:`**: no Dependabot ecosystem reads a
lefthook config, so no pull request is raised when a newer tag lands. The
`no-stale-hook-pins` guard watches it instead, and refuses a lefthook pin that
has fallen behind its upstream or names no `ref:`. You are told the pin is
stale; you are not handed the bump. It reads `lefthook.yml`, `lefthook.yaml`,
`.lefthook.yml` and `.lefthook.yaml` at any depth, but not `lefthook.toml`,
`lefthook.json` or the `-local` overlay files, so a pin written in one of those
is not watched.

For pre-commit `rev:` pins the guard checks only that the tag exists. Whether
it is the newest is answered by `prek update --check`
([ADR 0010](docs/adr/0010-who-asks-whether-a-hook-pin-is-current.md)); add it
to your `.pre-commit-config.yaml`:

```yaml
  - repo: local
    hooks:
      - id: prek-pins-current
        name: pre-commit pins are the newest tag
        entry: prek update --check
        language: system
        pass_filenames: false
        always_run: true
        stages: [manual]
```

prek exits 1 both for a pin that would move and for a remote it could not
reach; its output distinguishes them (`would update rev` or `update failed`).

**Go repositories** — uphold ships no Go toolchain hooks. Declare a Go gate in
your own config as `repo: local` hooks with `language: system`, so they use the
`go` on PATH and the choice of vet, linters, `-race` or build tags stays in your
config rather than behind a `rev:`. Note that `gofmt -l` prints the files it
would reformat and exits `0` regardless, so a gate on it must test that the
output is empty:

```yaml
  - repo: local
    hooks:
      - id: gofmt
        name: gofmt
        entry: sh -c 'out="$(gofmt -l .)"; [ -z "$out" ] || { echo "$out"; exit 1; }'
        language: system
        pass_filenames: false
        files: '(\.go|go\.mod|go\.sum)$'
```

`uphold hooks --identity` compares a declaration like this one across
repositories and reports the copy that drifted.

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

`rule` is the rule's own id, resolved against every seam this repository runs.

```text
reconciled 2 enforcement claims:
  least-privilege <- prevent-public-push  enforced by uphold
  complete-mediation <- prevent-ai-author  enforced by uphold
```

A rule enforced at more than one seam is reported at every seam. A claim is
refused when no seam supplies the rule, or when it names a principle the catalog
does not define, one that is deprecated, or one marked
`enforcement.automatable = "no"`. A seam that could not be read is reported as
could-not-look, never as a false claim.

A principle with no rule yet does not belong in this file. Build the rule first.

Every mode that decides whether a check passed reads the policy, so it lives in
the binary, which owns the loader. `uphold_check.py` keeps only the modes that
read the catalog and render prose for a person.

Exit codes, everywhere: `0` clean, `1` a claim is false or a violation was
found, `2` could not look — see [`explicit-unknown`](principles/explicit-unknown.toml).

At `scan --text`, `guard --text` and `hook`, the step from what each kind of rule
answered about a piece of text to the exit code is model-checked with Kani, over
every seam and every combination of answers: `0` only when every kind the seam
consults looked and found nothing, `2` whenever one could not look. The proof
starts where the rules have answered. The rule bodies, the shim's per-rule
dispatch and everything that reads a file or runs a process are tested, not
proven; [CONTRIBUTING](CONTRIBUTING.md#proving-the-fail-closed-property) has
the harnesses and what they cost.

## Commands

```sh
uphold init --owner OWNER --visibility public   # a first policy, claims and hook config
uphold scan                     # content rules over the tree
uphold scan --text -            # a commit message, release note, PR body
uphold check                    # the claims in policy/upheld.toml still hold
uphold check --coverage         # which rules here carry a principle
uphold rules --effective        # every rule inheritance resolved to, and where each runs
uphold guard --stage pre-push   # the guards for that Git hook
uphold shim gh pr create ...    # stand in front of a command, then exec
uphold shim --install           # link this binary under each command's name
uphold shim --status            # what is linked, and whether PATH reaches it
uphold hook claude-code         # judge a pending agent tool call, read on stdin
uphold audit --for-publication  # before flipping private -> public
uphold supply-chain             # six scanners over the pushed range; a missing one is exit 2
uphold supply-chain --all       # the same over every manifest and every commit

uphold hooks --identity ../a ../b   # do these repositories declare the same hooks
uphold hooks --install              # write the hooks Git runs, as tracked files
uphold probe                        # can each declared hook actually refuse

uphold_check.py --explain ID    # one record in full; also accepts a name
uphold_check.py --list          # every id in the catalog
uphold_check.py --init          # a starter declaration
uphold_check.py --oscal         # OSCAL component-definition JSON
uphold_check.py --review        # what routes to the review tier
```

## The four seams

One config file, `policy/principles.toml`, one flat id namespace. A rule states
**what it checks** in the field it writes, and **where it runs** in up to three
tables; an absent table is a place the rule does not run. Full field reference:
[`docs/REFERENCE.md`](docs/REFERENCE.md).

**`uphold scan`** evaluates content rules over the repository's own files,
using ripgrep's search libraries, so a pattern written for `rg` means the same
thing here. "Its own files" means **what Git tracks**, not a directory walk: a
tracked file that an ignore pattern also matches is still pushed and cloned, so
it is still scanned. A selected file that cannot be read is **not** reported
clean; it is named with its reason, and the run exits `2`. `--text -` scans text
that never becomes a file. `uphold rules --effective` prints what inheritance
resolved to.

**`uphold guard --stage STAGE`** reads an *act* rather than a tree: the message
about to be recorded, the identity about to be stamped, the range about to be
pushed. There are eleven built-in guards, registered by `git.hooks`. A file's
**name** is committed text too, and at a push the guards also read the commit
**messages** the push publishes. `UPHOLD_ALLOW=<id>` overrides one invocation.

**`uphold shim`** stands in front of a command, checks what the invocation is
about to publish, and execs the real command. A pull-request body reaches a
public API without passing any Git hook; so do a branch name, an issue title and
a commit made with `--no-verify`. A link named for the command, placed on PATH
ahead of the real one, is the whole installation, because `uphold` is a
multicall binary. Where the text is composed in an **editor**, the shim makes
itself the editor and checks what the editor leaves in the file, so no
invocation publishes text the shim has not read.

`uphold shim --install` creates those links, one per command this repository
declares, in one directory (`~/.local/uphold/shims`) the operator adds to PATH;
`--status` reports which of them the shell actually reaches.
`uphold shim --hook bash|zsh|fish` is the alternative: the same links, on PATH
only inside a tree that declares a policy, in the way `direnv` works. Either
way, the behavior is per repository: where no policy applies, the shim execs the
real command and prints nothing. The reasoning, and what was deliberately not
built: [ADR 0002](docs/adr/0002-the-reach-of-a-command-shim.md).

**`uphold hook <harness>`** covers a caller that spawns no process. An agent
reaching a forge through an MCP server posts a pull-request body over HTTPS from
inside its own process: there is no command, no `argv[0]` and no link to
install. In place of `argv[0]`, the harness's own pre-call decision point hands
the hook the pending call as JSON on stdin and reads a verdict back, so the
rules the shim runs are reached without a process.

The hook does not replace the shim. The shim reaches a person at a terminal, a
CI step and a script, whatever launched them; the hook reaches every transport
one harness can use and nothing from any other harness. Neither covers the
other. The hook also refuses *earlier* than the other three seams, which refuse
at commit or at exec, after the work is staged.

Which calls reach the hook is decided by the harness's own matcher, not by a
second matcher in this binary. An unknown harness name is refused rather than
guessed at, because where to find the text in its event cannot be derived from
its name.

```jsonc
// ~/.claude/settings.json
{"hooks": {"PreToolUse": [
  {"matcher": "mcp__github__.*",
   "hooks": [{"type": "command", "command": "uphold hook claude-code"}]}
]}}
```

**`uphold hooks --identity DIR...`** and **`uphold probe`** answer two questions
a single repository cannot answer about itself. A forked hook declaration is
valid in every tree that holds it, so only a comparison across repositories
shows that the copies have diverged. A hook that *cannot fail* reports the same
pass as one that keeps finding nothing, so only planting something it must
refuse tells the two apart. The probe does that in a temporary `git worktree`,
never in the current tree. Both read `policy/hooks.toml`: waivers for the first,
fixtures for the second.

## The catalog

Canonical records are TOML under [`principles/`](principles/). Every entry must
state what it claims, the problem it addresses, where it applies and where it
does not, its costs, conflicts and failure modes, whether it is enforceable by
review, lint, test, runtime or governance, and its sources. A record has a
`kind` from a closed list of fifteen (law, theorem, principle, heuristic,
metric and the rest), and may state the rungs at which a check can see it
(`enforcement.rung`) and the tools that illustrate it (`[[tools]]`). A field the
schema does not name fails validation. Every field and vocabulary:
[`principles/SCHEMA.md`](principles/SCHEMA.md).

```toml
id = "single-authoritative-source"
title = "Single Authoritative Source"
kind = "principle"
status = "seed"
domains = ["data", "architecture", "socio-technical"]

summary = "One authority owns each fact; copies may exist."
claim = """
Each authoritative fact should have one designated ownership and update authority.
"""

[enforcement]
level = "governance"
automatable = "partially"
checks = ["Require an owner for every canonical data entity."]
```

Lookup takes a name or an id. Both go through one normalization (NFKC,
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
[`lefthook.yml`](lefthook.yml) equivalent. The two check the same things, with
one exception: the whitespace and parse checks from `pre-commit-hooks` are
Python hooks with no standalone binary, so lefthook cannot run them and
`uphold scan` does not cover them.

```sh
prek install                                  # or: pre-commit install
prek run --all-files --hook-stage manual      # everything CI runs
```

Individual steps:

```sh
uv run --no-project scripts/validate.py        # schema and relationship validation
uv run --no-project scripts/build_reference.py # rebuild the generated files after edits
uv run --no-project python -m unittest discover -s tests
cargo run --quiet -- check                  # this repository's own claims, reconciled
cargo run --quiet -- guard --stage manual   # every pin still names a ref
```

```text
principles/*.toml       canonical records
QUICK_REFERENCE.md      generated human index
REVIEW.md, AGENTS.md    generated review tier: the judgment no rule decides
review-controls.json    generated: the change each controlled record must be found by
name-index.json         generated lookup index: every name -> a record id
uphold_check.py         catalog prose: --explain, --list, --review, --oscal, --init
scripts/                analysis, catalog loading, validation, generation
```

## License

Apache-2.0. Sources cited by entries retain their own copyrights and licenses.
