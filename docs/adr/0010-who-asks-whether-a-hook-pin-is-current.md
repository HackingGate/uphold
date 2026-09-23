# ADR 0010: who asks whether a hook pin is current

Status: Accepted

`no-stale-hook-pins` used to ask two things of every pin in a hook config:
does the tag it names exist, and is it the newest one. The second question
needs an ordering of tags, and `version_key` in `src/pins.rs` is a hand-written
one. It has already shipped one bug: `v0.11.0.1-1` sorted under `v0.11.0.1`, so
the newest pin was reported as stale.

For a pre-commit `rev:`, a tool the consumer already has answers the second
question: `prek update --check`. For a lefthook `remotes:` ref, nothing does.
This record splits the question along that line, and records the probes that
decided it.

## Decisions

- **A pre-commit `rev:` is asked for freshness by prek, run by the consumer.**
  uphold does not shell out to it. A consumer adds a `repo: local` hook,
  `prek-pins-current`, whose entry is `prek update --check`, at the manual
  stage; this repository runs the same entry under both runners. The README
  carries the block to copy.
- **`no-stale-hook-pins` keeps the rest.** For a pre-commit `rev:` it still
  refuses a rev that names no tag and a rev that names a branch, and exits 2
  over a remote it could not reach. For a lefthook ref it asks all of that and
  whether the ref is the newest tag, through `version_key`, which now serves
  that one format. The rule id is unchanged, so no policy that names it breaks.
- **A run that skipped the freshness question says so.** The guard prints
  how many pre-commit pins it checked for existence only, and names the hook
  that asks the rest, so a pass is not read as "these pins are current" in a
  repository that never added it.

## What prek does

Probed with prek 0.4.14, each probe a scratch repository holding one
`.pre-commit-config.yaml`, with a scratch `PREK_HOME`, against GitHub remotes
and against local `file://` upstreams whose tags were cut at chosen dates.

It agrees with the old guard here:

- `shellcheck-py/shellcheck-py` pinned at `v0.11.0.1-1` exits 0; pinned at
  `v0.11.0.1` it exits 1 with `would update rev v0.11.0.1 -> v0.11.0.1-1`.
- A stale `rev:` in `sub/.pre-commit-config.yaml` is reported under that path.
- A stale `rev:` in a `.pre-commit-config.yaml` inside a checked-out submodule
  is not seen: the run exits 0. The guard skips submodules too, since a
  submodule's pins are its own repository's.
- `--check` leaves the config file untouched. It writes under `PREK_HOME`
  only (a cache, a log, a scratch fetch), and it needs the network, as the
  guard's `git ls-remote` does.

It differs here, and each is something a consumer running it should know:

1. **An unreachable remote exits 1, the same code as a stale pin.** Neither
   is a pass, so the hook fails closed, but the exit code does not say which
   happened. The output does: `would update rev` on stdout for a pin that
   would move, `update failed:` on stderr for a remote it could not fetch.
2. **It orders tags by date, not by version.** With `v1.0.1` cut on a
   maintenance branch after `v1.1.0-rc1`, a pin on `v1.1.0-rc1` is told to
   move to `v1.0.1`. With `v9` and `v10` tagged in the same second, a pin on
   `v10` is told to move to `v9`.
3. **A bare sha is reported as movable,** even when it is the commit the
   newest tag names. The guard passes a sha naming no tag on purpose
   (`policy/base/stale-pins.toml` says why). `--freeze` changes the question
   to "is this the newest tag's sha" rather than removing it.
4. **A `rev:` naming no tag reads as behind:** `would update rev v7.7.7 ->
   <an older tag>`. The guard reports it as naming no tag, which is the fault:
   it fails at hook-init as a clone error. That is why this arm stays here.

## Why not Renovate

Renovate's `pre-commit` manager is an updater that opens a pull request, not
a check that returns a verdict to a hook; its documentation calls the manager
beta and opt-in; and it has no lefthook manager, so the lefthook half would
stay here regardless. It was not run. Dependabot's `pre-commit` ecosystem is
the same shape. Either complements the hook; neither replaces it.
