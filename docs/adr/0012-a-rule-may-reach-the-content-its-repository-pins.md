# ADR 0012: a rule may reach the content its repository pins

Status: Proposed

`uphold scan` reads what `git ls-files -z` lists (`index_bytes`,
`src/selection.rs:150`) and drops every gitlink on purpose
(`src/selection.rs:434-442`). It takes only `--policy` and `--text`
(`src/main.rs:589-615`). A superproject's rule therefore sees none of its
mounts. Measured by a consumer, a superproject of 49 repositories, against
v1.13.0 and again against v1.22.0: a rule written to hold every member to one
convention selected four root files and nothing under any mount.

## Where the boundary is drawn today

"A submodule is its own repository" is written at `src/selection.rs:438`,
`src/main.rs:230-240` and `262-273`, `src/hook.rs:269`, `src/pins.rs:194`,
`src/guard/scope.rs:147` and `src/git.rs:57`. Two directions are guarded, for
two different reasons:

- **Upward, for correctness.** A member with no policy of its own must not load
  the superproject's and report on the superproject's tree under its own name
  (`discover` and `no_policy_here`; the case is
  `tests/root_cli.rs:103`). A report about another tree is wrong, not costly.
- **Downward, for ownership and cost.** The scan skips a gitlink, the pin guard
  does not walk into a member's hook configs, and git run inside a member is
  stripped of the superproject's environment. None of these says the
  superproject may never look; each says it does not look by default.

`uphold supply-chain` already reaches downward on purpose
(`src/supply.rs:686-790`): `collect_range` follows a moved gitlink,
`expand_gitlink` runs git inside the member through `run_elsewhere`, findings
carry the path under the mount prefix, and a mount that is not checked out is
`Fatal`, exit 2 (`src/supply.rs:754`), not silence.

## Decision

- **A rule declares its reach: `files.reach`, `"repository"` or `"pinned"`.**
  Absent means `"repository"`, which is today's behavior, byte for byte.
- **A `"pinned"` rule enumerates with `git ls-files -z --recurse-submodules`.**
  Every tracked file of every checked-out mount is listed under its mount path.
- **A pinned mount that is not checked out is exit 2**, naming the mount and
  `git submodule update --init <path>`, as `expand_gitlink` does. A rule that
  claims the pinned content and cannot read part of it has not looked.
- **`not_text_paths` asks each member.** A member's `.gitattributes` is
  invisible from the root, so `check-attr` runs per member through
  `run_elsewhere`, and a member that cannot answer is reported the way the
  root's unmeasured case is (`src/selection.rs:57-90`).
- **Paths are mount-prefixed everywhere.** Findings, path baselines and size
  baselines (`src/scan.rs:1464-1575`) key on `member/sub/file`. A link in a
  member's Markdown resolves a leading `/` against the member's root, not the
  superproject's (`resolve_link`, `src/scan.rs:1827`).
- **`include`, `exclude` and `glob` keep gitignore semantics rooted at the
  superproject.** A leading-slash exclude stays anchored at the superproject
  root; a bare name matches at any depth, inside mounts too.
- **The direction rule, stated once:** a member never borrows upward; a
  repository may judge, downward, the content it pins, and reports it under
  the mount path.

## Rejected

- **Member-side `[inherit] paths = ["../..."]`.** It loads today only because
  `inherit.paths` is joined to the root with no containment check
  (`src/config.rs:1785-1787`). A member depending on `../` is the upward borrow
  the doctrine refuses, a standalone clone of that member fails fatally on the
  read, and it means editing every member and defining what an anchored glob
  means once re-rooted.
- **A workspace-level membership check.** It checks that a member declared a
  rule, not what the member's files contain, and it is close to the shared
  profiles `ROADMAP.md` lists as not planned.

## Consequences

- No change for an existing consumer: no rule carries `reach` today.
- An adopting rule costs the size of the mounts it reads, once per run.
- A CI checkout without `git submodule update --init` goes red on a pinned
  rule, on purpose.
- `docs/REFERENCE.md` gains the field in the rule-shape table and in the scan
  section's paragraph on what "the repository's own files" means.
- Tests: a CLI case on a scratch superproject (`support::scratch`) with a
  canary submodule, asserting the finding's mount-prefixed path and exit 2 on
  an uninitialized mount; selection unit tests for the anchored and bare
  globs; and a `cargo mutants` run over `src/selection.rs` per
  `CONTRIBUTING.md`.
