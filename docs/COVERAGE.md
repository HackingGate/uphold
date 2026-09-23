# Coverage

Which rung of checking exists for which language, and who runs it. A claim in
[`policy/upheld.toml`](../policy/upheld.toml) names a rule and the seam it runs
at; this page is the same claim one level up: for a language, at a rung, what
enforces it and where.

Every cell holds exactly one of three states:

- `native`: this binary evaluates it.
- `consumer-owned external gate`: the compiler, linter or verifier the consumer
  wires into its own hook config, named in the cell. uphold ships nothing that
  runs the tool; its part is the pointer on this page. One tool per job: a
  wrapper of the consumer's toolchain shipped from here would be a second copy
  of the consumer's gate, coupled to an uphold release.
- `not covered`: nothing here and no named tool. A cell whose state is planned
  but not yet true carries the issue that plans it, and nothing more.

## Rungs

| rung | what | ladder |
| --- | --- | --- |
| text | regex over bytes: `regexp`, `comment_regexp`, `prose_regexp`, `require_regexp` | commit |
| syntax | a tree-sitter query over the parse tree | commit (proposed; this repository runs no syntax rung on itself) |
| semantic | compiler and linter | push for a whole-program build and lint; commit for a per-file linter |
| proof | a verifier over a stated core | push, or manual where a run is longer than minutes (proposed; this repository runs no proof rung on itself) |

The ladder column is checked against [`lefthook.yml`](../lefthook.yml) and
[`.pre-commit-config.yaml`](../.pre-commit-config.yaml) for the rungs this
repository runs on itself, and the two files agree with each other on each:

- text: `uphold scan` (`content-policy`) is a pre-commit hook in both.
- semantic: `cargo clippy --all-targets` (`engine-clippy`) is a pre-push hook in
  both, because it compiles the whole crate and its tests. `ruff check` and
  `shellcheck` are pre-commit hooks in both, because each reads only the files
  staged. The rung is split by cost class, not by name: a linter that reads one
  file at a time sits at commit, and one that needs the whole program built sits
  at push.

The syntax and proof rows have no hook in this repository to check against, so
their ladder entries are the proposal and are marked as such.

## Languages by rungs

| rung | Rust | Go | Python | TypeScript | shell |
| --- | --- | --- | --- | --- | --- |
| text | `native` | `native` | `native` | `native` | `native` |
| syntax | `not covered` (issue 212) | `not covered` (issue 216) | `not covered` (issue 216) | `not covered` (issue 216) | `not covered` (issue 216) |
| semantic | `consumer-owned external gate`: clippy | `consumer-owned external gate`: go vet, staticcheck | `consumer-owned external gate`: mypy, ruff | `consumer-owned external gate`: tsc, eslint | `consumer-owned external gate`: shellcheck |
| proof | `consumer-owned external gate`: Verus | `consumer-owned external gate`: Gobra | `consumer-owned external gate`: CrossHair, Nagini | `not covered` | `not covered` |

Dafny, compiled to Go or Python for a verified core, is a proof entry that
belongs to no one column: `consumer-owned external gate`, Dafny.

The Rust proof cell is about a consumer's Rust tree. Verifying this binary's own
evaluator core with Verus is issue 213; that is this repository as its own
consumer, and it puts no proof rung into anyone else's tree.

## The comment checks are text, not syntax

`comment_regexp` and `trivial_comments` are text-rung checks with a parsed
comment extractor, not a syntax rung. The extractor parses Rust, Python and Go
with their tree-sitter grammars, so a `// TODO` inside a string literal is not a
comment to them, and reads the `#` lines of TOML, YAML, ini, dotfiles and shell
scripts named `.sh`, `.bash`, `.zsh` or `.fish`, where a line whose first
non-blank character is `#` is the comment. It reads no TypeScript. What each
check then does with a comment is a regex or a word comparison, which is why the
text row holds them; a rule over the parse tree itself is the syntax row, and
that row is `not covered`. The rule table in [`REFERENCE.md`](REFERENCE.md)
states the same file kinds.
