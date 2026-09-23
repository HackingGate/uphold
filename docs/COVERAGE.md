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
| syntax | an `ast-grep` rule over the parse tree | commit (this repository runs no syntax rung on itself) |
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

The syntax and proof rows have no hook in this repository to check against. The
syntax entry is where the consumer's `ast-grep scan` belongs by cost: it reads
one tree per file and needs no build. The proof entry is the proposal and is
marked as such.

## Languages by rungs

| rung | Rust | Go | Python | TypeScript | shell |
| --- | --- | --- | --- | --- | --- |
| text | `native` | `native` | `native` | `native` | `native` |
| syntax | `consumer-owned external gate`: ast-grep | `consumer-owned external gate`: ast-grep | `consumer-owned external gate`: ast-grep | `consumer-owned external gate`: ast-grep | `consumer-owned external gate`: ast-grep |
| semantic | `consumer-owned external gate`: clippy | `consumer-owned external gate`: go vet, staticcheck | `consumer-owned external gate`: mypy, ruff | `consumer-owned external gate`: tsc, eslint | `consumer-owned external gate`: shellcheck |
| proof | `consumer-owned external gate`: Verus | `consumer-owned external gate`: Gobra | `consumer-owned external gate`: CrossHair, Nagini | `not covered` | `not covered` |

Dafny, compiled to Go or Python for a verified core, is a proof entry that
belongs to no one column: `consumer-owned external gate`, Dafny.

The Rust proof cell is about a consumer's Rust tree. Verifying this binary's own
evaluator core with Verus is issue 213; that is this repository as its own
consumer, and it puts no proof rung into anyone else's tree.

## The syntax rung is the consumer's ast-grep

A structural rule, such as "no `.unwrap()` outside `#[cfg(test)]`", is an
`ast-grep` rule in the consumer's own tree, run from the consumer's own hook
config. uphold carries no rule form over the parse tree and no wrapper around
`ast-grep`; [ADR 0009](adr/0009-a-consumers-structural-rules-are-ast-greps.md)
records why. The entry, for pre-commit or prek:

```yaml
- repo: local
  hooks:
    - id: ast-grep
      name: ast-grep scan
      entry: ast-grep scan
      language: system
      pass_filenames: false
```

`ast-grep scan` reads `sgconfig.yml` and every rule under its `ruleDirs`, and
exits 1 on a finding at `error`. `pass_filenames: false` because the project
file, not the staged list, decides what each rule reads. `language: system`
because the binary is the consumer's, like its compiler; this repository adds
the entry to its own config only once it has a rule directory to run.

`ast-grep` answers "nothing to report" in three places where the answer is
"did not look", measured on 0.45.3. An adopter owns all three:

- **Every rule sets `severity: error`.** A rule with no `severity` is a
  `hint`: its findings print and the exit is 0.
- **Every language gets a companion rule matching `kind: ERROR`.** `ast-grep`
  matches inside a tree the grammar recovered and exits by what it matched,
  so a file that did not parse reads like a clean one. The companion refuses a
  file with an ERROR node:

  ```yaml
  id: unparsed-rust
  language: rust
  severity: error
  message: the grammar could not read this region, so no rule here looked at it
  rule:
    kind: ERROR
  ```

  Its limit: recovery that only inserts a MISSING node produces no ERROR node,
  and the companion exits 0 over it. `fn broken( {` is one such file, repaired
  by an inserted `)`. No `ast-grep` rule matches a MISSING node. The backstop
  is the semantic row: the compiler or linter refuses that file.
- **Top-level keys are read by eye.** `ast-grep` refuses a misspelled key
  inside `rule:`, and drops one at the top level of a rule or of
  `sgconfig.yml` without a word: `constraint:` for `constraints:` runs the rule
  without its constraint, and `ruleDir:` for `ruleDirs:` runs no rule and
  exits 0. Check these in review.

## Rules a stock linter already carries

Four structural rules were proposed for this binary, one per language. Each is
already a stock rule in the linter the semantic row names, so the pointer is
the whole of uphold's part:

| language | the rule | where it already is |
| --- | --- | --- |
| shell | an unquoted `$var` as an argument | ShellCheck SC2086, for every command and not only `rm` |
| Python | a bare `except:` | ruff E722 (pycodestyle), also flake8 E722 |
| TypeScript | `any` in an exported signature | typescript-eslint `no-explicit-any`, with `explicit-module-boundary-types` for the exported half |
| Go | `panic(` outside `_test.go` | golangci-lint `forbidigo`, with a `panic` pattern and `_test.go` excluded |

A rule of the consumer's own that no linter carries is an `ast-grep` rule, as
above.

## The comment checks are text, not syntax

`comment_regexp` and `trivial_comments` are text-rung checks with a parsed
comment extractor, not a syntax rung. The extractor parses Rust, Python and Go
with their tree-sitter grammars, so a `// TODO` inside a string literal is not a
comment to them, and reads the `#` lines of TOML, YAML, ini, dotfiles and shell
scripts named `.sh`, `.bash`, `.zsh` or `.fish`, where a line whose first
non-blank character is `#` is the comment. It reads no TypeScript. What each
check then does with a comment is a regex or a word comparison, which is why the
text row holds them; a rule over the parse tree itself is the syntax row, and
that row is the consumer's `ast-grep`. The rule table in [`REFERENCE.md`](REFERENCE.md)
states the same file kinds.
