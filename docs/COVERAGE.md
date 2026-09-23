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
| proof | a verifier over a stated core | push, or manual where a run is longer than minutes |

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
- proof: `cargo kani` (`kani`) is a manual hook in both, and CI runs it as a job
  of its own, because the harnesses take minutes of solver time.

The syntax row has no hook in this repository to check against. It is where the
consumer's `ast-grep scan` belongs by cost: it reads one tree per file and needs
no build.

## What a gate at each rung reads

These are what a consumer imports into its own hook config and claims a record
for in [`policy/upheld.toml`](../policy/upheld.toml); uphold ships the pointer,
not the tool. None of them is a record: a record is what is upheld, and these
are how a gate observes it.

### text

| concept | what it gives a check | example tools |
| --- | --- | --- |
| [Lexical analysis](https://en.wikipedia.org/wiki/Lexical_analysis) (tokens) | the source as a stream of tokens, so a match can tell a keyword from the same word in a string or comment | [flex](https://github.com/westes/flex), [ANTLR](https://www.antlr.org/) lexer grammars |

### syntax

| concept | what it gives a check | example tools |
| --- | --- | --- |
| [Concrete syntax tree](https://en.wikipedia.org/wiki/Parse_tree) | every token in the grammar's shape, layout and comments kept, so a finding can print the exact span | [tree-sitter](https://tree-sitter.github.io/tree-sitter/), [ANTLR](https://www.antlr.org/) |
| [Abstract syntax tree](https://en.wikipedia.org/wiki/Abstract_syntax_tree) | the program's structure without layout, so a rule matches a construct however it is spelled | [Clang AST](https://clang.llvm.org/docs/IntroductionToTheClangAST.html), [ast-grep](https://ast-grep.github.io/) |

### semantic

| concept | what it gives a check | example tools |
| --- | --- | --- |
| [High-level intermediate representation](https://en.wikipedia.org/wiki/Intermediate_representation) | names resolved and types assigned, so a check sees what an identifier refers to | [rustc HIR](https://rustc-dev-guide.rust-lang.org/hir.html), [MLIR](https://mlir.llvm.org/), [LLVM IR](https://llvm.org/docs/LangRef.html) |
| [Control-flow graph](https://en.wikipedia.org/wiki/Control-flow_graph) | every path a function can take, so a check can ask whether one statement is reached before another | [LLVM](https://llvm.org/), [Soot](https://soot-oss.github.io/soot/) |
| [Data-flow graph](https://en.wikipedia.org/wiki/Data_dependency) | which value flows into which operation | [Joern](https://joern.io/), [LLVM](https://llvm.org/) |
| [Program dependence graph](https://doi.org/10.1145/24039.24041) | data and control dependences in one graph, so a program can be sliced to what affects one statement | [Joern](https://joern.io/), [WALA](https://github.com/wala/WALA) |
| [Static single-assignment form](https://en.wikipedia.org/wiki/Static_single-assignment_form) | each variable assigned once, so a value's definition is its name | [LLVM](https://llvm.org/), [GCC](https://gcc.gnu.org/) |
| [Call graph](https://en.wikipedia.org/wiki/Call_graph) | which function can call which, the ground of every interprocedural question | [Soot](https://soot-oss.github.io/soot/), [WALA](https://github.com/wala/WALA), [SVF](https://github.com/SVF-tools/SVF) |
| [Def-use chains](https://en.wikipedia.org/wiki/Use-define_chain) | each definition linked to every use it reaches, and back | [LLVM](https://llvm.org/), [GCC](https://gcc.gnu.org/) |
| [Dominator tree](https://en.wikipedia.org/wiki/Dominator_(graph_theory)) | which statement runs before another on every path, so "checked before used" is decidable | [LLVM](https://llvm.org/), [GCC](https://gcc.gnu.org/) |
| [Data-flow analysis](https://en.wikipedia.org/wiki/Data-flow_analysis) | facts propagated over the control-flow graph to a fixed point; reaching definitions, liveness and constant propagation are instances | [CodeQL](https://codeql.github.com/), [Soot](https://soot-oss.github.io/soot/) |
| [Range analysis](https://en.wikipedia.org/wiki/Value_range_analysis) | the interval each integer can hold, so an index or an overflow can be shown in bounds | [Frama-C](https://frama-c.com/), [GCC](https://gcc.gnu.org/) |
| [Nullness analysis](https://en.wikipedia.org/wiki/Void_safety) | whether a reference can be null where it is dereferenced | [NullAway](https://github.com/uber/NullAway), [Infer](https://fbinfer.com/) |
| [Pointer](https://en.wikipedia.org/wiki/Pointer_analysis) and [alias analysis](https://en.wikipedia.org/wiki/Alias_analysis) | which memory a pointer may refer to, so two accesses can be told apart | [SVF](https://github.com/SVF-tools/SVF), [WALA](https://github.com/wala/WALA) |
| [Escape analysis](https://en.wikipedia.org/wiki/Escape_analysis) | whether a reference outlives its scope or its thread | [Go compiler](https://go.dev/doc/faq#stack_or_heap) |
| [Shape analysis](https://en.wikipedia.org/wiki/Shape_analysis_(program_analysis)) | the form a heap structure keeps, such as an acyclic list, across every operation on it | [Infer](https://fbinfer.com/) |
| [Taint analysis](https://en.wikipedia.org/wiki/Taint_checking) | whether data from an untrusted source reaches a sink without passing a sanitizer | [CodeQL](https://codeql.github.com/), [Semgrep](https://semgrep.dev/), [Joern](https://joern.io/) |
| [Information-flow analysis](https://doi.org/10.1145/360051.360056) | whether a secret can influence a public output, implicit flows through branches included | [JOANA](https://github.com/joana-team/joana) |
| [Dependency analysis](https://en.wikipedia.org/wiki/Dependence_analysis) | which statements must stay in order, the ground of loop transformation and slicing | [Polly](https://polly.llvm.org/), [isl](https://libisl.sourceforge.io/) |
| [Precision](https://en.wikipedia.org/wiki/Data-flow_analysis#Sensitivities): interprocedural, flow-, context- and path-sensitive | how much of the program an answer accounts for: across calls, in statement order, per call site, per branch; each costs time and removes false positives | [Infer](https://fbinfer.com/), [Clang Static Analyzer](https://clang-analyzer.llvm.org/), [SVF](https://github.com/SVF-tools/SVF) |
| [Abstract interpretation](https://en.wikipedia.org/wiki/Abstract_interpretation) | a sound over-approximation of every run in a chosen domain, so an absent alarm is a proof over that domain | [Astree](https://www.absint.com/astree/), [Frama-C](https://frama-c.com/), [APRON](https://github.com/antoinemine/apron) |
| [Interval](https://en.wikipedia.org/wiki/Interval_arithmetic), [octagon](https://doi.org/10.1007/s10990-006-8609-1) and [polyhedral](https://doi.org/10.1145/512760.512770) domains | bounds per variable; bounds on sums and differences of pairs; any linear relation: each more precise and more costly than the last | [APRON](https://github.com/antoinemine/apron), [Astree](https://www.absint.com/astree/), [Polly](https://polly.llvm.org/)/[isl](https://libisl.sourceforge.io/) |

### proof

| concept | what it gives a check | example tools |
| --- | --- | --- |
| [Operational semantics](https://en.wikipedia.org/wiki/Operational_semantics) and abstract machines | an executable definition of what a language means, against which programs and tools are checked | [K Framework](https://kframework.org/) |
| [Predicate abstraction](https://doi.org/10.1007/3-540-63166-6_10) | a finite abstraction by the truth of chosen predicates, which a model checker can explore | [CPAchecker](https://cpachecker.sosy-lab.org/) |
| [Hoare logic](https://en.wikipedia.org/wiki/Hoare_logic) | pre- and postconditions a proof carries across each statement | [Dafny](https://dafny.org/), [Why3](https://www.why3.org/), [SPARK](https://www.adacore.com/about-spark) |
| [Weakest preconditions](https://en.wikipedia.org/wiki/Predicate_transformer_semantics) | the least a state must satisfy before a statement for its postcondition to hold after it | [Why3](https://www.why3.org/), [Boogie](https://github.com/boogie-org/boogie) |
| [Verification-condition generation](https://doi.org/10.1145/360204.360220) | each annotated routine turned into formulas a solver discharges | [Boogie](https://github.com/boogie-org/boogie), [Why3](https://www.why3.org/) |
| [Separation logic](https://en.wikipedia.org/wiki/Separation_logic) | reasoning about one heap region with the rest framed off, so pointer programs can be proved | [VeriFast](https://github.com/verifast/verifast), [Infer](https://fbinfer.com/) |
| [Concurrent separation logic](https://doi.org/10.1016/j.tcs.2006.12.035) | heap ownership divided between threads, so each is proved alone | [Iris](https://iris-project.org/), [VeriFast](https://github.com/verifast/verifast) |
| [Rely-guarantee](https://doi.org/10.1145/69575.69577) | each thread proved against what the others may do and what it promises them | [Iris](https://iris-project.org/) |
| [Refinement types](https://en.wikipedia.org/wiki/Refinement_type) | types carrying predicates a solver checks, such as a non-empty list or an in-bounds index | [Liquid Haskell](https://ucsd-progsys.github.io/liquidhaskell/), [F*](https://fstar-lang.org/) |
| [Dependent types](https://en.wikipedia.org/wiki/Dependent_type) | types that mention values, so a specification is a type and a proof is a program | [Lean](https://lean-lang.org/), [Agda](https://agda.readthedocs.io/), [Idris](https://www.idris-lang.org/) |
| [Contract verification](https://en.wikipedia.org/wiki/Design_by_contract) | each routine's pre- and postconditions proved for every input rather than checked on some | [SPARK](https://www.adacore.com/about-spark), [Frama-C](https://frama-c.com/), [Dafny](https://dafny.org/) |
| [Invariant checking](https://en.wikipedia.org/wiki/Loop_invariant) | a property shown to hold at every loop iteration or every reachable state | [Dafny](https://dafny.org/), [Kind 2](https://kind.cs.uiowa.edu/kind2_user_doc/) |
| [Termination analysis](https://en.wikipedia.org/wiki/Termination_analysis) | a ranking function that decreases on every loop and call, so the program halts | [AProVE](https://aprove.informatik.rwth-aachen.de/), [Ultimate Automizer](https://ultimate.informatik.uni-freiburg.de/) |
| [Refinement checking](https://en.wikipedia.org/wiki/Refinement_(computing)) | an implementation's behaviors shown to be among its specification's | [FDR](https://cocotec.io/fdr/), [mCRL2](https://www.mcrl2.org/) |
| [Relational verification](https://doi.org/10.1145/964001.964003) | a property relating two runs or two programs, proved together | [EasyCrypt](https://www.easycrypt.info/) |
| [Noninterference](https://en.wikipedia.org/wiki/Non-interference_(security)) | secret inputs shown not to affect public outputs, over every pair of runs | [EasyCrypt](https://www.easycrypt.info/), [F*](https://fstar-lang.org/) |
| [Translation validation](https://doi.org/10.1007/BFb0054170) | each compilation checked to preserve meaning, instead of the compiler proved once | [Alive2](https://github.com/AliveToolkit/alive2) |
| [Equivalence checking](https://en.wikipedia.org/wiki/Formal_equivalence_checking) | two programs shown to compute the same function | [Alive2](https://github.com/AliveToolkit/alive2) |
| [Bisimulation](https://en.wikipedia.org/wiki/Bisimulation) | two transition systems shown to match each other step for step | [mCRL2](https://www.mcrl2.org/) |
| [Symbolic execution](https://en.wikipedia.org/wiki/Symbolic_execution) | each path's condition as a formula, so a solver finds an input that reaches it or shows none does | [KLEE](https://klee-se.org/), [angr](https://angr.io/) |
| [Concolic execution](https://en.wikipedia.org/wiki/Concolic_testing) | concrete runs that record their path conditions and negate them to reach new paths | [SymCC](https://github.com/eurecom-s3/symcc) |
| [Bounded model checking](https://doi.org/10.1007/3-540-49059-0_14) | every execution up to a bound encoded for a SAT or SMT solver; this repository proves its own verdict path this way with Kani | [CBMC](https://www.cprover.org/cbmc/), [Kani](https://model-checking.github.io/kani/) |
| [Explicit-state model checking](https://en.wikipedia.org/wiki/Model_checking) | every reachable state enumerated and stored | [SPIN](https://spinroot.com/) |
| [Symbolic model checking](https://doi.org/10.1016/0890-5401(92)90017-A) | sets of states held as decision diagrams or formulas, so large spaces are explored without listing them | [nuXmv](https://nuxmv.fbk.eu/) |
| [Unbounded model checking](https://doi.org/10.1007/978-3-642-18275-4_7) | a property proved for runs of any length, by induction or interpolation | [nuXmv](https://nuxmv.fbk.eu/), [Kind 2](https://kind.cs.uiowa.edu/kind2_user_doc/) |
| [Software model checking](https://doi.org/10.1145/1592434.1592438) | model checking over source code rather than a hand-written model | [CPAchecker](https://cpachecker.sosy-lab.org/), [Ultimate Automizer](https://ultimate.informatik.uni-freiburg.de/) |
| [CEGAR](https://doi.org/10.1007/10722167_15) | a coarse abstraction refined wherever a counterexample turns out spurious | [CPAchecker](https://cpachecker.sosy-lab.org/) |
| Temporal logic: [LTL](https://en.wikipedia.org/wiki/Linear_temporal_logic), [CTL](https://en.wikipedia.org/wiki/Computation_tree_logic) | properties over time, such as every request being answered eventually | [SPIN](https://spinroot.com/), [nuXmv](https://nuxmv.fbk.eu/) |
| [Probabilistic model checking](https://mitpress.mit.edu/9780262026499/principles-of-model-checking/) | probabilities and expected costs over systems that make random choices | [PRISM](https://www.prismmodelchecker.org/), [Storm](https://www.stormchecker.org/) |
| [Partial-order reduction](https://en.wikipedia.org/wiki/Partial_order_reduction) | interleavings that differ only in the order of independent steps explored once | [SPIN](https://spinroot.com/) |
| [Stateless model checking](https://doi.org/10.1145/263699.263717) | every thread schedule of a concurrent program run, without storing states | [GenMC](https://github.com/MPI-SWS/genmc) |
| [CSP](https://en.wikipedia.org/wiki/Communicating_sequential_processes) | processes and their communication as an algebra, checked by refinement | [FDR](https://cocotec.io/fdr/) |
| [Automated theorem proving](https://en.wikipedia.org/wiki/Automated_theorem_proving) | first-order goals proved without guidance | [Vampire](https://vprover.github.io/), [E](https://eprover.org/) |
| [Interactive theorem proving](https://en.wikipedia.org/wiki/Proof_assistant) | proofs written with a person steering and a kernel checking each step | [Rocq](https://rocq-prover.org/), [Isabelle](https://isabelle.in.tum.de/), [Lean](https://lean-lang.org/) |
| [Proof checking](https://en.wikipedia.org/wiki/Automated_proof_checking) | a small kernel that accepts or rejects a finished proof, so trust rests on the kernel alone | [Lean](https://lean-lang.org/), [Rocq](https://rocq-prover.org/), [Isabelle](https://isabelle.in.tum.de/) |

### test (enforcement level)

| concept | what it gives a check | example tools |
| --- | --- | --- |
| [Unit testing](https://en.wikipedia.org/wiki/Unit_testing) | one unit's behavior on chosen inputs | [pytest](https://docs.pytest.org/), [JUnit](https://junit.org/) |
| [Integration testing](https://en.wikipedia.org/wiki/Integration_testing) | components run against their real collaborators | [Testcontainers](https://testcontainers.com/) |
| [System testing](https://en.wikipedia.org/wiki/System_testing) | the whole system through its external interface | [Robot Framework](https://robotframework.org/) |
| [Regression testing](https://en.wikipedia.org/wiki/Regression_testing) | behavior that worked stays working across changes | [pytest](https://docs.pytest.org/), [JUnit](https://junit.org/) |
| [Property-based testing](https://doi.org/10.1145/351240.351266) | a stated property over generated inputs, with a failing case shrunk to a minimal one | [QuickCheck](https://hackage.haskell.org/package/QuickCheck), [Hypothesis](https://hypothesis.readthedocs.io/) |
| [Coverage-guided fuzzing](https://en.wikipedia.org/wiki/Fuzzing) | inputs mutated toward new code coverage until one fails | [AFL++](https://aflplus.plus/), [libFuzzer](https://llvm.org/docs/LibFuzzer.html), [honggfuzz](https://github.com/google/honggfuzz) |
| [Grammar-based fuzzing](https://en.wikipedia.org/wiki/Fuzzing) | inputs generated from a grammar, so they pass the parser and reach the logic behind it | [Grammarinator](https://github.com/renatahodovan/grammarinator) |
| [Structure-aware fuzzing](https://en.wikipedia.org/wiki/Fuzzing) | mutations over a typed structure rather than bytes | [libprotobuf-mutator](https://github.com/google/libprotobuf-mutator) |
| [Stateful fuzzing](https://en.wikipedia.org/wiki/Fuzzing) | sequences of calls or messages, reaching states no single input can | [Hypothesis](https://hypothesis.readthedocs.io/en/latest/stateful.html) |
| [Differential testing](https://en.wikipedia.org/wiki/Differential_testing) | two implementations fed the same input, and any disagreement reported | [Csmith](https://github.com/csmith-project/csmith) |
| [Metamorphic testing](https://en.wikipedia.org/wiki/Metamorphic_testing) | a relation between the outputs of related inputs, where nothing gives the right output itself | [Hypothesis](https://hypothesis.readthedocs.io/) |
| [Mutation testing](https://en.wikipedia.org/wiki/Mutation_testing) | faults planted in the code; a suite that passes over one has not tested it | [PIT](https://pitest.org/), [Stryker](https://stryker-mutator.io/) |
| [Combinatorial testing](https://en.wikipedia.org/wiki/All-pairs_testing) | every pair, or every t-tuple, of parameter values covered by few cases | [ACTS](https://csrc.nist.gov/projects/automated-combinatorial-testing-for-software) |
| [Search-based testing](https://en.wikipedia.org/wiki/Search-based_software_engineering) | test inputs found by optimizing toward a coverage goal | [EvoSuite](https://www.evosuite.org/) |
| [Coverage analysis](https://en.wikipedia.org/wiki/Code_coverage) | which lines, branches or conditions a suite ran; a measure that stops measuring once it is a target, as [goodharts-law](../principles/goodharts-law.toml) says | [llvm-cov](https://llvm.org/docs/CommandGuide/llvm-cov.html), [gcov](https://gcc.gnu.org/onlinedocs/gcc/Gcov.html) |

### runtime (enforcement level)

| concept | what it gives a check | example tools |
| --- | --- | --- |
| [Dynamic analysis](https://en.wikipedia.org/wiki/Dynamic_program_analysis) | facts observed on real executions, exact for the runs seen and silent about the rest | [Valgrind](https://valgrind.org/), [DynamoRIO](https://dynamorio.org/) |
| [Runtime verification](https://en.wikipedia.org/wiki/Runtime_verification) | a monitor checking a specification against the trace of a running program | [RV-Monitor](https://runtimeverification.com/) |
| [Memory instrumentation](https://en.wikipedia.org/wiki/Instrumentation_(computer_programming)) | every access checked against allocation bounds and lifetimes | [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html), [Valgrind](https://valgrind.org/) |
| [Race detection](https://en.wikipedia.org/wiki/Race_condition) | unsynchronized conflicting accesses found from the happens-before order of a run | [ThreadSanitizer](https://clang.llvm.org/docs/ThreadSanitizer.html), [Helgrind](https://valgrind.org/docs/manual/hg-manual.html) |
| [Dynamic taint analysis](https://en.wikipedia.org/wiki/Taint_checking) | untrusted bytes tracked through a running program to where they are used | [Triton](https://triton-library.github.io/) |
| [Deadlock analysis](https://en.wikipedia.org/wiki/Deadlock_(computer_science)) | lock-order cycles seen in one run, which can deadlock in another | [Helgrind](https://valgrind.org/docs/manual/hg-manual.html), [ThreadSanitizer](https://clang.llvm.org/docs/ThreadSanitizer.html) |

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
