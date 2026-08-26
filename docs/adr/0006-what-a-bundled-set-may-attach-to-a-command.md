# ADR 0006: what a bundled set may attach to a command

Status: Accepted

This record answers a question two earlier decisions left standing on opposite
sides of one seam: may a bundled set carry rules that run when a command is
about to publish text? `private-names` wrote down the case against and shipped
without them; a fleet sweep then measured what that bought. This is the
reconciliation, and `published-text` is the set built on it.

## The two decisions that collided

**A set must not put a program in front of a real command.** A `[[shim]]` on
PATH is reached by every invocation of that command in a participating tree.
Acquiring one by writing a set's name in an `[inherit]` line — one word, whose
meaning can widen with a version bump — is not a decision anybody visibly made.
`private-names` records the same objection against shipping a shell command in
a set: a bundled `exec` line runs on every inheriting machine with nothing in
any tree to review.

**A transcribed rule is the failure this repository exists to refuse.** Six
repositories in one workspace declared the same three checker rules by hand —
same ids, same `command.before`, same two `exec` lines re-invoking this binary
from PATH. One copy had grown an `UPHOLD_ALLOW` prefix, one a
`private_owners_from` the others deliberately omit, and nothing compared the
copies. That is the drift `policy/base/` was invented to end, sitting at the
one seam no set was allowed to reach.

Both decisions are right, and holding both as stated leaves the fleet
transcribing forever. The resolution is to notice they are about different
halves of the seam.

## The split: the shim is a decision, the checker is a rule

A shim and the checkers it consults were already two things — `validate_shims`
refuses either one standing alone. They have different owners:

* **The shim is the repository's.** Which commands this tree stands in front
  of, which verbs carry text, which flags mean what — that is a decision about
  a real command on a real machine, made visibly, in the tree it binds. No set
  ships one. `parse_bundled` now refuses a set that tries, rather than letting
  only `.rules` be adopted and the table vanish in silence.

* **The checker is the engine's.** "Published text satisfies the text-capable
  guards" is not a per-repository judgment; it is the same rule everywhere,
  which is why six repositories had written it out byte-alike. A set may carry
  it — under a ceiling, and only into a repository that has already made the
  shim decision itself.

## What makes the arrival safe

**A `[set] commands` ceiling, beside `stages`.** Each set declares, verbatim,
the `command.before` lines its rules may name; a rule reaching past it is
refused at load. Verbatim lines rather than first words — `"git push"` does
not admit `"git"` — so a set cannot widen its reach without editing the line
that says what it may do, which is a diff in the one repository that can
review it.

**The shim tables are still not optional.** A `command.before` entry names a
`[[shim]]`, and a repository inheriting `published-text` without declaring the
tables is refused at load, with the refusal naming the set and the cure that
is actually available — declare the table, or drop the set. This is the
`unowned-push` shape at a new seam: the set supplies the rule and refuses to
run until the repository has answered the question only it can answer.
Nothing arrives quietly: the `[[shim]]` line in the policy is the visible
decision, exactly where ADR 0002 wants it.

**In-process consultations instead of a shipped shell line.** The hand copies
ran `uphold scan --text -` and `uphold guard --text -` as subprocesses. A set
may not ship a shell command, and the subprocess had a second defect the
objection did not even need: it answered with whatever `uphold` PATH happened
to reach, which is not necessarily the binary that asked. `text-guards` and
`text-literals` are the same two consultations as built-ins — the dispatch
`guard --text` and `scan --text` already run, reached without a process, a
PATH, or a version skew. They judge text and nothing else, so `command.before`
is the only place a rule may put them; at a git hook or in a scan every rule
they would consult already runs itself, and a declaration there is refused at
load rather than reporting each finding twice.

**The recursion is closed by construction.** `text-guards` runs the other
text-capable guards and never itself: `over_text` skips the meta guards, so
the consultation is one level deep however a policy is written.

## What was deliberately not built

* **A per-repository command list handed to the set.** This repository stands
  in front of `glab` and `npm` as well; the set ships `["gh", "git push"]`,
  the two lines all six transcriptions shared. A rule arriving from a set
  cannot be handed a parameter, and the documented override — shadow the id,
  same built-in, wider `command.before` — says the widening in the one file
  that can. This policy does exactly that, so the shape is exercised where it
  ships.

* **Attaching to every declared shim implicitly.** "Run wherever the
  repository put a shim" reads well until a repository shims a command whose
  subjects are not prose — `npm` is shimmed here for its tarball metadata, and
  `no-published-markers` deliberately does not stand in front of it, because a
  guard that reads prose has nothing to say about a package directory and a
  pass from it would be a check that did not happen. The rule names its
  commands; the ceiling names the rule's reach; nothing is inferred.
