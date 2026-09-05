# Configuration reference

Everything below lives in one file, `policy/principles.toml`, in one flat id
namespace — that is what lets a claim in
[`policy/upheld.toml`](../policy/upheld.toml) name a rule by id alone.

- [Rule shape](#rule-shape)
- [`uphold scan` — the content policy](#uphold-scan--the-content-policy)
- [`uphold guard` — the guards](#uphold-guard--the-guards)
- [`uphold shim` — the shims](#uphold-shim--the-shims)
  - [The links, and what reaches them](#the-links-and-what-reaches-them)
- [`uphold audit --for-publication`](#uphold-audit---for-publication)
- [`uphold hooks --identity` — across repositories](#uphold-hooks---identity--across-repositories)
- [`uphold probe` — can each hook refuse?](#uphold-probe--can-each-hook-refuse)
- [`uphold check --coverage` and `--oscal`](#uphold-check---coverage-and---oscal)
- [The review tier](#the-review-tier)
  - [Controls: can a record produce a finding at all?](#controls-can-a-record-produce-a-finding-at-all)

## Rule shape

One rule is one section, and **the id is the section header**:

```toml
[rule.no-conflict-markers]
regexp = '^<{7} '
message = "resolve the conflict"
files.glob = ["*.md"]
```

Everything about a rule lives inside its section — there is no `id` field and
no detached sub-table to drift away from its rule during an edit. Two sections
with one id are a TOML parse error. Kebab-case ids are legal bare keys; quote
anything else (`[rule."my rule"]`).

**What it checks** — one field, no discriminant beside it:

| field | fails when |
|---|---|
| `regexp` | the regex matches anywhere in the selected files |
| `comment_regexp` | the regex matches a **comment** in a selected Rust, Python or Go file |
| `prose_regexp` | the regex matches the **prose** of a selected file — a document minus its code blocks, a source file's comments, a configuration file's `#` lines |
| `trivial_comments` | a comment contributes no word the code beneath it already names |
| `path_regexp` | a tracked path matches the regex |
| `require_regexp` | a selected file does **not** contain the regex |
| `max_lines` | a selected file is longer than that, or grew past its baseline |
| `max_bytes` | a selected file is bigger than that, or grew past its baseline |
| `forbidden_literals` / `forbidden_literals_from` | a runtime literal — username, hostname, route — appears in them |
| `encoding` | a selected file does not decode cleanly under the declared charset |
| `allowed_scripts` | a letter uses a Unicode script outside the declared list |
| `builtin` | a check compiled in here says so — see [the guards](#uphold-guard--the-guards) |
| `exec` | an executable you name says so |

**Where it runs** — up to three key groups inside the rule's section, each in
the vocabulary of the thing that runs it. **Absent keys are a place the rule
does not run.**

| keys | vocabulary | runs it |
|---|---|---|
| `files.*` | ripgrep scoping — `glob`, `multiline`, `fixed_strings` — and `min_selected`, the floor under what the scoping leaves | `uphold scan` |
| `git.hooks` | githooks(5) names — `pre-commit`, `commit-msg`, `pre-merge-commit`, `pre-push`, `manual` | `uphold guard --stage <hook>` |
| `command.before` | the command line as typed — `"gh pr create"`, `"git push"` | `uphold shim <command>` |

Both halves are checked at load. A rule naming two checks is refused, because
one of them would be read by nothing while looking enforced. A rule naming no
place is refused, because it runs nowhere and that reads exactly like a rule
that passes. `command.before` is refused on a check no shim can consult — the
shim consults `exec` checkers, the three pattern checks (`regexp`,
`require_regexp` and `prose_regexp`, which mean the same thing against a title
as against a line of a file), the built-ins that can judge arbitrary text
(`prevent-ai-author`, `prevent-unusual-unicode`, `no-private-repo-names`, and
the two consultations `text-guards` and `text-literals`), and the built-in that
judges a **destination** rather than text (`prevent-unowned-target`); anything
else reads an index, an identity or a push range and has nothing to say about a
pull-request body. The destination-judging built-in is refused in the other
direction too — `git.hooks` or `files.*` beside it, where nothing hands it a
destination, would be a rule looking at nothing and reporting clean.

A pattern rule at this seam may also say **which subjects** it is asked about,
with `subjects` — a list drawn from `text`, `title`, `path`, `ref`, `argv` —
and the filter narrows every kind of checker the same way. Absent means every
subject, which is every rule written before the field existed; `subjects`
anywhere but beside `command.before` is refused, because nothing else hands a
rule a subject that has a kind. The worked example is the release title:

```toml
[rule.release-title-is-the-tag]
message = "Title a release by its tag -- vX.Y.Z; the prose belongs in the notes."
require_regexp = '^v[0-9]+\.[0-9]+\.[0-9]+$'
subjects = ["title"]
command.before = ["gh release create", "gh release edit"]
command.scope = "always"     # a format is a fact about the text, not the destination
```

The same shape reaches a branch- or tag-naming convention through
`subjects = ["ref"]` on `git push`. These rules run at the shim seam only —
`uphold hook` hands a harness's call to the text guards, the literal rules and
the prose rules, and a pattern scoped to one command's subjects has no flag
vocabulary there.

`text-guards` and `text-literals` are the same dispatches `uphold guard
--text` and `uphold scan --text` run, as built-ins: every text-capable guard
the policy declares, and every literal rule plus the running-host fallback,
consulted in-process. They exist so a checker does not have to be written as
`exec = "uphold guard --text -"` — a subprocess that answers with whatever
`uphold` PATH happens to reach, which is not necessarily the binary that
asked. They judge text and nothing else, so `command.before` is the only
place a rule may put them; at a git hook or in a scan every rule they would
consult already runs itself, and a declaration there is refused at load.

A text-capable built-in with `command.before` and no `git.hooks` is a deliberate
shape, not an omission. `no-private-repo-names` reads the commit message at
every git hook, and a repository whose own prose cites its issues would have
every one of those citations refused — so the seam it belongs at is the command
that publishes text to a forge, and only that one.

### One command, more than one flag vocabulary

A `[[shim]]` names one `text_flags` for a whole command, and a command's flags do
not all mean one thing. On `gh`, `-c` is a **boolean** on `pr review` -- "Comment
on a pull request" -- and **takes a value** on `issue close` -- "Leave a closing
comment". Name it once for the table and one of the two is read wrong:

* named -- `gh pr review -c -b "body"` reads `-c` as consuming `-b`, and the body
  being published goes unread;
* not named -- `gh issue close --comment "text"` publishes with nothing in front
  of it.

Both are false negatives in the seam that exists to prevent one. A second
`[[shim]]` for the same command is not the answer either: it is refused at load,
because two vocabularies for one command have to be merged and merging is the
same guess in a different place.

So a table may carry entries for the verbs whose grammar differs:

```toml
[[shim]]
command = "gh"
match = ["pr:review", "issue:close"]
text_flags = ["-b", "--body"]
title_flags = ["-t", "--title"]

  [[shim.verbs]]
  match = ["issue:close"]
  text_flags = ["-c", "--comment"]
```

`match` takes the same `verb:noun` and `verb:*` spellings the table's own does,
and every entry must name a verb the table matches -- a vocabulary for an
invocation the shim does not stand in front of classifies nothing, and is refused
at load.

**The entry's lists replace the table's** for the verbs it names, rather than
adding to them. Same rule as `allowed_scripts`, for the same reason: what is
declared beside the narrower thing is the whole truth for it. A union would mean
a vocabulary nobody wrote -- here `issue close --body`, a flag the real command
does not accept -- and reading a flag a command will not take is the shim
claiming to have checked a subject that was never published.

`text_flags`, `title_flags`, `file_flags`, `path_flags`, `skip_flags` and
`web_flags` may be overridden. `target_flags` may not: `-R`/`--repo` means the same thing on every
verb, and a per-verb answer to "which repository is this going to" would be a way
to publish somewhere the table did not expect.

### A baseline entry may be asked to say who excused it and why

`files.baseline` names a file of repository-relative paths a rule excuses, and
an entry that no longer matches is reported as stale -- an exemption that has
stopped describing the tree is the rule switched off for that path.

A baseline holds two different things and the format could only express one:

* **debt** -- eight modules awaiting the same migration. One reason at the top
  of the file covers every entry, and the file's header is the right place for
  it.
* **exceptions** -- the places a rule is simply wrong. `.ljust(` building a
  five-column table should take the dependency; `.ljust(` building a two-column
  key/value list is correct and a table would read worse. No pattern separates
  those, so the entry excusing the second has to carry the judgement, and the
  whole line was the path.

So an entry may be signed:

```text
# the places this rule is wrong
src/cli/top.py | alice | a two-column key/value list; a table reads worse
```

`path | owner | reason`, with `|` as the separator -- whitespace already
separates the size baseline's count and a path may hold it, and `#` at line
start already means a comment.

Set `baselines_signed = true` at the top of the policy to require it. Off by
default, which is what every existing baseline file already is; a repository
turns it on when its baselines stop being one homogeneous debt. Unsigned
entries are then reported at the same tier as stale ones, and for the same
reason: both are a baseline that has stopped recording a decision somebody made.

A signature is an addition to the record and not a way out of it. A reason says
why an entry is there; it says nothing about whether it still needs to be, so a
signed entry still goes stale.

### A rule may declare a floor under what it selects

`files.min_selected = N` fails the rule when its selection comes in under `N`
files, naming the floor, the count and the keys that produced the count.

The defect it closes is the quietest one here. A rule that selects nothing runs
cleanly over nothing, and every check kind reports that the same way:

| check | with zero files selected | reported |
|---|---|---|
| `regexp` | nothing to match | `policy checks passed` |
| `require_regexp` | nothing to be missing the pattern | `policy checks passed` |
| `max_lines` | nothing to be too long | `policy checks passed` |
| `prose_regexp` | nothing whose prose could be read | `policy checks passed` |

`require_regexp` is the sharpest of the three, because its whole job is to
insist that something is there. Rename the directory its `include` names, or
narrow its `glob` past the files it was written for, and the rule stops
insisting — permanently, silently, and with a green run every time. An
`include` root that is not there is already named on stderr, but stderr is not
an exit code, and a `glob` that stops matching is not reported at all.

So the floor is written down, and the count is measured against it:

```toml
[rule.workflows-declare-permissions]
require_regexp = '^permissions:'
message = "declare the token scopes the job needs"
files.include = [".github/workflows"]
files.glob = ["*.yml", "*.yaml"]
files.min_selected = 1
```

```text
policy check failed: workflows-declare-permissions (selection floor)
This rule selected fewer files than it declared it must. ...
selected 0 file(s), and `files.min_selected = 1` requires at least 1.
The keys that selected them: include = [".github/workflows"], glob = ["*.yml", "*.yaml"]
```

**A number rather than a `require_selection = true`**, because one is a value
and not a kind of floor: a repository whose selection must cover four workflow
files writes `4`, and no second field has to be invented for it. `1` is the
smallest claim the field can make — *this rule still selects something* — and
is what most rules want. `0` is refused at load, because every selection there
is meets it, the empty one included: the line would declare a floor and enforce
nothing.

**Every check whose selection this scan builds reads it**, and that is a
decision rather than a convenience. Zero *findings* is the goal state for a
match-forbidding rule; zero *files* is the goal state for none of them, so
"this rule still covers something" is as live a claim under `regexp` as it is
under `require_regexp`. The floor is measured at the one place every rule's
selection passes through, so a check kind added later carries it without its
author having to know the field exists.

Where it is refused is a **guard** built-in carrying `[rule.files]` —
`prevent-unusual-unicode-in-files` scoped to `docs/`, say. There the table is a
scope the guard applies to one path at a time, and the scan never dispatches the
rule, so no count is ever taken for a floor to stand under. The three built-ins
the scan does select for — `links-resolve`, `anchors-resolve`,
`commands-resolve` — accept it, and it counts *files* where `require_any_link`
counts links and `require_any_anchor` counts anchors. A `links-resolve` rule may
hold both; they fail differently, and a glob typo is caught by the one that
counts files.

### A rule may not be about its own declaration

A policy file is a tracked file, so a rule's `regexp` and `require_regexp` are
inside the corpus that rule scans. An unanchored literal therefore matches the
line it is written on, and both fields reach the same accident from opposite
directions:

| field | must find | a self-match is |
|---|---|---|
| `regexp` | nothing | a finding that is always there, naming the rule instead of the tree |
| `require_regexp` | something | a pass that is always there, exempting the policy file forever |

**A rule that matches its own declaration *and* selects the file that
declaration is in is refused at load.** Both halves are required. Most rules
never select the policy file — an `include` of `["cmd", "internal"]` with a
`glob` of `["*.go"]` cannot reach `policy/` — and a pattern matching its own
text under such a rule is harmless, so the scope test comes first.

Three cures, and the refusal names all of them:

```toml
[rule.no-yubikey-mentions]
regexp = '\bYubiKey\b'
[rule.no-yubikey-mentions.files]
include = ["."]
exclude = ["policy/**"]     # 1. exclude the policy file
```

2. narrow `files.include` to what the rule is actually about;
3. anchor the pattern, so it cannot match the key it is written under.

The third is worth knowing before reaching for the first. `^Status:` does not
match `regexp = '^Status:...'`, because that line begins with `regexp` — so an
anchored pattern needs nothing, and a one-character class written to dodge a
self-match it never had (`^Sta[t]us:`) is a defensive edit that can be deleted.

Own rules only. A bundled set's rule is declared inside the binary and an
`inherit.paths` rule in a file the rule may not select; neither has a
declaration in this policy file to match.

Exit codes: `0` clean, `1` violations, `2` the check could not be made.

There is no fourth. A reader that closes a pipe — `uphold scan | head` — is a
reader's decision and not a failed check: the rest of the output is dropped and
the code stays whatever the run decided. A write that fails for any other reason
is `2`, because the report is then not where it was sent and a caller holding
half a file must not read `0` as a clean tree.

## `uphold scan` — the content policy

Evaluates every rule over the repository's own files, using ripgrep's search
libraries rather than a second regex engine.

**What "the repository's own files" means is what git tracks.** The globs in
`[rule.files]` are applied to `git ls-files`, not to a directory walk. A tracked
file that some ignore pattern also matches — a `.gitignore` line, a
`.git/info/exclude` entry, or the operator's *global* ignore file, which is not
in the repository at all — is still tracked, still pushed, and still read by
everyone who clones it, and a walker that honoured those patterns could not see
it. In a directory git has no index for, the tree is walked instead with **no**
ignore file consulted, which selects a superset of what would be tracked.
Over-reporting is the direction a checker may fail in; hiding a file is not.

A path a rule selected and could not open — an unstaged deletion, a sparse
checkout, a directory this process may not enter — is **named on stderr and is
exit `2`**, after every other rule has reported. It is not dropped from the
list, because a rule that searched what was left and found nothing there would
otherwise print `policy checks passed` over a tree it never finished reading.
A finding outranks it: `1` when something was found, `2` when nothing was found
and something could not be read, `0` only when the whole selection was read and
was clean.

```toml
allowed_scripts = ["Latin"]

[inherit]
sets = ["process-residue"]          # bundled sets, named by what they refuse
disabled_rules = ["no-task-tracker-references"]

[rule.workflow-declares-permissions]
require_regexp = '^permissions:'
message = "declare the token scopes the job needs"
files.include = [".github/workflows"]
files.glob = ["*.yml", "*.yaml"]
```

`inherit.sets` names bundled sets to inherit; it does not add settings. There
is no `true` shorthand — naming the sets is cheap, and what a repository
inherits should be written in the repository. Twenty are compiled into the
binary and mirrored in [`policy/base/`](../policy/base), each **named by what
it refuses** so the name predicts the rule list:

| set | refuses |
|---|---|
| `process-residue` | authoring and process residue in committed content — conflict markers, home paths, dated and status metadata, tracker and thread references, private data paths — and the residue a process leaves in the policy file itself: a rule transcribed out of a set. **Installs `pre-commit` and `manual`**, and the two report different things |
| `credentials` | credential material — private keys and service tokens, literal credential values, populated environment files, browser profile and session stores |
| `unmanaged-pins` | a version pinned where no manifest holds it — a shell install line, a `releases/download/vX.Y.Z` URL, a versioned `curl` or `wget` |
| `host-identity` | the machine the author is standing on — its username, home path, hostname and default route, read at scan time and searched for in content |
| `broken-links` | a markdown link naming a path that does not exist or leaving the repository, and a selection that yields no links at all |
| `captured-fixtures` | a test fixture holding non-ASCII content, as the one signal that a capture from a live upstream survives redaction |
| `doc-claims` | a document whose anchored fact disagrees with the record it names — a value the record does not hold, a key that is not there, a source or captured artifact that is absent |
| `default-token-grant` | a GitHub Actions workflow with no top-level `permissions:` block, whose `GITHUB_TOKEN` is therefore scoped by a repository setting rather than by the workflow |
| `hand-rolled-toolchain` | a host tool installed by hand where a version manager was available — a `curl \| tar` download-and-unpack, and the `$HOME/.local` symlink that puts its output on PATH. Deliberately silent on `curl \| sh` (a version manager's own bootstrap has nowhere else to live), on a host-prerequisite manifest beside it (a resolver provisions, a doctor verifies), and on distro packages |
| `comment-facts` | a measurement of your own data stated in a source comment, where no anchor can ever recount it — `# 60 s timeout`, `// ~127 MB of rlib`, `# 3 of 5 done`. The other half of `doc-claims`: that one checks a fact somebody anchored, this one refuses the shape of a fact nobody can anchor. Scoped to lines whose first token opens a comment, in source files by extension, so a string literal and a markdown bullet are never read. Lets through a version (`v1.14.1`, `Go 1.25`), a date (`2026-09-04`) and a citation (`ADR 0005`, `issue 101`), none of which is followed by a unit. Cannot tell your data from a number that is not yours — a platform constant, a limit the code enforces, a worked example — so it refuses the shape and the reader decides. Installs no git hook; the fix is to drop the measurement (or move it to the commit or pull-request body), and for a number that is not a measurement to give the code a named constant the comment points at. Never spell the digits out as words |
| `commit-message-residue` | authorship markers and unusual characters in the message a commit records — **installs `commit-msg`** |
| `unreviewed-history` | a merge made locally rather than through a pull request — **installs `pre-commit` and `pre-merge-commit`** |
| `mismatched-author` | a commit whose author or committer identity disagrees with the global one on the machine making it — **installs `pre-commit`**, and declines with a note where no global identity is configured |
| `invisible-characters` | characters that draw nothing, in committed content and in the paths that carry it — **installs four stages**, and reads the whole tree at each |
| `stale-pins` | a hook pinned at a revision its upstream has left, or at none — **installs `manual`** alone, and reaches the network |
| `unowned-push` | a push to an owner this repository has not named — **installs `pre-push`**, and refuses to run until the repository says who it is |
| `private-names` | a private organisation or repository named in a commit message, a staged diff, or the tracked tree of a **public** repository — **installs five stages**, and refuses to run until the repository says whether it is published |
| `stale-visibility` | a policy declaring `private` over a repository the forge serves as **public** — **installs `pre-push` and `manual`**, and reaches the network. Refuses that one direction only; it can never confirm privacy |
| `published-text` | host identity, refused markers and private names in the text a command is about to publish — a pull-request body, an issue title, a branch name in a push. **Installs no git hook**: its rules run at the shim seam (`gh`, `git push`), and it refuses to load until the repository has declared the `[[shim]]` tables itself — see [ADR 0006](adr/0006-what-a-bundled-set-may-attach-to-a-command.md) |
| `prose-shapes` | four sentence shapes that carry nothing — a sentence announcing what the next one will say, a clause behind a dash restating the one in front of it, a hedge admitting no uncertainty, an objection nobody raised being answered. **Installs no git hook**: its rules run in `uphold scan` and at the shim seam (`gh`, `git push`), and like `published-text` it refuses to load until the repository has declared the `[[shim]]` tables itself. `UPHOLD_ALLOW=<rule-id>` is the waiver for the sentence a rule is wrong about |

The eight before it install git hooks. Taking one is a decision about what will be
refused and when, so each is named and argued separately: `stale-pins` reaches
the network and cannot answer on a train, `invisible-characters` reads the tree
at four stages and is the slowest thing in a hook, `unreviewed-history` stands
in front of every commit, and two of them demand one line before they will run
at all:

```toml
owner = "your-org"          # at the top of the policy file
visibility = "public"       # ditto

[inherit]
sets = ["unowned-push", "private-names"]
```

Both are top-level fields rather than rule parameters because a rule arriving
from a set cannot be handed one — the only way would be to write the rule out
again, which is the transcription `no-hand-copied-base-rule` refuses — and
because neither fact was ever a property of one rule.

`owner_required = true` on the rule is what makes the omission an exit `2`
rather than a guard that quietly reads the answer off `origin`, which is the
remote most likely to be the thing that went wrong. `allowed_owners` or
`allowed_repos` satisfy it too: naming the destinations is a way of saying who
you are.

`visibility_required = true` is the same argument for the other fact. The
private-name guards fire on one condition — is this tree public — and left to
themselves they ask the forge, which answers `unknown` with no token, `unknown`
with no network, and answers about the visibility a repository has *today*,
which is the thing that changes on the day it matters. `visibility = "private"`
is a real answer, not an opt-out: it says the condition does not hold here.

**What then checks the declaration** is `stale-visibility`, and it is a separate
set because it reaches the network. Declaring the visibility makes the guards
offline and deterministic, and it also makes the file a **cache with no
reconcile**: flip a repository to public and the policy goes on saying `private`
forever, with the three private-name guards standing down over a tree everybody
can read.

The rule refuses **one direction and only one**, because that is the only
direction a probe can establish. No probe can prove a repository is private — a
`404` is a private repository, a deleted one, a renamed one, and a request that
carried no credentials — while any probe can disprove it, and disproving it is
what catches the leak.

| declared | what the forge says | outcome |
|---|---|---|
| `public` | not asked | passes, and says no request was made |
| `private` / `internal` | `public` | **refused**, naming the flip |
| `private` / `internal` | `private` / `internal` | passes |
| `private` / `internal` | nothing it could be asked | **exit `2`** — never "confirmed private" |
| nothing declared | not asked | **exit `2`** — no claim to check |

The last two rows are the design. If a failed lookup could settle the answer,
an offline laptop would flip the guards to `private` and disarm a disclosure
check in silence, which is fail-open on the one family where fail-open is
unacceptable. The declaration stays the input; the probe only ever refuses.

It installs at `pre-push` and `manual` and never at `pre-commit`, for the reason
`stale-pins` gives: a guard that adds a network round trip to every commit is
one somebody comments out.

**Two different "unknowns", and only one of them is `refuse_unknown`'s.** A
forge that *answers* `404` has told you something about the name: no repository
it will show you is called that. A forge that could not be asked — no `gh`, no
credentials, a rate limit, no network — has told you nothing, and the guard did
not run. These were one state, which meant an unauthenticated `gh` printed a
line per name and then permitted the commit. They are separate now:

| what happened | outcome |
|---|---|
| forge answers `public` | passes |
| forge answers `private` / `internal` | refused |
| forge answers `404` | reported; refused only under `refuse_unknown` |
| forge could not be asked | **exit `2`** — always, whatever `refuse_unknown` says |

The shim seam asks the same forge the same question, for a different purpose —
`scope = "public-target"` is "do these checks apply here at all" — and it now
gives the bottom row the same answer. A scope that could not be *evaluated* is
neither "in scope" nor "out of scope", and reading it as out of scope stood the
checkers down exactly where the lookup failed. That is exit `2` before the
command runs, and `unresolved = "run"` on the `[[shim]]` table is the opt-out —
see [the shims](#uphold-shim--the-shims).

So **`gh` must be authenticated wherever these rules run**, CI included. In a
GitHub Actions job that means `GH_TOKEN: ${{ github.token }}`; the job token
reads this repository and public ones and answers `404` for everything else,
which is the right answer for an invented name. This is a real behaviour change:
a run with no token used to report every name as unresolved and pass, so a job
without one was running the family and reaching a verdict on nothing.

`private-names` does not turn `refuse_unknown` on. What is left fail-open under
that default is the `404` alone, and a `404` is what every invented name in
every document produces: measured on the tree that ships the set, fifteen names
answer `404` and every one is a documentation or test fixture. Turn it on per
repository after naming those in `public_repos`.

**A name on a host that is not GitHub.** `gh` answers for github.com and for
nothing else -- a GitHub Enterprise host is a different forge that happens to
share the software, and asking github.com about a name seen on
`github.acme.com` answers about somebody else's repository. Every other
`host.tld/owner/repo` is therefore a name this tool has no answer for, and which
of two answers it gets depends on **whose name it is**:

| the owner segment | outcome |
|---|---|
| a declared `private_owners` owner, or the policy's own `owner` | **exit `2`** -- could-not-look, printed beside any finding |
| anybody else | reported as unresolved; refused only under `refuse_unknown` |

The split is the whole of it. A repository under an owner this policy has named
is the case the rule exists for, and silence about it is not a pass. Every other
`host.tld/a/b` is a DOI, a licence URL or an encyclopaedia article -- the shape
of a repository name and not one -- and calling those could-not-look would make
the cure "enumerate every host you cite" in every consuming repository, which is
`parameterize-do-not-enumerate` with the enumeration moved out of the binary and
into every policy file.

`foreign_hosts` is how a repository says a host is not a forge at all, which
quiets both rows:

```toml
foreign_hosts = ["git.acme-internal.example", "*.sr.ht"]
```

Host globs, matched case-insensitively. It is a top-level policy field for the
reason `private_owners_from` is one -- a rule arriving from a bundled set cannot
be handed a parameter -- and a rule may write its own list, which **replaces**
the policy's for that rule rather than extending it. Nothing is quieted by
default: which hosts carry a repository worth an answer is a fact about the
repository, not about this tool.

`doc-claims` is the one set whose rule needs the author to write something
beside the prose, so its grammar is here rather than only in the set. A
document that leans on a value carries a marker naming where the value lives:

```markdown
<!-- fact-anchor: source=config/services/db.yaml key=read_path states=api -->
#    fact-anchor: source=config/accounts.toml key=sbi.tier states=broker
//   data-anchor: artifact=captures/*/filing.json states=the issuer's own NAV
```

`source` is a repository-relative YAML, TOML or JSON file and `key` a dotted
path into it, where an integer segment indexes a list and a negative one counts
from the end. `states` is the value the prose relies on and **runs to the end of
the marker** — a stated value has spaces in it often enough that stopping at the
first would silently compare half of it — with a trailing `-->` or `*/` not part
of it. A null renders as `none`, a boolean lowercase.

`artifact` is a glob, and a `data-anchor` is checked only for **presence**. The
value inside is never compared, because the point of a captured document is that
this repository does not get to say what it contains; what fails is a literal
standing in for a document nobody captured.

Unlike `broken-links`, this set does **not** set a floor by default. Zero
anchors is the goal state — every fact rendered or read at runtime, no sentence
needing one pinned — so `require_any_anchor = true` is opt-in for a repository
that has decided its anchors are load-bearing.

Each is named separately because taking one is a separate decision:
`unmanaged-pins` refuses a shape a repository that vendors its dependencies
has on purpose, `host-identity` shells out to read the running machine, and
`captured-fixtures` refuses the script a parser's own test corpus is made of.
None of those arguments should stand between anyone and `process-residue`. The
binary answers "what is in it" directly:

```sh
uphold rules --set process-residue           # the set's rules, one per line
uphold rules --set process-residue --json    # the same set, field for field
uphold rules --sets --json                   # every bundled set, field for field
```

The JSON form exists for one question the summary cannot answer. A set ships
compiled in, so a pattern edited between two releases changes what is refused in
every repository that inherits it, **with no diff in any of them**:

```sh
diff <(uphold-1.1 rules --sets --json) <(uphold-1.2 rules --sets --json)
```

The same document is committed here as
[`policy/base/sets.lock.json`](../policy/base/sets.lock.json), and a test
refuses a tree where it has drifted from what the binary would install — so a
change to a bundled set is a reviewable diff in the repository that owns it.

**What a set may install is declared in the set**, and it is a ceiling rather
than a description:

```toml
[set]
stages = ["pre-commit", "manual"]   # empty (the default) means: no git hook at all
commands = ["gh", "git push"]       # empty (the default) means: no command at all
```

A rule in a bundled set declaring a hook outside that list is refused at load.
`commands` is the same ceiling for the shim seam: the `command.before` lines
the set's rules may name, matched **verbatim** — `"git push"` does not admit
`"git"` — so a set cannot widen its reach without editing the line that says
what it may do. What the ceiling does not grant is a shim: a set declaring
`[[shim]]` is refused outright, and a repository inheriting a set whose rules
name a command it has no `[[shim]]` for is refused at load with the table to
write, because a program in front of a real command is a decision the
repository makes visibly or not at all
([ADR 0006](adr/0006-what-a-bundled-set-may-attach-to-a-command.md)).
The constraint it makes mechanical is *a new guard gets a new set name rather
than joining an existing one*: a content rule arriving with a version bump is a
finding somebody argues about, and a guard arriving the same way is a commit
refused in every inheriting repository at once. Widening `stages` is possible
and is a one-line diff that says so. `[set]` in a repository's own policy, or in
an `inherit.paths` file, is refused — nothing there ships compiled in, so
nothing there has the problem the ceiling exists for.

A repository's own rule of the same `id` shadows the inherited one;
`inherit.disabled_rules` drops it, and naming an id nothing inherited defines
is an error rather than a line that quietly does nothing. `inherit.paths`
merges extra policy files, repository-relative, after the bundled sets.

Two things a set says out loud, because a set is the one place a rule can run
from without appearing in any file in the repository it runs in:

- **A refusal names the set it came from**: `guard refused: no-merge-commit
  [set: unreviewed-history]`. A reader greps their policy for that id and finds
  nothing, because the whole declaration is one word in an `[inherit]` line.
- **An override that changes the CHECK is reported at load**, on stderr, as a
  note and not a refusal. Narrowing an inherited rule is supported; replacing a
  compiled-in `builtin` with a `regexp` of your own under the same id is a
  private copy of somebody else's rule, and it is invisible to everything else
  here — the id resolves, so every claim naming it reconciles green.

The same argument in the other direction is a check: `no-hand-copied-base-rule`
(shipped in `process-residue`) refuses a rule written out by hand under an id a
set already ships, from a set the repository does not inherit. It names the id,
the owning set, and what else inheriting that set would bring. A rule of the
same id from a set the repository **does** inherit is the documented override
and stays silent.

It runs at two stages and they answer different questions:

| stage | what it reports |
|---|---|
| `pre-commit` | only the ids **this change adds**, against the policy file at `HEAD` |
| `manual` | **every** transcription in the policy — the sweep |

The split is why it can sit at a hook at all. It shipped at `manual` alone, and
a sweep of 77 repositories then measured what that bought: 76 of them inherited
the set, so the check was *loaded* almost everywhere, and roughly forty carried
a transcription it had never once reported — nothing runs a manual stage on its
own. A report nobody asks for is coverage of zero. Refusing the *addition*
rather than the *state* costs nothing in a repository that adds none, so the
hook arrives with no commit to be surprised by, while a transcription written
after it cannot be committed silently.

Those five fields interact, so "which rules does this repository run" is not a
question anyone can answer by reading the `[rule.*]` tables. The loader answers
it:

```sh
uphold rules --effective          # every resolved rule, and where it fires
uphold rules --effective --json   # the same, for a program
```

The JSON is one array of `{"id": ..., "git_hooks": [...], "seams": [...]}`, in
the order the engine resolved them. It exists so that nothing has to
re-implement the loader to find out what runs — a second reader of these fields
is a reader free to disagree with the engine, and it will disagree exactly where
somebody used a field it does not know about.

`seams` is `scan`, `guard`, `shim`, or more than one, and it is the half
`git_hooks` cannot express. An empty hook list is true of a content rule and of
a checker standing in front of a command alike, so a reader with only the hooks
has to guess between two unrelated places — and the reconciler guessed `scan`,
which credited a shim-only rule to a seam that never touches it. An empty
`seams` means nothing runs the rule at all, which the loader refuses.

The two requests this shape exists to make writable:

```toml
# Stand in front of `gh pr create`, search the tree, install no git hook.
[rule.no-ai-authorship-trailer]
regexp = '(?im)^Co-Authored-By:.*<noreply@'
message = "Remove the marker; represent the work as your own."
files.glob = ["**/*.md"]
command.before = ["gh pr create"]

[[shim]]
command = "gh"
match = ["pr:create"]
```

```toml
# `git push` and nothing else.
[rule.no-published-host-identity]
exec = "uphold scan --text -"
message = "Use neutral placeholders."
command.before = ["git push"]

[[shim]]
command = "git"
collect = "git-refs"
```

**A `command.before` and a `[[shim]]` are two halves of one seam, and the load
refuses either half on its own.** A checker naming a command no `[[shim]]`
declares is never invoked by anything; a shim no checker names collects the
subject, consults an empty list of checkers and execs anyway — reporting a pass
over text nothing read. Both failures are silence at run time, so load is the
only place they can be said.

```sh
uphold scan                 # the tree
uphold scan --text -        # a commit message, a release note, a PR body
```

`--text` exists because the content that leaks host identity most often is the
content that never becomes a file. It runs the `forbidden_literals` rules —
those describe the running machine, so they mean something against any text —
and every [`prose_regexp`](#prose_regexp--the-sentence-not-the-file) rule that
declares `command.before`, which is how a shape refused in a pull-request body
is also refused in the commit message `uphold-scan-text` reads at `commit-msg`.
A `regexp` rule is not run here: it is scoped to paths and file types, and
firing it at prose would be guesswork. Neither is a prose rule that names no
command, for the same reason.

Two things it does not do. It does not decode: text that is not UTF-8 is exit
`2` naming the offset, because a lossy decode searches U+FFFD where the bytes
were and calls the result clean. And a repository declaring `forbidden_literals`
rules of its own does not switch the built-in host-identity rule off — the
built-in is added unless one of the declared rules is itself
`forbidden_literals = "running-os-identity"`. Declaring a rule about something
else is not a decision to stop checking this.

### `comment_regexp` and `trivial_comments` — the comment, not the line

Both parse the file rather than searching it, in Rust, Python and Go. That is
the whole reason they are separate checks: `regexp` reads bytes, so
`let marker = "// TODO";` is a hit for a rule about `// TODO` and there is no
way to write the difference down. These read comment nodes, so a marker inside a
string literal is a string literal.

```toml
[rule.no-before-after-narrative-in-source]
message = "State what holds, not what it replaced."
comment_regexp = '(?i)\bused to be\b'
files.include = ["src"]
files.glob = ["*.rs", "*.py", "*.go"]

[rule.no-trivial-comment]
message = "This comment says only what the code beneath it already says."
trivial_comments = true
files.include = ["src"]
files.glob = ["*.rs", "*.py", "*.go"]
```

**Documentation comments are excluded from both.** `///` and `//!` are published
output, not remarks to the next reader, and a check that cannot tell them apart
from `//` is one whose findings, acted on, delete a public item's documentation.
The grammar marks them; nothing here matches on the prefix, which is what a
prefix test gets wrong by construction — `///` starts with `//`.

Rust is the only one of the three whose grammar marks them. Python has no such
syntax, and Go's godoc comment is spelled `//` like every other — so in Go every
comment is an ordinary one, which is the reading that leaves the check doing
something. Guessing from position would make every comment above a declaration a
doc comment and exclude it.

`trivial_comments` is a subset test and carries no list of boring verbs: a
comment fails when every word it contributes is a word the statements beneath it
already name, counting their string literals. `// Stop and disable dnsmasq` over
`systemd::stop("dnsmasq")` and `systemd::disable("dnsmasq")` fails; the same
comment with a reason attached does not, and no list had to be edited for that to
be true. The code it is judged against runs from the comment to the next blank
line or the next comment — where a reader stops attributing it.

Five shapes are left alone, each because its words restate the code by design
while the comment is doing something else: a trailing comment on the same line as
code, one line of a multi-line comment run, a separator (`---`, `===`, box
drawing), a worked example (containing `=` or `→`), and a parenthesised aside.
A tree that wants its separators gone writes a `comment_regexp` saying so; this
check does not reach that verdict on its own.

There is no fixer, and that is a decision rather than a gap. A comment worth
deleting is usually worth replacing with the reason the code is that way, and
that is not an edit a checker can make.

### `forbidden_literals` — what must appear nowhere

```toml
[rule.no-host-identity]
forbidden_literals = "running-os-identity"
ignore_literals = ["nas", "lab"]     # extends the default ignore list below
message = "use neutral placeholders"
files.include = ["."]
files.word = true
```

The name says what fails: a literal describing **this machine** — username,
home path, hostname and its identifying segments, default-route addresses —
found in content. Sources: `running-os-identity`, `running-os-metadata`
(identity plus route), `running-default-route`. `forbidden_literals_from`
names any command producing one literal per line (`label<TAB>value`, or a bare
line as its own label):

```toml
[rule.no-lan-hostnames]
forbidden_literals_from = "awk '/^[^#]/ { print $2 }' /etc/hosts"
message = "use neutral placeholders"
files.include = ["."]
```

**The default ignore list.** Some literals are never searched for, because
they describe a machine's *kind* rather than its owner and would fire on every
legitimate mention. The suppression is a documented list rather than a
hard-coded one; `ignore_literals` extends it per rule, and the defaults are:

- distribution and OS words — `alma`, `alpine`, `arch`, `archlinux`,
  `armbian`, `bsd`, `cachyos`, `centos`, `darwin`, `debian`, `endeavour`,
  `endeavouros`, `fedora`, `gentoo`, `kali`, `linux`, `macos`, `manjaro`,
  `mint`, `nix`, `nixos`, `openwrt`, `opensuse`, `pop`, `popos`, `raspbian`,
  `redhat`, `rhel`, `rocky`, `suse`, `ubuntu`, `unix`, `void`, `windows`
- architecture words — `aarch64`, `amd64`, `arm`, `arm64`, `i386`, `i686`,
  `riscv`, `riscv64`, `x86`, `x8664`, `x64`
- role and form-factor words — `box`, `build`, `builder`, `cloud`, `desktop`,
  `dev`, `gateway`, `guest`, `home`, `host`, `lab`, `laptop`, `local`,
  `machine`, `main`, `media`, `nas`, `node`, `router`, `server`, `srv`,
  `test`, `virt`, `workstation`
- `runner` (a CI machine's own name), and any hostname segment shorter than
  three characters or all digits — too collision-prone even under whole-word
  matching

### `encoding` — the bytes, not the text

```toml
[rule.scrape-output-is-shift-jis]
encoding = "Shift_JIS"                # a WHATWG charset label
message = "scrape output is Shift-JIS by contract"
files.glob = ["scrape/**/ja/**"]
```

Fails when a selected file does not decode cleanly under the declared charset.
The label is a **WHATWG encoding label** — `"UTF-8"`, `"Shift_JIS"`,
`"EUC-JP"`, `"windows-1252"` — resolved against the registry browsers use; an
unknown label is refused at load, not at the first file.

Deliberately separate from `allowed_scripts`: encoding is a property of the
bytes, script is a property of the decoded text. Two fields can say "UTF-8
file containing Japanese" and "Shift-JIS file containing Japanese" apart —
and they compose, so a Shift-JIS file covered by both is decoded under its
declared charset and then script-checked as text.

**Every check reads the declaration, not only `allowed_scripts`.** A selected
file is decoded once — as UTF-8 where it is UTF-8, under a covering `encoding`
rule where one selects it, by its byte-order mark otherwise — and the text is
what `regexp`, `forbidden_literals`, `require_regexp`, `comment_regexp`,
`prose_regexp` and the script check all read. A file whose bytes nothing can
decode goes into the unreadable list: reported beside the findings, exit `2`,
and never a pass. A binary file is the one skip, because it has no lines for a
pattern to be found on.

### `redact_matches` — the finding without the text

```toml
redact_matches = true    # at the top of the policy file
```

Prints the rule and the location of every hit and **not the matched text**. For
the tree where the finding is itself the secret: a `forbidden_literals` rule
refusing a hostname writes that hostname into a CI log every time it fires, and
the log is read by more people than the file was.

Off by default, because a finding whose text a reader cannot see is one they
have to reproduce locally before they can act on it. It is a policy field
rather than a rule one: what may be printed is a property of where the output
goes, not of any one rule.

### `max_lines` and `max_bytes`, and the baseline that ratchets them

A language's own linter caps the length of the files its parser opens. These run
over whatever `files.*` selects, so the Markdown, the workflow YAML and the
generated table are in scope too — and they take a baseline, which is the reason
they are here rather than deferred to that linter.

```toml
[rule.keep-modules-readable]
max_lines = 400
message = "split the module"
files.glob = ["src/**/*.rs"]
files.baseline = "policy/size-baseline.txt"

[rule.keep-the-agent-file-small]
max_bytes = 20000
message = "the file outgrew its purpose; split it"
files.glob = ["AGENTS.md"]
files.baseline = "policy/byte-baseline.txt"
```

**Two checks and not one field with a unit**, because they bound different
things and a repository means one of them. Lines are what a reader feels, and a
reflow changes them; bytes do not move when a paragraph is rewrapped, and a cap
in lines is defeated by writing longer lines while a cap in bytes reads as
arbitrary to the person who hits it. A file that should be bounded both ways
gets two rules — which is what the exactly-one-check rule says everywhere else,
and it keeps each report in the unit its own cap was written in.

One `path count` per line, in that rule's own unit. A listed file is held to
**its own number** instead of the limit and fails when it grows, so what is
already oversized is frozen rather than exempted — the difference between a
ratchet and a suppression comment, which is invisible in the policy and
permanent in the file. A file listed under a `max_bytes` rule is a count of
bytes; the same file listed under a `max_lines` rule is a count of lines, and
neither baseline can be read by the other rule.

A baselined path the rule no longer selects is reported. An allowance nothing
reports is the rule switched off for that path, and it would apply again in full
the day something takes the name back.

Not to be confused with [`[review] max_lines`](#the-review-tier), which budgets
the compiled review document rather than a file a rule selects.

### `prose_regexp` — the sentence, not the file

`regexp` reads bytes and `comment_regexp` reads comment nodes. Neither can carry
a rule about how a **sentence** is written, because a sentence is spelled
differently in every file that holds one: a wrapped paragraph in a document, a
run of `//` lines in a source file, a run of `#` lines no grammar here parses at
all. So `prose_regexp` is handed the prose, one **span** at a time — one run of
it, unwrapped onto a single line, carrying the line the run starts at.

```toml
[rule.no-empty-hedge]
prose_regexp = '(?i)\b(?:arguably|it is worth noting|needless to say)\b'
message = "State the claim, or state what is actually unknown about it."
files.include = ["."]
files.min_selected = 1
command.before = ["gh", "git push"]
```

The extractor is chosen by the file's kind:

| file | what is prose |
|---|---|
| `.md` | the whole file, minus fenced blocks (` ``` `, `~~~`) and indented code (4+ spaces) |
| `.rst`, `.txt`, `.adoc`, and a file with **no extension** | the whole file, minus fenced blocks |
| `.rs`, `.py`, `.pyi`, `.go` | the comments, read by the grammar — **doc comments included** |
| `.toml`, `.yaml`, `.yml`, `.sh`, `.bash`, `.zsh`, `.ini`, `.cfg`, and a dotfile with no extension (`.gitignore`) | the lines whose first non-space character is `#`, with the `#` stripped |
| anything else | nothing |

Two consequences worth writing down. **A wrapped sentence still matches**: the
lines of a paragraph are joined before the pattern sees them, which is why
`files.multiline` is refused beside `prose_regexp` — the span is already one
line and there is nothing left to span. And **a file of any other kind
contributes nothing**, silently: `files.include = ["."]` over a mixed tree is
the normal thing to write, and a captured PNG under it is not a document
somebody wrote badly. That silence is indistinguishable from prose with nothing
wrong in it, so a prose rule is the one most worth giving a
[`files.min_selected`](#a-rule-may-declare-a-floor-under-what-it-selects).

**Doc comments are included**, which is the one place this parts company with
`comment_regexp`. That check excludes them because acting on its findings
deletes a public item's documentation; this one is about how a sentence is
written, and a published sentence is exactly what a style rule is for.

**The seams.** `files.*` runs it in `uphold scan`. `command.before` runs it at
the shim, where the subject — a pull-request body, an issue title, a branch name
— is read as whole-text prose, so a fenced example in a body is an example there
too. A prose rule standing in front of a command is **also consulted by
`--text`**: both `uphold scan --text` and `uphold guard --text` ask it about the
text they were handed, so a shape refused in the pull-request body announcing a
commit is refused in the commit message that `uphold-scan-text` reads at
`commit-msg`. [`uphold hook`](#uphold-hook--the-caller-that-spawns-no-process)
asks it too, over the strings a pending tool call was about to send: an agent
posting through an MCP server is publishing what `gh` would have published, and
the rule that stands in front of `gh` is the rule that stands there.
A prose rule with no `command.before` is left out of `--text`, for
the reason every other pattern rule is: it is scoped by `files.*` to particular
paths, and firing it at prose that has no path would be guesswork.

`UPHOLD_ALLOW=<rule-id>` is the waiver at both of those seams, and it is what
makes refusing a sentence acceptable: the rule is wrong about this one, the
person standing there says so, and what was switched off is legible in the shell
history that switched it.

### What `allowed_scripts` reads

The Unicode **Script** property (UTS 24) of every alphabetic character.
`Common`, `Inherited` and `Unknown` — punctuation, digits, combining marks —
are never the subject, and declaring them is refused because it would be read
by nothing.

Values are **Unicode script names as regex engines spell them**:
`allowed_scripts = ["Hiragana"]` admits exactly what `\p{Script=Hiragana}`
matches. An engineer who knows regex already knows the whole namespace. An
unknown or miscased name is refused at load with the standard spelling
suggested — `latin` proposes `"Latin"`, `old italic` proposes `"Old_Italic"`.

Script is the unit rather than a codepoint range because a range is the wrong
shape for the question: Han alone is scattered over non-contiguous blocks plus
extensions, and membership moves with the Unicode version.

`allowed_scripts` at the top level constrains every file no scoped rule
selects. A scoped rule's list is **the whole truth for the files it selects**
— replace, not union — so what is declared beside the path is what holds for
the path:

```toml
allowed_scripts = ["Latin"]

[rule.ja-content-uses-ja-scripts]
allowed_scripts = ["Latin", "Hiragana", "Katakana", "Han"]
exclusive = true
files.glob = ["docs/**/ja/**", "i18n/**/ja/**"]
```

**`exclusive` is the reverse direction.** The forward check says files in
scope may use only these scripts; `exclusive = true` says these scripts are
*also* refused in every file the rule does not select — Japanese text leaking
into `src/` fails, attributed to this rule. Both directions together are the
if-and-only-if; `false` (the default) is the forward-only check. A script
admitted where it stands — by the top level, or by another rule selecting that
file — stays admitted: exclusivity adds refusals where nothing admits the
script, it does not revoke an explicit grant (Latin above passes everywhere on
the top-level grant).

**A file the check cannot read is reported, never skipped.** A non-UTF-8 file
silently passed over would be a file nobody read, reported as clean. Bytes an
`encoding` rule declares are decoded under that declaration and their scripts
judged; bytes nothing declares are exit 2, with the cures named: declare the
charset, exclude the file, or mark it not text in `.gitattributes`.

**What this catches is a script with no business in the text** — a Cyrillic
small a, `U+0430`, sitting inside an otherwise ASCII word and rendering as one
of its letters. It is not a check on which language the prose is written in —
it never was: `en` and `de` would both admit exactly Latin, which is why the
field names scripts and not languages.

### `commands-resolve` — a command a reader would run

The third resolver, and the last of the three things a document asserts about a
tree. `links-resolve` resolves a path a reader would **click**;
`anchors-resolve` a value a reader would **believe**; this one a command a
reader would **run**. All three are prose that happens to be checkable, and
before they existed all three failed the same way: silently, forever, with every
gate in every repository still green.

The defect it was built from, measured rather than imagined. A `README.md`
opened with

```text
fg-registry credentials
```

for as long as the file existed. That command has two verbs and `credentials`
was never one of them — the binary's own error names the alternatives — so the
answer was one invocation away, and nobody invoked it: a reader who trusts the
README has no reason to, and a reader who does not is not reading the README.

```toml
[rule.doc-commands-resolve]
builtin = "commands-resolve"
message = "Name a verb the command dispatches on."
command_sources = ["cmd/{}/*.go", "scripts/{}.rs"]

[rule.doc-commands-resolve.files]
glob = ["*.md"]
```

**`command_sources` is a pattern, not a table of names**, and that is the whole
design. `{}` stands for the command's name and is captured out of the path, so
the convention stays in the repository that has one and nothing about any
workspace's layout is compiled into the binary. A list of command names would be
a second copy of the tree, free to go stale, which is the class of defect this
rule exists to refuse in documents. The capture also **bounds** the union: a
command's verbs are read from the files its own pattern selected and no others,
so a sibling binary in the same repository cannot lend it verbs.

**It parses the dispatch. It does not run `--help`.** Running the binary needs a
build — warm locally, cold in CI, and a gate that needs the network is one that
gets skipped — and it invites the far worse mistake of resolving a verb by
*running* it: `fg-registry sync` in a document would be "verified" by
fast-forwarding thirty-nine submodules. Only the help text is safe to execute
for, and help text is prose too; a doc comment drifts from the switch below it
exactly as the README drifted. The switch **is** the verb list: `case "sync":`
is not a description of what the command accepts, it is the mechanism by which
it accepts it, and it cannot be stale without also being broken.

**A command must agree with itself before it judges anyone.** A verb list read
wrong is worse than no verb list: it produces confident findings against
documents that were right. Measured — the first run of the implementation this
ports reported 38 findings, one binary supplied 22 of them by dispatching in a
form the parser could not read, and every one of those was false and read as
real. So a command judges documents only when two independent readings of its
own sources agree: the string labels of its dispatch, and the verbs its own
usage block names about itself. When they disagree the command is **counted,
named and skipped**, never guessed at — and the count is printed every run,
because a check that read four commands out of a hundred otherwise reads exactly
like one that read them all.

```text
doc-commands-resolve: 3 command(s) discovered, 2 judged, 1 skipped
doc-commands-resolve: not judged: session (no dispatch this parse can read)
```

**Zero judged is exit `1`, not a pass.** A renamed directory, a typo in the
glob, and a grammar that stopped matching all arrive in the same state, and
without this they are indistinguishable from a tree whose every documented verb
resolves.

A dispatch is read with tree-sitter — already in this binary for the comment
checks — and is recognised structurally rather than by a list of subject
spellings:

| condition | what it rejects |
|---|---|
| at least two branches name string literals | a match over an enum, whose variants are not things a reader types |
| a catch-all branch exists | a lookup that never has to answer for a word it does not know |
| where it dispatches on nothing, **every** branch names a literal | a Go tagless `switch { case ready(): }`, whose arms are booleans and not verbs |

"Dispatches on something" is deliberately **not** one of the conditions, and
that was measured rather than reasoned. Go spells a dispatch that also guards its
own argument count as `switch { case len(args) > 0 && args[0] == "serve": }`, and
refusing to read it left a real command judged against a *sub*-dispatch found in
another file of the same package — which produced three confident findings
against a README that was right. "Every branch names a literal" is the property
that separates the two.

Go and Rust. A third language is a grammar dependency and one row.

`command_sources` accepts `*`, `**`, `/` and literal text, and **refuses the
rest of the glob syntax at load** — `?`, bracket classes and brace alternation.
The pattern is used twice, once as a glob to select the files and once as a
regex to read the command's name out of the path, and a construct only the first
of those understands would select a file the second cannot name. That file would
then vanish from the discovered count with nothing said, which is the failure
this rule exists to refuse. A path selected and not nameable is reported and
counted anyway, in case one ever gets past the refusal.

What it deliberately does not do:

- **Only code spans**, fenced or inline, and only where the command is the
  **first token** of the span. An invocation begins with the binary; a sentence
  that happens to contain the same two words in a row does not, and neither does
  a column of an ASCII diagram. Both were false findings on the first run, and
  narrowing to the shape of an actual instruction is what keeps a gate from
  crying wrong — a gate that cries wrong gets waived.
- **No bundled set ships it.** The rule needs a `command_sources` pattern that
  describes one tree's layout, and a rule arriving from a set cannot be handed a
  parameter. A set carrying a layout would either impose one workspace's
  convention on every inheriting repository or ship a rule that refuses to run.

Two limits worth knowing before adopting it:

- A flag that takes a **separate** value hides the verb behind it:
  `fg-registry --workspace here sync` reads `here`. Nothing in the text
  distinguishes a flag's value from a verb — only the command's own flag table
  does, and reading that is a second parse with a second way to be wrong.
  `--flag=value` is unambiguous and passes through.
- A binary whose name lives in a manifest rather than in its path is not
  discoverable by a path pattern. `src/bin/{}.rs` works; a single-binary crate
  whose name is set in `Cargo.toml` over `src/main.rs` does not.

## `uphold guard` — the guards

`uphold guard --stage STAGE` runs the guards that have something to say at
that moment. A content rule reads the tree and could run at any time; a guard
reads an **act** — the message about to be recorded, the identity about to be
stamped on it, the range about to be pushed.

| guard | refuses |
|---|---|
| `prevent-ai-author` | AI-authorship markers in the message being written — and at a push, in **every commit message the push publishes** |
| `prevent-author-mismatch` | an identity that is not your global one |
| `prevent-unusual-unicode` | unusual characters in the same set of messages, judged against the scripts the message is written in |
| `prevent-unusual-unicode-in-files` | characters that draw nothing, in committed content **and in the paths that carry it** |
| `no-private-repo-names` | a private repository named in a public one's message |
| `no-private-repo-names-staged` | the same, in the lines a commit adds |
| `no-private-repo-names-in-files` | the same, anywhere in what is being introduced — content, **path names**, and at a push the **commit messages** the push publishes |
| `prevent-public-push` | a push to somewhere off the allow-list **and off the forge's own answer** — a GitHub destination the allow-list refused is put to `gh`, and a forge that could not be asked is exit `2` |
| `prevent-unowned-target` | a **command** told to publish to a repository this workspace does not own. The same decision as the row above, reached from the shim seam instead of a hook — so it registers with `command.before` and never `git.hooks`, and a destination it could not resolve is exit `2` |
| `no-local-merge` | a merge that would make a merge commit |
| `no-merge-commit` | a commit finishing a merge or a squash merge |
| `no-stale-hook-pins` | a pin left behind its upstream, or naming no ref — in `.pre-commit-config.yaml` **and** lefthook `remotes:`, at any depth in the tree; a pin it **could not check** is exit `2` |
| `no-hand-copied-base-rule` | a rule this policy writes out by hand under an id a bundled set already ships, from a set it does not inherit. Reads the **policy**, not the tree. At `pre-commit` only what the change adds; at `manual` the whole sweep |
| `no-stale-visibility` | a declared `private` the forge no longer serves. Reads the **declaration** and the forge, not the tree; a forge that did not answer is exit `2` and never "confirmed private" |

Declared like any other rule, in the same file and the same id namespace.
**`git.hooks` is the whole registration.**

`prevent-unusual-unicode` reads what is ordinary off the message rather than off
a fixed list. ASCII passes, and so do the letters and digits of every script; a
script's punctuation passes once that script's **letters are in the same
message**, which is what makes a Japanese subject line, with the `。`, `、` and
`「」` that Japanese prose cannot be written without, something somebody can
actually type. The fullwidth forms (`！`, `（`) name no script in Unicode at all
and are admitted on the presence of an East Asian one instead.
The same `。` in an English sentence is still refused, because nothing in that
message is written in a script that uses it, and that is the paste artefact the
rule exists for. A character belonging to no script is refused whatever the
message is written in: an em dash, a curly quote, and everything
`prevent-unusual-unicode-in-files` bans for drawing nothing.

```toml
[rule.prevent-public-push]
builtin = "prevent-public-push"
owner = "acme"                    # pinned, not derived from origin
allowed_repos = ["other/thing"]
git.hooks = ["pre-push"]

[rule.prevent-unusual-unicode-in-files]
builtin = "prevent-unusual-unicode-in-files"
allow = ["U+00A0:docs/captured/**"]
git.hooks = ["pre-commit", "pre-merge-commit", "pre-push", "manual"]
```

`owner` is a pin rather than a derivation: taking the owner from `origin` is
tautological for the one remote most likely to be wrong — repointing origin at a
public upstream, the exact accident the guard exists to prevent, also repoints
the allow-list. Where nothing is pinned the guard still runs off origin, and
says so — at the point of refusal, and **on the allow path too**, since a guard
running in its weaker mode is silent for exactly as long as nothing has gone
wrong. The note is exit `0` and it is scoped to the case where the derived owner
is what allowed the push: a pinned `owner` has nothing to report, and an
`allowed_repos` hit decided the question from a written list.

```text
uphold guard: prevent-public-push allowed this push to acme/widget, judged
against acme -- DERIVED FROM ORIGIN, not pinned. […] Pin it with
`owner = "acme"` on the rule.
```

The pin is asked first and the forge second. A destination on the allow-list —
the pinned owner, `allowed_owners`, `allowed_repos` — passes exactly as before,
with no network call. Only a destination the list refused, and only on GitHub,
is put to `gh`: whether `gh api user` is the destination's owner, and failing
that whether `gh api repos/<owner>/<repo>` reports `permissions.admin`. Either
is ownership and the run exits `0` with nothing extra printed. This is what a
pin cannot express — a bundled rule takes no parameter, so an operator who owns
two forges had no lever short of `UPHOLD_ALLOW`, which switches the guard off
rather than answering it — and it is not the tautology `owner` exists to refuse,
because ownership is a fact the forge holds and editing a remote cannot move it.

A forge that answers **no** is today's refusal, exit `1`, with one line saying
the forge was asked and disagreed too. A forge that **could not be asked** — no
`gh`, not authenticated, no network, output that is neither a yes nor a no — is
exit `2` with the same report and a line saying why: a question that could not
be asked is not a pass. A destination on a host no client answers for keeps the
allow-list's answer unchanged.

### Built-in parameters

Each built-in declares the parameters it reads, and **a parameter on a rule
whose check does not read it is refused at load** — the same refusal as a
second check field, for the same reason: a field read by nothing looks
enforced and is not.

| parameter | read by | meaning |
|---|---|---|
| `owner` | `prevent-public-push`, `prevent-unowned-target` | the owner this workspace is pinned to |
| `owner_required` | `prevent-public-push`, `prevent-unowned-target` | exit `2` rather than read the owner off `origin` when nothing has declared one |
| `allowed_owners` | `prevent-public-push`, `prevent-unowned-target` | further owners a publication may go to — the pinned `owner` is always allowed, and where nothing is pinned the list stands in for the owner read off `origin` |
| `allowed_repos` | `prevent-public-push`, `prevent-unowned-target` | single repositories allowed through, `"owner/repo"` |
| `visibility` | the `no-private-repo-names` family, `no-stale-visibility` | this repository's visibility, declared instead of looked up |
| `visibility_required` | the `no-private-repo-names` family | exit `2` rather than fall back to the forge when nothing has declared a visibility |
| `private_owners` | the `no-private-repo-names` family | owners whose repositories are private regardless of what a forge says |
| `private_owners_from` | the `no-private-repo-names` family | a command whose stdout is one private owner per line |
| `public_repos` | the `no-private-repo-names` family | names treated as public without asking a forge |
| `refuse_unknown` | the `no-private-repo-names` family | treat a name whose visibility could not be determined as private |
| `foreign_hosts` | the `no-private-repo-names` family | host globs carrying no repository this rule needs resolved — replaces the top-level list for this rule |
| `allow` | `prevent-unusual-unicode-in-files` | codepoints admitted, optionally under one glob — `"U+00A0:docs/captured/**"` |

The "family" is `no-private-repo-names`, `-staged` and `-in-files`. No other
built-in reads any parameter. The first four rows are **one row twice**:
`prevent-public-push` and `prevent-unowned-target` are one decision reached from
two seams, and who this workspace is means the same thing whether a push or a
`gh` invocation is asking. `no-stale-visibility` reads `visibility` and
nothing else — everything else in that row is about judging names in text, which
the falsifier never does.

**Four of these are also top-level policy fields**, and that is not a
convenience. A rule arriving from a bundled set cannot be handed a parameter —
the only way to give it one is to write the rule out again, which is the
transcription `no-hand-copied-base-rule` refuses — so the facts that belong to
the repository rather than to any one rule are declared once, at the top of the
file, and every rule that needs one reads it from there:

```toml
owner = "your-org"          # read by prevent-public-push and prevent-unowned-target
visibility = "public"       # read by the no-private-repo-names family
private_owners_from = "cat ~/.config/private-owners"
private_owners_optional = true    # only where this policy is cloned; see below
foreign_hosts = ["doi.org"]       # hosts that are not forges this repository cites
```

A rule's own field wins where both are written.

### Reading a repository fact from a command

`owner` and `visibility` are each written once per repository, and across one
fleet that is 78 `owner` lines carrying seven distinct values — 41 copies of one
string inside a single organisation. `owner_from` and `visibility_from` are the
same move `private_owners_from` already makes: a command whose stdout is the
value, run in the repository root, so a workspace fact is written once outside
the tree instead of once per tree.

```toml
owner_from = "cat ${XDG_CONFIG_HOME:-$HOME/.config}/uphold/owner"
visibility_from = "cat .workspace/visibility-cache"
```

**They move a declaration; they do not look one up.** Deriving the owner from
`origin` is the defect rather than the fix — repointing `origin` at somebody
else's remote is the exact accident `prevent-public-push` exists to catch, and a
derived allow-list is repointed by the same command. The same applies to
visibility: a command that asks a forge what a repository is *today* hands three
guards' one scope condition to a network call, which answers nothing on a train,
nothing in CI without a token, and answers about the visibility a repository is
in the middle of changing. What the command reads must be a value somebody
decided, not the state being guarded.

So every way the command can fail to answer is exit `2`:

| what the command does | what happens |
|---|---|
| prints one value | that is the declaration, cached for the rest of the process |
| exits non-zero | exit `2`, naming the fallback it refused to take |
| exits `0` printing nothing | exit `2` — the file reads as a declaration and there is none |
| prints more than one non-empty line | exit `2` — one repository, one fact, and no first-line guess. A trailing blank line is not a second value; `cat` gives one back for any file that ends with one |
| prints a word that is not a visibility | exit `2`, naming the command rather than the file |

There is deliberately **no `..._optional`** beside these, and the asymmetry with
`private_owners_from` is the point. An unreadable owner list degrades to a
narrower check, which can be reported and lived with. An unreadable owner
degrades to the tautology above, and an unreadable visibility degrades to
standing a disclosure guard down — neither is a degradation anybody should be
able to opt into.

Two further refusals, both at load:

- **`owner` beside `owner_from`** (or `visibility` beside `visibility_from`) is
  refused. They are two statements of one fact, free to disagree, with nothing
  anywhere to notice when they do — which is the defect the field exists to
  remove, arriving through the field.
- **Neither may arrive by inheritance.** A bundled set or an `inherit.paths`
  file carrying one is refused, for the reason `private-names` gives for not
  shipping `private_owners_from`: a command arriving that way runs in every
  inheriting repository on the strength of a version bump, with nothing in any
  of those trees to review.

The command runs at most once per process, on the first ask — the private-name
family asks about visibility three times, once per variant — and the answer is
never cached to disk. A declaration exists to avoid a stale answer, and a cache
outliving the run is a stale answer with a longer life.

**Why the owner list is worth declaring**, measured rather than asserted. A
forge lookup only *adjudicates* names something already extracted, and a bare
`owner/repo` is extracted only for declared owners and for this repository's
own — anything else is indistinguishable from a relative path, and treating
every path in every document as a name would be one lookup per path:

| form in the text | with a declared owner list | without |
|---|---|---|
| `https://github.com/owner/repo` | refused | refused |
| `<your own owner>/repo` | refused | refused |
| `otherowner/repo`, bare | refused | **not seen** |
| an organisation named on its own | refused | **not seen** |

An unreadable source is exit `2`, because a rule with no owners refuses nothing
and would report a clean tree over a list it could not read.
`private_owners_optional = true` is the one exemption and it is for one shape: a
policy in a repository other people **clone**, naming a source that is one
operator's. There the default refuses every clone's first commit, and the usual
workaround — a command that swallows its own failure — loses the bottom two rows
silently and permanently. With the field, the failure is reported on stderr,
naming those two rows, and the run proceeds. Setting it with no
`private_owners_from` anywhere is refused at load: it would permit a failure
that cannot happen. `visibility` is held to
`public`, `private` or `internal` **at load**, not when a hook fires: a misspelt
visibility is a fact about the file, and a guard that hears about it months
later has been reporting a clean tree the whole way. The same mechanism holds beside the checks:
`exclude_cfg_test` is read only by the content searches (`regexp`, `values` —
its job is dropping a matched *line* inside a `#[cfg(test)]` block, and no
other check has one), `require_any_link` / `allow_outside_repo` are read only
by `links-resolve`, `require_any_anchor` only by `anchors-resolve`, and
`command_sources` only by `commands-resolve`. `files.min_selected` is the one
that goes the other way — every check whose selection the scan builds reads it,
and it is refused only on a guard built-in whose `[rule.files]` is a scope
rather than a selection.

**Which bytes a guard reads: the index, unless a push says otherwise.** At a
push there is no index at all — the artifact is the pushed commit's whole tree
*plus every blob the pushed range introduces*. Neither half covers the other;
see [DESIGN.md](DESIGN.md#which-bytes-a-guard-reads).

**A path is committed text too.** A file name is published exactly as a file's
contents are, so the tree-wide guards read the path as well as the blob under
it: a repository name in a directory name, a zero-width character in a file
name. A tab and a newline are legal inside a file and never inside a path, so
the same `allow` list means something slightly stricter there. At a push the
guards also read the **commit messages** the push publishes, which no earlier
seam can reach for a commit written under `--no-verify`.

**A blob a guard could not read is exit `2`, never a skip.** The one honest
skip is a genuinely binary file — a NUL in the first 8000 bytes. Anything else
that will not decode is a surface this run did not examine, and saying so is
the whole contract. A submodule is enumerated by path and never read as a blob:
its content is another repository's.

`no-stale-hook-pins` reaches every `.pre-commit-config.yaml` and every lefthook
config in the tree — `lefthook.yml`, `lefthook.yaml`, `.lefthook.yml`,
`.lefthook.yaml`, at any depth, gitignored files and submodules excluded — and
reads lefthook `remotes:` entries as pins alongside pre-commit `repo:`/`rev:`
pairs. A `remotes:` entry with no `ref:` is refused as unpinned, because it
follows the upstream's default branch. `lefthook.toml`, `lefthook.json` and the
`-local` overlay files are **not** read, so a pin written in one of those is
watched by nothing here.

Three trees that look alike from the outside and are three different answers:

| the tree | the answer |
|---|---|
| a lefthook config and no `.pre-commit-config.yaml` | `0` with a note. That is the documented lefthook-only install path, and any `remotes:` the lefthook config pins *were* read |
| a hook config naming no remote pin — every entry `repo: local` or `repo: meta`, or a lefthook config with no `remotes:` | `0` with a note. These files were read, and what they say is that this repository pins nothing remote |
| no hook configuration of **either** manager, anywhere under the root | `2`. Zero pins found is not zero pins to find: a config renamed, moved above this root, or added to `.gitignore` — ignored files are not walked — arrives here as an empty tree, and used to read as clean |

A pin whose remote could not be reached is exit `2` for the same reason: a
runner with no network fails this guard where it used to pass it.
`UPHOLD_ALLOW=no-stale-hook-pins` is the deliberate bypass in each of those
cases, and every refusal names it.

### Overriding one

```sh
UPHOLD_ALLOW=prevent-ai-author git commit
```

One spelling. The id is in it, so what was switched off is legible in a shell
history and in a CI log. It stays in the environment and is deliberately not a
rule field: a bypass written into the policy file would be committed, reviewed
once, and permanent.

## `uphold shim` — the shims

A pull-request body is typed into a CLI and goes straight to a public API
without passing a single hook. So does an issue title, a release note, a branch
name, and a commit message written under `--no-verify` — the one path that
exists precisely to skip `commit-msg`.

`uphold shim` stands in front of the command, checks what the invocation is
about to publish, and **execs through**. Put a link named for the command on
PATH ahead of the real one and `argv[0]` does the rest.

### The links, and what reaches them

```sh
uphold shim --install [COMMAND...]   # one link per command, in one directory
uphold shim --status                 # what is linked, and what PATH would run
uphold shim --uninstall              # take the links back
uphold shim --hook bash|zsh|fish     # those links on PATH inside a policy tree
uphold shim --path                   # the PATH a shell should have, standing here
```

The links live in `~/.local/uphold/shims` unless `--dir` names somewhere else,
and they live **together** so that the whole seam is one PATH entry to add,
inspect or drop and `ls` answers "what am I standing in front of". With no
names, `--install` links the commands this repository's `[[shim]]` tables
declare; it never overwrites a file it did not write, and `--uninstall` removes
only links that land on this binary. Why the reach is shaped this way, and what
was deliberately not built:
[ADR 0002](adr/0002-the-reach-of-a-command-shim.md).

**Installed and reached are different facts.** Both `--install` and `--status`
end by walking PATH for each name and exit `1` when the shell would reach
something else first, naming what wins — `SHADOWED gh (/usr/local/bin/gh comes
first)`. A link nothing reaches refuses nothing, and reporting the install as
done over one would be this tool's own failure mode.

**The hook is the direnv shape**, for whoever does not want the links on PATH
outside a participating tree: the same links, added on entering a tree that
declares a policy and removed on leaving it. It decides nothing itself — it runs
`uphold shim --path` once per prompt and installs what it is handed, so the walk
that finds a policy is the loader's and not the shell's. What is asked is
whether a policy is *discoverable*, never what it declares; parsing it would cost
a parse per prompt and print its refusals there too. When the binary the hook
names is gone the hook says so, once per prompt, because the alternative is
commands publishing with nothing standing in front of them and nothing saying so.

That link is on PATH for the whole machine, while a `[[shim]]` is a line in one
repository's policy — so **where nothing declares the command, the command
simply runs**: no policy in this directory, or a policy that declares a shim for
some other command. Neither is a could-not-look, so neither is exit `2`; the
policy was read and it said this command is not one it stands in front of. A
policy that exists and cannot be *read* still exits `2`, because the
declaration that could not be read might have been the one. Asked for by name —
`uphold shim faux …` — an undeclared command is still an error, since nothing is
standing in front of anything and the caller asked.

```toml
[[shim]]
command = "gh"
match = ["pr:create", "pr:edit", "issue:create",  # named, never guessed
         "api:*"]                                 # the write half only — see below
text_flags = ["-b", "--body"]
title_flags = ["-t", "--title"]
file_flags = ["-F", "--body-file"]
skip_flags = ["--fill"]
editor_env = "GH_EDITOR"
target = "forge-repo"
scope = "public-target"
unresolved = "refuse"                             # the default; "run" is the opt-out
```

`title_flags` is `text_flags` for the subject a forge shows above the body,
and a separate kind for both directions of the difference: a format rule with
`subjects = ["title"]` is never asked about a body, and a title given alone no
longer reads as "the body was supplied" — under `text_flags` it did, which
told the shim not to install itself as the editor, so the body the command was
about to open an editor *for* closed unread.

`target` is `forge-repo` or `git-remote`, both built-in resolvers. `scope` is
`public-target | public-registry | always`, with
`scope = { command = { command = "..." } }` as the escape hatch — exit `0` to
be in scope, for a question that is none of the other three. (The doubly
nested form is the enum's own spelling; the flatter one this page used to show
never parsed.) `collect = "git-refs"` replaces the argv walk for `git`, whose
published text is positional.

**A scope that could not be evaluated is not a scope that said no.**
`public-target` is the one predicate that asks somebody else, and `gh`
unauthenticated, a rate limit, no network, or a repository with no `origin` all
answer nothing. That was read as "out of scope", which stood every checker
behind the table down — including `prevent-unowned-target`, whose own contract
two sections below is exit `2` on a destination it could not resolve. So the
predicate has three answers now, and the third is **exit `2` before the command
runs**, naming what could not be asked. `unresolved = "run"` on the table opts
back into the old behaviour: the command runs and the shim says on stderr that
no checker did. The field is refused at load on a table no reading of which can
reach `public-target` — neither the table's own `scope` nor the `command.scope`
of any rule naming the command — because a parameter nothing reads is
configuration that looks like it works.

**An alias is expanded before the `match` list is consulted.** `match` names
verbs literally, and every one of these commands lets a person rename one:
`git -c alias.p=push p origin HEAD:refs/heads/x`, a persisted `[alias] p =
push`, `gh alias set` and `glab alias set` all present a verb no list contains,
which used to mean a push to a public forge exec'd unexamined at exit `0` with
nothing printed. Where — and only where — nothing matched, the shim asks the
real command what the word expands to (`git config --get alias.<word>`,
`<command> alias list`) and matches again against the expansion, with the global
options left in front of it. A **shell alias** (`!…`) and a lookup that failed
are could-not-looks, not absences: exit `2`, since what a shell runs is not an
invocation any table can read and it may well be a push. An ordinary `git push`
pays no process for this — a `match` hit is already the answer.

**`git push` reads its refspecs under both readings of the grammar.** The
matcher tries an unclassifiable option both ways and matches under either; the
positional collector now does the same, because an option in front of the
refspecs shifts every one of them by one. Where the two readings disagree about
which names are being published — `git --attr-source HEAD push origin` reads
`origin` under one and the current branch under the other — the answer is exit
`2` and not a guess. This is a *matched* invocation, so nothing here risks the
warning-on-every-command failure the [stand-downs](#the-stand-downs) exist to
avoid.

**`--all`, `--mirror` and `--tags` name no refspec and publish many.** They are
enumerated with `git for-each-ref` and every name is checked; before that the
collector fell back to `HEAD`, so a mirror push of forty branches was checked as
one. A leading `+` is the force marker and no part of a name — `+fix/acme-outage`
was a name no rule recognised, which made the force-push the way past a rule
standing in front of the branch it names.

**A rule may carry its own scope.** The table's `scope` answers for the
command — is this push going somewhere public — and one answer cannot fit
every rule consulted behind it. `command.scope` on a rule overrides the
table's for that rule alone, in the same vocabulary:

```toml
[rule.no-published-host-identity]
builtin = "text-literals"
command.before = ["gh", "git push"]
command.scope = "always"     # this rule reads every egress the shim collects
```

A private-name check belongs only where the destination is public, and the
table's `public-target` says so once for it. Host identity in a pull-request
body is worth refusing whatever the destination — a private forge repository
is still somebody else's infrastructure with its own retention — and before
this field, a workspace whose every repository is private had a
`public-target` table standing down on every invocation, with the checkers it
declared never consulted. Two workspaces closed that with a hand-rolled agent
hook standing outside the shim, re-invoking this binary for the same rules
the policy already declared; this field is that hook retired. Each distinct
scope is evaluated once per invocation, the editor checkpoint stays open when
any rule's scope holds, and the editor pass consults only the rules whose
scope held.

**A rule reached through a consultation is judged under its own effective
scope**, exactly as when the shim reaches it directly: `text-guards` scoped
`always` runs the guards the policy declares, and each of those that names
this command in its own `command.before` is asked under its own
`command.scope` where it wrote one and the table's where it did not. So a
`text-guards` rule that reads every egress no longer drags a `public-target`
rule along with it to a private destination — before this, the only way past
that was `UPHOLD_ALLOW` on the consultation, which switched off the checks it
was there for. A guard the consultation reaches that this command does not
name — one standing at a git hook, say — is consulted as before, because no
scope was ever written about it here. A scope that could not be told is exit
`2` on this path too: an inner rule whose destination question the forge could
not answer is neither in scope nor out of it.

`editor_env` names the variable the command consults for its editor —
`GH_EDITOR` for `gh`, `GLAB_EDITOR` for `glab`. The shim sets it to itself
before exec'ing, which is what closes the editor path below; without it there
is nothing to re-enter through, and the shim can only say it did not see the
body.

The shim finds the subcommand by walking argv for the first two words that are
neither an option nor an option's *value*, honouring `--`, `--flag=value`, and
its own `text_flags`/`file_flags`/`skip_flags` as value-taking. `gh --repo
owner/name issue create` matches `issue:create`; where a release puts its flags
is not something a policy author should have to track.

**`gh api` and `glab api` are matched when the call carries a body.** `gh pr
edit` was unavailable to an agent whose token lacked `read:org`, so it ran

```
gh api -X PATCH repos/OWNER/REPO/pulls/N -F body=@file
```

— the same body, the same account, the same public tracker — and no `match`
list named `api`, so the shim exec'd it with nothing printed. The tables ship
`api:*` now, on both `gh` and `glab`.

The verb is not a verb like the others, and the two ways it differs are both in
the table above's `match` list only by name. **It is read with its own
grammar**: `-F` is `--body-file` on `gh pr create` and `--field` on `gh api`, so
the table's flag lists answer for neither and the `api` walk reads `-X`/`--method`,
`-f`/`-F`/`--field`/`--raw-field`, `--input`, and the value-taking options
around them. **And only the write half is checked**: a call carries a body when
`-X`/`--method` names something other than `GET`, or when any field or `--input`
is present — which is when `gh` switches to POST anyway. A GET with no fields is
left exactly where it was, unmatched and unexamined, because that is also the
call `public-target` makes to ask a forge about visibility, and a shim standing
in front of its own lookup is a loop.

| what it reads | what becomes a subject |
|---|---|
| `-f`/`-F`/`--field`/`--raw-field` | the value after `key=`, with `@file` read from the file and `@-` from stdin |
| `--input FILE` | the whole file — each **string value** where it is JSON, the raw text where it is not |
| the endpoint path | `repos/OWNER/REPO/…`, or GitLab's `projects/OWNER%2FREPO`, as the **destination** |

The destination is the same `owner/repo` a `--repo` resolves to on every other
verb, so `prevent-unowned-target` and a `public-target` scope read a `gh api`
call exactly as they read a `gh pr create` one — `gh api -X POST
repos/other-owner/their-repo/issues -f title=…` is refused by the destination
guard on ordinary prose. A path naming no repository (`gh api graphql`, `gh api
user`) falls through to the table's own `target` resolver, which is the honest
bound: the destination of a GraphQL mutation is inside its query, and nothing in
a path can say. A JSON body is judged one string value at a time because the
encoding otherwise hides the text — a prose rule reading the raw document reads
the escapes rather than the sentence — and "JSON" means a document that starts
with `{` or `[` and parses as one, not YAML's superset reading, under which an
ordinary Markdown body with a `Note: something` line would parse as a mapping
and most of it would reach no checker at all.

### The stand-downs

Four paths through this seam **run the command with nothing checked, exit `0`,
and say so on stderr**. All are deliberate, all are stated here so the contract
is not folded into "the shim passed it", and a reader who sees `This is not a
pass.` on a terminal is reading one of them.

| what happened | what runs | what is printed |
|---|---|---|
| **two or more options nothing can classify sit before the subcommand**, and the readings disagree about which word it even is | the command | which option, that the subcommand could not be established, and that no checker ran |
| `UPHOLD_ALLOW=all` | the command | that it ran unchecked, every time |
| `unresolved = "run"` and a scope that could not be evaluated | the command | what could not be asked, and that no checker ran |
| `UPHOLD_SHIM_INNER` is set | the command | that it ran unchecked, and by which marker, every time |

The first is bounded on purpose. **One** unclassifiable option is not a doubt —
the two readings are then the whole space, both are asked, and both missing is a
conclusion; that case is silent, and making it loud cost nine of sixteen
ordinary git invocations a refusal line while `git push` itself stayed quiet. A
warning printed over every command trains its reader to ignore the one where the
doubt is real.

The second is asked **before** the policy is read, which is what makes it the
way out of a policy file that will not parse — see [when the policy itself will
not load](#when-the-policy-itself-will-not-load). An empty `UPHOLD_ALLOW=`
switches nothing off, and `UPHOLD_ALLOW=<rule-id>` stands one rule down rather
than the seam.

The fourth is uphold getting out of its own way, and it is documented here
rather than left implicit because a reader who meets the line deserves to know
what set it. A `public-target` scope asks the forge whether the destination is
public, and it asks by running `gh api repos/<owner>/<repo> --jq .visibility`;
a `git-remote` target asks by running `git remote get-url origin`. PATH answers
`gh` and `git` with the shim, so **every question this tool asks on the way to a
verdict is a command it stands in front of**. On 2026-09-02 that closed into a
loop against the released binary inside this repository's own checkout: the
`gh` table listed `api:*`, the visibility probe matched itself, and asking the
question was asking the question -- around two hundred and fifty processes a
second, a load average of three thousand, and nothing under `kill -9` on the
process group stopped it. A bodyless `GET` is exempt from `api:*` now, so that
particular trigger is gone; the marker is what stops the next one, because any
`match` entry, or a binary and a policy that disagree about which entries exist,
reopens the same shape.

So uphold sets `UPHOLD_SHIM_INNER=<depth>` on every `git`, `gh` and `glab` it
spawns for its own probes, and a shim that sees it resolves the real command --
walking PATH past its own file, the same walk the final exec does -- and hands
over without judging.

It is **not a bypass**, and the reason is not that it is hidden. It is set only
by uphold's own processes, on the children they spawn for their own questions,
and never on the exec that runs the command a person typed -- so a `git push`
that fires a hook that re-enters this tool arrives unmarked and is checked.
Exported by hand it is `UPHOLD_ALLOW=all` under another name, it buys nothing
that one does not, and it is printed on stderr exactly the way that one is,
every time, so a habit of it is visible in a shell history and in a CI log.
Every probe uphold makes reads its child with `output()`, which captures that
line, so the notice a person sees on a terminal is one they set themselves.

The value is a depth rather than a flag, and past `2` the seam refuses with exit
`2` and names the loop instead of running anything. Nothing legitimate goes that
deep -- a shim probes, the probe execs the real command, and the real command
does not probe -- so a marker deeper than that is a chain calling itself, and
the honest answer to it is not to publish.

Everything else this seam cannot establish is exit `2` and no command at all: a
non-UTF-8 argument on a matched invocation, a body file that is not there, an
alias that is a shell command, refspecs two readings disagree about, a
destination `prevent-unowned-target` could not resolve, a scope that could not
be evaluated under the default `unresolved = "refuse"`, a `current_exe()` the
editor re-entry cannot be installed from, and a `UPHOLD_SHIM_INNER` deeper than
`2`.

### The checker contract

```toml
[rule.no-published-host-identity]
exec = "uphold scan --text -"
message = "use neutral placeholders"
command.before = ["gh", "glab", "git push"]
```

Any executable: the subject on stdin, its kind in `UPHOLD_KIND`, **0** to
pass, **1** to refuse, **2** to say it could not look. Exit 2 is the third
answer and is never folded into either of the others.

**A checker need not be asked about text at all.** A shim resolves two things
from an invocation: the **subjects** it is about to publish, and the
**destination** it was told to publish them to. Those are two questions, and a
checker answers one of them. Every kind above judges a subject; a rule whose
built-in is `prevent-unowned-target` judges the destination:

```toml
[rule.unowned-forge-target]
builtin = "prevent-unowned-target"
owner_required = true
command.before = ["gh", "glab"]
command.scope = "always"
```

The distinction is not decorative. A destination is a property of the
**invocation** and not of any subject it carries, so a target-judging checker is
consulted **once per invocation**, outside the per-subject loop — and it is
consulted even where the invocation collected no subject at all, since `gh issue
create --repo other-owner/their-repo` with an empty body still publishes to
somewhere. Before this kind existed, an invocation carrying blameless prose and
somebody else's `--repo` satisfied every checker standing in front of `gh` and
published: nothing was wrong with the text, and no rule was looking at where it
was going.

It is the same decision `prevent-public-push` makes at `pre-push`, and it is
**the same rule body** — one predicate, reached from both seams, so a push and a
`gh` invocation cannot come to different conclusions about the same owner. The
parameters are the ones in that guard's row: `owner`, `owner_required`,
`allowed_owners`, `allowed_repos`.

`command.scope = "always"` is the scope to write here, and `public-target` is
the wrong one twice over. It stands the rule down exactly where the forge lookup
failed, which is the invocation that most needs asking about; and whether a
destination is *yours* is a fact about the destination, not about its
visibility — a private repository belonging to somebody else is still not yours.
The resolution costs no round trip either way: the destination is read off
`--repo`/`-R` or off the remote, and no forge is asked.

**A destination that could not be resolved is exit `2`.** No `--repo` on the
command line and no remote to read one off is a could-not-look, not a pass —
`explicit-unknown`, the same reading the editor pass and a non-UTF-8 argv take.

**A checker must read stdin to the end.** One that exits 0 having consumed part
of a long subject — a bare `grep -q`, a `head -c` — is answering about text it
did not finish reading, and the short write is now exit `2` rather than a pass.
A refusal after a short read still stands as a refusal: the checker saw enough
to say no. Both shipped checkers (`uphold guard --text -`, `uphold scan --text
-`) read to EOF.

**`before` is what the checker is asked about, and nothing else.** The match is
the command, then its subcommand words in order — `"gh pr create"` catches
`gh -R acme/x pr create`, because where a release puts its flags is not
something a reader should have to track.

**The editor is a checkpoint, not a blind spot.** No body on the command line,
no `--web`, and a command about to open an editor is the case where the text has
not been written yet at the moment the shim runs — so there is nothing in argv
to hand a checker. The shim sets the command's own editor variable
(`editor_env`, above) to itself: the command opens *this binary* as the editor,
the binary runs the real editor, reads the file back when it closes, and
consults the same checkers over what was actually typed. A refusal exits 1,
which is what makes `gh` or `glab` abandon the publication; an editor that
itself fails is exit `2`, not a pass.

The re-entry is routed by a WORD on the command line. The editor variable is set
to `<this binary> shim --as-editor <command>`, and `--as-editor` is what tells
the re-entered process that it is the editor. Two environment variables carry
the data it then needs, both set by the shim on the command it execs:
`UPHOLD_SHIM_EDITOR_REAL` (the user's actual editor command line) and
`UPHOLD_SHIM_EDITOR_ARGV` (the original argv words, read only to decide which
`command.before` rules apply). Neither routes anything, so a process that
inherits them does nothing with them.

Routing an editor re-entry through the environment is a defect, and the reason
is worth holding: an environment is inherited by every descendant, and the
descendants of the editor pass include the `git` its own checkers run — which,
after the install above, *is this binary* under a link. A child that reads such
a marker takes itself for somebody's editor, opens the user's editor on whatever
its last argument happens to be, consults the same checkers, runs `git`, and
recurses without bound. A process is the editor because it was invoked as one,
and only argv can say that.

For the same reason the shim will not hand off to a link that lands on another
`uphold`: two copies on `PATH` — a `cargo install` beside a packaged one, a
release binary beside a build under test — are two different files, so each one
reads the other as "the real `git`" and execs it back.

Where `current_exe()` cannot be resolved there is nothing to install as the
editor, and the invocation is refused with exit `2`. It warned and execed anyway,
on the argument that a guard which stops work gets removed — but that argument
belongs to a guard that *looked* and found nothing, and this one never looked.
The body does not exist yet, so it cannot be checked now, and after the hand-off
there is no process left here to check it later. The text would be published
unexamined by the one path the editor re-entry exists to close. This is the only
place the shim refuses without having read anything, and `explicit-unknown` is
why: an unobserved property must not resolve to success.

## `uphold hook` — the caller that spawns no process

```sh
uphold hook claude-code   # the pending call arrives as JSON on stdin
```

The shim decides by `argv[0]`, which works for exactly as long as publishing
means running a command. An agent reaching a forge through an MCP server sends
the body over HTTPS from inside its own process. There is no command to link a
name in front of, so `prevent-ai-author`, the `private-names` guards and the
`credentials` rules read nothing — not because any was disabled, but because all
of them are reached from a seam that needs a process to have been spawned.

`hook` is that seam without the process. The harness hands over the pending call
and reads a verdict back, and the rules it consults are the literal rules, the
text-capable guards **and the `prose_regexp` rules that stand in front of a
command** — the same dispatches `scan --text` and `guard --text` reach, through
the same functions. A prose rule naming `gh` is asked here for the reason it is
asked at `commit-msg`: this seam is what an agent uses *instead of* `gh`, so a
sentence shape refused when a person publishes it and allowed when an agent
publishes it would be the same rule with two answers. A prose rule that names no
command is left out, as it is at every `--text` seam — it is scoped by `files.*`
to particular paths, and a tool call has none.

### Configuring it

```jsonc
// ~/.claude/settings.json
{"hooks": {"PreToolUse": [
  {"matcher": "mcp__github__.*",
   "hooks": [{"type": "command", "command": "uphold hook claude-code"}]}
]}}
```

The `.*` is required. A matcher of `mcp__github` holds only exact-match
characters, so it is compared as a string and matches no tool.

**Which calls arrive is the harness's decision, not this binary's.** Re-deciding
it here would be a second matcher free to disagree with the first, and an
operator would have to hold both. What arrives is checked.

### What runs where there is no policy

Every other seam requires a policy and exits `2` without one, because a git hook
runs in the repository whose policy applies by construction. A tool call does
not: it is made from wherever the session was started, which is frequently a
workspace superproject whose policy is deliberately not borrowed, a scratch
directory, or a checkout with no `policy/` at all. **Could-not-look is the
ordinary case at this seam rather than the edge**, and the choice of what it
means is load-bearing:

- refusing on it blocks routine work from every non-policy directory, and
  `psychological-acceptability` says what happens next — the cheapest response is
  deleting the matcher, and the seam's real coverage goes to zero
- passing silently reports an unknown as a pass, which `explicit-unknown` refuses

So the halves are split by what each needs. The **host-identity rules run
anyway**, carrying the fallback `scan --text` documents for this case, because a
seam that stood down here would be absent in exactly the places nobody thought
to configure it. The **guards and the prose rules do not run** — both are
declarations, and there is no file declaring them — and their absence is printed
to stderr: partial coverage, said out loud, rather than a pass.

### The exit code is the harness's, not uphold's

Everywhere else in this binary `1` is refused and `2` is could-not-look. Here the
harness owns the protocol. Claude Code reads a refusal out of a JSON document on
stdout and treats a non-zero status as a failure *of the hook* rather than a
verdict *on the call* — so exiting `1` to mean refused would let the body through
with a complaint attached. The refusal travels in the document:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
 "permissionDecisionReason":"uphold refused what mcp__github__create_pull_request ..."}}
```

It is printed to stderr as well, so a person running `uphold hook` by hand reads
the report rather than a line of JSON. `2` keeps its meaning for the two things
that are uphold's own: a harness name the binary does not describe, an event that
is not JSON, and an event carrying nothing at all where the subject pointer says
it should be. None was examined, and none is reported as allowed.

That third one is the case that does not announce itself. The JSON parses, the
run exits, and what the call was about to send was never read -- which is what a
harness renaming its field looks like from here. **Absent is not empty.** A
subject that is present and holds no strings is a call carrying only numbers and
flags: read, and clean. A subject that is a bare string rather than an object is
text, and text is what every rule at this seam judges. The question is whether
the subject was found, never what shape the harness chose for it.

### What it reads out of the call

Every string anywhere under the harness's input pointer, at any depth. Not a
list of field names per tool: a server decides what to call the field holding a
body, a release note or a branch name, and a table of those names is a table
missing the one a new server just added — silently, and in the green direction.

### Adding a harness

The shapes are data, one row per harness: a pointer to what the call is called,
a pointer to what it is about to send, the refusal document, where in it the
report goes, and which exit code that harness reads as blocked. A name the table
does not carry is refused and the known ones are listed, because none of those
five values is derivable from a name.

## `uphold audit --for-publication`

Every guard across every seam conditions on *is the target public **now***. So
content written into a private repository is correctly allowed at write time,
and nothing re-examines that decision when the repository later goes public. A
private→public flip is a **bulk republication event** covering the tree, every
commit message, and every issue and comment at once — and no seam has a trigger
for it.

```sh
uphold audit --for-publication
```

One shot, not a hook. It judges under the visibility the repository is *about
to have*, using the repository's own `no-private-repo-names` rule with that one
field overridden — so what counts as a private name here is what counts
everywhere else.

The names must come from outside the tree, since a public repository cannot hold
the list of what must not be published:

```toml
[rule.no-private-repo-names]
builtin = "no-private-repo-names"
private_owners_from = "cat ${XDG_CONFIG_HOME:-$HOME/.config}/principles/private-owners"
git.hooks = ["commit-msg"]
```

A literal `private_owners` list is right for a repository staying private, and
the audit reports it as a finding for one being published.

What it reads is **every blob reachable** from `HEAD`, from `origin`'s branches
and from the retained pull-request refs — not `HEAD`'s tree. A name committed
and deleted before `HEAD` is served by the forge forever and survives the
default-branch rewrite, so a tree-only audit answered the wrong question. On the
forge side it reads issue and pull-request **titles** as well as bodies, plus
review bodies and review-thread comments, and a listing that comes back at the
request cap is reported as truncated rather than quietly cut short.

Two surfaces survive a history rewrite: `refs/pull/<n>/head`, which is fetched
explicitly and scanned, and comment **edit history**, which no API exposes.

A fetch of `refs/pull/*/head` that brings back nothing is asked about rather
than assumed: `git ls-remote origin 'refs/pull/*/head'` separates "the forge
retains none", which is a fact about a repository that has never opened a pull
request and leaves the run able to exit `0`, from "the fetch matched nothing",
which is a published surface that went unread. Reading both as unread meant no
such repository could reach a clean answer through this path.

The reachable blobs are read by **one** `git cat-file --batch`, and a run over
more than a couple of thousand objects prints what it is reading and how far it
has got, on stderr. It read one object per process and said nothing until it
finished, which from outside makes a slow audit and a hung one look alike.

An object the batch names without content -- the ordinary case in a shallow or
partial clone -- is reported as a surface this run could not read, and so is exit
`2`. It is not skipped: an object the audit could not open is not an object the
audit found clean.

The edit history is a **standing caveat**, not an unreadable surface. It is true
of every run, on every repository, and nothing about this run could change it —
so it is stated in the body of every report and is *not* counted as something
this run failed to read. Counting it there makes the unreadable list
unconditionally non-empty, which makes exit `0` unreachable and takes away the
clean answer this command exists to be able to give. Exit `1` for something
found, `2` where a surface this run tried to read could not be read, `0` when
every surface a flip would republish was read and was clean — subject to the
standing caveats, which the clean line says.

### When the policy itself will not load

A policy that exists and cannot be read is fatal for every command the shim
stands in front of, because the declaration that could not be read might have
been the one standing in front of *this* invocation. That leaves one problem to
solve rather than to argue with: the `git checkout` that would put the file back
is itself a shimmed command.

```sh
UPHOLD_ALLOW=all git checkout policy/principles.toml
```

`UPHOLD_ALLOW=all` is asked **before** the policy is read, so it works when
nothing else does. It is not a pass — the shim says on stderr that the command
ran unchecked, every time, so a bypass that becomes habit is visible in a shell
history and in a CI log. An empty `UPHOLD_ALLOW=` switches nothing off.

## `uphold supply-chain` — five scanners, one verdict

```sh
uphold supply-chain
```

Orchestrates the five external scanners a fleet had been driving from a
~100-line shell task copied into seven repositories: **osv-scanner** (known
vulnerabilities and reported-malicious packages), **zizmor** (workflow
security), **cargo-deny** (origin, advisories, bans, licenses), **cargo-vet**
(has anyone looked at this dependency) and **guarddog** (publisher identity
and typosquats — the half OSV cannot reach, scoring an *unknown* package on
how closely its name shadows a popular one). The copies had already diverged:
one grew a failure-output dump the others lack, so the same red printed a
reason on one machine and a bare FAILED on the rest.

The scanners come from the host's own toolchain; none is built or fetched
here. What this command adds over the shell it replaces is the third answer:
a tool that is not on PATH is **could not look** — reported by name, exit `2`
through the same verdict ranking every other command here uses — where the
shell spelled it exactly like a refusal, and a wrapper less careful would
spell it like a pass.

Per section: `vendor/`, `upstream/`, `target/`, `node_modules/` and `.git/`
are never descended into — somebody else's manifests are somebody else's
backlog. cargo-deny runs once per crate or workspace root against the root
`deny.toml` (no `deny.toml`, and the section says so and stands down);
cargo-vet runs only where a `supply-chain/` store exists, because a store
created automatically is a store nobody owns; guarddog reads each `uv.lock`
through `uv export` and each `package.json` directly, metadata rules only. A
section with nothing to read says so — "no workflows here" and "checked and
clean" must never look the same.

zizmor is handed the repository's own `zizmor.yml` where one exists, and a
**bundled default** — `ref-pin`, the policy six repositories carried
byte-identically — where none does. `--config` is always named explicitly:
zizmor resolves a discovered config relative to a single input path and finds
none when handed several, then silently falls back to its hash-pin default
and invents a backlog.

Each scanner's own exit code decides; findings are shown, never re-judged.
The one filter applied is cargo-deny's headline lines, dropping the four
classes that describe `deny.toml` rather than a dependency.

One hook id ships it — `uphold-supply-chain` in `.pre-commit-hooks.yaml` —
at `pre-push` and `manual` and never at `pre-commit`: every scanner reaches
the network, and a check that adds a network round trip to a commit is a check
somebody switches off. It is deliberately absent from `hooks/lefthook.yml`:
that file is merged into a consumer's own config wholesale, so a command there
arrives with a `ref:` bump in every consuming repository — and on any machine
without the scanners installed it refuses every push with exit `2`. A
lefthook consumer opts in by writing the command in its own file, where the
decision is visible.

## `uphold hooks --identity` — across repositories

```sh
uphold hooks --identity ../repo-a ../repo-b ../repo-c
```

Every other command here reads one repository. This one reads several, because
the question has no answer inside any of them: **a forked hook declaration is
byte-perfect in every repository that holds it**, and only the comparison shows
that the copies stopped agreeing. A claim naming that id then means one thing in
one repository and something else next door, and `uphold check` reconciles both
green.

Three findings, and they are three different failures:

| finding | means |
|---|---|
| `forked` | one id, two declarations — different `args:`, a different `entry:`, a different glob |
| `pinned apart` | one id, one upstream, two revisions. Everybody runs the check; some run an older one |
| `absent` | an id **most** of the set declares and one does not |

`absent` is deliberately reported only where a majority declares the id. "This
repository has a hook the others do not" is the normal state of a fleet — a
repository with no Go in it has no business declaring `gofmt` — and reporting
every such id turns the answer into a list nobody reads.

The same id in a `.pre-commit-config.yaml` and in a `lefthook.yml` is one check
written twice in two formats, which is what supporting both runners means; the
two are never compared against each other. A lefthook command under two hook
names is two declarations, not one that disagrees with itself.

Exit `0` when every declaration agrees, `1` on a divergence, `2` when a named
directory is not a repository — a directory that declares nothing and one that
could not be read are different answers.

### Waivers

`policy/hooks.toml`, in the repository the command is run **from** — a
fleet-wide exemption written inside one of the repositories it exempts is a
repository excusing itself.

```toml
[[waive]]
id = "uphold-guard-push"
findings = ["absent"]        # or omit: covers all three
repos = ["uphold"]           # or omit: every repository in the comparison
reason = "the hooks repository cannot pin itself"
```

One file holds both halves: the waivers this command reads and the `[[probe]]`
fixtures `uphold probe` drives. Each reader names the other's table, so neither
refuses a well-formed file, and both still refuse a misspelled field of their
own -- which is what `deny_unknown_fields` is for.

`reason` is required and an empty one is refused: a waiver with no reason is a
check switched off with nobody's name on it. A waiver naming a finding that does
not exist is refused, since it would waive nothing while reading as though it
does. A waiver that matches nothing is **reported** — an exemption that no
longer describes the fleet reads as a decision that is doing something while
doing nothing. Whether a waiver is stale depends on which repositories were
compared, because the comparison set is whatever was named on the command line.

## `uphold hooks --install` — the hooks git actually runs

```sh
uphold hooks --install                      # runner detected from PATH
uphold hooks --install --runner pre-commit  # or named; --dir DIR for the directory
```

Writes the four guard-stage hook files — `pre-commit`, `commit-msg`,
`pre-merge-commit`, `pre-push` — into a **tracked** directory (`.githooks/` by
default) and points `core.hooksPath` at it. The hook git runs is then a file a
diff can review, and a rerun of the runner's own `install` cannot quietly take
its place.

The file that earns the inversion is `pre-push`. Measured 2026-08-16, prek
0.3.13: prek computes the pushed range as `<local sha> --not --remotes` and,
when that range comes back empty, skips the whole pre-push stage —
`always_run: true` included. The empty range is the dangerous case, not the
boring one: repointing `origin` at somebody else's remote is a URL edit, not a
commit, so the push that publishes the entire history hands the runner a range
of zero commits. The written `pre-push` runs `uphold guard --stage pre-push`
unconditionally, reading the destination off argv — where git puts it, and
where a `git config` lookup would answer with the very thing that was just
changed — and only then delegates to the runner. One fleet carried this file
by hand, byte-identical in ten trees, with a script whose whole job was to
notice when a copy drifted.

The other three files are delegates. `core.hooksPath` makes git look for
**every** hook in the named directory, so a directory holding only `pre-push`
would silently switch the other stages off — the defect the pre-push file
exists to close, at the other stages.

Fail-closed, in every direction it can be: the written `pre-push` refuses
(exit `2`) when `uphold` or the runner is not on PATH rather than passing what
it could not check; a file in the directory this command did not write is
refused, never replaced; a `core.hooksPath` already pointing elsewhere is
refused, never repointed; and a `default_install_hook_types` naming a hook
type outside the four is refused, because that type would otherwise stop
firing while the install read as one that worked. lefthook is refused by name:
it installs and owns its own hooks, and a `core.hooksPath` written here would
displace them.

## `uphold probe` — can each hook refuse?

```sh
uphold probe                       # runner detected from the config and PATH
uphold probe --runner lefthook     # or named
```

A hook that **cannot fail** reports the same green tick as a hook that keeps
finding nothing, run after run, for as long as nobody plants what it is supposed
to catch. The case this exists for is not hypothetical: an entry declared as
`gofmt -l .` can never exit non-zero, because `gofmt -l` *prints* its findings
and exits 0.

So each probe drives one hook to both verdicts, in a throwaway `git worktree` at
HEAD — never the tree you are standing in:

1. plant the fixture it must refuse, run that hook **alone**, expect non-zero;
2. put the clean fixture in its place, run it again, expect zero.

Isolation is what makes step 1 an answer about the hook rather than about the
stage: the runner is asked for one id, so a non-zero exit is that hook refusing
and not a neighbour.

```toml
# policy/hooks.toml
timeout_seconds = 900       # optional; how long one run may take, for every probe

[[probe]]
id = "gofmt"
path = "probe/fixture.go"
refuses = "package main\nfunc  main( ){}\n"
allows = "package main\n\nfunc main() {}\n"
stage = "pre-commit"        # optional; pre-commit is the default
expect = "gofmt"            # optional; words the refusal must contain
timeout_seconds = 60        # optional; this probe's own patience
```

| report | means |
|---|---|
| refuses its fixture, accepts a clean one | a demonstrated gate |
| refuses its fixture, no `allows` | one verdict driven, and the report says so |
| **ACCEPTED what it is declared to refuse** | the hook cannot fail |
| refused the clean fixture as well | it refuses everything, so its refusal says nothing |
| refused **without the words `expect` names** | a red from somewhere else — reported with what it did say |
| still running at its deadline | killed and **unmeasured** — exit `2`, never a refusal and never a pass |

`expect` pins the refusal to the *rule* the probe is about. Running the hook
alone already narrows a non-zero exit to the hook; it cannot narrow it further,
and a planted fixture that trips a **neighbouring** rule in the same hook — a
whitespace fixer objecting to the fixture written for a home-path rule — reads
as a demonstrated gate without it. An empty `expect` is refused: every refusal
contains the empty string, so it would assert nothing while reading as though
the refusal had been pinned.

`timeout_seconds` is a declaration rather than a constant compiled in, because
where it sits is an operator's call about the machines this runs on: long
enough that a probe pulling a container image on a cold runner is not called a
timeout, short enough that a hook which has wedged is not waited on all
afternoon. The nearest declaration wins — `--timeout` for one run, the probe's
own field, then the file's — and with none of the three the run waits, which
is what it always did. A hook killed at its deadline is **unmeasured**: exit
`2`, never a pass, and `--timeout` is how a suite proves that a timeout is a
failure rather than a silent green. `timeout_seconds = 0` is refused wherever
it is written.

Fixtures are staged in the throwaway worktree the moment they are planted, so
a rule that reads **tracked** files sees every plant — a probe is never
invisible to the scan it drives.

Fixtures are written down rather than generated. uphold knows what its own rules
match and knows nothing about `gofmt`, `ruff`, or a hook somebody wrote this
morning — and the hooks worth probing are exactly the ones it knows nothing
about. A fixture in a file is also reviewable, which matters more than the
typing it saves.

The count of declared hooks with **no** probe is printed every run: "two hooks
were probed" means one thing beside two declarations and another beside twenty.
A probe naming a hook nothing declares is refused, and so is an empty `refuses`
— an empty fixture demonstrates nothing, and a hook that accepted it would be
reported as unable to fail.

Exit `0` when every probed hook behaved, `1` when one could not fail or refuses
everything, `2` when there is no runner to drive them with — a hook that could
not be run has not been shown to refuse anything. `probe` runs the repository's
own hooks, which means the programs it already trusts on every commit.

## `uphold check --coverage` and `--oscal`

```sh
uphold check --coverage       # every rule this repository runs, vs the claims
uphold_check.py --oscal > component-definition.json
```

`--coverage` counts the direction the reconcile cannot — a rule firing under no
claim is invisible to a reconcile. It reports and does not refuse: `0`, or `2`
where a tier's configuration could not be read, with a count of `?` rather than
`0`. See [DESIGN.md](DESIGN.md#coverage-is-not-the-reconcile).

`--oscal` emits a NIST OSCAL component-definition. It reconciles first and emits
only what held. Identifiers are UUIDv5 over repository, tier and rule, so a
re-export with nothing changed is a diff with nothing in it. Four fields ride
along as props in this repository's namespace: the rule id, the seam, the
record's `enforcement.level` and its `automatable`. The catalog itself does not
cross over — see [DESIGN.md](DESIGN.md#why-oscal-and-why-only-the-mapping).

## The review tier

`enforcement.automatable` routes each record to a static rule, to a reviewer, or
to both:

| value | static | review tier |
|---|---|---|
| `yes` | **must** carry a claim — unclaimed is an error, not a statistic | excluded; a rule already refuses it |
| `partially` | may carry claims | the remainder compiles in |
| `no` | must carry **no** claim | compiles in |

```sh
uphold_check.py --review          # what routes where
uphold_check.py --review --emit   # write REVIEW.md and AGENTS.md
uphold_check.py --review --check  # refuse a stale or over-budget document
```

A compiled entry is `claim`, `applies_when` and `review_questions` — no new
schema. `[review] max_lines` (default 900) budgets that compiled document, and
is a different field from the [rule one](#max_lines-and-max_bytes-and-the-baseline-that-ratchets-them)
of the same name. It is load-bearing rather than a nicety: see
[DESIGN.md](DESIGN.md#why-the-review-tier-is-not-what-that-record-refuses).
Over budget fails the build and says to shorten records or narrow
`include_domains`.

When a repository has no subject for a principle, say so with a reason:

```toml
[review.no_subject_here]
backpressure = "Nothing here has a queue, an admission decision, or a producer to slow down."
```

An entry goes stale the moment a rule does claim the record, and is reported
then.

### Controls: can a record produce a finding at all?

A record nobody has raised and a record that says nothing a reviewer could act
on are the same silence. A control is the change that separates them — the
[probe](#uphold-probe--can-each-hook-refuse) fixture one tier
up, written beside the declaration and refused on the same grounds:

```toml
[[review.control]]
record = "single-authoritative-source"
catches = "Add a hand-written page restating what the generated one already compiles."
misses  = "Change the renderer that generates it."
```

`catches` is a change the record **must** be found by; `misses` is optional and
is a change it must **not** fire on. An empty `catches` is refused — a reviewer
handed nothing either names the record, crediting it with a finding nobody
planted, or does not, and reports a live record as dead. So is an empty
`misses`, a field no control has, a `record` the catalog does not define, and a
`record` no reviewer is shown: one that is `automatable = "yes"` is excluded
from the compiled document because a static rule already refuses it, and one
outside `include_domains` here is not in the document either. The shape of the
declaration is exit `2`; a control that names the wrong record is exit `1`,
beside a stale exemption.

The count **and the names** of review-carried records with no control print on
every run:

```text
18 review-carried record(s) have no control, so nothing here shows they can produce a finding: complete-mediation, ...
```

`[review] emit_controls` writes them where a harness can read them, under the
same `--check` gate as the document, so a control that was added and never
exported is refused:

```toml
emit_controls = ["review-controls.json"]
```

It carries `record`, `catches`, `misses` and the uncontrolled list, and nothing
from the catalog: a harness also handed the claim and the questions would be
carrying a second copy of the compiled document. Driving a reviewer against a
control needs a model, a budget and a verdict nothing here can make
deterministic, so the harness itself is outside this repository. See
[DESIGN.md](DESIGN.md#a-control-is-the-probe-fixture-one-tier-up).
