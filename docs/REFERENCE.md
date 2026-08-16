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
| `comment_regexp` | the regex matches a **comment** in a selected Rust or Python file |
| `trivial_comments` | a comment contributes no word the code beneath it already names |
| `path_regexp` | a tracked path matches the regex |
| `require_regexp` | a selected file does **not** contain the regex |
| `max_lines` | a selected file is longer than that, or grew past its baseline |
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
| `files.*` | ripgrep scoping — `glob`, `multiline`, `fixed_strings` | `uphold scan` |
| `git.hooks` | githooks(5) names — `pre-commit`, `commit-msg`, `pre-merge-commit`, `pre-push`, `manual` | `uphold guard --stage <hook>` |
| `command.before` | the command line as typed — `"gh pr create"`, `"git push"` | `uphold shim <command>` |

Both halves are checked at load. A rule naming two checks is refused, because
one of them would be read by nothing while looking enforced. A rule naming no
place is refused, because it runs nowhere and that reads exactly like a rule
that passes. `command.before` is refused on a check no shim can consult — the
shim consults `exec` checkers and the built-ins that can judge arbitrary text
(`prevent-ai-author`, `prevent-unusual-unicode`, `no-private-repo-names`), and
anything else reads an index, an identity or a push range and has nothing to say
about a pull-request body.

A text-capable built-in with `command.before` and no `git.hooks` is a deliberate
shape, not an omission. `no-private-repo-names` reads the commit message at
every git hook, and a repository whose own prose cites its issues would have
every one of those citations refused — so the seam it belongs at is the command
that publishes text to a forge, and only that one.

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
inherits should be written in the repository. Twelve are compiled into the
binary and mirrored in [`policy/base/`](../policy/base), each **named by what
it refuses** so the name predicts the rule list:

| set | refuses |
|---|---|
| `process-residue` | authoring and process residue in committed content — conflict markers, home paths, dated and status metadata, tracker and thread references, private data paths — and, at `manual`, the residue a process leaves in the policy file itself: a rule transcribed out of a set |
| `credentials` | credential material — private keys and service tokens, literal credential values, populated environment files, browser profile and session stores |
| `unmanaged-pins` | a version pinned where no manifest holds it — a shell install line, a `releases/download/vX.Y.Z` URL, a versioned `curl` or `wget` |
| `host-identity` | the machine the author is standing on — its username, home path, hostname and default route, read at scan time and searched for in content |
| `broken-links` | a markdown link naming a path that does not exist or leaving the repository, and a selection that yields no links at all |
| `captured-fixtures` | a test fixture holding non-ASCII content, as the one signal that a capture from a live upstream survives redaction |
| `doc-claims` | a document whose anchored fact disagrees with the record it names — a value the record does not hold, a key that is not there, a source or captured artifact that is absent |
| `commit-message-residue` | authorship markers and unusual characters in the message a commit records — **installs `commit-msg`** |
| `unreviewed-history` | a merge made locally rather than through a pull request — **installs `pre-commit` and `pre-merge-commit`** |
| `invisible-characters` | characters that draw nothing, in committed content and in the paths that carry it — **installs four stages**, and reads the whole tree at each |
| `stale-pins` | a hook pinned at a revision its upstream has left, or at none — **installs `pre-push` and `manual`**, and reaches the network |
| `unowned-push` | a push to an owner this repository has not named — **installs `pre-push`**, and refuses to run until the repository says who it is |

The last five install git hooks. Taking one is a decision about what will be
refused and when, so each is named and argued separately: `stale-pins` reaches
the network and cannot answer on a train, `invisible-characters` reads the tree
at four stages and is the slowest thing in a hook, `unreviewed-history` stands
in front of every commit, and `unowned-push` demands one line before it will run
at all:

```toml
owner = "your-org"          # at the top of the policy file

[inherit]
sets = ["unowned-push"]
```

`owner` is a top-level field rather than a rule parameter because a rule
arriving from a set cannot be handed one — the only way would be to write the
rule out again, which is the transcription `no-hand-copied-base-rule` refuses —
and because who a repository belongs to was never a property of one rule in it.
`owner_required = true` on the rule is what makes the omission an exit `2`
rather than a guard that quietly reads the answer off `origin`, which is the
remote most likely to be the thing that went wrong. `allowed_owners` or
`allowed_repos` satisfy it too: naming the destinations is a way of saying who
you are.

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
stages = ["manual"]   # empty (the default) means: no git hook at all
```

A rule in a bundled set declaring a hook outside that list is refused at load.
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
(shipped in `process-residue`, at `manual`) refuses a rule written out by hand
under an id a set already ships, from a set the repository does not inherit. It
names the id, the owning set, and what else inheriting that set would bring.
A rule of the same id from a set the repository **does** inherit is the
documented override and stays silent.

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
content that never becomes a file. It runs the `forbidden_literals` rules only:
those describe the running machine, so they mean something against any text,
while a `regexp` rule is scoped to paths and file types and firing it at prose
would be guesswork.

Two things it does not do. It does not decode: text that is not UTF-8 is exit
`2` naming the offset, because a lossy decode searches U+FFFD where the bytes
were and calls the result clean. And a repository declaring `forbidden_literals`
rules of its own does not switch the built-in host-identity rule off — the
built-in is added unless one of the declared rules is itself
`forbidden_literals = "running-os-identity"`. Declaring a rule about something
else is not a decision to stop checking this.

### `comment_regexp` and `trivial_comments` — the comment, not the line

Both parse the file rather than searching it, in Rust and Python. That is the
whole reason they are separate checks: `regexp` reads bytes, so
`let marker = "// TODO";` is a hit for a rule about `// TODO` and there is no
way to write the difference down. These read comment nodes, so a marker inside a
string literal is a string literal.

```toml
[rule.no-before-after-narrative-in-source]
message = "State what holds, not what it replaced."
comment_regexp = '(?i)\bused to be\b'
files.include = ["src"]
files.glob = ["*.rs", "*.py"]

[rule.no-trivial-comment]
message = "This comment says only what the code beneath it already says."
trivial_comments = true
files.include = ["src"]
files.glob = ["*.rs", "*.py"]
```

**Documentation comments are excluded from both.** `///` and `//!` are published
output, not remarks to the next reader, and a check that cannot tell them apart
from `//` is one whose findings, acted on, delete a public item's documentation.
The grammar marks them; nothing here matches on the prefix, which is what a
prefix test gets wrong by construction — `///` starts with `//`.

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

### `max_lines`, and the baseline that ratchets it

A language's own linter caps the length of the files its parser opens. This one
runs over whatever `files.*` selects, so the Markdown, the workflow YAML
and the generated table are in scope too — and it takes a baseline, which is
the reason it is here rather than deferred to that linter.

```toml
[rule.keep-modules-readable]
max_lines = 400
message = "split the module"
files.glob = ["src/**/*.rs"]
files.baseline = "policy/size-baseline.txt"
```

One `path count` per line. A listed file is held to **its own number** instead
of the limit and fails when it grows, so what is already oversized is frozen
rather than exempted — the difference between a ratchet and a suppression
comment, which is invisible in the policy and permanent in the file.

A baselined path the rule no longer selects is reported. An allowance nothing
reports is the rule switched off for that path, and it would apply again in full
the day something takes the name back.

Not to be confused with [`[review] max_lines`](#the-review-tier), which budgets
the compiled review document rather than a file a rule selects.

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

## `uphold guard` — the guards

`uphold guard --stage STAGE` runs the guards that have something to say at
that moment. A content rule reads the tree and could run at any time; a guard
reads an **act** — the message about to be recorded, the identity about to be
stamped on it, the range about to be pushed.

| guard | refuses |
|---|---|
| `prevent-ai-author` | AI-authorship markers in the message being written — and at a push, in **every commit message the push publishes** |
| `prevent-author-mismatch` | an identity that is not your global one |
| `prevent-unusual-unicode` | unusual characters in the same set of messages |
| `prevent-unusual-unicode-in-files` | characters that draw nothing, in committed content **and in the paths that carry it** |
| `no-private-repo-names` | a private repository named in a public one's message |
| `no-private-repo-names-staged` | the same, in the lines a commit adds |
| `no-private-repo-names-in-files` | the same, anywhere in what is being introduced — content, **path names**, and at a push the **commit messages** the push publishes |
| `prevent-public-push` | a push to somewhere off the allow-list |
| `no-local-merge` | a merge that would make a merge commit |
| `no-merge-commit` | a commit finishing a merge or a squash merge |
| `no-stale-hook-pins` | a pin left behind its upstream, or naming no ref — in `.pre-commit-config.yaml` **and** lefthook `remotes:`, at any depth in the tree; a pin it **could not check** is exit `2` |
| `no-hand-copied-base-rule` | a rule this policy writes out by hand under an id a bundled set already ships, from a set it does not inherit. Reads the **policy**, not the tree |

Declared like any other rule, in the same file and the same id namespace.
**`git.hooks` is the whole registration.**

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

### Built-in parameters

Each built-in declares the parameters it reads, and **a parameter on a rule
whose check does not read it is refused at load** — the same refusal as a
second check field, for the same reason: a field read by nothing looks
enforced and is not.

| parameter | read by | meaning |
|---|---|---|
| `owner` | `prevent-public-push` | the owner this workspace is pinned to |
| `allowed_owners` | `prevent-public-push` | owners a push may go to; defaults to the pinned owner |
| `allowed_repos` | `prevent-public-push` | single repositories allowed through, `"owner/repo"` |
| `visibility` | the `no-private-repo-names` family | this repository's visibility, declared instead of looked up |
| `private_owners` | the `no-private-repo-names` family | owners whose repositories are private regardless of what a forge says |
| `private_owners_from` | the `no-private-repo-names` family | a command whose stdout is one private owner per line |
| `public_repos` | the `no-private-repo-names` family | names treated as public without asking a forge |
| `refuse_unknown` | the `no-private-repo-names` family | treat a name whose visibility could not be determined as private |
| `allow` | `prevent-unusual-unicode-in-files` | codepoints admitted, optionally under one glob — `"U+00A0:docs/captured/**"` |

The "family" is `no-private-repo-names`, `-staged` and `-in-files`. No other
built-in reads any parameter. The same mechanism holds beside the checks:
`exclude_cfg_test` is read only by the content searches (`regexp`, `values` —
its job is dropping a matched *line* inside a `#[cfg(test)]` block, and no
other check has one), `require_any_link` / `allow_outside_repo` are read only
by `links-resolve`, and `require_any_anchor` only by `anchors-resolve`.

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
match = ["pr:create", "pr:edit", "issue:create"]   # named, never guessed
text_flags = ["-t", "--title", "-b", "--body"]
file_flags = ["-F", "--body-file"]
skip_flags = ["--fill"]
editor_env = "GH_EDITOR"
target = "forge-repo"
scope = "public-target"
```

`target` is `forge-repo` or `git-remote`, both built-in resolvers. `scope` is
`public-target | public-registry | always`, with `scope = { command = "..." }`
as the escape hatch — `npm publish` has no repository, owner or visibility
endpoint in it. `collect = "git-refs"` replaces the argv walk for `git`, whose
published text is positional.

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
[[probe]]
id = "gofmt"
path = "probe/fixture.go"
refuses = "package main\nfunc  main( ){}\n"
allows = "package main\n\nfunc main() {}\n"
stage = "pre-commit"        # optional; pre-commit is the default
```

| report | means |
|---|---|
| refuses its fixture, accepts a clean one | a demonstrated gate |
| refuses its fixture, no `allows` | one verdict driven, and the report says so |
| **ACCEPTED what it is declared to refuse** | the hook cannot fail |
| refused the clean fixture as well | it refuses everything, so its refusal says nothing |

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
is a different field from the [rule one](#max_lines-and-the-baseline-that-ratchets-it)
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
