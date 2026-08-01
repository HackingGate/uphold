# ADR 0001: a config surface a stranger can read in one minute

Status: Accepted

This record carries the design rationale for the consumer-writable config
surface: what each name is, and why it earns its place. It is not the
reference — [REFERENCE.md](../REFERENCE.md) documents the schema. Where this
record and that document disagree, it wins; this one records the judgment
behind it.

## Goal

This tool is meant to be adopted by strangers, not run by its authors. The
acceptance test for every name in the config surface: **an engineer who knows
common basics — regex, encodings, globs, git hooks — browses the repo for one
minute and can predict what a rule does from its spelling alone.** No field
may require reading `src/` to configure, and no field may use a word this
repository invented when a standard vocabulary exists.

## The judges

The judges are four records this repository ships in `principles/`:

- **psychological-acceptability** — a mechanism the operator cannot understand
  gets misused or bypassed. The one-minute test is this record's test.
- **parameterize-do-not-enumerate** — accept the standard namespace, don't
  hand-enumerate a subset of it.
- **mechanism-policy-separation** — a mapping the tool applies on your behalf
  is policy; it belongs in the config, not the binary.
- **least-astonishment** — a field silently unioning with another declaration,
  or a parameter silently read by nothing, is astonishment.

Every consumer-writable field is held to all four. The decisions below are the
places where holding to them decides something a reader might otherwise expect
to go the other way.

## One rule is one section

The rule id is the section header — `[rule.<id>]` — and `files.*`, `git.*`
and `command.*` are dotted keys inside it. Nothing about a rule lives outside
its header's scope, so which rule owns a key is visible at the point of use
and cannot drift during an edit.

Two properties fall out for free. A duplicate rule id is a TOML parse error,
not a runtime check — `make-illegal-states-unrepresentable` — and the only
uniqueness check that remains is for the one collision no parser can see: two
*inherited* files defining the same id. And kebab-case ids are legal bare
keys, no quoting.

"The whole tree" is written `files.include = ["."]`, which is what an absent
`include` means; dotted keys cannot spell an empty table, and the explicit
spelling reads better anyway.

Shims are `[[shim]]` tables: their fields are flat, with no sub-tables to own,
so the ambiguity the rule sections exist to prevent has no purchase there.

## Scripts are the unit, spelled the way regex spells them

`allowed_scripts` constrains which Unicode scripts may appear in text. The
check is mixed-script detection — UTS 39, over the UTS 24 Script property —
and the field says so rather than wearing a language-shaped name: no list of
prose languages can express it, because two languages can admit exactly the
same script.

- Values are **Unicode script names as regex engines spell them**:
  `allowed_scripts = ["Hiragana"]` admits exactly what `\p{Script=Hiragana}`
  matches. An engineer who knows regex already knows the whole namespace, and
  the runtime validates against that namespace rather than a hand-enumerated
  subset — `parameterize-do-not-enumerate`. A miscased or unknown name is
  refused with the standard spelling suggested.
- A scoped rule's list is **the whole truth for the files it selects** —
  replace, not union, with the top-level declaration. What is declared beside
  the path is what holds for the path; nothing invisible reaches in.
- `Common` / `Inherited` / `Unknown` — punctuation, digits, combining marks —
  are never the subject, and declaring one is refused because it would be read
  by nothing.
- `exclusive = true` is the reverse direction: the rule's scripts are also
  refused in every file the rule does not select, so both directions together
  are the if-and-only-if. A script admitted where it stands — by the top
  level, or by another rule selecting that file — stays admitted: exclusivity
  adds refusals where nothing admits the script, and does not revoke an
  explicit grant.
- Script is the unit rather than a codepoint range because a range is the
  wrong shape for the question: Han alone is scattered over non-contiguous
  blocks plus extensions, and membership moves with the Unicode version.

## Encoding is a property of the bytes, script of the decoded text

`encoding` declares the charset a file's bytes must decode cleanly under, by
its WHATWG label — `"Shift_JIS"` means what it means to every browser, and an
unknown label is refused at load against the registry, not at the first file.

It is a separate field from `allowed_scripts` because the two speak about
different layers: one field fusing them could not say "UTF-8 file containing
Japanese" and "Shift-JIS file containing Japanese" apart. They compose — a
file covered by both is decoded under its declared charset and then
script-checked as text.

The `explicit-unknown` consequence: a non-UTF-8 file under a script
declaration that no encoding rule covers is could-not-look, exit 2, with the
cures named — declare the charset, exclude the file, or mark it not text in
`.gitattributes`. "Clean" must never mean "unexamined".

## The literal check is named by what it forbids

`forbidden_literals` names a built-in source of literals that must appear
nowhere in the selected files: values describing the running machine —
username, hostname and its identifying segments, home path, default-route
addresses — which cannot be written into a policy file, because writing them
there is the leak the rule exists to prevent. `forbidden_literals_from` names
any command producing one literal per line: same check, operator-supplied
source, writable in any language.

Some literals are never searched for — words that describe a machine's *kind*
rather than its owner, which would fire on every legitimate mention. That
suppression is policy, so it lives where policy lives: the default list is
documented word for word in REFERENCE.md, and `ignore_literals` extends it per
rule. A suppression the operator cannot see is mechanism eating policy.

## Inherited sets are named by what they refuse

`[inherit]` says what happens to the rules; `sets` says what it selects; each
bundled set is named by what it refuses — `process-residue`, `credentials`,
`unmanaged-pins` — because the name is the only thing a stranger reads before
deciding to inherit one, and it must predict the rule list.

There is no take-everything shorthand: naming three sets is cheap, what a
repository inherits is written in the repository, and each set is a separate
decision — `unmanaged-pins` refuses a shape a repository that vendors
deliberately has on purpose, and that argument should not stand between
anyone and `process-residue`.

The name-must-predict principle has a mechanism, not just an intention:
`uphold rules --set <name>` prints a set's rules, so the binary answers
"what is in it" without a docs round-trip, and a proposed name can be judged
against the list it must predict.

## A parameter is read, or it is refused

Every built-in declares, in one place, which parameters it reads — and a
parameter written on a rule whose check does not read it is refused at load,
exactly as a second check field is, and for the same reason: a field read by
nothing looks enforced and is not.

The parameter fields are optional rather than defaulted so that WRITTEN and
ABSENT are different facts to the validator; an explicitly empty list beside
the wrong check is precisely the thing that looks enforced, and a defaulted
field could not be refused.

The same discipline holds for every check-specific knob: `exclusive` beside a
check that reads no scripts, `ignore_literals` beside one that searches for no
literals, `require_any_link` / `allow_outside_repo` beside one that reads no
links, `exclude_cfg_test` beside one with no matched line — each is refused
where nothing reads it. Check knobs are rule-level fields, not entries in the
shared `files.*` selection vocabulary, so a rule author never scrolls past
fields that cannot apply to their rule.

## What is deliberately borrowed, and what is deliberately absent

The rest of the surface borrows standard vocabularies on purpose and adds
nothing to them: `regexp` / `path_regexp` / `require_regexp` are regex, with
the require/forbid split legible from the names; `max_lines` takes a
`baseline`, the standard ratchet term; `files.*` selection is ripgrep's own
scoping; `git.hooks` takes githooks(5) names; the `exec` contract is one
contract for any language — subject on stdin, kind in `UPHOLD_KIND`,
0 pass / 1 refuse / 2 could-not-look.

Deliberately absent: regex-based file selection. Globs are the standard
selection language (ripgrep, gitignore), they express every scope raised, and
a second path language in the selection keys would be two ways to say one
thing.

Older spellings of this surface are not part of it, and no path carries one
forward: a file writing one is refused at load, naming the field it wrote and
the field this schema reads. There is one repository behind this tool and it
holds one config; a translation layer for a shape nothing writes is surface
that has to keep working and nothing to prove it does.

## Scope

The claims file (`policy/upheld.toml`) and its `[review]` table are outside
this record's scope; their surface is documented in REFERENCE.md.
