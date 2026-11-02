---
name: wheels-scan
description: Scan one repository for hand-rolled code that a maintained component already provides, and for stack choices that are no longer current, judged against the reuse-maintained-components and current-stack records at the pinned uphold revision. Use when asked to find reinvented wheels, hand-rolled helpers, outdated frameworks or toolchains, or to check whether a repository's stack is current.
---

# Wheels scan

A scan reads one repository and reports two kinds of finding: code that
re-implements what a maintained component provides, and a language, runtime,
framework, library, toolchain or service whose choice no longer rests on
current evidence. It judges both by two catalog records and by nothing else:
`reuse-maintained-components` and `current-stack`. The scan reports; it does
not change code. Each swap it recommends is a separate change the owner
decides on.

## 1. Read the records the scan applies

Find the uphold revision the repository pins: the `rev:` of the
`HackingGate/uphold` entry in `.pre-commit-config.yaml`, or the `ref:` of that
remote in `lefthook.yml`. No pin: use the installed `uphold --version` and say
so in the report.

Read `principles/reuse-maintained-components.toml` and
`principles/current-stack.toml` at that revision. Every finding cites the
record line it rests on, and the lines that bound the scan most are each
record's `does_not_mean`:

- A component that is abandoned or has one maintainer is not a better choice
  than the code it would replace.
- Code whose fit to a library is poor, whose library would be large against
  the need, or that is the product's own core, is kept, with its reason.
- An incumbent that is still maintained and still fits is kept, and the
  report says it was judged and kept.
- The newest release is not the current one.

## 2. Map what the repository is built from

From the repository root, list:

1. Each manifest and lock file (for example `Cargo.toml`, `package.json`,
   `go.mod`, `pyproject.toml`) and the runtime and toolchain pins (for example
   `rust-toolchain.toml`, `mise.toml`, `.tool-versions`, `engines`).
2. Each direct dependency with its pinned version.
3. The source areas, split into slices a reader can hold at once: one
   directory or one concern per slice.

When there are more than a few slices, scan them in parallel, one agent per
slice, each given only its slice and this file. Give each agent a scratch file
of its own for its output.

## 3. Find hand-rolled code

In each slice, look for a function or block that does what a standard library,
a widely used library or a tool already does. The shapes met most often are:

- parsing or writing a standard format: Markdown, TOML, YAML, JSON, URLs,
  version strings, dates;
- quoting or splitting for a shell, and building command lines as one string;
- walking files with hand-written glob or ignore matching;
- downloading and unpacking a toolchain outside a version manager;
- temporary files, atomic writes, and checking that a path exists before
  creating it;
- argument parsing, terminal width, colour and Unicode classification.

For each candidate:

1. Read the comment beside it. A reason for not using a component that
   matches a `does_not_mean` line ends the finding: report it as kept, with
   the line.
2. Name the component that would replace it, and confirm the component
   covers what this code does, including its edge cases, from the
   component's documentation at a version the repository could take.
3. Where you think the hand-rolled form is wrong, write a test or command
   that shows it failing before you call it a bug. A defect with no repro is
   reported as unverified, never as a bug.

## 4. Judge each stack choice on current evidence

For each runtime, toolchain and direct dependency, and for each replacement
component named in step 3, collect the evidence `current-stack` and
`reuse-maintained-components` name:

- the publisher's support window for the pinned release, and the supported
  release line;
- the date of the latest release, and whether the repository is archived;
- open security advisories against the pinned version;
- how many projects depend on it, and its maintenance score where one is
  published.

Use any source that publishes these, and name it beside each fact. Sources
that do include endoflife.date for support windows, deps.dev for versions,
dependents and advisories, and OpenSSF Scorecard for maintenance. A fact no
source gives is reported as unknown, not guessed.

A pinned version behind its latest release is not a finding when the pinned
line is still supported. The finding is a line that is past its support
window, unmaintained, or carrying an advisory, or a choice whose only stated
reason is that it was already in use.

## 5. Write the report

One entry per finding, grouped by verdict:

```text
<verdict>: <path>:<line> <what the code or pin is>
  replace with: <component> <version>, or none
  evidence: <fact> (<source>), ...
  record: <id> L<n> "<the line, exactly as at the pinned revision>"
  repro: <test or command that shows the defect>, or none
```

The verdicts are:

- `bug`: the hand-rolled form is wrong, and the repro shows it.
- `swap`: a maintained component fits and the reason to keep the code is
  missing.
- `stale`: a stack choice past support, unmaintained or carrying an advisory.
- `kept`: judged and kept, with the reason and the record line that allows
  it.
- `unverified`: a suspected defect or gap without a repro, or evidence no
  source gave.

Do not add a severity, effort or confidence the records do not define. Do not
open pull requests from the scan. Put line numbers in the report as they are
on the commit scanned, and name that commit, because they move.
