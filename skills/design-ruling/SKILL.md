---
name: design-ruling
description: Answer the open questions in a repository's design issues from the uphold records that repository adopts under [decide], checked against the specification it declares there, citing each record item by a link to the record and a quote of the item, and each requirement the answer changes, or escalate. Use when asked to rule on, answer or decide a design record's questions.
---

# Design ruling

A ruling answers one question in a design issue from the records the
repository adopts, and from nothing else. Where the repository declares a
specification, the ruling also reads it: it never decides a question, but an
answer that contradicts it must say what it changes there, so that the
specification and the ruling never hold two copies of one fact. The owner
reviews which records are adopted, the order between two that conflict, and
where the specification lives; everything else in a ruling must be traceable
to them.

## 1. Read what the repository rules by

Run `uphold check --json` from the repository root and read `decide`:

- `adopt` is the record ids the repository answers design questions from.
  An entry may be a table `{id, why}` instead of an id. Its `why` is the
  repository's reason for adopting the record: context for reading the
  record's scope, never a citation, and never a ground for an answer.
- `order` is one `{prefer, over, why}` per adopted pair that conflicts.

- `specification`, when present, is `{path, repository}`: where the
  repository's specification lives. With no `repository` it is `path` in this
  repository, read at the checked-out commit. With one, it is `path` in that
  `owner/name` repository at its latest tag, the first line of
  `git ls-remote --tags --refs --sort=-v:refname https://github.com/<repository>`.
  Record the commit id or tag, because the answer cites it. Absent, rule from
  the records alone.

If `uphold check` exits 1 with `design rulings refused ([decide])`, escalate
every question: an adopted conflict with no order has two answers, and a
declared specification that is not there cannot be checked against.

Read the whole specification at that revision before ruling. Note the id of
each item it holds, as the specification's own tooling names it: for example
an [OpenFastTrace](https://github.com/itsallcode/openfasttrace) item's
`<type>~<name>~<revision>`, or a [Duvet](https://github.com/awslabs/duvet)
requirement's file and section heading. If it is declared and cannot be
read, or its repository has no tag, escalate every question; never rule as
though none were declared.

Find the uphold revision the repository pins: the `rev:` of the
`HackingGate/uphold` entry in `.pre-commit-config.yaml`, or the `ref:` of that
remote in `lefthook.yml`. Read each adopted record as
`principles/<id>.toml` at that revision, with `uphold --version` matching it.
A different binary carries a different catalog, and its items are not the ones
the quotes will be checked against. The answer never repeats the revision: the
hook configuration states it once.

## 2. Check the options

A ruling can pick only among the options the issue offers, so an option left
out is an answer the records never see. Before ruling on a question:

1. Name the published standard each part of the question reads, writes,
   speaks or implements (an RFC, ISO, W3C or ECMA text, or the protocol the
   design is modelled on), and the convention of the neighbouring tools. The
   framer writes it under the question, before the options, on one line:
   `Standard: <the standard, with a link>`, or
   `Standard: none -- <why none fits>`. A question that lacks the line is not
   ready to rule: write it first, from the standard you found, and
   `questions-name-a-standard` refuses the body on `gh issue create` or
   `gh issue edit` until every question under the questions heading carries
   it. Where an adopted record asks for conformance and no option conforms,
   add the option that does.
2. Name the constraints every option shares: an existing field, structure or
   path kept as it is, a change kept small, compatibility with what was
   built. Keep a constraint only when an adopted record or the repository's
   written instructions impose it. Where the instructions allow replacing what
   exists, add the option that replaces it outright, with nothing old left
   beside it.
3. Write each added option under the question with the others, and say in
   the answer that it was added at ruling and why.
4. Where a specification is declared, check each option against every item
   in it. An option that contradicts an item must carry the change it would
   make there: each item it changes or removes, by its id, with the new text
   of a changed item. An option that contradicts an item and does not carry
   that change cannot be picked: if the records would decide it, escalate the
   question as incomplete, naming the items it contradicts.

## 3. Rule on each question

For each question under the issue's questions heading:

1. Strip any "(recommended)" from the options and read them in no particular
   order. Which option the proposer prefers is not evidence.
2. Find the adopted records whose `applies_when` holds for the question. None
   applies: escalate, saying which part of the question no record covers.
3. Where two applicable records conflict, the `order` between them decides.
   No order for that pair: escalate.
4. Pick the option the applicable records decide. Cite every record item the
   decision rests on: a `claim`, an `applies_when`, a `does_not_mean`, a
   `review_questions` item. Where a record's source decides it, cite the
   source's `locator` or URL fragment too.
5. Where no option meets the goal the records state, answer that none does,
   and cite the line that states the goal.
6. Name the closest ruled precedent: an earlier design issue labelled
   `design:accepted`, or `ruling:accepted` where the repository still carries
   that label, whose `Answered:` line cites the same record items. None: say
   so.

Run the ruling three times, independently, with the options in a different
order each time. All three must give the same answer, or escalate and say they
did not.

## 4. Write the answer

Each question already carries its `Standard:` line from step 2.1; keep it, and
correct it in the same edit where the ruling found a standard the framer did
not name. Under the question, after its options, on its own line:

```text
Answered: (a). [<id> <field>](https://github.com/HackingGate/uphold/blob/HEAD/principles/<id>.toml) "<the item, exactly as the record says it>"; precedent: <issue link, or none>
```

Where the picked option changes the specification, name each item it changes
after the last record quote and before the precedent, with the revision read
(the tag, or the commit id for this repository's own):

```text
Answered: (b). [<id> <field>](...) "<the item>"; specification at <tag>: changes `<item id>`, removes `<item id>`; precedent: <issue link, or none>
```

Write item ids in backticks, never in double quotes: `ruling-citations-resolve`
reads the first double-quoted text after a record link as its quote. An answer
that changes nothing in a declared specification says
`specification at <tag>: unchanged`.

Or, to escalate:

```text
Answered: escalated -- <reason>
```

The link names no revision and no line: its revision segment is `HEAD`, and
which catalog the quote is read in is the pin. `<field>` is the key the item
sits under (`claim`, `applies_when`, ...), for a reader; the check does not
read it. The quote follows its link and is copied from the item as the record
holds it at the pin, an exact substring of one string, because
`ruling-citations-resolve` refuses the body when no item of that record at the
pin contains it. That refusal on a later edit means the item changed in a bump:
re-rule the question it names before publishing again. Publish with `gh issue edit` or
`gh issue create` so that check and `questions-name-a-standard` run. Do not
change the issue's status label (`design:proposed`, or `ruling:pending` where
the repository still carries it): the owner records the ruling.

## 5. Score the answer and its citations

`uphold_check.py --review --drive --rule -- <ruler>` asks a ruler each
`[[review.ruling]]` control in `policy/upheld.toml` and scores it; see
docs/REFERENCE.md, "Ruling controls". The ruler reads
`{"document", "question", "options"}` on stdin and prints
`{"answer", "citations"}`, `{"none", "citations"}` or `{"escalate"}`. The
precedent step and the specification check are not scored: the ruler is
handed no issue history to find a precedent in, and no specification.
