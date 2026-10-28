---
name: design-ruling
description: Answer the open questions in a repository's design issues from the uphold records that repository adopts under [decide], citing each record line at the pinned uphold revision with a quote, or escalate. Use when asked to rule on, answer or decide a design record's questions.
---

# Design ruling

A ruling answers one question in a design issue from the records the
repository adopts, and from nothing else. The owner reviews which records are
adopted and the order between two that conflict; everything else in a ruling
must be traceable to them.

## 1. Read what the repository rules by

Run `uphold check --json` from the repository root and read `decide`:

- `adopt` is the record ids the repository answers design questions from.
  An entry may be a table `{id, why}` instead of an id. Its `why` is the
  repository's reason for adopting the record: context for reading the
  record's scope, never a citation, and never a ground for an answer.
- `order` is one `{prefer, over, why}` per adopted pair that conflicts.

If `uphold check` exits 1 with `design rulings refused ([decide])`, escalate
every question: an adopted conflict with no order has two answers.

Find the uphold revision the repository pins: the `rev:` of the
`HackingGate/uphold` entry in `.pre-commit-config.yaml`, or the `ref:` of that
remote in `lefthook.yml`. Read each adopted record as
`principles/<id>.toml` at that revision, with `uphold --version` matching it.
A different binary carries a different catalog, and its line numbers are not
the ones the citations will be checked against.

## 2. Rule on each question

For each question under the issue's questions heading:

1. Strip any "(recommended)" from the options and read them in no particular
   order. Which option the proposer prefers is not evidence.
2. Find the adopted records whose `applies_when` holds for the question. None
   applies: escalate, saying which part of the question no record covers.
3. Where two applicable records conflict, the `order` between them decides.
   No order for that pair: escalate.
4. Pick the option the applicable records decide. Cite every record line the
   decision rests on: a `claim`, an `applies_when`, a `does_not_mean`, a
   `review_questions` item. Where a record's source decides it, cite the
   source's `locator` or URL fragment too.
5. Where no option meets the goal the records state, answer that none does,
   and cite the line that states the goal.
6. Name the closest ruled precedent: an earlier design issue labelled
   `ruling:accepted` whose `Answered:` line cites the same record lines. None:
   say so.

Run the ruling three times, independently, with the options in a different
order each time. All three must give the same answer, or escalate and say they
did not.

## 3. Write the answer

Under the question, on its own line:

```text
Answered: (a). [<id> L<n>](https://github.com/HackingGate/uphold/blob/<pinned rev>/principles/<id>.toml#L<n>) "<the item, exactly as on that line>"; precedent: <issue link, or none>
```

Or, to escalate:

```text
Answered: escalated -- <reason>
```

The link's revision is the pin, never `main`. The quote follows its link and is
copied from that line, because `ruling-citations-resolve` refuses the body when
the line at that revision does not contain it. Publish with `gh issue edit` or
`gh issue create` so that check runs. Do not change the issue's `ruling:` label:
the owner records the ruling.

## 4. Score the answer and its citations

`uphold_check.py --review --drive --rule -- <ruler>` asks a ruler each
`[[review.ruling]]` control in `policy/upheld.toml` and scores it; see
docs/REFERENCE.md, "Ruling controls". The ruler reads
`{"document", "question", "options"}` on stdin and prints
`{"answer", "citations"}`, `{"none", "citations"}` or `{"escalate"}`. The
precedent step is not scored: the ruler is handed no issue history to find one
in.
