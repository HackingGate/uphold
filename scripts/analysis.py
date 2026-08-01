#!/usr/bin/env python3
"""Text analysis for the name index: one written name, one lookup key.

A search engine never compares the string a reader typed against the string a
document holds. Lucene -- and OpenSearch and Elasticsearch over it -- runs both
through the same *analysis chain* first: character filters rewrite the raw text,
a tokenizer cuts it into terms, and token filters fold each term toward the form
every equivalent spelling shares. What is stored is the chain's output, and a
query matches because it went through the identical chain, not because the two
strings happened to be typed the same way.

The catalog needs the small end of that idea. `aliases` and `title` are short
labels, not prose, so the shape that fits is what OpenSearch calls a
*normalizer*: the same folding filters, no tokenizer, exactly one term out.
`normalize()` is that term -- the key that "Fail-Safe Defaults", "fail safe
defaults" and "FAIL-SAFE  DEFAULTS" all have to agree on before any of them can
be said to name the same record. `tokens()` is its split form, which is what a
`match` query with `operator: and` compares when the reader typed a subset of a
name rather than the whole of it.

The chain, in order, and what each step exists to absorb:

1. **NFKC** -- Unicode compatibility composition. Folds the spellings a keyboard
   or a paste produces without meaning to: fullwidth latin, ligatures, the
   several codepoints that render as one character.
2. **casefold** -- the aggressive sibling of `lower()`; folds ``ß`` to ``ss``
   where lowercasing leaves it alone. Lucene spells this `lowercase`.
3. **strip combining marks** -- decompose (NFD) and drop the marks, so `naïve`
   and `naive` share a key. Lucene spells this `asciifolding` / `icu_folding`.
4. **non-alphanumeric to space** -- hyphen, comma, slash, parenthesis, the
   several dashes, and the `|` that would otherwise have to survive a Markdown
   cell all become separators. Deliberately simpler than the UAX#29 segmentation
   the standard tokenizer implements: these are short labels, and a rule a
   consumer can reimplement in ten lines of any language is worth more to a
   published index than exact parity with a tokenizer nobody here is running.
5. **collapse and strip** -- runs of separators become one space, so token
   boundaries are the only whitespace left.

Steps 4 and 5 are also why the generated Markdown stopped being a carrier the
index could be read back from: `build_reference.py` escapes `|` to `\\|` to keep
a row intact, and a consumer parsing that row has to undo an escaping decision
this generator made. The key is computed from the record instead, and the name
as written travels beside it.

`ANALYZER` describes the chain in the generated artifact, so a reader outside
Python can reproduce a key rather than guess at one. Change a step and change
its version: a key computed by an older chain is not comparable to one computed
by this chain, and silence about that is the failure the version exists to make
loud.
"""

from __future__ import annotations

import unicodedata

ANALYZER = {
    "name": "principle-name",
    "version": 1,
    "steps": [
        "unicode-nfkc",
        "casefold",
        "strip-combining-marks",
        "non-alphanumeric-to-space",
        "collapse-whitespace",
    ],
    "token_separator": " ",
}


def normalize(name: str) -> str:
    """Return the lookup key for one written name.

    Two names naming the same thing produce the same key; the key is not
    displayable and is never shown to a reader in place of what the record
    wrote.
    """
    folded = unicodedata.normalize("NFKC", name).casefold()
    decomposed = unicodedata.normalize("NFD", folded)
    stripped = "".join(char for char in decomposed if not unicodedata.combining(char))
    separated = "".join(
        char if char.isalnum() else " "
        for char in unicodedata.normalize("NFC", stripped)
    )
    return " ".join(separated.split())


def tokens(name: str) -> tuple[str, ...]:
    """Return the analyzed terms of one name, in written order."""
    return tuple(normalize(name).split())


def matches(query: str, name_tokens: tuple[str, ...]) -> bool:
    """True when every term the reader typed appears among a name's terms.

    This is `match` with `operator: and`, minus the scoring: a reader who typed
    "combinatorial explosion" finds the record whose alias is exactly that, and
    a reader who typed "least privilege" finds "Principle of least privilege"
    without having to have known the whole of it. Term order is not required --
    it carries no meaning across "Cohesion and coupling" and "coupling,
    cohesion" -- and a query with no terms matches nothing rather than
    everything, because an empty search is a question that was never asked.
    """
    query_tokens = tokens(query)
    if not query_tokens:
        return False
    return set(query_tokens) <= set(name_tokens)
