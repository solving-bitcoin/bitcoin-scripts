# Carry-checked distinct nibble set mask

Can Bitcoin Script reject duplicate canonical nibbles and return their exact
compact set without comparing every pair? The hypothesis is that a shared
one-hot fold and a binary weight check will save script bytes and executed
non-push operations at larger widths. Compare with a direct pairwise
schedule using the same input validation, fold, mask, and terminal predicate.

## Construction

Map every nibble `x` to `2^x` and add the results as one ScriptNum. Binary
normalization replaces two equal powers by the next power, losing one
summand per carry. The weight of the canonical sum equals the input count
exactly if no duplicate occurred. With that condition the sum is the set
mask, and canonical input bytes exclude alternate encodings. For a full
16-element set, direct equality to 65,535 suffices. The accumulator fits
within 524,288 even with all inputs equal to 15.

The underlying all-different relation is standard in constraint programming.
See [Régin, AAAI-94](https://cse.unl.edu/~choueiry/Documents/ReginAAAI-1994.pdf).
This Script experiment adds a compact output contract. It reuses the table
from the [one-hot projection](u4-one-hot.md). The existing
[presence bits](u4-presence.md) collapse multiplicities without rejecting
duplicates. The hinted [PR #283](https://github.com/solving-bitcoin/bitcoin-scripts/pull/283)
also emits 16 presence bits and records duplicate detection as follow-up
work at revision `00c7532e697fd258b2c7e6dd36422d1b697196ee`. The pairwise
predicate in [PR #277](https://github.com/solving-bitcoin/bitcoin-scripts/pull/277)
at revision `72d3b13dd949ef395bc61c536c11637d8780bb9b` returns a boolean.
The matched local baseline uses pairwise verification before producing
the same canonical mask, avoiding the cost of a boolean output followed by
a separate encoder. The fixed-composition checker in #277 additionally
requires a public histogram, with an overlapping special case when all 16
nibbles appear once.

## Evidence and limits

At 16 inputs the carry and pairwise mask leaves use 316 versus 1,121 bytes
and 189 versus 787 executed non-push operations. Both use 32 serialized
data-witness bytes, 16 ordinary items, zero hints, and peak at 36 combined
items. At four inputs the pairwise leaf is smaller and executes fewer
operations. At eight inputs the carry leaf executes fewer operations but
uses more bytes. See the [schedule and binding limits](../negative-results/u4-distinct-mask.md)
and [all measured rows](../../src/arithmetic/u4/distinct_mask/README.md).

Evidence is `locally-reproduced` and deployment `unclassified`. All
measured leaves use a strict local tapscript profile with a combined stack
limit. A funded spend and relay policy were outside the experiment. The
mask identifies the unordered set and preserves no input order.
