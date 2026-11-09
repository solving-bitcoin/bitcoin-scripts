# Uniform circular step over canonical nibbles

Can Script check every edge of a nibble walk for a common circular
distance while evaluating the actual distance only once? The hypothesis
is that comparing a centered representation of the distance saves
per-edge arithmetic against a direct minimum. Compare identical
canonical guards, reverse scans, input witnesses, and output checks.

## Construction

The [Lee metric](https://doi.org/10.1109/TIT.1958.1057446) measures
shortest distances on a modular alphabet. The one-symbol weight is
given in [Alderson and Huntemann, section 2.1](https://onlinelibrary.wiley.com/doi/10.1155/2013/625912).
For nibble values `x` and `y`, write `a = abs(x - y)`. Their Lee
distance is `min(a, 16-a) = 8 - abs(a-8)`. Since `d -> 8-d` is
one-to-one on `0..=8`, the scan compares the centered magnitude
`abs(a-8)` at every edge and converts it back once after the fold.

The existing [adjacent delta](u4-adjacent-delta.md) emits directed
residues and does not require the edge distances to agree. [PR #270](https://github.com/solving-bitcoin/bitcoin-scripts/pull/270),
revision `5c0c718249a201fdc97efc049d95f94fc8092354`, sums pointwise Lee
distances between two vectors. That work shares the direct per-edge
kernel. The local matched baseline uses the direct kernel inside the
same one-vector uniformity scan and returns the same common distance.

## Evidence and limits

At width 128 the centered leaf uses 2,681 bytes and 2,167 executed
non-push operations. The direct leaf uses 2,932 bytes and 2,419
operations. Both use a 248-byte serialized data witness, 128 ordinary
items, zero hints, and a 131-item combined peak. The width-two direct
leaf is one byte smaller, with identical executed counts. See
[all matched rows](../../src/arithmetic/u4/lee_step/README.md) and
[relation and composition limits](../negative-results/u4-lee-step.md).

Evidence is `locally-reproduced`; execution is `unclassified`.
The scan permits direction changes and ignores a closing edge from last
to first. It does not bind a particular walk or its orientation.
