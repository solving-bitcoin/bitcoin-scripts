# Uniform circular step limits and counterexamples

The centered representation costs one extra leaf byte for a single
edge. At width two it uses 35 bytes versus 34 for the direct minimum,
and both execute 25 non-push operations at a five-item peak. Both use
five serialized data-witness bytes and zero hints. Width four and the
larger measured widths amortize the final conversion.

Direct equality of modular forward differences rejects valid direction
changes. The walk `[14, 1, 14]` has modular forward steps 3 and 13 but
two Lee distances of 3. Conversely, equality of the total edge distance
does not prove uniformity. `[0, 3, 6]` and `[0, 2, 6]` both have total
distance 6, but the latter has edge distances 2 and 4 and fails the
uniform leaf. Checking the closing edge is a separate relation.

The combined peak is `n + 3` plus preserved caller items, so the
width-997 standalone boundary has no caller headroom. A composed
width-995 fixture preserves two items and rejects with a third.
See the [fixture and reproduction](../../src/arithmetic/u4/lee_step/README.md).
Evidence is `locally-reproduced` and execution is `unclassified`.
