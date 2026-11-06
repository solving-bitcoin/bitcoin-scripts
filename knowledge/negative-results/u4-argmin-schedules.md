# Argmin scheduling losses and boundaries

A 16-entry table is dominated at width four on the matched fixture. Its
complete leaf costs 162 script bytes, 77 executed non-push operations and
24 peak stack items. The two-register reverse scan uses 95 bytes, 64
operations and nine items. Both have seven serialized data-witness bytes,
four ordinary items and zero hints. Even the packed-shift baseline uses
125 bytes, 75 operations and eight peak items at this width.

At width 128 the packed-shift baseline's seven constant doublings per input
increase the cost to 3,764 leaf bytes and 3,091 executed non-push operations,
versus 2,540 and 1,565 for the table. It saves 16 peak items, so it remains
relevant under a stack budget. The table cannot compose beyond
`n + 20 + preserved_items <= 1000`; width 978 with three preserved items
fails the local stack check.

A minimum-only scan or an unordered histogram cannot bind the tie index.
For example, `[7, 0, 4, 0]` and `[0, 7, 4, 0]` have the same histogram and
minimum but earliest indices 1 and 0. The focused test rejects a claim of
index 3 for the first vector even though the item at index 3 is minimal.

The [matched fixture](../../src/arithmetic/u4/argmin/README.md#script-metrics)
includes canonical checks, setup, cleanup, and output equality on both sides.
Evidence is `locally-reproduced`; execution is `unclassified`.
