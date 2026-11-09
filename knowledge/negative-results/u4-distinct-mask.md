# Carry-check losses and set-mask boundaries

At four inputs the carry check uses 324 script bytes and 140 executed
non-push operations, while the pairwise leaf uses 154 and 85. Both have a
nine-byte serialized data witness, zero hints, and a 24-item combined
peak. The partial-width threshold scan has a fixed cost. At eight inputs,
the carry check uses 24 more bytes but executes 39 fewer operations.
At 16 inputs the direct comparison with the full-domain mask avoids the
threshold scan entirely.

Raw one-hot addition admits carry aliases. The vector `[0, 0, 2]` yields
mask 6, whose set bits are 1 and 2. The weak sum-only wrapper accepts it.
The complete leaf rejects because that mask has weight two and the
witness count is three. `[15, 15]` yields 65,536 and violates the
partial-set mask bound. Reordering a valid set is still permitted, so
the output cannot stand in for an ordered-message commitment.

The 16-entry table is present in both matched schedules and leaves at
most 964 items of caller state at width 16. The additional preserved
item fails at peak 1,001 in the strict local stack check. See
[fixture and reproduction](../../src/arithmetic/u4/distinct_mask/README.md).
Evidence is `locally-reproduced` and execution is `unclassified`.
