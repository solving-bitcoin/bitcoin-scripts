# Total matches can overstate the common prefix

Two vectors can agree again after the first mismatch. The contract test
uses two width-four vectors that differ only at position one. Three pairs
match, but the canonical prefix length is one. A checked leaf expecting
the total match count rejects this witness.

The matched forward prefix fold avoids that error with an active bit and
count. At width 128 it costs 1,458 script bytes, a peak of 259 and 897
executed non-push operations. The reverse mismatch schedule costs 1,256
bytes, peaks at 258 and executes 657 operations for the same case. Both
use 771 serialized witness bytes, 256 ordinary items and zero hints.
The forward fold also rejects 499 pairs at the combined-stack limit.
These are `locally-reproduced`, `unclassified` exact local comparisons.
See the [measured boundary and reproduction](../primitives/opaque-common-prefix.md).
