# Recomputing stable split depth uses another live stack item

A forward split can keep the current false count and derive roll depth
by adding the remaining pair width before each roll. It gives the same
results as maintaining the live cursor for every tested short mask.
At 499 pairs, all 998 ordinary witness items coexist. The false-count
register and the copied count reach 1,000, and pushing the fixed width
requires item 1,001. The stack-limited local interpreter rejects with
`StackSize`. The cursor schedule reaches 1,000 and accepts the same
499-pair witness with both groups checked.

The [matched comparison](../comparisons/stack-bipartition.md)
gives successful cost rows at smaller widths. Evidence is
`locally-reproduced` and execution is `unclassified`.
