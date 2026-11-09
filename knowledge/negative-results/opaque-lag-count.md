# Initializing the lag count early loses a stack slot

At width 999, the eager destructive schedule starts by pushing a zero
count, bringing the combined stack to 1,000 before copying a pair
member. Its first pick depth then exceeds the limit. The matched
nondestructive schedule also fails. The local interpreter returns
`StackSize` for both. At width 998, eager destructive counting
still fits at 1,000, while copying both operands already fails.

The [deferred schedule](../../src/support/lag_count/README.md) creates
the count from the first comparison, after removing the later operand.
It accepts the same 999-input fixture with peak 1,000. All 999 items
are ordinary data and zero are hints. See the
[matched comparison](../comparisons/opaque-lag-count.md).
Evidence is `locally-reproduced`; execution is `unclassified`.
