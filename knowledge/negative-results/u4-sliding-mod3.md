# Sliding modulo-three boundaries and collisions

Rolling at width one has no overlap to reuse. For four inputs the rolling
leaf costs 129 bytes and 87 executed non-push operations, compared with
128 bytes and 84 operations for rescanning. Both use the same eight-byte
data witness, zero hints, and 23 peak items. This is the matched comparison
with all validation and output checks included.

A seven-nibble projected sum fits the 16-entry table with upper bound 14.
Extending the existing route to width eight without changing that table or
the first-window reduction would address index 16 for eight projected
twos. The same issue applies to the rescan baseline. Neither handles a
wider window under its stated lookup invariant.

The rolling schedule retains the table and does not reduce the combined
peak compared with rescanning. All inputs coexist at entry. At width 7
and 979 inputs, two preserved items leave a 1,000-item combined peak and
a third item fails the local stack check.

Even all windows together cannot bind the input message. The focused
test accepts eight zeros and eight threes against the same two zero
residue outputs. More generally, replacing any nibble with a different
nibble in its residue class leaves every window residue unchanged.

The [matched fixture](../../src/arithmetic/u4/sliding_mod3/README.md#script-metrics)
documents the boundaries. Evidence is `locally-reproduced` and execution
is `unclassified`.
