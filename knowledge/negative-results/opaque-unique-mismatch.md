# Eager mismatch state rejects a full 500-pair input

Initializing a zero index state before consuming a pair makes the
combined stack peak exceed the 1,000-item limit at width 500. The local
interpreter rejects with `StackSize`. The same eager implementation
accepts a 499-pair control with one mismatch.

The [fused scan](../../src/support/mismatch/README.md) consumes the
first pair before creating the index slot. It accepts the identical
500-pair witness with a measured peak of exactly 1,000. The matched
two-pass equality-mask schedule also fits. This frontier depends on
all `2*n` ordinary inputs coexisting at entry and using zero hints.
Evidence is `locally-reproduced`; execution is `unclassified`.
