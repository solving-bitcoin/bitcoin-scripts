# Checked fixed-symbol u4 occurrence count

`arithmetic::u4::count::u4_nibbles_count` consumes a batch of checked u4
nibbles and returns the number of occurrences of one generation-time target
nibble. The result is a numeric ScriptNum in `0..=n`; the target is public
locking-script data.

## Boundary and comparison

Every hostile input is range-checked before the equality scans. The target is
validated at script-generation time and must be in `0..=15`. The operation
preserves unrelated lower main-stack and alt-stack state and consumes only the
input batch.

The representative configuration counts target `0` across 16 canonical
one-byte witness nibbles. It includes all range checks, equality tests,
Boolean-to-count additions, and input cleanup; it excludes input pushes, the
terminal predicate, unrelated live state, and transaction context. No hints
are required.

Evidence is `locally-reproduced`; execution is `unclassified`. The strict local
executor enforces the combined 1,000-item stack limit. No Bitcoin Core
consensus or relay-policy validation is claimed.

This is a fixed-alphabet counting primitive, not a packed histogram or a
duplicate detector by itself. Callers can compare the count to zero, one, or a
protocol-specific bound.

## Reproduction

```sh
cargo test --locked arithmetic::u4::count::tests --lib
cargo test --locked --test primitive_metrics u4_symbol_count_metrics_are_current -- --exact
python3 tools/kb.py validate
```
