# Checked u4 embedded-threshold mask

`arithmetic::u4::threshold::u4_nibbles_to_lt_mask` consumes a contiguous batch
of canonical u4 nibbles and replaces each item with the numeric Boolean for
`nibble < threshold`. The threshold is embedded public locking-script data, so
repeated uses do not add threshold witness items.

## Boundary and comparison

Every hostile nibble is range-checked before comparison. Generation rejects a
non-u4 threshold, an empty batch, and a batch over the standalone strict-stack
ceiling. The fragment preserves unrelated lower main-stack and alt-stack state
and returns one mask item per input in the original order.

The numeric range check does not enforce byte-unique ScriptNum encoding. A
caller that needs canonical witness bytes must compose the existing
`verify_canonical_nibble()` boundary before this mask.

The representative configuration uses threshold `5` over 16 canonical
one-byte witness nibbles. It includes range checks, comparisons, and output
restoration; it excludes input pushes, the terminal predicate, unrelated live
state, and transaction context. No hints are required.

Evidence is `locally-reproduced`; execution is `unclassified`. The strict local
executor enforces the combined 1,000-item stack limit. No Bitcoin Core
consensus or relay-policy validation is claimed.

This is a per-nibble range-bucketing mask, not a count or complete histogram.
Callers can feed the Boolean outputs to existing accumulators or use them as
selectors for a threshold-defined subset.

## Reproduction

```sh
cargo test --locked arithmetic::u4::threshold::tests --lib
cargo test --locked --test primitive_metrics u4_lt_mask_metrics_are_current -- --exact
python3 tools/kb.py validate
```
