# Checked u4 embedded-cap clamp

`arithmetic::u4::clamp::u4_nibbles_to_clamp` consumes a contiguous batch of
canonical u4 nibbles and replaces each item with `min(nibble, maximum)`. The
cap is embedded public locking-script data, so it adds no repeated witness
items.

## Boundary and comparison

Every hostile nibble is range-checked before the cap comparison. Generation
rejects a non-u4 cap, an empty batch, and a batch over the standalone
strict-stack ceiling. The fragment preserves unrelated lower main-stack and
alt-stack state and returns values in the original order.

The numeric range check does not enforce byte-unique ScriptNum encoding. A
caller that needs canonical witness bytes must compose the existing
`verify_canonical_nibble()` boundary before this clamp.

The representative configuration uses cap `4` over 16 canonical one-byte
witness nibbles. It includes range checks, cap comparisons, replacement, and
output restoration; it excludes input pushes, the terminal predicate,
unrelated live state, and transaction context. No hints are required.

Unlike the threshold masks and trichotomy classifier, this construction
returns normalized bounded digits. It is useful before a fixed-domain lookup
when out-of-range values should collapse to one public endpoint, but it does
not by itself prove that such collapsing is protocol-safe.

Evidence is `locally-reproduced`; execution is `unclassified`. The strict local
executor enforces the combined 1,000-item stack limit. No Bitcoin Core
consensus or relay-policy validation is claimed.

## Reproduction

```sh
cargo test --locked arithmetic::u4::clamp::tests --lib
cargo test --locked --test primitive_metrics u4_clamp_metrics_are_current -- --exact
python3 tools/kb.py validate
```
