# Checked u4 triplet-to-u12 packing

`arithmetic::u4::stack::u4_triplet_to_u12(true)` consumes three stack nibbles
`high | middle | low` and returns the numeric ScriptNum
`256*high + 16*middle + low`. The unchecked form is available for callers that
already hold certified nibble values.

## Boundary and comparison

Checked mode validates all three hostile inputs in `0..=15` before arithmetic;
it preserves unrelated lower main-stack and alt-stack state. The result is in
`0..=4095`, so it fits a 12-bit ScriptNum but is not a byte-oriented witness
item. Canonical byte encoding is not established by numeric range checks alone;
callers needing that property must use the repository's canonical boundary.

The representative checked configuration packs `0xf | 0xf | 0xf` and includes
three range checks plus the Horner-style base-16 accumulation. It excludes input
pushes, witness serialization, terminal predicates, unrelated live state, and
transaction context. No hints are required.

Compared with the existing checked pair-to-byte adapter, this is the same
representation bridge extended by one radix-16 limb: it consumes one extra
witness item and returns a 12-bit value without an intermediate byte split.

Evidence is `locally-reproduced`; execution is `unclassified`. No Bitcoin Core
consensus or relay-policy validation is claimed.

## Reproduction

```sh
cargo test --locked arithmetic::u4::stack::tests::checked_triplet --lib
cargo test --locked arithmetic::u4::stack::tests::unchecked_triplet --lib
cargo test --locked --test primitive_metrics u4_triplet_to_u12_metrics_are_current -- --exact
python3 tools/kb.py validate
```
