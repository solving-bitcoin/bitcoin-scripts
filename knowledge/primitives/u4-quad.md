# Checked u4 quad-to-u16 packing

`arithmetic::u4::stack::u4_quad_to_u16(true)` consumes four stack nibbles
`high | high_middle | low_middle | low` and returns the numeric ScriptNum
`4096*high + 256*high_middle + 16*low_middle + low`. The checked and unchecked
forms share one base-16 accumulation schedule.

## Boundary and comparison

Checked mode validates all four hostile inputs in `0..=15` before arithmetic
and preserves unrelated lower main-stack and alt-stack state. The result is in
`0..=65535`, so it fits a 16-bit ScriptNum but is not a byte-oriented witness
item. Numeric range checks do not establish byte-unique canonical encoding.

The representative checked configuration packs `0xf | 0xf | 0xf | 0xf` and
includes four range checks plus the base-16 accumulation. It excludes input
pushes, witness serialization, terminal predicates, unrelated live state, and
transaction context. No hints are required.

Compared with the pair-to-byte bridge, the quad packs two additional radix-16
limbs and returns a 16-bit value directly, avoiding intermediate byte-oriented
state when a consumer already uses a numeric word.

Evidence is `locally-reproduced`; execution is `unclassified`. No Bitcoin Core
consensus or relay-policy validation is claimed.

## Reproduction

```sh
cargo test --locked arithmetic::u4::stack::tests::checked_quad --lib
cargo test --locked --test primitive_metrics u4_quad_to_u16_metrics_are_current -- --exact
python3 tools/kb.py validate
```
