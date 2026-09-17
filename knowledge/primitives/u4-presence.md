# Checked u4 presence-bit projection

`arithmetic::u4::presence::u4_nibbles_to_presence_bits` consumes a contiguous
batch of numeric u4 nibbles and returns 16 Boolean items. Output item `n` is
one iff nibble `n` occurred in the input. The construction uses only numeric
equality and `OP_BOOLOR`; it does not rely on disabled bitwise opcodes.

## Boundary and comparison

Every hostile input nibble is range-checked before the 16 membership scans.
The input nibbles are consumed, and unrelated lower main-stack and alt-stack
state is preserved. The output is a Boolean vector rather than a packed mask,
which keeps the operation compatible with tapscript's enabled opcode set.

The representative 16-nibble all-`0x0f` boundary uses one-byte canonical
witness items and zero hints. The metric includes all 16 range checks, 256
equality checks, Boolean folds, and output restoration; it excludes input
pushes, terminal predicates, unrelated live state, and transaction context.

Evidence is `locally-reproduced`; execution is `unclassified`. The local
strict executor enforces the combined 1,000-item stack limit. No Bitcoin Core
consensus or relay-policy validation is claimed.

This is a membership projection, not a packed bitmask or a duplicate detector
by itself: callers can compare or combine the returned bits according to their
protocol's boundary.

## Reproduction

```sh
cargo test --locked arithmetic::u4::presence::tests --lib
cargo test --locked --test primitive_metrics u4_presence_bits_metrics_are_current -- --exact
python3 tools/kb.py validate
```
