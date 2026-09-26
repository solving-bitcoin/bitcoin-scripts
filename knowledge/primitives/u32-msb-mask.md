# Checked u32 byte high-bit mask

## Research question

Can a checked byte-oriented u32 expose the high bit of every byte as one
packed routing value without materializing all 32 bit lanes or using a lookup
table? The comparison objective is a compact lane selector for byte-sliced
arithmetic and range logic.

## Semantics and boundary

`arithmetic::u32::msb_mask::u32_msb_mask()` consumes one u32 word in the
repository's most-significant-byte-first representation and returns:

```text
mask = 8*msb(byte[0]) + 4*msb(byte[1])
     + 2*msb(byte[2]) + msb(byte[3])
```

Bit 3 describes the most-significant byte and bit 0 the least-significant
byte. Every input is a minimally encoded ScriptNum in `0..=255`. The fragment
consumes the word and returns one numeric ScriptNum in `0..=15`; it does not
provide a terminal predicate or clean-stack policy.

The threat model treats each witness byte and its raw encoding as hostile.
Canonical range checks run before bit extraction. There are no hints and no
cryptographic security claim.

## Evidence and cost

The result is `locally-reproduced` by boundary coverage, deterministic random
words, malformed numeric values, noncanonical zero encodings, and strict local
tapscript execution.

| Configuration | Script | Witness | Data items | Hint items | Combined peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| one checked u32 word, four `0x42` limbs | 133 bytes | 9 bytes | 4 | 0 | 8 | 92 |
| maximum canonical byte witness (`0xff` in every limb) | 133 bytes | 13 bytes | 4 | 0 | — | 92 |

The local executor does not provide a useful dynamic opcode count for this
fragment, so the table records static non-push operations separately. The
execution class is `unclassified`: no complete Bitcoin Core consensus or
relay-policy transaction has been tested.

## Closest comparison

`u32_to_le_bits()` costs 514 bytes and expands the same four checked bytes to
32 stack items. This primitive costs 133 bytes and returns only the four high
bits needed by a lane predicate. Its output is a packed numeric mask, so a
caller that needs all bit lanes should keep the full splitter instead.

The implementation uses the existing canonical-byte validator and one-bit
extractor, moves the word through the altstack, and packs the extracted bits
with a four-step doubling schedule. Temporary altstack entries are restored;
unrelated main- and altstack state is preserved.

## Reproduction

```sh
cargo test --locked msb_mask --lib
cargo test --locked --test primitive_metrics u32_msb_mask_metrics_are_current
python3 tools/kb.py validate
```
