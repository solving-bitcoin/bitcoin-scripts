# Checked u4 packed zero-bitmask projection

## Question

Can checked u4 zero predicates be packed into byte-oriented ScriptNums so a
caller gets eight predicates in one stack item, while keeping witness inputs
canonical and avoiding a lookup table?

## Construction

`u4_nibbles_to_zero_bitmasks(n)` consumes a multiple of eight canonical
nibbles, grouped in input order, and returns one numeric mask per group. Bit
`i` of each mask is set exactly when the `i`th nibble in that group is zero.
The implementation processes each group from the top of the stack, doubles an
accumulator, and adds the checked zero predicate; intermediate masks use the
altstack only to restore group order.

The public batch accepts complete groups from `8..=992`. The strict local peak
is the complete input batch plus four local items, so the maximum is lowered
from the arithmetic bound of 996 to the largest multiple of eight. Callers
must reduce it further for unrelated live main- or altstack state.

## Evidence and comparison

This result is `locally-reproduced` and `unclassified` for deployment. Tests
cover group/output order, preservation of unrelated state, all canonical nibble
values, invalid numeric values, negative zero, redundant ScriptNum encodings,
out-of-range values, incomplete batches, and the batch bound.

The representative boundary is 32 canonical `0x0f` witness nibbles and four
packed outputs:

| Metric | Result |
| --- | ---: |
| Locking-script bytes | <!-- metric:u4_zero_bitmask_batch32 -->482<!-- /metric:u4_zero_bitmask_batch32 --> |
| Serialized witness bytes | <!-- metric:u4_zero_bitmask_batch32_witness -->65<!-- /metric:u4_zero_bitmask_batch32_witness --> |
| Combined stack peak | <!-- metric:u4_zero_bitmask_batch32_stack -->36<!-- /metric:u4_zero_bitmask_batch32_stack --> items |
| Static non-push opcodes | <!-- metric:u4_zero_bitmask_batch32_opcodes -->382<!-- /metric:u4_zero_bitmask_batch32_opcodes --> |
| Complete input data items | 32 |
| Incremental hint items | 0 |
| Output items | 4 |
| Resident table items | 0 |

The closest existing checked parity and LSB projections cost 440 bytes and
peak at 50 items for the same 32-input witness, but leave 32 one-bit output
items and retain a 16-item lookup table. The packed variant costs 42 additional
bytes while reducing the output representation to four byte masks and the
combined peak by 14 items. It is intended for byte-oriented consumers; the
extra arithmetic is not a win when individual bit outputs are already needed.

## Threat model and limitations

Witness-provided nibbles are hostile. Every input is checked for canonical
ScriptNum encoding and numeric range `0..=15` before it contributes to the
mask. The output is a script-produced numeric byte, not a cryptographic
commitment or terminal predicate. The local strict tapscript executor does not
establish Bitcoin Core consensus or relay-policy validity.

## Reproduction

```sh
cargo test --locked 'arithmetic::u4::zero_bitmask::tests' --lib
cargo test --locked --test primitive_metrics u4_zero_bitmask_metrics_are_current
python3 tools/kb.py validate
```
