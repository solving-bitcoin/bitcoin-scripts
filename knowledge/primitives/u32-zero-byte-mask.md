# Checked u32 zero-byte mask

## Question

Can a byte-oriented u32 fragment preserve which individual byte limbs are zero
without a lookup table, instead of collapsing the word to one aggregate zero
predicate?

## Construction

`u32_to_zero_byte_mask()` consumes
`preserved | byte[0] | byte[1] | byte[2] | byte[3]`, where `byte[0]` is the
most-significant limb and `byte[3]` is on top. It returns `preserved | mask`,
with bit `i` set iff `byte[i] == 0`. Every limb is checked by
`verify_canonical_byte()` before the numeric comparison. The mask is a
script-produced numeric ScriptNum in `0..=15`.

## Evidence and comparison

This result is `locally-reproduced` and `unclassified` for deployment. The
tests cover word-order mapping, main- and altstack preservation, boundary
vectors containing `0`, `1`, `128`, and `255`, invalid numeric values,
negative zero, redundant encodings, and an oversized byte encoding.

The representative boundary uses four canonical `0xff` witness limbs:

| Metric | Result |
| --- | ---: |
| Locking-script bytes | <!-- metric:u32_zero_byte_mask -->67<!-- /metric:u32_zero_byte_mask --> |
| Serialized witness bytes | <!-- metric:u32_zero_byte_mask_witness -->13<!-- /metric:u32_zero_byte_mask_witness --> |
| Combined stack peak | <!-- metric:u32_zero_byte_mask_stack -->8<!-- /metric:u32_zero_byte_mask_stack --> items |
| Static non-push opcodes | <!-- metric:u32_zero_byte_mask_opcodes -->46<!-- /metric:u32_zero_byte_mask_opcodes --> |
| Complete input data items | 4 |
| Incremental hint items | 0 |
| Output items | 1 |
| Resident table items | 0 |

The existing `u32_iszero()` is 4 bytes and peaks at 4 items with a 5-byte
zero-limb witness, but returns only one aggregate Boolean. The new mask costs
63 additional locking bytes and four additional peak items at this boundary;
that overhead buys four independently addressable zero flags in one stack
item, which is the useful representation for byte-classification consumers.

## Threat model and limitations

Witness-provided byte limbs are hostile. The fragment rejects values outside
`0..=255` and noncanonical ScriptNum encodings before setting mask bits. It
does not provide a cryptographic claim, terminal predicate, or transaction
binding. The strict local tapscript executor does not establish Bitcoin Core
consensus or relay-policy validity.

## Reproduction

```sh
cargo test --locked 'arithmetic::u32::zero_byte_mask::tests' --lib
cargo test --locked --test primitive_metrics u32_zero_byte_mask_metrics_are_current
python3 tools/kb.py validate
```
