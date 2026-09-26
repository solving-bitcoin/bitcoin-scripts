# Checked u4 zero-mask projection

## Question

Can hostile canonical u4 nibbles be projected to one numeric zero predicate
each without retaining the 16-item lookup table used by the parity and LSB
projections?

## Construction

`u4_nibbles_to_zero_mask(n)` consumes
`preserved | nibble[0] | ... | nibble[n-1]` and returns the same preserved
prefix followed by one numeric `nibble == 0` result per input, with the last
result on top. Each input is checked with `verify_canonical_nibble()` before
`OP_NUMEQUAL`; no lookup table or auxiliary hint is used.

The standalone generator accepts `1..=997` inputs. The bound follows the
strict combined stack limit: the batch contributes `n` restored outputs and
the canonical check needs three temporary stack items at its peak. Callers
must lower the batch when unrelated main- or alt-stack state is live.

## Evidence and comparison

This result is `locally-reproduced` and `unclassified` for deployment. The
focused tests cover output order, invalid numeric inputs, noncanonical raw
ScriptNum encodings, and a composed strict-stack run.

The representative boundary is a 32-nibble fragment with 32 canonical
`0x0f` witness items:

| Metric | Result |
| --- | ---: |
| Locking-script bytes | <!-- metric:u4_zero_mask_batch32 -->414<!-- /metric:u4_zero_mask_batch32 --> |
| Serialized witness bytes | <!-- metric:u4_zero_mask_batch32_witness -->65<!-- /metric:u4_zero_mask_batch32_witness --> |
| Combined stack peak | <!-- metric:u4_zero_mask_batch32_stack -->35<!-- /metric:u4_zero_mask_batch32_stack --> items |
| Static non-push opcodes | <!-- metric:u4_zero_mask_batch32_opcodes -->318<!-- /metric:u4_zero_mask_batch32_opcodes --> |
| Incremental hint items | 0 |
| Resident table items | 0 |

At the same witness and output boundary, the existing checked parity and LSB
projections are 440 bytes and peak at 50 combined items. The zero-mask result
saves 26 bytes and 15 stack items, but its output is a per-nibble numeric
predicate rather than a packed value or terminal truth value.

## Threat model and limitations

Witness-provided nibbles are hostile. The fragment rejects values outside
`0..=15` and noncanonical ScriptNum encodings before comparing to zero, but it
does not bind the values to a protocol or supply a terminal predicate. The
local strict tapscript executor is not Bitcoin Core validation; consensus and
relay-policy deployment remain unverified.

## Reproduction

```sh
cargo test --locked 'arithmetic::u4::zero::tests' --lib
cargo test --locked --test primitive_metrics u4_zero_mask_metrics_are_current
python3 tools/kb.py validate
```
