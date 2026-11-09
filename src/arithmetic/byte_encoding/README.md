# Canonical numeric byte to one raw byte

`arithmetic::byte_encoding::numeric_to_raw_byte()` replaces one
canonical nonnegative byte-valued ScriptNum with its exact one-byte
vector. All witness data are hostile. The output is a byte item rather
than a number, so `00` and `80` are both one-byte vectors.

## Parameters

There are no generation-time parameters. The checked numeric input
range is `0..=255`.

## Script metrics

| Byte | Schedule | Hash-checking leaf bytes | Data witness bytes | Ordinary items | Hint items | Combined peak | Executed non-push ops |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `0x00` | Sign-magnitude | <!-- metric:raw_byte_sign_zero_script -->72<!-- /metric:raw_byte_sign_zero_script --> | <!-- metric:raw_byte_sign_zero_witness -->2<!-- /metric:raw_byte_sign_zero_witness --> | 1 | 0 (none) | <!-- metric:raw_byte_sign_zero_stack -->4<!-- /metric:raw_byte_sign_zero_stack --> | <!-- metric:raw_byte_sign_zero_executed -->20<!-- /metric:raw_byte_sign_zero_executed --> |
| `0x00` | High-half table | <!-- metric:raw_byte_table_zero_script -->391<!-- /metric:raw_byte_table_zero_script --> | <!-- metric:raw_byte_table_zero_witness -->2<!-- /metric:raw_byte_table_zero_witness --> | 1 | 0 (none) | <!-- metric:raw_byte_table_zero_stack -->4<!-- /metric:raw_byte_table_zero_stack --> | <!-- metric:raw_byte_table_zero_executed -->19<!-- /metric:raw_byte_table_zero_executed --> |
| `0xc8` | Sign-magnitude | <!-- metric:raw_byte_sign_high_script -->72<!-- /metric:raw_byte_sign_high_script --> | <!-- metric:raw_byte_sign_high_witness -->4<!-- /metric:raw_byte_sign_high_witness --> | 1 | 0 (none) | <!-- metric:raw_byte_sign_high_stack -->4<!-- /metric:raw_byte_sign_high_stack --> | <!-- metric:raw_byte_sign_high_executed -->22<!-- /metric:raw_byte_sign_high_executed --> |
| `0xc8` | High-half table | <!-- metric:raw_byte_table_high_script -->391<!-- /metric:raw_byte_table_high_script --> | <!-- metric:raw_byte_table_high_witness -->4<!-- /metric:raw_byte_table_high_witness --> | 1 | 0 (none) | <!-- metric:raw_byte_table_high_stack -->129<!-- /metric:raw_byte_table_high_stack --> | <!-- metric:raw_byte_table_high_executed -->86<!-- /metric:raw_byte_table_high_executed --> |

Both leaves convert the same witness value, compute `OP_SHA256` over the
one-byte result, verify its digest and leave true. The entire artifact
uses optimizer `ALL`. Witness bytes include the item count and length
prefix, excluding script, control block, annex and transaction. The sole
input coexists at entry, and opcode counts include encountered branch
delimiters. No signatures execute.

## Security

The fragment validates the input encoding and materializes one exact byte.
The application supplies any digest or identity binding. There is no
one-time key or cryptographic security parameter.

## Script compatibility and standardness

Bare, P2SH and P2WSH complete execution is unclassified. The measured
profile is local tapscript `Consensus` with MINIMALIF and stack limits,
numeric minimality and experimental OP_CAT disabled and a synthetic
transaction. Both valid and malformed fixtures are also covered by the
documented local tests. Evidence is `locally-reproduced` and execution
is `unclassified`. See [script types](../../../docs/script-types.md)
and [standardness](../../../docs/standardness.md).

## Witness and hints

Supply one canonical nonnegative ScriptNum. Values from 128 through 255
have a sign pad in the witness. There are zero hint items and hint bytes.
The converted output may be consumed by a byte operation such as hashing.

## Stack contract

`caller | numeric byte -> caller | raw byte`. Altstack is unused by the
sign-magnitude schedule. Peak is four items plus both caller stacks.
Use a terminal predicate suited to the raw output.

## Operational notes and knowledge-base integration

See the [research note](../../../knowledge/primitives/raw-scriptnum-byte.md)
for the comparison, encoding counterexamples and reproduction.
