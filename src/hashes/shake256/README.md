# SHAKE256

This module implements the FIPS 202 SHAKE256 extendable-output function in
Bitcoin Script. `shake256(num_bytes)` preserves the original 1,024-byte output;
`shake256_prefix(num_bytes, output_len)` produces a fixed-length prefix without
materializing the unused suffix.

## Parameters

- Message length: 0 through 511 bytes, fixed when the script is generated; no
  default.
- Output length: `1..=1024` bytes, fixed at script generation time.
- Input: one stack item per byte, first message byte on top.
- Output: 1024 byte-valued stack items, first SHAKE byte on top.
- Sponge rate: 136 bytes; capacity: 512 bits.
- Domain separation: SHAKE suffix `0x1f`, followed by multi-rate padding.

Keccak-f[1600] uses 25 little-endian 64-bit lanes represented as eight byte
items apiece. It shares the byte lookup table used by the u32 XOR and AND
primitives.

## Script metrics

The boundary is `fragment-with-memory:` generated SHAKE256 operation including
lookup-table setup and cleanup; message pushes, output comparison, terminal
predicate, and witness serialization are excluded from the locking-script
size. The witness metric is the complete serialization of 32 one-byte message
items. The peak is combined main and alt stack under the research-unlimited
local executor; the metric harness appends output cleanup and a truthy terminal
predicate after the measured peak so execution can finish successfully.

| Configuration | Locking script | Unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| 32-byte input, 1024-byte output | <!-- metric:shake256_32_1024 -->15927814<!-- /metric:shake256_32_1024 --> bytes | <!-- metric:shake256_witness_32 -->65<!-- /metric:shake256_witness_32 --> bytes | <!-- metric:shake256_stack_32_1024 -->1709<!-- /metric:shake256_stack_32_1024 --> |
| 32-byte input, 32-byte prefix | <!-- metric:shake256_prefix_32_32 -->2000127<!-- /metric:shake256_prefix_32_32 --> bytes | <!-- metric:shake256_prefix_witness_32 -->65<!-- /metric:shake256_prefix_witness_32 --> bytes | <!-- metric:shake256_prefix_stack_32_32 -->813<!-- /metric:shake256_prefix_stack_32_32 --> |

This fragment exceeds the repository optimizer's 32 KiB input cutoff and is
reported unoptimized.

The full-output script reflects eight Keccak-f[1600] permutations for the
fixed output length, in addition to message absorption. A prefix uses only the
permutations needed to cover its requested output blocks.

## Security

SHAKE256 has a 512-bit capacity. For unrestricted output it targets 256-bit
preimage and collision security under the usual sponge and Keccak assumptions.
This primitive only hashes its input; callers must provide
any authentication, domain separation beyond SHAKE's standard suffix, and
terminal output predicate required by their protocol.

## Script compatibility and standardness

The raw 1,024-byte output contains 1,024 stack items and exceeds Bitcoin's
consensus limit of 1,000 combined main- and alt-stack items. The prefix form
avoids this failure for small outputs; the representative 32-byte prefix is
strictly executed below the limit. Larger prefixes still require a measured
stack check after accounting for the live state and lookup table.

The implementation does not rely on disabled opcodes or transaction context,
but the output shape makes the standalone primitive non-standard and
non-consensus-executable under current limits. The 15.9 MB fragment is also
unsuitable for bare script, P2SH, and P2WSH size limits. Tapscript does not make
the raw construction deployable because its 1,709-item measured peak still
violates the combined-stack consensus rule. See
[`docs/script-types.md`](../../../docs/script-types.md) and
[`docs/standardness.md`](../../../docs/standardness.md).

## Witness and hints

The message bytes are the only witness data; no hints are used. The caller must
place the last message byte deepest and the first byte on top. Every item must
represent an integer in `0..=255`; the fragment does not independently reject
non-byte witness values before using them in lookup-table operations.

## Stack contract

`shake256(num_bytes)` consumes exactly `num_bytes` main-stack items and leaves
1,024 output items with byte zero on top. `shake256_prefix(num_bytes,
output_len)` leaves exactly `output_len` items. Both variants remove their
lookup table and 200-byte Keccak state and restore the altstack to its starting
depth.

The fragment does not append an output comparison, clean-stack check, or final
truthy predicate.

## Operational notes

Tests differentially validate all 1,024 output bytes for empty input, `abc`,
and an exact 136-byte rate block, plus prefix lengths crossing the 136-byte
rate boundary. A 32-byte prefix also passes the strict combined-stack check.
These executions use `bitcoin-scriptexec` in a tapscript context; the full
output remains `research-unlimited` and `consensus-incompatible`, while the
small prefix has `unclassified` deployment evidence pending Core validation.
