# RIPEMD-160

RIPEMD-160 hashing implemented with the byte-oriented u32 Bitcoin Script
primitives. It uses the algorithm's parallel 80-round compression branches
and little-endian message and digest encoding.

## Parameters

- Message length: `0..=511` bytes, fixed at script-generation time. There is
  no default.
- Input representation: one byte-valued stack item per message byte.
- Output representation: 20 byte-valued stack items.

## Script metrics

The metric covers the hashing fragment only. It excludes message pushes and
digest comparison.

| Configuration | Hashing script |
| --- | ---: |
| 32-byte input | <!-- metric:ripemd160_u32_32 -->240223<!-- /metric:ripemd160_u32_32 --> bytes |
| 32-byte input, 8-byte output prefix | <!-- metric:ripemd160_prefix_32_8 -->240251<!-- /metric:ripemd160_prefix_32_8 --> bytes |

This fragment exceeds the repository optimizer's 32 KiB input cutoff and is
reported unoptimized.

Maximum stack depth depends on message length. The implementation uses a
256-item bitwise lookup table, the active 16-word message block, two five-word
branch states, and temporary feed-forward state.

The `ripemd160_prefix(num_bytes, output_bytes)` adapter accepts `1..=20`
leading digest bytes. It keeps the full compression schedule and only routes
the selected output at the terminal boundary. The representative profile uses
a 65-byte witness, a combined peak of
`<!-- metric:ripemd160_prefix_32_8_stack -->406<!-- /metric:ripemd160_prefix_32_8_stack -->`
items, and
`<!-- metric:ripemd160_prefix_32_8_opcodes -->169971<!-- /metric:ripemd160_prefix_32_8_opcodes -->`
static non-push opcodes. These are `research-unlimited` local metrics.

## Security

RIPEMD-160 has a 160-bit output. An ideal 160-bit hash offers 80-bit generic
collision resistance and 160-bit generic preimage and second-preimage
resistance. That collision bound is below modern recommendations, so this
implementation is intended for compatibility with existing constructions such
as Bitcoin's HASH160 rather than as a default for new protocols. An 8-byte
prefix has at most a 32-bit generic collision bound and an ideal 64-bit
preimage bound; it is a result-shape adapter, not a cheaper compressor.

## Script compatibility and standardness

The generated script uses the repository's arithmetic opcode vocabulary, but
is far larger and more operation-heavy than ordinary standard output scripts.
Treat it as a tapscript research fragment. Bare, P2SH, and P2WSH deployment is
generally unsuitable because of consensus or policy limits; tapscript use can
also require a non-standard execution environment. See
[`docs/script-types.md`](../../../docs/script-types.md) and
[`docs/standardness.md`](../../../docs/standardness.md).

## Witness and hints

No hints are required. The witness places the last message byte deepest and
the first message byte on top, with every item canonically representing a
value in `0..=255`.

The representative prefix witness is
`<!-- metric:ripemd160_prefix_32_8_witness -->65<!-- /metric:ripemd160_prefix_32_8_witness -->`
bytes for 32 one-byte items.

## Stack contract

`ripemd160(num_bytes)` consumes exactly `num_bytes` main-stack items and leaves
the 20 digest bytes on the main stack with the first digest byte on top. The
temporary lookup table, branch states, and message block are removed, and the
altstack is restored to its starting depth.

## Operational notes

Padding and the 64-bit bit length use RIPEMD-160's little-endian encoding. The
supported range keeps the high length word zero. Tests cover all five Boolean
round functions and reference digests for empty, single-block,
padding-boundary, two-block, and three-block messages.
