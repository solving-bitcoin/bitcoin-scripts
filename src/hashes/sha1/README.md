# SHA-1

SHA-1 hashing implemented with the byte-oriented u32 Bitcoin Script
primitives. This module exists for compatibility and research; SHA-1 is not
suitable for new collision-resistant constructions.

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
| 32-byte input | <!-- metric:sha1_u32_32 -->209726<!-- /metric:sha1_u32_32 --> bytes |

This fragment exceeds the repository optimizer's 32 KiB input cutoff and is
reported unoptimized.

Maximum stack depth depends on the message length. The implementation uses a
256-item bitwise lookup table and expands each active block to 80 u32 words;
some inputs exceed the default 1,000-item combined stack limit.

## Security

SHA-1 has a 160-bit output. An ideal 160-bit hash would offer 80-bit generic
collision resistance and 160-bit generic preimage and second-preimage
resistance, but practical SHA-1 collision attacks invalidate the collision
bound. Do not use it where collision resistance, signatures over
attacker-chosen content, or a modern security margin is required.

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

## Stack contract

`sha1(num_bytes)` consumes exactly `num_bytes` main-stack items and leaves the
20 digest bytes on the main stack with the first digest byte on top. The
temporary lookup table and message schedule are removed, and the altstack is
restored to its starting depth.

## Operational notes

Padding uses SHA-1's big-endian length encoding with a zero high 32-bit word,
which is sufficient for the supported range. Tests cover standard empty,
single-block, padding-boundary, and multi-block vectors, plus the message
schedule and all three round functions.
