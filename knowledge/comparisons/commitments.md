# Integer commitments

| Construction | Value mechanism | Script bytes | Witness bytes | Peak items | Main caveat |
| --- | --- | ---: | ---: | ---: | --- |
| Preimage length | `len(preimage)-offset` | 44 | 18–524 | 3 | Range coupled to item size |
| Mixed hash path | 31 authenticated bits | 457 | 78 | 33 | Starting preimage must be independently bound; mixed-hash assumption |
| Four-way mixed hash path | 16 authenticated base-4 digits / 31 bits | 438 | 61 | 19 | Tapscript `MINIMALIF` required; non-standard mixed-hash code |
| Two-round mixed hash chain | 4-bit path → 3-bit path | 80 | 45 | 8 | Independently bind the start and checkpoint order |
| Lamport 2-bit | Select one of four preimages | 96 | 11 | small | Strictly one-time |

The schemes have different semantics. Preimage length is compact but encodes
the integer indirectly; hash paths scale to more bits; Lamport authenticates a
tiny value with one-time key material. Under the measured 31-bit configuration,
the four-way path saves 19 script bytes, 17 witness bytes, and 14 peak stack
items relative to the binary path. This comparison does not erase its stronger
tapscript-only execution assumption or its non-standard mixed-hash security
assumption.

Binary-path numbers use the optional-SHA256 construction; old digests are
incompatible. The 5/7 static opcodes per bit exclude pinning, output comparison
and integer reconstruction. A freely chosen starting preimage permits first-bit
substitution (NR-056). All three measured commitment witnesses use **0 hints**.
Binary/four-way metrics are `locally-reproduced`, `research-unlimited` tapscript
runs with the stack check disabled, excluding input pushes and terminal checks.

Taproot Merkle branches are intentionally absent from this cost table. The
native-byte adapter search is an inspected negative result: current Script
cannot bind two hostile 32-byte nodes into the tagged `TapBranch` SHA256
preimage without an enabled concatenation/splitting operation. See
[NR-057](../negative-results/index.md#nr-057-native-taproot-merkle-branch-adapter-is-not-available)
and [OP-021](../open-problems.md#op-021--taproot-merkle-path-verifier).

Ordinary `HASH256(left || right)` Merkle composition is a separate negative
result. The current byte-oriented SHA-256 backend measures one 64-byte layer
at 1,060,200 unoptimized script bytes and 770,481 static non-push opcodes,
with a 129-byte one-byte fixture witness or 193-byte canonical maximum for 64
data items and zero hints. This is a backend-specific compile-only profile,
not a universal lower bound or a complete branch verifier; see [NR-064](../negative-results/merkle-branch-composition.md).
