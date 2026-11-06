# Commitments and opening relations

## Integer commitments

| Construction | Value mechanism | Script bytes | Witness bytes | Peak items | Main caveat |
| --- | --- | ---: | ---: | ---: | --- |
| Preimage length | `len(preimage)-offset` | 44 | 18–524 | 3 | Range coupled to item size |
| Mixed hash path | 31 authenticated bits | 457 | 78 | 33 | Starting preimage must be independently bound; mixed-hash assumption |
| Mixed hash path, retained bits | 31 authenticated bits retained on altstack | 302 | 78 | 33 | Retained bits are normalized; starting preimage must still be bound |
| Four-way mixed hash path | 16 authenticated base-4 digits / 31 bits | 438 | 61 | 19 | Tapscript `MINIMALIF` required; non-standard mixed-hash code |
| Four-way path, retained digits | 16 raw digits retained on altstack | 360 | 61 | 20 | Retained bytes are caller-bound; tapscript `MINIMALIF` required |
| Ternary mixed hash path | 20 authenticated base-3 trits / 31 bits | 947 | 63 | 24 | Native ternary state encoding; dominated by the four-way path |
| TapBranch u4 hash | BIP341 tagged hash over two ordered nodes | <!-- metric:tapbranch_hash_u4 -->1106723<!-- /metric:tapbranch_hash_u4 --> | <!-- metric:tapbranch_hash_u4_witness -->161<!-- /metric:tapbranch_hash_u4_witness --> | <!-- metric:tapbranch_hash_u4_stack -->969<!-- /metric:tapbranch_hash_u4_stack --> | Unclassified; above standard transaction-weight policy |
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
Historical binary/four-way integer metrics are `locally-reproduced`,
`research-unlimited` tapscript runs with the stack check disabled. Retained-bit
and retained-digit rows use strict local stack checks and remain `unclassified`.
All exclude input pushes and terminal checks.

The ternary path is not a byte-efficiency improvement for this integer target:
it uses 21 data items (zero hints) versus 17 for the four-way path and is 509
bytes larger (NR-072). It is retained as a different representation point for
protocols whose state is naturally three-valued (OP-030). It performs explicit
trit canonicality and integer-width checks instead of relying on tapscript
`MINIMALIF`; its row uses strict local stack checks, is `locally-reproduced`,
and remains `unclassified`.

The preimage-length boundary is 42 bytes with one empty witness item at offset
0 and 46 bytes with one 520-byte item at offset 520. The latter is a consensus
stack-element boundary, not a relay-policy claim. HORS index serialization
crosses from a 36-byte witness at index 127 to 37 bytes at index 128 for
`n=129,t=1`; its verifier clamps index 129 rather than enforcing the encoded
index verbatim.

Taproot Merkle branches are intentionally absent from this cost table. The
native-byte adapter search is an inspected negative result: current Script
cannot bind two hostile 32-byte nodes into the tagged `TapBranch` SHA256
preimage without an enabled concatenation/splitting operation. See
[NR-057](../negative-results/index.md#nr-057-native-taproot-merkle-branch-adapter-is-not-available)
and [OP-021](../open-problems.md#op-021--taproot-merkle-path-verifier).

The TapBranch row is a fixed-prefix u4 boundary measurement. Tapscript removes
the legacy 10,000-byte and 201-opcode limits, but the measured script is above
standard transaction-weight policy and has not been validated as a complete
spend. Its node ordering is a caller precondition.

Ordinary `HASH256(left || right)` Merkle composition is a separate negative
result. The current byte-oriented SHA-256 backend measures one 64-byte layer
at 1,060,200 unoptimized script bytes and 770,481 static non-push opcodes,
with a 129-byte one-byte fixture witness or 193-byte canonical maximum for 64
data items and zero hints. This is a backend-specific compile-only profile,
not a universal lower bound or a complete branch verifier; see [NR-066](../negative-results/merkle-branch-composition.md).

## Two distinct SHA-256 openings

The [two-opening comparison](../primitives/sha256-pair-pool.md) measures
complete leaves with the same unique digest list and the same two
32-byte preimages. Each row executes two native SHA-256 operations.
Both selectors coexist with the preimages at entry in the hinted rows.
The scan takes only the two preimages.

| Pool | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items | Hint bytes | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 32 | Destructive ranks | 1112 | 71 | 2 | 2 | 4 | 39 | 39 |
| 32 | Fixed indices | 1119 | 71 | 2 | 2 | 4 | 39 | 46 |
| 32 | Scan | 1388 | 67 | 2 | 0 | 0 | 6 | 265 |
| 129 | Destructive ranks | 4368 | 71 | 2 | 2 | 4 | 136 | 88 |
| 129 | Fixed indices | 4375 | 72 | 2 | 2 | 5 | 136 | 95 |
| 129 | Scan | 5559 | 67 | 2 | 0 | 0 | 6 | 1041 |

Leaf bytes include setup, both checks, cleanup, and terminal true. Witness
bytes include only serialized data and selectors. The scan saves live
stack state and witness bytes. Removing the first selected slot eliminates
an explicit inequality and maps original slot 128 to rank 127 for the
width-129 fixture. The [checked markers](../../src/commitments/sha256_pool/README.md#script-metrics)
include width three and the unoptimized width-993 frontier.
