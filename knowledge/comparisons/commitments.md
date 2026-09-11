# Integer commitments

| Construction | Value mechanism | Script bytes | Witness bytes | Peak items | Main caveat |
| --- | --- | ---: | ---: | ---: | --- |
| Preimage length | `len(preimage)-offset` | 44 | 18–524 | 3 | Range coupled to item size |
| Mixed hash path | 31 authenticated bits | 520 | 78 | 34 | Mixed-hash assumption; wider opcode cost |
| Four-way mixed hash path | 16 authenticated base-4 digits / 31 bits | 453 | 61 | 19 | Tapscript `MINIMALIF` required; non-standard mixed-hash code |
| Lamport 2-bit | Select one of four preimages | 96 | 11 | small | Strictly one-time |

The schemes have different semantics. Preimage length is compact but encodes
the integer indirectly; hash paths scale to more bits; Lamport authenticates a
tiny value with one-time key material. Under the measured 31-bit configuration,
the four-way path saves 67 script bytes, 17 witness bytes, and 15 peak stack
items relative to the binary path. This comparison does not erase its stronger
tapscript-only execution assumption or its non-standard mixed-hash security
assumption.

The mixed-hash rows are unary commitment paths, not binary Merkle proofs. A
standard Merkle branch needs `HASH256(left || right)` and therefore a way to
concatenate two 32-byte stack items; the current opcode set has no enabled
`OP_CAT`. The closest byte-oriented workaround is already 1,060,200 script
bytes for one 64-byte SHA-256 layer before double hashing or routing.
