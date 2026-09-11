# Integer commitments

| Construction | Value mechanism | Script bytes | Witness bytes | Peak items | Main caveat |
| --- | --- | ---: | ---: | ---: | --- |
| Preimage length | `len(preimage)-offset` | 44 | 18–524 | 3 | Range coupled to item size |
| Mixed hash path | 31 authenticated bits | 520 | 78 | 34 | Mixed-hash assumption; wider opcode cost |
| Four-way mixed hash path | 16 authenticated base-4 digits / 31 bits | 453 | 61 | 19 | Tapscript `MINIMALIF` required; non-standard mixed-hash code |
| Lamport 2-bit | Select one of four preimages | 96 | 11 | small | Strictly one-time |
| TapBranch u4 | BIP341 tagged hash over two ordered nodes | 1,106,745 | 161 | 969 | Consensus-incompatible script size |

The schemes have different semantics. Preimage length is compact but encodes
the integer indirectly; hash paths scale to more bits; Lamport authenticates a
tiny value with one-time key material. Under the measured 31-bit configuration,
the four-way path saves 67 script bytes, 17 witness bytes, and 15 peak stack
items relative to the binary path. This comparison does not erase its stronger
tapscript-only execution assumption or its non-standard mixed-hash security
assumption.

The TapBranch row is a boundary measurement rather than a deployable
alternative: it is an executable fixed-prefix composition, but its generated
script exceeds the 10,000-byte consensus limit. It demonstrates that the
existing u4 circuit can bind the fixed BIP341 domain separator without
`OP_CAT`; it does not solve compact byte concatenation or node ordering.
