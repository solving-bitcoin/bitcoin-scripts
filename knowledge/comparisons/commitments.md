# Integer commitments

| Construction | Value mechanism | Script bytes | Witness bytes | Peak items | Main caveat |
| --- | --- | ---: | ---: | ---: | --- |
| Preimage length | `len(preimage)-offset` | 44 | 18–524 | 3 | Range coupled to item size |
| Mixed hash path | 31 authenticated bits | 520 | 78 | 34 | Mixed-hash assumption; wider opcode cost |
| Mixed hash path with retained bits | 31 authenticated bits plus reusable altstack state | 365 | 78 | 34 | Retained bits consume 31 combined stack items |
| Four-way mixed hash path | 16 authenticated base-4 digits / 31 bits | 453 | 61 | 19 | Tapscript `MINIMALIF` required; non-standard mixed-hash code |
| Lamport 2-bit | Select one of four preimages | 96 | 11 | small | Strictly one-time |

The schemes have different semantics. Preimage length is compact but encodes
the integer indirectly; hash paths scale to more bits; Lamport authenticates a
tiny value with one-time key material. Under the measured 31-bit configuration,
the four-way path saves 67 script bytes, 17 witness bytes, and 15 peak stack
items relative to the binary path. This comparison does not erase its stronger
tapscript-only execution assumption or its non-standard mixed-hash security
assumption.

The retained-bit adapter is 155 bytes smaller than integer reconstruction at
31 bits because it stops after authenticated path evaluation; its 31 retained
bits still coexist with the 32-byte preimage-derived execution state and must
be consumed or composed deliberately.
