# Integer commitments

| Construction | Value mechanism | Script bytes | Witness bytes | Peak items | Main caveat |
| --- | --- | ---: | ---: | ---: | --- |
| Preimage length | `len(preimage)-offset` | 44 | 18–524 | 3 | Range coupled to item size |
| Mixed hash path | 31 authenticated bits | 520 | 78 | 34 | Mixed-hash assumption; wider opcode cost |
| Four-way mixed hash path | 16 authenticated base-4 digits / 31 bits | 438 | 61 | 19 | Tapscript `MINIMALIF` required; non-standard mixed-hash code |
| Ternary mixed hash path | 20 authenticated base-3 trits / 31 bits | 924 | 63 | 24 | Native ternary state encoding; larger than four-way path |
| Lamport 2-bit | Select one of four preimages | 96 | 11 | small | Strictly one-time |

The schemes have different semantics. Preimage length is compact but encodes
the integer indirectly; hash paths scale to more bits; Lamport authenticates a
tiny value with one-time key material. Under the measured 31-bit configuration,
the four-way path saves 67 script bytes, 17 witness bytes, and 15 peak stack
items relative to the binary path. This comparison does not erase its stronger
tapscript-only execution assumption or its non-standard mixed-hash security
assumption.

The ternary path is not a byte-efficiency improvement for this integer target:
it uses one more witness item than the four-way path and is 486 bytes larger.
It is retained as a different representation point for protocols whose state
is naturally three-valued. Its local implementation performs explicit trit
canonicality checks instead of relying on tapscript `MINIMALIF`.
