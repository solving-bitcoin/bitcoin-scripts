# Integer commitments

| Construction | Value mechanism | Script bytes | Witness bytes | Peak items | Main caveat |
| --- | --- | ---: | ---: | ---: | --- |
| Preimage length | `len(preimage)-offset` | 44 | 18–524 | 3 | Range coupled to item size |
| Mixed hash path | 31 authenticated bits | 520 | 78 | 34 | Mixed-hash assumption; wider opcode cost |
| Four-way mixed hash path | 16 authenticated base-4 digits / 31 bits | 653 | 61 | 20 | Larger script; non-standard fixed-length mixed-hash code |
| Lamport 2-bit | Select one of four preimages | 96 | 11 | small | Strictly one-time |

The schemes have different semantics. Preimage length is compact but encodes
the integer indirectly; hash paths scale to more bits; Lamport authenticates a
tiny value with one-time key material. The four-way path is not a byte-size
replacement for the binary path: under the measured 31-bit configuration it
trades 133 additional script bytes for 17 fewer witness bytes and 14 fewer peak
stack items.
