# Stack representations

Representation determines both local opcode cost and how a primitive composes.

| Representation | Items per value | Strength | Main cost |
| --- | ---: | --- | --- |
| ScriptNum | 1 | Native arithmetic and comparisons | Four-byte numeric domain |
| u4 | 2 per byte | Small table domain | High item count |
| u32 bytes | 4 per word | Direct byte logic | 256-item logic table |
| u31 field | 1 per coefficient | Prime-field arithmetic in ScriptNum | Canonicality and hinted reduction |
| bigint limbs | Width-dependent | General wide integers | Large multiplication scripts |
| RNS | 5 per represented integer | Coordinate-wise lookup/log arithmetic | Conversion, canonicality, and table memory |

Conversion is a protocol cost, not bookkeeping. A comparison that changes
representations must account for conversion fragments, witness layout, and
coexistence with the surrounding state.

The u4 bit-reversal adapter is a checked per-nibble representation change. It
preserves lane order, uses a 16-item table, and costs 344 bytes for 32 input
nibbles with a 51-item combined peak and zero incremental hints.

For terminal one-time authentication, the host may instead encode an unchanged
message as a fixed-sum vector. The
[20-byte Winternitz construction](../primitives/winternitz-constant-sum20.md)
uses reversible ranking into 41 mixed-radix digits, removing checksum chains.
Its default HASH160 witness has 82 data items and zero auxiliary hints, all
present at entry, with a measured 93-item combined main/alt-stack peak.
The measured class is `research-unlimited`. No onchain byte decoder is
included; protocols consuming the original bytes must count that additional
conversion and binding cost.

A [fixed-composition assignment](../primitives/winternitz-constant-composition20.md)
goes further: encode the 20-byte message as a permutation of a fixed digit
multiset across 49 independent keys. Radix-25 counts
`[1 × 15, 2 × 7, 3 × 2, 14]` leave fourteen maximum-digit keys implicit.
The other 35 keys are authenticated in fixed digit slots, so the witness
contains only selectors and openings, without numeric digit values. The
host mapping remains reversible and performs no input search or truncation.

HASH160/Preimage16 reaches 1,598 script bytes plus an attained maximum
802-byte serialized signer witness in the isolated API. Its 70 complete data
items, zero auxiliary hints, and 119-item combined peak are
`locally-reproduced`, `research-unlimited` measurements. A depth guard requires
all main-stack items to be signature data; the 2,498-byte composable alternative
preserves unrelated main state and peaks at 120. Neither method reconstructs
bytes or checks the host's rank bound. BitVM3 can use the assignment subject
to integration that binds its meaning and handles unused ranks; an onchain
byte consumer remains a separate measured cost.
