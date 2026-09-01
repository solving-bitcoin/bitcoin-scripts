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
