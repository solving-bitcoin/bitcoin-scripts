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

The checked u32 byte-plane adapter is a fixed-width stack-scheduling boundary:
it transposes word-major MSB-first bytes into byte-major planes, preserves
unrelated state, and costs 411 bytes for eight words with a 35-item combined
peak and zero incremental hints. The generated permutation contains 4*n
`OP_ROLL` operations, but cumulative stack-shifting work is quadratic in batch
width, so consumers should price the actual batch rather than the 249-word
static ceiling.

The u4 bit-plane adapter is a checked transpose boundary: it reuses the
four-bit decomposition, groups one bit position across all input nibbles, and
preserves unrelated main and altstack state. Its representative 16-nibble
batch is 776 bytes with a 125-item combined peak and zero incremental hints.
Its standalone peak is `4*n + 61`; live main- or alt-stack state must be
included in that bound, so the 234-nibble generator ceiling is not a universal
composition width.

The u4 bit-reversal adapter is a checked per-nibble representation change. It
preserves lane order, uses a 16-item table, and costs 344 bytes for 32 input
nibbles with a 51-item combined peak and zero incremental hints.

The checked u32 byte-equality mask is a two-word routing boundary: it keeps
four per-lane equality predicates as one nibble instead of folding them into
the single Boolean returned by `u32_equal()`. Its 149-byte fragment has no
lookup table or hints, but validates eight canonical byte limbs and therefore
is useful only when the caller needs the individual lane bits.

The checked u32 byte-less-than mask is a two-word routing boundary: it keeps
four lane-local ordering predicates as one nibble instead of folding them into
the single Boolean returned by `u32_lessthan()`. Its 149-byte fragment has no
lookup table or hints, but validates eight canonical byte limbs and is useful
only when the caller needs the individual lane bits.

The checked u32 byte high-bit mask is a compact projection boundary: it keeps
one selected bit from each byte as a four-bit numeric mask. Its 133-byte
fragment validates four canonical byte limbs, uses no table or hints, and is
smaller than the 514-byte full 32-bit splitter when the remaining bit lanes
are irrelevant.

The checked u4 modulo-16 sum is an accumulator boundary rather than a
per-nibble projection. It uses a 31-item table for the `0..30` intermediate
sum, folds an arbitrary checked batch to one nibble, and costs 592 bytes for
32 inputs with a 66-item peak and zero hints.

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
