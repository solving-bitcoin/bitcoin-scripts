# Signed ScriptNum metadata carriers

## Question and comparison objective

Can an Ed25519 Montgomery slope-chain reuse the unused bits of its mandatory
quotient hints for a BLAKE3 transcript and scalar, without adding witness stack
items? The comparison objective is metadata capacity per existing item, subject
to exact quotient recovery, hostile-input canonicality, four-byte ScriptNum
arithmetic, and Bitcoin's 1,000-item combined stack limit.

## Construction

For a signed `w`-bit quotient slot, let `bias = 2^(w-1)`. The lower `31-w`
metadata bits and the biased quotient form a nonnegative 31-bit payload. The
ScriptNum sign carries one more bit:

```text
payload = (metadata_low << w) + (q + bias)
carrier = payload          if metadata_high = 0
carrier = -(payload + 1)   if metadata_high = 1
```

The decoder returns `q` and `32-w` literal zero-or-one items. It first rejects
items longer than four bytes, then compares the raw input to an arithmetic
normalization. This rejects negative zero and redundant sign bytes even when
the execution flags do not enforce minimal pushes. It never feeds `-2^31` to
an arithmetic opcode.

There is one absent carrier code: the negative representation of an all-one
31-bit payload would be `-2^31`, which requires five ScriptNum bytes. The
locally reproduced intervals for the currently implemented staggered-linear
kernel avoid the corresponding top quotient slot:

- curve relation: `[-3,150,640, 3,360,683]`, signed 23;
- first one-product continuity relation: `[-1,843,466, 1,843,466]`, signed 22;
- regular two-product continuity relation: `[-3,686,931, 3,686,931]`, signed
  23.

Thus every 10- or 9-bit metadata value is encodable for every honest quotient
in its applicable interval. The relation verifier, not the codec, must prove
that the recovered quotient is honest. The signed-20 and signed-21 rows below
are reusable codec profiles, not bounds claimed for this kernel.

## Locally reproduced codec metrics

The following fragment-only measurements come from
[`examples/ed25519_slope_carrier_codec.rs`](../../examples/ed25519_slope_carrier_codec.rs).
Every generated script was compiled through the centralized policy. Each
standalone decoder and its raw serialization have the same size. Boundary
fixtures for both signs, signed-slot endpoints, actual quotient endpoints, the
missing `-2^31` code, negative zero, and redundant sign bytes executed in
tapscript under `bitcoin-scriptexec` with the strict 1,000-item stack limit.
The evidence level is `locally-reproduced`; the deployment class is
`unclassified`.

| Quotient slot | Metadata bits | Script bytes | Static non-push opcodes | Input items | Output items | Strict combined peak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| signed 23 | 9 | 152 | 89 | 1 | 10 | 12 |
| signed 22 | 10 | 167 | 98 | 1 | 11 | 13 |
| signed 21 | 11 | 182 | 107 | 1 | 12 | 14 |
| signed 20 | 12 | 197 | 116 | 1 | 13 | 15 |

Each row consumes one already-required logical quotient hint item. It adds
exactly zero hint items and zero data items. A signed-23 carrier payload is at
most four bytes, versus at most three for the direct quotient. Its standalone
one-item witness serialization is therefore at most six bytes. For the same
quotient, the metadata carrier can add between zero and four payload bytes;
`q = 0` is the four-byte worst case because its direct encoding is empty.

### Compact output

The bit-vector decoder is useful as a reference but expands one carrier to ten
or eleven live items in the active profile. A second strictly executed decoder
returns `q | metadata_chunk` in only two items:

| Quotient slot | Compact script bytes | Input items | Output items | Strict combined peak |
| --- | ---: | ---: | ---: | ---: |
| signed 23 | 185 | 1 | 2 | 6 |
| signed 22 | 203 | 1 | 2 | 6 |
| signed 21 | 221 | 1 | 2 | 6 |
| signed 20 | 239 | 1 | 2 | 6 |

The active first relation pair plus two certified trace-padding bits decodes to
`q_curve | q_continuity | chunk21` in 438 bytes with a strict local peak of 10.
A regular pair plus two padding bits produces at most a 20-bit chunk in 418
bytes and also peaks at 10. With no padding, a regular pair produces one
18-bit chunk in 392 bytes and peaks at eight. These pair fragments consume
exactly two existing quotient hint items; their padding-bit inputs are
previously certified trace data, not new hints. Each transition retains one
compact transcript item instead of 18--21 separate bit items.

## Capacity and hint coexistence

This carrier remains the measured byte-minimizing transport for the historical
hinted G29 leaf. The current G32 quotient-derived leaf does not use it: no q is
accepted from the witness, so that leaf has neither carrier metadata nor
quotient-hint items. Keeping this distinction explicit avoids treating an old
88-hint transport result as part of the zero-hint verifier.

The historical 44-transition G29/H16 slope chain has exactly two logical quotient hint
items per transition, hence **88 hint items total**. All 88 coexist at complete
script entry. Its 88 trace fields occupy 704 packed data items. There are no
separate scalar words at entry, so the raw trace-plus-hint entry is 792 items
before tables or transient work.

The first 28 transitions consume 56 of those quotient hints. Their mixed-width
capacity is:

```text
first pair:  9 + 10 = 19 bits
next 27:    27 * (9 + 9) = 486 bits
total:      505 bits
```

The concrete stream extracts eight normally-zero padding bits from existing
packed trace fields, giving 513 bits of response-side capacity. Chunk order
places all eight padding bits inside the 512-bit transcript; the one final
forced-zero spare bit is quotient metadata in the last response chunk. Across
all 44 transitions, quotient capacity is
`19 + 43*18 = 793` bits, 28 more than the 512-bit transcript plus 253-bit
scalar. The schedule places the scalar in 29 final challenge-side signed-23 q
items, which provide 261 bits. A full item-accurate synthetic router in
[`ed25519_h16_scalar_carrier_router.rs`](../../examples/ed25519_h16_scalar_carrier_router.rs)
compact-decodes those carriers, restores every q in its exact packet slot, and
repacks the low 253 bits into the eight signed-u32 words expected by the G29
scalar payload. It starts with all 792 witness items, returns 800 items, has a
strict combined main-plus-alt-stack peak of **813 items**, and uses a
25,231-byte raw/unoptimized router fragment. The complete strict probe exceeds
the centralized policy's 32 KiB cutoff, so it uses `CompileOptions::NONE`. The
earlier analytic 805-item estimate is superseded: each nine-bit carrier
temporarily materializes its bits while the word accumulator is live. The
isolated 56- and 88-carrier vectors have
serialized-witness upper bounds of 281 and 441 bytes respectively. These byte
counts do not alter the 88-item hint count.

The router establishes only its synthetic 792-item packet boundary under the
1,000-item limit. Selected-point tables, transcript consumers, live arithmetic
state, and kernel temporaries must still be included in a whole-verifier strict
measurement.

## Packed-field padding channel

Each eight-item Ed25519 packed field has a normally-zero bit 255 in bit 31 of
word seven. A 37-byte fragment interprets the compressed-u32 sign as that bit
and restores the low 31-bit word. It consumes one existing data item, returns
the restored word plus one certified bit, requires **zero hint items**, and has
a strict combined peak of four items. It special-cases the canonical five-byte
`-2^31` sentinel before arithmetic.

A 6,296-byte wrapper restores public word order and invokes the canonical
packed-field decoder. It consumes eight packed data items, returns 51 field
digits plus the bit, requires zero hints, and has a locally reproduced strict
combined peak of 59. The current response stream extracts eight such bits, all
of which occur before its final quotient-metadata bit and therefore enter the
transcript hash. The remaining capacity comes from the 32 challenge-side q
hints added by H16, so no additional padding bits are needed for the scalar.

## Security and composition obligations

- The quotient relation must consume and bind every recovered `q`. Merely
  fitting it in a signed slot is not a proof of the field identity.
- The hash/scalar consumer must consume every recovered bit in one specified
  order and bind it to the signature, public key, and message. Capacity alone
  supplies no authentication.
- The quotient-width proof must match the exact generated coefficient basis.
  Changing limb grouping or sparse linear terms can invalidate the interval
  and the guarantee that the missing code is unreachable.
- Padding-bit extraction alone does not prove that the lower 255 bits are a
  canonical field element. Run the field decoder after clearing, as the
  measured wrapper does.
- The complete script must account explicitly for 88 coexisting hint items,
  all data items, and the combined main-plus-alt-stack peak. Serialized bytes
  are not a substitute for these item counts.
- The codec has no terminal predicate and makes no consensus-deployment or
  signature-acceptance claim.
