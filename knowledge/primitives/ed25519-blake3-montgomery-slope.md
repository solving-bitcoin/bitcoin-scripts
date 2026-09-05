# BLAKE3 Ed25519-style Montgomery slope verifier candidate

## Question and objective

Can one key-specialized signature verifier fit both a four-million-weight block
envelope and Bitcoin's 1,000-item combined stack limit? This construction
targets a custom 128-bit-BLAKE3 Schnorr/EdDSA-style equation over the Ed25519
prime subgroup. It is deliberately not RFC 8032 Ed25519.

## Signature and transcript

Let `B` generate the order-`l` Ed25519 subgroup, let the fixed public key be
`A=[a]B`, and let `C` be the public offset for the selected centered response
recoding. A signature is two 32-byte strings:

```text
Rtilde = canonical little-endian packed-backend field encoding of u(R-U)
z      = 256-bit little-endian encoding of C+s
```

The signer chooses `r`, sets `R=[r]B`, and computes

```text
h = LE(bytes[0..16] of BLAKE3(D32 || compressed_edwards(A) || Rtilde || M32))
s = r + h*a mod l.
```

The verifier proves `0<=s<l` by checking the transported `C+s` encoding, then
computes `[s]B-[h]A`. Since `h<2^128<l`, this profile needs no separate scalar
reduction for the challenge. `D32` is
`BLAKE3("bitcoin-lab/custom-ed25519-blake3-slope-v1")`, exactly
`fa127341786f99905cbe988ae146443624be8eaf478ff357bd1068f01863b581`.
It and the canonical public-key encoding are compiled into BLAKE3's first-
block chaining value. The response string is the little-endian integer `C+s`;
the scalar validator consumes exactly its low 253 bits and proves its top
three bits are zero. `M32` is a caller-bound message or prehash; supplying it
as unconstrained witness data would verify a prover-chosen message and is not
a transaction-signature construction.

The current G32 leaf fixes `M32` to the deterministic benchmark value
`M[i]=7*i mod 256` and materializes those fixed words inside the specialized
BLAKE3 compressor; it accepts no message witness items. The historical hinted
G29 leaf instead recovers 64 hostile message nibbles from quotient metadata,
checks them against the same constant with a 128-byte binder, and drops them.
Neither boundary authorizes a transaction message. A production construction
needs a message-binding mechanism appropriate to its transaction protocol.
In particular, this fixed value is not a transaction digest and supplies no
transaction replay protection. Nonce derivation is also unspecified; a
production scheme must define a domain-separated deterministic or securely
random nonce procedure, and must never reuse a nonce with Ed25519 or another
scheme under the same scalar.

The exact linked fixture uses
`A32=7db0dc9222f3c183457ddde4c708de8e5ea6bf3d5c4404cca14b32729a05c32a`
and
`M32=00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9`.
The linker asserts that `A32` is the RFC 8032 compression of the very point
used to generate the challenge tables.

`Rtilde` uses the [torsion-coset u encoding](../techniques/ed25519-torsion-coset-u-encoding.md).
It is injective for prime-subgroup points even though an ordinary Montgomery
`u` coordinate identifies a point up to sign. Its bytes are the eight
little-endian `u32` words obtained by packing the canonical biased-radix-32
backend encoding in word-zero-through-word-seven order; they are not the
ordinary integer encoding of the field residue. The G32 witness supplies the
same encoding directly as 51 digits and the hash helper validates and packs
them without consuming the original field.

## Montgomery slope chain

The current zero-hint response uses 32 groups. Every width is eight except
lower positions 21, 25, and 29, which have width seven; the widths sum to all
253 response bits. The 128-bit challenge uses sixteen byte-wide groups. This
gives 48 selected groups and 47 slope transitions. The historical linked
configurations below retain the earlier 29-group response widths
`8x8,9x21` and 44 transitions.

Every selected subgroup contribution is translated by the order-two point
`T=(0,-1)`, making a zero digit a real affine point. For challenge bytes
`b_i`, the verifier independently selects signed digits `e_i=b_i-127` in
`[-127,128]`. With

```text
K_127 = sum(127 * 2^(8i), i=0..15) = 0x7f7f...7f
h     = sum(e_i * 2^(8i), i=0..15) + K_127,
```

all sixteen challenge tables need only magnitudes `0..128`; there is no carry
chain or 257-leaf top table. The exact control map is `00 -> (-,127)`,
`7f -> (+,0)`, `80 -> (+,1)`, and `ff -> (+,128)`, with zero's sign derived
as false. The fixed `-[K_127]A` term is folded into every response-top
initializer leaf.

For G32, the order-four translation `U=(sqrt(-1),0)` initializes
`P0=U+Qtop-[K_127]A`, without an initial `T`. The 47 following selections each
add `T`, so their odd total again changes `U` to `-U`. The historical G29
initializer includes `T` and is followed by 44 translated selections. Both
parity-correct schedules exclude zero denominators and end at

```text
-U + [s]B - [h]A.
```

For current `(u,v)`, selected `(a,b)`, next `u'`, and slope `lambda`, Script
checks

```text
lambda^2 = u + a + u' + 486662                         mod p
lambda(a-u) - b + v = 0                                mod p   (first)
lambda(a-u) + lambda_prev(a_prev-u) - b - b_prev = 0   mod p   (chained)
```

where `p=2^255-19`. The second chained relation eliminates the current `v`.
Each transition has two exact coefficient recurrences. The retained baseline
accepts one scalar quotient for each recurrence, so it needs two hints rather
than a full generic field-multiplication certificate. The newer derived
kernel instead reconstructs the unique signed 22- or 23-bit quotient from the
five low radix-32 coefficients and then runs the same complete carry identity;
it needs zero quotient hints. Its square relation exploits the symmetry of
`lambda^2`: 51 own terms plus 300 doubled cross terms replace 663 generic
bilinear table updates. The final G32 transition consumes a canonical 51-item
radix-32 `Rtilde` field and fuses the endpoint check, cleanup, and clean truth.

The current kernel reduces each Horner stage while reading `h4..h0`, so only
one low residue remains live. Reducing stage `i` modulo `2^(w-5i)` preserves
the reconstructed value modulo `2^w`; the final inverse-of-minus-19 step still
derives the same signed quotient. Starting the exact reverse recurrence at
`-q` permits `d=32*d+h_i` and a negated low-column equation. Sparse linear
terms share a coefficient traversal. All 94 relations still use zero hints.

Partial-word decoding supplies each consumer's required representation:
46 eight-item `u_next` inputs become sixteen centered limbs at a 62-item
local combined peak, and 47 eight-item lambda inputs become 51 certified
digits at a 93-item peak. The sixteen temporary powers are Script constants,
removed before return. Both decoder sets use zero auxiliary hints per
invocation and in total; padding and the canonical gap remain validated.
[NR-036](../negative-results/index.md) records the decoder byte/stack tradeoff.

Selected `u/a` values use sixteen direct centered limbs `[4x3,3x13]`.
Selected `v/b` values use nine staggered limbs `[4,6x7,5]` at offsets
`0,4,10,16,22,28,34,40,46`. A negative table digit negates those nine limbs
literally. The trace/witness builder consumes the exact literal limb
representative; regrouping the field-equivalent canonical residue can shift
the derived continuity quotient by one and is not interchangeable.

The pinned birational convention is
`u=(1+y)/(1-y)` and `v=sqrt(-486664)*u/x`, with the exceptional Edwards point
`T=(0,-1)` represented as Montgomery `(0,0)`. The chosen `sqrt(-1)` is
`0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0`.
The `v` scale is the root selected by the implementation's `(p+3)/8`
algorithm, multiplying by that `sqrt(-1)` only when required:
`0x0f26edf460a006bbd27b08dc03fc4f7ec5a1d3d14b7d1a82cc6e04aaff457e06`.

## Witness configurations, hints, and metadata transport

In the quotient-carrier baseline, every transition packet contains two
canonical packed trace fields and two logical quotient hints:

| Entry class | Per transition | 44-transition total | Hint status |
| --- | ---: | ---: | --- |
| packed `u_next,lambda_next` trace | 16 | 704 | circuit data |
| exact relation quotients | **2** | **88** | mandatory hints |
| separate scalar or transcript items | 0 | 0 | carried in q metadata |
| **Raw entry** | **18** | **792** | **88 hints** |

All 792 items, including all 88 hints, coexist at script entry. The honest
curve and regular-continuity quotients fit signed-23 slots; the first
continuity quotient fits signed 22. They are not full 32-bit hint payloads.

The separate G29 quotient-derived configuration removes every q carrier and
supplies the scalar as eight canonical compressed-u32 words:

| G29 q-free entry class | Per transition | Complete total | Hint status |
| --- | ---: | ---: | --- |
| packed `u_next,lambda_next` trace | 16 | 704 | circuit data |
| canonical scalar words | - | 8 | circuit data |
| exact relation quotients | **0** | **0** | verifier-derived |
| **Raw entry** | - | **712** | **zero hints** |

All 712 data items coexist at entry in physical order
`challenge_trace[16] | response_trace[28] | scalar[8]`. The scalar validator
streams the response high-to-low without a quotient router or packet
transpose. After the response side, 256 untouched challenge-trace items and a
41-item current state remain. BLAKE3 deep-copies the eight packed `Rtilde`
words from the bottom challenge packet while preserving all 297 items; the
last derived challenge transition later certifies and consumes those original
words. Thus the hash binding does not require a second retained R suffix.

The current G32 hybrid-u5 configuration expands the response trace to 31
packets and replaces the final challenge packet's packed `u_next` field with
the 51 canonical radix-32 digits of `Rtilde`:

| G32 hybrid-u5 entry class | Per ordinary transition | Complete total | Hint status |
| --- | ---: | ---: | --- |
| 46 ordinary packed trace packets | 16 | 736 | circuit data |
| terminal `p0: Rtilde[50..0] | lambda[7..0]` packet | - | 59 | circuit data |
| canonical scalar words | - | 8 | primary input |
| relation quotients | **0** | **0** | verifier-derived |
| **Raw entry** | - | **803** | **zero hints** |

All 803 items coexist at script entry in physical order
`challenge_p0_u5 | challenge_p1..p15_packed | response_packed[31] | scalar[8]`;
`p0` is the last challenge packet consumed by the high-to-low schedule.
Every one of the 47 transitions needs exactly zero auxiliary hint items, so
the repeated total is also zero. The fifteen-item first-transition pool holds
bits 16 through 30; the
sixteen-item later-transition pools are constructed by Script and live only
during their scheduled phases; they are lookup memory, not hints or witness
data. Their lifetimes are included in the combined-stack analysis.

In the baseline, a sign-aware four-byte ScriptNum carrier recovers the exact q and uses the
remaining sign/magnitude codes for metadata. The first 28 response pairs carry
505 bits and eight cleared packed-field padding bits make a 513-bit stream.
In the concrete chunk order all eight padding bits enter the 512-bit
`Rtilde32||M32` suffix; the final quotient-metadata bit is forced to zero.
Twenty-nine challenge-side q carriers hold the 253-bit `C+s` payload plus eight
forced-zero bits. To keep those carriers shallow, the witness starts in
`response[28] | challenge[16]` packet order. The scalar router restores every
q to its packet slot and emits eight words without adding a witness item; a
2,032-byte exact block transpose then produces the execution order
`challenge[16] | response[28] | scalar[8]`. The three unused challenge
carriers are decoded with zero metadata. See the
[carrier construction](../techniques/signed-scriptnum-metadata-carriers.md).
For an honest witness, response packet `27-j` produces transcript chunk `j`.
Within a chunk, curve-q metadata is least significant, continuity-q metadata
follows, and chunks zero through three append lambda-padding then u-padding.
All eight padding bits are transcript data. Global bit 512 is the high metadata
bit of response packet zero's continuity carrier and is forced to zero.

## Linked serialization and schedule metrics

Each generation-only linker constructs one complete clean-stack leaf and
passes the entire result through the repository compilation policy. Every leaf
is above 32 KiB, so the whole composition receives `CompileOptions::NONE` and
its reported final size is unoptimized by upstream fixpoint passes. Slope
kernels and selected small semantic fragments retain their allowed step-local
policy compilation. The current G32 linker's disjoint components sum exactly
to:

| G32 hybrid-u5 zero-hint component | Policy-produced bytes |
| --- | ---: |
| canonical G32 scalar validator | 774 |
| response tables, stream, 31 derived kernels, pools, and routing | 1,821,324 |
| canonical-u5 `Rtilde` conversion and fixed-message BLAKE3-128 | 67,137 |
| independent bias-127 H16 challenge recoder | 389 |
| challenge tables, 16 derived kernels, pools, fused terminal truth, and routing | 945,029 |
| **Complete G32 linked leaf** | **2,834,653** |

The response and challenge schedules contain 582,560 authenticated table
bytes, 20,530 scaffold bytes, and 2,163,263 kernel bytes. The table split is
382,149 response plus 200,411 challenge bytes. Relative to the 2,999,983-byte
G32 baseline at `f7bb0c2`, partial decoding, fused sparse passes, Horner
reduction, the larger first pool, and endpoint table selection save
165,330 bytes (5.511%). The final leaf is 993,404 bytes smaller than the
policy-compliant hinted G29 projection and 1,061,682 bytes smaller than the
corresponding zero-hint G29 projection.
These are whole-script byte comparisons at the same fixed-key/fixed-message
clean-stack boundary.
The whole serialization contains 1,663,690 static non-push opcodes; the
disjoint component sum has zero cross-component optimizer delta.
The [generic-square/per-transition-power baseline](../negative-results/index.md)
is recorded as NR-034. NR-035 records the historical `f7bb0c2` cross-hash
pool alternative, which projected 25 fewer bytes while coupling BLAKE3 and
the recoder to a nonempty alt stack. The production schedule keeps explicit
empty phase boundaries; NR-036 records the current relation/decoder changes.

For history, the quotient-carrier G29 components now give the following
policy-compliant additive projection. The complete linker has not been
regenerated after correcting the hash fragment's compilation policy; the old
3,826,949-byte whole serialization is superseded.

| Linked component | Policy-produced bytes |
| --- | ---: |
| shallow scalar carrier router | 25,231 |
| response/challenge packet-block transpose | 2,032 |
| canonical G29 scalar validator | 774 |
| response stream, tables, 28 kernels, carrier decoders, and routing | 2,468,115 |
| routed canonical transcript unpacker | 11,220 |
| fixed `M32` consume-and-drop binding | 128 |
| fixed-prefix/fixed-`M32` BLAKE3, low 128 bits, 337 items preserved | 63,990 |
| independent bias-127 H16 challenge recoder | 389 |
| challenge tables, 16 kernels, remaining-q checks, and routing | 1,256,139 |
| endpoint comparison and clean truth | 39 |
| **Projected complete linked leaf** | **3,828,057** |

That table is the 792-item quotient-carrier baseline. A separate zero-hint G29
component account, likewise not regenerated after the policy correction,
projects:

| G29 q-free linked component | Policy-produced bytes |
| --- | ---: |
| canonical G29 scalar validator | 774 |
| response tables, scalar stream, 28 derived kernels, and routing | 2,528,330 |
| fixed-message BLAKE3 copied from later-certified packed `Rtilde` | 67,806 |
| independent bias-127 H16 challenge recoder | 389 |
| challenge tables, 16 derived kernels, and routing | 1,299,014 |
| terminal state cleanup and clean truth | 22 |
| **Projected complete q-free linked leaf** | **3,896,335** |

The superseded pre-policy q-free serialization contained 2,087,154 static
non-push opcodes; a current whole count is not claimed without regeneration.
The projected disjoint rows sum exactly and a regenerated whole leaf would be
above 32 KiB and therefore receive `CompileOptions::NONE`. The 45 tables still account for
826,072 bytes. The first plus 43 derived kernels account for 2,982,140 bytes,
119,962 bytes more than the hinted kernels. Removing the carriers, router,
transpose, transcript unpacker, and retained endpoint copy reduces stack use,
but quotient derivation and the packed-R hash boundary make this projection
68,278 bytes larger than the hinted projection.

At the isolated hash boundary, the corrected variable-`M32` design costs
65,315 bytes (192-byte check-and-republish binder plus 65,123-byte hash). The
fixed-message pair now costs 64,118 bytes. The older 63,766-
byte preserving-hash measurement was not composable: its lookup tables sat
above the 337-item prefix, so the first `OP_DEPTH`-based packed-XOR lookup
failed. Both corrected alternatives now execute against the host digest.

Within the two schedules, the 45 authenticated direct-limb tables account for
826,072 bytes and the first plus 43 chained slope kernels account for
2,862,178 bytes. Those are sub-attributions, not extra rows to add to the
linked total. Relative to the carry-centered comparison, bias-127 adds 57
response-top bytes, removes 12,441 challenge-top bytes, and removes 191
recoder bytes: an exact 12,575-byte net saving. Tables and recoding still add
zero witness hints or entry items. The focused independent-byte probe checks
the exact table partition without executing it, strictly executes the 389-byte
recoder with its real 337-item prefix at a 371-item peak, covers bytes
`00,7f,80,ff`, and host-checks response values `0,1,l-1`, the `K_127`
identity, torsion translations, and the final group endpoint.

The G32 raw entry is exactly 803 circuit-data items and **zero auxiliary hint
items**. Its first transition has 787 preserved items plus a separately strict-
measured 204-item local peak, giving 991 combined main-plus-alt-stack items.
The analytical maximum is **995**, at response transition one; transition
two reaches 994. The 391-item canonical-u5 BLAKE3 boundary strict-peaks at
918. Independent abstract execution of all 679 first-kernel conditional
branches confirms its 204-item local bound and 92-main-item/empty-alt exit.
All fifteen- and
sixteen-item shared-power pools are included in those local measurements and
are authored by Script rather than supplied by the witness. A strict synthetic
routing schedule and the real component interfaces were executed separately;
the multi-megabyte composition was not.

The production-shaped G32 honest-witness generator serializes those 803
arguments to **3,863 bytes**: the independently serialized 795-item trace and
eight-item scalar subvectors are 3,824 and 40 bytes respectively (their two
item-count prefixes collapse to one in the complete vector). Its complete
argument-vector BLAKE3 digest is
`896812f002f5c8b1a2816eed80ceb84e9822a9202ae226771a48091a6ef8c5d1`.
The host audit checks all 47 transition pairs and 94 exact relations without
serializing a quotient; its audit digest is
`39b80a67b6be1791810841c8bcd99fa894c356f93f8f499d03ddf20ce6c83b95`.
The fixture's curve q/carry intervals are `[-1228890,911978]` and
`[-23346570,21167866]`; first continuity q is `-249700` with carry interval
`[-16963155,14977586]`; chained continuity q/carry intervals are
`[-760980,643390]` and `[-31878743,32260603]`.
For this fixture, adding a script of `S` bytes and a depth-zero control block
gives exact complete-witness bytes `S+3,902`, target weight `S+4,280`, and
minimum block weight `S+5,048`. At `S=2,834,653`, these are 2,838,555 bytes,
2,838,933 WU, and 2,839,701 WU, leaving **1,160,299 WU** below four million in
the minimum-block model. A content-independent conservative argument bound is
4,617 bytes; its target/minimum-block formulas are `S+5,034` and `S+5,802`,
leaving 1,159,545 WU at this script size. Both projections exceed default
transaction policy and omit real miner overhead beyond the stated 768-WU
minimum block model.

The hinted G29 raw entry is 792 items. Materializing the scalar temporarily returns
800 items and peaks at 813. The real transcript unpacker peaks at 843. After
the binder consumes `M32`, the BLAKE3 hash frontier contains 337 preserved
items plus 64 `Rtilde` nibbles; a focused strict host-differential execution
peaks at 864. The strict whole stub peaks at **999**. The critical first
arithmetic row is 783 preserved items plus a separately measured 216-item
local peak; the second is
766+232=998. Tables and BLAKE3 require exactly zero hint items.

The q-free raw entry is 704 trace items plus eight scalar words, exactly 712
items and **zero auxiliary hint items** throughout the leaf. Its synthetic
full routing probe strict-peaks at 763. Separately strict-executed derived
first/chained kernels have 214/232-item local peaks; composing those measured
interfaces with the exact schedule gives an analytical worst frontier of
**912 items**, at response transition one. The 67,806-byte packed-R BLAKE3
helper strictly executes at an 824-item combined peak, preserves its 297-item
prefix byte-for-byte, matches host BLAKE3, and rejects extra input. The 912
figure is analytical rather than a whole-leaf execution measurement.

The short strict linker probes verify the response packet/table/q/prior-state
order across padded, unpadded, signed, and width-boundary cases; the challenge
top selector 128; both remaining-q layouts; literal selected-`b` negation; and
fixed-message preservation plus mutated-message rejection. A separate focused
probe executes the fixed-message BLAKE3 pair, matches ordinary host BLAKE3,
checks exact prefix/`Rtilde` order, and rejects malformed/reordered/extra input;
it does not execute the large arithmetic bodies. Under a conservative
704-by-five-byte trace and 88-by-four-byte-carrier witness, a one-input/one-
P2TR-output target
weighs `S+5,084` WU for script size `S`. A minimum current-height
witness-committing block consumes another 768 WU, giving a conservative
planning ceiling of 3,994,148 script bytes. At projected `S=3,828,057`, the
target weight is 3,833,141 WU and the minimum block weight is 3,833,909 WU,
leaving **166,091 WU** for real miner overhead.

The deterministic honest-witness generator independently constructs the exact
792-item entry for the pinned benchmark signature. It derives every trace
point and slope, takes all 45 selected direct-limb representatives from the
same generator as the Script tables, computes all 88 relation quotients from
those exact representatives, embeds both metadata streams, and proves the
host endpoint `-U+[s]B-[h]A=R-U`. The exact argument witness serialization is
**3,958 bytes**, versus the 4,667-byte conservative envelope. Its honest
curve-quotient interval is `[-977396,517495]`, its continuity interval is
`[-760980,716035]`, and every carrier avoids `-2^31` and occupies at most four
payload bytes. The fixed result is committed by BLAKE3 digest
`972a0d8d76b4246f88b24aeb148813bc9c863c9ee16ecfb52bb1026a4ba71c6a`.
This is `locally-reproduced` host generation and serialization, not execution
of the complete leaf. Because both 792 and 794 items use a three-byte witness
count, adding a script of `S` bytes and a depth-zero control block gives an
exact fixture witness of `S+3,997` bytes, target weight `S+4,375`, and minimum
block weight `S+5,143`. At projected `S=3,828,057`, those last two values are
3,832,432 and 3,833,200 WU, leaving **166,800 WU**. The conservative `S+5,084` target and
`S+5,852` block formulas remain the safe content-independent planning bounds.

The separate q-free honest generator uses the same signature and exact 44-
packet trace, but serializes canonical packets in challenge-first order and
adds eight scalar words. Its **712-item** argument witness is **3,561 bytes**:
3,522 bytes for the 704-item trace vector and 40 bytes for the eight-word
scalar vector (each sub-vector includes its own CompactSize prefix). Its
BLAKE3 digest is
`a78ec4fe4999fa3d00c6412e7119117d3b0ce1296e2a2c63c9c18beaa624eddd`.
No quotient is serialized. For audit only, the host reconstructs all 44
curve/continuity pairs, checks all 88 exact divisibility identities and both
directions of every radix-32 carry recurrence, and verifies `sB-hA=R`. The
fixture's curve q/carry intervals are `[-977396,517495]` and
`[-15502210,18536294]`; first-continuity q is `38337` with carry interval
`[-6554982,10386674]`; chained-continuity q/carry intervals are
`[-760980,716035]` and `[-33165039,32260603]`.

For the q-free fixture, adding a script of `S` bytes and a depth-zero control
block gives exact complete-witness bytes `S+3,600`, target weight `S+3,978`,
and minimum block weight `S+4,746`. At projected `S=3,896,335`, these are
3,899,935 bytes, 3,900,313 WU, and 3,901,081 WU, leaving **98,919 WU**. A conservative
five-byte-payload bound for all 712 inputs gives target `S+4,692` and minimum
block `S+5,460`; the projection therefore reaches 3,901,027 and 3,901,795 WU,
leaving **98,205 WU**. Both envelopes exceed default transaction policy
and omit real miner overhead beyond the stated 768-WU minimum block model.

Evidence is `locally-reproduced` for the exact current G32 linked serialization, host
algebra, external-key validation boundary, isolated transition kernels, table
leaves, carrier/router fragments, midpoint routing, scalar control, strict
stub/synthetic routing schedules, packed-R BLAKE3, short linker-routing probes,
the exact honest witness generations, and serialization formulas at their
stated boundaries. The corrected G29 whole sizes remain additive projections.
No complete multi-megabyte Script was executed and no
honest witness was validated through Bitcoin Core, so the overall signature
candidate remains `inspected`. Deployment is `unclassified`. Generated long-
running tests are ignored by default and require explicit opt-in.

## Security and completion boundary

- The fixed BLAKE3 `A32` must be the exact standard compressed encoding of the
  subgroup point used to generate the `-A` tables. The production-oriented
  host boundary now accepts that external 32-byte encoding directly, proves
  canonical `y`, valid root/sign and curve equation, rejects identity and
  small-order points, and requires `[l]A=identity` before generating either
  Script fragments or exact witness-builder leaves. The returned `A32` and all
  challenge tables come from that one validated point; this path has no secret
  scalar parameter or secret-scalar derivation.
- The current exact leaf uses the disclosed benchmark secret
  `a=987654321`; it is therefore forgeable and **not a production-secure key**.
  Its no-argument helper is retained only as a stable benchmark wrapper around
  the validated external-key API. The fast host-only boundary probe covers the
  RFC 8032 base point, the benchmark point, nonsquare and noncanonical
  encodings, forbidden negative zero, identity, order-two, and a mixed-torsion
  point; it does not build tables or execute Bitcoin Script.
- Its fixed `M32` is not a Bitcoin transaction digest, so the benchmark leaf
  has no transaction authorization or replay-binding semantics.
- In G32, `Rtilde` is supplied once as 51 canonical radix-32 digits. The hash
  helper checks every digit and the 19-value `p..2^255-1` gap while copying it
  into BLAKE3 nibbles, and preserves the original field for the terminal slope
  relation. The historical G29 paths instead use eight packed words.
- In the hinted baseline, every carrier is raw-canonical and at most four
  bytes. Every recovered q is consumed by its exact relation; every
  transcript/scalar bit is consumed once, and all surplus metadata bits are
  forced to zero. The q-free configuration has no carrier or quotient witness:
  it derives the unique bounded q from the completed accumulator and checks the
  entire relation recurrence.
- The G29 q-free packed-R hash reads an uncertified copy before the original words
  reach the final slope transition. Soundness therefore relies on that later
  transition executing and certifying the exact untouched originals; the
  complete linked control flow includes this obligation.
- Table constants are compiled and trusted but must be generated from valid
  subgroup points using one pinned birational-map convention. Host-side table
  generation has not been independently differentially validated.
- A 128-bit challenge is a custom security choice intended to target roughly
  128-bit work, not an RFC 8032 compatibility claim or a completed proof.
- The construction exceeds the 400,000-WU standard-transaction policy limit.
  It has not been validated in a complete transaction against Bitcoin Core.

The focused implementations are
[`montgomery_slope.rs`](../../src/curves/ed25519/montgomery_slope.rs),
[`ed25519_montgomery_slope_chain_model.rs`](../../examples/ed25519_montgomery_slope_chain_model.rs),
[`ed25519_montgomery_h16_full_linker.rs`](../../examples/ed25519_montgomery_h16_full_linker.rs),
[`ed25519_montgomery_h16_honest_witness.rs`](../../examples/ed25519_montgomery_h16_honest_witness.rs),
[`ed25519_montgomery_slope_no_hint_probe.rs`](../../examples/ed25519_montgomery_slope_no_hint_probe.rs),
[`ed25519_montgomery_h16_qfree_scheduler.rs`](../../examples/ed25519_montgomery_h16_qfree_scheduler.rs),
[`ed25519_blake3_packed_r_probe.rs`](../../examples/ed25519_blake3_packed_r_probe.rs),
[`ed25519_montgomery_h16_qfree_full_linker.rs`](../../examples/ed25519_montgomery_h16_qfree_full_linker.rs),
[`ed25519_montgomery_h16_qfree_honest_witness.rs`](../../examples/ed25519_montgomery_h16_qfree_honest_witness.rs),
[`ed25519_montgomery_slope_square_probe.rs`](../../examples/ed25519_montgomery_slope_square_probe.rs),
[`ed25519_montgomery_slope_shared_constants_probe.rs`](../../examples/ed25519_montgomery_slope_shared_constants_probe.rs),
[`ed25519_packed_grouped_decode_probe.rs`](../../examples/ed25519_packed_grouped_decode_probe.rs),
[`ed25519_slope_quotient_horner_probe.rs`](../../examples/ed25519_slope_quotient_horner_probe.rs),
[`ed25519_montgomery_slope_optimized_probe.rs`](../../examples/ed25519_montgomery_slope_optimized_probe.rs),
[`ed25519_montgomery_first_stack_bound.rs`](../../examples/ed25519_montgomery_first_stack_bound.rs),
[`ed25519_table_boundary_probe.rs`](../../examples/ed25519_table_boundary_probe.rs),
[`ed25519_montgomery_h16_hybrid_scheduler.rs`](../../examples/ed25519_montgomery_h16_hybrid_scheduler.rs),
[`ed25519_montgomery_h16_hybrid_u5_group_cost.rs`](../../examples/ed25519_montgomery_h16_hybrid_u5_group_cost.rs),
[`ed25519_montgomery_h16_hybrid_u5_challenge_cost.rs`](../../examples/ed25519_montgomery_h16_hybrid_u5_challenge_cost.rs),
[`ed25519_blake3_u5_r_hybrid_probe.rs`](../../examples/ed25519_blake3_u5_r_hybrid_probe.rs),
[`ed25519_montgomery_h16_hybrid_u5_g32_full_linker.rs`](../../examples/ed25519_montgomery_h16_hybrid_u5_g32_full_linker.rs),
[`ed25519_montgomery_h16_g32_hybrid_u5_honest_witness.rs`](../../examples/ed25519_montgomery_h16_g32_hybrid_u5_honest_witness.rs),
[`ed25519_h16_public_key_boundary.rs`](../../examples/ed25519_h16_public_key_boundary.rs),
[`ed25519_montgomery_h16_schedule_model.rs`](../../examples/ed25519_montgomery_h16_schedule_model.rs),
[`ed25519_h16_midpoint_glue.rs`](../../examples/ed25519_h16_midpoint_glue.rs),
and [`ed25519_montgomery_h16_envelope_model.rs`](../../examples/ed25519_montgomery_h16_envelope_model.rs).
