# Signature verification and one-time authentication

## Point locks

| Construction | Script family | Script bytes | Revelation data | Setup / security boundary |
| --- | --- | ---: | ---: | --- |
| Schnorr adaptor signature | Tapscript | 34 for the ordinary x-only-key/checksig leaf | 66 for a default 64-byte signature | Interactive adaptor transcript; discrete-log/adaptor security |
| ECDSA `G/2` small-R | Legacy, P2SH, or P2WSH | 40 | 62 representative and maximum | Non-interactive; conservatively about 80-bit security, not locally established |
| Three-check ECDSA | Bare legacy or P2SH | 79 | 60-byte representative signature; 61-byte bare scriptSig | `T` alone; DLP hiding and related-scriptCode reduced-sighash collision resistance |
| Committed ECDSA | Legacy or P2SH only | 71 | 73 representative, at most 74 for low-S | Off-chain ZK proof of the SHA-256/DER-r relation; SHA-256 binding |

All rows are complete success predicates but exclude refund branches and
wrapper/control-block costs. The first row is only the ordinary on-chain
BIP340 check; adaptor creation and validation are off chain. The small-R row
uses the 21-byte x-coordinate of `G/2`. The committed row hashes the exact
`DER(r,s) || 0x03` item and relies on the pre-SegWit SIGHASH_SINGLE bug; it is
not a P2WSH construction. The three-check row is a legacy scriptSig boundary,
not witness serialization; its size guard eliminates the `r+n` coordinate
case rather than enforcing a small nonce. See the
[point-lock page](../primitives/point-locks.md) for extraction equations and
evidence qualifications.

## Secp256k1 Schnorr

| Construction | Public-input boundary | Script bytes | Witness bytes/items | Stack peak | Execution |
| --- | --- | ---: | ---: | ---: | --- |
| Native `OP_CHECKSIG` | Spend-time BIP340 signature and transaction digest | 34-byte x-only-key/checksig template, excluding spend context | signature-dependent | signature-dependent | consensus opcode; not measured here |
| Explicit affine CSFS | Public key fixed; 32-byte message and signature selected in witness | 8,292,228 | 81,740 / 32,556 | 33,589 | `research-unlimited`; known consensus-incompatible resource use |
| Explicit CSFS + conceptual `2^32` low-`s` taptree | As above, with one 32-bit signature chunk fixed by the selected leaf | 7,850,893 representative leaf | 77,869 arithmetic/input witness; depth-32 control block adds 1,026 versus depth zero | not remeasured; still far above 1,000 | `research-unlimited`; full tree not constructed |
| Native-field instance proof | Key, 32-byte message, and signature fixed before leaf generation | 58,596 | 1,039 / 346 | 882 | strict local tapscript; unclassified deployment |

These are not substitutes on the same boundary. The explicit CSFS row really
does place `r`, `s`, and the message in the witness, computes the tagged hash,
validates the supplied even nonce, and checks `sG-eP=R`; its size, stack, and
weight make it a research circuit rather than a deployable opcode replacement.
The native-field instance construction is useful only when a protocol needs an
explicit, inspectable field certificate for an already-fixed BIP340 instance.
Its GLV/wNAF/Jacobian engine runs in the trusted deterministic generator;
Script certifies only the final affine equation. Ordinary transaction-context
signatures should use `OP_CHECKSIG`.

The gigantic-taptree row moves four of the generator scalar's fixed-position
windows into leaf selection. The locally executed representative saves 441,335
script bytes and 3,871 arithmetic-witness bytes; after the 1,026-byte serialized
control-path penalty, the revealed-path saving is 444,180 bytes. The conceptual
tree requires `2^32` distinct leaves and roughly 33.7 PB of naïve leaf material,
so this is a lookup thought experiment, not a deployment path.

Within the explicit field certificate, the retained 2M/1S schedule has a
57,241-byte raw-certified core. It is 5,978 bytes smaller than a three-general-
product shared batch and 8,075 bytes smaller than three isolated general
multipliers. The specialized square also lowers peak stack use from 993 to 882.

## Custom Ed25519-style BLAKE3 slope verifier

These rows share one fixed public key and one fixed 32-byte benchmark message,
use digest bytes 0 through 15 of a custom BLAKE3 transcript as the challenge,
and end in a clean truth predicate. They are **not RFC 8032 Ed25519** and do
not authorize a Bitcoin transaction. The disclosed fixture secret
`a=987654321` makes each exact benchmark leaf forgeable.

| Configuration | Policy-produced Script | Exact argument witness | Entry data / auxiliary hints | Combined stack peak |
| --- | ---: | ---: | --- | ---: |
| Historical H16/G29 quotient carriers | 3,828,057-byte policy-compliant projection | 3,958 bytes | 704 data + 88 hints = 792 coexisting items; 2 hints per each of 44 transitions | 999 strict peak-equivalent schedule |
| Historical H16/G29 q-free | 3,896,335-byte policy-compliant projection | 3,561 bytes | 712 coexisting data items; 0 hints per transition and total | 912 analytical |
| **Current H16/G32 hybrid-u5 q-free** | **2,834,653 bytes** | **3,863 bytes** | **803 coexisting data items; 0 hints per each of 47 transitions and total** | **995 analytical** |

The current G32 leaf uses 31 response transitions and 16 challenge
transitions, a canonical 51-digit radix-32 `Rtilde` hash boundary,
symmetry-specialized squaring, and two phase-local Script-authored power pools.
Those pools are constants created by the locking Script, not witness hints, and
are included in the 995-item main-plus-alt-stack account. Its disjoint
component sizes sum exactly to 2,834,653 bytes: response 1,821,324; challenge
945,029; BLAKE3 67,137; recoder 389; and scalar validator 774. The whole
leaf exceeds 32 KiB and therefore uses `CompileOptions::NONE`; the reported
whole size is unoptimized by upstream fixpoint passes.

The current serialization contains 1,663,690 static non-push opcodes and is
165,330 bytes (5.511%) smaller than the `f7bb0c2` G32 baseline. Partial-word
decoding, fused sparse passes, Horner quotient reduction, the larger first
power pool, and endpoint table selection account for that reduction.

The two G29 totals are additive projections after applying the current hash
compilation policy; their corrected whole Scripts were not regenerated. Their
superseded pre-policy whole serializations were 3,826,949 and 3,895,323 bytes.

At that size, the exact fixture produces a 2,838,555-byte complete witness, a
2,838,933-WU target, and a 2,839,701-WU minimum-block projection, leaving
1,160,299 WU below four million. This is generation and serialization evidence,
not deployment evidence: the complete multi-megabyte Script has not been
executed or checked by Bitcoin Core. The overall construction is `inspected`
and `unclassified`; its square, transition, routing, hash, and host-witness
components have focused local or differential validation. See the
[construction page](../primitives/ed25519-blake3-montgomery-slope.md) for the
exact boundary and security obligations.

## One-time authentication

The original Winternitz rows below use HASH160 with full-width 20-byte starts
and nodes. Optional `Preimage16` comparisons follow the hash comparison.

| Construction | Authenticated object | Script bytes | Witness bytes (zero / upper bound) | Stack peak | Verification work / missing protocol work |
| --- | --- | ---: | ---: | ---: | --- |
| Lamport 2-bit | One value in 0..3 | 96 | 11 | not recorded | Reject rather than clamp invalid values |
| HORS-like n32/t8 | Explicit subset | 809 | 280 | not recorded | Message-to-index derivation |
| Legacy Wots32 list-pick | 32-byte message | 4,908 | 1,477 / 1,542 | 143 | 15 hashes for digits below 8, seven otherwise; clamps above-range digits |
| Legacy Wots32 list-pick + clear | 32-byte message | 4,844 | 1,477 / 1,542 | 143 | Direct checksum reduction; consumes message; terminal predicate excluded |
| FastWots32 clamped lookup | 32-byte message | 4,465 | 1,476 / 1,542 | 143 | Legacy-style upper saturation; recovers authenticated clamped digits |
| FastWots32 clamped lookup + clear | 32-byte message | 4,403 | 1,476 / 1,542 | 143 | Same clamped relation; consumes message; terminal predicate excluded |
| FastWots32 bitwise | 32-byte message | 4,325 | 1,680 / 1,942 | 334 | Canonical bits; exact suffix hashes; relaxed chain-item length; recovers message |
| FastWots32 bitwise + clear | 32-byte message | 4,206 | 1,938 / 1,942 | 333 | Branch-fused checksum; consumes message; terminal predicate excluded |
| FastWots32 size lookup | 32-byte message | 4,599 | 1,476 / 1,542 | 143 | Strict numeric digits; relaxed raw chain-item length; recovers message |
| FastWots32 size lookup + clear | 32-byte message | 4,537 | 1,476 / 1,542 | 143 | Same chain relation; consumes message; terminal predicate excluded |
| FastWots32 exact | 32-byte message | 5,267 | 1,476 / 1,542 | 137 | Residual-digit exact suffix hashes; 498 on the balanced vector |
| FastWots32 strict lookup | 32-byte message | 4,934 | 1,476 / 1,542 | 143 | 733 hashes on the balanced vector; explicit range check |
| FastWots32 exact + clear | 32-byte message | 5,205 | 1,476 / 1,542 | 137 | Staged digits and Horner checksum; terminal predicate excluded |

Locking figures are `fragment-only`; witness figures are full serialized item
vectors. Recorded Winternitz stack peaks are from complete local compositions, but the metric
executor disables the consensus stack check and therefore remains
`research-unlimited`. Separate strict local tests stay below 1,000 items. The
balanced-vector message and all other boundaries are recorded in the
[implementation README](../../src/signatures/winternitz/README.md).

There is no universal winner. The Fast bitwise recovery fragment is 583 bytes
(11.9%) smaller than the legacy list-pick recovery fragment; its terminal form
is 638 bytes (13.2%) smaller than the legacy terminal fragment. Canonical
`MINIMALIF` bits drive complementary hash
blocks, a `[8,8,16]` checksum covers the 0–960 range, and recovery rebuilds the
same 64 nibbles. The gain costs 333 witness items and a larger serialized
witness. Like the numeric size profile, it omits an explicit 20-byte check on
each chain item: a maximum digit equality forces 20 bytes, while smaller digits
admit an arbitrary-length HASH160 preimage before the first hash. The
strict-encoding lookup profile retains explicit 20-byte checks at 4,934 bytes.

The exact ladder and staged checksum preserve existing Fast witnesses while
reducing recovery by 75 bytes and terminal verification by 203 bytes.
Full tables replace the half-table selector for checksum widths up to three
bits. The strict lookup also removes its redundant lower-bound check while
retaining the upper bound and `OP_PICK`'s negative-index rejection. This
reduces the HASH160 clamped/strict numeric fragments by six bytes and strict
lookup by 73 bytes; the balanced lookup vector executes 733 hashes rather
than 729, an execution-work tradeoff for smaller scripts. Numeric size/clamped
peaks rise from 141 to 143 items because their narrow checksum table grows.
All listed Fast profiles require zero auxiliary hint items; the 134 numeric or
333 bitwise data items are present together at script entry.

Legacy terminal verification also avoids recovering digits that it will
immediately discard, reducing its locking fragment by 96 bytes. This preserves
the legacy clamped-digit relation and its 134-item witness layout with zero
auxiliary hints.

For on-chain byte cost, the locking fragment and serialized data witness must
be added. The zero-message and signer-node upper-bound sums are:

| FastWots32 profile | Script + zero-message witness | Script + maximum signer-node witness |
| --- | ---: | ---: |
| Clamped lookup recovery | 5,941 | 6,007 |
| Clamped lookup terminal | 5,879 | 5,945 |
| Numeric size recovery | 6,075 | 6,141 |
| Bitwise recovery | 6,005 | 6,267 |
| Numeric size terminal | 6,013 | 6,079 |
| Bitwise terminal | 6,144 | 6,148 |

Clamped lookup minimizes both stated total-cost boundaries. It accepts an
above-range raw digit as the chain maximum and authenticates that clamped
value in the checksum, matching the legacy behavior; strict upper rejection
remains a separate profile. The witness format and honest recovered message
are unchanged. Ordering can depend on the message: for `[0xff; 32]`, bitwise
terminal totals 5,892 bytes versus 5,942 clamped. These sums exclude the same
script/control-block framing, consumer, and transaction overhead; they are not
complete transaction weights.

The legacy and Fast rows are not wire-compatible: chain-start derivation,
message digit order, checksum digit order, and witness pair order differ. All
constructions are one-time. Comparing them as interchangeable signatures also
requires fixing key/public commitment cost, forgery target, durable reuse
policy, raw ScriptNum canonicality, whether the recovered value must remain on
the stack, and whether tapscript `MINIMALIF` is available.

### HASH160 versus SHA-256 Winternitz

Every Fast profile also supports `FastWinternitz<32, Sha256>`. SHA-256 uses
32-byte nodes and endpoints, while HASH160 uses 20. These rows use the
explicit `FullWidth` start mode. The following zero-message comparisons include fragment plus serialized data
witness, excluding the same terminal consumer and transaction framing:

| Profile | HASH160 sum | SHA-256 sum | SHA-256 signer-node bound |
| --- | ---: | ---: | ---: |
| Clamped recovery | 5,941 | 7,289 | 7,355 |
| Clamped terminal | 5,879 | 7,227 | 7,293 |
| Bitwise recovery | 6,005 | 7,152 | 7,414 |
| Bitwise terminal | 6,144 | 7,291 | 7,295 |

HASH160 is cheaper for matching profiles. SHA-256's larger hash width offers
higher idealized hash-level security bounds, but is not a WOTS+ security
claim. Adjacent SHA-256 steps compile into HASH256: exact/bitwise profiles
save 461 script bytes from pair fusion, lookup profiles 260. This makes
bitwise the lowest zero-message recovery cost within SHA-256; clamped is the
lowest zero-message terminal cost. Keys are hash-typed and domain-separated;
changing the hash changes both keys and witnesses.

The SHA-256 numeric and bitwise witnesses still have 134 and 333 coexisting
entry data items and zero auxiliary hints. Corresponding stack peaks are
unchanged (137–143 numeric, 334/333 bitwise). All metric rows remain
`research-unlimited` under the stack-limit-disabled tapscript helper, with
separate strict-stack tests and no Core/policy validation. See the
[full hash comparison](../../src/signatures/winternitz/base16/README.md#sha-256-onchain-comparison)
for script, witness, static opcode counts, security assumptions and boundaries.

### SHA-256 chains with smaller endpoint commitments

`FastWinternitz<32, Sha256Hash160>` retains 32-byte SHA-256 intermediate nodes
and uses a final HASH160 to produce each 20-byte public commitment. This
combines SHA256-pair fusion with shorter endpoint pushes. The hash choice has
a fresh key-derivation domain. All existing Fast verifier profiles support it;
the additional strided terminal profile consumes one upper-clamped quotient,
one chain node, and one canonical low bit per chain.

For seed `[0x42;32]` and message `[0;32]`, the same policy-produced fragment
and serialized data-witness boundary gives:

| Hybrid terminal profile | Script bytes | FullWidth witness / sum | Preimage16 witness / sum | Entry data items / hints | Combined peak |
| --- | ---: | ---: | ---: | ---: | ---: |
| Clamped | 4,210 | 2,280 / 6,490 | 1,224 / 5,434 | 134 / 0 | 143 |
| Bitwise | 3,812 | 2,742 / 6,554 | 1,686 / 5,498 | 333 / 0 | 333 |
| Strided | 3,961 | 2,413 / 6,374 | 1,357 / 5,318 | 201 / 0 | 209 |

The bitwise fragment saves 394 locking bytes relative to HASH160 bitwise.
The strided profile trades 149 additional locking bytes for a smaller witness
and stack. With Preimage16, its 5,318-byte zero-message sum is 297 bytes below
the 5,615-byte HASH160 clamped terminal sum. The smallest locking fragment and
the smallest measured zero-message total are therefore different choices.
FullWidth hybrid totals exceed HASH160's matching zero-message costs because
32-byte openings outweigh the locking savings. These are measured fixture
comparisons, not uniform-message averages or global optima.

All data items coexist at entry and are included in the combined peaks,
together with temporary tables and checksum state. There are zero auxiliary
hints per invocation. Both profiles consume the message and require a final
protocol predicate; unrelated state still counts against the 1,000-item
limit. Metrics remain `locally-reproduced` and `research-unlimited` under the
stack-limit-disabled tapscript helper; strict-stack tests are separate and
do not establish Core consensus or policy validation.

The hybrid commitment retains a 160-bit output and about 80-bit generic
collision bound, rather than the 128-bit collision bound of full SHA-256
commitments. Size-oriented hybrid verifiers permit arbitrary raw node lengths
even at the maximum digit, because the final commitment hash always executes.
Strict exact/lookup retain raw-width checks. Strided authenticates the same
clamped quotient and canonical bit in the chain selector and checksum;
protocols requiring rejection of all raw numeric aliases need a strict
profile. The security analysis and message distribution remain part of the
cost comparison.


### Initial-secret width

`FastWinternitz<32, H, Preimage16>` shortens only digit-zero signature values
to 16 bytes. Every hash output retains the selected native width, and public
commitments retain their selected width. It is a separately domain-separated mode; the explicit `FullWidth`
keys and witnesses remain compatible with the tables above.

For the same zero-message fixture, 66 of 67 digits are zero. The following
measurements use the same fragment plus serialized data-witness boundary and
excluded transaction framing:

| Clamped terminal mode | Script bytes | Witness bytes | Sum | Saving from FullWidth |
| --- | ---: | ---: | ---: | ---: |
| HASH160 + Preimage16 | 4,403 | 1,212 | 5,615 | 264 |
| SHA-256 + Preimage16 | 4,947 | 1,224 | 6,171 | 1,056 |

Numeric size, clamped, and bitwise profiles need no new width validation and
retain their existing stack schedules. Strict exact and lookup profiles pay
469 extra script bytes for digit-dependent width checks, so a
smaller witness need not lower their total cost. Savings for other messages
are four bytes per zero digit with HASH160 and 16 with SHA-256, counting the
checksum; the all-zero fixture is not a uniform-message average.

Numeric signatures retain 134 coexisting entry data items and bitwise 333,
with zero auxiliary hints in every profile. Narrower items do not reduce
these counts or relax the 1,000-item combined stack bound. Consult the
[Fast primitive page](../primitives/winternitz-fast-base16.md#default-16-byte-initial-secrets)
for metric evidence when comparing profiles. The table is `locally-reproduced`
and `research-unlimited`: the tapscript metric helper disables the stack
limit. It does not establish Core consensus or policy validation.

The smaller secret restricts generic single-target classical search to at
most 128 bits, with concrete chain/multi-target losses still unresolved. It
does not change the native hash-output collision bounds (roughly 80 bits for
HASH160, 128 for SHA-256) or make the two security profiles interchangeable.

### Terminal verification of unchanged 20-byte messages

The current smaller construction is
[constant-composition Winternitz](../primitives/winternitz-constant-composition20.md).
It assigns 49 independent keys to a radix-25 digit multiset with counts
`[1 × 15, 2 × 7, 3 × 2, 14]`. Fixed digit slots replace per-chain digit
lookups and a sum accumulator. Fourteen maximum-digit keys remain implicit;
35 openings and 35 pool selectors authenticate the assignment. Host ranking
preserves every unchanged 20-byte input without search or truncation.

| Constant-composition terminal profile | Script bytes | Attained maximum signer witness | Maximum combined bytes | Entry items / hints | Combined peak |
| --- | ---: | ---: | ---: | ---: | ---: |
| HASH160/Preimage16, isolated | 1,598 | 802 | 2,400 | 70 / 0 | 119 |
| HASH160/Preimage16, composable | 1,696 | 802 | 2,498 | 70 / 0 | 120 |
| HASH160/Preimage16, bounded | 1,767 | 802 | 2,569 | 70 / 0 | 121 |
| SHA-256/HASH160/Preimage16, isolated | 1,468 | 1,210 | 2,678 | 70 / 0 | 119 |
| SHA-256/Preimage16, isolated | 2,021 | 1,210 | 3,231 | 70 / 0 | 119 |

The isolated fragment requires exactly 70 items on the entire main stack;
its entry-depth guard makes the public-key pool the whole main stack before
each `OP_ROLL`. The composable variants preserve unrelated main and alt state;
isolated verification preserves alt state only. HASH160 wins the combined
objective, while the hybrid has the smallest locking fragment. These are
`locally-reproduced`, `research-unlimited` measurements with the same witness
serialization and excluded terminal/framing costs as below. Strict local
tests remain `unclassified`; one exact out-of-pool `OP_ROLL` boundary is
recorded as a pinned-interpreter panic, not a successful rejection. Script
checks the composition without enforcing the host's rank-below-`2^160` image
or returning bytes. The search is bounded, not a proof of global optimality;
see [NR-042](../negative-results/index.md#nr-042-constant-composition-search-and-endpoint-sharing-limits).

The following fixed-sum comparison records the earlier 20-byte frontier.
The 20-byte comparison has a different message size and is separate from the
32-byte tables above. `ConstantSumWinternitz20` ranks the unchanged input into
41 digits with radices `[16 × 32, 18 × 4, 20 × 5]` and sum 321. There are no
checksum chains. The host encoder is reversible; neither terminal verifier
returns the original bytes or checks the host's rank-below-`2^160` condition.

The same HASH160/Preimage16 seed `[0x42;32]`, final compilation policy, and
fragment-plus-serialized-signature boundary give:

| 20-byte terminal profile | Script bytes | Maximum signer witness | Maximum script + witness | Complete entry items / hints | Combined peak |
| --- | ---: | ---: | ---: | ---: | ---: |
| Fast base-16 clamped | 2,819 | 990 | 3,809 | 86 / 0 | 95 |
| Constant-sum default | 2,680 | 944 | 3,624 | 82 / 0 | 93 |

The constant-sum result saves 139 locking bytes and 185 bytes at the maximum
signer-witness boundary. The zero, all-`ff`, and varied-byte fixtures use
839, 934, and 924 witness bytes respectively. Exact integer counting over all
`2^160` message ranks yields mean witness approximately 931.841783370768
bytes, hence mean total 3,611.841783370768. The baseline's exact mean witness
is approximately 976.262466089252 bytes, giving mean total
3,795.262466089252. The new profile saves approximately 183.420682718484
bytes, or 4.83%, in that uniform-message expectation. Both means are rounded
displays of exact integer/rational counts, not sampled estimates.
Witness maxima refer to signer encodings, not accepted adversarial raw items.

The SHA-256/HASH160 constant-sum variant has a shorter 2,381-byte script but
larger native openings: its maximum witness is 1,517 bytes, totaling 3,898.
It uses 123 entry items, zero hints, and peaks at 133. The plain SHA-256
variant totals 4,349 maximum bytes from a 2,832-byte fragment and the same
witness. HASH160 therefore wins the measured mean/maximum total objective
within this earlier fixed-sum family; the hybrid wins its locking-script
size alone. The explicit bounded HASH160
method costs 2,853 script bytes and has a 3,797-byte maximum combined total.

The default relation intentionally omits individual upper-digit guards.
An overflow lookup can select a matching preceding stack value, but its raw
digit still enters the fixed sum. Under honestly generated keys and a
canonical one-time signature, any distinct same-sum vector must decrease
another coordinate; that coordinate is in range and needs an earlier chain
node. This is an `inspected` local whole-vector inference, not a claim that
each overflow coordinate is locally authenticated. The explicit bounded
method adds radix rejection and retains the same host-rank limitation and
relaxed raw node-width relation.
With all signing secrets, an accepted out-of-radix same-sum vector can be
constructed; the unbounded method is not a boxed-code membership check.

All items coexist at entry and every invocation has zero auxiliary hints.
The combined peaks include temporary tables and sum state. The caller's
terminal predicate, script framing, control block, and transaction overhead
are excluded equally. Metrics are `locally-reproduced` and
`research-unlimited` under the stack-limit-disabled tapscript helper with
`OP_TRUE`; separate strict-stack tests remain `unclassified` deployment
evidence. No Core consensus or policy acceptance is established. The pinned
executor's out-of-entire-stack `OP_PICK` panic limits malformed-index coverage.

See the [constant-sum primitive](../primitives/winternitz-constant-sum20.md)
for exact code capacity, public API, proof scope, hash alternatives,
independent Python reproduction, and [NR-041](../negative-results/index.md#nr-041-20-byte-winternitz-search-and-overflow-relation-boundaries)
for the restricted radix search and rejected zero-fixture-only improvements.

The constant-composition verifier intentionally has no Script byte-recovery
row. Its host-side rank decoder is not included in the authentication costs;
the missing consumer boundary is tracked by [NR-048](../negative-results/index.md#nr-048-constant-composition-byte-recovery-is-not-yet-a-composable-script-primitive)
and [OP-021](../open-problems.md#op-021--constant-composition-script-decoder).
