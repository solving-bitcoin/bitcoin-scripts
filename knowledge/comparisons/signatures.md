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

| Construction | Authenticated object | Script bytes | Witness bytes | Stack peak | Verification work / missing protocol work |
| --- | --- | ---: | ---: | ---: | --- |
| Lamport 2-bit | One value in 0..3 | 96 | 11 | not recorded | Reject rather than clamp invalid values |
| HORS-like n32/t8 | Explicit subset | 809 | 280 | not recorded | Message-to-index derivation |
| Legacy Wots32 list-pick | 32-byte message | 4,908 | 1,477 | not recorded | 15 hashes for digits below 8, seven otherwise; clamps above-range digits |
| FastWots32 bitwise | 32-byte message | 4,325 | 1,680–1,942 | 334 | Canonical bits; exact suffix hashes; relaxed chain-item length; recovers message |
| FastWots32 bitwise + clear | 32-byte message | 4,208 | 1,938–1,942 | 334 | Branch-fused checksum; consumes message; terminal predicate excluded |
| FastWots32 size lookup | 32-byte message | 4,605 | 1,476–1,542 | 141 | Strict numeric digits; relaxed raw chain-item length; recovers message |
| FastWots32 size lookup + clear | 32-byte message | 4,543 | 1,476–1,542 | 141 | Same chain relation; consumes message; terminal predicate excluded |
| FastWots32 exact | 32-byte message | 5,342 | 1,476–1,542 | 137 | Exact suffix hashes; 498 on the balanced vector |
| FastWots32 strict lookup | 32-byte message | 5,013 | 1,476–1,542 | 143 | 729 hashes on the balanced vector; explicit range check |
| FastWots32 exact + clear | 32-byte message | 5,408 | 1,476–1,542 | 137 | Fused checksum accumulator; terminal predicate excluded |

Locking figures are `fragment-only`; witness figures are full serialized item
vectors. Fast stack peaks are from complete local compositions, but the metric
executor disables the consensus stack check and therefore remains
`research-unlimited`. Separate strict local tests stay below 1,000 items. The
balanced-vector message and all other boundaries are recorded in the
[implementation README](../../src/signatures/winternitz/README.md).

There is no universal winner. The Fast bitwise recovery fragment is 583 bytes
(11.9%) smaller than the legacy list-pick fragment; its terminal form is 700
bytes (14.3%) smaller. Canonical `MINIMALIF` bits drive complementary hash
blocks, a `[8,8,16]` checksum covers the 0–960 range, and recovery rebuilds the
same 64 nibbles. The gain costs 333 witness items and a larger serialized
witness. Like the numeric size profile, it omits an explicit 20-byte check on
each chain item: a maximum digit equality forces 20 bytes, while smaller digits
admit an arbitrary-length HASH160 preimage before the first hash. The
strict-encoding lookup profile retains explicit 20-byte checks at 5,013 bytes.

The legacy and Fast rows are not wire-compatible: chain-start derivation,
message digit order, checksum digit order, and witness pair order differ. All
constructions are one-time. Comparing them as interchangeable signatures also
requires fixing key/public commitment cost, forgery target, durable reuse
policy, raw ScriptNum canonicality, whether the recovered value must remain on
the stack, and whether tapscript `MINIMALIF` is available.
