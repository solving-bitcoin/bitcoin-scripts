# Point locks

A point lock is the discrete-log analogue of a hash lock. Its public instance
is a secp256k1 point `T = tG`; a successful spend publishes enough signature
material for an observer to recover `t`. The catalog records constructions
and candidates with different setup and security boundaries.

Point-label extraction and verifier-label privacy are separate checks. The
[public algebraic AND probe](../../research/pointlocks-2026-09-17/public-algebraic-gate.md)
has publicly verifiable point equations and correct evaluation, yet one
opening reveals a complete alternative input's labels, even with distinct
commitments. See [NR-069](../negative-results/public-algebraic-gate-labels.md);
output authenticity alone does not meet the one-message label requirement.

The [vector-label extension](../../research/pointlocks-2026-09-17/vector-label-gates.md)
does meet both properties for one binary gate under its stated discrete-log
assumption, with two scalar coordinates per input label. Its public checker
needs no secret encoding key. The cost of delivering those coordinates and
full-verifier composition remain open; a direct guarded legacy wrapper costs
at least 241,664 vB for one layer on 2,048 message bits (NR-072).

The [shared-coordinate improvement](../../research/pointlocks-2026-09-17/shared-vector-gates.md)
reduces that layer's scalar count by 25%, to a still-too-large 181,248-vB
legacy signature-push floor. It proves a tight N-1-of-N boundary for linear
binary-label lookup: correlated full t-subset alphabets with N>=t+2 cannot
supply the same interface while preserving candidate-label privacy (NR-073).
The current nonlinear garbled decoder is outside this bound.

The [relative-log follow-up](../../research/pointlocks-2026-09-17/ratio-labels.md)
tests the nonlinear-looking label a/b with publicly affine point endpoints.
It requires both scalar forms to be opened, apart from publicly recognizable
constant ratios (NR-074). This leaves other nonlinear metadata and native
relative-log openings as distinct, unresolved interfaces.

The [DH quartet selector](../../research/pointlocks-2026-09-17/dh-quartet-labels.md)
does change that interface: one scalar opening selects two secret group-valued
labels. Its correlated profile publicly excludes exact output aliases and
has a one-opening square-CDH argument for honest private setup. These are
point values, not their discrete logs. Public binding to a composable garbled
verifier remains unresolved; NR-075 limits a direct
independent-coordinate extension to high-rate subset pools.

The [fixed-digest nonce wrapper](../../research/pointlocks-2026-09-17/fixed-digest-nonce.md)
now delivers the quartet's target scalars in small native legacy spends.
Three common-key checks force the SINGLE-bug digest under a reduced-sighash
collision assumption; one derived-key check fixes the nonce point. Core
reproduces 23 positive and eight negative cases. The 86-byte single lock and
199-byte quartet are nonstandard, and the quartet's explicit candidate-key
pushes alone cost 139,264 legacy vB for 2,048 bits. This experimental adapter
does not supply a full publication or setup benchmark.

The [correlated quadratic-label analysis](../../research/pointlocks-2026-09-17/correlated-quadratic-labels.md)
also closes the correlated full-subset extension of that DH interface. If
every t-subset leaves the other candidate scalars unavailable, two fixed
hidden quadratic point labels require N-t<=3. Forty-four exact field ranks
and 34 curve views corroborate the degree argument and its positive boundary.
Thus 5-of-54 needs another label interface, extra nonlinear metadata, or a
different admissible choice family (NR-077).

## Comparison objective

Compare the on-chain predicate, setup interaction, extraction relation, and
security assumptions for a single point revelation. Locking-script and witness
figures include only the point-lock success branch, not timeout/refund branches,
Taproot control blocks, P2SH wrappers, or complete transactions.

| Construction | Setup | On-chain primitive | Principal drawback |
| --- | --- | --- | --- |
| Schnorr adaptor signature | Interactive; counterparty creates and verifies an encrypted signature | Ordinary tapscript BIP340 `OP_CHECKSIG` | Requires a valid adaptor transcript before funding |
| ECDSA `G/2` small-R | Non-interactive after publishing `T` | Signature length plus legacy ECDSA `OP_CHECKSIG` | Total-length security under adaptive digest search is unproved |
| Three-check ECDSA | Non-interactive; constructed from `T` alone | One signature, two legacy `scriptCode` views, and related keys `T,Q` | Non-standard legacy-only construction; reduced-sighash collision assumption |
| Two-check ECDSA candidate | Non-interactive; constructed from `T` alone | One signature and related keys `T,Q` in one legacy `scriptCode` | Conditional experimental variant: arbitrary-target ordinary-transcript resistance is unproved |
| Committed ECDSA | Non-interactive on chain; spender proves the commitment relation off chain during setup | SHA-256 equality plus legacy ECDSA `OP_CHECKSIG` | Requires an off-chain ZK proof and the legacy SIGHASH_SINGLE bug |
| Sum-key ECDSA | Non-interactive algebraic setup; common-G version generates fresh targets | Same signature under distinct keys whose sum is the locked point | Compact shared-key setup cannot directly reuse arbitrary existing targets |

## Sum-key ECDSA with a common generator

The [sum-key implementation](../../src/signatures/pointlocks/sum_key/README.md)
changes what is locked: the target is `T=P+Q`, rather than either individual
verification key. A signature longer than 57 bytes accepted under distinct
`P,Q` at the same actual digest `z` forces opposite verification nonce points.
Adding the verification equations gives `2zG+rT=0`, hence `t=-2z/r mod n`.
This extracts for ordinary digests as well as the SINGLE constant; the earlier
two-check scheme's ordinary-digest gap is not inherited.

Set `Q=G` across every candidate. For an independent secret nonce `k`, compute
`r=x(kG) mod n`, `t=-2C/r`, `T=tG`, `P=T-G`, and `s=(C+r)/k`, where
`C=2^248`. The signature verifies under both `G` and `P`. Public setup rejects
`P=G`, `P=-G`, duplicate targets, and duplicate table commitments. It requires
no ZKP or interactive adaptor transcript, but generates the labels rather
than opening arbitrary pre-existing points with a common G key.

The standalone predicate is 76 bytes, with one signature item, zero hints,
and a combined-stack peak of three. Its deterministic P2SH transaction
fixtures are `differentially-validated` and `policy-validated` in the
[Core report](../../research/pointlocks-2026-09-17/sum_key_core_check.json).
The [shared-key multisig pools](../../research/pointlocks-2026-09-17/common-key-multisig.md)
and [single-key-hash lookup pools](../../research/pointlocks-2026-09-17/sum-lookup.md)
reduce publication costs further. Hash lookup authenticates `P`, not the
signature; it requires second-preimage resistance for an honestly fixed key,
and collision binding against a malicious setup chooser. Ordinary HASH160
birthday work is about `2^80`; the ECDSA equations do not remove that attack.

See the [complete encoding accounting](../../research/pointlocks-2026-09-17/encoding-optimization.md)
for recoverable 256-byte encodings, actual funding-output costs, and relay-size
splitting. Variable-cardinality pools additionally need a mechanism that prevents
third-party erasure of optional revelations. Checking the global count only
after publication is insufficient: the same transaction authorization can
remain valid after changing other inputs' scriptSigs. Execution evidence does not establish full BitVM3
protocol integration.

The [bare publication validation](../../research/pointlocks-2026-09-17/bare-publication.md)
uses 79 seven-of-48 pools: **161,382 vB actual**, **161,560 vB canonical maximum**,
with all output creation/consumption included. Core validates funding and 11
positive spending variants and rejects 15 negative controls. The three complete
message fixtures each recover 553 scalars and 256 bytes. It is
`differentially-validated` and `consensus-validated`, with default policy rejection.
Per pool: 1,232-byte script, seven hints, 21 entry items, combined-stack peak 73;
total hints 553 and entry data 1,659 across independent stacks. Accepted partial
publication and surplus codewords remain application limits.

The [opt-in policy experiment](../../research/pointlocks-2026-09-17/bare-nonstandard-policy.md)
accepts and mines the identical bare publication through a patched Core mempool
with `acceptnonstdtxn=1`. Its 11 valid controls pass the modified policy and 15
invalid controls still fail block consensus. The default-policy branch remains
unchanged; this does not establish public-network relay acceptance.

The [HORS lookup comparison](../../research/pointlocks-2026-09-17/hors-lookup-comparison.md)
extends the old seven-selection scan to ten, giving a **153,125-vB maximum
serialization estimate** for 58 ten-of-57 pools. Local legacy tests pass;
complete publication/Core validation and setup timing are pending. Evidence
is `locally-reproduced`, deployment `unclassified`. The Binohash-style direct
stack layout saves opcodes but costs slightly more total bytes.

The [table-first lookup follow-up](../../research/pointlocks-2026-09-17/clamped-lookup.md)
fits twelve selections in 192 operations. Ten 12-of-67 plus 38 12-of-68 pools
have a **151,176-vB maximum estimate**, including funding and spending. Core
passes 78 individual-pool controls with 282 scalar extractions; full independent
256-byte publication validation and setup timing remain outstanding. Exact
accepted pools are `differentially-validated`, `consensus-validated`; the mixed
publication estimate remains `locally-reproduced`, `unclassified`.

## Sub-100,000-vbyte publication research

The [anchored native candidate](../../research/pointlocks-2026-09-17/anchored-codesep.md)
has a Core-accepted honest256-byte fixture at96,176 vB and a measured66-ms
median for point-lock generation plus checking, excluding VSS/garbling.
General extraction is unresolved. The
[full-consensus follow-up](../../research/pointlocks-2026-09-17/anchored-rounds-limits.md)
confirms256 permitted sighash bytes and65-byte uncompressed/hybrid keys, beyond
the relay-policy subset. Additional rounds exceed the measured layout budget;
see [NR-063](../negative-results/anchored-rounds-and-four-roots.md). Honest
execution evidence must not be read as point-lock soundness.

The [affine-nonce extractor](../../research/pointlocks-2026-09-17/nonce-relation-extraction.md)
adds exact offchain recovery for nondegenerate public relations between two
nonce points, including signed GLV orbits. It changes no onchain bytes or hints.
Unrelated nonces and zero-determinant relations remain outside that theorem;
18 focused helper/wrapper test methods do not establish general extraction.
The anchored search now also covers relations to the anchor's own nonce.

The [cross-key nonce graph](../../research/pointlocks-2026-09-17/cross-key-nonce-extraction.md)
additionally combines signatures across labels. Nondegenerate cycles recover
cases unresolved by every separate per-key check. Eight focused tests and an
offline replay of all 475 native label openings validate the implementation;
an unknown-log six-context control shows why shared nonces alone do not
guarantee full rank. It adds no onchain bytes and is not a general extraction
proof or a new Core validation run.

The [typed-selector optimization](../../research/pointlocks-2026-09-17/typed-selector-layout.md)
has new 94,120-vB five-context and 105,039-vB six-context serialization rows,
with full creation/spending and authorizations included. Core validates small
selector fixtures (24 positive, 14 negative); the full-size rows still contain
placeholder signatures and add no general extraction or setup-time claim.

The [shared-anchor-context variant](../../research/pointlocks-2026-09-17/shared-anchor-context.md)
further reduces the five/six-context estimates to 94,005/103,345 vB. Separate
Core fixtures validate six short contexts per label (24 positive, 14 negative).
The first short check shares scriptCode with the anchor; this preserves
distinct short contexts but does not establish unknown-nonce extraction.

The [round-major layout](../../research/pointlocks-2026-09-17/round-major-contexts.md)
shares each separator across labels and reduces five/six-context serialization
to 90,114/98,334 vB including all creation and consumption. Core accepts 18
positive cases and rejects 19 malformed cases, including the full 5-of-54
pool at 201 opcodes. The [full native publication](../../research/pointlocks-2026-09-17/round-major-publication.md)
now uses actual signatures at98,323 vB and independently recovers475 scalars
and256 bytes. Point-lock-only setup/checking measures89.63 ms median with15
workers,154.47 ms on the first sample. General extraction and publicly
checked label/garbling setup remain open.

The [matching 95-pool decoder](../../research/pointlocks-2026-09-17/round-major-message-decoder.md)
now takes those 475 scalars through encrypted shares and garbled ranks to
2,048 message labels. Every complete valid codeword has a defined modulo
2^2048 interpretation. Fresh generation measures 364.16 ms median, or
733.29 ms including an audit with all secrets. It adds no onchain bytes or
hints; public setup verification and complete-protocol correctness remain open.

The [participation follow-up](../../research/pointlocks-2026-09-17/pool-participation.md)
also confirms four Core-accepted one-pool spends of that exact instance,
leaving 94 pools unopened. Retained-key ALL authorization does not itself
enforce complete publication; see [NR-070](../negative-results/pointlock-pool-participation.md).

A [dual-anchor/sum-key replacement](../../research/pointlocks-2026-09-17/dual-anchor-sum-collapse.md)
has a consensus-validated public-opening counterexample: the exact sum-key
check extracts an already public dynamic key sum, not the target scalar.
See [NR-068](../negative-results/dual-anchor-public-opening.md). This is a
separate rejected construction, not a cap60 extraction counterexample.

The [distinct-target follow-up](../../research/pointlocks-2026-09-17/two-target-anchors.md)
has exact two-label extraction, but prescribes the native signature nonce's
x-coordinate. Its 31 synthetic curve examples do not provide efficient
native openings; see [NR-071](../negative-results/two-target-anchor-opening.md).

The [direct-key variation](../../research/pointlocks-2026-09-17/direct-context.md)
fits six checks into a 98,706-vB Core-validated honest publication. Removing
the anchor permits staged searches under different sighash modes; it is not
an established security improvement. Point-lock-only setup/checking measures
46.59 ms median, with a 130.23-ms first sample. See
[NR-065](../negative-results/direct-context-staged-grinding.md).

The [subset translation](../../research/pointlocks-2026-09-17/subset-translation.md)
now maps the honest report's 460 scalars to 2,070 binary rank labels. Its full
table generation and opened-table audit take 1.590 s median, but that audit
requires all secrets and excludes VSS/garbled copies. Malicious ciphertext
binding and the public-zero-label shortcut are recorded in
[NR-064](../negative-results/subset-translation-binding.md).

A [threshold-complement bridge](../../research/pointlocks-2026-09-17/complement-translation.md)
now replaces the subset-row table with encrypted Shamir shares. The 460 cached
scalar openings supply one label for each of 5,750 membership wires; actual
garbled per-pool decoders recover the rank labels and original payload.
Generation plus an all-secrets audit takes 72.64 ms median including those
decoders. This is still not public setup verification, a complete garbled
verifier, or a repair for missing point-lock extraction. Omitting diagonal
shares avoids the earlier public-zero-label leak; affine public masks instead
expose all scalars in a focused counterexample.

The [total message-decoder extension](../../research/pointlocks-2026-09-17/total-message-decoder.md)
now turns the 115 garbled ranks into 2,048 message labels, using modulo 2^2048
to give every complete valid codeword a unique message. Generation is 341.82 ms
median; auditing with all secrets is 348.66 ms, with a combined median of
701.05 ms. This offchain extension adds no native bytes or hints. Public setup
binding, general extraction and full verifier/transaction-graph integration
remain unresolved.

The [fixed four-root orbit candidate](../../research/pointlocks-2026-09-17/four-root-orbit.md)
replaces the earlier weak inverse-r label with a full scalar committed through
an unordered point set. Extraction at the constant digest is exact; other
digests require an explicit random-oracle assumption. Even its generously
compressed explicit legacy table has a131,601-vB floor before signatures or
transactions. The [key-sharing analysis](../../research/pointlocks-2026-09-17/orbit-key-sharing.md)
also bounds ideal reuse: each key belongs to at most two canonical labels,
leaving a 116,700-vB floor for four checks and 40-byte openings. Two overlapping
openings reveal the base ratio and can disclose unselected labels in the same
component. These are scoped algebra and representation results, not a native
construction. The [graph/privacy refinement](../../research/pointlocks-2026-09-17/orbit-private-sharing-bound.md)
also excludes the hypothetical two-key, 40-byte-opening inventory: at least
110,865 vB with graph-consistent reuse, or 116,643 vB when known alternative
scalar disclosure is forbidden. Separately, [NR-066](../negative-results/linear-complement-labels.md)
excludes the direct scalar-linear repair of threshold-complement label delivery
for the large n/t profiles, without excluding nonlinear bridges.

The [direct binary-label rank bound](../../research/pointlocks-2026-09-17/binary-linear-label-rank.md)
also excludes a purely linear shortcut from 460 field openings to the complete
2,048-bit authenticated label interface. Privacy forces those selected labels
to have rank 2,048. With one guarded legacy sum-key signature per opening,
even signature pushes alone exceed 100,000 vB. This does not constrain the
existing nonlinear garbled decoder or every alternative input interface.

The [DDH batch-select probe](../../research/pointlocks-2026-09-17/ddh-batch-select.md)
compresses a full input-label vector into scalar aggregate keys offchain. Its
512-byte raw opening profile excludes all Bitcoin machinery. Public setup
verification and native aggregate extraction remain absent. Feeding it
separately opened common-shift point scalars instead reveals both labels and
the free-XOR offset; [NR-067](../negative-results/ddh-batch-select-share-disclosure.md)
reproduces that composition failure. This does not strengthen any point-lock
deployment or extraction claim.
Its [linear-disclosure analysis](../../research/pointlocks-2026-09-17/ddh-linear-leakage.md)
now shows that any extra scalar-linear key function outside the aggregate's
span exposes a label pair in that layout. Public affine relations between
row bases do so as well. These are composition restrictions, not a new native
point-lock implementation or a general impossibility result.
Its [masked follow-up](../../research/pointlocks-2026-09-17/ddh-masked-audit.md)
extends recovery to informative group actions without their underlying
scalars, and reproduces a false-table certificate for a challenge fixed
before mask commitments. It does not refute properly bound proof protocols.

The [Argo MAC / Duty-Free Bits review](../../research/pointlocks-2026-09-17/arithmetic-garbling-interface.md)
identifies a separate affine-garbling evaluator with two passing upstream
correctness tests. These translation primitives consume authenticated input
labels; they do not by themselves supply native point-scalar extraction or
public malicious-setup verification. Their published component timings are
not complete publication-setup measurements.

The [WOTS-to-Lamport source audit](../../research/pointlocks-2026-09-17/wots-translation-boundary.md)
adds a locally reproduced offchain access structure based on checksum-controlled
sharing. It neither extracts secp256k1 point scalars nor publicly certifies
malicious encrypted tables. The paper's full protocol and reported runtime
must not be substituted for the current2048-bit goal's missing setup checks.

**The windowed candidate below is rejected for impractical setup cost.** Its
`2^63.138` expected SHA256 compressions do not meet the user's practical-setup
requirement. The measurements remain research evidence; they are not a usable
solution or a reason to weaken extraction. See [NR-061](../negative-results/windowed-pointlock-setup-cost.md).

A [native byte-distinctness counterexample](../../research/pointlocks-2026-09-17/distinct-short-signatures.md)
also rules out repetition based only on different signature encodings in the
legacy SINGLE-constant setting. A maliciously selected key admits16 exact60
encodings of one equation; Core accepts the existing max60 predicate and
all-pairs-distinct batches of up to eight. Extracting that key's scalar would
solve the transparently lifted nonce point's DLP. This scopes a concrete
failure of legacy malicious setup without breaking the anchored P2WSH or
exact sum-key constructions; see [NR-062](../negative-results/repeated-short-pointlocks.md).

The separate [windowed P2WSH publication candidate](../../research/pointlocks-2026-09-17/windowed-publication.md)
uses a tighter 53-byte small-R predicate and hidden scalar offsets so one
native digest search prepares every choice in a pool. Four six-of-nineteen
multisig blocks per input give a 39,396-vB creation-plus-spending profile for
arbitrary 256-byte data. This is `locally-reproduced` serialization with
`inspected` algebra, not a production-mined or cryptographically validated
53-byte publication. The expected search cost is about `2^63.138` SHA256
compressions; short-signature exclusion and correlated-label security remain
explicit assumptions. The full reduced-work 59-byte-cap fixture is
`differentially-validated` and `policy-validated` at 40,656 vB, with all 840
scalars and the exact 256-byte payload recovered. It validates that fixture's
execution, not the production search or security. See the independent review
linked by the report.

If the payload is specifically a 256-byte uncompressed BN254 Groth16 proof,
the [conditional compressed-proof experiment](../../research/pointlocks-2026-09-17/conditional-proof-compression.md)
instead uses the existing sum-key construction for 128 bytes. Its exact
92,706-vB synthetic payload fixture is `differentially-validated` and
`policy-validated`. It does not encode 256 arbitrary bytes, and adapting the
garbled verifier to compressed inputs remains separate work.

## Schnorr adaptor signature

The counterparty produces a Schnorr adaptor signature encrypted to `T` and the
prospective spender verifies it before accepting the contract. Completing the
adaptor signature with `t` yields an ordinary BIP340 signature. Comparing the
completed signature with the previously validated adaptor transcript extracts
`t` (with the convention-specific sign handling required by BIP340).

The blockchain sees only the ordinary x-only public key and `OP_CHECKSIG`; the
point lock is enforced by the off-chain transcript. This is the smallest and
strongest construction here under standard discrete-log and adaptor-signature
assumptions, but setup is interactive: without the counterparty-created
adaptor signature there is no later extraction guarantee. No adaptor library
is added locally because Script contains no adaptor-specific predicate.

## ECDSA with the `G/2` nonce

The spender signs under `T = tG` using nonce scalar
`k = 2^-1 mod n`. The public nonce `R = G/2` has

```text
x(R) = 0x3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63,
```

which is only 21 bytes as a positive DER integer. A low-S Bitcoin signature is
therefore at most `7 + 21 + 32 = 60` bytes including the sighash byte. Script
requires a signature no longer than 60 bytes and verifies it under `T`:

```text
OP_SIZE 60 OP_LESSTHANOREQUAL OP_VERIFY <T> OP_CHECKSIG
```

Given the published transaction digest `z`, extraction tries the two ECDSA
nonce signs and selects the scalar whose public key is `T`:

```text
t = (s*(+/- 2^-1) - z) * r^-1 mod n.
```

Measured facts: the policy-compiled complete predicate is 40 bytes; the
deterministic representative signature is 60 bytes and its serialized
one-item witness is 62 bytes; local tests reproduce signing, extraction, and
legacy ECDSA verification. The `G/2` x-coordinate and DER accounting match the
Binohash paper.

Security inference: Script constrains total encoding length, not the exact
nonce. The Binohash paper's roughly 97-bit smaller-coordinate estimate does
not bound a total-length search with adaptive transaction digests. The earlier
roughly 80-bit protocol estimate is withdrawn pending the adaptive and
multi-target analysis in [OP-017](../open-problems.md#op-017--point-lock-security-and-deployment-validation).
The [windowed review](../../research/pointlocks-2026-09-17/windowed-small-r-review.md)
separates the relevant search models; it supplies no proved security level
for the original 60-byte predicate.

## Three-check ECDSA from `T` alone

This construction removes the small-R search assumption, signature
commitment, and setup proof. Let `k0=1/2 mod n`, `r0=x(G/2)`, and let `z0=2^248`
be the ECDSA interpretation of the legacy out-of-range SIGHASH_SINGLE digest.
From the public target derive

```text
Q = -(2*z0/r0)G - T.
```

Reject the publicly detectable cases `Q=infinity` and `Q=T`. The lock is:

```text
OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
OP_DUP <T>
OP_2DUP OP_CHECKSIGVERIFY
OP_CODESEPARATOR
OP_CHECKSIGVERIFY
<Q> OP_CHECKSIG
```

The first two checks verify the same signature under `T` using full and suffix
legacy `scriptCode` views. The third verifies it under `Q` using the suffix
view. The policy-produced predicate is 79 bytes, consumes one signature item,
uses zero witness hints, and has a five-item combined-stack peak.

For digests `zA,zB`, the target checks reconstruct nonce points

```text
RA = s^-1(zA*G + r*T),  RB = s^-1(zB*G + r*T).
```

The strict `length > 57` guard excludes every `r` for which the alternative
field coordinate `r+n` can exist. Consequently `RA=+/-RB`. The opposite case
reveals `t=-(zA+zB)/(2r) mod n`; the equal case requires `zA=zB mod n`, which
is the stated related-scriptCode reduced-sighash collision exception. This
does not rely on an attacker being unable to find an x-coordinate shorter than
`x(G/2)`.

For an honest spend, place the input at an index without a corresponding
output and sign with SIGHASH_SINGLE and nonce `k0`. All checks then use `z0`.
The `T,Q` checks force `r=r0`, and trying both nonce signs extracts `t`. A low-S
signature is at most 60 bytes. If its DER integer is too short for the guard,
the equivalent high-S encoding is 61 bytes and restores consensus-level
completeness, at the cost of an additional policy violation.

The Rust implementation and detailed compatibility matrix are in
[`src/signatures/pointlocks/three_check/`](../../src/signatures/pointlocks/three_check/).
Its deterministic tests reproduce the script, companion relation, intended
legacy execution, both extraction branches, DER boundary, high-S fallback,
and exceptional targets. Exact unpadded bare and P2SH transactions, including
high-S and undefined-flag cases, are now `differentially-validated` and
`consensus-validated` against pinned Core 30.3; their policy rejection is
recorded in the [complete experiment](../../research/pointlocks-2026-09-17/CORE.md).

## Experimental two-check ECDSA from `T` alone

Use the same `C=z0=2^248`, `r0=x(G/2)`, companion
`Q=-(2*C/r0)G-T`, and exceptional-target exclusions as the three-check
construction, but check the target only once:

```text
OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
OP_DUP <T> OP_CHECKSIGVERIFY
<Q> OP_CHECKSIG
```

The policy-produced predicate is 76 bytes, consumes one signature data item,
uses zero hints, executes six non-push opcodes, and peaks at three combined
stack items. The representative signature is 60 bytes: a 61-byte bare
scriptSig or a 139-byte P2SH scriptSig including the redeem-script push.
These legacy inputs have no witness serialization.

The size guard excludes all `r+n` cases. The distinct keys must reconstruct
opposite nonce points for their common actual digest `z`, forcing exactly
`r=r0*z/C mod n`. Thus an honest SINGLE-bug spend forces `r=r0` and reveals
`t` through the existing G/2 extraction equation. The same rare 61-byte high-S
fallback ensures legacy-consensus completeness but is non-standard.

For ordinary `z!=C`, this invariant does not give a known nonce. The
implementation verifies both equations and then returns `NonConstantDigest`
instead of inventing an extraction result. A synthetic supplied-digest vector
demonstrates this boundary; no actual native preimage was found. A malicious
spender knowing `t` would need a native-hash/known-nonce coordinate match.
The approximately `2^128` independent-list estimate is not a proved security
bound. For arbitrary targets without a known discrete log, even that
known-nonce reduction does not follow; the stronger ordinary-native-transcript
assumption remains unresolved.

The [implementation README](../../src/signatures/pointlocks/two_check/README.md)
records the API, data boundary, and compatibility. The
[algebra review](../../research/pointlocks-2026-09-17/algebra.md) and
[negative result](../negative-results/two-check-point-lock-extraction.md)
separate the proved constant-digest extraction from this additional assumption.
The variant removes executed CODESEPARATOR and its P2SH policy obstacle, but
does not inherit the 79-byte construction's stronger extraction argument.
Its representative low-S P2SH transaction is `differentially-validated` and
`policy-validated` by Core 30.3, with a complete two-input weight of 1,054 WU.
Bare, high-S, and undefined-flag positives are `consensus-validated` with
policy rejection. The [Core report](../../research/pointlocks-2026-09-17/CORE.md)
separates the helper witness and full transaction bytes from the legacy
point-lock input, and records the negative-context checks. This validates
execution, not the additional cryptographic assumption.

## Committed ECDSA over the SIGHASH_SINGLE bug

Let `P = xG` be an ECDSA verification key whose scalar `x` is public protocol
data. The spender creates a low-S SIGHASH_SINGLE signature using nonce point
`R = +/-T`, then commits to the complete Script signature item:

```text
h = SHA256(DER(r,s) || 0x03).
```

The lock is:

```text
OP_DUP OP_SHA256 <h> OP_EQUALVERIFY <P> OP_CHECKSIG
```

It must execute in a legacy input whose input index has no corresponding
output. The historical SIGHASH_SINGLE bug then supplies the fixed digest
conventionally displayed as `000...001`. Once the committed signature appears,
an observer computes the nonce scalar and corrects its sign against `T`:

```text
t = +/-(z + r*x) * s^-1 mod n.
```

At the byte interface used by Bitcoin Core and libsecp256k1, the internal
`uint256(1)` buffer is `01 00...00`; ECDSA interprets those 32 bytes as a
big-endian integer. The local helper therefore uses `z = 2^248`, not the
human-display integer `1`. Protocol implementations must follow the actual
digest bytes rather than transcribing the displayed hash as an integer.

During contract setup the spender must give the counterparty an off-chain
zero-knowledge proof that the SHA-256 preimage contains `x(T) mod n` in the DER
`r` field and ends in `0x03`. The proof need not establish curve membership or
ECDSA validity: the public target point is already parsed off chain, and the
on-chain `OP_CHECKSIG` checks the signature. RISC Zero, SP1, and Flock are
possible proving backends, but this repository intentionally does not pull one
in as a dependency.

Measured facts: the complete predicate is 71 bytes; the deterministic
representative signature is 71 bytes and its serialized one-item witness is 73
bytes. Tests reproduce the bug-context signature, exact SHA-256 commitment,
legacy ECDSA validation, extraction, and rejection of substituted signatures,
wrong points, and wrong sighash flags.

## Compatibility

The small-R lock is meaningful in bare legacy, P2SH, and P2WSH scripts because
extraction can use the actual public transaction digest. The committed lock is
limited to bare legacy or P2SH: BIP143 SegWit v0 does not reproduce the
SIGHASH_SINGLE constant-digest bug. The three-check lock is likewise limited
to bare legacy or P2SH and is non-standard in both forms: bare arbitrary
outputs are not standard templates, while executed `OP_CODESEPARATOR` violates
`CONST_SCRIPTCODE` policy. The experimental two-check variant has no separator;
its representative low-S P2SH spend is policy-validated by pinned Core, while its
high-S fallback remains non-standard. Both variants are incompatible with
P2WSH because BIP143 fixes the required bug. All ECDSA locks are incompatible with tapscript, where
`OP_CHECKSIG` uses BIP340 and 33-byte keys have unknown-key semantics. The
Schnorr adaptor construction is the tapscript alternative.

Local legacy unit tests use the pinned `bitcoin-scriptexec` interpreter and
alone do not establish relay policy. The separate complete-transaction Core
experiment covers the two-check and three-check forms. In the small-R success
test, semantic NOP padding works around a pinned-interpreter FindAndDelete
underflow for scriptCode shorter than the signature; the measured 40-byte
predicate itself is not padded.

## References and status

- Binohash sections 2.1.1-2.1.4 specify ECDSA DER sizing and the 21-byte
  `G/2` x-coordinate; section 2.4.3 specifies the legacy SIGHASH_SINGLE bug.
- BIP340 and BIP342 specify the completed Schnorr signature and tapscript
  verification boundary.
- Fournier's one-time verifiably encrypted signature paper describes adaptor
  signature creation, adaptation, and extraction.

The small-R and committed ECDSA implementations remain `locally-reproduced`
with `unclassified` deployment. The two-check and three-check execution
fixtures are `differentially-validated` and `consensus-validated`; only the
recorded representative low-S two-check P2SH fixture is additionally
`policy-validated`. The Schnorr adaptor construction is `reported` and
unimplemented locally. These evidence levels concern the stated execution
and extraction checks, not proof of unresolved computational assumptions.


## HASH160-committed two-check extension

The [implementation](../../src/signatures/pointlocks/committed_two_check/README.md)
adds a signature commitment to the two-check predicate: 100 bytes per lock,
five locks in a 500-byte P2SH redeem script. These are fixed-point AND predicates, not selectable BitVM3 digit slots.
A direct binary 256-byte encoding needs 2,048 choices between pairs of points
(4,096 candidate locks); complete proof-publication integration remains open.
Small selectable and threshold subsets are implemented as research probes; see
the [subset analysis](../../research/pointlocks-2026-09-17/hors-subsets.md) and
[CHECKMULTISIG comparison](../../research/pointlocks-2026-09-17/multisig-probe.md).
The 187-fixed-point, 38-output example is not a 256-byte proof encoding.
One/five locks consume one/five signature data items, zero hints, and peak at
three/seven combined stack items. Sizes and default-options legacy interpreter
execution are `locally-reproduced`; deployment remains `unclassified` pending
Core validation. The commitment introduces a self-reference for ordinary
transaction digests, but no complete hardness argument is established (OP-017).
