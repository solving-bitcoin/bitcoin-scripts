# ECDSA point locks

A point lock has a public point `T = tG` and makes a successful spend reveal
its discrete logarithm `t`, analogously to a hash lock revealing a preimage.
This module implements six ECDSA constructions. Schnorr adaptor signatures are
covered in the knowledge page because their meaningful construction and
verification happen between counterparties off chain.

The new [`sum_key`](sum_key/) construction locks the scalar of `P+Q`, giving
the extractor `t=-2z/r` for every accepted common digest. Its common-generator
setup fixes `Q=G`, generates fresh label points, and needs no ZKP or interactive
transcript. Sharing G across selectable pools removes the earlier per-label
signature commitments and companion keys. The
[publication experiments](../../../research/pointlocks-2026-09-17/encoding-optimization.md)
include complete funding-output and spending costs; the standalone API and
recorded pool fixtures have pinned Core validation.

The [bare-legacy publication](../../../research/pointlocks-2026-09-17/bare-publication.md)
now validates complete funding and spending for 79 seven-of-48 pools:
161,382 vB actual, 161,560 vB canonical maximum, 553 scalar openings and a
256-byte roundtrip. This is `consensus-validated`, with default relay-policy
rejection. It retains the documented full-protocol integration boundaries.

The separate [anchored publication research](../../../research/pointlocks-2026-09-17/round-major-contexts.md)
now groups verification by round and shares separators across selected labels.
Its five/six-context serialization estimates are 90,114/98,334 vB, including
all creation/spending costs and authorizations. Core validates both small
selectors and the full 5-of-54 pool at 201 opcodes. The
[complete native publication](../../../research/pointlocks-2026-09-17/round-major-publication.md)
now costs98,323 vB with real signatures,475 recovered scalars and a256-byte
roundtrip. Point-lock-only setup/checking takes89.63 ms median with15 workers.
Full extraction and public garbled-label binding remain open; this is not a
completed publication API or a complete-goal setup benchmark.

The [95-pool decoder example](../../../research/pointlocks-2026-09-17/round-major-message-decoder.md)
connects the 475 openings to encrypted complement shares, garbled subset ranks
and 2,048 message labels. Its total modulo rule covers every complete valid
codeword. Generation takes 364.16 ms median; including an audit with all
secrets takes 733.29 ms. This adds no onchain bytes or hints, but public setup
verification and full protocol integration remain unresolved.

The [native participation probe](../../../research/pointlocks-2026-09-17/pool-participation.md)
also shows that the retained creator can spend one funded pool while leaving
94 unopened. Full publication or safe-abort handling requires additional
protocol binding; the existing ALL authorization alone does not enforce it.

The offchain [cross-key graph extractor](../../../research/pointlocks-2026-09-17/cross-key-nonce-extraction.md)
combines nonce relations across selected labels and verifies the resulting
linear rank. It recovers additional synthetic cases and replays all 475
native openings without changing their scripts or costs. Rank-deficient and
unrelated-nonce cases remain unresolved; this is a research helper, not a new
onchain primitive or complete publication API.

The [public scalar-gate probe](../../../research/pointlocks-2026-09-17/public-algebraic-gate.md)
also records a failed garbling interface: public point consistency and
correct AND evaluation do not prevent recovering another input's labels.
It changes no point-lock predicate and supplies no complete setup audit.

The [vector-label follow-up](../../../research/pointlocks-2026-09-17/vector-label-gates.md)
implements a public point check for a binary gate with two scalar coordinates
per input label and a scoped one-opening discrete-log argument. Nine focused
host tests cover all truth tables, malformed inputs and a failed scalar-packing
wrapper. This provides a checked offchain gate, not an efficient native
delivery mechanism or a replacement for the current publication candidate.

The [shared-coordinate reference](../../../research/pointlocks-2026-09-17/shared-vector-gates.md)
reduces the gate to three distinct scalar openings. Ten host tests cover its
curve equations, subset privacy and the correlated-label classification bound.
The direct independent legacy layer still exceeds 100,000 vB; no native API,
Bitcoin script or complete publication claim is added by this experiment.

The [ratio-label reference](../../../research/pointlocks-2026-09-17/ratio-labels.md)
tests relative logarithms of public affine point forms as a replacement
interface. Nine host tests distinguish genuinely available scalar ratios,
public constants and DLP-dependent labels. It provides no new native script
or whole-publication cost; see the scoped NR-074 reconstruction boundary.

The [DH quartet reference](../../../research/pointlocks-2026-09-17/dh-quartet-labels.md)
implements one scalar opening to two implicit group-valued labels, with
independent and correlated input profiles. Twelve host tests cover CDH
reductions, a chosen-setup alias, the correlated profile's public separation
check and the quadratic subset boundary. No native API, full publication,
public garbling checker or complete setup benchmark is added.

Its [fixed-digest nonce follow-up](../../../research/pointlocks-2026-09-17/fixed-digest-nonce.md)
provides an experimental native adapter: three checks under `G` force the
legacy constant digest, then a derived-key check fixes the target nonce.
Core validates the expected 23 positive and eight negative cases; an
independent Rust test checks native digests and extracted scalars. The
86-byte single-target and 199-byte quartet scripts are nonstandard legacy
scripts. The explicit quartet tables exceed the publication budget before
signatures; no stable primitive API or full setup benchmark is claimed.

The [correlated quadratic-label probe](../../../research/pointlocks-2026-09-17/correlated-quadratic-labels.md)
rules out extending that interface to the full 5-of-54 alphabet merely by
correlating private candidates. Its degree argument, 44 exact field ranks
and 34 curve views retain the missing-three boundary when every unselected
candidate must remain unavailable. It changes no native API or metric.

A [native negative-result fixture](../../../research/pointlocks-2026-09-17/dual-anchor-sum-collapse.md)
rejects the proposed dual-anchor/sum-key shortcut: it admits a public opening
without the intended target scalar. This does not change the exact sum-key
API or refute the separate cap60 anchored candidate.

The [distinct-target anchor algebra](../../../research/pointlocks-2026-09-17/two-target-anchors.md)
does recover one of two prebound label scalars exactly. Its opening instead
requires a nonce at a digest-prescribed x-coordinate; the 31 synthetic curve
fixtures do not provide a practical native opening or a new primitive API.

The separate [fixed-orbit analysis](../../../research/pointlocks-2026-09-17/orbit-key-sharing.md)
finds that reusing four-root verification keys still exceeds the publication
budget and may disclose alternative labels. It supplies algebra and restricted
size bounds, not a seventh implemented point-lock construction. The
[two-key refinement](../../../research/pointlocks-2026-09-17/orbit-private-sharing-bound.md)
also exceeds 100,000 vB for 40-byte openings after actual sharing structure
and alternative-label disclosure are accounted for.

The offchain [DDH masked-audit experiments](../../../research/pointlocks-2026-09-17/ddh-masked-audit.md)
and [arithmetic-garbling source review](../../../research/pointlocks-2026-09-17/arithmetic-garbling-interface.md)
record composition constraints and a possible faster label-translation API.
Neither adds a native point-lock implementation or upgrades the extraction
and public setup guarantees of the existing candidates.

The strongest point-only candidate is implemented in the dedicated
[`three_check`](three_check/) folder. It derives a companion key from `T`
alone and reuses one signature across three legacy ECDSA checks. It requires
neither a signature commitment nor a setup proof.

The separate [`two_check`](two_check/) experiment uses a 76-byte predicate
with one scriptCode and a three-item stack peak. It removes the separator
policy obstacle but has a stronger unresolved ordinary-transcript assumption.
Its public extractor deliberately reports `NonConstantDigest` after verifying
an ordinary-digest signature; it is not an equivalent replacement for the
three-check guarantee.

The dedicated [`committed_two_check`](committed_two_check/) module adds a
HASH160 signature commitment to the two-check predicate. It implements the
100-byte fixed-point lock and supports five-lock, 500-byte P2SH AND batches.
This fixed-point API does not itself implement selectable BitVM3 digit slots:
one fixed point is not an
11-bit choice among 2,048 points. Its ordinary-digest security
argument remains open; it does not inherit the older variants' Core validation.

## Parameters

- `T = tG`: the point whose scalar is to be revealed; no default.
- Small-R lock key: `T` itself is the ECDSA verification key.
- Small-R nonce: `G/2`, whose x-coordinate is the 21-byte integer
  `3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63`.
- Small-R maximum signature-item length: 60 bytes, including the sighash byte.
- Committed lock signing key: `P = xG`, with both `P` and `x` public.
- Committed lock digest: `SHA256(DER(r,s) || 0x03)`; no default.
- Committed lock transaction: legacy SIGHASH_SINGLE at an input index with no
  corresponding output, so the historical constant digest is used.

## Script metrics

The scripts are complete terminal predicates. Locking-script sizes include the
compressed public key and terminal `OP_CHECKSIG`. Witness sizes are consensus
serializations of a one-item vector and depend on the concrete `s` encoding.

| Configuration | Locking script | Representative unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| `G/2` small-R lock | <!-- metric:pointlock_small_r_script -->40<!-- /metric:pointlock_small_r_script --> bytes | <!-- metric:pointlock_small_r_witness -->62<!-- /metric:pointlock_small_r_witness --> bytes | 3 |
| Committed signature lock | <!-- metric:pointlock_committed_script -->71<!-- /metric:pointlock_committed_script --> bytes | <!-- metric:pointlock_committed_witness -->73<!-- /metric:pointlock_committed_witness --> bytes | 3 |

See the [three-check](three_check/) and [two-check](two_check/) READMEs for
their legacy `scriptSig` metrics rather than a witness-vector proxy. Both
consume one signature data item and zero hints; their combined stack peaks
are five and three respectively.

The first script is:

```text
OP_SIZE 60 OP_LESSTHANOREQUAL OP_VERIFY <T> OP_CHECKSIG
```

The committed script is:

```text
OP_DUP OP_SHA256 <SHA256(DER(r,s) || 0x03)> OP_EQUALVERIFY <P> OP_CHECKSIG
```

## Security

For the small-R construction, a low-S signature made with nonce scalar
`k = 1/2 mod n` has a signature item of at most 60 bytes. Once `(r,s)` and the
transaction digest `z` are public, either

```text
t = (s*k - z) / r mod n
```

or the corresponding value for `-k` matches `T`; the sign ambiguity comes from
low-S normalization. The Script does not prove that the nonce is `G/2`. It
only bounds the total DER size. Security therefore rests on the work required
to forge another valid signature within that size bound. The Binohash analysis
records a 21-byte `x(G/2)` and about 97 bits to find a smaller comparable
R-value. That estimate is not a bound for this total-length predicate when
the spender can vary the transaction digest. The earlier roughly 80-bit
protocol estimate is withdrawn pending an adaptive, multi-target analysis.
See the [windowed small-R review](../../../research/pointlocks-2026-09-17/windowed-small-r-review.md)
for the distinction between nonce-coordinate search and total-length search.
No established security level is claimed for this 60-byte predicate.

The [native malicious-setup fixture](../../../research/pointlocks-2026-09-17/distinct-short-signatures.md)
now gives a concrete failure on the legacy SINGLE-constant branch. From a
publicly lifted nonce point R with21-byte x-coordinate, choose `s=floor(n/2)`
and commit to `T=(sR-CG)/r`. A valid exact60 signature is then public without
using T's scalar; extracting it is equivalent to solving R's discrete log.
Core accepts this existing40-byte predicate, including a low-S policy-valid
spend. Distinct flags and both s signs also defeat a proposed byte-inequality
repetition repair. This is scoped to adversarial target selection and the
legacy constant branch; it is not a break of the anchored P2WSH experiment
or the sum-key predicate's different extraction relation.

For the committed construction, let the committed signature use nonce point
`R = +/-T`. With public signing scalar `x` and the fixed bug digest, revealing
the signature gives

```text
t = +/-(z + r*x) / s mod n.
```

Binding rests on SHA-256 second-preimage resistance, ECDSA verification, and
the soundness of the off-chain setup proof. The signing scalar `x` is not an
authorization secret. Reuse that treats it as one would let anyone sign; the
hash commitment is the actual spend authorization.

The bigint helpers in this module are deterministic research utilities and
are not constant-time. They must not handle production secrets.

## Script compatibility and standardness

- Bare legacy Script: both opcode sequences are consensus-compatible, but bare
  outputs are generally non-standard relay templates.
- P2SH: both redeem scripts fit the 520-byte element limit. Standard relay has
  not been reproduced here.
- P2WSH: the small-R construction remains meaningful with the BIP143 digest.
  The committed construction does not: SegWit v0 intentionally does not return
  the legacy SIGHASH_SINGLE bug digest.
- Tapscript: incompatible. Tapscript `OP_CHECKSIG` uses BIP340 Schnorr, and a
  33-byte key has unknown-key semantics rather than legacy ECDSA semantics.

See [`docs/script-types.md`](../../../docs/script-types.md) and
[`docs/standardness.md`](../../../docs/standardness.md).

## Witness and hints

Each script consumes exactly one signature item. Small-R accepts any defined
ECDSA sighash type whose actual transaction digest is supplied to extraction.
Committed ECDSA requires the byte-exact item `DER(r,s) || 0x03`; the final byte
is inside the SHA-256 commitment and selects SIGHASH_SINGLE.

Committed setup additionally requires an off-chain zero-knowledge proof that
the SHA-256 preimage contains the target point's x-coordinate in the DER `r`
field. On-chain DER parsing and `OP_CHECKSIG` establish signature validity, so
the proof need not establish curve membership or duplicate ECDSA verification.
A RISC Zero, SP1, or Flock circuit is an integration choice, not a dependency
of this module.

## Stack contract

For both scripts:

```text
... signature -> ... true
```

On a clean one-item witness, success leaves exactly one truthy item. The
altstack is unused and the peak is three main-stack items.

## Operational notes

The [total message-decoder experiment](../../../research/pointlocks-2026-09-17/total-message-decoder.md)
composes 460 cached native scalar openings into 2,048 garbled message labels,
with a total modulo rule for the 115-pool encoding. Its offchain generation
and all-secrets audit measure 341.82 ms and 348.66 ms median respectively.
Public setup binding and general extraction for the underlying anchored
candidate remain unresolved. This research example adds no native script,
witness or hint items and does not change the public primitive APIs.

The [windowed publication experiment](../../../research/pointlocks-2026-09-17/windowed-publication.md)
uses hidden scalar offsets and a tighter 53-byte ceiling to amortize a native
digest search across all choices in each P2WSH input. Its direct-key multisig
profile sizes to 39,396 vB for arbitrary 256-byte data, including creation and
spending, but retains an unproved short-signature assumption and an unperformed
production search. Its approximately `2^63.138` SHA256-compression setup is
rejected as impractical; it is not a recommended solution. It is separate
from the public APIs documented above.

Tests cover the 21-byte `G/2` constant, deterministic signing, both extraction
relations, byte-exact commitment enforcement, ordinary-signature rejection,
wrong targets, and wrong sighash flags. Legacy execution uses the pinned
`bitcoin-scriptexec` ECDSA path. The short-R success test appends semantic NOPs
because that pinned interpreter has an unsigned-underflow bug in legacy
FindAndDelete when `scriptCode` is shorter than the signature; the unpadded
script bytes are measured separately.

No zkVM verifier dependency is included. No implementation of adaptor-signature
nonce exchange, transcript validation, or encrypted-signature verification is
included.
