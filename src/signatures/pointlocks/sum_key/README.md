# Sum-key ECDSA point lock

A noninteractive scalar-revelation predicate for `T=P+Q`. The same signature
is verified under distinct public keys `P` and `Q`. Every accepted signature
reveals `t=log_G(T)` from its actual transaction digest, including ordinary
digests. No signature hash commitment, setup proof, or secret signing key is
required. The common-generator setup fixes `Q=G` and enables one shared key
across a selectable pool.

## Parameters and setup

All scalar arithmetic uses the secp256k1 order `n`. Let `C=2^248` be the
ECDSA interpretation of the legacy SINGLE-bug digest (`01` then 31 zero bytes).
Public inputs `P,Q` have no defaults and must be distinct, valid points with
`P+Q` not infinity. The common-generator API fixes `Q=G` (public scalar one).

To generate an independent common-G candidate, the holder selects a fresh
secret nonce `k` and computes:

```text
R = kG
r = x(R) mod n
s = (C+r)/k mod n
t = -2C/r mod n
T = tG
P = T-G
```

Use the low-S form of `(r,s)` and append `0x03`. Retry a degenerate nonce,
`P=G`, `P=-G`, or a signature item at most 57 bytes long. Publish `T` and
derive `P=T-G` publicly. Keep the nonce, signature, and scalar `t` secret until
publication. Anyone can verify the public-key relationship using group
operations. **This setup generates the target point; it does not open an
arbitrary previously selected target with a common G key.**

The general two-key construction can support an arbitrary given target with
holder-generated auxiliary keys; that setup is described in the
[research note](../../../../research/pointlocks-2026-09-17/sum-pointlock.md),
and is not part of `setup_from_nonce`.

## Script and extraction

```text
# Initial stack: <sigma>
OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
OP_DUP <P> OP_CHECKSIGVERIFY
<Q> OP_CHECKSIG
```

For the actual digest scalar `z`, the verification points are
`R_P=(zG+rP)/s` and `R_Q=(zG+rQ)/s`. Strict DER encodes any possible `r+n`
case in at most `7+17+33=57` bytes including the sighash flag. The length guard
therefore leaves only points with the same x-coordinate `r`. They are equal
or opposite. Equality would imply `P=Q`, excluded during public setup. Thus:

```text
R_P + R_Q = infinity
2zG + r(P+Q) = infinity
t = -2z/r mod n
```

Verify `tG=P+Q` after extraction. This argument does not require `z=C` and
does not assume a particular nonce. A nonzero sum point cannot pass at `z=0`.
The constant digest is used for constructing an honest opening before funding.

Both checks see the same scriptCode: there is no CODESEPARATOR and the only
data pushes are 33-byte keys and the small size constant. An accepted signature
is longer than 57 bytes, so its pushed serialization cannot occur at an opcode
boundary. Legacy FindAndDelete cannot change this scriptCode. An expanded pool
or surrounding protocol must retain the same-digest property for each pair.

## Script metrics

Boundary: complete-leaf predicate through a clean truthy result; excludes
funding output, transaction framing, payment authorization, and refunds.
The deterministic nonce `[7;32]` produces the representative signature.

| Configuration | Locking script | Signature item | Complete P2SH scriptSig | Hint items | Combined stack peak |
| --- | ---: | ---: | ---: | ---: | ---: |
| Single common-G lock | <!-- metric:pointlock_sum_key_script -->76<!-- /metric:pointlock_sum_key_script --> bytes | 72 bytes | 151 bytes | 0 | 3 |

The 151-byte scriptSig includes the signature push and redeem-script push.
There is one data item at redeem-script entry, no altstack, and zero auxiliary
hints. P2SH additionally pushes the redeem script before its evaluation.
The point-lock input has zero witness items; in a mixed SegWit transaction
its empty witness vector occupies one serialized byte. Twelve deterministic
nonce seeds `[7;32]` through `[18;32]` produce 71- or 72-byte signature items.
Script bytes use `compile_with_policy()`; no manual peepholes are required.

## Security and selected subsets

The extraction argument is algebraic under the stated validation conditions.
Producing an accepted opening reveals the target scalar rather than merely
demonstrating knowledge of it. This does not establish the security of a whole
BitVM3 protocol, a custom encoding, or any deliberate nonce-grinding profile.

For a pool, check that all `P_i` are distinct and neither `G` nor `-G`. Distinct
nonces alone are insufficient: `k` and `-k` have the same `r` and target. Use
independent, secret nonces; the API supplies no RNG. Public affine relations
between label scalars can expose unselected labels and must not be introduced
as a compression trick. Ordinary full-size independent nonces do not impose
such a public relation. No concrete reduction for all distributions of chosen
or heavily ground candidate nonces is claimed.

A selected signature can be checked in a `t-of-n CHECKMULTISIG` over the `P_i`
and against the common G key. The same signature must pass both checks.
Because G is one recovered key, the guard leaves at most one other recovered
key: one signature cannot match two distinct `P_i`. This eliminates the
cross-pair problem of two independently selectable lists of companion keys.
The research pool implementation and complete-transaction measurements remain
separate from this single-lock API.

## Script compatibility and standardness

- Bare legacy and P2SH have the required honest-setup digest. The 76-byte
  redeem script fits P2SH limits and contains two signature checks.
- P2WSH supports ECDSA and the extraction equation, but lacks the constant
  digest required by this noninteractive pre-funding opening construction.
  Do not transplant the setup by merely changing the wrapper.
- Tapscript uses Schnorr/unknown-key semantics rather than this ECDSA relation
  and is incompatible with the script as written.

See [script types](../../../../docs/script-types.md) and
[standardness](../../../../docs/standardness.md). The exact single-lock fixtures
are now `differentially-validated`, with their positive P2SH spends
`policy-validated`, by [Core 30.3](../../../../research/pointlocks-2026-09-17/sum_key_core_check.json).
That report passes 50 expectations: 13 positive sum locks, 36 negative sum-lock
mutations, and one historical cross-pair control. The algebraic argument is
`inspected`, not a claim that every surrounding protocol is validated.

## API, stack contract, and operational notes

- `setup_from_nonce(k)` returns public `target`, `verification_key`, and
  explicit `signature()` / `target_secret()` accessors for secret material.
- `generator_key()` returns G. `target_point(P,Q)` checks setup conditions.
- `point_lock(P,Q)` and `common_generator_lock(P)` return `Script`; compile
  it through `ScriptCompilation::compile_with_policy()`.
- `extract_from_digest` verifies both ECDSA equations at a supplied digest.
- `extract_from_transaction` computes the actual legacy digest for this exact
  standalone script, preserving the raw sighash byte. A larger pool requires
  its own complete scriptCode and the digest-level extractor.

Stack contract: `... signature -> ... true`. No hints or altstack are used;
surrounding stack state remains live and counts toward the 1,000-item limit.
For an AND batch, verify intermediate results and count all input signatures
at entry. Only the single-lock stack peak is measured here.

The setup inherits non-constant-time research bigint helpers. There is no
default nonce and no production randomness API. Publishing an opening reveals
the target scalar; do not reuse it as an authorization secret. The setup
object deliberately has no Debug implementation to avoid accidental opening
disclosure.

Seven focused tests cover constant-digest execution and extraction, equal and
opposite keys, malformed/short items, wrong flags and keys, synthetic ordinary
digests, zero digests, duplicate targets from opposite nonces, and high-S/raw
legacy-flag extraction. Execution uses `ExecCtx::Legacy`, default interpreter
options, and enabled stack limits. The shared tapscript helper is not used.

```sh
cargo test --locked --lib signatures::pointlocks::sum_key::
cargo run --locked --example pointlock_sum_probe
```

## Knowledge-base integration

See the [point-lock knowledge page](../../../../knowledge/primitives/point-locks.md),
[comparison](../../../../knowledge/comparisons/signatures.md), and
[research note](../../../../research/pointlocks-2026-09-17/sum-pointlock.md).
Primary verification details: [libsecp256k1 v0.6.0 ECDSA implementation](https://github.com/bitcoin-core/secp256k1/blob/v0.6.0/src/ecdsa_impl.h)
and [BIP66 strict DER specification](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki).

## BitVM3 proof publication

The complete fixed-cardinality experiment publishes and recovers an arbitrary
256-byte value using 180 four-of-seventeen pools and three three-of-eighteen
pools: **183 P2SH outputs, 3,114 independent candidates, 729 revelations**.
The shared-G key-hash lookup tables need 505-byte and 502-byte redeem scripts.
The mixed-radix encoding counts subsets, not their reveal order.

The [complete Core report](../../../../research/pointlocks-2026-09-17/publication_core_check.json)
records one creation transaction and two assertion transactions, each accepted
by default mempool policy and mined on isolated regtest. Independent decoding
recovers the original 256 bytes from the actually spent input scripts.

| Transaction | Actual virtual bytes |
| --- | ---: |
| Create a first P2TR helper and all 183 P2SH outputs | 5,967 |
| Consume the helper and 101 pool outputs | 99,065 |
| Consume the new helper and the remaining 82 pool outputs | 80,114 |
| **Combined** | **185,146** |

The combined worst-case bound for this layout is 185,432 vB; particular index
pushes account for the difference. A single oversized assertion would give
185,034 vB for two transactions on this fixture, but exceeds default relay
weight policy. These totals include creating and consuming every P2SH output,
helper signatures, count/length prefixes, empty legacy witness vectors, and
per-transaction rounding. They start with one existing P2TR funding UTXO;
creating that initial funding source, extra change, and refunds are excluded.

The inner HASH160 key table adds a binding assumption: honestly fixed keys
require second preimages, while malicious setup can seek colliding alternate
keys at the generic roughly 2^80 birthday scale. Direct embedded-key multisig
avoids this extra inner hash and costs about 200,690 vB for the compared
three-transaction layout. All setups remain purely algebraic, without ZKP.

The smaller variable-cardinality estimate is not the default: third parties
can erase optional revelations unless an additional binding mechanism prevents
it. See the [lookup analysis](../../../../research/pointlocks-2026-09-17/sum-lookup.md)
and [encoding comparison](../../../../research/pointlocks-2026-09-17/encoding-optimization.md).
Full BitVM3 challenge/refund integration, transaction malleability handling,
and a review of the complete protocol remain separate from this successful
publication experiment.

The [complete bare-legacy follow-up](../../../../research/pointlocks-2026-09-17/bare-publication.md)
uses 79 seven-of-48 pools and 553 revelations. Actual funding plus spending is
**161,382 vB**, with a **161,560-vB canonical maximum**. Core 30.3 mines funding
and all positive spending controls; independent decoding recovers the 256 bytes.
Evidence is `differentially-validated`, deployment `consensus-validated`, with
default relay-policy rejection. Per pool: 1,232-byte script, 140 executed
non-push opcodes, seven hints, 21 entry data items, combined-stack peak 73.
Across independent stacks: 553 hints and 1,659 entry items. Each bare input has
zero witness items but one serialized empty-vector byte beside the helper.
Funding/spending witness vectors occupy 66/145 bytes, plus marker/flag bytes.
The scripts retain 43 terminal stack items, allowed by bare legacy consensus.
Accepted partial spends and surplus codewords remain application boundaries;
complete setup timing has not been measured.

The [nonstandard-policy follow-up](../../../../research/pointlocks-2026-09-17/bare-nonstandard-policy.md)
admits and mines the identical bare transactions through the mempool using
`acceptnonstdtxn=1` and a scoped Core policy patch. Default policy still rejects
them, all 15 invalid controls still fail consensus, and the byte cost is unchanged.

A [Binohash HORS lookup comparison](../../../../research/pointlocks-2026-09-17/hors-lookup-comparison.md)
finds a smaller **153,125-vB maximum serialization estimate** using 58 ten-of-57
pools. The individual pool passes local legacy tests (200 non-push opcodes,
ten hints, 30 entry items, combined peak 91); full publication/Core validation
and complete setup timing remain outstanding. A direct-stack variant permits
11 selections but costs 153,687 vB. These estimates remain `locally-reproduced`,
`unclassified`; they do not replace the native validation above.

The [table-first lookup follow-up](../../../../research/pointlocks-2026-09-17/clamped-lookup.md)
reduces verification to 16 non-push operations per opening. The mixed profile
uses ten 12-of-67 and 38 12-of-68 pools, 576 openings, 576 index hints and 1,728
entry data items across separate stacks. Each pool has 12 hints, 36 entry items,
192 operations and combined peak 105/106. Core passes all 78 pool controls
(30 positive, 48 negative), with 282 independently extracted scalars. Exact
accepted pools are `differentially-validated`, `consensus-validated`.

| Table-first profile | Script bytes or estimated vB |
|---|---:|
| 12-of-67 bare locking script | <!-- metric:pointlock_clamped_pool_67_script -->1778<!-- /metric:pointlock_clamped_pool_67_script --> B |
| 12-of-68 bare locking script | <!-- metric:pointlock_clamped_pool_68_script -->1799<!-- /metric:pointlock_clamped_pool_68_script --> B |
| Mixed 256-byte publication, canonical maximum estimate | <!-- metric:pointlock_clamped_publication_estimate -->151176<!-- /metric:pointlock_clamped_publication_estimate --> vB |

The mixed total includes funding and spending every output. It is an estimate
from complete serialization shapes, with repeated pool fixtures and placeholder
helper signatures; full independent publication/decoding and setup timing are
pending (`locally-reproduced`, `unclassified`). Both witness vectors total
180 bytes excluding four marker/flag bytes. Upper index hints are clamped:
decode authenticated keys, not raw hint values. Unused hashes remain on the
terminal stack, allowed by bare consensus. Independent candidate generation,
HASH160 binding and application integration obligations remain.

| Recorded bare profile | Bytes or vB |
|---|---:|
| Locking script per seven-of-48 pool | <!-- metric:pointlock_bare_pool_script -->1232<!-- /metric:pointlock_bare_pool_script --> B |
| Complete funding and spending, increasing-byte message | <!-- metric:pointlock_bare_publication_vbytes -->161382<!-- /metric:pointlock_bare_publication_vbytes --> vB |
| Canonical maximum, complete funding and spending | <!-- metric:pointlock_bare_publication_max_vbytes -->161560<!-- /metric:pointlock_bare_publication_max_vbytes --> vB |

The subsequent [sub-100k research](../../../../research/pointlocks-2026-09-17/windowed-publication.md)
records a conditional 39,396-vB P2WSH profile, rejected for its impractical
`2^63.138`-compression setup, by changing to a windowed small-R predicate.
It does not preserve this module's exact extraction theorem and
has not mined its production search. A separate
[lossless-compression experiment](../../../../research/pointlocks-2026-09-17/conditional-proof-compression.md)
retains this sum-key primitive and validates a 92,706-vB synthetic 128-byte
publication, conditional on the application accepting that smaller payload.

An [offchain DDH batch-select experiment](../../../../research/pointlocks-2026-09-17/ddh-batch-select.md)
compresses a full label vector into aggregate scalar keys. It cannot directly
replace this module's subset-label translation: separately disclosing the
common-shift constituent scalars exposes both labels in the tested wrapper
(NR-067). The experiment supplies neither native aggregate-only extraction nor
public ciphertext verification and does not change this module's byte metrics.
