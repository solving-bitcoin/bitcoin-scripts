# Sum-key point locks and a shared generator key

Question: can public-key setup remove the per-candidate signature commitment
and companion-key table, while preserving noninteractive scalar revelation
without a ZKP? The sum-key construction does this by changing which point is
locked: it locks `P+Q`, rather than one of the two verification keys.

## Extraction for every actual digest

Use the same DER signature `(r,s)` and raw sighash flag under distinct keys
`P,Q`, with the existing complete-item length guard `>57`. Reject `P+Q=infinity`.
The length guard excludes the alternative x-coordinate `r+n`; strict DER has
only seven bytes of overhead including the sighash flag, so an `r+n` case
has at most `17+33+7=57` bytes.

For the shared actual native digest `z`, both reconstructed points have
x-coordinate `r`. They cannot be equal because `P!=Q`, so they are opposite:

```text
(zG+rP)/s = -(zG+rQ)/s
P+Q = (-2z/r)G
```

An accepted transcript therefore gives the scalar of the locked sum point
directly as **`t=-2z/r mod n`**. This holds for ordinary digests as well as
the legacy SINGLE constant `C=2^248`. The previous commitment/self-reference
hardness question is not needed for this extraction argument. At `z=0`,
acceptance would force the excluded infinite target.

The script has no CODESEPARATOR and no pushed items as long as an accepted
signature. FindAndDelete therefore leaves both full scriptCodes unchanged.
For a pool, the same-signature/same-digest association must be preserved.

## Common-G generation: the useful subset variant

Set `Q=G`. Generate a candidate from a fresh secret nonce `k`:

```text
r = x(kG) mod n
t = -2C/r mod n
T = tG
P = T-G
s = (C+r)/k mod n
```

The signature verifies under G with reconstructed nonce `kG`, and under P
with reconstructed nonce `-kG`. Low-S normalization only swaps these signs.
Publish T and derive P publicly. The scalar of G is intentionally public;
producing an arbitrary signature under G does not make it valid under a
particular committed P. Any signature that passes both reveals log(P+G).

All candidates use the same G, so a `t-of-n CHECKMULTISIG` over distinct P keys
can select the pool, while the same signatures are each checked against G.
No selected public keys, signature-hash table, or index hints are inherently
needed. Every selected signature must still satisfy its length guard. A single
signature valid under G has at most one other recovered key; therefore it cannot
count twice against distinct P entries. The ordinary multisig ordering enforces
distinct matched key positions.

Reject duplicate P values, P=G, and P=-G. Nonces k and -k produce the same r
and target, so checking nonce bytes alone is insufficient. The common-G setup
generates T; it does not efficiently open an arbitrary preexisting T. Full-size
independent nonces avoid deliberately introducing public affine relations among
label scalars. Heavy nonce grinding needs a separate distribution analysis.

This makes the previous two-independent-pool cross-pair counterexample
irrelevant to the common-G layout: there is only one possible companion key.
It does not rehabilitate the original construction with distinct Q_i keys.

## A given target with two holder-generated auxiliary keys

For an arbitrary `T=tG` with known t, choose a small public nonzero multiplier
a, starting at one, until `r=-2C/(a*t)` lifts to a point R with x-coordinate r.
Each independent-looking candidate lift succeeds with probability about half;
this is an expected-cost statement, not a proved worst-case bound. Select a
secret nonzero random s and construct points using group operations:

```text
P = (sR-CG)/r
Q = (-sR-CG)/r
P+Q = aT
```

No discrete logarithm of R is needed. The holder publishes a,P,Q, and the
funder verifies `P+Q=aT`, P!=Q, finite keys, and nonzero a. The holder keeps
`(r,s)` secret. Any accepted spend gives `t=-2z/(a*r)`. The short public retry
counter a must be chosen by the stated procedure; choosing a from an arbitrary
secret-dependent formula can itself disclose t.

This general construction has two candidate-specific verification keys, so
it does not provide the common-G table savings. The stable source API currently
implements common-G generation and generic pair verification/extraction; the
given-target setup remains in the executable research probe.

## Local reproduction and limits

[Source](../../src/signatures/pointlocks/sum_key/mod.rs) and
[README](../../src/signatures/pointlocks/sum_key/README.md) implement the
standalone predicate. The [probe](../../examples/pointlock_sum_probe.rs) tests
twelve common-G candidates with deterministic nonce seeds `[7;32]` through
`[18;32]`, one given-target construction, and synthetic ordinary-digest algebra.

Each complete standalone script is **76 bytes**, with 71- or 72-byte signature
items and measured combined stack peak **3**. There is one signature data item,
zero auxiliary hints, no altstack, and one additional P2SH redeem-script push.
Legacy inputs have no witness items. Measurements exclude transaction framing,
authorization, and refund logic.

All 13 constant-digest scripts passed the default-options legacy interpreter;
36 wrong-flag, 57-byte-item, and wrong-key mutations failed. The given-target
constant-digest fixture uses a=1. A separate synthetic digest `23` repeated
32 times uses a=2 and passes both libsecp ECDSA checks and scalar extraction;
it is not a native ordinary-transaction preimage or a native spending vector.
Seven stable unit tests additionally check zero digests, invalid key relations,
duplicate targets, malformed encodings, and high-S/raw-flag extraction.

Evidence: `locally-reproduced` for the probe and tests, `inspected` for the
algebraic argument. The [Core report](sum_key_core_check.json) independently
passes all 50 expectations: 13 positive sum locks, 36 negative mutations,
and one historical cross-pair control. The exact single-lock fixtures are
`differentially-validated`; all positive P2SH spends are `policy-validated`.
Core is 30.3, commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`.
Compiler `124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`,
interpreter `702544c9a045ac4fc14846da6da6559e2b7cd9d1`, `ExecCtx::Legacy`,
`Options::default()`, stack limits enabled. The shared tapscript helper is not
used. Exported JSON contains exact Core-harness-compatible cases and explicitly
public test scalars.

```sh
cargo test --locked --lib signatures::pointlocks::sum_key::
cargo run --locked --example pointlock_sum_probe > /private/tmp/pointlock-sum-vectors.json
```

The equation proves extraction, not the security of an entire BitVM3 protocol.
The selected-subset encoding, total transaction size, payment binding, and
candidate-generation distribution must be assessed separately. No ZKP or
interactive setup is included. The common-G layout does not need HASH160
signature commitments; an ordinary P2SH wrapper still uses HASH160.

Primary sources for verification behavior are
[libsecp256k1 v0.6.0](https://github.com/bitcoin-core/secp256k1/blob/v0.6.0/src/ecdsa_impl.h)
and the [BIP66 strict DER specification](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki).
