# Committed two-check ECDSA point lock

Noninteractive point lock using legacy P2SH, a HASH160 signature commitment,
and two ECDSA checks.

## Parameters and setup

Let `T = tG` be the point whose secret scalar `t` must be revealed. All scalar
arithmetic is modulo the secp256k1 group order `n`. Define:

```text
C  = 2^248
k0 = 2^-1 mod n
r0 = x(k0 G)
   = 0x3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63
Q  = -(2C/r0)G - T
```

Reject the publicly detectable cases `Q = infinity` and `Q = T`.

The holder of `t` signs `C` using nonce `k0`. Let `sigma` be the complete DER
signature including the `SIGHASH_SINGLE` byte `0x03`. Use the shortest of the
two equivalent S encodings (low-S) if the signature item is longer than 57
bytes; otherwise use its 61-byte high-S equivalent. Publish
`T` and `h = HASH160(sigma)`. The funder derives `Q` and constructs the script.
No ZKP or interactive setup protocol is included.

For fixed `t`, `C` and `k0`, `s = (C+r0*t)/k0` is fixed up to sign; there is
no free nonce to grind for a shorter signature in this construction. Low-S
uses at most 60 bytes. An honest shorter-than-58-byte G/2 signature would still
permit extraction, but the conservative length guard rejects it along with
all possible `r+n` cases. The high-S fallback passes that guard.

## P2SH redeem script

```text
# Initial stack: <sigma>
OP_DUP OP_HASH160 <h> OP_EQUALVERIFY
OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
OP_DUP <T> OP_CHECKSIGVERIFY
<Q> OP_CHECKSIG
```

Fund the ordinary legacy P2SH wrapper for this redeem script. The spending
`scriptSig` pushes `sigma`, followed by the redeem script. P2SH-wrapped SegWit
does not retain the required legacy signature-hash semantics.

## Spending and extraction

Place the point-lock input at an index without a corresponding output. The
legacy SINGLE bug then returns the digest bytes `01` followed by 31 zero
bytes, interpreted by ECDSA as `C = 2^248`. A complete honest transaction
normally needs at least two inputs and one output.

For signature `(r,s)` and actual digest scalar `z`, the two checks reconstruct:

```text
RT = (zG + rT)/s
RQ = (zG + rQ)/s
```

The size guard excludes the additional ECDSA field coordinate `r+n`:
that case would allow at most 17 DER bytes for `r`, hence at most
`7 + 17 + 33 = 57` bytes for the complete signature item. Consequently the
reconstructed nonce points must be equal or opposite. Since `T != Q`, they
must be opposite. Adding the equations gives:

```text
2zG + r(T+Q) = infinity
r = r0*z/C mod n
```

On the SINGLE-bug path, `z = C`, so `r = r0` and the nonce is `+k0` or `-k0`.
Anyone observing the signature can compute:

```text
t = (s*(+/-k0) - C)/r0 mod n
```

Try both signs and select the scalar whose public point equals `T`.

## Open security argument

For an ordinary spend, the signature commitment remains in the script that
the signature authenticates. A non-extractable spend would need to satisfy
both signature checks and the circular dependency:

```text
h = HASH160(sigma)
H_native(tx containing the script with h) = C*r(sigma)/r0 mod n
```

An arbitrary HASH160 collision is insufficient. On the constant-digest path,
every accepted signature still reveals `t`, even if the commitment has another
opening. For an already fixed honest commitment, a different opening concerns
second-preimage resistance. Adversarial setup also permits choosing the
commitment, signature and transaction together.

Proving that efficiently constructible non-extractable ordinary spends are
excluded remains open. Neither preimage resistance alone nor a concrete work
factor has been established for the complete construction. Identifying the
self-reference is not itself a hardness proof.

## Size and deployment status

The [size probe](../../../../examples/pointlock_batch_size_probe.rs) compiles the
complete predicates through the repository compilation policy:

One HASH160-committed lock uses <!-- metric:pointlock_hash160_two_check_script -->100<!-- /metric:pointlock_hash160_two_check_script --> bytes. Five locks use <!-- metric:pointlock_hash160_two_check_batch5_script -->500<!-- /metric:pointlock_hash160_two_check_batch5_script --> bytes,
within the 520-byte P2SH redeem-script limit; six would use 600 bytes.

A five-lock HASH160 batch uses ten signature checks. All five secrets must be
revealed together. Each lock consumes one signature data item and zero hint
items: five signatures and zero hints coexist at the five-lock predicate's
entry. The combined main/alt-stack peak is seven items by inspection; no
altstack is used. The P2SH `scriptSig` adds the redeem-script push. The legacy
point-lock input has no witness items. Script sizes exclude input serialization,
the P2SH funding wrapper, transaction framing, payment authorization and refunds.

Evidence is `locally-reproduced` for compiled sizes and legacy interpreter
execution, and `inspected` for the written argument. Deployment of these new committed batches is `unclassified`:
they have not been Core-validated. Targeted tests execute the exact policy-produced
one-lock and five-lock predicates using `ExecCtx::Legacy` with default
interpreter options and stack limits enabled, without script padding. The
shared tapscript execution helper is not used. The earlier [Core experiment](../../../../research/pointlocks-2026-09-17/CORE.md)
validated the uncommitted 76-byte two-check and 79-byte three-check variants;
those results do not validate this commitment extension. Rare short low-S
signatures require a legacy-consensus high-S fallback that is nonstandard.

Reproduce sizes without running unrelated primitive tests:

```sh
cargo run --locked --example pointlock_batch_size_probe
```

## API and stack contract

- `point_lock(T, h)` derives and checks `Q`, returning the complete predicate.
- `sign(t)` creates the honest signature with the shared high-S fallback.
- `signature_commitment(&sigma)` hashes the exact signature including its flag.
- `extract_from_transaction(T, h, bytes, tx, index)` checks the commitment,
  computes the full committed scriptCode digest, and verifies both equations.
  It is a transcript extractor, not a funded-prevout or full transaction validator.

Compile the returned Script with `ScriptCompilation::compile_with_policy()`.
For one lock, `... sigma -> ... true`; a standalone invocation leaves one
truthy item. To compose locks, verify each intermediate result. Supply the
signatures in reverse execution order so the first lock's signature is on top.
No altstack or auxiliary hints are required. Public parameters `T` and `h`
have no defaults. `T` must be a valid secp256k1 point and `h` is exactly 20 bytes.

## Script compatibility and standardness

Bare legacy and P2SH use the required ECDSA digest rules. Arbitrary bare scripts
are generally nonstandard. The P2SH batches fit the script-element and sigop
limits, but full transaction consensus and policy validation remain outstanding.
P2WSH, including P2SH-wrapped P2WSH, lacks the constant digest. Tapscript uses
Schnorr and unknown-key semantics for these 33-byte keys and is incompatible.
See [script types](../../../../docs/script-types.md) and
[standardness](../../../../docs/standardness.md).

## Operational notes

The signer uses non-constant-time research bigint helpers. A signature reveals
`t`: do not reuse it as an authorization secret. No concrete security work
factor or reduction from preimage resistance alone is claimed. No ZKP is used
for point-lock setup; the BitVM3 payload may itself be a zero-knowledge proof.

Targeted tests cover honest execution and extraction, a changed sighash byte,
malformed committed items at the length boundary, wrong transaction context,
and five distinct locks with correct and swapped signature order. Legacy
inputs have empty witnesses; unlocking data is in scriptSig. The transaction
size probe below includes its serialization. Per input there are one or five signature data items,
zero hints, and one additional redeem-script push for the P2SH wrapper.

```sh
cargo test --locked --lib signatures::pointlocks::committed_two_check::
cargo test --locked --test primitive_metrics pointlock_metrics_are_current
```

## Knowledge-base integration

Catalog: `signature/point-lock-ecdsa-hash160-two-check`.
See the [point-lock knowledge page](../../../../knowledge/primitives/point-locks.md),
[signature comparison](../../../../knowledge/comparisons/signatures.md), and
[open problems](../../../../knowledge/open-problems.md#op-017--point-lock-security-and-deployment-validation).
The original [research note](../../../../research/pointlocks-2026-09-17/committed-two-check-point-lock.md)
records the derivation and intended BitVM3 application.

## BitVM3 proof publication

The desired application is a noninteractive replacement for the digit slots in
Robin Linus's [adaptor-signature proof-publication construction](https://gist.github.com/RobinLinus/0fc7405ad7485c35465efb7996a7b014/d68af6b8461ea7bfa24ff0ed4f7738a11bd1d59a).
An 11-bit digit slot must allow selection among 2,048 candidate points. The
primitive implemented here locks exactly one fixed point; it does not implement
that choice. Consequently, 187 of these fixed-point locks do not publish an
arbitrary 256-byte proof. The earlier identification of a fixed-point lock with
an 11-bit digit slot was incorrect.

A direct binary construction needs **256 × 8 = 2,048 bit positions**, each
with two candidate point locks: **4,096 candidate locks** in total, with one
candidate revealed per position. The candidates need an OR/selection mechanism
and the surrounding protocol's binding and equivocation rules. The existing
five-lock batch is an AND of fixed-point predicates, so it cannot provide that
choice by simply batching the 4,096 candidates. A literal enumeration of all
11-bit choices would instead need 186 × 2,048 + 4 = 380,932 candidates when the
last slot carries only two bits (or 187 × 2,048 = 382,976 with uniform slots).
The [1-of-N experiment](../../../../research/pointlocks-2026-09-17/one-of-n.md)
implements small selectable sets with a shared verifier: five embedded-key
choices or seven hash-authenticated-key choices fit P2SH. It does not provide
a compact 1-of-2,048 slot or a complete proof-publication transaction.

The previous **1,327 vB creation transaction + 31,975 vB spending transaction
= 33,302 vB** calculation is correct only for revealing **187 fixed points**.
It includes creating 38 P2SH outputs (`38 × 32 = 1,216` bytes) and consuming
all of them (`37 × 851 + 367 = 31,854` stripped input bytes), plus the P2TR
helper and transaction overhead. It assumes one P2TR funding input, a first
P2TR helper output, one P2TR destination output in the spending transaction,
60-byte ECDSA signatures, and 64-byte P2TR key-path signatures. It is **not an
assertTX size estimate for publishing a selectable 256-byte proof**.

The [transaction size probe](../../../../examples/pointlock_transaction_size_probe.rs)
retains this fixed-point sizing example, using real deterministic point-lock
signatures and P2TR witness placeholders. Evidence is `locally-reproduced`
serialization; deployment remains `unclassified`.

```sh
cargo run --locked --example pointlock_transaction_size_probe
```


A [fixed-size subset encoding](../../../../research/pointlocks-2026-09-17/hors-subsets.md)
can share a pool across several revelations: a t-of-n pool has `binomial(n,t)`
possible values. This needs distinct-index enforcement and a measured shared
verifier; the 1-of-N sizes above are not threshold-script sizes.

The [CHECKMULTISIG comparison](../../../../research/pointlocks-2026-09-17/multisig-probe.md)
reduces the 2-of-6 CHECKSIG experiment to 512 redeem-script bytes by reordering
unlocking data. CHECKMULTISIG itself is larger (516 bytes for the best tested
pair-preserving layout); independent full-pool multisigs admit mismatched pairs.
