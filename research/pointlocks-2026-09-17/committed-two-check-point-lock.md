# Committed two-check ECDSA point lock

Noninteractive point lock using legacy P2SH, a HASH160 signature commitment,
and two ECDSA checks.

Source and maintained implementation documentation: [`committed_two_check`](../../src/signatures/pointlocks/committed_two_check/README.md).

## Setup

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

The [size probe](../../examples/pointlock_batch_size_probe.rs) compiles the
complete predicates through the repository compilation policy:

One HASH160-committed lock uses **100 bytes**. Five locks use **500 bytes**,
within the 520-byte P2SH redeem-script limit; six would use 600 bytes.

A five-lock HASH160 batch uses ten signature checks. All five secrets must be
revealed together. Each lock consumes one signature data item and zero hint
items: five signatures and zero hints coexist at the five-lock predicate's
entry. The combined main/alt-stack peak is seven items by inspection; no
altstack is used. The P2SH `scriptSig` adds the redeem-script push. The legacy
point-lock input has no witness items. Script sizes exclude input serialization,
the P2SH funding wrapper, transaction framing, payment authorization and refunds.

Evidence is `locally-reproduced` for compiled sizes and `inspected` for the
written argument. Deployment of these new committed batches is `unclassified`:
they have not been Core-validated. The earlier [Core experiment](CORE.md)
validated the uncommitted 76-byte two-check and 79-byte three-check variants;
those results do not validate this commitment extension. Rare short low-S
signatures require a legacy-consensus high-S fallback that is nonstandard.

Reproduce sizes without running unrelated primitive tests:

```sh
cargo run --locked --example pointlock_batch_size_probe
```

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
The [1-of-N experiment](one-of-n.md) implements small selectable sets, with
five embedded-key choices or seven hash-authenticated-key choices fitting P2SH.
A compact 1-of-2,048 slot and complete proof-publication transaction remain open.

The previous **1,327 vB creation transaction + 31,975 vB spending transaction
= 33,302 vB** calculation is correct only for revealing **187 fixed points**.
It includes creating 38 P2SH outputs (`38 × 32 = 1,216` bytes) and consuming
all of them (`37 × 851 + 367 = 31,854` stripped input bytes), plus the P2TR
helper and transaction overhead. It assumes one P2TR funding input, a first
P2TR helper output, one P2TR destination output in the spending transaction,
60-byte ECDSA signatures, and 64-byte P2TR key-path signatures. It is **not an
assertTX size estimate for publishing a selectable 256-byte proof**.

The [transaction size probe](../../examples/pointlock_transaction_size_probe.rs)
retains this fixed-point sizing example, using real deterministic point-lock
signatures and P2TR witness placeholders. Evidence is `locally-reproduced`
serialization; deployment remains `unclassified`.

```sh
cargo run --locked --example pointlock_transaction_size_probe
```
