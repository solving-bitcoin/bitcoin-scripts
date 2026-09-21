# Legacy binding investigation, 2026-09-17

Question: can legacy signature relations or two shared FindAndDelete puzzles
give an exact-output covenant with less than 2^64 honest total work against a
creator retaining all setup state?

No complete construction was found. These are scoped exclusions and a
reproduced counterexample, not a general impossibility theorem.

## One free ECDSA signature does not bind two messages to equality

Let `n` be the secp256k1 group order, `G` its generator, and `z1 != z2` the
two reduced message digests. Choose `k=1`, `r=x(G)`, then calculate

```text
s = (z1 - z2) / 2 mod n
d = -(z1 + z2) / (2r) mod n
P = dG
```

The two verification equations are

```text
(z1 G + rP) / s = G
(z2 G + rP) / s = -G.
```

Both points have the same x-coordinate. Thus the **same** strictly DER-encoded
ECDSA signature and **same** public key verify both messages. Low-S
normalization preserves both verifications. Except for the elementary zero
exceptions, the construction takes ordinary scalar/point arithmetic, no grind.

The fixed four-byte legacy script

```text
OP_2DUP OP_CHECKSIGVERIFY OP_CODESEPARATOR OP_CHECKSIG
hex: 6eadabac
```

therefore accepts a freely supplied signature/public-key pair for arbitrary
output choices. Its first and second ALL scriptCodes are `6eadac` and `ac`.
The signature and key are in the unlocking script and do not occur in either
scriptCode, so the digest computation has no circular dependency.

The runnable [experiment](legacy_same_signature_counterexample.py) creates
two distinct P2WPKH output variants and verifies all four resulting ECDSA
checks both with independent affine curve equations and LibreSSL 3.3.6 through
`/usr/bin/openssl pkeyutl`. Its [saved vectors](legacy_same_signature_counterexample.json)
contain the complete transaction bytes, actual ALL digests, and signatures.

Evidence: `differentially-validated` **for these signature equations**.
Deployment of these standalone vectors: `unclassified`; their default outpoint
is synthetic. The subsequent [Core experiment](core_gate_check.json) supplies
a real isolated-regtest funding outpoint and confirms two P2SH output variants
against that same outpoint: `differentially-validated` / `consensus-validated`.
Both fail standard relay because of legacy CODESEPARATOR policy.
This experiment does not use the default
tapscript executor. The four-byte script is an explicitly fixed raw boundary
vector, not a script generated outside the repository compilation policy.

Inspected complete script boundary: four locking-script bytes, four static
and executed non-push opcodes, two initial data items, zero hint items,
106-byte scriptSig for each saved vector, no witness, combined main/alt-stack
peak four, one final truthy item. The bare output and CODESEPARATOR are not a
claim of standard relay acceptance.

This algebra is not a new cryptographic discovery: the repository's
`src/signatures/pointlocks/three_check/` already uses the opposite-nonce
relation for scalar extraction. The contribution here is its explicit use as
a counterexample to the proposed covenant shortcut, including separate output
variants and independent verification.

## A fixed r=s=1 signature closes that particular shortcut

For `sigma0 = 300602010102010101`, point candidates have x-coordinate 1 or
`n+1`. Direct field arithmetic shows that `x=1` lifts to a curve point `R`,
while `x=n+1` does not. Hence the only nonce points are `+R` and `-R`.

If the fixed signature verifies two digests `z1,z2` under the same `P`, then

```text
z1 G + P = epsilon1 R
z2 G + P = epsilon2 R,
epsilon1,epsilon2 in {-1,+1}.
```

Either the reduced digests agree, or their difference discloses a discrete
logarithm of R:

```text
(z1 - z2) G = +/-2R
log_G(R) = +/-(z1 - z2)/2 mod n.
```

Thus the free-signature counterexample does not break the handoff's fixed
signature gadget. It instead makes the missing honest shortcut precise: a
pair of unequal digests satisfying it entails a discrete-log computation;
equal digests from genuinely different serialized contexts entail a reduced
hash collision. This observation does not assign a tight work factor to an
arbitrary correlated search.

## Two native contexts do not supply a good-only shared predicate

For two checks of the same input using the same full sighash byte, their
legacy serialization differs only by the active scriptCode after
FindAndDelete/CODESEPARATOR processing. If a common selected subset makes
these scriptCodes byte-identical, they have identical digest gates for **all**
output lists. The agreement is not specific to the intended outputs.

If the processed scriptCodes differ, canonical transaction serialization
preserves that difference. The intended outputs do not make those two
preimages identical. Different full sighash bytes additionally create
different four-byte trailers; even two bytes that select the same base
sighash semantics do not remove this domain distinction. The out-of-range
SINGLE special case returns a constant, but drops the wanted output binding.

Consequently, sharing dummy subsets and recovered keys between two native
rounds does not by itself instantiate the handoff's K2,2 equality model.
It still needs a separate representation provably restricted to the intended
outputs. This is a scoped statement about identical-input legacy contexts,
not all conceivable multi-input signature constructions.

## Cheaper native gate: DER parsing without a recovery key

The original hash-to-DER gadget additionally requires its hash output to
verify under a recovered public key `Q`. That condition can be removed when
only the public rare event is wanted. Under legacy consensus rules,
signature DER validation precedes verification, and an empty public key
makes cryptographic verification return false. Thus

```text
OP_SHA256 OP_0 OP_CHECKSIG OP_NOT
hex: a800ac91
```

accepts exactly those preimages whose 32-byte SHA256 value is syntactically a
strict DER signature plus one arbitrary sighash byte. Malformed DER aborts
before OP_NOT. This use of a nonempty failed signature/invalid key is excluded
by ordinary relay policy; it is a legacy consensus-oriented observation.

With the fixed ALL check, one obtains the following 16-byte public puzzle:

```text
<300602010102010101> OP_OVER OP_CHECKSIGVERIFY
OP_SHA256 OP_0 OP_CHECKSIG OP_NOT
hex: 0930060201010201010178ada800ac91
```

It consumes one supplied transaction-bound point `P`; there is no `Q` item or
second-key recovery. The full transaction-bound PoW has not been mined here.
The gate can separately be exercised with the handoff's known preimage
`00000000000000000200a8013bbb8678`.

Under a uniform-hash model, its success probability is exactly

```text
p = 2^-48 * [2*(1/2)*(255/512) + 22*(255/512)^2]
  = 780555 / 2^65
  = approximately 2^-45.4258592336.
```

Here `len(r)+len(s)=25` gives 24 partitions. A canonical nonnegative DER
integer of one byte occupies 1/2 of its byte space; for length at least two
the fraction is 255/512. DER-encoded zero is included, since no successful
ECDSA verification is requested. This is an analytical estimate under the
uniform-hash assumption, not a mined-work measurement. It does not include
the curve cost of generating candidate `P` values. It also supplies no
honest/creator asymmetry, so it is not a covenant.

## Primary-source boundary

Legacy suffix selection and FindAndDelete are in `EvalChecksigPreTapscript`;
separator removal and transaction serialization are in
`CTransactionSignatureSerializer`. Inspected source:
[Bitcoin Core 30.3, commit 49faec4f87f5cd19c88db01a82e5c68b087c8227](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).

Reproduce the algebraic experiment:

```sh
python3 research/covenant-2026-09-17/legacy_same_signature_counterexample.py
```

No catalog primitive, compilation policy, metrics fixture, or existing source
file was changed. No field-arithmetic repository tests were run.
