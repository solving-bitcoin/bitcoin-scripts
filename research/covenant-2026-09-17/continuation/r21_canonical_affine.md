# R21: canonical recovery pairs and an affine Schnorr interface

Question: does the already-known canonical two-key ECDSA recovery set supply
an output-binding value for a mandatory auxiliary input, when that value is
used as a native Schnorr verification key? This report classifies **fixed
scalar affine aggregates** of the pair, including the x-only sign ambiguity.
It also records a nonlinear, permutation-invariant aggregate outside that
classification. No complete covenant or general impossibility result follows.

The [fixture](r21_canonical_affine.py) and [results](r21_canonical_affine.json)
are `locally-reproduced` / `unclassified`. They contain host point and signature
equations, not a new Script or a complete spend. No Core run, Rust change,
field-library test, new witness layout, or resource measurement is included.

## The canonical native primitive is prior work

[Search 3](../seven/search3_native_algebra.md) already established the fixed
signature `r=s=1`. Its nonce roots are exactly `+R,-R`, where `R=lift_x(1)`;
`n+1` does not lift. Requiring two distinct, canonical 33-byte compressed keys
to accept that literal signature under one native digest forces the complete
unordered pair

```
P+ = (sR - zG)/r
P- = (-sR - zG)/r.
```

Here and below scalars are modulo the odd prime order `n`, with `r,s != 0`.
This describes cases where both keys are finite. The map from a verifying
public key to its nonce point is injective. Pair uniqueness is therefore a
native property, without knowing `log_G(R)` or deleting a key.

The previous `two-recovery-keys-same-context` record in
[core_fragments.json](../seven/core_fragments.json) is
`differentially-validated` / `consensus-validated`; its relay-policy check
rejects signature FindAndDelete. It has a 23-byte P2SH locking script,
75-byte redeem script, 144-byte scriptSig, 22 executed redeem-script non-push
operations, two redeem-entry data items and zero hints. Its inspected
combined stack peak is five; the scriptSig also pushes the redeem script,
for three scriptSig pushes. Its legacy transaction is 226 bytes / 904 WU
and has no witness. These are **reused prior measurements**, not a new R21
execution. The R21 fixture recomputes exactly the two public keys in that
saved Core record from its actual native digest.

Canonical encoding does not order the pair. In 64 actual legacy ALL digest
contexts obtained by varying that prior transaction's locktime from 0 through
63, the pair contains zero, one, or two even-y public keys in 18, 28, and 18
cases respectively. Thus choosing an even-y key would not generally choose
one unique member, even if a prefix reader were granted. No native sorting
or prefix-reading primitive is supplied here.

## Exact fixed-coefficient classification

Let `a,b,c` be public fixed scalars, and consider

```
A = aP+ + bP- + cG = uR + vG
u = (a-b)s/r
v = c - (a+b)z/r.
```

Swapping the two input keys gives `A'=-uR+vG`. Because `R` and `G` have
nonzero prime order:

- Equality as full points, `A'=A`, holds exactly when `u=0`, hence `a=b`.
- For finite `A,A'`, equality of their x-only keys holds exactly when
  `A'=A` or `A'=-A`, hence exactly when `u=0` **or** `v=0`.

The second branch must not be omitted merely because a native BIP340 key is
x-only. It does preserve an unknown nonce-log term. But for fixed asymmetric
coefficients to be invariant as an x-only key at two distinct digest scalars,
`v(z)=0` at both values requires `a+b=0,c=0`. The aggregate then becomes

```
A = (2as/r)R,
```

which is independent of the digest. In particular, `P+ - P-` yields the same
x-only key after a swap, but loses all transaction dependence.

The other branch, `a=b`, yields the public signing scalar
`v=c-2az/r`. BIP340's even-y adjustment changes this scalar to `v` or `-v`
as necessary; it does not make a public scalar unknown. A native Schnorr
check under such an aggregate supplies no signing restriction by itself:
for any fixed aggregate chosen using a public reference digest, everyone
can sign a different message under the same aggregate key. This observation
is conditional on there being no additional output-restricting checks.

For `u != 0`, possession of the aggregate's **scalar** `ell` gives
`log_G(R)=(ell-v)/u`. This is an exact reduction for computing a secret-key
scalar. It does not assert that a single Schnorr signature reveals that
scalar, nor that every signing method must first compute it.

The classification is limited to fixed coefficients and an unordered pair.
It does not cover coefficients that depend on the keys or digest, a proven
native ordering rule, or a nonlinear function of the pair.

## Known and unknown nonce logarithms are different cases

The fixture checks both `R=lift_x(1)`, for which it is given no nonce scalar,
and `R=G/2`, for which the public scalar is `1/2`. The latter's recovery keys
already have public signing scalars `(s/2-z)/r` and `(-s/2-z)/r`.
Consequently every aggregate built with publicly computable scalar
coefficients has a public scalar in that case, even when the coefficients
depend on the keys.

There are twelve fixed-coefficient vectors, six in each nonce case. Eight
aggregates have a demonstrated public signing scalar. Each signs two
different saved BIP341 hashes, giving sixteen successful BIP340 equation
checks. The hashes are the original and helper-omission hashes from
[R20's actual Core record](r20_taproot_reference_core.json). The generated
aggregate-key signatures are **not spend witnesses for that old record's
7G leaf**. They test the signing equation on concrete distinct messages.
The four difference vectors also keep exactly the same aggregate when `z`
changes to `z+1`.

BIP340's x-only keys, even-y normalization, and verification equation are
specified in [BIP340 at commit 24e96e8](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0340.mediawiki#verification).
The affine classification above is our derivation.

## A nonlinear escape is real, but not yet a signer

A blanket statement that every permutation-invariant weighted aggregate
cancels `R` would be false. For example, let

```
H(P) = SHA256(compressed(P)) mod n
F(P,Q) = H(P)P + H(Q)Q.
```

Swapping the input pair leaves the full point unchanged: each coefficient
travels with its key. No ordering operation is required by the mathematical
function. For the actual canonical pair reused from Core, the fixture finds
`H(P) != H(Q)`, so `F` retains a nonzero coefficient of the unknown-log `R`.
It supplies neither a native implementation of the point/hash encoding
relation nor an honest Schnorr signer for this output point.

The separate [fixed-source hash-weight analysis](r21_hash_weight_cost.md)
examines the `H(P)=H(Q)` branch that cancels `R`. Its bound is scoped to that
branch and a source signature fixed before point-hash queries. It is not a
bound on all nonlinear interfaces or all ways to produce a Schnorr signature.

## Missing interface and dependency graph

For an ordinary output-committing auxiliary sighash the dependencies are:

```
funding outpoints + auxiliary script + spend outputs
                 -> actual native z_aux
                 -> canonical unordered auxiliary pair
                 -> proposed point/scalar/byte interface
                 -> main-input acceptance
```

Native uniqueness establishes the second arrow inside the auxiliary input.
It does not make its two stack items readable by another input.
[BIP341's DEFAULT commitments](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0341.mediawiki#common-signature-message)
cover the auxiliary outpoint and scriptPubKey, but do not copy that input's
unlocking values into the main input's stack. R20 already demonstrates the
difference between committing the locking script and binding arbitrary
auxiliary rows. Canonical rows remove that particular row freedom; they do
not, by themselves, add the missing cross-input equality check.

If the main locking script or its committed Tapleaf embeds the result only
after computing `z_aux`, it also changes funding and therefore the committed
outpoint, creating a return dependency to `z_aux`. Supplying the result as a
main-input witness avoids that setup step but requires an actual native
binding to the auxiliary pair. Neither step is resolved by this report.

A successful next construction must give complete funding and spending
bytes, force execution of the auxiliary check, enforce that the main value
is the chosen function of that actual auxiliary canonical pair, and provide
an honest accepted-output signer/setup algorithm below `2^64` total work.
With all setup state retained, an alternative-output transaction must fail
for an enforced reason unavailable to a fresh public witness/signature. A
fixed public aggregate scalar, a digest-independent difference key, or a
claimed cross-input stack value does not meet that acceptance criterion.

Reproduce: `python3 research/covenant-2026-09-17/continuation/r21_canonical_affine.py`.
