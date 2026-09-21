# R22: construct an ECDSA recovery pair from a native Taproot edge

Date: 2026-09-17. Question: can the actual control-block tweak equation
connect the canonical ECDSA pair to a hash and a point without first solving
R4's prescribed BIP340 challenge?

**There is a positive public algebraic interface.** Any suitable Taproot
edge `O = I + tG` gives an ECDSA signature whose recovery pair contains
`I` and `-O`, on an explicitly manufactured digest. No nonce or internal-key
logarithm is required. It has an acyclic generation order when the edge is
chosen first. The remaining transaction equation and endpoint binding are
precise, and unsolved. This is not a covenant or an honest spend algorithm
under the requested work bound.

The [fixture](r22_taptweak_interface.py) and
[results](r22_taptweak_interface.json) are `locally-reproduced` /
`unclassified`. General derivations and primary-source interpretation are
`inspected`. No Script/Core execution, Bitcoin transaction, real signature
hash preimage, rare search, or field-library test was performed. Leaf and
control-block bytes below are host commitment vectors, not deployment
measurements. No witness/data/hint count, stack peak, executed-opcode count,
validation budget, or transaction weight is claimed for a complete spend.

## Native values and their encodings

Use `I` for the even-y internal point and `O` for the raw tweaked output
point. The funded program contains only `x(O)`. The control block carries
`x(I)` and the parity of raw `O`. With current leaf version `0xc0`, exact
script bytes `L`, and a real Merkle path, consensus computes

```text
leaf = H_TapLeaf(0xc0 || CompactSize(len(L)) || L)
M    = sorted TapBranch folding of leaf and the control-block siblings
t    = int(H_TapTweak(x(I) || M))             reject t >= n
O    = I + tG                               reject infinity
```

It compares the funded x coordinate and the control-block parity with `O`.
The tweak is not silently reduced modulo `n`. The script begins after the
script, control block, and optional annex have been removed from its initial
stack. These are the exact native boundaries in
[BIP341 at commit 24e96e8](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0341.mediawiki#script-validation-rules).

The algebra below uses full points. In particular, its second ECDSA key is
`-O`, whose compressed prefix is the opposite of raw `O`'s parity. It is
not automatically the even representative used by BIP340.

## Positive construction: edge first, signature second

Start with a chosen even-y point `I` and a real leaf/tree commitment `M`.
Compute the valid native tweak and output. Define the midpoint

```text
J = I + (t/2)G.
```

Require `I`, `O`, and `J` to be finite and `J != infinity`. For any public
nonzero scalar `a`, calculate

```text
R  = J/a
r  = x(R) mod n                 require r != 0
s  = a*r mod n
z* = t*r/2 mod n.
```

The two ECDSA recovery equations then give exactly

```text
(s/r)R  - (z*/r)G = J - (t/2)G = I,
-(s/r)R - (z*/r)G = -J - (t/2)G = -O.
```

Thus the publicly computed signature `(r,s)` verifies under both keys on
digest scalar `z*`. Replacing `s` by `n-s` swaps the two nonce signs and
preserves the recovery set, permitting LOW_S normalization. The generator
never needs `log_G(I)`, `log_G(J)`, or `log_G(R)`.

To claim a *complete canonical pair*, additionally require that the only
valid nonce coordinates reducing to `r` are the chosen one: enumerate both
`r` and `r+n` below the field prime and their lifts. The general edge lemma
only establishes these two keys; it does not preclude two additional keys
when both coordinate branches lift. All 64 fixture instances explicitly
have exactly two nonce roots, finite distinct recovered keys, and the
complete recovery set `{I,-O}`.

This source signature is selected after the TapTweak result. It is not a
fixed-source search as in [R21](r21_hash_weight_cost.md), and does not
contradict that report's oracle bounds.

## Converse: the point equation yields an exact digest target

Let a canonical pair for an ECDSA signature and digest be

```text
A = (s/r)R - (z/r)G,
B = -(s/r)R - (z/r)G.
```

Suppose an actual binding identifies the native internal point with
`I=delta*A`, where `delta` is the sign making it even. Identify raw output
`O=kappa*B`; `kappa` is a full-point sign, not freely selectable output
parity after funding. Then the native equation is

```text
tG = O-I
   = -(kappa+delta)(s/r)R + (delta-kappa)(z/r)G.
```

For opposite signs, `kappa=-delta`, the unknown point cancels and

```text
H_TapTweak(x(delta*A) || M) = 2*delta*z/r mod n.       (1)
```

For equal signs, the equation instead publicly determines
`log_G(R)=-t*r/(2*delta*s)`. This extraction identity does not prove that
all possible constructions must avoid that branch.

Equation (1) is a different interface from R4's Schnorr challenge target:
it uses the script-path opening itself. The forward construction realizes
its opposite-sign branch with `delta=1` and manufactured `z*`. It still
must reconcile `z*` with the actual transaction digest. In the edge-first
family the missing equation is

```text
z_native(T, input, scriptCode, flag)
    = (t/2) * (x((I+(t/2)G)/a) mod n) mod n,          (2)
t = H_TapTweak(x(I) || M), with the native range check.
```

For a fixed public edge and fixed `a`, the right side is a prescribed
scalar. The fixture supplies no transaction satisfying (2), and no
sub-`2^64` method or advantage for the permitted outputs is inferred.
Choosing other `a`, leaves, or funding data creates a coupled search;
it must be analyzed in that form, rather than treating `z_native` as a
freely selectable scalar.

For orbit interfaces, the same exact bookkeeping applies. If recovered
keys have the form `K_i=c_i R-b_i G`, with `c_i` including the nonce sign
and `lambda^i`, a native edge from `delta*K_i` to `kappa*K_j` requires

```text
tG = (kappa*c_j-delta*c_i)R + (delta*b_i-kappa*b_j)G.
```

Zero unknown-point coefficient leaves a prescribed tweak scalar;
a nonzero coefficient publicly extracts the base nonce logarithm. This
states what the edge adds to [R21's orbit interface](r21_orbit_interface.md),
without asserting that the required keys or orbit are already bound by
Bitcoin Script.

## DER boundary of the particularly simple a=1 choice

For `a=1`, the construction has `s=r`. Strict DER plus one sighash flag has
length `7+len_DER(r)+len_DER(s)`. Therefore its length is odd and can never
be exactly a 20- or 32-byte native hash output. LOW_S does not repair this:
if `r<=n/2`, nothing changes; if `r>n/2`, `r` itself needs a 33-byte positive
DER integer, already making the complete signature longer than 32 bytes.

The weaker size requirement `length<=32` allows exactly
`1<=r<=2^95-1` for unnormalized `s=r`. This is not an exact32 encoding.
General public `a` need not give equal DER lengths, so the parity exclusion
must not be generalized to all edge-generated signatures. Nor is the
distribution of the generated pair `(r,a*r mod n)` a uniform 32-byte hash:
the earlier hash-to-DER density cannot be used as its search cost.

## Binding, funding, and signing remain separate obligations

The native opening binds **its actual** `I`, `M`, and `O`. It does not make
them available as stack values or authenticate copies used by another
input's ECDSA checks. Current tapscript does not execute the legacy ECDSA
recovery primitive. A separate input needs a compulsory execution link and
an enforced equality between its ECDSA keys and these actual endpoints.
Putting the protected value in the Taproot output can force the selected
leaf, but an unrelated optional ECDSA input supplies no such interface.

Embedding a chosen `I` in a leaf can be acyclic because it is selected
first. Embedding the eventual `O` in its own leaf adds
`O -> leaf -> M -> t -> O`. Witness copies avoid that literal commitment
cycle only if their missing equality check is supplied. The control block
does not provide that check to script by itself.

For the positive construction, the honest public generation order is

```text
I + complete chosen tree -> M -> t,O -> source signature and z*
                                   -> funding outputs -> funding txids
                                   -> actual spend outpoints -> z_native(T).
```

There is no cycle in producing those objects; equality (2) is the unsolved
last condition. Conversely, constructing the recovery pair from an actual
intended digest and then using its members as the funded internal/output
keys introduces the existing return dependency

```text
z_native -> I/O -> funding scriptPubKeys -> funding txids
         -> spend outpoints -> z_native.
```

Known and unknown internal scalars remain different. If the creator knows
`I=dG`, it knows the output scalar `d+t`, and the even-y BIP340 scalar is
`epsilon*(d+t) mod n`. Retaining that state permits unrestricted key-path
spending irrespective of the leaf. Choosing a public point whose logarithm
is not supplied avoids this immediate scalar bypass, but gives no native
key-path signature. This follows also from
[BIP341's tweak-key construction](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0341.mediawiki#constructing-and-spending-taproot-outputs).

Trying the midpoint as a BIP340 nonce returns to the already analyzed
challenge issue. Let `R_B=eta*J` and `Q_B=epsilon*O` be even, and let
`e=H_BIP0340/challenge(x(R_B)||x(Q_B)||m) mod n`, with `m` the actual Bitcoin
signature hash in a native spend. Then

```text
s_B G = (eta+e*epsilon)I + (eta/2+e*epsilon)tG.
```

The direct cancellation requires `e=-eta*epsilon` and
`s_B=-eta*t/2`. The control-block equation does not set that challenge.
Its byte inputs and parity rules follow
[BIP340](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0340.mediawiki#verification).
This observation reuses R4's limitation; the new positive result is the
ECDSA pair generated from the native edge, not a new Schnorr signer.

## Deterministic checks and next acceptance criterion

The host fixture uses 16 fixed labeled leaves, eight single-leaf trees and
eight trees with a real OP_RETURN sibling, and public scales `1,2,3,5`.
Their selected leaves push 32 bytes, drop them, and return true; they
deliberately do not restrict transaction outputs. Every encoded commitment
has a valid host opening equation; changing parity, leaf bytes, or the
funded x coordinate rejects, for 48 negative controls. Four output/midpoint
parity combinations occur. Sixty-four source pairs pass before and after
LOW_S normalization, with exactly two nonce roots each; changing the
manufactured digest to `z*+1` rejects the pair. The restricted midpoint
Schnorr cancellation equation passes with its artificial challenge and
rejects all 16 actual challenges on clearly labeled synthetic messages.
There are 513 deterministic DER boundary checks.

Reproduce with
`python3 research/covenant-2026-09-17/continuation/r22_taptweak_interface.py`.

A useful next success is an exact funded transaction satisfying (2), with
the actual endpoints authenticated to mandatory ECDSA checks, a fully
audited leaf tree, and an honest setup/witness algorithm below `2^64`.
Alternative-output spends must be harder despite retained setup state.
The native edge supplies genuine hash/point authentication, but the
manufactured-digest construction alone has not connected it to those
transaction conditions.
