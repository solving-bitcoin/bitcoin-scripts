# R13: the three-point orbit is an identity, not yet a native query

Question: can three native ECDSA signatures and one readable integer
`h in {1,2}` connect the endomorphism relation to Script arithmetic?

The exact orbit identity is useful, but the examined six-CHECKSIG predicate
does not enforce orbit membership. Two distinct output templates admit
three byte-distinct signatures under the same two keys. With every signature
and key retained, changing the claimed h from 1 to 2 still passes. The first
two signatures even have equal numerical r, which no genuine secp256k1
three-point orbit can have. This is a concrete missing check, not a general
impossibility result for native orbit predicates.

Evidence: `locally-reproduced`. Deployment: `unclassified`. The
[Python](r13_orbit_query.py) and [JSON](r13_orbit_query.json) use exact integer
and curve arithmetic plus an explicitly limited raw-vector interpreter.
There is no Core execution, actual funding, mined hash preimage, or complete
covenant in this report.

## Exact identity and its possible use

For the field prime p, curve order n and standard nonidentity endomorphism,

```
phi(x,y) = (beta*x mod p,y) = lambda*(x,y),
1+beta+beta^2 = 0 mod p.
```

The constants and scalar/point relation are documented by
[libsecp256k1 v0.6.0](https://github.com/bitcoin-core/secp256k1/blob/v0.6.0/src/scalar_impl.h).
For ordinary integer representatives `x0,x1,x2 in [1,p-1]` of one orbit,

```
x0+x1+x2 = h*p,                   h in {1,2}.
r0+r1+r2 = h*(p-n) mod n,         ri=xi mod n.
```

The sum is a positive multiple of p below 3p; x=0 does not lift to this
curve. If `u=r1/r0`, `v=r2/r1`, all divisions modulo n, then

```
r0 = h*(p-n)/(1+u+u*v) mod n.
```

The denominator is nonzero for a real orbit with valid nonzero r values.
This would reduce a scalar reconstruction to two ratios and a single small
integer, **if a native predicate authenticated those ratios and the orbit**.
Eight curve vectors verify the formula, including x=r+n cases. Script does
not gain direct access to the CHECKSIG nonce coordinates from this host
calculation.

At a shared pair of distinct recovery keys, when each accepted pair of
nonce points is antipodal, adding the two ECDSA equations gives

```
P+Q = -2*zi/ri * G.
```

Thus all `zi/ri` are equal. If the three nonces also form a genuine orbit,
then, for nonzero `z0+z1+z2`, necessarily

```
ri = h*(p-n)*zi/(z0+z1+z2) mod n.
```

These are necessary candidate values. Curve lifting, orbit membership and
the pair-width equations still have to hold. In particular, two equal
nonzero constant digests imply equal r under this antipodal premise and
therefore cannot provide two positions of the real orbit. This statement
does not silently exclude nonsymmetric pairs from a four-root recovery set.

## Pairwise distinct r, including order reduction

Different orbit coordinates cannot be equal in the field. If they reduced
to the same r modulo n, `p<2n` implies `x'=x+n` or `x'=x-n`. For exponent
`j=1,2` and sign `epsilon=+1,-1`, the only possible field coordinate is

```
x = epsilon*n/(beta^j-1) mod p,
x' = x+epsilon*n.
```

All four exact candidates have x' outside `[1,p-1]`. The JSON contains
their full integers. This exhausts the possible equal-r cases, rather than
checking only a sample of points or forgetting the r+n recovery branch.

## Actual native-hash countermodel

The 64-byte raw script requires exactly this initial stack, bottom to top:

```
h sigma0 sigma1 sigma2 P Q
```

It checks `1 <= h < 3`, two distinct 33-byte keys, and each of the three
signatures under both keys. It consumes the entry operands and leaves one
true. The two-input transaction places this input at index 1 with one
output. Consequently both `SINGLE` and `SINGLE|ANYONECANPAY` take the legacy
constant-hash branch, with ECDSA scalar `C=2^248`.

For each actual ALL digest z, the existing R11 lattice solver constructs
`R' = tR`, `r'/r=z/C`. Set

```
P,Q = (±R-CG)/r,
sigma0 = DER(r,1) || 03,
sigma1 = DER(r,1) || 83,
sigma2 = DER(r',low_s(r'/(t*r))) || 01.
```

These are three different byte strings, and all six native ECDSA equations
hold. The first two r values coincide, so this is not a three-point orbit.
Neither native digest nor any CHECKSIG operand depends on the h supplied
as a scriptSig item. Both h values pass with identical remaining data.
An additional byte-distinctness check would not reject these witnesses.

Two different output scripts at the same synthetic outpoints reproduce
this behavior, with respectively one and two native digest attempts.
Four positive h cases and ten negative cases pass their expectations. The
negative cases cover h=0, h=3, equal keys, changed alpha s, and changed
outputs with the old witness. Recomputing the public witness permits the
second output template. Honest use of the stated flags already provides
the countermodel; the raw predicate itself does not extract flag bytes.

| Measured boundary | Value |
| --- | ---: |
| Complete raw redeemScript | 64 bytes |
| Hypothetical P2SH locking wrapper | 23 bytes |
| Static/executed non-push operations | 39 |
| ECDSA checks | 6 |
| Entry data items, all coexisting | 6 |
| Auxiliary hint items | 0 |
| Combined main-plus-alt-stack peak | 8 |
| Full scriptSig including redeemScript | 291 bytes, 7 pushed items |
| Serialized witness | 0 bytes |
| Complete synthetic two-input transaction | 1,664 WU |

Input pushes, cleanup and terminal predicate are included in their stated
boundaries; no repeated fragment composition is measured. The local
interpreter is not Bitcoin Core and not the repository's Tapscript executor.
These are raw research fixtures, not policy-compiled library metrics.

The next falsifiable task is an enforced orbit or a different authenticated
observable whose accepted native witnesses determine a readable value.
Merely supplying h and checking three signatures is insufficient.
