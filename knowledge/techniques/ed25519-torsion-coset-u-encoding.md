# Ed25519 torsion-coset u encoding

## Question

Can an Ed25519 prime-subgroup point be represented by one canonical field
element, with no Edwards sign bit and no ambiguity in the final verification
equation? The Montgomery slope-chain candidate needs this to compare only its
retained `u` coordinate while keeping zero digits and every intermediate
addition away from exceptional affine points.

## Construction

Let `H=<B>` be Ed25519's odd-order prime subgroup. On the Edwards curve, let

```text
T = (0,-1),             order 2
U = (sqrt(-1),0),       order 4, with 2U=T.
```

For `R in H`, define

```text
encode_U(R) = canonical_field_encoding(u(R-U)),
```

where `u` is the Edwards-to-Curve25519 Montgomery coordinate. This is a custom
32-byte point encoding; it is not RFC 8032 compressed Edwards encoding.

The encoding is injective on `H`. If two encoded values are equal, the two
Montgomery points have the same `u` coordinate and are equal up to negation:

```text
R1-U = R2-U                 => R1=R2
R1-U = -(R2-U)              => R1+R2=2U=T.
```

The second case is impossible: `R1+R2` is in the odd-order subgroup `H`, while
the nonidentity order-two point `T` is not. The translated point cannot be an
exceptional Edwards identity or order-two point for the same coset reason.

The H16 verifier keeps its computed prime-subgroup result `X=[s]B-[h]A` in
the translated coset as `X-U`. Comparing only canonical
`u(X-U)` with `encode_U(R)` therefore proves `X=R`; the ordinary Montgomery
`P` versus `-P` ambiguity cannot cross from `-U+H` to `U+H`. The active G32
leaf supplies that canonical field value directly as 51 radix-32 items so the
last slope relation and the transcript hash can share it without retaining a
second packed copy.

## Slope-chain use

Every selected subgroup contribution after the response-top initializer is
translated by `T`, so a zero scalar digit selects the real affine point `T`
rather than the identity. The initializer includes `T` exactly when required
by the parity of the remaining selections.

The historical G29/H16 schedule has 44 post-initializer selections. Its
response-top leaf is

```text
P0 = U + (T + Qtop) = -U + Qtop.
```

The other 44 leaves each add `T + Qi`. Equivalently, across all 45 selected
groups the accumulated translation is

```text
U + 45*T = U+T = -U.
```

Thus the final chain point is `-U+[s]B-[h]A`. For an honest signature with
`[s]B-[h]A=R`, its packed Montgomery `u` is exactly `encode_U(R)`.

The current G32/H16 schedule instead has 47 post-initializer selections. Its
response-top leaf starts at `U+Qtop` without `T`; the remaining leaves add
`47*T=T`, again ending at `-U+[s]B-[h]A`. The parity change is mandatory:
reusing the G29 top initializer would move the result into the wrong torsion
coset.

This encoding and translation require exactly **zero witness-hint items**.
They change table constants and the final comparison. The historical hinted
G29 leaf separately needs 88 quotient hints; the current quotient-derived
G32 leaf needs zero hints across all 47 transitions.

## Security and evidence boundary

The host algebra fixture in
[`examples/ed25519_montgomery_slope_chain_model.rs`](../../examples/ed25519_montgomery_slope_chain_model.rs)
reproduces the coset identities, the custom signing equation, all 45 host
point additions, and the final encoding equality. Evidence is
`locally-reproduced` for that host-algebra boundary and deployment is
`unclassified`.

The linked fixture pins the birational map to `u=(1+y)/(1-y)` and
`v=sqrt(-486664)*u/x`, maps the exceptional `T=(0,-1)` to `(0,0)`, selects
`sqrt(-1)=0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0`,
and selects the `v` scale
`0x0f26edf460a006bbd27b08dc03fc4f7ec5a1d3d14b7d1a82cc6e04aaff457e06`.
Independent validation must still cover those constants, the exact fixed
public key and table generation, canonical field encoding, and subgroup
membership of `A` and `B`. The custom BLAKE3 signature scheme needs
independent cryptographic review; this argument establishes encoding
injectivity and removes the final sign ambiguity, not a security reduction or
RFC 8032 compatibility.
