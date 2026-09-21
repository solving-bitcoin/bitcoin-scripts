# R8: two short DER signatures with affine-related keys

Date: 2026-09-17. Question: can a second correlated DER signature cancel the
fixed layout constant C0, keep a genuinely short nonce coordinate, and give
an honest native output-binding construction below `2^64`?

**The scalar cancellation can be constructed, but this family does not yet
give a covenant or the required native hash search cost.** Unlike the fixed
key `P=−A*G` in R6/R7, a nontrivial affine relation between two public keys
admits two distinct 32-byte DER signatures on the numerical value of the
first signature. Both use the real short-r nonce `G/2`. The missing part is
obtaining these very constrained blobs as actual native hash outputs and
authenticating the key/byte relation within one mandatory spend.

The experiment is `locally-reproduced`, deployment `unclassified`. It checks
108 actual secp256k1 cases. These are synthetic digest identities, not mined
hashes or executed Bitcoin scripts. No new locking-script size, serialized
witness size, entry-data count, hint-item count, combined stack peak or opcode
count is reported: there is no executable Script implementation of the
required affine point/byte relation. No Core, repository Script executor,
Rust tests, or field-arithmetic tests were used.

## A concrete coupled family

Fix a common full sighash flag f, the known nonce scalar `k=1/2 mod n`, and

```
r = x(kG) = 0x3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63.
```

This r has 21 strict-DER bytes. Thus a 32-byte DER signature including its
flag has a four-byte s. Set

```
alpha = DER(r,s,f)
beta  = DER(r,q*s,f)
z     = int_big_endian(alpha) = C0 + A*r + 256*s
A     = 2^56
B     = A + C0/r mod n.
```

Choose q so s and q*s both retain their four-byte minimal encoding. For
example, q=2 permits

```
2^23 <= s <= 2^30−1.
```

Now define

```
d1 = (k−256)*s/r − B
a  = (k*q−256)/(k−256) = (512−q)/511
d2 = a*d1 + (a−1)*B
P1 = d1*G
P2 = a*P1 + (a−1)*B*G.
```

All divisions are modulo the curve order n. The two actual verification
equations are

```
z + r*d1 = k*s
z + r*d2 = k*q*s.
```

Consequently alpha verifies under P1 and beta verifies under P2, on the
**same** digest z and with the **same** short-r nonce. The fixed DER prefix
constant really cancels. It is not silently set to zero, and r is not forced
to the too-large x coordinate of 256G.

The formula also works for `k=−1/2`, replacing a by `(512+q)/513`. For this
specific r, `r+n >= p`, so both signs of G/2 exhaust the recovery points; no
additional x=r+n branch is omitted. Generalizing to another r would require
checking that branch explicitly.

For q=2, f=ALL and s=`2^23`, a concrete example is:

```
alpha = 301d02153b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6302040080000001
beta  = 301d02153b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6302040100000001
P1    = 0277d2d31c04d51f5f943c62f0f6c67b45c075c78cade4ca97f16dcf8a1e31677c
P2    = 037aea9f219f527db37ffa232033b9932297ba83b74449bd3b477df8cb4c8a555b
```

The companion program checks both nonce signs, q in `{2,3,5}`, six flag
values, and three s values including the smallest and largest allowed
values: **108 pairs of valid signatures**. It independently checks the
affine point identity, the DER lengths, and
`int(beta)−int(alpha)=256*(q−1)*s`.

This family has no unknown secret; all d values are explicitly computable.
It is a scalar construction, not a claim that knowing these keys enforces
outputs. The q=1 endpoint collapses to identical signatures and identical
keys, so reusing exactly one blob does not produce a second independent
constraint in this family.

## Obtaining the blobs from hashes is still expensive

Fixing the known small-r nonce makes alpha much more constrained than a
generic SHA256-to-DER gate. For q=2 and one fixed flag, the entire permissible
alpha set has

```
M = 2^30 − 2^23 = 1,065,353,216
```

members. Under a uniform 256-bit native hash model, a concrete transaction
hash lands in that set with probability `M/2^256`. Even granting that the
public keys may be derived afterward and that the blob/native-digest binding
has somehow been provided for free, the expected native search is about
**`2^226.0113` hash queries**. This is a cost estimate for this fixed-r,
fixed-layout, fixed-flag family, not a lower bound for all coupled-DER
constructions. The q=3 and q=5 domains are smaller still.

Making beta a second native hash result adds an obligation. For example,
`beta=SHA256(alpha)` is a concrete available hash-chain relation, but requires
that SHA256 map one of these M alpha blobs to its exact prescribed beta.
In an ideal SHA256 model the expected number of such pairs over the **entire
domain** is only `M/2^256`. There is no arbitrary new s after that finite set
has been exhausted. The 108 synthetic pairs are not SHA256-chain hits.

If independent hash inputs U and V are allowed instead, the prescribed
pairs form a set of only M points in the 512-bit output-pair space. Two
independent batches with Q_U and Q_V queries have expected matching-pair
count

```
Q_U * Q_V * M / 2^512.
```

At a total query budget `Q_U+Q_V <= 2^64`, that favorable batch model gives
about `2^−356.0113` expected pairs for q=2. This is a specified independent
batch model, not a proof about arbitrary adaptive or algebraically linked
hash inputs. Setup, storage, point work and output verification have not
been charged, so those omissions cannot improve the candidate's accounting.

Supplying beta directly as an unrestricted witness blob avoids hashing beta,
but then it is not a second hash commitment. The relation `s_beta=q*s_alpha`
is a relation between embedded DER integers. A Script that merely checks
both complete signatures does not automatically implement a byte-level
proof of that relation. Similarly, the mathematical formula for P2 does not
by itself implement an on-chain affine point check for witness keys. Those
are concrete missing constructions, not independent capabilities being
assumed available here.

## Fixed keys collapse the remaining target freedom

If d1 is fixed in the funding script, then the first self-digest identity
forces

```
s = (C0 + A*r + r*d1)/(k−256) mod n.
```

There is exactly one candidate s per nonce sign, because neither
`1/2−256` nor `−1/2−256` is zero modulo n. Thus the M different s values
used by the construction require changing the key. They are not M
post-funding choices under one fixed script. With the preselected flag and
r retained, at most two self-digest targets remain before the second
signature and its affine relation are checked.

Choosing s, deriving the two keys, and embedding them in a funding output
therefore leaves the actual spending transaction hash to be matched against
the predetermined target. Choosing keys after calculating the concrete
spending hash instead changes the funding transaction and its outpoint,
unless the keys are unconstrained witness data. In that latter case their
affine relationship and the output reference must still be enforced by the
mandatory script. The depositor's ability to inspect a spend before
broadcast does not remove this dependency.

The literal example uses ALL for both signatures. The host model also checks
NONE, SINGLE, ANYONECANPAY|ALL and other bytes to ensure the scalar algebra
does not secretly exclude them. Its common-z calculation assumes both
checks actually use the same full flag and scriptCode. Different flags may
select different native hashes, invalidating that common-z equation. A
complete construction must enforce the intended flag or otherwise prove
complete output binding. An honest ALL selection is insufficient.

## Result and remaining route

This is an explicit algebraic escape from the single-key fixed-DER
cancellation: two different short DER signatures and affine-related keys
work on the same digest without requiring nonce 256G. It does **not** escape
the native hash-to-blob and funding obligations. In this precise fixed-r
family, even the favorable search granting free witness-key derivation is
far above `2^64`.

A potentially different family would need many cheaply generated small-r
nonces, or another actually supported correlation between the two native
hash outputs, together with a mandatory representation/key check. Its
target cardinality and post-funding degrees of freedom must be counted;
the scalar cancellation alone is not an honest search advantage.

ECDSA verification and recovery use
[SEC 1 v2.0, 21 May 2009, §§4.1.4–4.1.7](https://www.secg.org/sec1-v2.pdf).
The affine family and all cost estimates here are local derivations.

Reproduce:
`python3 research/covenant-2026-09-17/continuation/r8_coupled_der.py`.
