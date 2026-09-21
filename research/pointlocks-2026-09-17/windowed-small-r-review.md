# Review of the windowed small-R P2WSH candidate

Question: can correlated but hidden scalar offsets amortize the honest work
of producing very short signatures across every candidate in a selectable
pool, while retaining useful unrevealed point labels?

The proposed honest algorithm is algebraically consistent. Hidden offsets
do not immediately disclose unselected labels after a subset is opened.
However, this changes the primitive's guarantee: extraction is conditional
on the spender not producing another valid signature within the length cap
whose nonce is not `+/-G/2`. The exact sum-key extraction guarantee does not
carry over. The estimates below are `inspected`; deployment is `unclassified`.
No full grinding run, funded transaction or Core validation is claimed here.
Compiler sizing and pool fixtures are separate artifacts.

## Honest algorithm and the missing circularity

Let `k0=1/2 mod n`, `r0=x(k0G)`, whose positive DER integer has 21 bytes.
Choose a secret base b and independent hidden offsets `a_i in [0,A)`. Set

```text
t_i = b + a_i/(2r0) mod n,       T_i=t_iG.
```

After the keys, locking scripts and funding transaction are fixed, a native
BIP143 digest z gives the raw honest signature scalar

```text
s_i = (z+r0*t_i)/k0 = 2z+2r0*b+a_i mod n.
```

Thus only the shared center `S=2z+2r0*b` needs grinding. For cap 53, the
signature item consists of seven framing/sighash bytes, 21 r bytes and at
most 25 s bytes. Positive DER encoding therefore requires low-S `<2^199`.
Write H=`2^199`, `D=max(a)-min(a)`, and assume all offsets are distinct.

The exact interval of center representatives satisfying
`1 <= |S+a_i| <= H-1` for every i has

```text
2H - 1 - D - n_candidates
```

integer values. The candidate-count term removes zero signatures. Mixed
signs across the pool are harmless: low-S normalization negates the nonce,
and extraction checks the two known nonce signs separately against T_i.
Restricting to common-sign bands is also valid but unnecessarily discards
roughly D additional center values.

For `A=2^190`, the success probability is approximately `2^-56`; its
dependence on the number of candidates is negligible at these parameters.
For cap 54 the corresponding H is `2^207`, giving approximately `2^-48`.
Cap 52 would already cost approximately `2^64` digest trials per pool before
SHA256 compression accounting or multiple pools, so it does not meet the
proposed total honest budget by this method.

SIGHASH_SINGLE|ANYONECANPAY makes the corresponding output available for an
independent nonce grind for each input. Every input still needs its matching
output and all those outputs must be charged. Funding fixes all outpoints
before the grind; the known acceptance interval replaces a digest fixed-point
problem with an ordinary search. Use actual nonce-bearing output data in the
construction. Varying a P2TR public key by scalar multiplication on every
trial would add work; putting arbitrary bytes in a P2TR program may instead
make outputs unspendable. A nonce-bearing OP_RETURN output has clear semantics,
subject to the explicitly documented relay policy for the complete output set.

## What openings reveal about the hidden offsets

Scale every label by the public factor `2r0`:

```text
u_i=2r0*t_i=B+a_i mod n,          B=2r0*b.
```

Once some u values are disclosed, the hidden base lies in an interval of
width `W=A-(max(a_open)-min(a_open))`. For q independently sampled uniform
offsets, its expected width is `2A/(q+1)`. This is not an interval of that
size for each unopened label: an unopened label retains its own independent
offset. Its possible u values occupy an interval of width `A+W`, with expected
width `A*(1+2/(q+1))`.

Accordingly, `A=2^190` leaves an approximately 190-bit interval search for an
unopened scaled label, or an approximately 95-bit square-root interval-DLP
estimate. This is a conditional generic-algorithm estimate, not a proof.
Larger public target sets, preprocessing and the complete application deserve
separate analysis. Publishing sorted offsets, their numerical values, or
additional relations would be a different construction. The offsets here
must be independently sampled and kept hidden.

The public points already reveal bounded differences
`2r0*(T_i-T_j)=(a_i-a_j)G`; a subset of openings does not create that relation
for the first time. The signature scalars reveal no extra independent offset
equation: after the actual digest is public, they give exactly the opened t
values through the known-nonce extractor.

This permits computationally hidden correlated labels, rather than fully
independent 256-bit scalar secrets. A protocol using the labels must accept
that distinction. It is not enough to call them independent because each
offset was sampled independently.

## The outstanding short-signature assumption

For every accepted signature with `r=r0`, strict ECDSA validation implies
nonce `+/-G/2`, so the usual two-candidate extractor recovers the target
scalar at any actual native digest. The open question is the cost of finding
an accepted signature with another r. A length bound does not algebraically
exclude such signatures.

One relevant model lets an adversarial spender know the committed private
keys, search for alternative known nonces with short r, and grind a native
digest for short s. If r and s have positive DER lengths a and b, with
`a+b=L-7` for total cap L, then approximately:

```text
A_curve = 2^(257-8a),
B_hash  = 2^(256-8b),
work(m) = m*A_curve + B_hash/(m*n_keys).
```

Here m is a number of precomputed short-r nonce candidates. The last term
optimistically counts a hit on any key in the same pool. Key testing for
one nonce can be organized as membership in a sorted union of scalar
intervals, so testing many keys need not require one scalar multiplication
per key for every digest. Group operations, scalar operations and hash
compressions still are different units and must not be silently equated.

Balancing the two displayed terms gives the exponent per term

```text
(569-8L-log2(n_keys))/2.
```

For 150 keys, this is approximately 68.89 at cap 53 and 64.89 at cap 54;
summing both terms adds approximately one bit where a feasible balance is
available. This explains why inspecting just one r/s byte split can be
misleading. It is not a proven optimum, a cryptographic lower bound or an
implemented attack. In particular, producing one exceptional signature
does not automatically supply all signatures required by a t-of-n pool.
Conversely, that extra threshold must not be credited without analyzing
maliciously correlated setup and the whole protocol.

A native BIP143 digest belongs to one input, outpoint and scriptCode.
It can serve all candidate keys in that pool, but is not automatically one
free trial against every key in every other pool. Granting 4,000 targets per
hash anyway gives a still more optimistic attacker relaxation, with cap-53
balanced exponent about 66.52 per term. This stronger grant may be useful
as a conservative screen but is not an actual cross-pool batching algorithm.

These figures support investigating cap 53. They do not establish a robust
80-bit or 128-bit point-lock guarantee, and cap 54 has particularly little
margin in the displayed model. Unknown-nonce constructions and other methods
are outside this calculation. No attack code is supplied or needed for this
mathematical qualification.

## Expected honest work is not a hard upper bound

With independent random native hashes, each pool takes a geometric number of
trials. Under the conservative common-sign window and five SHA256 compression
operations per trial, 40 pools with cap 53 and `A=2^190` have expected work
approximately `2^63.647` compression operations. The gamma/Poisson approximation
for the sum gives about a 4.8% probability of exceeding `2^64`. At 45 pools
that probability is about 17.9%, and at 50 pools about 42.0%. Using the full
mixed-sign interval slightly improves these figures.

A hard capped search is possible, but then setup can fail with a stated
probability. Reporting expected work below `2^64` is justified by the model;
reporting guaranteed completion below that count is not. The exact number of
SHA256 compressions depends on the actual serialized output, preimage length,
midstate reuse and final candidate layout. Those must be measured before
the honest-budget claim is attached to a concrete transaction.
