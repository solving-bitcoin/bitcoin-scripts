# Fixed four-root orbit commitments

Question: can the four-recovery-key idea bind a full-size scalar instead of
the small inverse-coordinate scalar in the older experiment? **Yes on the
fixed-digest branch**, by changing the label commitment to a four-point orbit.
There is also a simple fixed-target random-oracle bound for other native
digests. But explicit legacy key tables still exceed 100,000 vB, even under
very generous accounting. This is not a solution to the user goal.

[Algebra and cost probe](four_root_orbit_probe.py),
[reproduced results](four-root-orbit-probe.json).
No Script, transaction, Core validation or setup benchmark is claimed.

The [key-sharing follow-up](orbit-key-sharing.md) now covers one escape from
the original explicit-table bound. A key belongs to at most two canonical
orbit labels, so even perfect reuse leaves a 116,700-vB floor for the four-key,
40-byte-opening profile. Two overlapping scalar openings also disclose the
base ratio and allow propagation through their sharing component. A
hypothetical three-key variant still exceeds the goal in the stated model.

## Public parameters and labels

Let p and n be the secp256k1 field prime and group order, G its usual base, and
C=2^248 the integer interpretation of the legacy SINGLE-bug digest. Fix the
same r0=2 for the whole protocol. Both x=2 and x=n+2 lift to curve points.
Let their root set be

```
W = { R0, -R0, R1, -R1 }.
```

These are fixed points obtained from transparent x-coordinates, not scalar
multiples generated from a retained known secret relative to G. No proof of
DLP hardness follows from this choice.

Choose the secret label s in 1,...,(n-1)/2 and define its public commitment as
the unordered set O(s)={sR : R in W}. For each H in O(s), derive a script key

```
Q_H = (H - C G) / r0.
```

Public checking rejects invalid/infinite/duplicate curve points and checks
that the four committed script keys sum to -4 C G/r0. The intended opening is
the ECDSA signature (r0,s,SINGLE), used unchanged under all four keys at a common
scriptCode. When the input index has no corresponding output, all four checks
succeed because C G+r0 Q_H=H=sR.

This is an **unordered four-point scalar commitment**, not a claim to extract
a scalar relative to one designated standard-G point. A general goal-compliant
garbled protocol using this different algebraic commitment has not been built.
Malformed commitments with the required sum might have no opening; correctness
for honestly generated commitments and extraction from accepted openings are
separate statements.

## Exact extraction at z=C

For any accepted (r,u) under four distinct keys, recover

```
R_i = (zG+rQ_i)/u.
```

The four R_i are distinct and have x mod n equal to r. Because p<2n, their
coordinates must be r and r+n, with both signs present. In particular,
0<r<p-n and sum R_i=0. Using the checked key sum gives

```
z = C*r/r0 mod n.
```

If z=C, then r=r0. Rearranging the individual checks gives
r0 Q_i+C G=u R_i. Thus the committed H set is exactly O(u). Return the canonical
scalar min(u,n-u). Both low-S and consensus-permitted high-S signatures yield
the same opening. This part does not assume ECDSA unforgeability or nonce
knowledge. It does require four distinct curve points and the same signature
and actual digest for all four checks.

The commitment is injective modulo sign. If aW=W, multiplication by a acts
freely on four nonzero group points, so its order divides four. The only
possible extra stabilizer has order four, a^2=-1 mod n. The probe computes
both such scalars and confirms neither sends R0 into W. Only a=+/-1 remains.
Consequently O(u)=O(s) implies u=+/-s, and canonical openings are unique.

This avoids the old choice of label t=-4C/r with r in a roughly 128-bit
interval. Here s has a full roughly 255-bit canonical domain. It does not
prove that special-coordinate multi-base DLP has a particular concrete
security level, and it does not turn the sum of the keys into a hidden label:
that sum is deliberately public and constant.

## Nonconstant native digests

Four successful checks force the reduced digest into the fixed set

```
A = { C*r/r0 mod n : 1 <= r < p-n }.
```

Its size is p-n-1. This set is fixed before and independently of any malicious
label/setup choice because r0 and C are global constants. Every allowed reduced
digest corresponds to at most two 256-bit hash values. If nonconstant native
sighashes are modeled as uniform random-oracle outputs, q distinct adaptive
hash queries therefore give the conservative bound

```
Pr[any nonconstant digest in A] <= q * 2*(p-n-1) / 2^256
                              ~= q * 2^-126.6543.
```

Raw sighash flags, different scripts, candidate labels and transaction variants
consume queries; they are not free trials outside this accounting. This bound
covers the mathematical predicate assuming a correctly committed, checked set
of keys and a common digest. It is explicitly a random-oracle assumption about
native hashing, not a theorem about SHA256 or a native consensus reproduction.
The legacy SINGLE constant bypasses hashing and intentionally remains usable.
SegWit has no corresponding constant-digest branch, so this argument does not
provide efficient honest native-witness setup.

The probe includes a **synthetic nonconstant digest** z=C*r1/r0 for another
four-root coordinate. Four keys with the required sum accept its signature,
but extraction into the reference r0 orbit fails. That digest was deliberately
assigned, not realized by a Bitcoin transaction. This control matters: the
predicate does not algebraically force z=C; the nonconstant branch is excluded
only with the stated computational bound.

Five deterministic full-size label fixtures check 40 ECDSA equations, including
high-S counterparts, and the synthetic control checks four more. All 44 pass
the independent Python curve verifier. Honest signatures are 40 bytes in these
fixtures. None of this is a Core verdict or production-entropy test.

## Explicit-table size obstruction

Consider a legacy construction whose message is an unordered subset of an
explicit independent candidate inventory. Grant, unrealistically, one raw
20-byte commitment authenticating **all four keys** of each candidate, with
no Script work to bind/unpack that packet. Grant free signature bytes, selectors,
all other operations and every transaction/output/input framing byte. Charge
only 132 raw compressed-key bytes for each selected candidate. No witness
discount exists for the legacy execution needed by this honest algorithm.

If an unselected candidate costs a bytes and a selected candidate costs a+b,
let R solve

```
2^(-a/R) + 2^(-(a+b)/R) = 1.
```

For a fixed inventory of N candidates, summing 2^(-cost/R) over all its subsets
gives one. If 2^2048 distinct subset messages all cost at most B, their sum is
at least 2^2048 * 2^(-B/R), hence B>=2048R. Restricting subsets, using multiple
pools or mixing cardinalities cannot improve this bound within the model.
Counting different orders of the same recovered labels as distinct private
messages would require an additional binding mechanism, not supplied here.

| Representation assumption | a | b | Lower bound for 2048 bits |
|---|---:|---:|---:|
| One raw packet hash, raw supplied keys; all framing free | 20 | 132 | **131,601 vB** |
| One packet hash push, four separately pushed keys | 21 | 136 | 136,722 vB |
| Four separate key-hash pushes | 84 | 136 | 288,414 vB |
| Four embedded compressed-key pushes; opening free | 136 | 0 | 278,528 vB |

The first row is more generous than the actual available Script interface.
It already misses the target before paying a single signature or transaction
byte. The bound does **not** cover a new implicit candidate set, safe reuse of
keys, algebraic onchain decompression, other label encoding, or a new efficient
SegWit construction. Such a representation change, plus full garbled-label
binding, is required to make this direction useful for the goal.

Evidence: **inspected** extraction/stabilizer/hash-model/size arguments and
**locally-reproduced** curve equations and numerical bounds. Deployment:
**unclassified**. No Bitcoin script is generated, so script size, hint counts,
stack peak, opcode counts and actual transaction sizes are not measured here.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/four_root_orbit_probe.py
```
