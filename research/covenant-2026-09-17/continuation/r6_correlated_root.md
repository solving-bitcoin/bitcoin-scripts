# R6: correlated roots, native two-key cycles, and a digest/signature identity

Date: 2026-09-17. Question: can a concrete correlation eliminate the separate
`IsDER(H(proof))` and `IsDER(H(P))` searches while preserving mandatory exact
output verification and honest total work below `2^64`?

**No complete construction is obtained.** There are two precise constructive
correlations: an eight-opcode native cross-key cycle, and an affine
digest/signature identity whose required nonce has the wrong DER size. The
first does not supply a cheap short-cycle solver or an output advantage; the
second really cancels a scalar variable, but its fixed-r version cannot fit
the output of a native Bitcoin hash opcode. These are scoped results, not a
general impossibility theorem about correlated commitments.

The equations and raw Script layout are `inspected`. The companion Python
experiment is `locally-reproduced`; deployment is `unclassified`. It contains
24 actual secp256k1 algebra cases and an explicitly artificial small-curve
hash/signature model. Neither is a Bitcoin Core execution. No SHA256-to-DER
hit, complete Bitcoin transaction, proof opening, or covenant was generated.
No repository Script executor or field-arithmetic tests were used.

## 1. Direct same-root solving is a concrete list-intersection problem

For `alpha=H(P)=DER(r,s,flag)`, native verification requires

```
z_flag(T) G = Z_j(P) = s R_j - r P,
R_j in { all curve points with x(R_j) mod n = r }.
```

Thus one actual strategy is to generate admissible public keys P, compute
their target points Z, and intersect that list with native transaction points
`z_flag(T)G`. This does not require extracting discrete logarithms of the
recovery points. It also is not ordinary unconstrained ECDSA recovery: that
operation changes P, whose hash supplied r and s in the first place.

For two independently generated batches, let `Q_P` count raw key hashes and
`Q_T` count transaction candidates. Grant at most `b=4` recovery branches per
admissible key and unit cost for everything. In an ideal model with uniformly
distributed independent native scalars, the expected number of matches is

```
lambda <= b p Q_P Q_T / n,
p = 780555 / 2^65 approximately 2^-45.425859.
```

Balancing the two batches gives about `2^150.713` total raw trials for one
expected match using the favorable b=4 bound. At `Q_P+Q_T=2^64`, the same
model gives at most about `6.22e-53` expected matches. Scalar reduction's tiny
nonuniformity and the negligible difference between n and `2^256` are ignored
in these estimates. Curve operations, list memory, setup, funding, proof work,
and up to 256 flag-specific transaction hashes are also uncharged.

**This is an estimate for a specified batch strategy, not a lower bound for
all adaptive solvers.** In particular, choosing P as a function of previous
transaction hashes invalidates an unqualified independent-batch argument.
Neither a generic birthday slogan nor this estimate rules out another
algebraic construction. The point-list form makes the missing construction
explicit enough to inspect.

All flags remain relevant. Each key's root selects the actual native
`z_flag`, rather than a freely chosen scalar from the list. The `r+n` x branch
cannot be discarded for short DER integers; there are zero, two, or four
candidate nonce points, after rejecting r=0 and s=0. All branches are included
in the local model. The favorable b=4 estimate is a maximum, not a measured
average recovery multiplicity.

## 2. A real cross-key correlation with eight native opcodes

Replace a self-loop by a two-key cycle:

```
alpha0 = SHA256(P0);  ECDSA(alpha0, P1, T) = true
alpha1 = SHA256(P1);  ECDSA(alpha1, P0, T) = true.
```

With entry stack `P0 P1`, the raw legacy Script is

```
OP_2DUP OP_SWAP OP_SHA256 OP_SWAP OP_CHECKSIGVERIFY
OP_SHA256 OP_SWAP OP_CHECKSIG
```

Hex: `6e7ca87cada87cac`. By inspection: **8 bytes, 8 non-push opcodes,
2 entry data items, 0 hint items, combined main-plus-alt-stack peak 4**. Both
data items coexist at entry; the altstack is unused. The predicate consumes
its inputs and leaves one boolean. These are raw boundary-vector counts,
not policy-produced compiler measurements. There is no complete witness
serialization or transaction weight. No Core or policy validity is claimed
without actual mined keys.

Each successful edge uses its own hash as its native signature, so there is
no independent extra `H(P_i)` DER test to multiply into that edge's cost.
This is a concrete correlation beyond merely identifying proof=P. With no
CODESEPARATOR and no 32-byte signature push inside this eight-byte script,
the two checks share the same scriptCode; their complete sighash flags can
still differ because their hash roots differ.

For fixed T, define the branch-valued recovery graph

```
P -> F_T,j(P) = r(H(P))^-1 * (s(H(P))*R_j - z_flag(H(P))(T)*G).
```

An accepting two-key witness is a length-two directed cycle. A collision
`F(A)=F(B)` is not such a cycle: it only produces two incoming edges to a
third vertex. Likewise, a rho walk's repeated vertex can yield a long cycle;
it does not supply a cycle short enough for a bounded Bitcoin script.

There is also a sparsity issue before any rho estimate. A fresh destination
has an admissible next SHA256 root only with probability p in the independent
gate model. Allowing four recovery branches gives mean continuation at most
`4p`, far below one. The map is not a freely iterable total random function.
For the separate random directed-graph idealization with uniform independent
destinations, the expected number of simple length-k cycles over the whole
key domain is at most approximately `(b*p)^k/k`. This explains why merely
spending more time walking one fixed transaction's sparse graph is not a
demonstrated birthday solver. Real recovery edges are correlated, so that
graph calculation is expressly not a secp256k1 lower bound.

One can grant a later hash-schedule nonce per edge and mine an admissible
alpha for each source, turning it into a total selected-branch map. That
charges roughly `1/p` hash trials per edge, plus recovery. Even granting an
ideal map on about `2^256` keys, an ordinary rho collision then has a nominal
`2^128/p` cost and a typical cycle with about `2^128` vertices. Neither cost
nor witness length fits the target. This does not exclude a different
bounded-cycle algorithm or a smaller authenticated state space; those would
be concrete additional constructions, including native nonce-routing costs.

Wagner's generalized birthday algorithm requires independently selectable
lists in a sum relation. Here the r and s coefficients and recovery point at
each edge are hashes of the preceding full public key. Replacing these
linked edges by independent lists, or freely selecting a compatible scalar
tuple for one actual transaction, has not been implemented. The prior free-s
ECDSA cycle algebra does not remove these hash-input constraints.

### Reproduction and output dependence

The fixture uses `y^2=x^3+7` over F211, prime group order 199, and G=(3,33).
It enumerates all group points and all 199 scalar contexts. A documented
SHA256 adapter gives an artificial 1/4 admissibility gate and nonzero r/s,
and grants fixed ALL flags. It is **not** shortened real DER, a small hash
attack against Bitcoin, or a calibrated estimate of secp256k1 behavior.

All 11,880 recovered edges verify; eight distinct two-key cycles execute the
same stack routing and end true. One wrong-key case is rejected. The model
also checks the direct-root point-list identity. For example z=13 accepts
P0=(22,152), P1=(19,89), with model signatures (85,18) and (129,81). The
successes establish what the proposed algebra/stack gadget means, not a
full-size witness or favorable scaling law.

The funding chronology of this bare gadget is acyclic: publish or inspect a
fixed script, fix the concrete funding outpoint, then search witness-only
keys against that transaction. This point matters: **not every correlated
proposal automatically has a funding fixed point**. However, the gadget
contains no exact-output reference. Replacing O* by a disallowed output list
gives another native digest instance with the same search distribution in
the ideal model. Adding an inert literal O* to scriptCode merely changes
those digest instances; it does not compare actual outputs to that literal.

If all edges use NONE, a found witness replays across output changes directly.
If full-output flags are enforced for free, the ideal search symmetry still
remains. If P_i instead commit reference-proof data, its authenticated
openings and binding must be supplied. Embedding those witness-dependent
keys into the locking script additionally changes the funding outpoint and
needs a new dependency analysis. A cycle of valid signatures alone is no
proof of the committed computation.

## 3. An exact affine cancellation when the digest is itself the signature

The root researcher proposed a distinct correlation: let a hash blob alpha
be both the numerical native digest z and the DER signature. Grant the
missing native-to-blob equality temporarily, so that we can examine the
algebra rather than assume that equality has already been implemented.

Fix a strict-DER layout, r, and the last sighash byte. The s bytes occur
immediately before that final byte. Across all s values preserving this
layout, the unsigned digest integer is

```
z = int(alpha) = C + 256*s.
```

Set `P=-(C/r)G`. Then the actual ECDSA verification point is identically

```
(zG+rP)/s = 256G.
```

This is a real cancellation with no scalar search. To make it a valid
signature for variable s, however, r must be `x(256G) mod n`. On secp256k1,

```
r = 8282263212c609d9ea2a6e3e172de238
    d8c39cabd5ac1ca10646e23fd5f51508
```

This integer needs **33 DER bytes**, because its 32-byte unsigned encoding
starts with bit 1 and therefore requires a leading zero. A 32-byte complete
Bitcoin ECDSA signature has `len(r)+len(s)=25`, so nonzero s permits at most
24 r bytes. A 20-byte signature permits at most 12. The affine identity's r
therefore cannot fit either native hash output. Even with one-byte s, its
complete DER signature plus flag needs 41 bytes.

The fixture checks 24 actual secp256k1 cases across 20/32-byte layouts, four
flags, and three s choices. In every case the verification point is exactly
256G, and the signature fails solely because the chosen short r is not that
x-coordinate. These are synthetic DER blobs, not known hash preimages.

This obstruction covers the **fixed-r/fixed-layout affine family**. It does
not prove that all correlated digest/signature interpretations fail. If both
r and s vary while their lengths and flag stay fixed, write

```
z = C0 + A*r + 256*s,
A = 2^(8*(len(s)+3)).
```

Choosing `P=-A*G` leaves the exact requirement

```
R = (256 + C0/s)G,       r = x(R) mod n.
```

Thus a remaining constructive question is whether this two-variable
relation can be combined with native transaction hashing and short-DER
encoding more cheaply than testing random digest blobs. `C0` is a nonzero
positive integer below n for a 20/32-byte DER blob, so it cannot simply be
discarded modulo n. Choosing s and computing r produces target digest
strings; it does not make an actual transaction hash equal one of them.
No such solver or output-specific advantage is supplied here.

The equality `alpha=z` itself is another explicit obligation. A native
`OP_HASH256` of an exactly validated legacy preimage would have the right
hash function, but accepting a witness blob as that actual preimage is the
original transaction-binding problem. Output enforcement and the concrete
funding outpoint cannot be assumed away by the scalar identity.

## 4. Next falsifiable directions

1. Supply a bounded-cycle solver whose states retain authenticated proof
   meaning and whose actual transaction variables give an honest advantage.
   Include DER mining, recovery branches, all flags, script routing, setup,
   and retained-state alternatives. A generic repeated vertex is insufficient.
2. For the variable-r affine relation above, derive an actual supported
   native hash-preimage family with output enforcement. Count both short-r
   generation and actual hash matching. A table of target scalars alone is
   not an evaluation verifier.

ECDSA verification, recovery and the distinction between signature-containing
messages and key-containing fixed points follow the primary standard
[SEC 1 v2.0, 21 May 2009, §§4.1.4–4.1.7](https://www.secg.org/sec1-v2.pdf).
The independently selectable list premise is from
[Wagner, *A Generalized Birthday Problem*, CRYPTO 2002](https://people.eecs.berkeley.edu/~daw/papers/genbday.html).
The correlated constructions, capacity calculation, probability models and
output conclusions in this note are our derivations, not claims of those
sources.

Reproduce: `python3 research/covenant-2026-09-17/continuation/r6_correlated_root.py`.
