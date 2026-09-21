# Search 3: signed ECDSA graphs and complete recovery sets

Question: can native ECDSA relations enforce an exact predetermined output
list, with existing opcodes, retained setup information, and honest total work
below `2^64`? This bounded search finds a new exact native **digest-scalar
equality** relation, but no representation bridge or good-output advantage.
It does not produce a covenant or an impossibility theorem.

The companion [fixture](search3_native_algebra.py) and
[results](search3_native_algebra.json) check 256 signed-graph cases, four
representative curve-equation fixtures, and eight OpenSSL cases. Graph
evidence is `locally-reproduced`; the four-root ECDSA fixture is
`differentially-validated` against OpenSSL. Deployment is `unclassified`:
there is no executed Bitcoin Script or complete transaction in this search.
No repository Script executor or disabled consensus check is used.

Parent validation update: the [Core runner](core_fragments.py) now checks the
two-root specialization in complete P2SH spends. Four checks in the same
context accept; duplicate keys, short key encoding and a changed second
context reject. The positive raw vector is 75 bytes without CODESEPARATOR,
22 non-push opcodes, two entry items, zero hints and peak five by inspection.
It is `differentially-validated` / `consensus-validated`; policy rejects
FindAndDelete of the fixed signature. This does not exhibit two different
contexts with an equal digest or validate a covenant. See [complete metrics](README.md).

## 1. All sign cases for two shared cycles

Work modulo the secp256k1 group order `n`. For an edge using the same ECDSA
signature `(r_e,s_e)` in contexts `z_e,L,z_e,R` under `P_u=d_u G,P_v=d_v G`,
assume the two recovered nonce points have the same x coordinate. Then

```
d_v = tau_e*d_u + b_e
b_e = (tau_e*z_e,L - z_e,R)/r_e,  tau_e in {+1,-1}.
```

The assumption matters: `x=r` and `x=r+n` can both be valid. The fixture uses
`r=x(G/2)>p-n`, which excludes that extra branch. Low-S normalization flips
both nonce points and preserves `tau_e`.

For a rooted cycle, composition gives `d_0=T*d_0+C`, where `T` is the product
of its edge signs. For two cycles sharing a root:

| T1 | T2 | Necessary and sufficient affine compatibility |
| --- | --- | --- |
| +1 | +1 | C1=0 and C2=0; root free |
| +1 | -1 | C1=0; root=C2/2 |
| -1 | +1 | C2=0; root=C1/2 |
| -1 | -1 | C1=C2; root=C1/2 |

Thus a second independent cycle closes the zero-work escape of a single
unbalanced cycle **for fixed r values and signs**. It leaves at least one
scalar compatibility condition. Our two four-edge cycles have seven nodes
and eight edges. All 256 assignments were enumerated: 64 in each row, rank
six for the first row and seven otherwise. One deterministic arbitrary
digest tuple satisfies none of the 256 assignments; constructed compatible
tuples pass the independent curve equations for representatives of all rows.
Those constructed scalars are expressly **not Bitcoin transaction digests**.

More generally, a connected signed graph has rank `V-1` when all cycles are
balanced and rank `V` otherwise, over this odd-order field. A spanning tree
expresses every node as `a_v*d_0+c_v` with `a_v=±1`; a non-tree edge either
imposes a compatibility condition or determines `2*d_0`. This proves the
rank statement without assuming independent digests. Fixing one anchor node
leaves `E-V+1` compatibility conditions in both cases. An unknown-log anchor
does not give an honest signer a missing discrete logarithm for free.

These are not work lower bounds. A spender may also vary `r_e`, signatures,
recovery branches and transaction structure. CODESEPARATOR contexts in one
transaction supply a coupled tuple, not independently combinable lists.
Even an efficient solver for that tuple would apply to bad outputs too.

## 2. What same-context distinct keys really force

For the same `(r,s,z)`, two distinct canonical 33-byte compressed keys have
distinct recovered nonce points, since `Q -> (zG+rQ)/s` is injective. If the
only nonce candidates are `±R`, they must have opposite signs, and therefore

```
r*(P+Q) = -2zG.
```

An even cycle of these reflections forces an alternating sum of `z_e/r_e`
to vanish. This is a real native relation, with no sign-product escape.
However, signature size does not fix the individual `r_e`, and fixing each
whole signature also fixes `s_e`: adjacent vertices then must be individual
members of two-point recovery sets. Merely satisfying the alternating sum
is insufficient. The free-s versus enforced-common-r gap is unresolved.

The `r+n` exception is concrete, not hypothetical. **r=2** already has four
nonce candidates `±lift(2), ±lift(n+2)`. The fixture recovers two distinct
canonical keys using one root from each x coordinate. Both verify the same
signature in the same context, although their nonce points are neither equal
nor negatives. Key distinctness alone cannot justify a sign equation.

## 3. New relation: exhaust all four recovery keys

Choose the fixed low-S signature `r=2,s=1`, with ALL encoding
`300602010202010101`. For any scalar digest `z`, compute the four public keys

```
S = {+lift(2), -lift(2), +lift(n+2), -lift(n+2)}
Q_R = (R-zG)/2, for R in S.
```

They are distinct and all verify. This requires public point arithmetic and
no search, known private keys, nonce logarithms, or discarded information.

Now require the **same four pairwise-distinct canonical keys** and the same
signature to verify in a second native context `z'`. In each context the
four recovered nonce points exhaust `S`, whose point sum is zero. Hence

```
4zG + 2*sum_R Q_R = 0
4z'G + 2*sum_R Q_R = 0
therefore z'=z mod n.
```

This works with any freely supplied common signature that has four roots,
but the fixed nine-byte signature makes the proposed verifier simpler. It
must check all six pairwise inequalities, all four 33-byte lengths, and all
eight native signatures. These are enforced conditions, not trusted witness
promises. Validity plus 33-byte length makes compressed encoding canonical.

**Digest equality means modulo n.** Two 256-bit digest integers could differ
by n; this is not a proof of byte equality. Both contexts must really execute
their checks. Checking only one arbitrary key in the second context does
not prove the four-root sum equation.

Concrete layout by inspection, with entry stack `Q0 Q1 Q2 Q3`:

- For each key, copy with `PICK`, check `SIZE == 33`, then drop the copy.
- For each of six key pairs, copy both with `PICK`, then
  `EQUAL NOT VERIFY`.
- In each of two contexts, push the fixed signature, copy each key with
  `PICK`, and execute `CHECKSIGVERIFY`. A CODESEPARATOR may divide contexts.
- Drop the four original keys with two `2DROP`s; finish with true.

This raw proposed layout is **178 bytes, 65 executed non-push opcodes and
combined peak 7**, including one separator, by inspection. It is not a
policy-produced compiled script or an executed resource measurement. The
four size checks use 28 bytes/16 operations; six inequalities use 42/30;
eight signature checks use 104/16; separator and cleanup use 4/3. Altstack
is empty. Entry has exactly **4 key data items, 0 hint items**, all coexisting.
With a fixed signature in the script there is no signature input item.
No complete witness, transaction weight or policy claim is made.

The fixture verifies all four original-context signatures with OpenSSL,
then rejects all four when `z` changes to `z+1`. It does not manufacture two
different Bitcoin contexts with the same digest, which would itself need a
construction or search.

## 4. Why the new relation is not yet a bridge

The root researcher identified the cheaper fixed-r specialization: **r=s=1**
has only `±lift(1)` because `n+1` does not lift on secp256k1 (also checked by
this search's root enumerator). The fixed signature is
`300602010102010101`. Two distinct canonical keys exhaust these two roots;
checking both keys in both contexts forces `z'=z mod n` by summing two
equations. The corresponding inspected layout has **two entry key items,
zero hints, 76 bytes, 23 non-push operations, and peak 5**, including one
separator and clean-stack cleanup. Counts are: size checks 14 bytes/8 ops,
one inequality 7/5, four signature checks 52/8, separator and `2DROP TRUE`
3/2. These are
inspection counts, not compiled or executed measurements. The four-root
variant remains the exhaustive form when r is not fixed or is deliberately 2.

Both arguments of this equality gadget are **native Bitcoin digests**. A
stack value representing a checked output serialization is not automatically
one of those contexts. The gadget cannot simply substitute an arithmetically
computed digest for `z'`. Enforcing equality against the SINGLE-bug constant
would demand a scalar preimage; native equalities between different
CODESEPARATOR contexts likewise do not by themselves privilege the intended
outputs. Committing recovered keys after choosing a digest changes funding
and revives the previously identified diagonal dependency.

An explicit native context whose bytes track exactly an arithmetically
validated output serialization could make this relation useful. That is the
falsifiable next step; it must include funding and bad-output replay. No such
context or honest work advantage was found here.

The signature verification/recovery equations follow
[SEC 1 v2.0, 21 May 2009, §§4.1.4–4.1.6](https://www.secg.org/sec1-v2.pdf).
All rank, recovery-set, cost-boundary and covenant conclusions above are our
own derivations and local fixtures, not claims attributed to that standard.

Reproduce: `python3 research/covenant-2026-09-17/seven/search3_native_algebra.py`.
No Rust source or primitive metrics changed; no field tests were run.
