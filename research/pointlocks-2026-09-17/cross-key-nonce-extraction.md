# Exact extraction across several point-lock labels

Question: can the 98,323-vB publication extract additional transcripts by
combining verified signatures from different selected labels? The objective
is to enlarge exact extraction coverage without changing the onchain
predicate, not to infer soundness from the honest fixture.

**Yes, when the resulting nonce graph has a nondegenerate cycle.** The new
extractor recovers two- and three-key synthetic cases in which every existing
per-key affine extractor returns unresolved. It also recovers all 475 target
scalars from the actual historical full publication. Neither result proves
that every accepted publication has such a cycle. Six shared contexts alone
are insufficient even to guarantee full rank of the algebraic system.

[Extractor and tests](cross_key_nonce_extraction.py),
[algebra report](cross-key-nonce-extraction.json),
[native replay](cross_key_native_replay.py),
[native replay report](cross-key-native-replay.json).

## Public equations and exact rank criterion

For a verified key P_i=d_i G and actual reduced digest z_e, independently
reconstruct the verification nonce point

```
R_e = (z_e G + r_e P_i) / s_e.
```

Validate the key, scalar ranges and ECDSA equation before using the row.
Group nonce points by the six signed secp256k1 GLV transformations. For each
orbit choose a canonical point U_j and compute its public nonzero multiplier
m_e, with R_e=m_e U_j. This uses the complete verified point, including its
sign, rather than assuming equal r means equal nonce. Writing U_j=u_j G,
each signature gives

```
s_e m_e u_j - r_e d_i = z_e       (mod n),
u_j = A_e d_i + B_e,
A_e = r_e / (s_e m_e),  B_e = z_e / (s_e m_e).
```

Make one node per distinct verification key and one per nonce orbit; every
signature supplies an edge with a nonzero multiplier. In a connected
component, a spanning tree expresses every scalar as x_v=a_v X+b_v, with
a_v nonzero. Each remaining edge then supplies an equation D X=C:

- If any D is nonzero, the root is fixed as X=C/D. Recover every scalar in
  the component and check its multiplication against the corresponding
  public point before returning it.
- If all D vanish, validated group equations also force all C to vanish.
  The signature-derived linear system has nullity one. Report unresolved.

Thus a connected component has linear rank V or V-1. This is the rank of
these scalar equations, not a claim that the public points have multiple
discrete logarithms. Other algorithms or publicly known relations may still
extract an unresolved component. The helper does not search nonce translations
outside signed GLV orbits, affine relations between different key points, or
known scalar anchors such as G/2; existing extractors remain useful.

For an anchored label, after recovering d_i the existing anchor equation
gives t_i=+/-(r_T d_i+z_0). Check which sign reconstructs the committed target
T_i. No creator secret or nonce scalar is an extractor input.

## Common contexts help, but do not themselves force extraction

For two distinct keys A and B using the same actual nonce in round j, and
the same actual digest z_j within that round, eliminating the nonce gives

```
r_j (s_Bj d_A - s_Aj d_B) = z_j (s_Aj - s_Bj).
```

With two rounds the determinant is

```
r_1 r_2 (d_B-d_A) (z_1 r_2-z_2 r_1) / (k_1 k_2).
```

Distinct keys therefore extract if z_1/r_1 differs from z_2/r_2. The actual
implementation computes the determinant from public coefficients, so it does
not need any of the secrets appearing in this explanatory factorization.
Opposite nonce signs and GLV relations require the corresponding multipliers;
the graph handles them explicitly. Shared scriptCode alone does not imply
equal digest when raw sighash bytes differ.

The following unknown-log control prevents treating the number of contexts
or graph cycles as a proof. Transparently lift a domain-separated hash to a
curve point X without computing its scalar. Choose

```
P_i = u_i X + 11G,       u_i in {7,13,17},
R_j = a_j X,             a_j in {1,19,23,29,31,37},
r_j = x(R_j) mod n,
s_ij = r_j u_i/a_j,
z_j = -11 r_j.
```

All 18 equations verify, the three keys share a digest in every round, and
all six nonces are shared across keys. Nevertheless every cycle degenerates:
there are nine nodes, rank eight and ten redundant non-tree edges. An
extracted d_i would also give log_G(X)=(d_i-11)/u_i.

**This control assigns digests algebraically and does not impose cap60.** It
is not a Bitcoin hash preimage, a native accepted point-lock counterexample,
or a lower bound. It establishes the necessary rank condition and rules out
the proposed inference from shared-context/cycle count alone.

Cross-key elimination is established related work: see section IV-C of
[Madhwal et al., arXiv:2605.21498v1](https://arxiv.org/html/2605.21498v1).
The local extension validates reconstructed signed GLV orbits, checks rank
and every recovered point, and exercises the point-lock label interface.
No novelty claim or reproduction of that paper's external transaction cases
is made. The zero-determinant qualification is explicit here.

## Reproductions and boundaries

Eight focused Python test methods cover two-key extraction with common
contexts; a three-key cycle without a double collision between any pair;
12 signed-GLV/sign variants; two exact-60-byte synthetic anchored openings;
the rank-eight control; incomplete and disconnected graphs; duplicate keys;
empty inputs; digest boundaries; and malformed keys/signatures. An independent
dense modular elimination checks the sparse graph's ranks in the principal
positive and negative cases. The exact60 case chooses synthetic digests and
does not claim native preimages or shared contexts.

The replay uses Bitcoin Core 30.3's offline `bitcoin-tx -json -` utility to
decode the existing funding and spending bytes. It checks the historical
Core report's transaction/source hashes, derives all native BIP143 digests
from those transactions and executed script suffixes, and checks commitments,
prevouts, selectors and 95 authorization equations. Generator `frames`, which
contain private fixture scalars and supplied digests, are removed before
extraction. The result is compared to the historical recovery only afterward.

| Native replay quantity | Result |
|---|---:|
| Selected keys / target scalars recovered | 475 |
| Anchor plus short-signature equations | 3,325 |
| Nonce orbits, including anchors | 476 |
| Connected components | 1 |
| Nodes / linear rank | 951 / 951 |
| Nondegenerate non-tree edges | 2,375 |
| Decoded message | 256 bytes, 00 through ff |
| Unchanged complete funding plus spending cost | 98,323 vB |

The honest fixture already extracted through G/2. Replaying it demonstrates
native digest/witness compatibility of the graph, not additional protection
against arbitrary nonce choices. This is **locally-reproduced** extraction
research with deployment **unclassified**. Historical transaction acceptance
remains **differentially-validated**, **policy-validated** under Core 30.3
commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`; no new mining/policy run is
claimed. The report pins the offline decoder executable and all source inputs.

Incremental script bytes, witness bytes, opcodes, hints and Bitcoin stack
items are zero. The unchanged native profile has five hints, 46 entry data
items and 47 complete witness items per pool; all hints coexist at entry and
the independently traced combined main/alt-stack peak is 100. Across 95
independent inputs there are 475 hints, 4,370 entry items and 4,465 pool witness
items, plus the helper witness. No tapscript or unlimited-stack helper runs.
No new setup or complete-goal performance benchmark is claimed.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/cross_key_nonce_extraction.py -v
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/cross_key_native_replay.py --bitcoin-tx /path/to/bitcoin-30.3/bin/bitcoin-tx
```

The next extraction requirement is to cover accepted transcripts whose
public equations remain unresolved, or prove a stated work bound for
producing them under actual native hashing and malicious setup. An opener
can attempt distinct unrelated nonce orbits for every label; the graph alone
does not exclude this. Public garbling/translation binding, a total decoder,
mandatory-input binding and the complete setup benchmark remain open.
