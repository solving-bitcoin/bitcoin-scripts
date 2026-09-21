# Distinct target anchors: exact extraction, prescribed nonce to open

Question: can two fixed ECDSA anchors for different target points replace
the repeated short-signature checks and give exact scalar revelation with
efficient noninteractive setup and opening?

There is an exact extraction equation for two prebound label choices. Unlike
the earlier [same-target dual-anchor shortcut](dual-anchor-sum-collapse.md),
its extracted combination need not be public before the spend. However,
generating a valid ordinary-digest opening requires a signature nonce with
a prescribed x-coordinate. The experiment supplies no efficient native
opening algorithm and is not a solution to the publication goal.

[Algebra probe](two_target_anchor_algebra.py),
[deterministic results](two-target-anchor-algebra.json).

## Public setup and extraction

Work modulo secp256k1 order n. Fix valid points T_i=t_i G, for i=1,2,
whose x-coordinates r_i satisfy p_field-n < r_i < n. Define public anchors
tau_i=(r_i,1,ALL), and two canonical label points:

```
U_plus  = T_1/r_1 + T_2/r_2
U_minus = T_1/r_1 - T_2/r_2.
```

Public setup checks anchor encodings and point validity, and excludes zero
or equal-up-to-sign label points. This is a point-consistency check, not a
complete hiding or malicious-garbling proof.

Consider a predicate checking tau_1 under witness key P and tau_2 under
witness key Q at their common actual ALL digest z0. It requires distinct
finite P,Q and checks the same signature sigma=(r,s,flag) under both at their
common actual digest z1. The signature item must exceed 57 bytes. A shared
SegWit-v0 scriptCode gives each pair its common digest; z1 need not equal z0,
since the opening flag may differ from ALL.

The anchors give publicly recoverable signs epsilon_i in {+1,-1}:

```
r_1 P + z0 G = epsilon_1 T_1
r_2 Q + z0 G = epsilon_2 T_2.
```

The setup bounds exclude r_i+n ambiguity. Define

```
c = 1/r_1 + 1/r_2
A G = epsilon_1 T_1/r_1 + epsilon_2 T_2/r_2.
```

Then P+Q=(A-c*z0)G. The long-signature sum-key theorem gives
r(P+Q)=-2*z1*G, so every accepted transcript supplies

```
A = c*z0 - 2*z1/r.
```

The canonical label is plus if epsilon_1*epsilon_2=+1 and minus otherwise.
Its scalar is epsilon_1*A, checked against the corresponding U point.
Flipping both anchor signs changes only the internal sign, not the canonical
label. It does not create four independent message labels.

The equation also works at z1=0: it returns A=c*z0 when P+Q is zero. Public
setup excludes zero selected target points. This is exact algebraic
extraction for the specified predicate, without a short-signature or
known-nonce assumption. It establishes neither native deployment nor a
complete garbled-label interface.

## The native opening obligation

The creator knows t_1,t_2 and hence dynamic signing scalars p_P,p_Q. For
nonzero A-c*z0, a common signature must have

```
r = -2*z1 / (A-c*z0).
```

The native digests and prebound targets prescribe r; the signer cannot freely
choose k first and take r=x(kG). If r does not lift to the curve, this branch
has no opening. If it does lift, any accepted response gives the creator

```
k = (z1+r*p_P)/s,
```

the logarithm of recovery point R=(z1*G+r*P)/s, whose x-coordinate is r.
Conversely, such a k supplies s by ordinary signing. The numerator is nonzero
for a valid finite recovery point. The long-signature guard excludes the
alternate coordinate r+n. This is an exact equivalence at this boundary, not
a runtime measurement or a general cryptographic lower bound.

For the same-ALL branch z0=z1=z and nonzero A, the relation is invertible:

```
r = -2*z/(A-c*z),       z = r*A/(c*r-2).
```

For c nonzero this bijects nonzero z except A/c with nonzero r except 2/c;
for c zero it bijects all nonzero values. Under a uniform-digest model, a
small precomputed nonce table does not make those r values likely to hit the
table. Calculating a matching z algebraically is not finding a transaction
with that hash. Other flags must use the unspecialized two-digest equation.

The A=0 same-digest exception has fixed r=2/c when c is nonzero, but carries
only a zero, public target scalar. It recovers the earlier same-target failure
mode rather than a useful hidden label; public setup here excludes it.

No general impossibility or search-optimality theorem is claimed. A useful
repair must exhibit a fast native opening algorithm including funding/hash
dependencies. Moving target selection after the native digest requires
addressing the changed funding/script commitment and future-message condition.

## Reproduced evidence

Eight deterministic test methods pass. Twenty-four curve fixtures cover three
setups, all four anchor-sign pairs and two known nonces. Six more use distinct
synthetic anchor/opening digests with flags 0, 2, 3, 128, 129 and 255. Another
uses zero opening digest and opposite dynamic keys. Each of these 31 fixtures
checks both anchors and both common signature equations, then recovers the
canonical label. Their digests are calculated from known nonces, deliberately
reversing the hard native task; no Bitcoin hash preimages were found.

Other tests cover the nonce-recovery equivalence, zero-aggregate boundary,
degenerate public setups and six malformed transcripts. Fifteen exhaustive
maps over the field of order 101 check the excluded sets and inverse identity;
they are algebra checks, not Bitcoin hashing or secp256k1 signature models.

Evidence: **locally-reproduced** examples and **inspected** algebra.
Deployment: **unclassified**. No compiled Script, complete witness, hint
count, stack peak, opcode budget, transaction size, Core result or setup
benchmark is claimed. Those metrics are not applicable to this host-only
experiment, not zero. No existing primitive or native fixture is changed.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/two_target_anchor_algebra.py
```
