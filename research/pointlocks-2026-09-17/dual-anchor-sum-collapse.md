# Two dynamic anchors do not make a sum-key target lock

Question: can two public ECDSA recovery anchors replace the repeated short
checks with an exact sum-key check, allowing a small SegWit point lock with
cheap setup? **This specific replacement fails.** A complete native spend
can be constructed from the public target point without computing its scalar.
The sum-key theorem remains correct: it extracts the already public scalar of
the dynamic key sum, not the desired scalar of T.

[Policy-compiled Script generator](../../examples/pointlock_dual_anchor_probe.rs),
[public opening algorithm and native harness](dual_anchor_core_check.py),
[Core report](dual-anchor-core-check.json),
[separate host report](dual-anchor-host-check.json).

This is a counterexample to the proposed replacement. It is not a break of
the existing exact sum-key primitive or of the anchored exact-60-byte,
separated-context candidate.

## Public construction

Let T be a valid nonzero point whose x-coordinate r_T has an unsigned 32-byte
DER encoding. In particular r_T>p_field-n, so its ECDSA recovery points are
only T and -T. The public anchor is tau=(r_T,1,ALL), a 40-byte signature item.
The candidate authenticates two distinct, compressed witness keys P,Q by
checking tau under each, then checks the same longer-than-57-byte signature
sigma under both. All four checks use the same scriptCode. A separate owner
authorization is included in the actual fixture.

After the real funding outpoint is known, compute the ordinary BIP143 ALL
digest z. For z!=0 and non-infinite P,Q, use only public curve operations:

```
P = ( T - zG) / r_T
Q = (-T - zG) / r_T
sigma = (r_T, n-1, ALL).
```

No log_G(T) is needed. The two anchor checks recover T and -T, respectively.
The sigma checks recover -T and T. Sigma has 72 bytes and passes the long
signature guard. P and Q are distinct because T is nonzero and the group
order is odd. Their sum satisfies

```
P+Q = (-2z/r_T)G.
```

Thus exact sum-key extraction returns -2z/r_T, a scalar computable before
the spend from public r_T and the transaction. It supplies no new scalar
for T. The program accepts a point and public transaction data; it has no
target-secret argument. The fixture point is obtained by hashing a counter
to an x-coordinate and lifting it, not by multiplying G by a retained scalar.

This is more than a failed particular extractor: an efficient universal
extractor of log_G(T) from this publicly simulatable transcript would give
a discrete-log algorithm for such target points. No transcript is claimed
to make discrete logarithms information-theoretically impossible. The claim
is that the script does not compel disclosure beyond public computation.

## The same-digest branch is completely determined

Suppose both anchor checks pass under distinct P,Q, and another accepted
sigma=(r,s) uses the same nonzero digest z. The >57 guard excludes mixed
r/r+n nonce lifts. Applying the sum-key identity to tau and sigma gives

```
P+Q = -2z/r_T * G = -2z/r * G,
```

hence r=r_T. The anchor equation for P is zG+r_T P=+/-T. The sigma equation
then gives a nonce +/-T/s. With the same r_T it must be either T or -T, so
s=+/-1. These are exactly the public low-S anchor and its high-S counterpart.
Their signature-item sizes are 40 and 72 bytes. The length guard rejects
the first and accepts the second.

Rejecting high-S would remove the cheap same-digest opening altogether; it
does not turn this branch into a scalar-revelation mechanism. A different raw
sighash flag may change sigma's digest z1. In that case the identities force
r=r_T*z1/z modulo n, returning to an honest-opening obligation for that
specified nonce x-coordinate. The native counterexample needs only the
ordinary ALL branch. No claim about impossibility for all different-context
repairs follows from the same-digest classification.

The [distinct-target follow-up](two-target-anchors.md) gives an exact scalar
equation for two different prebound label combinations. It avoids this public
sum collapse, but the digests prescribe the opening nonce's x-coordinate.
Its 31 synthetic curve cases do not supply an efficient native opening.

## Actual Script and transactions

The generator uses `compile_with_policy()`. Its complete witnessScript has
150 bytes after optimization and no CODESEPARATOR. The input stack is
`sigma P Q authorization`, with zero auxiliary hints. The script checks
33-byte key encodings and inequality, performs both anchor checks, enforces
the long signature guard, checks sigma under both keys and terminates with
one true item.

On isolated network/wallet-disabled Core 30.3, commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`, the public opening and the version
with P,Q swapped are both mined successfully. Default policy rejects both
because sigma is high-S. This is a consensus counterexample despite policy
rejection; the research goal explicitly covers consensus-permitted spends.

Seven malformed controls fail both consensus and policy: the 40-byte low-S
anchor substituted for sigma, a changed s response, duplicate keys, a wrong
key, a changed sigma flag, an extra entry item, and a transaction mutation
with a freshly valid owner authorization. The final control fails an anchor
check, rather than merely relying on an outdated authorization. The independent
trace agrees with all nine Core verdicts and validates actual native digests.

| Metric | Each positive point-lock input |
|---|---:|
| Locking script | 150 B |
| Serialized complete witness | 354 B |
| Entry data items | 4 |
| Complete witness items, including script | 5 |
| Hint items | 0 |
| Combined main-plus-alt-stack peak | 5 |
| Executed non-push opcodes | 25 |
| Executed signature checks, including authorization | 5 |

Across the two independent positive executions there are zero hints and eight
entry-item occurrences; those inputs never share a stack. Peak 5 comes from
the independent value/height trace, not an instrumented Core counter. Each
complete spending fixture is 899 WU / 225 vB; funding includes test-only
helper/change outputs. These are single-predicate test costs, not a
256-byte-message publication estimate. The tapscript/unlimited-stack helper
is not used. Compiler pin: `124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`.

Evidence: **differentially-validated** native execution and **inspected**
algebraic classification. Positive transaction deployment:
**consensus-validated**, not **policy-validated**. The proposed target-lock
replacement is refuted; this is not a deployable point-lock construction.
No complete protocol, setup benchmark, or broader impossibility theorem is
claimed. A successful dynamic-key repair must bind the extracted combination
to the intended target and provide efficient honest openings.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/dual_anchor_core_check.py --host-only
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/dual_anchor_core_check.py
```
