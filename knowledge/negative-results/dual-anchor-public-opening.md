# Dual dynamic recovery anchors disclose only a public key sum

Replacing repeated short checks with two public anchors plus a long same-
signature sum-key check does not lock the target's scalar. For tau=(r_T,1)
and the actual nonzero native digest z, derive P=(T-zG)/r_T and
Q=(-T-zG)/r_T publicly. Sigma=(r_T,n-1) verifies under both and passes the
>57-byte guard. It reveals only log(P+Q)=-2z/r_T, which was already public.

The [construction and native reproduction](../../research/pointlocks-2026-09-17/dual-anchor-sum-collapse.md)
use a hash-to-x target without a supplied target scalar. Core mines two
positive variants and rejects seven malformed controls. The positive spends
are high-S, so default relay policy rejects them. Restricting the same-digest
branch to low-S removes its honest opening rather than repairing extraction:
the equations force r=r_T and s=+/-1, whose sizes are 40 and 72 bytes.

This refutes this particular repair, not the existing cap60 anchored design
or the sum-key theorem. Evidence: **differentially-validated** for native
execution, **inspected** for the algebra. Positive fixture deployment:
**consensus-validated**; it is not a valid target-lock construction.
