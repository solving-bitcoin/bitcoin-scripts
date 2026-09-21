# Repeated short-signature checks do not establish a sub-100k point lock

The objective is publication of any future 256-byte payload, with practical
noninteractive algebraic setup, no setup ZKP, and less than 100,000 vbytes for
both creating and consuming all publication outputs.

The [repeated-check probe](../../research/pointlocks-2026-09-17/repeated-cap60-sizing.md)
uses three or four capped ECDSA checks on publicly scaled copies of each target
point. An honest opener can use the known nonce G/2 without window grinding.
One common row index binds the repeated checks to the same selected label.

This does not supply the claimed extraction amplification. The predicate does
not restrict sighash flags, and different flags can bind different transaction
fields. Treating all signatures as independent constraints on one shared digest
therefore lacks justification. Public scalar relations between the verification
keys do not enforce equal sighash flags.

Independently, the best three-check layout in the bounded scan serializes to
130,182 vbytes, including output creation and spending. Four checks cost
176,685 vbytes. Both spending transactions exceed default relay weight limits;
splitting increases the totals. These are fixed-60-byte placeholder-signature
measurements, not funded native witness executions or a global size optimum.
Two local Legacy fixtures test the row-selection stack behavior only.

Evidence: `locally-reproduced` for the measured compilation, serialization and
Legacy layout fixtures; `inspected` for the sighash objection. Deployment:
`unclassified`. No complete alternative-opening search or work bound is claimed.

Reopening requires a justified extraction property for every permitted sighash
choice, plus a concrete smaller script and complete creation/spending accounting.
Neither repetition count alone nor a table bound assuming 60-byte signatures
establishes those conditions.

## A nonce relation alone does not establish extraction

The [affine-nonce extractor](../../research/pointlocks-2026-09-17/nonce-relation-extraction.md)
provides exact recovery when a public relation R_j=aR_i+bG gives a nonzero
determinant a*s_j*r_i-s_i*r_j. Its negative control constructs valid ECDSA
rows from an unknown-log point X with P=uX+vG and nonces R_i=a_iX+b_iG.
Public coefficient matching makes both determinant and numerator zero, so
the relation supplies no scalar recovery. This `locally-reproduced`,
`unclassified` control uses assigned digests and unrestricted signature
lengths; it is not a new native cap60 counterexample. Related nonce points
alone therefore do not establish extraction or a repetition work bound.

## Pairwise byte inequality is not a replacement for separate contexts

A [native follow-up](../../research/pointlocks-2026-09-17/distinct-short-signatures.md)
constructs a committed key Q from a transparently lifted nonce point R,
without using either discrete logarithm. At the legacy SINGLE constant C,
`Q=(sR-CG)/r`, with21-byte r and `s=floor(n/2)`, admits16 different exact60
encodings: two s signs and eight consensus-accepted constant-digest flags.
They provide only one underlying ECDSA equation. Extracting Q's scalar is
equivalent to computing the lifted R's logarithm.

Core accepts predicates enforcing all-pairs inequality on two, six, and eight
such signatures. Two low-S ordinary-flag encodings even pass default policy.
The existing single-signature max60 predicate accepts the same public fixture.
Five controls reject duplicates, altered scalars/length/flags, or a transaction
leaving the constant branch. Evidence: `differentially-validated`; positive
transactions: `consensus-validated`, with the documented subset also
`policy-validated`. Full costs, stack peaks, zero hint counts and source pins
are in the linked note and report.

This excludes byte-distinct repetition as a repair on that legacy branch and
provides a malicious-key-setup counterexample for the standalone max60 lock.
It does not break the anchored P2WSH candidate, the exact two-key sum lock, or
prove a general impossibility for noninteractive point locks.
