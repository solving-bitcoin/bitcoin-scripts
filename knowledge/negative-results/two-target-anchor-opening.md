# Two distinct anchors move the difficulty into native opening

The [two-target anchor experiment](../../research/pointlocks-2026-09-17/two-target-anchors.md)
avoids the public-zero-target collapse of the same-target shortcut. If two
fixed anchors authenticate distinct dynamic keys P,Q and one long signature
passes under both, their signs select one of two prebound point combinations.
The corresponding scalar follows exactly from actual digests:
`A=c*z_anchor-2*z_open/r`.

For nonzero dynamic key sum, however, these values prescribe the signature's
nonce x-coordinate: `r=-2*z_open/(A-c*z_anchor)`. Even a creator who knows
both signing scalars needs a nonce logarithm at that x-coordinate to supply
the common signature. An accepted response conversely gives that logarithm
to the creator. The same-ALL relation is an invertible fractional-linear map
for nonzero hidden A; the fixed-r exception has a zero public target.

Thirty-one synthetic secp256k1 fixtures and eight deterministic test methods
reproduce extraction, both signs, different digest/flag cases, the zero-digest
boundary, malformed inputs and the opening equivalence. Digests are assigned
algebraically, not realized as Bitcoin transaction hashes. No native opening
algorithm, transaction or complete setup benchmark is supplied.

This is a boundary on this proposed replacement, not a general impossibility
result or a failure of its extraction equation. A future repair must provide
efficient actual openings without moving the prebound labels after the
transaction hash or weakening the future-message requirement. Evidence:
**locally-reproduced** examples and **inspected** algebra; deployment:
**unclassified**.
