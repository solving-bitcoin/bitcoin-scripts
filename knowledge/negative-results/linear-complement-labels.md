# Scalar-linear complement delivery cannot preserve both kinds of hidden labels

The [threshold-complement translation](../../research/pointlocks-2026-09-17/complement-translation.md)
has practical honest setup, but its encrypted shares still lack public binding.
Replacing the encrypted layer with scalar-linear public relations encounters a
specific obstruction, not merely a bad choice of random coefficients.

For n candidates and t scalar openings, require every t-subset to reconstruct
zero-labels for its unselected candidates, while reconstructing neither their
unselected point scalars nor the selected candidates' zero-labels. With linear
scalar reconstruction over a common field, these conditions are incompatible
for n>=t+2. A dependence among t+1 candidate forms leaks an unselected scalar;
without such a dependence, intersecting two permitted reconstruction spans
leaks a selected zero-label. The n=t+1 boundary is achievable.

The [proof and reproduction](../../research/pointlocks-2026-09-17/complement-linear-obstruction.md)
state the exact scope. This does not exclude the existing PRF-encrypted bridge,
nonlinear/group-valued labels, or all publicly verifiable constructions.

## Direct binary-label delivery has a separate rank bound

The [binary-label rank argument](../../research/pointlocks-2026-09-17/binary-linear-label-rank.md)
shows that every selected k-label set must be independent if all 2^k messages
are allowed and the binary labels completely authenticate the message.
Otherwise an opening of a one-bit-neighbor message supplies a public linear
combination for the opposite label. Thus a direct scalar-linear decoder needs
at least k field openings, even with correlated masks. The bound is tight
with k+1 hidden dimensions; 510 messages, 3,586 opposite-label checks and a
secp256k1/KDF disclosure fixture are reproduced.

With one guarded legacy sum-key signature per opening, k=2,048 requires at
least 120,832 vB for signature pushes alone, even granting every signature
the 58-byte minimum. This is a restricted analytic bound, not a complete
transaction measurement. Nonlinear garbling/KDF expansion, other native
opening mechanisms and additional message-dependent authentication inputs
are outside the model.

Evidence: **inspected** proof, **locally-reproduced** exact regression examples.
Deployment: **unclassified**. No new Bitcoin execution, bytes or setup timing.
