# An unordered match can admit both orientations

The hostile quartet `[80, 80, 80, 80]`, with each entry a raw one-byte
vector, satisfies both straight and reversed equalities. A branch on
`b == d` that accepts the first matching orientation returns zero for
this input. That output fails to certify a unique orientation even though
it is deterministic.

The focused test runs this reduced verifier and the checked construction
on the same witness. The checked construction rejects. The baseline also
rejects because its computed orientation flags are equal. The
[eager baseline](../comparisons/opaque-pair-orientation.md) additionally
spends more executed operations and reaches the standalone stack frontier
with two fewer caller slots than the branch schedule. Evidence is
`locally-reproduced`. Execution is `unclassified`.
