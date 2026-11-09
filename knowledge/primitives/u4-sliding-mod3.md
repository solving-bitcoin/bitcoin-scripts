# Sliding modulo-three sums over u4 inputs

Can a fixed-width window update its modulo-three sum using one resident
table, with lower complete-leaf byte and opcode costs than independently
rescanning each window? The hypothesis is that subtracting the outgoing
residue and adding the incoming residue saves code as the overlap grows.
Compare the schedules with the same input checks, table, output order,
witness, and terminal predicates.

## Construction

Project every canonical nibble to its residue in `0..=2`. Sum the rightmost
window and use the same 16-entry table to reduce that sum. Moving left,
subtract the outgoing rightmost residue, add the incoming left residue,
and reduce the updated value. The result before adding a bias is in
`-2..=4`, so adding three makes it a nonnegative table argument in
`1..=7`. The altstack reverses the stream of outputs back to increasing
window-start order.

The reusable overlap principle is described for polynomial fingerprints in
[Karp and Rabin (1987)](https://doi.org/10.1147/rd.312.0249). The local
relation is the unweighted sum modulo three. The closest repository
constructions are [individual modulo-three projection](u4-mod3.md) and the
[modulo-16 prefix scan](u4-prefix-sum.md). Individual projection alone does
not sum windows, and a wrapped modulo-16 prefix difference does not determine
a modulo-three sum because 16 is not divisible by three. No matching PR was
found by the scoped sliding-window and rolling-checksum searches.

## Evidence and limits

At 128 inputs and window width seven, the rolling leaf uses 3,548 bytes and
2,528 executed non-push operations. Rescanning uses 5,599 bytes and 3,859
operations. Both have 249 serialized data-witness bytes, 128 ordinary
items, zero hint items, and a 147-item combined peak. Width one loses;
the [negative result](../negative-results/u4-sliding-mod3.md) records that
comparison and the limits of the table and output relation.

The [implementation README](../../src/arithmetic/u4/sliding_mod3/README.md)
contains all matched measurements and reproduction commands. Evidence is
`locally-reproduced`, execution is `unclassified`, and no funded spend
or relay policy has been exercised for these leaves. This relation exposes
small arithmetic residues. A surrounding application must independently
bind its original inputs if it intends to identify a committed message.
