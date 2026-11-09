# Two distinct SHA-256 openings from one public pool

Can a Script verify two distinct openings from a public digest pool by
consuming each selected slot, with a lower cost than keeping all slots
and comparing original indices? Compare those two schedules and a
zero-hint scan on the same two opaque preimages and unique public list.
The hypothesis is that shrinking the pool removes an explicit
distinctness check and sometimes makes the second selector shorter.

## Construction

Embed a unique list of 32-byte digests. The first canonical ScriptNum
selects a slot and removes it with `OP_ROLL`. The second canonical
ScriptNum selects from the remaining slots. Range checks run before
each selection. The leaf verifies both preimages with native
`OP_SHA256` and byte equality. For original positions `i != j`, use
ranks `i` and `j - (j > i)`. Two data items and two hint items are
present at entry and consumed. The related [WOTS key-pool technique](../techniques/lookup-tables.md#destructive-public-key-pools)
also removes selected slots. [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4)
specifies SHA-256.

The repository's [HORS helper](../../src/signatures/hors/README.md)
opens indexed HASH160 commitments as part of a signature protocol.
It accepts a repeated index at its own opening boundary, as the
focused test reproduces. The new relation enforces different
digests without using message-derived indices or defining a
signature scheme. The zero-hint scan compares two distinct
computed hashes against every member of the list and verifies
two total hits.

## Evidence and limits

At width 129, destructive ranks use 4,368 leaf bytes, 71 data-witness
bytes, two hint items carrying four incremental bytes, a 136-item
combined peak, and 88 executed non-push operations. Fixed indices use
4,375 leaf bytes, 72 data-witness bytes, two hints carrying five bytes,
peak 136, and 95 operations. The scan uses 5,559 leaf bytes, 67
data-witness bytes, zero hints, peak six, and 1,041 operations. All
three use two ordinary preimages and two native SHA-256 executions.

At width 993 the destructive route reaches the local 1,000-item limit.
The 993-digest comparison is unoptimized because all leaves exceed
the central 32-KiB optimizer cutoff. See the
[full comparison](../comparisons/commitments.md#two-distinct-sha-256-openings)
and [negative results](../negative-results/sha256-pair-pool.md).

Evidence is `locally-reproduced`; execution is `unclassified`.
The relation concerns openings of the embedded list. It does not
bind a message, prove freshness, or prevent reuse of disclosed
preimages. See [fixtures and reproduction](../../src/commitments/sha256_pool/README.md).
