# SHA-256 pool selection limits

Two independent indexed checks can open the same slot twice unless
distinctness is enforced. The focused test feeds the same index and
preimage twice to the existing HORS opening helper and observes
acceptance under its own contract. The destructive SHA-256 leaf rejects
the repeated preimage because the selected digest was removed and the
remaining list has unique digests. Its generator rejects duplicate
public digest entries.

Destructive ranks do not reduce the number of hint items. Both indexed
schedules carry two preimages and two selectors. The width-129 fixture
saves one serialized hint byte because removing slot 1 maps original
slot 128 to rank 127. At widths 3, 32, and 993 the measured witness
sizes tie between the indexed schedules.

The zero-hint scan uses six peak items in every measured case. The
resident pool has peak `n + 7` plus preserved caller state and
leaves no caller headroom at width 993. It saves script bytes and
executed operations against the scan, while the scan saves witness
bytes and live stack space. The scan cost grows because both hashes
are compared against every public digest. The 993-digest rows are
unoptimized under the repository policy.

Reproduce with the [focused tests and metrics](../../src/commitments/sha256_pool/README.md).
Evidence is `locally-reproduced`; execution is `unclassified`.
