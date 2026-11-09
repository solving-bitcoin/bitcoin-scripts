# Unique mismatch schedules for opaque items

Both schedules consume the same interleaved opaque witnesses, require
exactly one raw mismatch, and verify the same returned index before
terminal true. The fused scan uses one private altstack state. The
materialized mask parks one equality flag per pair before decoding
the index.

| Pairs | Mismatch index | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items | Combined peak | Executed non-push ops |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0 | Fused reverse scan | 8 | 6 | 2 | 0 | 2 | 6 |
| 1 | 0 | Materialized equality mask | 15 | 6 | 2 | 0 | 2 | 10 |
| 32 | 0 | Fused reverse scan | 278 | 192 | 64 | 0 | 64 | 106 |
| 32 | 0 | Materialized equality mask | 279 | 192 | 64 | 0 | 64 | 165 |
| 128 | 43 | Fused reverse scan | 1,144 | 770 | 256 | 0 | 256 | 394 |
| 128 | 43 | Materialized equality mask | 1,145 | 770 | 256 | 0 | 256 | 645 |
| 500 | 499 | Fused reverse scan | 4,865 | 3,002 | 1,000 | 0 | 1,000 | 1,507 |
| 500 | 499 | Materialized equality mask | 4,866 | 3,002 | 1,000 | 0 | 1,000 | 2,505 |

The fused scan executes 998 fewer non-push operations at width 500
and saves one leaf byte. Initial data depth dominates the combined
peak for both. All rows include terminal true and use policy `ALL`,
the pinned stack-limited local tapscript interpreter, and zero
signature charge. Data witness includes count and lengths, excluding
leaf, control block, annex and transaction framing. The executed count
includes encountered branch delimiters and excludes pushes.
See the [implementation snapshots](../../src/support/mismatch/README.md#script-metrics).
Evidence is `locally-reproduced`; execution is `unclassified`.
