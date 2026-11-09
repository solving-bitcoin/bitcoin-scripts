# Script caps on serialized witness data

The [witness-data size predicate](../primitives/witness-data-size.md) checks
a cap on a fixed suffix and preserves its raw inputs. Both complete leaves
below include the cap check, input cleanup and terminal true. The data
witness includes its CompactSize count and item-length prefixes and
excludes the leaf, control block, annex, and transaction. All ordinary
items coexist at entry, and both schedules use zero hints.

| Ordinary items | Cap | Fixture | Selected script / executed ops / peak | Always conditional script / executed ops / peak | Data witness bytes |
| ---: | ---: | --- | ---: | ---: | ---: |
| 32 | 161 | Four bytes each | 199 / 146 / 35 | 487 / 274 / 36 | 161 |
| 32 | 286 | Four bytes each | 455 / 306 / 36 | 487 / 274 / 36 | 161 |
| 32 | 1062 | Lengths 252, 253, 520, then empty | 455 / 306 / 36 | 487 / 276 / 36 | 1062 |
| 253 | 256 | Empty items | 1763 / 1141 / 256 | 4040 / 2153 / 257 | 256 |

A cap below the lower-bound cost of any long-prefix item allows the
selected script to skip every item-prefix check. At larger caps it
counts the additional bytes without branching. The exact conditional
schedule executes fewer operations in the mixed and all-short fixtures,
while the exact branch-free schedule is smaller. These are executed
non-push counts with visited branch delimiters, rather than time
measurements. See the [checked metric markers](../../src/support/witness_data_size/README.md#script-metrics)
and [sharp cutoff](../negative-results/witness-data-size.md).
