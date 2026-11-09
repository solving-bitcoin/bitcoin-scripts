# Signed arithmetic progression schedules

Compare carrying one backward difference with checking the cross-sum
identity for every overlapping triple. Both schedules explicitly bound
each ordinary input to four bytes, consume the same input suffix,
verify the same numeric relation, and finish with true. Each compares
canonical arithmetic results by raw equality. The leaves use zero
hints and no signatures. All data coexist at entry.

| Values | Schedule | Leaf bytes | Data witness bytes | Data items | Hint items | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 3 | Carried difference | 25 | 16 | 3 | 0 | 5 | 20 |
| 3 | Local cross-sums | 24 | 16 | 3 | 0 | 5 | 19 |
| 32 | Carried difference | 344 | 160 | 32 | 0 | 34 | 281 |
| 32 | Local cross-sums | 401 | 160 | 32 | 0 | 34 | 338 |
| 128 | Carried difference | 1,400 | 640 | 128 | 0 | 130 | 1,145 |
| 128 | Local cross-sums | 1,649 | 640 | 128 | 0 | 130 | 1,394 |
| 998 | Carried difference | 10,970 | 1,001 | 998 | 0 | 1,000 | 8,975 |
| 998 | Local cross-sums | 12,959 | 1,001 | 998 | 0 | 1,000 | 10,964 |

The carried schedule loses one byte and one operation at three values.
At 128 values it saves 249 bytes and 249 executed operations while
holding the same combined stack peak. All leaves use policy `ALL`.
Witness bytes include the data item count and lengths and exclude
leaf, control block, annex and transaction framing. The
[implementation snapshots](../../src/arithmetic/progression/README.md#script-metrics)
record the deterministic inputs and local execution profiles.
Evidence is `locally-reproduced`; execution is `unclassified`.
