# Opaque lag-match count schedules

Compare the same exact count over the same unwrapped raw comparisons.
The deferred and eager schedules consume the later member as they
scan. The copying baseline keeps all original items and copies
both operands for each comparison.

| Width | Lag | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items | Combined peak | Executed non-push ops |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 32 | 1 | Deferred accumulator | 157 | 89 | 32 | 0 | 33 | 124 |
| 32 | 1 | Eager accumulator | 161 | 89 | 32 | 0 | 34 | 126 |
| 32 | 1 | Copy both operands | 238 | 89 | 32 | 0 | 35 | 142 |
| 128 | 28 | Deferred accumulator | 618 | 365 | 128 | 0 | 129 | 415 |
| 128 | 28 | Eager accumulator | 621 | 365 | 128 | 0 | 130 | 417 |
| 128 | 28 | Copy both operands | 857 | 365 | 128 | 0 | 131 | 467 |
| 998 | 27 | Deferred accumulator | 5,845 | 2,853 | 998 | 0 | 999 | 3,899 |
| 998 | 27 | Eager accumulator | 5,848 | 2,853 | 998 | 0 | 1,000 | 3,901 |
| 999 | 27 | Deferred accumulator | 5,851 | 2,856 | 999 | 0 | 1,000 | 3,903 |

Every leaf includes exact count equality and terminal true. Data
witness bytes include item count and lengths, excluding leaf,
control block, annex and transaction. All data coexist at entry.
Executed counts exclude pushes. All rows use policy `ALL`, the
stack-limited local tapscript interpreter, and zero signature charge.

The initial stack and copy temporaries determine the frontier.
The [negative result](../negative-results/opaque-lag-count.md)
records the failed wider schedules. See the
[metric snapshots](../../src/support/lag_count/README.md#script-metrics).
Evidence is `locally-reproduced`; execution is `unclassified`.
