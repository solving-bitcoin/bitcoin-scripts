# Signed midpoint hint schedules

Both schedules verify the same floor midpoint from two signed
ScriptNums and one canonical proposed-result hint. The implicit
schedule derives the case by comparing raw sums. The explicit
baseline also requires a parity hint and checks it with MINIMALIF.

| Fixture | Calls | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items | Total data items | Serialized hint bytes | Combined peak | Executed non-push ops |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Even maximum | 1 | Implicit | 49 | 16 | 2 | 1 | 3 | 5 | 6 | 26 |
| Even maximum | 1 | Explicit | 47 | 17 | 2 | 2 | 4 | 6 | 7 | 26 |
| Odd negative wide | 1 | Implicit | 49 | 16 | 2 | 1 | 3 | 5 | 6 | 33 |
| Odd negative wide | 1 | Explicit | 47 | 18 | 2 | 2 | 4 | 7 | 7 | 30 |
| Mixed | 128 | Implicit | 5,889 | 1,475 | 256 | 128 | 384 | 416 | 387 | 3,776 |
| Mixed | 128 | Explicit | 5,633 | 1,667 | 256 | 256 | 512 | 608 | 515 | 3,584 |
| Mixed | 249 | Implicit | 11,457 | 2,870 | 498 | 249 | 747 | 811 | 750 | 7,342 |
| Mixed | 249 | Explicit | 10,959 | 3,243 | 498 | 498 | 996 | 1,184 | 999 | 6,970 |
| Mixed | 332 | Implicit | 15,273 | 3,821 | 664 | 332 | 996 | 1,079 | 999 | 9,794 |

Both complete leaves verify and consume every returned midpoint
and finish with true. All ordinary data and hints coexist at
entry. Witness bytes include item count and lengths and exclude
leaf, control block, annex and transaction. Incremental hint
bytes include each hint's length and exclude the shared item
count. Executed operations exclude pushes and include encountered
control delimiters. All rows use policy `ALL`, stack-limited
local tapscript, and zero signature charge.

Implicit parity saves 128 stack items and 192 witness bytes in
the 128-call fixture, while adding 256 leaf bytes and 192 executed
operations. Explicit parity uses 64 fewer bytes when leaf and
data witness are summed at this boundary. The explicit batch
frontier is 249 with one caller item, versus 332 with implicit
parity. See the
[implementation snapshots](../../src/arithmetic/midpoint/README.md#script-metrics-and-witness-layout).
Evidence is `locally-reproduced`. Execution is `unclassified`.
