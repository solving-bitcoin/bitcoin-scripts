# Checked nibble erasure recovery schedules

Both schedules consume the same surviving canonical digits and
use the same two public checks modulo 17. Direct recomposition
inserts the recovered digit into the second weighted check.
The centered schedule subtracts the erased position times the
first equation from the second, so the erased coefficient is
zero. It represents the other coefficients in `[-8,8]`.

| Width | Erased index | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items | Combined peak | Executed non-push ops |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | 1 | Centered check | 116 | 7 | 3 | 0 | 7 | 74 |
| 4 | 1 | Direct recomposition | 116 | 7 | 3 | 0 | 7 | 76 |
| 17 | 0 | Centered check | 479 | 33 | 16 | 0 | 20 | 359 |
| 17 | 0 | Direct recomposition | 525 | 33 | 16 | 0 | 21 | 408 |
| 17 | 8 | Centered check | 468 | 33 | 16 | 0 | 20 | 357 |
| 17 | 8 | Direct recomposition | 522 | 33 | 16 | 0 | 21 | 405 |
| 17 | 16 | Centered check | 468 | 33 | 16 | 0 | 20 | 356 |
| 17 | 16 | Direct recomposition | 522 | 33 | 16 | 0 | 21 | 405 |

Every leaf includes canonical checks, recovery, the second
check, exact output equality and terminal true. All witness
items coexist at entry. Data witness includes item count and
lengths and excludes leaf, control block, annex and transaction.
Executed counts exclude pushes and include encountered branch
delimiters. All rows use policy `ALL`, stack-limited local
tapscript, and zero signature charge.

The width-four fixture ties on bytes and stack. At width 17
with erased index eight, centering saves 54 leaf bytes,
48 executed non-push operations and one live item. See the
[implementation snapshots](../../src/arithmetic/u4/erasure/README.md#script-metrics).
Evidence is `locally-reproduced`. Execution is `unclassified`.
