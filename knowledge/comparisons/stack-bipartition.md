# Stable bipartition schedules

The [opaque bipartition](../primitives/stable-bipartition.md) consumes all
flags and preserves both stable groups. The false group and its count
remain on main and the true group goes to alt. That output contract differs
from filtering. Compare the single live cursor with recomputing depth, both
using the same two-byte payloads, alternating flags, literal output checks
and terminal true. All inputs coexist at entry and hints are zero.

| Pairs | Schedule | Leaf bytes | Data witness bytes | Data items | Hint items | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 32 | Single cursor | 533 | 145 | 64 | 0 | 66 | 337 |
| 32 | Recomputed depth | 644 | 145 | 64 | 0 | 67 | 385 |
| 128 | Single cursor | 2,119 | 579 | 256 | 0 | 258 | 1,345 |
| 128 | Recomputed depth | 2,743 | 579 | 256 | 0 | 259 | 1,537 |
| 499 | Single cursor | 8,242 | 2,249 | 998 | 0 | 1,000 | 5,241 |

Script bytes include checks for every output on both stacks. Witness bytes
include the data count and item lengths, excluding leaf, control block,
annex and transaction. The opcode count includes processed control
delimiters and excludes pushes. The [recomputed-depth leaf](../negative-results/stable-bipartition.md)
fails at 499 pairs. All successful rows use policy `ALL`, local stack-limited
tapscript execution and zero signature charge. Evidence is `locally-reproduced`
and execution is `unclassified`. See the
[implementation snapshots](../../src/support/split/README.md#script-metrics).
