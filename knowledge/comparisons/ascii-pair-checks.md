# Opposite-case ASCII pair schedules

The shared interval and gap schedule checks the lower numeric value once
and binds the distance to 32. The raw mate schedule checks one operand
and compares the other to the exact synthesized opposite-case bytes.
The independent folds validate each operand and compare both the folded
letter and the case class.

All rows use the same ordinary raw data items and zero hints. The
policy-compiled leaves include every check and terminal true. Data
witness serialization includes the item count and lengths and excludes
leaf, control block, annex and transaction framing. Combined peak
includes all pairs preloaded at entry. The opcode count includes
executed non-push operations and encountered control delimiters.

| Pairs | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Shared interval and gap | 21 | 5 | 2 | 0 | 5 | 12 |
| 1 | Raw mate | 32 | 5 | 2 | 0 | 5 | 12 |
| 1 | Independent folds | 46 | 5 | 2 | 0 | 7 | 26 |
| 128 | Shared interval and gap | 2,561 | 515 | 256 | 0 | 259 | 1,536 |
| 128 | Raw mate | 3,969 | 515 | 256 | 0 | 259 | 1,536 |
| 128 | Independent folds | 5,761 | 515 | 256 | 0 | 261 | 3,328 |

The shared check uses 1,408 fewer leaf bytes than raw mate synthesis at
128 pairs with the same executed count and peak. Independent folds also
use two more live stack items. See the
[metric snapshots](../../src/support/ascii_case/README.md#script-metrics).
Evidence is `locally-reproduced`; execution is `unclassified`.
