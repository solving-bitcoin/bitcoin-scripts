# Strict signed peak verification schedules

Both schedules require the same strict increase followed by strict
decrease and return the same interior peak index. They share all
numeric width checks and strict edge comparisons. The arithmetic
schedule enforces the phase transition as an inequality. The other
schedule uses a branch on the current ascent bit.

| Width | Peak index | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items | Combined peak | Executed non-push ops |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 32 | 1 | Arithmetic phase | 556 | 90 | 32 | 0 | 34 | 521 |
| 32 | 1 | Branched phase | 649 | 90 | 32 | 0 | 34 | 494 |
| 32 | 30 | Arithmetic phase | 557 | 93 | 32 | 0 | 34 | 521 |
| 32 | 30 | Branched phase | 650 | 93 | 32 | 0 | 34 | 494 |
| 128 | 53 | Arithmetic phase | 2,285 | 375 | 128 | 0 | 130 | 2,153 |
| 128 | 53 | Branched phase | 2,666 | 375 | 128 | 0 | 130 | 2,030 |
| 998 | 497 | Arithmetic phase | 17,946 | 2,993 | 998 | 0 | 1,000 | 16,943 |
| 998 | 497 | Branched phase | 20,937 | 2,993 | 998 | 0 | 1,000 | 15,950 |

At width 998, arithmetic saves 2,991 leaf bytes and executes
993 additional non-push operations. The witness and peak are
identical. Every leaf compares the exact index and ends with true.
All data coexist at entry. Data witness includes count and lengths
and excludes leaf, control block, annex and transaction.
Executed counts exclude pushes and include encountered control
delimiters. All leaves use policy `ALL`, stack-limited local
tapscript and zero signature charge. See the
[implementation snapshots](../../src/arithmetic/single_peak/README.md#script-metrics).
Evidence is `locally-reproduced`. Execution is `unclassified`.
