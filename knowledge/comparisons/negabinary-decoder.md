# Checked negabinary decoder schedules

Both schedules consume the same fixed-width canonical bits and
return the same signed value. The two-subtraction schedule
evaluates `d-x-x`. The multiply-first schedule evaluates
`d-(x+x)` and checks or corrects its final width-32 step.

| Width | Calls | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items | Combined peak | Executed non-push ops |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 8 | 1 | Two subtractions | 103 | 14 | 8 | 0 | 11 | 84 |
| 8 | 1 | Checked multiply first | 103 | 14 | 8 | 0 | 11 | 84 |
| 31 | 1 | Two subtractions | 405 | 48 | 31 | 0 | 34 | 337 |
| 31 | 1 | Checked multiply first | 405 | 48 | 31 | 0 | 34 | 337 |
| 32 | 1 | Two subtractions | 422 | 35 | 32 | 0 | 35 | 351 |
| 32 | 1 | Checked multiply first | 444 | 35 | 32 | 0 | 35 | 352 |
| 32 | 16 | Two subtractions | 6,705 | 595 | 512 | 0 | 515 | 5,616 |
| 32 | 16 | Checked multiply first | 7,057 | 595 | 512 | 0 | 515 | 5,680 |

The measured smaller widths tie. The full-width batch saves
352 leaf bytes and 64 executed operations at the same peak.
Every leaf verifies and removes each exact decoded value and
finishes with true. All bits coexist at entry. Data witness
includes count and item lengths, excluding leaf, control block,
annex and transaction. Executed counts exclude pushes and include
encountered branch delimiters. All fixtures use policy `ALL`,
the stack-limited local tapscript interpreter, and zero signature
charge. See the
[implementation snapshots](../../src/arithmetic/negabinary/README.md#script-metrics).
Evidence is `locally-reproduced`. Execution is `unclassified`.
