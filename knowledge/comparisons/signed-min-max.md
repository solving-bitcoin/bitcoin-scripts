# Signed extrema schedules

The paired and streaming schedules consume the same canonical signed vector
and return the same exact minimum and maximum. Both start by ordering the
top pair once. The complete leaves use identical raw output checks and finish
with true. Every ordinary input coexists at entry. Data witness includes the
item count and each length prefix and excludes leaf, control block, annex and
transaction. Both use zero hints and charge zero signature weight. Peak covers
main and alt stacks together.

The [deterministic fixture](../../research/paired-signed-extrema/fixture.rs)
alternates values near the four-byte signed endpoints. Both schedules are
compiled with policy `ALL`. Measurements use the stack-limited local tapscript
Consensus profile with experimental OP_CAT disabled and a synthetic transaction.
The measured leaves also pass the local Policy profile. Executed non-push
operations include branch delimiters. Value comparisons count executed
`OP_GREATERTHAN`, `OP_MIN` and `OP_MAX`.

| Width | Schedule | Leaf bytes | Data witness bytes | Data items | Hint items | Combined peak | Executed non-push ops | Value comparisons |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | Paired | 37 | 11 | 2 | 0 | 5 | 21 | 1 |
| 2 | Streaming | 37 | 11 | 2 | 0 | 5 | 21 | 1 |
| 32 | Paired | 487 | 161 | 32 | 0 | 35 | 396 | 46 |
| 32 | Streaming | 487 | 161 | 32 | 0 | 35 | 411 | 61 |
| 128 | Paired | 1,927 | 641 | 128 | 0 | 131 | 1,596 | 190 |
| 128 | Streaming | 1,927 | 641 | 128 | 0 | 131 | 1,659 | 253 |
| 997 | Paired | 14,962 | 4,988 | 997 | 0 | 1,000 | 12,957 | 1,494 |
| 997 | Streaming | 14,962 | 4,988 | 997 | 0 | 1,000 | 12,957 | 1,991 |

The first pair has the same cost on both schedules. Each subsequent pair uses
three value comparisons instead of four. Each such pair saves one total
executed non-push operation when its conditional swap is skipped and ties
when the swap runs. At widths 32 and 128 the fixture skips all subsequent
swaps. At width 997 it takes all of them, so 497 fewer value comparisons
do not lower the total executed count. Serialized leaf bytes and stack peak
tie in every matched row. A paired reduction therefore does not give a strict
byte, witness, or stack improvement on these schedules.

Both schedules peak at `width + 3` items for measured widths of at least two.
The tested standalone frontier is 997 inputs. The paired schedule at width
995 also preserves one caller item on each stack at a combined peak of 1,000.
The [sum-reconstruction counterexample](../negative-results/signed-min-max.md)
has the same required output but fails on valid four-byte inputs.

See the [primitive](../primitives/signed-min-max.md) and
[reproduction commands](../../src/arithmetic/extrema/README.md).
Evidence is `locally-reproduced`. Execution is `unclassified`.
