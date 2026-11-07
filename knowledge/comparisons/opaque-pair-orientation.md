# Unique opaque pair orientation schedules

Both schedules return a bit per quartet, require exactly one matching
orientation, and preserve both caller stacks. The branch schedule compares
one discriminating pair before it checks the selected orientation. The eager
baseline copies a quartet, computes both orientation flags, and requires
them to differ. Output staging, restoration, literal bit checks, and
terminal true are included on both sides.

All ordinary input items coexist at script entry. Data witness includes
the count and item length prefixes and excludes leaf, control block, annex
and transaction. Peak combines main and alt stacks. Executed non-push
operations include encountered branch delimiters. The
[deterministic fixture](../../research/opaque-pair-orientation/fixture.rs)
uses three-byte payloads. Catalog witness maxima instead assume all
payloads use the local Consensus profile's 520-byte element limit.

| Quartets | Pattern | Schedule | Leaf bytes | Data witness bytes | Data items | Hint items | Combined peak | Executed non-push ops |
| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Straight | Branch | 23 | 17 | 4 | 0 | 6 | 14 |
| 1 | Straight | Eager | 23 | 17 | 4 | 0 | 8 | 21 |
| 1 | Reversed | Branch | 23 | 17 | 4 | 0 | 6 | 11 |
| 1 | Reversed | Eager | 23 | 17 | 4 | 0 | 8 | 21 |
| 128 | Alternating | Branch | 3,071 | 2,051 | 512 | 0 | 514 | 1,854 |
| 128 | Alternating | Eager | 3,071 | 2,051 | 512 | 0 | 516 | 2,942 |
| 249 | Alternating | Branch | 5,975 | 3,987 | 996 | 0 | 998 | 3,610 |
| 249 | Alternating | Eager | 5,975 | 3,987 | 996 | 0 | 1,000 | 5,725 |

The schedules tie in serialized script and data witness bytes. The branch
executes three raw equality operations per quartet, while eager executes
four. The reversed branch spends three fewer non-push operations than the
straight branch because its routing and equality checks establish
distinctness directly. At width 249 the branch saves 2,115 non-push
operations and two peak items. Both schedules support that standalone width.
The branch preserves one caller item on each stack there and reaches 1,000.
One more caller item fails. Eager reaches 1,000 before caller state.

The [ambiguity counterexample](../negative-results/opaque-pair-orientation.md)
rules out returning the first matching orientation with no uniqueness check.
The [implementation README](../../src/support/unique_pair_orientation/README.md)
has reproduction commands. Each measured script compiles with policy `ALL`
and runs in the stack-limited local tapscript Consensus profile with a
synthetic transaction and experimental OP_CAT disabled. The same fixtures
pass the local Policy profile. Both schedules have zero hints and zero
signature charge. Evidence is `locally-reproduced`. Execution is
`unclassified`.
