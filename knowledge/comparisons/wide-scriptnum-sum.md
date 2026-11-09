# Exact signed sum representation schedules

Both schedules consume the same two signed four-byte ScriptNums and
return a canonical residual and signed class. Post-add dispatch checks
the byte length of the arithmetic result. Pre-add dispatch compares
the operands against the signed headroom before adding. The ordering
fixture runs the same schedule twice and compares the generated
descriptors by class and residual.

| Fixture | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items | Combined peak | Executed non-push ops |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `M + (-M)` | Post-add size | 49 | 11 | 2 | 0 | 5 | 22 |
| `M + (-M)` | Pre-add headroom | 69 | 11 | 2 | 0 | 4 | 27 |
| `M + 1` | Post-add size | 49 | 8 | 2 | 0 | 5 | 27 |
| `M + 1` | Pre-add headroom | 69 | 8 | 2 | 0 | 4 | 28 |
| `-M - 1` | Post-add size | 49 | 8 | 2 | 0 | 5 | 27 |
| `-M - 1` | Pre-add headroom | 69 | 8 | 2 | 0 | 4 | 28 |
| `M + 1 < M + 2` | Post-add size | 106 | 15 | 4 | 0 | 7 | 63 |
| `M + 1 < M + 2` | Pre-add headroom | 146 | 15 | 4 | 0 | 6 | 65 |

`M = 2147483647`. Every leaf includes both operand guards and the
same terminal verification for its fixture. All witness data coexist
at entry. Witness bytes include the count and item lengths, excluding
leaf, control block, annex and transaction. Executed operations
exclude pushes and include processed branch delimiters. All leaves use
policy `ALL`, stack-limited local tapscript, and zero signature charge.

Post-add dispatch saves 20 bytes for one split and 40 for the ordering
leaf. Pre-add headroom needs one fewer combined stack item at both
boundaries. See the [implementation metrics](../../src/arithmetic/wide_sum/README.md#script-metrics).
Evidence is `locally-reproduced`; execution is `unclassified`.
