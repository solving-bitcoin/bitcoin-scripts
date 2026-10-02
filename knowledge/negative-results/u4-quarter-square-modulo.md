# NR-076: Quarter-square modulo multiplication is a memory/byte tradeoff

Store floor(x*x/4) modulo 16 in 31 entries, query at a+b and abs(a-b), subtract,
and add 16 when negative. All canonical 0..15 operand pairs reproduce modulo
products. Removing 225 table items does not universally reduce lifecycle bytes:

| Pairs | Quarter fragment / peak | Canonical full fragment / peak | Data items | Hints | Data witness bytes |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 32 | 1583 / 98 | 1792 / 323 | 64 | 0 | 129 |
| 128 | 6191 / 290 | 6016 / 515 | 256 | 0 | 515 |
| 370 | 17807 / 774 | 16664 / 999 | 740 | 0 | 1483 |

Every operand is present at entry. Both include table setup, canonical/range
checks, routing, cleanup and ordered modulo outputs, excluding pushes/terminal
checks. Conditional normalization increases per-query bytes; the quarter table
retains stack savings but loses bytes on the latter two measured batches.
All scripts are policy-optimized. Dynamic executed counts and validation weight
are unavailable. Evidence locally-reproduced, execution unclassified: strict
local tapscript with no Core or relay transaction evidence. This is not an
impossibility or global optimum claim. The [exact product](../primitives/u4-exact-product.md)
uses Q values directly and has a different cost/output boundary. Reproduce
with [the producer and manifest](../../research/u4-quarter-square/README.md).
