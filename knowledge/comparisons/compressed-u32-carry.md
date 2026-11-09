# Compressed u32 carry schedules

All three leaves verify the same final unsigned carry bit from two
canonical compressed ScriptNums. The sign-class schedule uses small
tags and a signed mixed-case sum. Complement comparison checks
`~b < a` using the existing compressed unsigned comparator.
Expanded ripple reuses the canonical decoder and u32 zip and
propagates carry without generating the wrapped sum.

| Operands | Carry | Data witness bytes | Leaf bytes, classes / complement / ripple | Combined peak | Executed non-push ops |
| --- | ---: | ---: | --- | --- | --- |
| `0 + 1` | 0 | 4 | 69 / 153 / 912 | 6 / 6 / 11 | 38 / 78 / 620 |
| `0x7fffffff + 0x80000000` | 0 | 12 | 69 / 153 / 912 | 6 / 6 / 11 | 31 / 70 / 616 |
| `0x7fffffff + 0x80000001` | 1 | 11 | 69 / 153 / 912 | 6 / 6 / 11 | 38 / 75 / 622 |
| `0x80000000 + 0xffffffff` | 1 | 9 | 69 / 153 / 912 | 5 / 6 / 11 | 31 / 72 / 618 |

All fixtures have two ordinary witness items at entry and zero hints.
Leaf bytes include both input checks, output equality and terminal true.
Data witness bytes include the count and item lengths, excluding leaf,
control block, annex and transaction. The executed count excludes
pushes and includes encountered branch delimiters. All leaves use
policy `ALL` and the pinned stack-limited local tapscript profile,
with zero signature charge.

The complement comparator checks the synthesized word as part of its
existing public contract. These measurements give that reuse cost.
A comparator fused with its synthesis could change the comparison.
The [implementation snapshots](../../src/arithmetic/u32/carry/README.md#script-metrics)
hold the exact tested configurations. Evidence is `locally-reproduced`
and execution is `unclassified`.
