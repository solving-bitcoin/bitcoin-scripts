# Length-keyed SHA-256 digest schedules

Every leaf checks the preimage's exact byte length, hashes once,
matches the corresponding public digest and ends with true.
The schedules differ only in how many digest constants they
materialize in the selected branch. Every fixture supplies one
ordinary witness item and zero hints.

| First length | Digests | Opened length | Data witness bytes | Leaf bytes, per-digest / block 8 / full | Combined peak | Executed non-push ops |
| ---: | ---: | ---: | ---: | --- | --- | --- |
| 16 | 32 | 31 | 33 | 1,317 / 1,112 / 1,091 | 5 / 10 / 34 | 112 / 31 / 30 |
| 0 | 128 | 79 | 81 | 5,238 / 4,407 / 4,306 | 5 / 10 / 130 | 404 / 71 / 77 |
| 0 | 521 | 519 | 523 | 21,744 / 18,070 / 17,471 | 5 / 10 / 523 | 1,589 / 227 / 273 |
| 0 | 521 | 520 | 524 | 21,744 / 18,070 / 17,471 | 5 / 5 / 523 | 1,589 / 218 / 273 |

At 521 digests, eight-entry blocks add 599 bytes to the full
table and reduce peak by 513 items on the 519-byte fixture.
Length 520 reaches the singleton tail block and peaks at five.
The full table is the smallest measured leaf at all widths, and
per-digest branching minimizes worst-case stack usage.

Witness bytes include count and length, excluding leaf, control
block, annex and transaction framing. All rows use policy `ALL`,
the pinned local stack-limited tapscript interpreter, and zero
signature charge. The opcode count excludes pushes and includes
control delimiters processed in inactive branches. Local Policy
rejects the 519- and 520-byte entry items.
See the [implementation snapshots](../../src/commitments/length_keyed/README.md#script-metrics).
Evidence is `locally-reproduced`; execution is `unclassified`.
