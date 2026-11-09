# One-of-many Schnorr key selection

The HASH160 and raw-key scans take the same revealed key and
signature. The embedded-index baseline instead takes a signature
and an index, or just the signature for one embedded key. All
leaves check exactly one native Schnorr signature and leave true.

| Keys | Schedule | Leaf bytes | Data witness bytes | Complete witness bytes | Ordinary items | Hint items | Combined peak | Executed non-push ops | Initial budget | Charge |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | HASH160 scan | 35 | 99 | 169 | 2 | 0 | 6 | 10 | 219 | 50 |
| 1 | Raw-key scan | 40 | 99 | 174 | 2 | 0 | 5 | 5 | 224 | 50 |
| 1 | Embedded key | 35 | 66 | 136 | 1 | 0 | 2 | 1 | 186 | 50 |
| 4 | HASH160 scan | 107 | 99 | 241 | 2 | 0 | 6 | 19 | 291 | 50 |
| 4 | Raw-key scan | 148 | 99 | 282 | 2 | 0 | 5 | 14 | 332 | 50 |
| 4 | Embedded index | 145 | 68 | 248 | 1 | 1 | 6 | 10 | 298 | 50 |
| 32 | HASH160 scan | 779 | 99 | 915 | 2 | 0 | 6 | 103 | 965 | 50 |
| 32 | Raw-key scan | 1,156 | 99 | 1,292 | 2 | 0 | 5 | 98 | 1,342 | 50 |
| 32 | Embedded index | 1,085 | 68 | 1,190 | 1 | 1 | 34 | 25 | 1,240 | 50 |
| 129 | HASH160 scan | 3,107 | 99 | 3,243 | 2 | 0 | 6 | 394 | 3,293 | 50 |
| 129 | Raw-key scan | 4,648 | 99 | 4,784 | 2 | 0 | 5 | 389 | 4,834 | 50 |
| 129 | Embedded index | 4,335 | 69 | 4,441 | 1 | 1 | 131 | 73 | 4,491 | 50 |

All data and hints coexist at entry. Data witness includes its
item count and lengths. Complete witness additionally includes
the measured leaf and the 33-byte depth-zero control block, with
no annex. The index hint costs two serialized bytes at widths
four and 32, and three at width 129. Executed counts exclude pushes.
All leaves use policy `ALL` and the exact signed synthetic
transaction context. Each initial budget is 50 plus complete
witness size.

The direct embedded key wins for a singleton. At width 129, the
HASH160 scan saves 1,198 complete witness bytes against the
indexed baseline and uses 125 fewer live items. It executes 321
more non-push operations. See the
[implementation snapshots](../../src/signatures/hash_keyset/README.md#script-metrics).
Evidence is `locally-reproduced`. Execution is `unclassified`.
