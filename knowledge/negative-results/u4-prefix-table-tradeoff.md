# NR-075: Removing prefix-scan memory does not always save bytes

Question: does conditional modulo normalization dominate a 31-item sum table
when both return every canonical prefix? No. Under the same staging/check/output
boundary, n32 measures661/35 versus664/66 script bytes/combined items; n128
measures2677/131 versus2584/162; n966 measures20275/969 versus20182/1000.
The table is smaller by 93 bytes in the latter two measured rows but needs 31
more live items. The singleton skips table allocation on both sides. The
conditional generator supports997 inputs while the table supports966.

This is a measured Pareto tradeoff, not an impossibility or global novelty
claim. Retaining every prefix moves table indices deeper; canonical checks,
setup, cleanup and output restoration are included equally. Runtime witnesses
contain n canonical sevens and zero hints, all data present at entry; serialized
bytes are65,257 and1935 for n32/128/966. Static non-push counts are distinct from
unavailable dynamic counts. Evidence `locally-reproduced`, execution
`unclassified`: strict local tapscript, no Core or relay transaction evidence.
See [the primitive](../primitives/u4-prefix-sum.md) and
[reproduction manifest](../../research/u4-prefix-reconstruction/README.md).
