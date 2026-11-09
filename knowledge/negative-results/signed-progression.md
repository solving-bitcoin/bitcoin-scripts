# Numeric equality cannot reparse a wide cross-sum

The three identical inputs `2147483647` form a valid progression.
Both cross-sums are `4294967294` and require five bytes. A local
mutation that uses `OP_NUMEQUALVERIFY` on those results fails.
The matched [cross-sum schedule](../comparisons/signed-progression.md)
uses raw equality on canonical arithmetic outputs and accepts.
The carried schedule also accepts this witness.

For this three-input fixture, the checked cross-sum schedule uses
24 leaf bytes and 19 executed non-push operations. Carrying a step
uses 25 bytes and 20 operations with the same witness and stack peak.
The matched comparison records the opposite result at wider widths.

An invalid sequence can produce a wide difference even though every
valid three-or-longer sequence has a step fitting in four bytes.
Validating each input width and comparing intermediate encodings
avoids a second numeric parse. See the
[tests and measurements](../../src/arithmetic/progression/README.md).
Evidence is `locally-reproduced` and execution is `unclassified`.
