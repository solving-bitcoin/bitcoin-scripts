# Sparse signature hints lose at a higher selected fraction

The indexed 4-of-16 leaf cuts serialized entry data from 273 to 268 bytes,
but its script grows from 546 to 635 bytes. Complete witness size grows
from 856 to 940 bytes. Peak increases from 17 to 28 and executed non-push
operations from 17 to 77. Both leaves charge 200 signature-budget units.
The dense witness has 16 ordinary items and zero hints; the indexed witness
has four ordinary signatures and four hints.

At 2 of 64, the indexed complete witness is 40 bytes smaller, while
combined peak still grows from 65 to 72. Both leaves charge 100 units.
These are exact comparisons for two deterministic signed fixture sets,
with all witness items at entry and no annex or unrelated caller state.
The execution class is `unclassified`. See the
[complete cost boundary](../primitives/sparse-tapscript-threshold.md#matched-signed-leaves).
