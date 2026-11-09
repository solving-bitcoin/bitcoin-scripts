# Witness-data size shortcuts and boundaries

The short-prefix shortcut has a sharp upper cap. For two data items the
fixed overhead is three bytes. With lengths 253 and zero, counting one
length-prefix byte per item gives a false total of 256. The actual
serialization is 258 bytes. A deliberately weakened leaf passes that
witness at cap 256. The exact checks reject at 256 and 257 and accept at
258. At cap 255 the tight schedule correctly accepts a 252-byte item and
an empty item and rejects the 253-byte case.

Branch-free exact accounting saves one script byte per item against the
conditional branch. With 32 short items at cap 286, it costs 306 executed
non-push operations versus 274. Both have peak 36 and 161 serialized data
bytes. This is a script-bytes and operation-count tradeoff.

A standalone data count cannot stand in for a complete witness count.
For example, 251 empty data items serialize as 252 bytes as a separate
vector. Adding a leaf and control block raises the full item count to 253
and changes its count prefix from one to three bytes, before accounting
for the two extra lengths and payloads. A witness annex or other stack
data also lies beyond this suffix cap. The implementation intentionally
keeps the data and full-witness boundaries separate.

The exact route needs one more temporary item. A 997-item standalone
suffix fits the tight route and exceeds the exact route's 1,000-item
bound. See the [measurements and reproduction](../../src/support/witness_data_size/README.md).
Evidence is `locally-reproduced` and execution is `unclassified`.
