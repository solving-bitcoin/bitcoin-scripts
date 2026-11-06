# Packed XOR lane limits and collisions

Unsigned four-lane packing with base 256 can exceed the four-byte
positive ScriptNum arithmetic range at width 128. The all-15 witness
reaches a value above `2^31 - 1`, and a subsequent numeric operation
rejects the unsigned fixture. The signed construction handles it by
biasing the highest lane.

Width 255 does not fit this exact-count representation. All
`256^4 = 2^32` four-tuples of independent counts are attainable, because
the selected set of input positions for each bit can be chosen
independently. There are only `2^32 - 1` distinct canonical four-byte
ScriptNum values including zero. A single such value cannot encode all
exact count tuples injectively. A two-word or parity-only representation
has a different state contract.

The XOR relation is not an authentication check. The equal-length
vectors `[0, 0, 0, 0]` and `[3, 9, 3, 9]` both pass the XOR-zero leaf.
The measured packed route has peak `n + 20` for non-singleton widths,
including its resident 16-entry table. Width 254 with 726 preserved
caller items reaches the local limit; adding one fails.

See the [fixture and reproduction](../../src/arithmetic/u4/xor_lanes/README.md).
Evidence is `locally-reproduced` and execution is `unclassified`.
