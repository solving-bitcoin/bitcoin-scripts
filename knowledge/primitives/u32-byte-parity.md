# u32 byte parity projection

`u32_byte_parity()` consumes one four-byte u32 word and returns four numeric
parity bits, one per byte. The least-significant byte's parity is on top of the
output sequence.

## Research boundary

The fragment includes a generated 256-item parity table, four numeric byte
range checks, four lookups, table cleanup, and restoration of the four output
bits. It excludes witness pushes, terminal predicates, unrelated live state,
and transaction framing. No auxiliary hints are used.

## Comparison

The closest existing construction is `u32_popcount()`, which uses the same
table and input boundary but adds the four results into one count. This
projection keeps the four byte-local results, removing the accumulation tail
when downstream logic needs per-byte parity rather than a whole-word count.

## Security and execution

Inputs are hostile and are range-checked before table indexing. Numeric range
checking does not establish byte-unique ScriptNum encodings; callers needing
that property must add the canonical byte boundary. This is a locally
reproduced arithmetic fragment in the strict tapscript executor, with
deployment still `unclassified` and no independent cryptographic claim.

See the [implementation README](../../src/arithmetic/u32/README.md), the
[u32 overview](u32.md), and the catalog record `arithmetic/u32-byte-parity`.
