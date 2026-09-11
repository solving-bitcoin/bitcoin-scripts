# u4 nibble popcount

This primitive counts set bits in a batch of four-bit Script limbs. The
representative `popcount(8)` consumes eight checked nibbles and returns one
Script integer in `0..=32`.

## Research boundary

The fragment includes its generated 16-item lookup table, numeric range checks,
eight lookups, temporary altstack accumulation, and table cleanup. It excludes
witness pushes, the terminal predicate, and transaction framing. For the
representative fixture the locking fragment is 135 bytes, the complete
eight-item numeric witness is 17 serialized bytes, the combined strict local
peak is 27 items, and no auxiliary hints are used. The local tapscript
executor reports `opcode_count=0`; that is an unavailable measurement, not a
consensus budget.

## Comparison

The closest existing construction decomposes eight checked nibbles into 32
bits and then sums those bits. On the same fragment boundary its measured
script is 331 bytes and its standalone peak is 93 items. Popcount therefore
saves 196 script bytes and 66 stack items when only the Hamming weight is
needed; it does not return the individual bits.

## Security and limits

Inputs are hostile and are checked before they address the table. The numeric
check accepts any ScriptNum encoding with value 0 through 15; callers needing
byte-unique witness encodings must add canonical-encoding checks. This is an
arithmetic fragment, not a complete locking script, and it has no independent
cryptographic security claim or Bitcoin Core deployment validation.

See the [implementation README](../../src/arithmetic/u4/README.md) and the
catalog record `arithmetic/u4-popcount`. The reproducible research protocol is
in [research/u4-popcount](../../research/u4-popcount/README.md).
