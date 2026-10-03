# CRC-8/SMBus with nibble feedback

Catalog ID: `arithmetic/crc8-smbus`. Evidence: `locally-reproduced`.
Deployment: `unclassified`, separately for every measured configuration.
Implementation: [checksum module](../../src/arithmetic/checksums/crc8/mod.rs),
[README](../../src/arithmetic/checksums/crc8/README.md).

## Semantics and motivation

Compute CRC-8 with polynomial `x^8+x^2+x+1`, zero initial state, MSB-first
processing, no reflection and no final xor. The public byte-count constructor
admits 0..=406 complete bytes, represented by two hostile numeric nibbles each.
The first logical high nibble is on top; output is one canonical numeric CRC,
including canonical zero. This is noncryptographic error detection, not an
authentication or collision-resistant hash primitive.

Four-bit state `(H,L)` uses `T(H xor d)`, with T the sixteen polynomial
remainders of `i*x^8`. New state is `(L xor high(T), low(T))`. The implementation
reuses the existing 136-item triangular XOR table and sixteen offsets, adding
32 paired feedback entries. All inputs are numerically checked in 0..=15 before
indexing. No witness table, state or hint is trusted.

The private seed suggested fixed-distance feedback patterns. Coverage searches
found no existing CRC-8 record, not proof that this algorithm is new. The
[initial reproduction](../../research/crc8-nibble-feedback/README.md) preceded
production changes and is frozen at source
`0db90b9450d96a0bdf292d633fff14036bac2745`.

## Matched frontier

| Complete message | Feedback fragment / leaf | Serial bits fragment / leaf | Feedback / serial combined peak |
| --- | ---: | ---: | ---: |
| 1 byte | 414 / 419 | 285 / 290 | 190 / 15 |
| 2 bytes | 520 / 524 | 541 / 545 | 192 / 17 |
| 9 bytes, ASCII fixture | 1,262 / 1,267 | 2,333 / 2,338 | 206 / 31 |
| 16 bytes | 2,004 / 2,009 | 4,125 / 4,130 | 220 / 45 |

Both boundaries include numeric guards, all state/table setup, calculation,
canonical packing and cleanup. Leaf adds exact CRC comparison and TRUE equally.
Witnesses contain 2B ordinary numeric items, zero hints, all at entry; nine-byte
serialization is 37 fixture bytes, 91 maximum including four-byte numeric aliases.
The serial schedule wins at one byte, the table at two; neither dominates both
bytes and stack. Canonical-input compositions are separate measured families.

For numeric feedback, 306 bytes gives 32,744/32,749 with ALL, while 307 gives
32,851/32,856 with unoptimized NONE. At 406, 812 ordinary data items / zero
hints coexist with tables and temporaries at peak 1,000; fragment/leaf
43,345/43,349 are unoptimized NONE. Witness is 1,576 fixture / 4,063 maximum.
Serial accepts 493 complete bytes at peak 999, but is much larger. See
[NR-081](../negative-results/crc8-nibble-feedback.md).

Independent nine-byte calls retain all future input and each output: R=2 has
36 data / zero total and incremental hints, fragment/leaf 2,524/2,532, witness
71, peak 224; R=8 has 144 data / zero hints, 10,096/10,126, witness 280, peak
332. R=25 uses ALL, R=26 unoptimized NONE. R=45 has 810 ordinary entry items,
zero hints, peak 998, and permits only two caller items. R=46 fails StackSize
at measured peak 1,001. Component-policy deltas account for the whole-script
cutoff as well as optimizer rewrites. Exact fixtures, errors, hashes and both
leaf/fragment options are in [metrics.json](../../research/crc8-nibble-feedback/metrics.json).

## Contracts and evidence limits

Numeric aliases are accepted under the local Consensus profile, canonical CRC
output is mandatory, and byte-unique inputs remain a caller obligation. The
strict research siblings compose `verify_canonical_nibble`; their allowed
encoding cap is reported separately from an unknown maximum under a bound CRC.
Every family audits every malformed position and short prefix, asymmetric
ordering, every independent output, exact limits and runtime caller bytes on
both stacks. Actual compiled range/canonicality/terminal bypasses have valid
controls and are caught by the same typed assertions. The ordering mutant is
caught by the same exact-result assertion.

Exhaustive two-byte Script results and deterministic long fixtures agree with
an independent bitwise Python oracle and a Rust polynomial-division oracle.
Artifacts bind actual Cargo identities, immutable source, input/witness hashes,
final script/Tapleaf hashes, options and cost boundaries. Static counts do not
stand in for unknown executed counts or complete validation budgets. The local
Policy subset is not relay acceptance; no CRC fixture has Core consensus
validation. [OP-039](../open-problems.md#op-039--streamed-crc-8-frontier) retains
the wider input/byte Pareto question.

Primary references: [SMBus v3.1 section 6.4.1.3](https://smbus.org/specs/SMBus_3_1_20180319.pdf),
PDF SHA256 `ae22a791184fdd649c3101f70c3ce238c35b08c7f5b736458e740b903d1bf386`;
[Linux v6.18 generic CRC-8](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/lib/crc/crc8.c),
immutable commit `7d0a66e4bb9081d75c82ec4957c50034cb0ea449`, algorithm context only.
Neither Linux code nor its header's default initialization/complement convention
is substituted for the explicit profile measured here.
