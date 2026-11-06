# Checked XOR reduction with signed packed lanes

Can a carry-separated bit-count representation derive the XOR of hostile
canonical nibbles with zero hints and less live state than pairwise XOR
tables? Compare packed-lane decoding with the existing full-table
schedule and a triangular schedule that reuses the CRC-8 helpers. The
hypothesis is that a 16-item projection table saves stack space and
amortizes its final parity extraction at larger widths.

## Construction

XOR is parity in each bit position, as described for byte addition in
[FIPS 197 updated edition, section 4.1](https://doi.org/10.6028/NIST.FIPS.197-upd1).
The packed contribution for nibble `x` is
`sum_j bit_j(x) * B^j`, using a power of two `B > n` for `n` inputs.
Each lane holds an exact count until the final parity decode. Above
127 inputs, `B = 256` and the highest lane starts at `-floor(n/2)`.
The highest signed count stays in `-127..=127` through width 254.
The lower three lanes contribute a nonnegative value less than `2^24`,
and every partial accumulation lies between the initial and final
values. A negative final value is translated by `2^31` in two safe
additions. This leaves bits 0, 8, 16 and 24 unchanged, and the output
corrects the top parity for an odd initial bias.

The related [PR #285](https://github.com/solving-bitcoin/bitcoin-scripts/pull/285),
revision `8710b57bcb3c0a1f7f98ca93dad3329012f2dfcf`, independently
uses packed bit counts with base `n+2` and verifies a claimed XOR and
four half-counts. Its reported 212-input range and five hints describe
that certificate. This experiment reuses the packing idea, uses signed
power-of-two lanes to support 254 inputs, and derives all four output
bits from the input data without any certificate. Its zero-hint
comparators derive the same output using pairwise lookups.

## Evidence and limits

At width 254 the packed leaf uses 4,536 bytes, 2,958 executed non-push
operations, and a 274-item combined peak. The triangular leaf uses
7,058 bytes, 4,895 operations, and peak 408. The full-table leaf uses
7,086 bytes, 5,453 operations, and peak 511. Every row uses the same
490-byte data witness with 254 ordinary items and zero hints. These
leaves include the same canonical guard and output equality. The
[comparison](../comparisons/arithmetic.md#checked-nibble-xor-reduction)
includes the smaller widths and the limit of the comparison to the
hinted certificate.

All inputs are canonical ScriptNums and coexist at entry. No hints are
supplied. Both caller stacks are preserved for an exact suffix. XOR can
collide under same-parity changes and permutations. The measured leaf
checks its exact output, and the fragment does not authenticate a message.

Evidence is `locally-reproduced`; execution is `unclassified`. The
[implementation README](../../src/arithmetic/u4/xor_lanes/README.md)
gives exact matched costs and reproduction commands.
