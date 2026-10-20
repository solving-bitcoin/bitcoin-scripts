# Casting-out residues and delayed reduction

## Research question and hypothesis

Modular folds over nibbles and bytes can reduce after every addition or keep the
sum exact and reduce once. Does delaying the reduction save script bytes, and
how does it extend to the 2^k - 1 family (`16 = 1` mod 15, `256 = 1` mod 255,
`65,536 = 1` mod 65,535)? The hypothesis is that a short ladder of conditional
subtractions at the end costs far less than one conditional per element, so
the existing modulo-17 fold (which normalizes at every step) is improvable.
This is a new local construction; no global novelty claim is made for casting
out nines or fifteens.

## Contract and proof

- `u4::mod15::u4_nibbles_to_mod15(n)` (running) and `u4_nibbles_to_mod15_ladder(n)`
  (delayed): `preserved | x[0..n-1] -> preserved | r`, `r` the base-16 integer
  modulo 15 in `0..=14`, `1 <= n <= 997`. Because `16 = 1`, `r` is the digit sum
  modulo 15 and ignores digit order.
- `u4::mod17::u4_nibbles_to_mod17_delayed(n)`: the same residue as the existing
  `u4_nibbles_to_mod17`. The alternating sum (`16 = -1`) is left exact, negated
  for even `n`, shifted by one public offset into `0..=2*offset` and reduced by
  subtracting `17 * 2^k` when it fits, for `k` from the top level down.
- `u32::mersenne_residue::{u32_mod255, u32_mod65535}`: `preserved | b0 b1 b2 b3 ->
  preserved | r`. Sums of bytes (at most 1,020) or 16-bit lanes (at most
  131,070) are reduced by ladders of `1020, 510, 255` and `131070, 65535`.

A ladder with thresholds `m * 2^k` for `k = K..0` reduces any `S < m * 2^(K+1)`
to `0..m-1`: after the step for level `k` the value is below `m * 2^k`. Every
bound used (`15n`, `15 * ceil(n/2)` plus the offset, 1,020, 131,070) is far
inside the four-byte ScriptNum domain.

## Threat model and evidence

All inputs are hostile and checked for range and minimal encoding. Tests cover:
every one-to-three-digit vector for both mod-15 schedules and the delayed
mod-17; lengths up to 128 with all-F, all-zero and seeded random vectors against
conventional base-16 evaluation; all 8^4 combinations of byte boundary values
(and a rejected off-by-one expected residue) for modulo 255; all 64 lane
boundary pairs for modulo 65,535 plus 300 random words; non-canonical and
out-of-range limbs (`-1`, 16, 256, `[1,0]`, `[0x80]`) at every position; preserved
main/alt state; generation bounds; and an exact stack frontier for both mod-15
schedules. The mod-15 residue cannot see transpositions (`0x12` and `0x21`
collide), so it is arithmetic casting-out, not an integrity check. Evidence is
`locally-reproduced`; execution is `unclassified`; no Bitcoin Core validation
is claimed and the model is ordinary Rust.

## Measured comparison

Boundary: the policy-compiled fragment; input pushes and terminal predicate
excluded; zero hints, tables or setup. Sizes pinned by
`mod15::tests::recorded_sizes_are_current`.

| n | mod 15 running | mod 15 ladder | mod 17 running | mod 17 delayed |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 74 | 71 | 82 | 80 |
| 16 | 302 | 235 | 334 | 259 |
| 32 | 606 | 438 | 670 | 467 |
| 64 | 1,214 | 833 | 1,342 | 894 |
| 128 | 2,430 | 1,612 | 2,686 | 1,737 |

At 64 nibbles delayed reduction is 31% smaller for mod 15 and 33% smaller for
mod 17; at the 997-nibble limit mod 17 falls from 20,926 to 13,066 bytes (38%).
The delayed form loses only below four nibbles (one nibble: 31 versus 10 bytes
for mod 17). Peaks are unchanged (`n + 3`). The u32 byte-sum residues cost 87
(mod 255) and 115 (mod 65,535) script bytes against 100 for mod 65,537.

## Reproduction

```sh
cargo test --locked arithmetic::u4::mod15::tests arithmetic::u4::mod17 --lib
cargo test --locked --lib arithmetic::u32::mersenne_residue
cargo test --locked --test primitive_metrics casting_out_residue_metrics_are_current -- --exact
python3 tools/kb.py validate
```
