# Table-free Luhn checksum

## Research question and hypothesis

The repository has one decimal check-digit scheme, the Damm quasigroup fold with
a resident 100-entry table. Is a table-free Luhn mod-10 check cheaper in script
bytes and stack, and what does it give up in error detection? The hypothesis is
that Luhn's conditional doubling plus a delayed-reduction ladder costs well under
Damm's table and routing, but that Luhn keeps its textbook blind spot. This is a
new local construction; no global novelty claim is made for Luhn or Damm.

## Contract and proof

`arithmetic::u4::luhn::u4_decimal_digits_to_luhn(n)`, `1 <= n <= 997`:

```text
preserved | d[0] ... d[n-1]  ->  preserved | r        (r in 0..=9)
```

Digits are numeric decimal ScriptNums, leftmost first, last on top. Counting
from the rightmost digit at position 0, each odd position `p` contributes
`2d` (minus 9 if above 9) and each even position contributes `d`. The exact
sum is at most `9n`; a ladder subtracting `10 * 2^k` when it fits, for
`k` from the top level down, reduces any sum below `10 * 2^(top+1)` to `0..=9`.
The result is zero exactly for a valid Luhn code. All sums are far inside the
four-byte ScriptNum domain.

## Threat model and evidence

Every digit is hostile and range-checked in `0..=9` (numeric aliases are
accepted when the execution profile permits them, as for the Damm primitive).
Tests cover: every digit string of length 1 to 4 against a Rust model; the
published 11-digit example `79927398713`; seeded vectors up to 128 digits;
`-1`, 10, 15, 16 and 255 at every position; preserved main/alt state;
generation bounds; and an exact stack frontier at 997 digits.

Error detection is compared with the Damm quasigroup from Rust models only (the
shared table is the one the Damm primitive uses): over all 1,000 three-digit
messages with a computed check digit, neither scheme misses any of the 36,000
single-digit substitutions, but Luhn misses 60 of the 3,000 adjacent
transpositions, every one of them a swap of `0` and `9`, while Damm misses none.
Evidence is `locally-reproduced`; execution is `unclassified`; no Bitcoin Core
validation is claimed. This is an error-detecting checksum, not authentication.

## Measured comparison

Boundary: the policy-compiled fragment; input pushes and terminal predicate
excluded; zero hints; all `n` digits coexist at entry. Sizes pinned by
`luhn::tests::recorded_sizes_are_current`.

| Digits | Luhn bytes | Luhn peak | Damm bytes | Damm peak |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 5 | 4 | 172 | 105 |
| 8 | 115 | 11 | 305 | 112 |
| 32 | 411 | 35 | 766 | 136 |
| 128 | 1,537 | 131 | 2,686 | 232 |

Luhn costs about 13 bytes per digit with no fixed cost; Damm about 19 per digit
plus a 172-byte table setup. At 32 digits Luhn is 46% smaller and its peak is a
quarter of Damm's. The trade is detection: Luhn is not a drop-in replacement
where adjacent `09`/`90` swaps matter.

## Reproduction

```sh
cargo test --locked arithmetic::u4::luhn::tests --lib
cargo test --locked --test primitive_metrics u4_luhn_metrics_are_current -- --exact
python3 tools/kb.py validate
```
