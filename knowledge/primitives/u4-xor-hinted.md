# Parity-hinted XOR reduction

## Research question and hypothesis

XOR is bitwise parity, but Script has no bitwise opcodes, so the repository's XOR
reduction walks a resident 256-entry table (about 24 script bytes per nibble plus a
380-byte fixed table cost and a 256-item stack peak). Can an XOR be verified from a
claimed result using exact integer arithmetic? The hypothesis is that per-bit counts
packed in non-carrying lanes, plus a claimed half-count per lane, check the parity
of every bit at once without the table. This is a new local construction; no global
novelty claim is made for lane packing or parity certificates.

## Contract and proof

`arithmetic::u4::xor_hinted::u4_nibbles_xor_hinted(n)`, `1 <= n <= 212`:

```text
witness: x[0..n-1] | y | h0 h1 h2 h3     ->     y
```

Let `B = n + 2` and `T[v] = sum_{b<4} bit_b(v) * B^b`. The script range-checks every
`h_b` to `0..=n/2` and every nibble and `y` to `0..=15`, then requires
`S = sum_i T[x_i]` to equal `T[y] + 2 * H` where `H = sum_b h_b * B^b`. Lane `b` of
`S` is `c_b`, the number of nibbles with bit `b` set, at most `n < B`. Lane `b` of the
right side is `y_b + 2 h_b <= 1 + n < B`. Both sides are therefore base-`B`
numbers with every digit below `B`, so equal integers have equal digits:
`c_b = y_b + 2 h_b`, i.e. `y_b` is `c_b mod 2`, the XOR bit. A forged `y` or `h`
cannot pass, and the honest pair is unique. All sums are below `2^31` for
`n <= 212`, where `n * (B^4 - 1) / (B - 1)` stays inside the four-byte domain.

## Threat model and evidence

Nibbles, the claim and the lane halves are hostile. Tests cover: honest hints for every
vector of one to three nibbles; an **exhaustive hint search** over `y` in `-1..=16` and
all four half-counts in `-1..=3` (11,250 candidate tuples) for the vectors `[9, 5]`,
`[15, 15, 15]`, `[0, 0]` and `[3, 12, 6, 6]`, where exactly one tuple, the honest
one, verifies; seeded vectors up to 212 nibbles against the table reduction, and
the all-fifteen worst case; out-of-range nibbles, claims (`-1`, 16, 255) and
halves; preserved main/alt state; generation bounds; and a check that the
accumulator bound fits at the limit. Evidence is `locally-reproduced`; execution is
`unclassified`; no Bitcoin Core validation is claimed.

## Measured comparison

Boundary: the policy-compiled fragment; input pushes and terminal predicate
excluded. Sizes pinned by `xor_hinted::tests::recorded_sizes_are_current`.

| n | Table bytes | Table peak | Hinted bytes | Hinted peak | Totals (script + witness) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | 464 | 261 | 175 | 31 | 473 vs 192 |
| 16 | 740 | 273 | 367 | 43 | 772 vs 408 |
| 32 | 1,122 | 289 | 617 | 59 | 1,185 vs 689 |
| 64 | 1,890 | 321 | 1,087 | 91 | 2,015 vs 1,221 |
| 212 | 5,525 | 469 | 3,378 | 239 | 5,937 vs 3,799 |

The hinted form is 50% smaller on script at 16 nibbles and 42% at 64, with five hint
items and a combined peak six times lower at 16 nibbles (43 versus 273) because it
needs no resident table. Beyond 212 nibbles the single-word accumulator overflows and
a two-word lane split would be needed.

## Reproduction

```sh
cargo test --locked arithmetic::u4::xor_hinted::tests --lib
cargo test --locked --test primitive_metrics u4_xor_hinted_metrics_are_current -- --exact
python3 tools/kb.py validate
```
