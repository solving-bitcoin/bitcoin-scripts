# Hint-checked symbol histogram

## Research question and hypothesis

The repository counts one fixed symbol per pass (`u4_nibbles_count`), so a full
16-symbol histogram of a nibble vector costs sixteen passes, at least 4,256 script
bytes for 16 nibbles. Can a prover-supplied histogram be verified in one pass? The
hypothesis is that counts are exactly the digits of a base-`(n + 1)` number, so
packing the claimed counts and the vector's own symbol counts into a few lane words
and comparing the words verifies all 16 counts at once. This is a new local
construction built on the packed-histogram technique; no global novelty claim is made.

## Contract and proof

`arithmetic::u4::histogram::u4_nibbles_histogram_hinted(n)`, `1 <= n <= 962`:

```text
witness: x[0..n-1] | c[0..15]     (c[15] on top)   ->   c[0..15]
```

The script range-checks every `x[i]` to `0..=15` and every `c[s]` to `0..=n`. With
`B = n + 1`, symbol `s` adds `B^(s mod L)` to word `s div L` (the largest `L` with
`B^L <= 2^31`), and the claimed target word is `sum c[s] B^(s mod L)` built from the
hints with constant multiplications. Each lane count of the vector is at most `n`,
and each claimed `c[s]` is at most `n`, so both sides are numbers whose base-`B`
digits are below `B`: equal words mean equal digits, i.e. `c[s]` equals the number
of elements equal to `s`. A forged count or a count moved between symbols changes
some digit and fails. The counts are returned in order, the vector is consumed.

## Threat model and evidence

Nibbles and counts are hostile. Tests cover: honest histograms for 56 seeded vectors
(lengths 1, 2, 3, 8, 16, 33 and 64 over a full and a three-symbol alphabet), returned
in order; agreement with `u4_nibbles_count` for five symbols; every symbol's count
forged by +-1, +-2 and +-3; a count moved between two symbols; weight shifted between
every adjacent pair of lanes; **1,500 random count vectors** over `-1..=7` for a fixed
vector, accepted exactly when they equal the true histogram; out-of-range counts
(`-1`, `n + 1`, 255) and nibbles (`-1`, 16, 255) at every position; generation bounds;
and an exact stack frontier. Evidence is `locally-reproduced`; execution is
`unclassified`; no Bitcoin Core validation is claimed.

## Measured comparison

Boundary: the policy-compiled fragment; input pushes and terminal predicate excluded;
16 hint items (the counts). Sizes pinned by `histogram::tests::recorded_sizes_are_current`.

| n | Hinted histogram | 16 fixed-symbol counts (lower bound) |
| ---: | ---: | ---: |
| 4 | 432 | 1,072 |
| 16 | 956 | 4,256 |
| 64 | 3,158 | 18,448 |
| 128 | 5,988 | 37,424 |

At 64 nibbles the hinted histogram is 83% smaller than the lower bound for sixteen
counting passes (which also excludes the vector copies they would need), with a
102-item peak and 157 witness bytes over 80 items (16 hints). The baseline is an
estimate, not a built comparator.

## Reproduction

```sh
cargo test --locked arithmetic::u4::histogram::tests --lib
cargo test --locked --test primitive_metrics u4_histogram_metrics_are_current -- --exact
python3 tools/kb.py validate
```
