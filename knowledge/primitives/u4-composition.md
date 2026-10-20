# Fixed-composition check of a u4 vector

## Research question and hypothesis

Can a hostile u4 vector be checked, with no hints, for having exactly a public
multiset of nibbles (a fixed composition), and how does that compare with
pairwise distinctness when the composition is "one of each" (a permutation)? The
hypothesis is that packing the symbol counts into a few base-`n + 1` lanes makes
the check cost one table lookup per word per nibble, below sixteen per-symbol
counts and, for permutations, below the quadratic pairwise comparison. This is
a one-sided variant of the packed-histogram technique used for multiset
equality; no global novelty claim is made.

## Contract and proof

`arithmetic::u4::composition::u4_nibbles_have_composition(&counts)`, with
`n = sum(counts)` in `1..=979`:

```text
preserved | a[0] ... a[n-1]  ->  preserved | ok      (ok in {0, 1})
```

`ok` is `1` iff nibble value `s` occurs exactly `counts[s]` times for every `s`.
With `B = n + 1`, symbol `s` adds `B^(s mod L)` to word `s div L`, where `L` is the
largest integer with `B^L <= 2^31`. Every word sum is below `B^L`, so it fits the
four-byte ScriptNum domain, and every lane count is at most `n < B`, so lanes
cannot carry and a word equals its public target exactly when each lane count does.
Unlike the two-vector multiset check there are no signed lanes, so the base is
`n + 1` rather than `2n + 1`. A nibble outside `0..=15` aborts before it indexes the
table; the first pass range-checks, later passes reuse the checked inputs.

## Threat model and evidence

All nibbles are hostile. Tests cover: all `4^5` arrangements over a four-symbol
alphabet against a counting model for a five-element composition; every
single-position corruption of a 16-nibble permutation and the all-equal vectors;
30 seeded shuffles accepted; adjacent-symbol exchanges and a 24-element
concentration (`[8; 24]` accepted, one flipped symbol rejected); `-1`, 16 and 255 at
every position; preserved main/alt state; generation bounds; lane geometry
checked against its defining inequalities; and an exact stack frontier at the
979-nibble maximum. Evidence is `locally-reproduced`; execution is
`unclassified`; no Bitcoin Core validation is claimed.

## Measured comparison

Boundary: the policy-compiled fragment; input pushes and terminal predicate
excluded; zero hints; all `n` nibbles coexist at entry. Sizes pinned by
`composition::tests::recorded_sizes_are_current`.

| Composition | Script bytes | Combined peak |
| --- | ---: | ---: |
| eight sevens (n = 8) | 279 | 29 |
| permutation of 0..=15 (n = 16) | 649 | 37 |
| each symbol twice (n = 32) | 1,172 | 53 |
| balanced (n = 64) | 2,817 | n/a |

For the 16-nibble permutation the pairwise comparator (`120` equality tests) costs
823 bytes with a 19-item peak, so the lane check is 21% smaller but uses 18 more
combined stack items. Sixteen fixed-symbol counts alone are a 4,256-byte lower
bound (an estimate, excluding vector copies and the comparisons), 6.6 times the
lane check, and 8,976 against 1,172 at 32 nibbles (7.7 times).

## Reproduction

```sh
cargo test --locked arithmetic::u4::composition::tests --lib
cargo test --locked --test primitive_metrics u4_composition_metrics_are_current -- --exact
python3 tools/kb.py validate
```
