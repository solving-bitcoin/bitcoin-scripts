# Delayed-reduction modulo-16 nibble sum

## Research question and hypothesis

`u4_nibbles_to_sum_mod16` reduces a nibble sum with a resident 31-entry table
after every addition. Does keeping the sum exact and reducing once, with a short
ladder of conditional subtractions, beat it? The hypothesis is that the ladder
costs a handful of comparisons for the whole batch, whereas the table costs a
roll, an altstack round trip and a lookup per nibble plus 31 resident items. This
is a new local construction; no global novelty claim is made for delayed
reduction.

## Contract and proof

`arithmetic::u4::sum_ladder::u4_nibbles_to_sum_mod16_ladder(n)`, `1 <= n <= 997`:

```text
preserved | x[0] ... x[n-1]  ->  preserved | (sum x[i]) mod 16     (0..=15)
```

Each nibble is checked for range and minimal encoding and added to the running
exact sum, which is at most `15n`. A ladder subtracts `16 * 2^k` when it fits,
for `k` from the top level (the largest with `16 * 2^k <= 15n`) down to zero; any
sum below `16 * 2^(top+1)` ends in `0..=15`. The fragment never touches the
altstack, keeps no table and has combined peak `n + 3`. All values are far inside
the four-byte ScriptNum domain. The sum is order independent, so the output
does not depend on digit order.

## Threat model and evidence

All nibbles are hostile. Tests cover: every nibble vector of length 1 to 3
against a Rust model; all-F, all-zero and seeded random vectors of lengths up to
128; agreement with the table schedule on identical vectors; `-1`, 16, 255, the
aliases `[1, 0]`, `[0x80]` and `[0, 0]` at every position; preserved main/alt
state; generation bounds; and an exact stack frontier at 997 nibbles. Evidence is
`locally-reproduced`; execution is `unclassified`; no Bitcoin Core validation is
claimed, and the model is ordinary Rust.

## Measured comparison

Boundary: the policy-compiled fragment; input pushes and terminal predicate
excluded; zero hints; all `n` nibbles coexist at entry. Sizes pinned by
`sum_ladder::tests::recorded_sizes_are_current`.

| n | Table bytes | Table peak | Ladder bytes | Ladder peak |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 65 | 35 | 10 | 4 |
| 8 | 184 | 42 | 119 | 11 |
| 32 | 592 | 66 | 429 | 35 |
| 128 | 2,224 | 162 | 1,603 | 131 |

The ladder is smaller at every length: 28% at 32 nibbles, 28% at 128 and 29% at
the table version's 965 limit (16,453 versus 11,680 bytes), with a peak 31 items
lower. The batch limit also rises from 965 to 997.

## Reproduction

```sh
cargo test --locked arithmetic::u4::sum_ladder::tests --lib
cargo test --locked --test primitive_metrics u4_sum_ladder_metrics_are_current -- --exact
python3 tools/kb.py validate
```
