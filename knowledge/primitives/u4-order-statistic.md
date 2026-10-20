# k-th smallest nibble: claim check and pairwise selector

## Research question and hypothesis

Can the `k`-th smallest nibble (for example the lower median) of a hostile u4
vector be certified cheaply, and what does it cost to select it without a hint?
The hypothesis is that a witness-claimed value is checkable with two linear
counting passes, whereas hint-free selection by pairwise ranking is quadratic and
loses to a sorting network. This is a new local construction; no global novelty
claim is made for rank verification.

## Contract and proof

`arithmetic::u4::order_statistic`, `1 <= k <= n`:

- `u4_nibbles_kth_smallest_hinted(n, k)`, `n <= 996`:
  `preserved | a[0..n-1] | claim -> preserved | claim`, aborting unless the claim
  is the `k`-th smallest. With `L = #{a < claim}` and `U = #{a <= claim}` the claim
  is the `k`-th smallest exactly when `L < k <= U` (its sorted positions are
  `L+1..U`), which also forces it to occur in the vector. `k = (n + 1) / 2` is the
  lower median. The claim is range-checked, so a value outside `0..=15` aborts.
- `u4_nibbles_kth_smallest(n, k)`, `n <= 32`: `preserved | a[0..n-1] -> preserved |
  value`. For each element it computes `L` and `U` against all elements and keeps,
  with `OP_MAX`, the elements whose interval contains `k`; they all equal the
  answer.

## Threat model and evidence

All nibbles and the claim are hostile. Tests cover: every vector over a
three-symbol alphabet for `n = 1..=5` and every `k`, for the selector against a
sorted-vector model and for the verifier against every claim `0..=15` (accepted
exactly when it is the `k`-th smallest); deterministic vectors of 8, 9 and 16
nibbles at the minimum, median and maximum ranks; a vector where the plurality
value is the median but the second-most-common value, an absent value and the
median's neighbour are all rejected; `-1`, 16 and 255 as claims and as vector
entries at every position; preserved main/alt state; generation bounds; and an
exact stack frontier for the verifier. Evidence is `locally-reproduced`;
execution is `unclassified`; no Bitcoin Core validation is claimed.

## Measured comparison

Boundary: the policy-compiled fragment; input pushes and terminal predicate
excluded. Sizes pinned by `order_statistic::tests::recorded_sizes_are_current`.

| n (k = lower median) | Claim check (1 hint) | Pairwise selector (0 hints) |
| ---: | ---: | ---: |
| 4 | 88 | 286 |
| 8 | 162 | 956 |
| 16 | 312 | 3,512 |
| 32 | 656 | 14,223 |

At 16 nibbles the claim check costs 312 script bytes with a 35-byte, 17-item
witness (one hint) and a 20-item peak; the selector costs 3,512 bytes with a
33-byte witness and a 22-item peak. The selector is quadratic (14,223 bytes at 32)
and is dominated by a sorting network: the open sorting PR reports a zero-hint
min/max selection network at 3,044 script bytes plus 63 witness bytes for 32
inputs (reported there, not reproduced here), about a quarter of the pairwise
selector.

## Reproduction

```sh
cargo test --locked arithmetic::u4::order_statistic::tests --lib
cargo test --locked --test primitive_metrics u4_order_statistic_metrics_are_current -- --exact
python3 tools/kb.py validate
```
