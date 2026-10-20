# Checked u4 vector distances

## Research question and hypothesis

Can the Hamming, L1 and Lee distances between two hostile u4 vectors be
computed with no hints, and does fusing the XOR and popcount tables into one
256-entry Hamming table beat composing the existing XOR table with the
popcount table? The hypothesis is that the fused table removes one lookup per
pair and 16 resident items, while L1 and Lee need no table at all because
`OP_ABS`, `OP_MIN` and `OP_SUB` are native. This is a new local construction; no
global novelty claim is made for the metrics themselves.

## Contract and proof

`arithmetic::u4::distance`, all with the contract
`preserved | a[0..n-1] | b[0..n-1]  ->  preserved | distance` (last `b` on top):

- `u4_nibbles_l1_distance(n)`: `sum |a[i] - b[i]|`, table-free.
- `u4_nibbles_lee_distance(n)`: `sum min(|a[i] - b[i]|, 16 - |a[i] - b[i]|)`,
  table-free (distance on the cycle of 16).
- `u4_nibbles_hamming_distance(n)`: `sum popcount(a[i] ^ b[i])` through one fused
  256-entry table `T[16a + b]`.
- `u4_nibbles_hamming_distance_composed(n)`: the same value through the shared
  full XOR table followed by a 16-entry popcount table (the baseline).

Each fragment range-checks all `2n` nibbles into the altstack, restores them
(and, for the table forms, pushes the table beneath them), then rolls the pair
`(a[n-1-k], b[n-1-k])` into position, forms `16a + b` by four doublings where
a table is used, and accumulates. Distances are bounded by `4n` (Hamming),
`15n` (L1) and `8n` (Lee), far inside the four-byte ScriptNum domain.

## Threat model and evidence

All nibbles are hostile. Tests cover `-1`, `16` and `255` at every position of
both vectors, every one of the 256 nibble pairs for all four fragments (and a
deliberately wrong expected total is rejected), deterministic vectors of 2 to
24 nibbles, complementary extremes, preserved main/alt state, generation bounds,
and an exact stack frontier per fragment (accepted with a 1,000-item peak,
rejected with `StackSize` one item over). Evidence is `locally-reproduced`;
execution is `unclassified`; no Bitcoin Core validation is claimed, and the model
is ordinary Rust, not an independent Script interpreter.

## Measured comparison

Boundary: the policy-compiled fragment; input pushes and terminal predicate
excluded; zero hint items; all `2n` data items present at entry. Sizes pinned by
`distance::tests::recorded_sizes_are_current`.

| n | L1 | Lee | Hamming fused | Hamming composed |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 18 | 23 | 415 | 443 |
| 4 | 81 | 101 | 505 | 545 |
| 16 | 334 | 414 | 874 | 962 |
| 64 | 1,390 | 1,710 | 2,410 | 2,698 |

Peaks at 16 nibbles are 35 (L1, Lee), 290 (fused) and 306 (composed); the
witness is 63 bytes over 32 items. The fused table costs about 31.7 bytes per
pair against 35.8 composed and saves 6.3% at one nibble, 9.1% at 16 and 10.7% at
64, with 16 fewer resident items. The table-free metrics cost about 22 (L1) and
27 (Lee) bytes per pair with no resident table, so a Hamming bound is dearer
per pair than an L1 bound by roughly 1.5 times (1.2 for Lee) at 64 nibbles, plus
the fixed table cost of about 410 bytes.

## Reproduction

```sh
cargo test --locked arithmetic::u4::distance::tests --lib
cargo test --locked --test primitive_metrics u4_distance_metrics_are_current -- --exact
python3 tools/kb.py validate
```
