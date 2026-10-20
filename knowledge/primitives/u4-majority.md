# Checked u4 strict majority

## Research question and hypothesis

Can the strict-majority nibble (one occurring in more than half the positions)
of a hostile u4 vector be decided, including the answer "none", with no hints and
far less script than comparing sixteen per-symbol counts, and what does a
witness-claimed majority save? The hypothesis is that a Boyer-Moore vote plus one
verification count costs a few dozen bytes per element, and that a claim check
is cheaper still but can only verify, not refute. This is a new local construction;
no global novelty claim is made for the Boyer-Moore algorithm.

## Contract and proof

`arithmetic::u4::majority`, `1 <= n <= 996`:

- `u4_nibbles_majority(n)`: `preserved | a[0..n-1] -> preserved | m`, where `m` is
  the strict-majority nibble or `-1` when none exists (an exact tie has none).
- `u4_nibbles_majority_hinted(n)`: `preserved | a[0..n-1] | claim -> preserved | claim`,
  aborting unless the claim is in `0..=15` and occurs more than `n/2` times.

The hint-free form keeps a candidate and a counter. For each element in order a
zero counter adopts the element with counter one; otherwise a match adds one and
a mismatch subtracts one. If a strict majority exists it survives (every non-
majority element can be paired off against a distinct majority element), but the
survivor of a vector without one is arbitrary, so a second pass counts the
candidate and accepts only if twice the count exceeds `n`. All counts are at
most 996, far inside the four-byte ScriptNum domain.

## Threat model and evidence

Every nibble and the claim are hostile and range-checked. Tests cover: all
`3^n` vectors over the alphabet `{0, 5, 10}` for `n = 1..=7` against a Rust
model (including every tie and every Boyer-Moore survivor that is not a
majority, such as `[1, 1, 2, 2, 3]`); late-flipping candidates; 160 seeded
random vectors of length 6 to 33; out-of-range nibbles (`-1`, `16`, `255`) at every
position; preserved main/alt state; generation bounds; and an exact stack
frontier (accepted with a 1,000-item peak and rejected with `StackSize` one item
over) for both forms. For the claim check, all vectors of length 1 to 6 over the
same alphabet with claims 0, 5, 10, 7 (accepted exactly when the claim is the
majority), out-of-range claims, and the fact that no claim is accepted for a
tied vector. Evidence is `locally-reproduced`; execution is `unclassified`; no
Bitcoin Core validation is claimed, and the model is ordinary Rust.

## Measured comparison

Boundary: the policy-compiled fragment; input pushes and terminal predicate
excluded. Sizes pinned by `majority::tests::recorded_sizes_are_current`.

| n | Hint-free | Claim check (1 hint) | 16 symbol counts (lower bound) |
| ---: | ---: | ---: | ---: |
| 4 | 130 | 62 | 1,072 |
| 16 | 486 | 213 | 4,256 |
| 64 | 2,046 | 910 | 18,448 |

At 16 nibbles the hint-free decision costs 486 script bytes with 32 witness bytes
over 16 items (peak 20); the claim check 213 bytes with 34 witness bytes over 17
items (peak 20, one hint item). The hint-free decision is 8.8 times smaller than
sixteen `u4_nibbles_count` calls, whose total excludes the vector copies and the
comparison of sixteen counts against `n/2`; that lower bound is an estimate, not a
built comparator. The claim check costs about 13 bytes per element against about
30, but it cannot report that no majority exists.

## Reproduction

```sh
cargo test --locked arithmetic::u4::majority::tests --lib
cargo test --locked --test primitive_metrics u4_majority_metrics_are_current -- --exact
python3 tools/kb.py validate
```
