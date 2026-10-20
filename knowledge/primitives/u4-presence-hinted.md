# Hint-checked presence bits

## Research question and hypothesis

The zero-hint presence projection scans the whole vector once per symbol, 16 * n
equality tests, and is the most expensive u4 projection per nibble in the repository
(95 script bytes per nibble at 16 nibbles). Can a prover-supplied set of flags be
verified with `n + 16` lookups instead? The hypothesis is that soundness needs only
two cheap checks: every actual nibble has its flag set, and every set flag is
witnessed by an index of an element equal to the symbol. This is a new local
construction; no global novelty claim is made.

## Contract and proof

`arithmetic::u4::presence_hinted::u4_nibbles_to_presence_bits_hinted(n)`, `1 <= n <= 964`:

```text
witness: x[0..n-1] | idx[0..15] | p[15] ... p[0]       (p[0] on top)
-> p[15] ... p[0]    with p[s] = 1 iff symbol s occurs in x
```

(a) For each element `x[i]`, the script range-checks it and requires `p[x[i]]` to
be truthy, so the true set is contained in the flagged set. (b) For each symbol `s`,
if `p[s]` is true the script requires `idx[s]` in `0..n` and `x[idx[s]] == s`, so the
flagged set is contained in the true set. Together the flags equal the presence
bits. Indices for cleared flags are never used. In tapscript the `OP_IF` of (b)
tests all 16 flags, so MINIMALIF aborts any flag other than the empty item and
`[1]` and the returned flags are canonical Booleans; outside tapscript that check
would need to be explicit. The output order is the reverse of the zero-hint form.

## Threat model and evidence

Nibbles, indices and flags are all hostile. Tests cover: honest witnesses for 180
seeded vectors (lengths 1, 2, 3, 7, 16 and 33 over a full and a three-symbol
alphabet), the all-sixteen and single-repeated-symbol cases, and agreement with the
zero-hint projection; for every absent symbol a forged set flag with every possible
index; for every present symbol a cleared flag; indices `-1`, `n` and 255 and an
index naming a different symbol; flag encodings `[2]`, `[1, 0]`, `[0x80]` and
`[0, 0]`; out-of-range nibbles `-1`, 16 and 255 at every position; generation
bounds; and an exact stack frontier. Evidence is `locally-reproduced`; execution is
`unclassified`; no Bitcoin Core validation is claimed.

## Measured comparison

Boundary: the policy-compiled fragment; input pushes and terminal predicate excluded.
Hinted witnesses carry 32 extra items (16 indices and 16 flags). Sizes pinned by
`presence_hinted::tests::recorded_sizes_are_current`.

| n | Zero-hint bytes | Hinted bytes | Zero-hint total | Hinted total (script + witness) |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 412 | 383 | 421 | 431 |
| 8 | 778 | 425 | 795 | 489 |
| 16 | 1,526 | 509 | 1,558 | 604 |
| 64 | 6,733 | 1,029 | 6,858 | 1,217 |
| 128 | 13,709 | 1,765 | 13,958 | 2,077 |

Totals count serialized witness bytes. The hinted form wins on script bytes at every
width from four nibbles and on script-plus-witness from about five; at 64 nibbles it
is 85% smaller on script and 82% smaller in total, with a 100-item peak against 82
and 96 witness items against 64 (32 of them hints).

## Reproduction

```sh
cargo test --locked arithmetic::u4::presence_hinted::tests --lib
cargo test --locked --test primitive_metrics u4_presence_hinted_metrics_are_current -- --exact
python3 tools/kb.py validate
```
