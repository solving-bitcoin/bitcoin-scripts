# ScriptNum radix-16 expansion

## Research question and hypothesis

Packing nibbles into a ScriptNum is cheap (see the quad and triplet packers);
the inverse needs division, which Script lacks. Can one non-negative ScriptNum
be expanded to big-endian u4 nibbles with no hints, and is that worth its
script cost against a hint-checked expansion? The hypothesis is that a
compare-and-subtract ladder works but loses to Horner verification of witness
nibbles even after counting the extra witness bytes. This is a new local
construction; no global novelty claim is made for either elementary method.

## Contract and proof

`arithmetic::u4::scriptnum_nibbles`, `1 <= width <= 8`, domain `0 <= x < 16^width`
(`x < 2^31` at width 8, the full non-negative four-byte range):

- `u4_scriptnum_to_nibbles(width)`: `preserved | x -> preserved | d[0] ... d[width-1]`,
  `d[0]` most significant, no hints. For each place from the top it compares
  `x` with `8, 4, 2, 1` times the place value, subtracting and adding the
  matching weight to the nibble when it fits. Greedy binary expansion is exact,
  so the remainder is zero at the end; the weight-8 comparison of the top nibble
  is omitted at width 8 because `8 * 16^7 = 2^31` is not a four-byte operand.
- `u4_scriptnum_to_nibbles_hinted(width)`: `preserved | d[0..width-1] | x ->
  preserved | d[0..width-1]`. Each hint is range-checked to `0..=15` and the Horner
  sum must equal `x`. The sum is unique among in-range digits, so a wrong or
  carry-compensated hint cannot satisfy both checks.

## Threat model and evidence

`x` and any hints are hostile. Tests cover: every `x` for widths 1 to 3; boundary
and deterministic values for widths 4 to 8 (0, 1, 15, 16, domain minus one and
half-domain neighbours, and 40 seeded random values each); values below zero or
at or above the domain, which abort with `Verify` (or with a ScriptNum overflow
when the value leaves the four-byte operand domain); a five-byte number;
preserved main/alt state; and for the hinted form every single-hint ±1
perturbation, the carry-compensated aliases `[0, 16]` for 16 and `[16, -1]` for
255, and an over-range width-8 hint set. Evidence is `locally-reproduced`;
execution is `unclassified` (strict local tapscript, stack limit enforced); no
Bitcoin Core validation is claimed, and the model is ordinary Rust.

## Measured comparison

Boundary: the policy-compiled fragment; the number (and hints) are the only
witness items; terminal predicate excluded. All sizes pinned by
`scriptnum_nibbles::tests::recorded_sizes_are_current`. Fixture `0xBEEF` (4 nibbles).

| Width | Hint-free bytes | Hint-checked bytes |
| ---: | ---: | ---: |
| 1 | 50 | 9 |
| 2 | 105 | 24 |
| 4 | 230 | 59 |
| 6 | 371 | 93 |
| 8 | 501 | 127 |

At width 4 the hint-free form uses 230 script bytes plus 5 witness bytes over 1
item (peak 7), the hint-checked form 59 plus 13 over 5 items (peak 8), so the
hint-checked total of 72 bytes is 3.3 times smaller than 235 despite four hint
items. The hint-free ladder costs about 57 bytes per nibble against about 17.
Hint-free expansion is therefore justified only when a protocol forbids prover
supplied nibbles or must stay within a fixed witness shape.

## Reproduction

```sh
cargo test --locked arithmetic::u4::scriptnum_nibbles::tests --lib
cargo test --locked --test primitive_metrics u4_scriptnum_nibbles_metrics_are_current -- --exact
python3 tools/kb.py validate
```
