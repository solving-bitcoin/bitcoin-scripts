# ScriptNum decimal expansion

## Research question and hypothesis

Decimal check-digit schemes (Damm, Luhn) consume one numeric digit per stack
item, but amounts are ScriptNums. What does it cost to bind a ScriptNum amount
to its decimal digits, hint-free or with digit hints, and what does that add to a
complete checksummed leaf? The hypothesis mirrors the radix-16 expansion: the
hint-checked Horner form is several times cheaper than a compare-and-subtract
ladder even after counting the hint bytes. This is a new local construction; no
global novelty claim is made.

## Contract and proof

`arithmetic::u4::scriptnum_decimal`, `1 <= width <= 10`, domain `0 <= x < 10^width`
(`x < 2^31` at width 10, the full non-negative four-byte range):

- `u4_scriptnum_to_decimal(width)`: `preserved | x -> preserved | d[0] ... d[width-1]`,
  numeric digits `0..=9`, most significant first, no hints. For each place from
  the top it compares `x` with `8, 4, 2, 1` times the place value and subtracts;
  within the domain the quotient digit is at most nine, so the greedy binary
  expansion yields a valid digit. Weights that cannot occur below the domain are
  omitted at width 10.
- `u4_scriptnum_to_decimal_hinted(width)`: `preserved | d[0..width-1] | x ->
  preserved | d[0..width-1]`. Each hint is range-checked to `0..=9` and the
  amount is checked in its domain, and the Horner sum (multiplying by ten with `mul_by_constant(10)`) must numerically equal `x`,
  which is unique among in-range digits, so a carry-compensated hint cannot pass.

## Threat model and evidence

`x` and every hint are hostile. Tests cover: every `x` for widths 1 to 3;
boundary values (0, 1, 9, 10, 99, domain minus one, half and tenth of the domain)
and 40 seeded random values for widths 4 to 10; values outside the domain or
negative, rejected with `Verify` or a ScriptNum overflow; for the hinted form every
single-hint ±1 perturbation and the aliases `[0, 10]` for 10 and `[10, -1]` for 99;
and complete leaves that feed both forms into the existing Damm fold (checked
against a provenance-commented copy of the pinned table) for five amounts, where
a forged digit hint is rejected. Evidence is `locally-reproduced`; execution is
`unclassified`; no Bitcoin Core validation is claimed, and the model is ordinary
Rust. This is arithmetic binding, not authentication of the amount's meaning.

## Measured comparison

Boundary: fragment-only for expansions; complete-leaf for compositions (expansion,
nine-digit Damm fold, state check, clean result). Input pushes, transaction
framing and leaf/control-block witness items excluded. Sizes pinned by
`scriptnum_decimal::tests::recorded_sizes_are_current`.

| Digits | Hint-free bytes | Hint-checked bytes |
| ---: | ---: | ---: |
| 1 | 50 | 14 |
| 4 | 223 | 66 |
| 9 | 582 | 153 |
| 10 | 616 | 165 |

Complete leaves for the amount `123456789` and Damm state 4: nine digit items
alone are 326 script bytes with a 19-byte, 9-item witness (the digits are not
bound to any amount); a single hint-free amount is 908 bytes with a 6-byte, 1-item
witness (914 bytes in total); an amount plus nine digit hints is 479 bytes with a
24-byte, 10-item witness (503 in total). The combined peak is 113 in all three, set
by the Damm table. Binding the amount costs 582 script bytes hint-free or 153
hint-checked on top of the digits-only leaf, so the hint-checked form is 1.82 times
smaller in total for the same binding.

## Reproduction

```sh
cargo test --locked arithmetic::u4::scriptnum_decimal::tests --lib
cargo test --locked --test primitive_metrics u4_scriptnum_decimal_metrics_are_current -- --exact
python3 tools/kb.py validate
```

The local execution uses the explicit `TapscriptProfile::Consensus` interpreter
profile with stack enforcement and without minimal-number enforcement; this is
not Bitcoin Core validation. Numeric aliases can pass, and the hinted fragment
returns hint bytes unchanged. Byte-sensitive consumers must canonicalize them.
The fragment returns digits and needs a terminal predicate and clean stack in a
complete leaf.

For width `w`, the hinted fragment has exactly `w` hint items and `w+1` data
items at entry, all coexisting. For zero-valued hints their separate serialized
vector has `w+1` bytes and incremental hint cost is `w` bytes; nonzero digits
1 through 9 each use two serialized bytes, so the width-9 fixture uses 18
incremental bytes (19 as a separate vector). The measured isolated combined
main-plus-alt peak is `w+4` for widths 1, 2, 4, 6, 8, 9 and 10. With `p`
otherwise-preserved items, composition requires `w+4+p <= 1000`; preloaded
batches must also account for all remaining witness items and their staging.
The hint-free variant has zero hint items.

For the nine-digit fixture the hint-free fragment has 301 static non-push
opcodes, above the 201 limit for legacy, P2SH and P2WSH. The hinted fragment
has 114; these observations alone do not establish script or relay validity.
