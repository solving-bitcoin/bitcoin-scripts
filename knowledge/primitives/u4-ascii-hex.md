# Checked ASCII hexadecimal text to u4 nibbles

## Research question and hypothesis

Can hostile ASCII hexadecimal text, one ScriptNum per character, be converted
to u4 nibbles with no hints, rejecting every non-hex code, and at what text length
does a resident lookup table beat a table-free arithmetic fold? The hypothesis
is that the fold wins for short text and the table for digest-length text, with
the crossover moving with the accepted case set. This is a new local
construction; no global novelty claim is made for hex decoding itself.

## Contract and proof

`arithmetic::u4::ascii_hex::{ascii_hex_to_nibbles_fold, ascii_hex_to_nibbles_table}`
`(len, case)` with `case` in `Lower` (`0-9a-f`), `Upper` (`0-9A-F`) or `Either`:

```text
preserved | c[0] ... c[n-1]  ->  preserved | v[0] ... v[n-1]   (v[i] in 0..=15)
```

Any code outside the accepted set aborts the script. Order is preserved:
results are parked on the altstack and returned in the original order. Both
schedulers form `x = c - 48`.

- **Fold:** `x <= 9` is a digit; otherwise subtract 39 (`a-f`, `x` in 49..=54) or 7
  (`A-F`, `x` in 17..=22). Each branch range-checks its own result window
  (`0..=9` digits, `10..=15` letters), so gap codes such as `:` through `?` and
  `G`/`g` upward cannot alias a letter.
- **Table:** a resident 55-entry table (offset `x` in `0..=54`) stores the nibble or
  `-1`; each input is rolled in, range-checked against `0..55`, used as the
  `OP_PICK` index and its entry checked non-negative.

Both are exhaustively compared with a Rust model over every code in `-3..=300`
for all three cases. Extreme four-byte values are rejected: subtracting 48 from
`-(2^31 - 1)` leaves the four-byte operand domain and fails with a ScriptNum
overflow rather than `Verify`, still a rejection.

## Threat model and evidence

Every character is hostile and unrelated stack state is preserved (tested on
both stacks). A single bad character anywhere in a six-character batch aborts.
Nonminimal numeric encodings are accepted under a permissive local profile, as
for the other numeric u4 projections. The stack frontier is exact: the fold peaks
at `n + 3` (997 maximum) and the table at `n + 58` (942 maximum); each is
accepted at its maximum and rejected with `StackSize` when one more live item is
present. Evidence is `locally-reproduced`; execution is `unclassified` (strict
local tapscript with the stack limit enforced). No Bitcoin Core validation is
claimed and the model is ordinary Rust, not an independent Script interpreter.

## Measured comparison

Boundary: the policy-compiled fragment; input pushes, terminal predicate and
transaction framing excluded; zero hint items, all `n` data items present at entry.
The 64-character fixture (`0123456789abcdef` repeated, lowercase) has 64 data
items and 129 serialized witness bytes.

| Case | Chars | Fold bytes | Table bytes | Fold peak | Table peak |
| --- | ---: | ---: | ---: | ---: | ---: |
| Lower | 16 | 366 | 387 | 19 | 74 |
| Lower | 32 | 734 | 691 | 35 | 90 |
| Lower | 64 | 1,470 | 1,299 | 67 | 122 |
| Upper | 32 | 670 | 691 | 35 | 90 |
| Upper | 64 | 1,342 | 1,299 | 67 | 122 |
| Either | 8 | 270 | 235 | 11 | 66 |
| Either | 64 | 2,174 | 1,299 | 67 | 122 |

These sizes are pinned by `ascii_hex::tests::recorded_sizes_are_current`. The fold
costs about 23 bytes per lowercase character (33.9 for `Either`) and the table
about 19 plus 83 fixed, so the table wins above roughly 28 lowercase, 48
uppercase and 10 either-case characters. At digest-text length (64) the table is
12% smaller for lowercase and 40% smaller for either-case input, at the price
of 55 more combined stack items. Under a tight stack budget the fold remains
the only choice.

## Reproduction

```sh
cargo test --locked arithmetic::u4::ascii_hex::tests --lib
cargo test --locked --test primitive_metrics u4_ascii_hex_metrics_are_current -- --exact
python3 tools/kb.py validate
```
