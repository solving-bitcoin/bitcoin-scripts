# Nibbles to ASCII hexadecimal text

## Research question and hypothesis

Decimal and hexadecimal text often has to be produced inside Script, for example
to compare a digest with its textual form or to emit a payload. What does it cost
to turn hostile nibbles into ASCII hexadecimal digits, and where does a resident
16-entry code table beat the branching arithmetic form? The hypothesis is that the
table wins after a handful of nibbles, as for the decoding direction. This is a
new local construction; no global novelty claim is made for hex encoding.

## Contract and proof

`arithmetic::u4::ascii_hex_encode`, `case` in `Lower` or `Upper`:

```text
preserved | v[0] ... v[n-1]  ->  preserved | c[0] ... c[n-1]     (c[i] = ASCII code of v[i])
```

- `u4_nibbles_to_ascii_hex_arith(n, case)`, `n <= 997`: range-check, then `v + 48`
  for `v <= 9` or `v + 87` (lower) / `v + 55` (upper) above 9, parked on the
  altstack and restored in order.
- `u4_nibbles_to_ascii_hex_table(n, case)`, `n <= 981`: a 16-entry table of codes
  is pushed once; each input is rolled in, range-checked and used as the `OP_PICK`
  index.

Both abort on a nibble outside `0..=15`, preserve unrelated stack state and use no
hints. The 16 codes agree with the standard formatter for both cases (tested).

## Threat model and evidence

Nibbles are hostile. Tests cover: all 16 nibbles for each scheduler and case, with a
wrong expected code rejected; an eight-nibble batch in order with preserved
main/alt state; `-1`, 16 and 255 at every position; nonminimal numeric encodings
under a permissive profile; generation bounds; and an exact stack frontier per
scheduler. Evidence is `locally-reproduced`; execution is `unclassified`; no
Bitcoin Core validation is claimed. The text is not authenticated and the output
order is the input order.

## Measured comparison

Boundary: the policy-compiled fragment; input pushes and terminal predicate
excluded; zero hints. Sizes (identical for both cases) pinned by
`ascii_hex_encode::tests::recorded_sizes_are_current`.

| n | Arithmetic bytes | Table bytes |
| ---: | ---: | ---: |
| 1 | 16 | 50 |
| 4 | 70 | 80 |
| 8 | 142 | 120 |
| 16 | 286 | 200 |
| 64 | 1,150 | 680 |

The arithmetic form costs about 18 bytes per nibble with no fixed cost; the table
form about 10 per nibble plus 40 fixed, so the table wins from about five nibbles
and is 41% smaller at 64 (peaks 83 versus 67 combined items, 125 witness bytes over
64 items). Encoding is cheaper than decoding hexadecimal text because it need not
reject unaccepted characters.

## Reproduction

```sh
cargo test --locked arithmetic::u4::ascii_hex_encode::tests --lib
cargo test --locked --test primitive_metrics u4_ascii_hex_encode_metrics_are_current -- --exact
python3 tools/kb.py validate
```
