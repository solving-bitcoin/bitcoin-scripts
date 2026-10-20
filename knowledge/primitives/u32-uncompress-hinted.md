# Hint-checked u32 expansion

## Research question and hypothesis

`u32_uncompress_canonical` recovers the four bytes of a compressed u32 with a
31-step compare-and-subtract bit ladder and costs 431 script bytes. Compression is
cheap (76 bytes) and is a bijection between four-byte words and signed ScriptNums.
Can a prover-supplied set of four bytes be verified by re-compressing them? The
hypothesis is that four byte-range checks, one `u32_compress` and one bytewise
comparison cost about a third of the ladder, at the price of four hint items. This is
a new local construction; no global novelty claim is made.

## Contract and proof

`arithmetic::u32::uncompress_hinted::u32_uncompress_hinted_canonical()`:

```text
preserved | b0 b1 b2 b3 x  ->  preserved | b0 b1 b2 b3
```

`x` is the compressed value (`value as i32` in minimal signed encoding, with the
five-byte `-2^31` for words `>= 0x80000000` whose signed image is `-2^31`). The script
checks that every `b_i` is a canonical ScriptNum in `0..=255`, compresses a copy of
the four bytes with `u32_compress()` and requires the result to equal `x` with
`OP_EQUALVERIFY`. Because `OP_EQUALVERIFY` compares raw bytes and compression yields
a minimal encoding, `x` is also forced to be canonical. `u32_compress` maps distinct
four-byte words to distinct signed values, so the bytes accepted for a given `x` are
unique: forged or carry-compensated byte hints cannot pass both the range checks and
the equality.

## Threat model and evidence

`x` and every hint byte are hostile. Tests cover: 17 boundary words (0, 1, 0x7f, 0x80,
0xff, 0x100, 0xffff, 0x10000, 0xffffff, 0x1000000, 0x7ffffffe, 0x7fffffff, 0x80000000,
0x80000001, 0xffffff80, 0xfffffffe, 0xffffffff) and 300 seeded words; agreement with
the existing bit-ladder decoder on seven words including the `-2^31` case; every
single-byte forgery (+1, -1, +128, -128, +255) at every position; out-of-range
and carry-compensated byte hints (258, -254, 256, -1); non-minimal encodings of a
byte hint and of the compressed value, negative zero for compressed 0, and a
mismatched `x`, with the permissive local profile still failing the bytewise
comparison; and preserved main/alt state. Evidence is `locally-reproduced`;
execution is `unclassified`; no Bitcoin Core validation is claimed.

## Measured comparison

Boundary: the policy-compiled fragment on the word `0x89abcdef`; input pushes and
terminal predicate excluded; peak measured with a terminal word drop.

| Form | Script bytes | Witness bytes | Witness items | Hint items | Combined peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Bit ladder (`u32_uncompress_canonical`) | 431 | 6 | 1 | 0 | 7 | 323 |
| Hint-checked | 135 | 18 | 5 | 4 | 12 | 107 |

The hinted form is 69% smaller on script and 65% smaller in script plus witness (153
versus 437 bytes), with 4 hint items and a peak five items higher. It does not
replace the ladder where the bytes are not available to the prover.

## Reproduction

```sh
cargo test --locked arithmetic::u32::uncompress_hinted::tests --lib
cargo test --locked --test primitive_metrics u32_uncompress_hinted_metrics_are_current -- --exact
python3 tools/kb.py validate
```
