# Packed lexicographic comparison of u4 vectors

## Research question and hypothesis

`lexicographic_le` compares two equal-width nibble vectors with a per-nibble
first-difference state machine and costs 58 script bytes per nibble at 128
nibbles. Lexicographic order of big-endian nibbles equals numeric order of the
big integers they spell, and ScriptNum arithmetic compares 28 bits at once. Does
packing each vector into seven-nibble words and comparing the words beat the state
machine? This is a new local construction; no global novelty claim is made.

## Contract and proof

`arithmetic::u4::compare_packed::lexicographic_le_packed(n)`, `1 <= n <= 496`:

```text
preserved-free:  left[0] ... left[n-1] right[0] ... right[n-1]  ->  left <= right   (0 or 1)
```

Vectors are big-endian numeric nibbles in `0..=15`; equal vectors compare true.
The vectors are split into chunks of seven nibbles (the last chunk may be
shorter). A chunk's word is the Horner sum `w = 16 * w + nibble`, at most
`2^28 - 1`, so it fits a four-byte ScriptNum. Word order equals lexicographic order
of the chunk. Starting with `result = 1`, the fragment folds the chunks from the
last to the first: if the left and right words are equal it keeps `result`,
otherwise it replaces `result` with `left word < right word`. The first differing
chunk therefore decides, and within that chunk the numeric comparison is exact.
Every nibble is range-checked when it is picked into its word, once.
`lexicographic_le_packed_constant` embeds the right vector.

## Threat model and evidence

All nibbles are hostile. Tests cover: all 256 and all 65,536 vector pairs for widths
1 and 2; differences at every position, with ascending, descending and
overridden suffixes, for widths 6, 7, 8, 13, 14, 15, 21 and 22 (chunk boundaries at
multiples of seven); equal vectors; agreement with the existing per-nibble
`lexicographic_le` on 120 deterministic vector pairs that share a random-length
prefix, each also checked against a Rust ordering model; `-1`, 16 and 255 at every
position of both vectors; the embedded-constant form with preserved main/alt state;
generation bounds; and an exact stack frontier. Evidence is `locally-reproduced`;
execution is `unclassified`; no Bitcoin Core validation is claimed.

## Measured comparison

Boundary: the policy-compiled fragment; input pushes and terminal predicate
excluded; zero hints; all `2n` nibbles coexist at entry. Sizes pinned by
`compare_packed::tests::recorded_sizes_are_current`.

| n | Per-nibble state machine | Packed words | Saving |
| ---: | ---: | ---: | ---: |
| 1 | 44 | 29 | 34% |
| 8 | 397 | 256 | 36% |
| 16 | 843 | 531 | 37% |
| 64 | 3,532 | 2,171 | 39% |
| 128 | 7,500 | 4,486 | 40% |

For two 32-byte Taproot sibling nodes (64 nibbles each, 228 witness bytes over 128
items) the packed form is 2,171 bytes against 3,532, with a 135-item peak against
131 (`2n + 7` versus `2n + 3`) and 1,650 versus 2,178 static non-push opcodes. The
saving comes from replacing about 28 bytes of branching per nibble with about 17
bytes of Horner packing per nibble plus one word comparison per seven nibbles.

## Reproduction

```sh
cargo test --locked arithmetic::u4::compare_packed::tests --lib
cargo test --locked --test primitive_metrics u4_compare_packed_metrics_are_current -- --exact
python3 tools/kb.py validate
```
