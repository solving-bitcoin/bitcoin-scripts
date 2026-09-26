# Checked inverse u4 Gray projection

`arithmetic::u4::gray_inverse::u4_nibbles_from_gray` consumes a contiguous
batch of numeric four-bit reflected-Gray values, proves each value is in
`0..=15`, and replaces it with the corresponding binary nibble. The mapping is
`binary = gray ^ (gray >> 1) ^ (gray >> 2) ^ (gray >> 3)`.

- **Input:** `preserved | gray[0] | ... | gray[n-1]`, with the last code on
  top.
- **Output:** `preserved | value[0] | ... | value[n-1]`, with the last value
  on top.
- **Evidence:** `locally-reproduced` by exhaustive 16-value round-trip tests,
  hostile range tests, invalid batch checks, and a strict metric fixture.
- **Representative result:** 440 locking-script bytes, 65 serialized witness
  bytes for 32 one-byte data items, 50 combined stack items, and no hints. The
  fragment has 328 static non-push opcodes; dynamic execution is unavailable.
- **Execution class:** `unclassified`. The local strict executor runs in
  tapscript context with the combined stack limit; no Bitcoin Core consensus
  or relay-policy transaction has been tested.

## Research framing

- **Question:** can a compact lookup decode four-bit reflected-Gray values on
  the stack without expanding their bits or repeating the prefix-XOR schedule?
- **Hypothesis:** direct inverse decoding has the same byte and stack profile
  as other checked one-output u4 projections and provides the missing inverse
  boundary for Gray-coded nibble streams.
- **Comparison objective:** compare direct table decoding with a hand-written
  prefix-XOR composition. The table pays fixed 16-item memory but gives a
  stable per-input cost and preserves the vector shape.
- **Threat model:** every witness-supplied Gray code is hostile and is
  range-checked before it is used as an `OP_PICK` index. The fragment does not
  bind a byte-unique ScriptNum encoding or provide a terminal predicate.
- **Hard constraints:** keep the lookup table and all outputs within the
  1,000-item stack limit, use the repository compilation policy, and measure
  only the fragment boundary defined below.

## Measured configuration

`u4_nibbles_from_gray(32)` includes the generated 16-item inverse-Gray table,
32 range-checked lookups, table cleanup, and restoration of the outputs. It
excludes input pushes, witness serialization from the script, terminal
predicates, unrelated live state, and transaction context. The witness is 32
canonical one-byte `0x0f` code items; hint items: 0.

| Metric | Result |
| --- | ---: |
| Script bytes | 440 |
| Serialized witness bytes | 65 |
| Data items | 32 |
| Hint items | 0 |
| Maximum combined stack items | 50 |
| Static non-push opcodes | 328 |
| Executed opcodes | unavailable |
| Validation weight | unavailable |

The static opcode count is not an executed-opcode or deployment measurement.
The standalone result has one output per input and leaves a 16-item table
resident during each lookup. Callers must account for unrelated stack state
and add a terminal predicate when composing the fragment.

## Reproduction

```sh
CARGO_INCREMENTAL=0 cargo test --locked arithmetic::u4::gray_inverse --lib
CARGO_INCREMENTAL=0 cargo test --locked --test primitive_metrics u4_gray_inverse_metrics_are_current
python3 tools/kb.py validate
```

This result does not claim consensus validity, relay-policy acceptance, or
cryptographic security.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-gray-inverse`.
