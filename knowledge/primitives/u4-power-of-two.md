# Checked u4 nonzero-power-of-two predicate

`arithmetic::u4::power_of_two::u4_nibbles_to_power_of_two` consumes a
contiguous batch of numeric nibbles, proves each value is in `0..=15`, and
replaces it with one exactly when the value is a nonzero power of two. The
accepted values are `1`, `2`, `4`, and `8`; zero is rejected by the predicate.

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top.
- **Output:** `preserved | power[0] | ... | power[n-1]`, with the last bit on
  top.
- **Evidence:** `locally-reproduced` by exhaustive nibble tests, hostile range
  tests, invalid batch checks, and a strict metric fixture.
- **Representative result:** 440 locking-script bytes, 65 serialized witness
  bytes for 32 one-byte data items, 50 combined stack items, and no hints. The
  fragment has 328 static non-push opcodes; dynamic execution is unavailable.
- **Execution class:** `unclassified`. The local strict executor runs in
  tapscript context with the combined stack limit; no Bitcoin Core consensus
  or relay-policy transaction has been tested.

## Research framing

- **Question:** can a compact lookup validate single-set-bit nibble selectors
  without expanding the value or reconstructing a lowbit from other metadata?
- **Hypothesis:** direct classification has the same byte and stack profile as
  checked one-output u4 projections and is cheaper to compose than separate
  zero, lowbit, and equality checks.
- **Comparison objective:** compare direct classification against lowbit
  extraction followed by equality and against a one-hot representation. The
  predicate intentionally discards the selector value while preserving one
  boolean per input.
- **Threat model:** every witness-supplied nibble is hostile and is
  range-checked before it is used as an `OP_PICK` index. The fragment does not
  bind a byte-unique ScriptNum encoding or provide a terminal predicate.
- **Hard constraints:** keep the lookup table and all outputs within the
  1,000-item stack limit, use the repository compilation policy, and measure
  only the fragment boundary defined below.

## Measured configuration

`u4_nibbles_to_power_of_two(32)` includes the generated 16-item table, 32
range-checked lookups, table cleanup, and restoration of the outputs. It
excludes input pushes, witness serialization from the script, terminal
predicates, unrelated live state, and transaction context. The witness is 32
canonical one-byte `0x0f` data items; hint items: 0.

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
CARGO_INCREMENTAL=0 cargo test --locked arithmetic::u4::power_of_two --lib
CARGO_INCREMENTAL=0 cargo test --locked --test primitive_metrics u4_power_of_two_metrics_are_current
python3 tools/kb.py validate
```

This result does not claim consensus validity, relay-policy acceptance, or
cryptographic security.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-power-of-two`.
