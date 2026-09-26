# Checked u4 intra-nibble bit-transition projection

`arithmetic::u4::bit_transitions::u4_nibbles_to_bit_transitions` consumes a
contiguous batch of numeric nibbles, proves each value is in `0..=15`, and
replaces it with the number of changes across the three adjacent bit
boundaries in its four-bit representation. The output is always in `0..=3`.

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top.
- **Output:** `preserved | transitions[0] | ... | transitions[n-1]`, with the
  last count on top.
- **Evidence:** `locally-reproduced` by exhaustive nibble tests, hostile range
  tests, invalid batch checks, and a strict metric fixture.
- **Representative result:** 440 locking-script bytes, 65 serialized witness
  bytes for 32 one-byte data items, 50 combined stack items, and no hints. The
  fragment has 328 static non-push opcodes; dynamic execution is unavailable.
- **Execution class:** `unclassified`. The local strict executor runs in
  tapscript context with the combined stack limit; no Bitcoin Core consensus
  or relay-policy transaction has been tested.

## Research framing

- **Question:** can a compact lookup expose binary edge density inside each
  nibble without expanding the nibble into four stack items?
- **Hypothesis:** a 16-entry lookup preserves the 440-byte and 50-item profile
  of the existing checked one-output u4 projections while supplying a useful
  local complexity statistic for nibble streams.
- **Comparison objective:** compare one count in `0..=3` per nibble against
  full four-bit expansion and against scalar projections such as parity or
  population count. This is an intra-nibble statistic, not a comparison of
  neighboring input nibbles.
- **Threat model:** every witness-supplied nibble is hostile and is
  range-checked before it is used as an `OP_PICK` index. The fragment does not
  bind byte-unique ScriptNum encoding and does not provide a terminal
  predicate.
- **Hard constraints:** keep the lookup table and all outputs within the
  1,000-item stack limit, use the repository compilation policy, and measure
  only the fragment boundary defined below.

## Measured configuration

`u4_nibbles_to_bit_transitions(32)` includes the generated 16-item table, 32
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
CARGO_INCREMENTAL=0 cargo test --locked arithmetic::u4::bit_transitions --lib
CARGO_INCREMENTAL=0 cargo test --locked --test primitive_metrics u4_bit_transitions_metrics_are_current
python3 tools/kb.py validate
```

This result does not claim consensus validity, relay-policy acceptance, or
cryptographic security.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-bit-transitions`.
