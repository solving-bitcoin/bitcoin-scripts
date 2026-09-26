# Checked u4 leading-zero projection

`arithmetic::u4::leading_zeros::u4_nibbles_to_leading_zeros` consumes a
contiguous batch of numeric nibbles, proves each value is in `0..=15`, and
replaces it with the number of zero bits before its highest set bit. Zero maps
to four, so the output is always in `0..=4`.

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top.
- **Output:** `preserved | clz[0] | ... | clz[n-1]`, with the last count on
  top.
- **Evidence:** `locally-reproduced` by exhaustive nibble tests, hostile
  range tests, boundary batch checks, and a strict metric fixture.
- **Representative result:** 440 locking-script bytes, 65 serialized witness
  bytes for 32 one-byte data items, 50 combined stack items, and no hints. The
  fragment has 328 static non-push opcodes; dynamic execution is not measured.
- **Execution class:** `unclassified`. The local strict executor runs in
  tapscript context with the combined stack limit; no Bitcoin Core consensus
  or relay-policy transaction has been tested.

## Research framing

- **Question:** can a range-checked 16-entry lookup expose nibble magnitude
  classes without expanding each nibble into four bit items?
- **Hypothesis:** a direct leading-zero projection preserves the 440-byte,
  50-item profile of the existing checked parity/LSB projections while
  providing a useful magnitude signal for variable-width encodings.
- **Comparison objective:** compare one numeric output per nibble against the
  existing parity and LSB projections and against four-bit expansion. The
  leading-zero result is a magnitude-class representation, not a substitute
  for the full bit representation.
- **Threat model:** every witness-supplied nibble is hostile and must be
  range-checked before it is used as `OP_PICK` data. The fragment does not
  bind a byte-unique ScriptNum encoding and does not provide a terminal
  predicate.
- **Hard constraints:** keep the 16-item table and all outputs within the
  1,000-item stack limit; use the repository compilation policy; count only
  the fragment boundary defined below.

## Measured configuration

`u4_nibbles_to_leading_zeros(32)` includes the generated 16-item table, 32
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
The standalone result has one output item per input and leaves a 16-item table
resident during each lookup. Callers must account for any unrelated stack
state and add a terminal predicate when composing the fragment.

## Reproduction

```sh
CARGO_INCREMENTAL=0 cargo test --locked arithmetic::u4::leading_zeros --lib
CARGO_INCREMENTAL=0 cargo test --locked --test primitive_metrics u4_leading_zeros_metrics_are_current
python3 tools/kb.py validate
```

This result does not claim consensus validity, relay-policy acceptance, or
cryptographic security.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-leading-zeros`.
