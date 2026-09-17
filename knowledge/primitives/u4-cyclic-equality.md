# Checked u4 cyclic lag-equality mask

`arithmetic::u4::cyclic_equality::u4_nibbles_to_cyclic_equality` consumes a
contiguous vector of numeric nibbles, proves each value is in `0..=15`, and
returns one equality bit per input. Output `i` is true exactly when
`nibble[i] == nibble[(i + offset) mod n]`.

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top.
- **Output:** `preserved | equal[0] | ... | equal[n-1]`, with the last result
  on top.
- **Evidence:** `locally-reproduced` by periodic-vector, zero-offset,
  surrounding-stack, hostile-input, invalid-batch, and strict metric tests.
- **Representative result:** 569 locking-script bytes, 65 serialized witness
  bytes for 32 one-byte data items, 65 combined stack items, and no hints. The
  fragment has 368 static non-push opcodes; dynamic execution is unavailable.
- **Execution class:** `unclassified`. The local strict executor runs in
  tapscript context with the combined stack limit; no Bitcoin Core consensus
  or relay-policy transaction has been tested.

## Research framing

- **Question:** can a fixed-width nibble vector expose wrapped equality at an
  arbitrary lag without a lookup table or reducing the vector width?
- **Hypothesis:** direct stack copies are competitive for periodicity checks
  because one output bit is produced per input and the cycle boundary is
  explicit.
- **Comparison objective:** compare the wrapped lag mask with an adjacent-pair
  mask and a rotate-then-compare composition. The cyclic form retains one
  result for every input and handles the end-to-start comparison directly.
- **Threat model:** every witness-supplied nibble is hostile and both operands
  of every comparison are range-checked before comparison. The fragment does
  not bind a byte-unique ScriptNum encoding or provide a terminal predicate.
- **Hard constraints:** keep the source vector and staged results below the
  1,000-item combined stack limit, use the repository compilation policy, and
  measure only the fragment boundary defined below.

## Measured configuration

`u4_nibbles_to_cyclic_equality(32, 7)` includes 32 numeric range checks, 32
wrapped direct comparisons, altstack result staging, input cleanup, and output
restoration. It excludes input pushes, witness serialization from the script,
terminal predicates, unrelated live state, and transaction context. The
witness is 32 canonical one-byte `0x0f` data items; hint items: 0.

| Metric | Result |
| --- | ---: |
| Script bytes | 569 |
| Serialized witness bytes | 65 |
| Data items | 32 |
| Hint items | 0 |
| Maximum combined stack items | 65 |
| Static non-push opcodes | 368 |
| Executed opcodes | unavailable |
| Validation weight | unavailable |

The values are produced by the focused metric fixture. Static non-push opcodes
are a serialized-script count, not a dynamic execution or deployment
measurement. The standalone generator ceiling is 499 input nibbles before
unrelated state is accounted for.

## Reproduction

```sh
CARGO_INCREMENTAL=0 cargo test --locked arithmetic::u4::cyclic_equality --lib
CARGO_INCREMENTAL=0 cargo test --locked --test primitive_metrics u4_cyclic_equality_metrics_are_current
python3 tools/kb.py validate
```

This result does not claim consensus validity, relay-policy acceptance, or
cryptographic security.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-cyclic-equality`.
