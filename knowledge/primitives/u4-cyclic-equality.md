# Checked u4 cyclic lag-equality mask

`arithmetic::u4::cyclic_equality::u4_nibbles_to_cyclic_equality` consumes a
contiguous vector of numeric nibbles, proves each value is in `0..=15`, and
returns one equality bit per input. Output `i` is true exactly when
`nibble[i] == nibble[(i + offset) mod n]` numerically, including for
non-minimal ScriptNum encodings of the same value.

The [opaque lag-match count](opaque-lag-count.md) uses raw byte equality
at unwrapped indices and returns an aggregate count.

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top.
- **Output:** `preserved | equal[0] | ... | equal[n-1]`, with the last result
  on top.
- **Evidence:** `locally-reproduced` by periodic-vector, zero-offset,
  asymmetric-order, raw-encoding-alias, hostile-input, invalid-batch, frontier,
  and metric tests.
- **Representative result:** 569 locking-script bytes, 65 serialized witness
  bytes for 32 one-byte data items, 65 combined stack items, and no hints. The
  fragment has 368 static non-push opcodes. Executed opcodes and validation
  weight are not reported for this metric fixture.
- **Execution class:** `unclassified`. Existing periodic, zero-offset, and
  surrounding-stack cases call the local `execute_script` helper, which uses a
  tapscript context with the combined stack limit and default interpreter
  flags. Alias and frontier regressions use the explicit local
  `TapscriptProfile::Consensus` profile. Neither helper validates a Bitcoin
  Core transaction or establishes relay-policy acceptance.

## Research framing

- **Question:** can a fixed-width nibble vector expose wrapped equality at an
  arbitrary lag without a lookup table or reducing the vector width?
- **Hypothesis:** direct stack copies are competitive for periodicity checks
  because one output bit is produced per input and the cycle boundary is
  explicit.
- **Comparison objective:** compare the wrapped lag mask with an adjacent-pair
  mask and a rotate-then-compare composition. The cyclic form retains one
  result for every input and handles the end-to-start comparison directly.
- **Threat model:** every witness-supplied nibble is hostile. The fragment
  range-checks each source nibble once before copying and numerically comparing
  operands. It accepts non-minimal encodings of in-range values and does not
  provide a terminal predicate.
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
| Executed opcodes | not measured |
| Validation weight | not measured |

The values are produced by `u4_cyclic_equality_metrics_are_current`. Static
non-push opcodes are a serialized-script count, not a dynamic execution or
deployment measurement.

The local consensus-profile frontier test executes the generated 499-item
batch with output cleanup and a terminal `OP_TRUE`. Its policy-compiled script
is 11,041 bytes, the 499 one-byte witness items serialize to 1,001 bytes, and
the measured combined main-plus-alt-stack peak is 999 items. This configuration
has 499 data items and zero hint items, all present at script entry. With one
additional preserved witness item, the complete entry has 500 data items, 0
hint items, and 1,003 serialized witness bytes; its measured peak is 1,000
items. With two preserved witness items, the complete entry has 501 data items,
0 hint items, and 1,005 serialized witness bytes; execution fails with
`StackSize` at a measured peak of 1,001. Those extra items are complete witness
data too, not a free stack allowance. The test's local profile result remains
`unclassified` deployment evidence and is not a Bitcoin Core consensus result.
Executed opcodes and validation weight are not claimed for these frontier
runs.

The alias regression uses complete output checks and a clean single-item
terminal. Raw witness items `[0x01]` and `[0x01, 0x00]` both encode numeric one
and are accepted under the local `Consensus` profile. The same complete check
with a test-only byte-equality mutant fails at `EqualVerify`, proving why the
numeric `OP_NUMEQUAL` comparison is required. The mutant is produced by parsing
the policy-compiled instructions and replacing the comparison opcode; no
Bitcoin Core transaction was run.

## Reproduction

```sh
CARGO_INCREMENTAL=0 cargo test --locked arithmetic::u4::cyclic_equality::tests --lib
CARGO_INCREMENTAL=0 cargo test --locked --test primitive_metrics u4_cyclic_equality_metrics_are_current
python3 tools/kb.py validate
```

This result does not claim consensus validity, relay-policy acceptance, or
cryptographic security.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-cyclic-equality`.
