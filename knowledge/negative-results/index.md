# Negative, dominated, and boundary results

These records prevent repeated dead ends. They are scoped observations, not
universal impossibility proofs.

## NR-001: Raw 1,024-byte SHAKE256 output exceeds the stack limit

The current byte-lane SHAKE256 leaves 1,024 output items, already exceeding the
1,000 combined main/altstack consensus limit. A strict construction must reduce
the requested output or consume it incrementally. Evidence: source-level output
shape and implementation README.

## NR-002: F257 log/exp memory cannot coexist with a 512-item state

The 385-item memory plus protocol state and operation temporaries reaches a
measured peak of 900 at the documented depth; the exact-square table uses a
separate 129 items. The implementation documentation concludes the two memories
cannot coexist with a 512-coefficient state and should be phased. Evidence:
checked metric snapshots and stack-limit tests.

## NR-003: Legacy RNS multiplication leaves little composition headroom

The measured legacy RNS multiply peaks at 903 items. It is locally correct, but
only 97 items remain for unrelated state under the consensus ceiling. The
exact-256-bit-product prime-log profile uses a different 513-bit modulus and 75
canonical residues. It peaks at 462 items, leaving 538 items for unrelated
state, but is not a drop-in replacement at fixed value range or encoding.

## NR-004: Larger dense-log primes lose byte efficiency

For the streamed signed-log construction, a prime contributes `log2(p)` range
bits while its dense table occupies linear-in-`p` items. An inspected search
found that reducing the exact-product profile to roughly 54 primes in the
587–941 range requires more than three times the table items of the selected
75-prime basis. Larger primes reduce witness coordinates but are dominated for
one-shot locking-script bytes under this lookup model.

## NR-005: Monolithic pairing execution is not a deployment result

The full BN254 Miller-loop test is expensive, ignored by default, and uses a
relaxed executor. Passing it establishes algorithmic evidence, not consensus or
policy feasibility. Protocol chunking and authenticated boundaries are required.

## NR-006: SHA-1 is dominated for new collision-resistant protocols

SHA-1 remains useful for compatibility research, but practical collision
attacks invalidate the ideal collision claim. Its local script is also not
smaller than BLAKE3's measured 64-byte configuration. Semantics differ, so this
is not a universal byte comparison.

## NR-007: Large fragments do not become deployable through opcode compatibility

Many primitives use opcodes present in legacy and tapscript yet exceed script,
opcode, validation, stack, or relay-policy limits once composed. Compatibility
tables must never be interpreted as blanket standardness.
