# BLAKE3 sparse direct-u4 short-input construction

## Question and comparison objective

For an unkeyed BLAKE3 message fixed at generation time and no longer than 32
bytes, minimize the locking-script fragment while keeping the combined
main/altstack peak at or below 1,000 items. Compare against the previously
checked 32-byte, 4-bit-limb generator on the same
`fragment-with-memory` boundary.

## Result

The 32-byte direct-u4 compute fragment is 62,647 bytes, contains 39,664 static
non-push opcodes, and peaks at 580 combined stack items. It includes numeric
input validation, 383 bytes of lookup-table setup, compression, 192 bytes of
table cleanup, and digest restoration. It excludes input serialization and the
terminal digest predicate.

The deterministic `00 01 ... 1f` helper composition adds 64 bytes of input
pushes and 128 bytes of digest comparison, for 62,839 bytes total. Its canonical
64-item witness encoding would serialize to 111 bytes; the maximum over valid
numeric nibbles is 129 bytes.

The pre-optimization 32-byte, 4-bit-limb compute baseline was 67,974 bytes with
a peak of 644, so the selected result saves 5,327 bytes (7.84%) and 64 stack
items. After applying the shared addition and constant-column improvements to
the selected-limb path too, that generic 32-byte fragment is 62,953 bytes; the
direct layout accounts for the remaining 306-byte compute reduction and halves
the host-push fixture from 128 to 64 bytes.

## Construction

- Consume exactly two checked numeric nibbles per declared byte and synthesize
  partial-word and absent-word padding in the fragment.
- Retain only the dense prefix of live message words. Every absent scheduled
  word is represented in the generator, not by a stack item or runtime add.
- Evaluate wholly constant first-round column calls on the host. Active columns
  fold literal initial-state additions and use fixed rows of the XOR table;
  literal XOR nibbles zero and fifteen use copy and `15-x` special cases.
- Reuse one absolute stack index to fetch both quotient and modulo from the
  adjacent addition tables.
- Select disjoint G-call order at generation time. For exactly eight live
  words, place semantic words in physical order `w2,w4,w3,w7,w6,w1,w0,w5` so
  the final consuming round removes them with less routing.

The physical permutation has no runtime opcode cost. The public
`blake3_push_short_message_script` helper emits it.

## Validation and evidence

`hashes::blake3::tests::test_short_direct_nibbles_all_lengths` differentially
checks every length from 0 through 32 against the independent Rust `blake3`
crate while the local executor enforces the 1,000-item stack limit. Separate
tests reject negative and 16-valued digits, missing items, extra main-stack
items, and lengths above 32. The generated script is checked as a peephole
optimizer fixed point.

These results are `differentially-validated` locally. They remain
`research-unlimited`: no pinned Bitcoin Core consensus run or relay-policy
acceptance was performed. Numeric nibble bounds do not by themselves define a
protocol's raw-byte canonicality rule, and callers must bind both the generated
length choice and returned digest.

Rejected eager message expansion, active-quartet routing, alternate radix, and
carry-branch layouts are recorded in the negative-results index. The remaining
fused add/rotate frontier is tracked by OP-013.

See the [implementation README](../../src/hashes/blake3/README.md), the generic
[selected-limb profile](blake3-limb29.md), and catalog record
`hash/blake3-short-u4`.
