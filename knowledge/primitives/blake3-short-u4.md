# BLAKE3 sparse direct-u4 short-input construction

## Question and comparison objective

For an unkeyed BLAKE3 message fixed at generation time and no longer than 32
bytes, minimize the locking-script fragment while keeping the combined
main/altstack peak at or below 1,000 items. Compare against the previously
checked 32-byte, 4-bit-limb generator on the same
`fragment-with-memory` boundary.

## Result

The 32-byte direct-u4 compute fragment is 60,866 bytes, contains 41,148 static
non-push opcodes, and peaks at 543 combined stack items. It includes numeric
input validation, 369 bytes of lookup-table setup, compression, 174 bytes of
table cleanup, and digest restoration. It excludes input serialization and the
terminal digest predicate.

The deterministic `00 01 ... 1f` helper composition adds 64 bytes of input
pushes and 128 bytes of digest comparison, for 61,058 bytes total. Its canonical
64-item witness encoding would serialize to 111 bytes; the maximum over valid
numeric nibbles is 129 bytes.

The same independent-digit backend is selected whenever all eight message
words are live: lengths 29, 30, and 31 measure 60,892, 60,909, and 60,924
compute bytes, saving 61, 61, and 60 bytes over their packed-table word-register
forms. Shorter lengths retain the sparse word backend.

The pre-optimization 32-byte, 4-bit-limb compute baseline was 67,974 bytes with
a peak of 644, so the selected result saves 7,108 bytes (10.46%) and 101 stack
items. Relative to the preceding 61,074-byte checked direct-u4 frontier, packed
lookup memory and digit scheduling save 208 bytes and 85 stack items. The final
generic 32-byte selected-limb fragment is 61,252 bytes; the direct layout and
specialized digit backend account for the remaining 386-byte compute reduction
and halve the host-push fixture from 128 to 64 bytes.

## Construction

- Consume exactly two checked numeric nibbles per declared byte and synthesize
  partial-word and absent-word padding in the fragment.
- Retain only the dense prefix of live message words. Every absent scheduled
  word is represented in the generator, not by a stack item or runtime add.
- Evaluate wholly constant first-round column calls on the host. Active columns
  fold literal initial-state additions and use fixed rows of the XOR table;
  literal XOR nibbles zero and fifteen use copy and `15-x` special cases.
- Interleave modulo and carry at adjacent depths so one retained absolute index
  fetches both. A separate 48-item modulo table avoids doubling the discarded
  most-significant-digit sum, and constant additions fold literals into the
  lookup address.
- Pack the 16 fixed-orientation XOR rows into their 171-item shortest common
  superstring. A 16-item depth selector maps dynamic row values to the packed
  starts; an exhaustive subset search proves that no shorter ordering exists
  for those rows.
- Select disjoint G-call order at generation time. For exactly eight live
  words, keep each nibble as an independent tracked register and select the
  emission order of 16-, 12-, 8-, and 7-bit rotations. At exactly 32 bytes,
  place semantic words in physical order `w2,w4,w3,w7,w6,w1,w0,w5` and use the
  documented physical digit permutation.

The physical permutations have no runtime opcode cost. The public
`blake3_push_short_message_script` helper emits them.

## Validation and evidence

`hashes::blake3::tests::test_short_direct_nibbles_all_lengths` differentially
checks every length from 0 through 32 against the independent Rust `blake3`
crate while the local executor enforces the 1,000-item stack limit. Separate
tests reject negative and 16-valued digits, missing items, extra main-stack
items, and lengths above 32. Exhaustive table tests check all 256 nibble XOR
pairs and all 48 addition sums; a subset-DP test proves the 171-item fixed-row
packing bound. The generated script is checked as a peephole optimizer fixed
point.

These results are `differentially-validated` locally. They remain
`research-unlimited`: no pinned Bitcoin Core consensus run or relay-policy
acceptance was performed. Numeric nibble bounds do not by themselves define a
protocol's raw-byte canonicality rule, and callers must bind both the generated
length choice and returned digest.

Rejected eager message expansion, active-quartet routing, alternate radices,
byte hybrids, expanded low-XOR planes, and fused add/rotate layouts are recorded
in the negative-results index. The remaining circuit-superoptimization frontier
is tracked by OP-013.

See the [implementation README](../../src/hashes/blake3/README.md), the generic
[selected-limb profile](blake3-limb29.md), and catalog record
`hash/blake3-short-u4`.
