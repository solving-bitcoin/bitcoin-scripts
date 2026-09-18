# u4 arithmetic

Generic Bitcoin Script operations on 4-bit limbs. SHA-256 and BLAKE3 compose
these operations, but this module contains no hash-specific round logic.

## Parameters

- Limb width: fixed at 4 bits; valid values are `0..=15`.
- Arithmetic functions take a nibble count, operand stack offsets, and whether
  preloaded addition tables are used. There is no universal default.
- Logic may use full or triangular half tables; shifts and rotations take
  `1..=3` bit counts unless their function documents otherwise.
- `parity::u4_nibbles_to_parity(nibble_count)` takes a checked batch size in
  `1..=982`.
- `lsb::u4_nibbles_to_lsb(nibble_count)` takes a checked batch size in
  `1..=982` and returns one bit per input nibble.
- `bit_planes::u4_nibbles_to_bit_planes(nibble_count, check_inputs)` reuses
  checked nibble decomposition and transposes batches up to 234 nibbles.
- `bit_reverse::u4_nibbles_to_bit_reverse(nibble_count)` checks and reverses
  each nibble in a shared 16-item lookup table.
- `bits::u4_nibbles_to_be_bits[_toaltstack](nibble_count, check_inputs)` and
  `bits::u4_nibbles_to_le_bits[_toaltstack](nibble_count, check_inputs)` take
  an explicit batch size in `1..=234` and have no default for input checking.

## Script metrics

These are serialized locking-script fragments. Operand pushes and witness
serialization are excluded. The 32-nibble bit-conversion rows include table
setup, all queries, table cleanup, and restoration of 128 output bits to the
main stack. The branch baseline applies the existing four-bit limb splitter to
each input with the same output-restoration boundary.

| Fragment | Locking script | Maximum combined stack | Static non-push opcodes |
| --- | ---: | ---: | ---: |
| `u4_push_add_tables()` | <!-- metric:u4_add_tables -->92<!-- /metric:u4_add_tables --> bytes | instance-specific | not recorded |
| Staggered bit-table setup | <!-- metric:u4_bits_table_push -->61<!-- /metric:u4_bits_table_push --> bytes | 61 table items | not recorded |
| Staggered bit-table cleanup | <!-- metric:u4_bits_table_drop -->31<!-- /metric:u4_bits_table_drop --> bytes | consumes 61 items | not recorded |
| One checked table query, output on altstack | <!-- metric:u4_bits_checked_query -->22<!-- /metric:u4_bits_checked_query --> bytes | composition-dependent | not recorded |
| Little-endian staggered bit-table setup | <!-- metric:u4_bits_le_table_push -->61<!-- /metric:u4_bits_le_table_push --> bytes | 61 table items | not recorded |
| Checked table batch, 32 nibbles | <!-- metric:u4_bits_checked_batch32 -->924<!-- /metric:u4_bits_checked_batch32 --> bytes | <!-- metric:u4_bits_checked_batch32_stack -->189<!-- /metric:u4_bits_checked_batch32_stack --> items | <!-- metric:u4_bits_checked_batch32_opcodes -->735<!-- /metric:u4_bits_checked_batch32_opcodes --> |
| Checked little-endian table batch, 32 nibbles | <!-- metric:u4_bits_le_checked_batch32 -->924<!-- /metric:u4_bits_le_checked_batch32 --> bytes | <!-- metric:u4_bits_le_checked_batch32_stack -->189<!-- /metric:u4_bits_le_checked_batch32_stack --> items | <!-- metric:u4_bits_le_checked_batch32_opcodes -->735<!-- /metric:u4_bits_le_checked_batch32_opcodes --> |
| Unchecked table batch, 32 nibbles | <!-- metric:u4_bits_unchecked_batch32 -->764<!-- /metric:u4_bits_unchecked_batch32 --> bytes | 189 items | not recorded |
| Existing branch splitter, 32 four-bit limbs | <!-- metric:u4_bits_branch_batch32 -->1374<!-- /metric:u4_bits_branch_batch32 --> bytes | <!-- metric:u4_bits_branch_batch32_stack -->130<!-- /metric:u4_bits_branch_batch32_stack --> items | not recorded |
| Checked high/low nibble pair to one byte | <!-- metric:u4_pair_to_u8_checked -->20<!-- /metric:u4_pair_to_u8_checked --> bytes | <!-- metric:u4_pair_to_u8_checked_stack -->5<!-- /metric:u4_pair_to_u8_checked_stack --> items | not recorded |
| Checked byte to high/low nibble pair | <!-- metric:u8_to_u4_pair_checked -->62<!-- /metric:u8_to_u4_pair_checked --> bytes | <!-- metric:u8_to_u4_pair_checked_stack -->4<!-- /metric:u8_to_u4_pair_checked_stack --> items | not recorded |
| `verify_canonical_nibble()` | <!-- metric:u4_canonical_nibble -->10<!-- /metric:u4_canonical_nibble --> bytes | <!-- metric:u4_canonical_nibble_stack -->4<!-- /metric:u4_canonical_nibble_stack --> items | not recorded |
| `lexicographic_le(128)` | <!-- metric:u4_lexicographic_le_128 -->7500<!-- /metric:u4_lexicographic_le_128 --> bytes | <!-- metric:u4_lexicographic_le_128_stack -->259<!-- /metric:u4_lexicographic_le_128_stack --> items | <!-- metric:u4_lexicographic_le_128_opcodes -->4354<!-- /metric:u4_lexicographic_le_128_opcodes --> |
| Checked parity batch, 32 nibbles | <!-- metric:u4_parity_batch32 -->440<!-- /metric:u4_parity_batch32 --> bytes | <!-- metric:u4_parity_batch32_stack -->50<!-- /metric:u4_parity_batch32_stack --> items | <!-- metric:u4_parity_batch32_opcodes -->328<!-- /metric:u4_parity_batch32_opcodes --> |
| Fixed-symbol count, 16 nibbles | <!-- metric:u4_symbol_count_16 -->266<!-- /metric:u4_symbol_count_16 --> bytes | <!-- metric:u4_symbol_count_16_stack -->19<!-- /metric:u4_symbol_count_16_stack --> items | <!-- metric:u4_symbol_count_16_opcodes -->186<!-- /metric:u4_symbol_count_16_opcodes --> |
| Checked LSB batch, 32 nibbles | <!-- metric:u4_lsb_batch32 -->440<!-- /metric:u4_lsb_batch32 --> bytes | <!-- metric:u4_lsb_batch32_stack -->50<!-- /metric:u4_lsb_batch32_stack --> items | <!-- metric:u4_lsb_batch32_opcodes -->328<!-- /metric:u4_lsb_batch32_opcodes --> |
| Checked 16-nibble bit-plane transpose | <!-- metric:u4_bit_planes_batch16 -->776<!-- /metric:u4_bit_planes_batch16 --> bytes | <!-- metric:u4_bit_planes_batch16_stack -->125<!-- /metric:u4_bit_planes_batch16_stack --> items | <!-- metric:u4_bit_planes_batch16_opcodes -->573<!-- /metric:u4_bit_planes_batch16_opcodes --> |
| Checked 32-nibble bit reversal | <!-- metric:u4_bit_reverse_batch32 -->344<!-- /metric:u4_bit_reverse_batch32 --> bytes | <!-- metric:u4_bit_reverse_batch32_stack -->51<!-- /metric:u4_bit_reverse_batch32_stack --> items | <!-- metric:u4_bit_reverse_batch32_opcodes -->232<!-- /metric:u4_bit_reverse_batch32_opcodes --> |

The fixed-symbol count fixture uses <!-- metric:u4_symbol_count_16_witness -->33<!-- /metric:u4_symbol_count_16_witness --> serialized witness bytes for <!-- metric:u4_symbol_count_16_witness_items -->16<!-- /metric:u4_symbol_count_16_witness_items --> data items and returns one numeric count.

<!-- metric:u4_parity_batch32_witness -->65<!-- /metric:u4_parity_batch32_witness --> serialized witness bytes for the representative parity batch.

<!-- metric:u4_lsb_batch32_witness -->65<!-- /metric:u4_lsb_batch32_witness --> serialized witness bytes for the representative LSB batch.

The staggered table has 61 setup items and costs 31 bytes to remove. A checked
query costs 22 bytes and restoring its four bits costs another four, so the
complete checked batch is `92 + 26*n` bytes. The existing branch splitter is
`43*n` bytes on the same boundary; the checked table wins from six nibbles.
Unchecked lookup is `92 + 21*n` and wins from five, but is safe only for
previously certified nibbles.

`u4_pair_to_u8(check_inputs)` is the small runtime bridge from nibble-oriented
state to byte-oriented state. It consumes `high | low` and returns
`16*high + low`; checked mode enforces both nibble ranges, while unchecked mode
requires that invariant from the caller.
`u8_to_u4_pair(check_inputs)` is the inverse bridge from byte-oriented state
to high/low nibble state. Checked mode enforces `0..=255`; its four-threshold
schedule preserves unrelated altstack state. Unchecked mode requires the byte
invariant from the caller.
The parity table has 16 items. A checked 32-nibble batch is measured at 440
bytes and 50 combined stack items, with no hints and 65 witness bytes across
32 data items. It returns one numeric bit per nibble and is smaller than
expanding each nibble to four bits when only parity is needed.
The bit-plane transpose reuses the 61-item checked bit table and adds a static
stack permutation. It has no new witness or hint items; the representative
16-nibble row above includes the reused decomposition and the transpose.
The bit-reversal primitive installs 16 table items, checks each nibble, and
uses no witness hints beyond its input nibbles. Its 32-nibble row above is the
representative batch; callers with unrelated live state must reduce the 981
nibble standalone ceiling.
The little-endian row has the same size and stack profile: it changes only the
four values stored in each staggered table group. It is intended for callers
that consume each nibble least-significant-bit first; reversing four output
bits per nibble after the big-endian adapter is a separate composition cost.
The representative little-endian witness is 32 canonical `0x0f` stack items,
serialized as <!-- metric:u4_bits_le_checked_batch32_witness -->65<!-- /metric:u4_bits_le_checked_batch32_witness --> bytes.

## Security

No independent cryptographic security claim. Correctness requires callers to
provide canonical nibbles; not every operation range-checks every input.

For bit conversion, `check_inputs=true` proves the numeric range `0..=15`
before using a value as an `OP_PICK` index. `check_inputs=false` must be used
only when a surrounding fragment already established that range: an invalid
index can otherwise address below the table. The numeric range check does not
by itself prove a byte-unique ScriptNum encoding.

`compare::lexicographic_le(n)` range-checks two `n`-nibble big-endian vectors,
compares the first differing nibble, consumes both vectors, and returns one
truth value. For the representative 128-nibble vectors, the complete witness
is <!-- metric:u4_lexicographic_le_128_witness -->259<!-- /metric:u4_lexicographic_le_128_witness --> bytes across <!-- metric:u4_lexicographic_le_128_witness_items -->256<!-- /metric:u4_lexicographic_le_128_witness_items --> data items and <!-- metric:u4_lexicographic_le_128_hints -->0<!-- /metric:u4_lexicographic_le_128_hints --> hint items; all data items coexist at entry. Numeric range validation does not make non-minimal raw ScriptNum encodings byte-unique under consensus.
Parity uses the same numeric range proof before its `OP_PICK` lookup. Its
output is a ScriptNum bit, not a raw byte or a terminal truth value.

## Script compatibility and standardness

The fragments use arithmetic, flow, stack, and comparison opcodes available to
legacy script and tapscript. Actual bare/P2SH/P2WSH/tapscript compatibility is
determined by the composed size, opcode count, and stack depth. Lookup-heavy
compositions can be non-standard. See the repository script-type and
standardness notes.

The representative checked 32-nibble batch exceeds the 201-non-push-opcode
limit that applies to bare, P2SH, and P2WSH execution, and the 924-byte fragment
cannot be carried as a P2SH redeem script under the 520-byte element limit. It
is intended for tapscript composition. It is still a fragment rather than a
complete leaf, so its deployment class remains `unclassified` pending strict
Bitcoin Core validation.

## Witness and hints

No cryptographic hints are required. Operand nibbles may come from the witness;
their order is operation-specific. The bit-plane adapter adds zero data or
incremental hint items beyond the source nibbles. Tables are generated by the
locking script. The bit-reversal batch consumes one data
item per nibble and has zero incremental hint items; its 32-nibble metric uses
65 serialized witness bytes.

## Stack contract

For `u4_nibbles_to_be_bits(n, ...)`, input is
`preserved | nibble[0] | ... | nibble[n-1]`, with `nibble[n-1]` on top. The
inputs are consumed and replaced by four bits per nibble. The top input's most
significant bit is the top output, followed by that nibble's remaining bits and
then each deeper nibble. The `_toaltstack` variant leaves `preserved` on the
main stack and all new bits above any pre-existing altstack state.

For `u4_nibbles_to_le_bits(n, ...)`, the stack contract and input order are the
same, but each nibble's least-significant bit is emitted first. The checked
32-nibble representative consumes 32 witness data items (65 serialized
witness bytes for the all-15 fixture); no hint items are required.

The standalone batch peak is `4*n + 61` combined main/alt-stack items. The
generator rejects `n > 234`, but callers must reduce the batch further for any
unrelated live state.

For `u4_nibbles_to_parity(n)`, the same input ordering is consumed and replaced
one-for-one by parity bits. The standalone peak is `n + 18` during range checks;
the generator rejects `n > 982`, and callers must reduce the batch for unrelated
live state.
For `bit_planes::u4_nibbles_to_bit_planes(n, ...)`, the same input contract is
used, but the output is grouped as `plane0[0..n]`, then `plane1`, `plane2`, and
`plane3`, with the final plane-3 bit on top. A sentinel keeps unrelated main
stack items below the generated permutation, and pre-existing altstack items
are preserved. The representative 16-nibble fragment is 776 bytes, uses a
33-byte witness of 16 data items, and peaks at 125 combined items.
For `bit_reverse::u4_nibbles_to_bit_reverse(n)`, input and output order are
unchanged: each `nibble[i]` is replaced by its bit-reversed value. The checked
standalone peak is `n + 19` combined items, and the generator rejects empty
batches and batches above 981.

## Operational notes

`stack*.rs` contains adapters for `bitcoin-script-stack`; `add.rs`, `logic.rs`,
`rotate.rs`, and `shift.rs` remain generic. `bits.rs` exhaustively tests every
nibble in checked and unchecked mode, rejects malformed numeric inputs in
checked mode, verifies multi-input ordering, and executes the maximum
standalone batch under the strict local stack limit. `parity.rs` exhaustively
checks the 16-value lookup domain, rejects malformed inputs and invalid batch
sizes, and measures a representative strict batch.

The four-equal-index query is derived from the combined nibble-table sketch in
[`coins/bitcoin-scripts`](https://github.com/coins/bitcoin-scripts/blob/8f442e4bf8a744dd9bf69b2937bdebcaed5cae77/split-into-bits.md).
The published direct table layout is not correct for every nibble under Bitcoin
`OP_PICK` semantics. This implementation substitutes a locally reproduced
61-item staggered layout; see the corresponding negative result.

Canonical input witnesses, including the CompactSize item count: nibble packing uses <!-- metric:u4_pair_to_u8_checked_witness -->5<!-- /metric:u4_pair_to_u8_checked_witness --> bytes across two data items; byte splitting uses <!-- metric:u8_to_u4_pair_checked_witness -->4<!-- /metric:u8_to_u4_pair_checked_witness --> bytes in one data item; canonical-nibble validation uses <!-- metric:u4_canonical_nibble_witness -->3<!-- /metric:u4_canonical_nibble_witness --> bytes in one data item. None requires hints.
