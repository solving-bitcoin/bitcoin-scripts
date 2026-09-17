# u32 arithmetic

Unsigned 32-bit arithmetic represented as four 8-bit Script integers, most
significant byte first. Operations use Script integer opcodes on each byte;
they do not use BN254 or any other field modulus.

## Parameters

- Word width is fixed at 32 bits and limb width is fixed at 8 bits.
- Word offsets are zero-based stack depths: `0` is the top u32 word, `1` is
  the word below it, and so on.
- `u32_add[_drop](a, b)` accepts two distinct word offsets and wraps modulo
  `2^32`. The non-`drop` form preserves the word selected by `a`.
- `u32_sub_constant(value)` checks one hostile word and subtracts the public
  compile-time `value` modulo `2^32`; the constant contributes no witness
  items.
- `u32_sub[_drop](a, b)` computes `a - b` modulo `2^32` for either ordering of
  two distinct offsets. The non-`drop` form preserves the minuend.
- `u32_conditional_negate()` normalizes a top condition and negates the next
  word modulo `2^32` when it is nonzero.
- `u32_{less,greater}than[orequal]()` compares the top two words as unsigned
  integers and consumes both.
- `u32_iszero()` consumes the top word and returns whether all four limbs are
  numerically zero.
- `u32_or(a, b, stack_size)`, like XOR and AND, takes distinct word offsets.
  `stack_size` is one plus the number of u32 words above the shared byte-logic
  table. With exactly two working words, the usual value is `3`.
- `popcount::u32_popcount()` consumes one four-byte word, range-checks every
  byte, and returns its set-bit count in `0..=32`.
- `u32_conditional_select()` consumes `condition | when_true | when_false`,
  normalizes the condition with `OP_0NOTEQUAL`, and returns one complete word.
- Stack helpers use whole-word offsets. Rotation helpers additionally take a
  rotation count. There are no implicit parameter defaults.
- `u32_uncompress_canonical()` consumes one minimally encoded signed ScriptNum
  representing a u32 and returns its four MSB-first bytes. It rejects raw
  aliases and accepts five bytes only for `-2^31`.

## Script metrics

These are serialized locking-script fragment sizes. The maximum stack column
is measured by executing the fragment with its two input words; OR also
includes the required 256-item shared logic table. Strict greater-than has the
same metrics as strict less-than, and greater-than-or-equal has the same metrics
as less-than-or-equal.

| Fragment | Locking script | Witness bytes (see boundary below) | Combined stack peak |
| --- | ---: | ---: | ---: |
| `u32_add_drop(0, 1)` | <!-- metric:u32_add_drop -->78<!-- /metric:u32_add_drop --> bytes | 0 bytes | <!-- metric:u32_add_drop_stack -->10<!-- /metric:u32_add_drop_stack --> items |
| `u32_sub_constant(value)` | <!-- metric:u32_sub_constant -->141<!-- /metric:u32_sub_constant --> bytes | <!-- metric:u32_sub_constant_witness -->9<!-- /metric:u32_sub_constant_witness --> bytes (<!-- metric:u32_sub_constant_witness_max -->13<!-- /metric:u32_sub_constant_witness_max --> max) | <!-- metric:u32_sub_constant_stack -->9<!-- /metric:u32_sub_constant_stack --> items |
| `u32_compressed_add()` | <!-- metric:u32_compressed_add -->1016<!-- /metric:u32_compressed_add --> bytes | <!-- metric:u32_compressed_add_witness -->11<!-- /metric:u32_compressed_add_witness --> bytes (<!-- metric:u32_compressed_add_witness_max -->13<!-- /metric:u32_compressed_add_witness_max --> max) | <!-- metric:u32_compressed_add_stack -->11<!-- /metric:u32_compressed_add_stack --> items |
| `u32_sub_drop(0, 1)` | <!-- metric:u32_sub_drop -->77<!-- /metric:u32_sub_drop --> bytes | 0 bytes | <!-- metric:u32_sub_drop_stack -->9<!-- /metric:u32_sub_drop_stack --> items |
| `u32_conditional_negate()` | <!-- metric:u32_conditional_negate -->83<!-- /metric:u32_conditional_negate --> bytes | 0 bytes | <!-- metric:u32_conditional_negate_stack -->9<!-- /metric:u32_conditional_negate_stack --> items |
| `u32_lessthan()` | <!-- metric:u32_lessthan -->38<!-- /metric:u32_lessthan --> bytes | 0 bytes | <!-- metric:u32_lessthan_stack -->9<!-- /metric:u32_lessthan_stack --> items |
| `u32_compressed_lessthan()` | <!-- metric:u32_compressed_lessthan -->124<!-- /metric:u32_compressed_lessthan --> bytes | <!-- metric:u32_compressed_lessthan_witness -->11<!-- /metric:u32_compressed_lessthan_witness --> bytes | <!-- metric:u32_compressed_lessthan_stack -->6<!-- /metric:u32_compressed_lessthan_stack --> items |
| `u32_lessthanorequal()` | <!-- metric:u32_lessthanorequal -->61<!-- /metric:u32_lessthanorequal --> bytes | 0 bytes | <!-- metric:u32_lessthanorequal_stack -->13<!-- /metric:u32_lessthanorequal_stack --> items |
| `u32_or(0, 1, 3)` (table excluded) | <!-- metric:u32_or -->326<!-- /metric:u32_or --> bytes | 0 bytes | <!-- metric:u32_or_stack -->272<!-- /metric:u32_or_stack --> items, including table |
| `u32_notequal()` | <!-- metric:u32_notequal -->19<!-- /metric:u32_notequal --> bytes | 0 bytes | <!-- metric:u32_notequal_stack -->9<!-- /metric:u32_notequal_stack --> items |
| `u32_compressed_equal()` | <!-- metric:u32_compressed_equal -->37<!-- /metric:u32_compressed_equal --> bytes | <!-- metric:u32_compressed_equal_witness -->11<!-- /metric:u32_compressed_equal_witness --> bytes | <!-- metric:u32_compressed_equal_stack -->5<!-- /metric:u32_compressed_equal_stack --> items |
| `u32_conditional_select()` | <!-- metric:u32_conditional_select -->9<!-- /metric:u32_conditional_select --> bytes | <!-- metric:u32_conditional_select_witness_min -->10<!-- /metric:u32_conditional_select_witness_min -->–<!-- metric:u32_conditional_select_witness_max -->30<!-- /metric:u32_conditional_select_witness_max --> bytes | <!-- metric:u32_conditional_select_stack -->9<!-- /metric:u32_conditional_select_stack --> items |
| `u32_iszero()` | <!-- metric:u32_iszero -->4<!-- /metric:u32_iszero --> bytes | <!-- metric:u32_iszero_witness -->5<!-- /metric:u32_iszero_witness --> bytes | <!-- metric:u32_iszero_stack -->4<!-- /metric:u32_iszero_stack --> items |
| `u8_push_xor_table()` | <!-- metric:u8_logic_table_push -->236<!-- /metric:u8_logic_table_push --> bytes | 0 bytes | 256 table items |
| `u8_drop_xor_table()` | <!-- metric:u8_logic_table_drop -->128<!-- /metric:u8_logic_table_drop --> bytes | 0 bytes | consumes 256 table items |
| `u32_uncompress_canonical()` | <!-- metric:u32_uncompress_canonical -->431<!-- /metric:u32_uncompress_canonical --> bytes | <!-- metric:u32_uncompress_canonical_witness -->7<!-- /metric:u32_uncompress_canonical_witness --> bytes, 1 data item | <!-- metric:u32_uncompress_canonical_stack -->7<!-- /metric:u32_uncompress_canonical_stack --> items |
| `u8_extract_hbit_checked(4)` | <!-- metric:u8_extract_hbit_checked -->73<!-- /metric:u8_extract_hbit_checked --> bytes | <!-- metric:u8_extract_hbit_checked_witness -->4<!-- /metric:u8_extract_hbit_checked_witness --> bytes, 1 data item | <!-- metric:u8_extract_hbit_checked_stack -->5<!-- /metric:u8_extract_hbit_checked_stack --> items |
| `verify_canonical_byte()` | <!-- metric:u32_canonical_byte -->12<!-- /metric:u32_canonical_byte --> bytes | <!-- metric:u32_canonical_byte_witness -->4<!-- /metric:u32_canonical_byte_witness --> bytes, 1 data item | <!-- metric:u32_canonical_byte_stack -->4<!-- /metric:u32_canonical_byte_stack --> items |
| `u32_popcount()` | <!-- metric:u32_popcount -->455<!-- /metric:u32_popcount --> bytes | <!-- metric:u32_popcount_witness -->13<!-- /metric:u32_popcount_witness --> bytes | <!-- metric:u32_popcount_stack -->262<!-- /metric:u32_popcount_stack --> items; <!-- metric:u32_popcount_opcodes -->171<!-- /metric:u32_popcount_opcodes --> static non-push opcodes |
| `u32_to_le_bits()` | <!-- metric:u32_le_bits -->514<!-- /metric:u32_le_bits --> bytes | <!-- metric:u32_le_bits_witness -->9<!-- /metric:u32_le_bits_witness --> bytes | <!-- metric:u32_le_bits_stack -->35<!-- /metric:u32_le_bits_stack --> items |

`u32_sub_constant(value)` consumes one hostile four-limb word, checks each
limb, subtracts the public compile-time constant modulo `2^32`, and returns
four limbs. The representative fixture embeds `0x89abcdef` and supplies
`0x12345678` as four data items. It requires no hints and preserves unrelated
main- and alt-stack state. The fragment is
<!-- metric:u32_sub_constant_static_opcodes -->79<!-- /metric:u32_sub_constant_static_opcodes --> static
non-push opcodes, with 141 locking-script bytes, 9 serialized
witness bytes (13 at the maximum canonical byte fixture), and a strict
combined peak of 10 items. The closest
generic two-word baseline uses
<!-- metric:u32_sub_drop_constant_witness -->21<!-- /metric:u32_sub_drop_constant_witness -->
witness bytes across eight data items and peaks at
<!-- metric:u32_sub_drop_constant_stack -->9<!-- /metric:u32_sub_drop_constant_stack --> items.
This trades locking-script bytes for four fewer witness items; the constant is
public and must not be treated as a secret.

`u32_compressed_add()` is a checked wire adapter: it accepts two canonical
compressed u32 ScriptNums, expands them through the existing byte carry chain,
and returns the canonical compressed representation of the sum modulo `2^32`.
The top word is added to the word below it. The representative boundary uses
two data items and zero auxiliary hints; it includes both canonicality checks,
expansion, byte addition, and recompression, but excludes witness pushes and a
terminal predicate. The local strict fixture measures
<!-- metric:u32_compressed_add_static_opcodes -->765<!-- /metric:u32_compressed_add_static_opcodes --> static non-push operations;
dynamic opcode counting is unavailable in the local executor.

This is a witness-width tradeoff, not a general byte-cost improvement. At the
representative values it saves nine serialized witness bytes and six entry
items versus the four-byte `u32_add_drop` baseline, but adds 938 locking bytes
and one stack item. It is useful only when witness width or item count matters
more than locking-script bytes. All compressed inputs are treated as hostile:
non-minimal aliases, negative zero, wrong five-byte values, and malformed
widths are rejected before expansion.
The same representative byte baseline has
<!-- metric:u32_add_drop_witness -->20<!-- /metric:u32_add_drop_witness --> serialized witness bytes and a
<!-- metric:u32_add_drop_byte_stack -->10<!-- /metric:u32_add_drop_byte_stack --> item strict peak.

The conditional-negation fragment contains <!-- metric:u32_conditional_negate_opcodes -->52<!-- /metric:u32_conditional_negate_opcodes --> static non-push opcodes under the repository's compilation policy. The local tapscript executor does not expose a useful dynamic opcode counter for this fragment.

Rows with zero witness bytes exclude operand serialization: callers may construct
words inside the locking script or supply four witness items per word. No
operation-specific hint is needed. The conditional selector uses one condition
item plus two four-byte words, for nine witness items when all inputs come from
the witness. Its maximum canonical witness uses a four-byte ScriptNum condition and eight two-byte ScriptNum limbs. The logic table can be shared by any number of XOR, AND, and OR
operations in one script.

The canonical compressed-u32 row uses the maximum five-byte witness item for
`-2^31`. It is a raw-encoding boundary: `u32_uncompress()` remains available
for callers that intentionally accept ScriptNum aliases.
The popcount table is separate from the Boolean XOR table. Its representative
32-bit all-ones witness uses four data items and serializes to 13 bytes; the
strict combined peak is 262 items. The table is generated once per fragment
and removed before the single numeric result is returned.

## Security

There is no independent cryptographic security parameter. Arithmetic is exact
only for byte limbs in `0..=255`; callers accepting adversarial witness values
must enforce limb range and canonical Script-number encoding where required.
The conditional selector normalizes any numeric truthy/falsy condition before
`OP_IF`, so it does not rely on non-minimal tapscript branch values.

`u32_popcount` performs the byte range checks itself because unchecked values
would address outside the popcount table. Its output is a numeric ScriptNum,
not a four-byte word or a terminal predicate.

## Script compatibility and standardness

The fragments use opcodes available in both legacy Script and tapscript.
Arithmetic and comparison fragments can be embedded in tapscript, P2WSH,
P2SH, or a bare script subject to the complete script's size and opcode limits.
Table-backed logic is intended for tapscript: a standalone OR plus table setup
and cleanup is 690 bytes and its legacy non-push opcode count exceeds the
201-opcode limit, so it is not valid in P2SH or P2WSH as a single script. Bare
use is consensus-valid when limits are met but violates standard output-template
policy. Cleanstack is not provided by a fragment and must be enforced by its
caller.

## Witness and hints

No hints are required. A witness-supplied word occupies four stack items, most
significant byte first in the module's normal representation. Binary operation
inputs and any shared logic table must already be at the documented depths.

`u32_compressed_equal()` accepts two canonical compressed u32 ScriptNums and
returns one Boolean. It checks the exact ScriptNum encoding, including the
`0x80000000` sentinel, then compares the canonical wire values directly; it
does not expand the words. The representative compressed witness is two data
items and 11 serialized bytes, versus eight items and 17 bytes for the
four-byte `u32_equal()` witness. The maximum sentinel witness is 13 bytes.
The 37-byte fragment is a deliberate trade: it reduces witness item count and
width while costing 19 more locking bytes than `u32_equal()`. The measured
snapshot records a <!-- metric:u32_compressed_equal_witness_max -->13<!-- /metric:u32_compressed_equal_witness_max -->-byte maximum witness and a <!-- metric:u32_equal_witness -->17<!-- /metric:u32_equal_witness -->-byte, <!-- metric:u32_equal_stack -->9<!-- /metric:u32_equal_stack -->-item byte baseline.

`u32_compressed_lessthan()` accepts two canonical compressed u32 ScriptNums
with the same `... a b -> ... (a < b)` contract as `u32_lessthan()`. It
validates hostile encodings, maps the signed compressed domain to a sign bit
and a legal 31-bit magnitude, and compares those values without expanding
four byte limbs. The representative witness is two items and <!-- metric:u32_compressed_lessthan_witness -->11<!-- /metric:u32_compressed_lessthan_witness --> serialized bytes versus <!-- metric:u32_lessthan_witness -->17<!-- /metric:u32_lessthan_witness --> bytes for the byte baseline. The maximum canonical witness is <!-- metric:u32_compressed_lessthan_witness_max -->13<!-- /metric:u32_compressed_lessthan_witness_max --> bytes. The fragment costs 124 locking bytes and peaks at <!-- metric:u32_compressed_lessthan_stack -->6<!-- /metric:u32_compressed_lessthan_stack --> items, so it is a witness-shape tradeoff rather than a general byte win.

## Bit conversion

`u32_to_le_bits()` consumes one u32 word and returns 32 numeric bit items. The
least-significant byte is on top of the input word; its bit zero is on top of
the output, followed by bits one through seven and then the next byte. Each
byte is range-checked numerically against `0..=255`. The 514-byte fragment has
<!-- metric:u32_le_bits_opcodes -->338<!-- /metric:u32_le_bits_opcodes --> static non-push opcodes and a 35-item local peak with four one-byte witness
items; it does not establish byte-unique ScriptNum encodings.
This is a byte-input adapter rather than a replacement for the smaller
nibble-input table when a caller already owns canonical u4 values.

## Conditional and zero predicates

`u32_conditional_negate()` consumes a condition above one word and leaves the
word unchanged for zero, or returns its modulo-`2^32` negation for any nonzero
condition. It normalizes the condition before `OP_IF`, so non-minimal boolean
values such as `2` and `-1` are accepted as true. It inherits the module's
byte-limb contract and does not itself range-check the four word limbs.
`u32_iszero()` has no second operand: its four-item zero witness serializes to
5 bytes, and its 4-byte fragment is smaller than the 21-byte
`u32_push(0) + u32_equal()` baseline under the same policy compilation. The
zero predicate contains <!-- metric:u32_iszero_opcodes -->4<!-- /metric:u32_iszero_opcodes -->
static non-push opcodes; the baseline measures <!-- metric:u32_iszero_equal_baseline -->21<!-- /metric:u32_iszero_equal_baseline --> bytes.

The zero-word fixture uses 5 serialized witness bytes; the maximum canonical byte-word witness is <!-- metric:u32_iszero_witness_max -->13<!-- /metric:u32_iszero_witness_max --> bytes. The little-endian bit fixture uses four `0x42` limbs (9 bytes), with a maximum canonical witness of <!-- metric:u32_le_bits_witness_max -->13<!-- /metric:u32_le_bits_witness_max --> bytes. These focused metrics use strict local tapscript execution; deployment remains `unclassified`.
