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
- `u32_sub[_drop](a, b)` computes `a - b` modulo `2^32` for either ordering of
  two distinct offsets. The non-`drop` form preserves the minuend.
- `u32_conditional_negate()` normalizes a top condition and negates the next
  word modulo `2^32` when it is nonzero.
- `u32_{less,greater}than[orequal]()` compares the top two words as unsigned
  integers and consumes both.
- `u32_iszero()` consumes the top word and returns whether all four limbs are
  numerically zero.
- `zero_byte_mask::u32_to_zero_byte_mask()` consumes the top word and returns
  one four-bit mask whose bit `i` marks zero byte limb `i`.
- `u32_leading_zero_bytes()` consumes the top word and returns the count of
  leading zero byte limbs in `0..=4`.
- `u32_trailing_zero_bytes()` consumes the top word and returns the count of
  trailing zero byte limbs in `0..=4`.
- `u32_extract_byte(index)` validates a top word and returns one byte selected
  from most-significant index `0` through least-significant index `3`.
- `u32_byte_eq_mask()` consumes two canonical u32 words and returns a four-bit
  mask whose bit 3 compares the most-significant bytes and bit 0 compares the
  least-significant bytes.
- `u32_byte_lessthan_mask()` consumes two canonical u32 words and returns a
  four-bit mask whose bit 3 compares the most-significant bytes and bit 0
  compares the least-significant bytes.
- `u32_msb_mask()` consumes one canonical u32 word and returns a four-bit mask
  whose bit 3 is the most-significant byte's high bit and bit 0 is the
  least-significant byte's high bit.
- `u32_{xor,and,or}_drop()` consume both input words and return only the
  bitwise result.
- `u32_or(a, b, stack_size)`, like XOR and AND, takes distinct word offsets.
  `stack_size` is one plus the number of u32 words above the shared byte-logic
  table. With exactly two working words, the usual value is `3`.
- `u32_nand(a, b, stack_size)` computes the bitwise complement of AND using the
- `u32_nor(a, b, stack_size)` computes the bitwise complement of OR using the
  same shared table and preserves the word selected by `a`.
- `u32_xnor(a, b, stack_size)` computes the bitwise complement of XOR using
  the same shared table and preserves the word selected by `a`.
- `popcount::u32_popcount()` consumes one four-byte word, range-checks every
  byte, and returns its set-bit count in `0..=32`.
- `popcount::u32_byte_popcounts()` consumes one four-byte word, range-checks
  every byte, and returns four per-byte counts in the same word order.
- `u32_to_bit_planes()` consumes one checked word and returns eight 4-bit
  planes, with plane seven on top and plane zero deepest.
- `u32_conditional_select()` consumes `condition | when_true | when_false`,
  normalizes the condition with `OP_0NOTEQUAL`, and returns one complete word.
- `byte_parity::u32_byte_parity()` consumes one four-byte word and returns one
  numeric parity bit per byte, with the least-significant byte's bit on top.
- `zero::u32_iszero()` consumes one four-byte word, range-checks every byte,
  and returns one numeric Boolean.
- Stack helpers use whole-word offsets. Rotation helpers additionally take a
  rotation count. There are no implicit parameter defaults.
- `u32_rrot8_checked()` validates four canonical byte limbs before the
  byte-aligned eight-bit rotation.
- `u32_uncompress_canonical()` consumes one minimally encoded signed ScriptNum
  representing a u32 and returns its four MSB-first bytes. It rejects raw
  aliases and accepts five bytes only for `-2^31`.
- `u32_uncompress_canonical_nonnegative()` is a smaller decoder for canonical
  values in `0..=0x7fffffff`; it rejects negative values and raw aliases.
- `u32_rshift8_checked()` validates four canonical byte limbs before the
  direct byte-aligned logical right shift.
- `u32_lshift8_checked()` validates four canonical byte limbs before the
  direct byte-aligned logical left shift.
- `u32_rrot16_checked()` validates four canonical byte limbs before applying
  the existing one-opcode sixteen-bit rotation.

## Script metrics

These are serialized locking-script fragment sizes. The maximum stack column
is measured by executing the fragment with its two input words; OR also
includes the required 256-item shared logic table. Strict greater-than has the
same metrics as strict less-than, and greater-than-or-equal has the same metrics
as less-than-or-equal.

| Fragment | Locking script | Witness bytes (see boundary below) | Combined stack peak |
| --- | ---: | ---: | ---: |
| `u32_add_drop(0, 1)` | <!-- metric:u32_add_drop -->78<!-- /metric:u32_add_drop --> bytes | 0 bytes | <!-- metric:u32_add_drop_stack -->10<!-- /metric:u32_add_drop_stack --> items |
| `u32_compressed_add()` | <!-- metric:u32_compressed_add -->1016<!-- /metric:u32_compressed_add --> bytes | <!-- metric:u32_compressed_add_witness -->11<!-- /metric:u32_compressed_add_witness --> bytes (<!-- metric:u32_compressed_add_witness_max -->13<!-- /metric:u32_compressed_add_witness_max --> max) | <!-- metric:u32_compressed_add_stack -->11<!-- /metric:u32_compressed_add_stack --> items |
| `u32_sub_drop(0, 1)` | <!-- metric:u32_sub_drop -->77<!-- /metric:u32_sub_drop --> bytes | 0 bytes | <!-- metric:u32_sub_drop_stack -->9<!-- /metric:u32_sub_drop_stack --> items |
| `u32_conditional_negate()` | <!-- metric:u32_conditional_negate -->83<!-- /metric:u32_conditional_negate --> bytes | 0 bytes | <!-- metric:u32_conditional_negate_stack -->9<!-- /metric:u32_conditional_negate_stack --> items |
| `u32_lessthan()` | <!-- metric:u32_lessthan -->38<!-- /metric:u32_lessthan --> bytes | 0 bytes | <!-- metric:u32_lessthan_stack -->9<!-- /metric:u32_lessthan_stack --> items |
| `u32_compressed_lessthan()` | <!-- metric:u32_compressed_lessthan -->124<!-- /metric:u32_compressed_lessthan --> bytes | <!-- metric:u32_compressed_lessthan_witness -->11<!-- /metric:u32_compressed_lessthan_witness --> bytes | <!-- metric:u32_compressed_lessthan_stack -->6<!-- /metric:u32_compressed_lessthan_stack --> items |
| `u32_compressed_lessthan_constant(0x89abcdef)` | <!-- metric:u32_compressed_lessthan_constant -->127<!-- /metric:u32_compressed_lessthan_constant --> bytes | <!-- metric:u32_compressed_lessthan_constant_witness -->6<!-- /metric:u32_compressed_lessthan_constant_witness --> bytes (<!-- metric:u32_compressed_lessthan_constant_witness_max -->7<!-- /metric:u32_compressed_lessthan_constant_witness_max --> max), 1 data item | <!-- metric:u32_compressed_lessthan_constant_stack -->6<!-- /metric:u32_compressed_lessthan_constant_stack --> items; <!-- metric:u32_compressed_lessthan_constant_opcodes -->71<!-- /metric:u32_compressed_lessthan_constant_opcodes --> static non-push opcodes |
| `u32_lessthanorequal()` | <!-- metric:u32_lessthanorequal -->61<!-- /metric:u32_lessthanorequal --> bytes | 0 bytes | <!-- metric:u32_lessthanorequal_stack -->13<!-- /metric:u32_lessthanorequal_stack --> items |
| `u32_compressed_rshift(8)` | <!-- metric:u32_compressed_rshift_8 -->500<!-- /metric:u32_compressed_rshift_8 --> bytes | <!-- metric:u32_compressed_rshift_8_witness -->6<!-- /metric:u32_compressed_rshift_8_witness --> bytes | <!-- metric:u32_compressed_rshift_8_stack -->5<!-- /metric:u32_compressed_rshift_8_stack --> items |

| `u32_compressed_lshift(8)` | <!-- metric:u32_compressed_lshift_8 -->492<!-- /metric:u32_compressed_lshift_8 --> bytes | <!-- metric:u32_compressed_lshift_8_witness -->6<!-- /metric:u32_compressed_lshift_8_witness --> bytes | <!-- metric:u32_compressed_lshift_8_stack -->5<!-- /metric:u32_compressed_lshift_8_stack --> items |
| `u32_or(0, 1, 3)` (table excluded) | <!-- metric:u32_or -->326<!-- /metric:u32_or --> bytes | 0 bytes | <!-- metric:u32_or_stack -->272<!-- /metric:u32_or_stack --> items, including table |
| `u32_nand(0, 1, 3)` (table excluded) | <!-- metric:u32_nand -->190<!-- /metric:u32_nand --> bytes | 0 bytes | <!-- metric:u32_nand_stack -->272<!-- /metric:u32_nand_stack --> items, including table; <!-- metric:u32_nand_opcodes -->150<!-- /metric:u32_nand_opcodes --> static non-push opcodes |
| `u32_nor(0, 1, 3)` (table excluded) | <!-- metric:u32_nor -->346<!-- /metric:u32_nor --> bytes | 0 bytes | <!-- metric:u32_nor_stack -->272<!-- /metric:u32_nor_stack --> items, including table; <!-- metric:u32_nor_opcodes -->250<!-- /metric:u32_nor_opcodes --> static non-push opcodes |
| `u32_xnor(0, 1, 3)` (table excluded) | <!-- metric:u32_xnor -->222<!-- /metric:u32_xnor --> bytes | 0 bytes | <!-- metric:u32_xnor_stack -->272<!-- /metric:u32_xnor_stack --> items, including table; <!-- metric:u32_xnor_opcodes -->182<!-- /metric:u32_xnor_opcodes --> static non-push opcodes |
| `u32_notequal()` | <!-- metric:u32_notequal -->19<!-- /metric:u32_notequal --> bytes | 0 bytes | <!-- metric:u32_notequal_stack -->9<!-- /metric:u32_notequal_stack --> items |
| `u32_compressed_equal()` | <!-- metric:u32_compressed_equal -->37<!-- /metric:u32_compressed_equal --> bytes | <!-- metric:u32_compressed_equal_witness -->11<!-- /metric:u32_compressed_equal_witness --> bytes | <!-- metric:u32_compressed_equal_stack -->5<!-- /metric:u32_compressed_equal_stack --> items |
| `u32_conditional_select()` | <!-- metric:u32_conditional_select -->9<!-- /metric:u32_conditional_select --> bytes | <!-- metric:u32_conditional_select_witness_min -->10<!-- /metric:u32_conditional_select_witness_min -->–<!-- metric:u32_conditional_select_witness_max -->30<!-- /metric:u32_conditional_select_witness_max --> bytes | <!-- metric:u32_conditional_select_stack -->9<!-- /metric:u32_conditional_select_stack --> items |
| `u32_iszero()` | <!-- metric:u32_iszero -->4<!-- /metric:u32_iszero --> bytes | <!-- metric:u32_iszero_witness -->5<!-- /metric:u32_iszero_witness --> bytes | <!-- metric:u32_iszero_stack -->4<!-- /metric:u32_iszero_stack --> items |
| `u32_to_zero_byte_mask()` | <!-- metric:u32_zero_byte_mask -->67<!-- /metric:u32_zero_byte_mask --> bytes | <!-- metric:u32_zero_byte_mask_witness -->13<!-- /metric:u32_zero_byte_mask_witness --> bytes | <!-- metric:u32_zero_byte_mask_stack -->8<!-- /metric:u32_zero_byte_mask_stack --> items |
| `u32_leading_zero_bytes()` | <!-- metric:u32_leading_zero_bytes -->159<!-- /metric:u32_leading_zero_bytes --> bytes | <!-- metric:u32_leading_zero_bytes_witness -->13<!-- /metric:u32_leading_zero_bytes_witness --> bytes | <!-- metric:u32_leading_zero_bytes_stack -->7<!-- /metric:u32_leading_zero_bytes_stack --> items; <!-- metric:u32_leading_zero_bytes_opcodes -->104<!-- /metric:u32_leading_zero_bytes_opcodes --> static non-push opcodes |
| `u32_trailing_zero_bytes()` | <!-- metric:u32_trailing_zero_bytes -->147<!-- /metric:u32_trailing_zero_bytes --> bytes | <!-- metric:u32_trailing_zero_bytes_witness -->13<!-- /metric:u32_trailing_zero_bytes_witness --> bytes | <!-- metric:u32_trailing_zero_bytes_stack -->7<!-- /metric:u32_trailing_zero_bytes_stack --> items; <!-- metric:u32_trailing_zero_bytes_opcodes -->92<!-- /metric:u32_trailing_zero_bytes_opcodes --> static non-push opcodes |
| `u32_extract_byte(0)` | <!-- metric:u32_extract_byte -->56<!-- /metric:u32_extract_byte --> bytes | <!-- metric:u32_extract_byte_witness -->13<!-- /metric:u32_extract_byte_witness --> bytes | <!-- metric:u32_extract_byte_stack -->7<!-- /metric:u32_extract_byte_stack --> items; <!-- metric:u32_extract_byte_opcodes -->36<!-- /metric:u32_extract_byte_opcodes --> static non-push opcodes |
| `u32_byte_eq_mask()` | <!-- metric:u32_byte_eq_mask -->149<!-- /metric:u32_byte_eq_mask --> bytes | <!-- metric:u32_byte_eq_mask_witness -->17<!-- /metric:u32_byte_eq_mask_witness --> bytes (<!-- metric:u32_byte_eq_mask_witness_max -->25<!-- /metric:u32_byte_eq_mask_witness_max --> max) | <!-- metric:u32_byte_eq_mask_stack -->11<!-- /metric:u32_byte_eq_mask_stack --> items; <!-- metric:u32_byte_eq_mask_opcodes -->100<!-- /metric:u32_byte_eq_mask_opcodes --> static non-push opcodes; `u32_equal()` baseline <!-- metric:u32_byte_eq_mask_equal_baseline -->18<!-- /metric:u32_byte_eq_mask_equal_baseline --> bytes |
| `u32_byte_lessthan_mask()` | <!-- metric:u32_byte_less_mask -->149<!-- /metric:u32_byte_less_mask --> bytes | <!-- metric:u32_byte_less_mask_witness -->17<!-- /metric:u32_byte_less_mask_witness --> bytes (<!-- metric:u32_byte_less_mask_witness_max -->25<!-- /metric:u32_byte_less_mask_witness_max --> max) | <!-- metric:u32_byte_less_mask_stack -->11<!-- /metric:u32_byte_less_mask_stack --> items; <!-- metric:u32_byte_less_mask_opcodes -->100<!-- /metric:u32_byte_less_mask_opcodes --> static non-push opcodes; `u32_lessthan()` baseline <!-- metric:u32_byte_less_mask_less_baseline -->38<!-- /metric:u32_byte_less_mask_less_baseline --> bytes |
| `u32_msb_mask()` | <!-- metric:u32_msb_mask -->133<!-- /metric:u32_msb_mask --> bytes | <!-- metric:u32_msb_mask_witness -->9<!-- /metric:u32_msb_mask_witness --> bytes (<!-- metric:u32_msb_mask_witness_max -->13<!-- /metric:u32_msb_mask_witness_max --> max) | <!-- metric:u32_msb_mask_stack -->8<!-- /metric:u32_msb_mask_stack --> items; <!-- metric:u32_msb_mask_opcodes -->92<!-- /metric:u32_msb_mask_opcodes --> static non-push opcodes |
| `u32_xor_drop(0, 1, 3)` | <!-- metric:u32_xor_drop -->202<!-- /metric:u32_xor_drop --> bytes | 0 bytes | <!-- metric:u32_xor_drop_stack -->268<!-- /metric:u32_xor_drop_stack --> items; <!-- metric:u32_xor_drop_opcodes -->174<!-- /metric:u32_xor_drop_opcodes --> static non-push opcodes |
| `u32_and_drop(0, 1, 3)` | <!-- metric:u32_and_drop -->169<!-- /metric:u32_and_drop --> bytes | 0 bytes | <!-- metric:u32_and_drop_stack -->268<!-- /metric:u32_and_drop_stack --> items; <!-- metric:u32_and_drop_opcodes -->142<!-- /metric:u32_and_drop_opcodes --> static non-push opcodes |
| `u32_or_drop(0, 1, 3)` | <!-- metric:u32_or_drop -->326<!-- /metric:u32_or_drop --> bytes | 0 bytes | <!-- metric:u32_or_drop_stack -->268<!-- /metric:u32_or_drop_stack --> items; <!-- metric:u32_or_drop_opcodes -->242<!-- /metric:u32_or_drop_opcodes --> static non-push opcodes |
| `u32_zip(0, 1)` | <!-- metric:u32_zip -->16<!-- /metric:u32_zip --> bytes | <!-- metric:u32_zip_witness -->17<!-- /metric:u32_zip_witness --> bytes, 8 data items | <!-- metric:u32_zip_stack -->9<!-- /metric:u32_zip_stack --> items |
| `u32_copy_zip(0, 1)` | <!-- metric:u32_copy_zip -->16<!-- /metric:u32_copy_zip --> bytes | <!-- metric:u32_copy_zip_witness -->17<!-- /metric:u32_copy_zip_witness --> bytes, 8 data items | <!-- metric:u32_copy_zip_stack -->13<!-- /metric:u32_copy_zip_stack --> items |
| `byte_reorder(0)` | <!-- metric:u32_byte_reorder_0 -->3<!-- /metric:u32_byte_reorder_0 --> bytes | <!-- metric:u32_byte_reorder_witness_0 -->9<!-- /metric:u32_byte_reorder_witness_0 --> bytes, 4 data items | <!-- metric:u32_byte_reorder_stack_0 -->4<!-- /metric:u32_byte_reorder_stack_0 --> items |
| `byte_reorder(1)` | <!-- metric:u32_byte_reorder_1 -->2<!-- /metric:u32_byte_reorder_1 --> bytes | <!-- metric:u32_byte_reorder_witness_1 -->9<!-- /metric:u32_byte_reorder_witness_1 --> bytes, 4 data items | <!-- metric:u32_byte_reorder_stack_1 -->4<!-- /metric:u32_byte_reorder_stack_1 --> items |
| `byte_reorder(2)` | <!-- metric:u32_byte_reorder_2 -->4<!-- /metric:u32_byte_reorder_2 --> bytes | <!-- metric:u32_byte_reorder_witness_2 -->9<!-- /metric:u32_byte_reorder_witness_2 --> bytes, 4 data items | <!-- metric:u32_byte_reorder_stack_2 -->4<!-- /metric:u32_byte_reorder_stack_2 --> items |
| `byte_reorder(3)` | <!-- metric:u32_byte_reorder_3 -->3<!-- /metric:u32_byte_reorder_3 --> bytes | <!-- metric:u32_byte_reorder_witness_3 -->9<!-- /metric:u32_byte_reorder_witness_3 --> bytes, 4 data items | <!-- metric:u32_byte_reorder_stack_3 -->4<!-- /metric:u32_byte_reorder_stack_3 --> items |
| `u8_push_xor_table()` | <!-- metric:u8_logic_table_push -->236<!-- /metric:u8_logic_table_push --> bytes | 0 bytes | 256 table items |
| `u8_drop_xor_table()` | <!-- metric:u8_logic_table_drop -->128<!-- /metric:u8_logic_table_drop --> bytes | 0 bytes | consumes 256 table items |
| `u32_uncompress_canonical()` | <!-- metric:u32_uncompress_canonical -->431<!-- /metric:u32_uncompress_canonical --> bytes | <!-- metric:u32_uncompress_canonical_witness -->7<!-- /metric:u32_uncompress_canonical_witness --> bytes, 1 data item | <!-- metric:u32_uncompress_canonical_stack -->7<!-- /metric:u32_uncompress_canonical_stack --> items |
| `u32_uncompress_canonical_nonnegative()` | <!-- metric:u32_uncompress_canonical_nonnegative -->405<!-- /metric:u32_uncompress_canonical_nonnegative --> bytes | <!-- metric:u32_uncompress_canonical_nonnegative_witness -->6<!-- /metric:u32_uncompress_canonical_nonnegative_witness --> bytes, 1 data item | <!-- metric:u32_uncompress_canonical_nonnegative_stack -->7<!-- /metric:u32_uncompress_canonical_nonnegative_stack --> items; <!-- metric:u32_uncompress_canonical_nonnegative_opcodes -->328<!-- /metric:u32_uncompress_canonical_nonnegative_opcodes --> executed fragment opcodes |
| `u32_compress_canonical()` | <!-- metric:u32_compress_canonical -->130<!-- /metric:u32_compress_canonical --> bytes | <!-- metric:u32_compress_canonical_witness -->9<!-- /metric:u32_compress_canonical_witness --> bytes (<!-- metric:u32_compress_canonical_witness_max -->13<!-- /metric:u32_compress_canonical_witness_max --> max), 4 data items | <!-- metric:u32_compress_canonical_stack -->7<!-- /metric:u32_compress_canonical_stack --> items; <!-- metric:u32_compress_canonical_opcodes -->102<!-- /metric:u32_compress_canonical_opcodes --> static non-push opcodes |
| `u8_extract_hbit_checked(4)` | <!-- metric:u8_extract_hbit_checked -->73<!-- /metric:u8_extract_hbit_checked --> bytes | <!-- metric:u8_extract_hbit_checked_witness -->4<!-- /metric:u8_extract_hbit_checked_witness --> bytes, 1 data item | <!-- metric:u8_extract_hbit_checked_stack -->5<!-- /metric:u8_extract_hbit_checked_stack --> items |
| `verify_canonical_byte()` | <!-- metric:u32_canonical_byte -->12<!-- /metric:u32_canonical_byte --> bytes | <!-- metric:u32_canonical_byte_witness -->4<!-- /metric:u32_canonical_byte_witness --> bytes, 1 data item | <!-- metric:u32_canonical_byte_stack -->4<!-- /metric:u32_canonical_byte_stack --> items |
| `u32_rshift8_checked()` | <!-- metric:u32_rshift8_checked -->62<!-- /metric:u32_rshift8_checked --> bytes | <!-- metric:u32_rshift8_checked_witness -->9<!-- /metric:u32_rshift8_checked_witness --> bytes (<!-- metric:u32_rshift8_checked_witness_max -->13<!-- /metric:u32_rshift8_checked_witness_max --> max), 4 data items, 0 hints | <!-- metric:u32_rshift8_checked_stack -->7<!-- /metric:u32_rshift8_checked_stack --> items; <!-- metric:u32_rshift8_checked_opcodes -->41<!-- /metric:u32_rshift8_checked_opcodes --> static non-push opcodes |
| `u32_lshift8_checked()` | <!-- metric:u32_lshift8_checked -->56<!-- /metric:u32_lshift8_checked --> bytes | <!-- metric:u32_lshift8_checked_witness -->9<!-- /metric:u32_lshift8_checked_witness --> bytes (<!-- metric:u32_lshift8_checked_witness_max -->13<!-- /metric:u32_lshift8_checked_witness_max --> max), 4 data items, 0 hints | <!-- metric:u32_lshift8_checked_stack -->7<!-- /metric:u32_lshift8_checked_stack --> items; <!-- metric:u32_lshift8_checked_opcodes -->35<!-- /metric:u32_lshift8_checked_opcodes --> static non-push opcodes |
| `u32_rrot7_checked()` | <!-- metric:u32_rrot7_checked -->130<!-- /metric:u32_rrot7_checked --> bytes | <!-- metric:u32_rrot7_checked_witness -->9<!-- /metric:u32_rrot7_checked_witness --> bytes (<!-- metric:u32_rrot7_checked_witness_max -->13<!-- /metric:u32_rrot7_checked_witness_max --> max), 4 data items | <!-- metric:u32_rrot7_checked_stack -->8<!-- /metric:u32_rrot7_checked_stack --> items; <!-- metric:u32_rrot7_checked_opcodes -->87<!-- /metric:u32_rrot7_checked_opcodes --> static non-push opcodes |
| `u32_rrot8_checked()` | <!-- metric:u32_rrot8_checked -->57<!-- /metric:u32_rrot8_checked --> bytes | <!-- metric:u32_rrot8_checked_witness -->9<!-- /metric:u32_rrot8_checked_witness --> bytes (<!-- metric:u32_rrot8_checked_witness_max -->13<!-- /metric:u32_rrot8_checked_witness_max --> max), 4 data items | <!-- metric:u32_rrot8_checked_stack -->7<!-- /metric:u32_rrot8_checked_stack --> items; <!-- metric:u32_rrot8_checked_opcodes -->36<!-- /metric:u32_rrot8_checked_opcodes --> static non-push opcodes |
| `u32_rrot16_checked()` | <!-- metric:u32_rrot16_checked -->55<!-- /metric:u32_rrot16_checked --> bytes | <!-- metric:u32_rrot16_checked_witness -->9<!-- /metric:u32_rrot16_checked_witness --> bytes (<!-- metric:u32_rrot16_checked_witness_max -->13<!-- /metric:u32_rrot16_checked_witness_max --> max), 4 data items | <!-- metric:u32_rrot16_checked_stack -->7<!-- /metric:u32_rrot16_checked_stack --> items; <!-- metric:u32_rrot16_checked_opcodes -->35<!-- /metric:u32_rrot16_checked_opcodes --> static non-push opcodes |
| `u32_popcount()` | <!-- metric:u32_popcount -->455<!-- /metric:u32_popcount --> bytes | <!-- metric:u32_popcount_witness -->13<!-- /metric:u32_popcount_witness --> bytes | <!-- metric:u32_popcount_stack -->262<!-- /metric:u32_popcount_stack --> items; <!-- metric:u32_popcount_opcodes -->171<!-- /metric:u32_popcount_opcodes --> static non-push opcodes |
| `u32_byte_popcounts()` | <!-- metric:u32_byte_popcounts -->452<!-- /metric:u32_byte_popcounts --> bytes | <!-- metric:u32_byte_popcounts_witness -->13<!-- /metric:u32_byte_popcounts_witness --> bytes | <!-- metric:u32_byte_popcounts_stack -->262<!-- /metric:u32_byte_popcounts_stack --> items; <!-- metric:u32_byte_popcounts_opcodes -->168<!-- /metric:u32_byte_popcounts_opcodes --> static non-push opcodes |
| `u32_byte_parity()` | <!-- metric:u32_byte_parity -->452<!-- /metric:u32_byte_parity --> bytes | <!-- metric:u32_byte_parity_witness -->13<!-- /metric:u32_byte_parity_witness --> bytes, 4 data items | <!-- metric:u32_byte_parity_stack -->262<!-- /metric:u32_byte_parity_stack --> items; <!-- metric:u32_byte_parity_opcodes -->168<!-- /metric:u32_byte_parity_opcodes --> static non-push opcodes |
| `u32_to_le_bits()` | <!-- metric:u32_le_bits -->514<!-- /metric:u32_le_bits --> bytes | <!-- metric:u32_le_bits_witness -->9<!-- /metric:u32_le_bits_witness --> bytes | <!-- metric:u32_le_bits_stack -->35<!-- /metric:u32_le_bits_stack --> items |
| `u32_to_bit_planes()` | <!-- metric:u32_bit_planes -->877<!-- /metric:u32_bit_planes --> bytes | <!-- metric:u32_bit_planes_witness -->9<!-- /metric:u32_bit_planes_witness --> bytes (<!-- metric:u32_bit_planes_witness_max -->13<!-- /metric:u32_bit_planes_witness_max --> max) | <!-- metric:u32_bit_planes_stack -->45<!-- /metric:u32_bit_planes_stack --> items; <!-- metric:u32_bit_planes_opcodes -->628<!-- /metric:u32_bit_planes_opcodes --> static non-push opcodes |
| `u32_to_le_bits_canonical()` | <!-- metric:u32_le_bits_canonical -->562<!-- /metric:u32_le_bits_canonical --> bytes | <!-- metric:u32_le_bits_canonical_witness -->9<!-- /metric:u32_le_bits_canonical_witness --> bytes (<!-- metric:u32_le_bits_canonical_witness_max -->13<!-- /metric:u32_le_bits_canonical_witness_max --> max) | <!-- metric:u32_le_bits_canonical_stack -->35<!-- /metric:u32_le_bits_canonical_stack --> items; <!-- metric:u32_le_bits_canonical_opcodes -->366<!-- /metric:u32_le_bits_canonical_opcodes --> static non-push opcodes |
| `zero::u32_iszero()` | <!-- metric:u32_zero -->61<!-- /metric:u32_zero --> bytes | <!-- metric:u32_zero_witness -->13<!-- /metric:u32_zero_witness --> bytes | <!-- metric:u32_zero_stack -->6<!-- /metric:u32_zero_stack --> items; <!-- metric:u32_zero_opcodes -->45<!-- /metric:u32_zero_opcodes --> static non-push opcodes |
| `u32_pick(2)` | <!-- metric:u32_pick_2 -->8<!-- /metric:u32_pick_2 --> bytes | <!-- metric:u32_pick_2_witness -->24<!-- /metric:u32_pick_2_witness --> bytes, 12 data items | <!-- metric:u32_pick_2_stack -->16<!-- /metric:u32_pick_2_stack --> items |

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

`u32_nand()` is a fused universal-gate adapter: it performs the existing
byte-table AND schedule and complements each result before restoring the word.
It does not allocate a second lookup table or materialize a separate NOT
fragment. Like the existing byte Boolean operations, it requires numeric byte
limbs in `0..=255`; callers handling hostile witness encodings must add the
canonical byte checks required by their protocol.

`u32_nor()` is the fused dual of the AND-based NAND adapter: it performs the
existing byte-table OR schedule and complements each result before restoring
the word. It requires numeric byte limbs in `0..=255`; hostile witness
encodings need the canonical byte checks required by their protocol.
The consuming `u32_{xor,and,or}_drop()` variants use the same table and
standalone fragment sizes as their preserving counterparts, but consume both
input words. Their representative combined peak is 268 items, four below the
preserving OR profile; callers that otherwise discard the preserved word also
avoid the extra word-routing fragment.

The canonical compressed-u32 row uses the maximum five-byte witness item for
`-2^31`. It is a raw-encoding boundary: `u32_uncompress()` remains available
for callers that intentionally accept ScriptNum aliases.
The nonnegative decoder is a domain-specialized alternative: it omits signed
normalization and the five-byte sentinel path, saving locking bytes while
rejecting the negative half of the compressed u32 domain.
The popcount table is separate from the Boolean XOR table. Its representative
32-bit all-ones witness uses four data items and serializes to 13 bytes; the
strict combined peak is 262 items. The table is generated once per fragment
and removed before the single numeric result is returned.

`u32_byte_popcounts()` keeps the four table results instead of adding them. It
is useful when a caller needs lane-local Hamming weights; use `u32_popcount()`
when only the total is needed. Its output preserves the four-byte word order
and remains a fragment rather than a terminal predicate. It uses the same
256-item table and strict 262-item peak, but omits the three final additions.

`u32_compressed_rshift(shift)` accepts one canonical compressed u32 ScriptNum
and performs a logical right shift for `shift` in `1..=31`. It validates the
wire encoding, separates the sign-carried high bit from a legal 31-bit
magnitude, and emits the compressed ScriptNum result. For shift 8, the direct
fragment is <!-- metric:u32_compressed_rshift_8 -->500<!-- /metric:u32_compressed_rshift_8 --> bytes with a <!-- metric:u32_compressed_rshift_8_witness -->6<!-- /metric:u32_compressed_rshift_8_witness -->-byte one-item witness and a <!-- metric:u32_compressed_rshift_8_stack -->5<!-- /metric:u32_compressed_rshift_8_stack -->-item peak. A decode-byte-shift-reencode baseline costs <!-- metric:u32_compressed_rshift_8_baseline -->499<!-- /metric:u32_compressed_rshift_8_baseline --> bytes and peaks at <!-- metric:u32_compressed_rshift_8_baseline_stack -->7<!-- /metric:u32_compressed_rshift_8_baseline_stack --> items; both measurements exclude input pushes and the terminal predicate.

`u32_compressed_lshift(shift)` accepts one canonical compressed u32 ScriptNum
and performs a modulo-`2^32` logical left shift for `shift` in `1..=31`. It
validates the wire encoding, discards the shifted-out sign-carried bit, and
re-encodes each doubled magnitude without leaving the four-byte expansion live.
For shift 8, the direct fragment is <!-- metric:u32_compressed_lshift_8 -->492<!-- /metric:u32_compressed_lshift_8 --> bytes with a <!-- metric:u32_compressed_lshift_8_witness -->6<!-- /metric:u32_compressed_lshift_8_witness -->-byte one-item witness and a <!-- metric:u32_compressed_lshift_8_stack -->5<!-- /metric:u32_compressed_lshift_8_stack -->-item peak. A decode-byte-shift-reencode baseline costs <!-- metric:u32_compressed_lshift_8_baseline -->490<!-- /metric:u32_compressed_lshift_8_baseline --> bytes and peaks at <!-- metric:u32_compressed_lshift_8_baseline_stack -->7<!-- /metric:u32_compressed_lshift_8_baseline_stack --> items; both measurements exclude input pushes and the terminal predicate.

## Security

There is no independent cryptographic security parameter. Arithmetic is exact
only for byte limbs in `0..=255`; callers accepting adversarial witness values
must enforce limb range and canonical Script-number encoding where required.
The conditional selector normalizes any numeric truthy/falsy condition before
`OP_IF`, so it does not rely on non-minimal tapscript branch values.

`u32_popcount` performs the byte range checks itself because unchecked values
would address outside the popcount table. Its output is a numeric ScriptNum,
not a four-byte word or a terminal predicate.
`u32_rrot8_checked()` adds the raw ScriptNum boundary for hostile byte limbs
and then reuses the three-opcode byte rotation; it does not add a cryptographic
security claim or a terminal predicate.

`u32_rshift8_checked()` is the byte-aligned member of the logical right-shift
frontier. It reuses canonical byte validation, moves only three retained bytes
through the alt stack, inserts a zero most-significant byte, and avoids the
shared lookup table required by the generic bitwise shift helper. It has no
auxiliary hints and remains a fragment rather than a complete locking script.
On the same fragment boundary, the existing generic `u32_shr(8, 2)` path with
XOR-table setup and cleanup measures 561 bytes, 420 static non-push opcodes,
and a 272-item peak; this checked direct path measures 62 bytes, 41 opcodes,
and a 7-item peak. Both use four data items and no auxiliary hints, while the
generic path additionally keeps its 256-item table live during execution.

`u32_lshift8_checked()` is the byte-aligned left-shift counterpart to the
generic bitwise shift family. It drops the most-significant byte, inserts zero
at the least-significant end, and preserves unrelated stack state. It has no
auxiliary hints and remains a fragment rather than a complete locking script.

`u32_byte_parity` uses the same 256-entry byte table but returns the four
per-byte parity bits instead of summing them. It is useful when downstream
logic needs byte-local parity and would otherwise expand or rescan the word.

`u32_rrot16_checked()` is a narrow hostile-witness boundary for the existing
one-opcode sixteen-bit byte permutation. It rejects noncanonical ScriptNum
aliases before moving the four bytes through the alt stack, then leaves the
same four-byte word representation as `u32_rrot16()`. The representative
fixture uses four data items and no hints; its strict local tapscript result is
<!-- metric:u32_rrot16_checked -->55<!-- /metric:u32_rrot16_checked --> locking bytes,
<!-- metric:u32_rrot16_checked_stack -->7<!-- /metric:u32_rrot16_checked_stack --> stack items,
and <!-- metric:u32_rrot16_checked_opcodes -->35<!-- /metric:u32_rrot16_checked_opcodes --> static non-push opcodes.
This is locally reproduced and unclassified; it is not a consensus or relay
policy claim.

`u32_iszero` performs the byte range checks itself, then combines the four
byte-wise zero predicates without a lookup table. It returns a numeric Boolean
and does not provide a clean-stack or terminal-script wrapper.

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

`u32_compressed_lessthan_constant()` keeps the left operand as one hostile
witness item and embeds the right threshold. It preserves the signed
compressed encoding of values at and above `0x80000000`, so the threshold is
not silently treated as a positive ScriptNum. It removes one data item from
the two-item compressed comparison at the cost of a small wrapper and is
useful for fixed range gates.

## Bit conversion

`u32_to_le_bits()` consumes one u32 word and returns 32 numeric bit items. The
least-significant byte is on top of the input word; its bit zero is on top of
the output, followed by bits one through seven and then the next byte. Each
byte is range-checked numerically against `0..=255`. The 514-byte fragment has
<!-- metric:u32_le_bits_opcodes -->338<!-- /metric:u32_le_bits_opcodes --> static non-push opcodes and a 35-item local peak with four one-byte witness
items; it does not establish byte-unique ScriptNum encodings.
This is a byte-input adapter rather than a replacement for the smaller
nibble-input table when a caller already owns canonical u4 values.
`u32_to_le_bits_canonical()` adds four raw-encoding checks before reusing the
same splitter. It rejects aliases such as redundant positive signs and
negative zero, costing only the explicit canonicality boundary; use the
unchecked form when byte-unique witness encoding is already guaranteed.

`u32_to_bit_planes()` transposes the four checked bytes into eight numeric
nibbles. Each plane packs the corresponding bit from the four input bytes,
with the most-significant input byte as the plane's high bit; plane zero is on
the bottom of the returned stack and plane seven is on top. It reuses the
byte-to-bit conversion and a fixed-depth routing pass, so it trades 877 locking bytes and a 45-item local peak
for eight composable nibble items rather than 32 individual bits.

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

`u32_to_zero_byte_mask()` consumes the four canonical byte limbs and returns a
numeric mask in `0..=15`; bit `i` corresponds to the word's `i`th byte in the
normal MSB-first representation. Its representative four-item all-`0xff`
witness is 13 serialized bytes, and the 67-byte fragment peaks at 8 combined
items and contains
<!-- metric:u32_zero_byte_mask_opcodes -->46<!-- /metric:u32_zero_byte_mask_opcodes -->
static non-push opcodes. It costs four more stack items than `u32_iszero()` because it preserves
per-byte information instead of folding to one aggregate predicate.

`u32_byte_eq_mask()` consumes two words and validates all eight byte limbs,
including their minimal ScriptNum encodings, before comparing corresponding
lanes. It returns `8*eq(byte[0]) + 4*eq(byte[1]) + 2*eq(byte[2]) +
eq(byte[3])`. The representative strict fragment is
<!-- metric:u32_byte_eq_mask -->149<!-- /metric:u32_byte_eq_mask --> bytes, has a
<!-- metric:u32_byte_eq_mask_stack -->11<!-- /metric:u32_byte_eq_mask_stack -->-item
combined peak, and contains <!-- metric:u32_byte_eq_mask_opcodes -->100<!-- /metric:u32_byte_eq_mask_opcodes -->
static non-push opcodes. Its representative witness has eight data items and
<!-- metric:u32_byte_eq_mask_witness -->17<!-- /metric:u32_byte_eq_mask_witness -->
serialized bytes (<!-- metric:u32_byte_eq_mask_witness_max -->25<!-- /metric:u32_byte_eq_mask_witness_max -->
at the all-`0xff` maximum); it uses zero hint items. The whole-word equality
baseline is <!-- metric:u32_byte_eq_mask_equal_baseline -->18<!-- /metric:u32_byte_eq_mask_equal_baseline -->
bytes, so the mask deliberately pays for four independently addressable lane
predicates rather than improving aggregate equality.

`u32_byte_lessthan_mask()` consumes two words and validates all eight byte
limbs, including their minimal ScriptNum encodings, before comparing
corresponding lanes. It returns `8*(a[0] < b[0]) + 4*(a[1] < b[1]) +
2*(a[2] < b[2]) + (a[3] < b[3])`. The representative strict fragment is
<!-- metric:u32_byte_less_mask -->149<!-- /metric:u32_byte_less_mask --> bytes,
has a <!-- metric:u32_byte_less_mask_stack -->11<!-- /metric:u32_byte_less_mask_stack -->-item
combined peak, and contains <!-- metric:u32_byte_less_mask_opcodes -->100<!-- /metric:u32_byte_less_mask_opcodes -->
static non-push opcodes. Its representative witness has eight data items and
<!-- metric:u32_byte_less_mask_witness -->17<!-- /metric:u32_byte_less_mask_witness -->
serialized bytes (<!-- metric:u32_byte_less_mask_witness_max -->25<!-- /metric:u32_byte_less_mask_witness_max -->
at the all-`0xff` maximum); it uses zero hint items. The whole-word
`u32_lessthan()` baseline is <!-- metric:u32_byte_less_mask_less_baseline -->38<!-- /metric:u32_byte_less_mask_less_baseline -->
bytes, so the mask is a lane-information primitive rather than a cheaper
word comparison.

The zero-word fixture uses 5 serialized witness bytes; the maximum canonical byte-word witness is <!-- metric:u32_iszero_witness_max -->13<!-- /metric:u32_iszero_witness_max --> bytes. The little-endian bit fixture uses four `0x42` limbs (9 bytes), with a maximum canonical witness of <!-- metric:u32_le_bits_witness_max -->13<!-- /metric:u32_le_bits_witness_max --> bytes. These focused metrics use strict local tapscript execution; deployment remains `unclassified`.

`u32_leading_zero_bytes()` validates and consumes the four byte limbs from
most significant to least significant, stopping its count at the first
nonzero byte while dropping the remaining limbs. It is table-free and useful
for prefix-length or wire-format decisions; it does not replace a terminal
predicate or establish a complete u32 encoding on its own.

`u32_trailing_zero_bytes()` validates all four byte limbs while counting from
the least significant byte, which is the top limb in the module's stack order.
It is table-free and useful for suffix-length or little-endian wire-format
decisions; it does not provide a terminal predicate or a complete encoding
check for the surrounding script.

`u32_extract_byte(index)` validates all four byte limbs before routing the
selected lane to the output. It is a consuming adapter for byte-oriented
parsers and wire formats; the caller still owns any terminal predicate and
clean-stack rule.

`u32_msb_mask()` checks all four canonical byte limbs, extracts their high
bits, and packs them as `8*msb(byte[0]) + 4*msb(byte[1]) +
2*msb(byte[2]) + msb(byte[3])`. The representative fixture uses four
`0x42` data items and zero hints. Unlike `u32_to_le_bits()`, it materializes
only the four routing bits; the bit-expansion baseline is
<!-- metric:u32_msb_mask_bit_projection_baseline -->514<!-- /metric:u32_msb_mask_bit_projection_baseline --> bytes.
