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
- `xor_reduce::u4_nibbles_to_xor(nibble_count)` takes a checked batch size in
  `1..=742` and reduces the batch to one nibble with the full XOR table.
- `popcount::u4_nibbles_to_popcount(nibble_count)` takes a checked batch size
  in `1..=982` and returns one Hamming weight in `0..=4` per input nibble.
- `popcount::u4_popcount(nibble_count)` takes the same checked batch (up to 982
  items without unrelated live state) and returns one total Hamming weight in
  `0..=4*nibble_count`.
- `pack::u4_nibbles_to_bytes(nibble_count)` takes an even checked batch size in
  `2..=664` and returns one byte per high/low nibble pair.
- `adjacent_delta::u4_nibbles_to_adjacent_delta(nibble_count)` takes a checked
  batch size in `2..=499` and returns one forward modulo-16 delta per edge.
- `vector_rotate::u4_nibbles_rotate_left(nibble_count)` takes a checked batch
  size in `1..=499` and cyclically moves the first nibble to the top.
- `interleave::u4_nibbles_interleave(width)` takes two checked vectors of equal
  width in `1..=249` and alternates their items.
- `gray::u4_nibbles_to_gray(nibble_count)` takes a checked batch size in
  `1..=982` and projects each nibble to reflected Gray code.
- `one_hot::u4_nibbles_to_one_hot(nibble_count)` takes a checked batch size in
  `1..=982` and returns one 16-bit selector mask per input nibble.
- `trailing_zeros::u4_nibbles_to_trailing_zeros(nibble_count)` maps checked
  nibbles to their trailing-zero count in `0..=4`.
- `lowbit::u4_nibbles_to_lowbit(nibble_count)` maps checked nibbles to their
  lowest set bit, returning `0`, `1`, `2`, `4`, or `8`.
- `gray_inverse::u4_nibbles_from_gray(nibble_count)` decodes checked four-bit
  reflected-Gray values using a 16-item lookup table.
- `power_of_two::u4_nibbles_to_power_of_two(nibble_count)` maps checked nibbles
  to a bit indicating whether each is a nonzero power of two.
- `lsb::u4_nibbles_to_lsb(nibble_count)` takes a checked batch size in
  `1..=982` and returns one bit per input nibble; the range check does not
  establish canonical ScriptNum encoding.
- `sum::u4_nibbles_to_sum_mod16(nibble_count)` takes a checked batch size in
  `1..=965` and returns the batch sum modulo 16.
- `zero_bitmask::u4_nibbles_to_zero_bitmasks(nibble_count)` takes a checked
  multiple of eight in `8..=992` and returns one byte mask per eight nibbles.
- `nondecreasing::u4_nibbles_nondecreasing(nibble_count)` takes a checked
  batch size in `1..=997` and returns one monotonicity bit.
- `sum::u4_nibbles_sum_exact(nibble_count)` takes a checked batch size in
  `1..=997` and returns the exact sum in `0..=15*nibble_count`.
- `mirror::u4_nibbles_to_mirror(nibble_count)` canonicalizes each nibble under
  complement reflection to the range `0..=7`.
- `leading_zeros::u4_nibbles_to_leading_zeros(nibble_count)` maps checked
  nibbles to their four-bit leading-zero count in `0..=4`.
- `mod3::u4_nibbles_to_mod3(nibble_count)` maps checked nibbles to residues in
  `0..=2` using a 16-item lookup table.
- `bit_planes::u4_nibbles_to_bit_planes(nibble_count, check_inputs)` reuses
  checked nibble decomposition and transposes batches up to 234 nibbles.
- `bit_planes::u4_nibbles_to_bit_planes_canonical(nibble_count)` additionally
  rejects non-minimal ScriptNum encodings before transposing the batch.
- `bit_reverse::u4_nibbles_to_bit_reverse(nibble_count)` checks and reverses
  each nibble in a shared 16-item lookup table.
- `stack::u4_triplet_to_u12(check_inputs)` packs `high | middle | low` into a
  12-bit ScriptNum, checking all three inputs when requested.
- `stack::u4_quad_to_u16(check_inputs)` packs four nibbles into a 16-bit
  ScriptNum, checking all inputs when requested.
- `mul_constant::u4_mul_constant_mod16()` checks one u4 input and queries a
  reusable 16-item table generated for a public compile-time constant.
- `square::u4_square_mod16()` checks one u4 input and queries a reusable
  16-item table for its square modulo 16.
- `centered::u4_nibbles_to_centered(nibble_count)` maps checked nibbles to
  centered signed digits in `-8..=7`.
- `bit_transitions::u4_nibbles_to_bit_transitions(nibble_count)` maps checked
  nibbles to the number of changes across their three internal bit boundaries.
- `bits::u4_nibbles_to_be_bits[_toaltstack](nibble_count, check_inputs)` and
  `bits::u4_nibbles_to_le_bits[_toaltstack](nibble_count, check_inputs)` take
  an explicit batch size in `1..=234` and have no default for input checking.
- `bits::u4_nibbles_to_le_bits_canonical(nibble_count)` additionally rejects
  non-minimal ScriptNum encodings before little-endian decomposition.
- `bits::u4_nibbles_to_be_bits_canonical(nibble_count)` additionally rejects
  non-minimal ScriptNum encodings before big-endian decomposition.
- `bits::u4_nibbles_to_be_bits_toaltstack_canonical(nibble_count)` validates
  raw ScriptNum encoding and leaves big-endian output on the altstack.
- `bits::u4_nibbles_to_le_bits_toaltstack_canonical(nibble_count)` validates
  raw ScriptNum encoding and leaves little-endian output on the altstack.

## Script metrics

These are serialized locking-script fragments. Operand pushes and witness
serialization are excluded. The 32-nibble main-stack bit-conversion rows
include table setup, all queries, table cleanup, and restoration of 128 output
bits to the main stack. The altstack row ends at the reusable altstack output
boundary. The branch baseline applies the existing four-bit limb splitter to
each input with the same output-restoration boundary.

| Fragment | Locking script | Maximum combined stack | Static non-push opcodes |
| --- | ---: | ---: | ---: |
| `u4_push_add_tables()` | <!-- metric:u4_add_tables -->92<!-- /metric:u4_add_tables --> bytes | instance-specific | not recorded |
| Staggered bit-table setup | <!-- metric:u4_bits_table_push -->61<!-- /metric:u4_bits_table_push --> bytes | 61 table items | not recorded |
| Staggered bit-table cleanup | <!-- metric:u4_bits_table_drop -->31<!-- /metric:u4_bits_table_drop --> bytes | consumes 61 items | not recorded |
| One checked table query, output on altstack | <!-- metric:u4_bits_checked_query -->22<!-- /metric:u4_bits_checked_query --> bytes | composition-dependent | not recorded |
| Little-endian staggered bit-table setup | <!-- metric:u4_bits_le_table_push -->61<!-- /metric:u4_bits_le_table_push --> bytes | 61 table items | not recorded |
| Checked table batch, 32 nibbles | <!-- metric:u4_bits_checked_batch32 -->924<!-- /metric:u4_bits_checked_batch32 --> bytes | <!-- metric:u4_bits_checked_batch32_stack -->189<!-- /metric:u4_bits_checked_batch32_stack --> items | <!-- metric:u4_bits_checked_batch32_opcodes -->735<!-- /metric:u4_bits_checked_batch32_opcodes --> |
| Canonical checked table batch, 32 nibbles | <!-- metric:u4_bits_canonical_batch32 -->1306<!-- /metric:u4_bits_canonical_batch32 --> bytes | <!-- metric:u4_bits_canonical_batch32_stack -->189<!-- /metric:u4_bits_canonical_batch32_stack --> items | <!-- metric:u4_bits_canonical_batch32_opcodes -->1021<!-- /metric:u4_bits_canonical_batch32_opcodes --> |
| Canonical checked altstack batch, 32 nibbles | <!-- metric:u4_bits_be_alt_canonical_batch32 -->1178<!-- /metric:u4_bits_be_alt_canonical_batch32 --> bytes | <!-- metric:u4_bits_be_alt_canonical_batch32_stack -->189<!-- /metric:u4_bits_be_alt_canonical_batch32_stack --> items | <!-- metric:u4_bits_be_alt_canonical_batch32_opcodes -->893<!-- /metric:u4_bits_be_alt_canonical_batch32_opcodes --> |
| Checked little-endian table batch, 32 nibbles | <!-- metric:u4_bits_le_checked_batch32 -->924<!-- /metric:u4_bits_le_checked_batch32 --> bytes | <!-- metric:u4_bits_le_checked_batch32_stack -->189<!-- /metric:u4_bits_le_checked_batch32_stack --> items | <!-- metric:u4_bits_le_checked_batch32_opcodes -->735<!-- /metric:u4_bits_le_checked_batch32_opcodes --> |
| Canonical checked little-endian table batch, 32 nibbles | <!-- metric:u4_bits_le_canonical_batch32 -->1306<!-- /metric:u4_bits_le_canonical_batch32 --> bytes | <!-- metric:u4_bits_le_canonical_batch32_stack -->189<!-- /metric:u4_bits_le_canonical_batch32_stack --> items | <!-- metric:u4_bits_le_canonical_batch32_opcodes -->1021<!-- /metric:u4_bits_le_canonical_batch32_opcodes --> |
| Canonical checked little-endian altstack batch, 32 nibbles | <!-- metric:u4_bits_le_alt_canonical_batch32 -->1178<!-- /metric:u4_bits_le_alt_canonical_batch32 --> bytes | <!-- metric:u4_bits_le_alt_canonical_batch32_stack -->189<!-- /metric:u4_bits_le_alt_canonical_batch32_stack --> items | <!-- metric:u4_bits_le_alt_canonical_batch32_opcodes -->893<!-- /metric:u4_bits_le_alt_canonical_batch32_opcodes --> |
| Unchecked table batch, 32 nibbles | <!-- metric:u4_bits_unchecked_batch32 -->764<!-- /metric:u4_bits_unchecked_batch32 --> bytes | 189 items | not recorded |
| Existing branch splitter, 32 four-bit limbs | <!-- metric:u4_bits_branch_batch32 -->1374<!-- /metric:u4_bits_branch_batch32 --> bytes | <!-- metric:u4_bits_branch_batch32_stack -->130<!-- /metric:u4_bits_branch_batch32_stack --> items | not recorded |
| Checked high/low nibble pair to one byte | <!-- metric:u4_pair_to_u8_checked -->20<!-- /metric:u4_pair_to_u8_checked --> bytes | <!-- metric:u4_pair_to_u8_checked_stack -->5<!-- /metric:u4_pair_to_u8_checked_stack --> items | not recorded |
| Checked high/middle/low nibble triplet to u12 | <!-- metric:u4_triplet_to_u12_checked -->44<!-- /metric:u4_triplet_to_u12_checked --> bytes | <!-- metric:u4_triplet_to_u12_checked_stack -->6<!-- /metric:u4_triplet_to_u12_checked_stack --> items | not recorded |
| Checked high/high-middle/low-middle/low nibble quad to u16 | <!-- metric:u4_quad_to_u16_checked -->76<!-- /metric:u4_quad_to_u16_checked --> bytes | <!-- metric:u4_quad_to_u16_checked_stack -->7<!-- /metric:u4_quad_to_u16_checked_stack --> items | not recorded |
| Checked byte to high/low nibble pair | <!-- metric:u8_to_u4_pair_checked -->62<!-- /metric:u8_to_u4_pair_checked --> bytes | <!-- metric:u8_to_u4_pair_checked_stack -->4<!-- /metric:u8_to_u4_pair_checked_stack --> items | not recorded |
| `verify_canonical_nibble()` | <!-- metric:u4_canonical_nibble -->10<!-- /metric:u4_canonical_nibble --> bytes | <!-- metric:u4_canonical_nibble_stack -->4<!-- /metric:u4_canonical_nibble_stack --> items | not recorded |
| `lexicographic_le(128)` | <!-- metric:u4_lexicographic_le_128 -->7500<!-- /metric:u4_lexicographic_le_128 --> bytes | <!-- metric:u4_lexicographic_le_128_stack -->259<!-- /metric:u4_lexicographic_le_128_stack --> items | <!-- metric:u4_lexicographic_le_128_opcodes -->4354<!-- /metric:u4_lexicographic_le_128_opcodes --> |
| `lexicographic_le_constant(128)` | <!-- metric:u4_lexicographic_le_constant_128 -->7628<!-- /metric:u4_lexicographic_le_constant_128 --> bytes | <!-- metric:u4_lexicographic_le_constant_128_stack -->259<!-- /metric:u4_lexicographic_le_constant_128_stack --> items | <!-- metric:u4_lexicographic_le_constant_128_opcodes -->4354<!-- /metric:u4_lexicographic_le_constant_128_opcodes --> |
| Checked parity batch, 32 nibbles | <!-- metric:u4_parity_batch32 -->440<!-- /metric:u4_parity_batch32 --> bytes | <!-- metric:u4_parity_batch32_stack -->50<!-- /metric:u4_parity_batch32_stack --> items | <!-- metric:u4_parity_batch32_opcodes -->328<!-- /metric:u4_parity_batch32_opcodes --> |
| Checked XOR reduction, 16 nibbles | <!-- metric:u4_xor_reduce_batch16 -->740<!-- /metric:u4_xor_reduce_batch16 --> bytes | <!-- metric:u4_xor_reduce_batch16_stack -->273<!-- /metric:u4_xor_reduce_batch16_stack --> items | <!-- metric:u4_xor_reduce_batch16_opcodes -->438<!-- /metric:u4_xor_reduce_batch16_opcodes --> |
| Checked nondecreasing batch, 32 nibbles | <!-- metric:u4_nondecreasing_batch32 -->588<!-- /metric:u4_nondecreasing_batch32 --> bytes | <!-- metric:u4_nondecreasing_batch32_stack -->35<!-- /metric:u4_nondecreasing_batch32_stack --> items | <!-- metric:u4_nondecreasing_batch32_opcodes -->391<!-- /metric:u4_nondecreasing_batch32_opcodes --> |
| Checked exact-sum batch, 32 nibbles | <!-- metric:u4_exact_sum_batch32 -->489<!-- /metric:u4_exact_sum_batch32 --> bytes | <!-- metric:u4_exact_sum_batch32_stack -->35<!-- /metric:u4_exact_sum_batch32_stack --> items | <!-- metric:u4_exact_sum_batch32_opcodes -->334<!-- /metric:u4_exact_sum_batch32_opcodes --> |
| Checked 32-nibble batch pack | <!-- metric:u4_pack_batch32 -->442<!-- /metric:u4_pack_batch32 --> bytes | <!-- metric:u4_pack_batch32_stack -->52<!-- /metric:u4_pack_batch32_stack --> items | <!-- metric:u4_pack_batch32_opcodes -->334<!-- /metric:u4_pack_batch32_opcodes --> |
| Checked adjacent modulo-16 delta batch, 32 nibbles | <!-- metric:u4_adjacent_delta_batch32 -->806<!-- /metric:u4_adjacent_delta_batch32 --> bytes | <!-- metric:u4_adjacent_delta_batch32_stack -->65<!-- /metric:u4_adjacent_delta_batch32_stack --> items | <!-- metric:u4_adjacent_delta_batch32_opcodes -->547<!-- /metric:u4_adjacent_delta_batch32_opcodes --> |
| Checked cyclic left rotation, 32 nibbles | <!-- metric:u4_vector_rotate_batch32 -->457<!-- /metric:u4_vector_rotate_batch32 --> bytes | <!-- metric:u4_vector_rotate_batch32_stack -->64<!-- /metric:u4_vector_rotate_batch32_stack --> items | <!-- metric:u4_vector_rotate_batch32_opcodes -->303<!-- /metric:u4_vector_rotate_batch32_opcodes --> |
| Checked 32-wide vector interleave | <!-- metric:u4_interleave_batch32 -->954<!-- /metric:u4_interleave_batch32 --> bytes | <!-- metric:u4_interleave_batch32_stack -->128<!-- /metric:u4_interleave_batch32_stack --> items | <!-- metric:u4_interleave_batch32_opcodes -->608<!-- /metric:u4_interleave_batch32_opcodes --> |
| Checked reflected-Gray batch, 32 nibbles | <!-- metric:u4_gray_batch32 -->440<!-- /metric:u4_gray_batch32 --> bytes | <!-- metric:u4_gray_batch32_stack -->50<!-- /metric:u4_gray_batch32_stack --> items | <!-- metric:u4_gray_batch32_opcodes -->328<!-- /metric:u4_gray_batch32_opcodes --> |
| Checked one-hot batch, 32 nibbles | <!-- metric:u4_one_hot_batch32 -->461<!-- /metric:u4_one_hot_batch32 --> bytes | <!-- metric:u4_one_hot_batch32_stack -->50<!-- /metric:u4_one_hot_batch32_stack --> items | <!-- metric:u4_one_hot_batch32_opcodes -->328<!-- /metric:u4_one_hot_batch32_opcodes --> |
| Checked centered-signed batch, 32 nibbles | <!-- metric:u4_centered_batch32 -->447<!-- /metric:u4_centered_batch32 --> bytes | <!-- metric:u4_centered_batch32_stack -->50<!-- /metric:u4_centered_batch32_stack --> items | <!-- metric:u4_centered_batch32_opcodes -->328<!-- /metric:u4_centered_batch32_opcodes --> |
| Checked reflected-domain batch, 32 nibbles | <!-- metric:u4_mirror_batch32 -->440<!-- /metric:u4_mirror_batch32 --> bytes | <!-- metric:u4_mirror_batch32_stack -->50<!-- /metric:u4_mirror_batch32_stack --> items | <!-- metric:u4_mirror_batch32_opcodes -->328<!-- /metric:u4_mirror_batch32_opcodes --> |
| Checked leading-zero batch, 32 nibbles | <!-- metric:u4_leading_zeros_batch32 -->440<!-- /metric:u4_leading_zeros_batch32 --> bytes | <!-- metric:u4_leading_zeros_batch32_stack -->50<!-- /metric:u4_leading_zeros_batch32_stack --> items | <!-- metric:u4_leading_zeros_batch32_opcodes -->328<!-- /metric:u4_leading_zeros_batch32_opcodes --> |
| Checked bit-transition batch, 32 nibbles | <!-- metric:u4_bit_transitions_batch32 -->440<!-- /metric:u4_bit_transitions_batch32 --> bytes | <!-- metric:u4_bit_transitions_batch32_stack -->50<!-- /metric:u4_bit_transitions_batch32_stack --> items | <!-- metric:u4_bit_transitions_batch32_opcodes -->328<!-- /metric:u4_bit_transitions_batch32_opcodes --> |
| Checked trailing-zero batch, 32 nibbles | <!-- metric:u4_trailing_zeros_batch32 -->440<!-- /metric:u4_trailing_zeros_batch32 --> bytes | <!-- metric:u4_trailing_zeros_batch32_stack -->50<!-- /metric:u4_trailing_zeros_batch32_stack --> items | <!-- metric:u4_trailing_zeros_batch32_opcodes -->328<!-- /metric:u4_trailing_zeros_batch32_opcodes --> |
| Checked lowest-set-bit batch, 32 nibbles | <!-- metric:u4_lowbit_batch32 -->440<!-- /metric:u4_lowbit_batch32 --> bytes | <!-- metric:u4_lowbit_batch32_stack -->50<!-- /metric:u4_lowbit_batch32_stack --> items | <!-- metric:u4_lowbit_batch32_opcodes -->328<!-- /metric:u4_lowbit_batch32_opcodes --> |
| Checked inverse-Gray batch, 32 nibbles | <!-- metric:u4_gray_inverse_batch32 -->440<!-- /metric:u4_gray_inverse_batch32 --> bytes | <!-- metric:u4_gray_inverse_batch32_stack -->50<!-- /metric:u4_gray_inverse_batch32_stack --> items | <!-- metric:u4_gray_inverse_batch32_opcodes -->328<!-- /metric:u4_gray_inverse_batch32_opcodes --> |
| Checked power-of-two batch, 32 nibbles | <!-- metric:u4_power_of_two_batch32 -->440<!-- /metric:u4_power_of_two_batch32 --> bytes | <!-- metric:u4_power_of_two_batch32_stack -->50<!-- /metric:u4_power_of_two_batch32_stack --> items | <!-- metric:u4_power_of_two_batch32_opcodes -->328<!-- /metric:u4_power_of_two_batch32_opcodes --> |
| Checked modulo-three batch, 32 nibbles | <!-- metric:u4_mod3_batch32 -->440<!-- /metric:u4_mod3_batch32 --> bytes | <!-- metric:u4_mod3_batch32_stack -->50<!-- /metric:u4_mod3_batch32_stack --> items | <!-- metric:u4_mod3_batch32_opcodes -->328<!-- /metric:u4_mod3_batch32_opcodes --> |
| Checked LSB batch, 32 nibbles | <!-- metric:u4_lsb_batch32 -->440<!-- /metric:u4_lsb_batch32 --> bytes | <!-- metric:u4_lsb_batch32_stack -->50<!-- /metric:u4_lsb_batch32_stack --> items | <!-- metric:u4_lsb_batch32_opcodes -->328<!-- /metric:u4_lsb_batch32_opcodes --> |
| Checked zero-mask batch, 32 nibbles | <!-- metric:u4_zero_mask_batch32 -->414<!-- /metric:u4_zero_mask_batch32 --> bytes | <!-- metric:u4_zero_mask_batch32_stack -->35<!-- /metric:u4_zero_mask_batch32_stack --> items | <!-- metric:u4_zero_mask_batch32_opcodes -->318<!-- /metric:u4_zero_mask_batch32_opcodes --> |
| Checked popcount batch, 32 nibbles | <!-- metric:u4_popcount_batch32 -->440<!-- /metric:u4_popcount_batch32 --> bytes | <!-- metric:u4_popcount_batch32_stack -->50<!-- /metric:u4_popcount_batch32_stack --> items | <!-- metric:u4_popcount_batch32_opcodes -->328<!-- /metric:u4_popcount_batch32_opcodes --> |
| Checked total popcount, 32 nibbles | <!-- metric:u4_popcount_total_batch32 -->471<!-- /metric:u4_popcount_total_batch32 --> bytes | <!-- metric:u4_popcount_total_batch32_stack -->50<!-- /metric:u4_popcount_total_batch32_stack --> items | <!-- metric:u4_popcount_total_batch32_opcodes -->359<!-- /metric:u4_popcount_total_batch32_opcodes --> |
| Checked 32-nibble zero bitmask batch | <!-- metric:u4_zero_bitmask_batch32 -->482<!-- /metric:u4_zero_bitmask_batch32 --> bytes | <!-- metric:u4_zero_bitmask_batch32_stack -->36<!-- /metric:u4_zero_bitmask_batch32_stack --> items | <!-- metric:u4_zero_bitmask_batch32_opcodes -->382<!-- /metric:u4_zero_bitmask_batch32_opcodes --> |
| Checked 16-nibble bit-plane transpose | <!-- metric:u4_bit_planes_batch16 -->776<!-- /metric:u4_bit_planes_batch16 --> bytes | <!-- metric:u4_bit_planes_batch16_stack -->125<!-- /metric:u4_bit_planes_batch16_stack --> items | <!-- metric:u4_bit_planes_batch16_opcodes -->573<!-- /metric:u4_bit_planes_batch16_opcodes --> |
| Canonical checked 16-nibble bit-plane transpose | <!-- metric:u4_bit_planes_canonical_batch16 -->966<!-- /metric:u4_bit_planes_canonical_batch16 --> bytes | <!-- metric:u4_bit_planes_canonical_batch16_stack -->125<!-- /metric:u4_bit_planes_canonical_batch16_stack --> items | <!-- metric:u4_bit_planes_canonical_batch16_opcodes -->715<!-- /metric:u4_bit_planes_canonical_batch16_opcodes --> |
| Checked 32-nibble bit reversal | <!-- metric:u4_bit_reverse_batch32 -->344<!-- /metric:u4_bit_reverse_batch32 --> bytes | <!-- metric:u4_bit_reverse_batch32_stack -->51<!-- /metric:u4_bit_reverse_batch32_stack --> items | <!-- metric:u4_bit_reverse_batch32_opcodes -->232<!-- /metric:u4_bit_reverse_batch32_opcodes --> |
| Checked modulo-16 sum, 32 nibbles | <!-- metric:u4_sum_mod16_batch32 -->592<!-- /metric:u4_sum_mod16_batch32 --> bytes | <!-- metric:u4_sum_mod16_batch32_stack -->66<!-- /metric:u4_sum_mod16_batch32_stack --> items | <!-- metric:u4_sum_mod16_batch32_opcodes -->400<!-- /metric:u4_sum_mod16_batch32_opcodes --> |
| Checked constant multiplication query, `c=10` | <!-- metric:u4_mul_constant_mod16 -->6<!-- /metric:u4_mul_constant_mod16 --> bytes | <!-- metric:u4_mul_constant_mod16_stack -->20<!-- /metric:u4_mul_constant_mod16_stack --> items | <!-- metric:u4_mul_constant_mod16_opcodes -->4<!-- /metric:u4_mul_constant_mod16_opcodes --> |
| Checked u4 square query modulo 16 | <!-- metric:u4_square_mod16 -->6<!-- /metric:u4_square_mod16 --> bytes | <!-- metric:u4_square_mod16_stack -->20<!-- /metric:u4_square_mod16_stack --> items | <!-- metric:u4_square_mod16_opcodes -->4<!-- /metric:u4_square_mod16_opcodes --> |
| Canonical checked 32-nibble bit reversal | <!-- metric:u4_bit_reverse_canonical_batch32 -->504<!-- /metric:u4_bit_reverse_canonical_batch32 --> bytes | <!-- metric:u4_bit_reverse_canonical_batch32_stack -->51<!-- /metric:u4_bit_reverse_canonical_batch32_stack --> items | <!-- metric:u4_bit_reverse_canonical_batch32_opcodes -->360<!-- /metric:u4_bit_reverse_canonical_batch32_opcodes --> |

The constant multiplication row measures only the checked reusable query;
the generated 16-item table setup is <!-- metric:u4_mul_constant_mod16_table -->16<!-- /metric:u4_mul_constant_mod16_table --> bytes and can be shared across queries. The representative witness is
<!-- metric:u4_mul_constant_mod16_witness -->3<!-- /metric:u4_mul_constant_mod16_witness --> serialized bytes for one input item and has zero incremental hint items.

The square row measures only the checked reusable query; its generated
16-item table setup is <!-- metric:u4_square_mod16_table -->16<!-- /metric:u4_square_mod16_table --> bytes and can be shared across square queries. The representative witness is
<!-- metric:u4_square_mod16_witness -->3<!-- /metric:u4_square_mod16_witness --> serialized bytes for one input item and has zero incremental hint items.

<!-- metric:u4_popcount_batch32_witness -->65<!-- /metric:u4_popcount_batch32_witness --> serialized witness bytes for the representative checked popcount batch.

<!-- metric:u4_popcount_total_batch32_witness -->65<!-- /metric:u4_popcount_total_batch32_witness --> serialized witness bytes for the representative checked total-popcount batch.


<!-- metric:u4_parity_batch32_witness -->65<!-- /metric:u4_parity_batch32_witness --> serialized witness bytes for the representative parity batch.

<!-- metric:u4_nondecreasing_batch32_witness -->65<!-- /metric:u4_nondecreasing_batch32_witness --> serialized witness bytes for the representative nondecreasing batch.

<!-- metric:u4_exact_sum_batch32_witness -->65<!-- /metric:u4_exact_sum_batch32_witness --> serialized witness bytes for the representative exact-sum batch.

<!-- metric:u4_pack_batch32_witness -->65<!-- /metric:u4_pack_batch32_witness --> serialized witness bytes for the representative packed batch.

<!-- metric:u4_gray_batch32_witness -->65<!-- /metric:u4_gray_batch32_witness --> serialized witness bytes for the representative Gray-code batch.

<!-- metric:u4_one_hot_batch32_witness -->65<!-- /metric:u4_one_hot_batch32_witness --> serialized witness bytes for the representative one-hot batch.

<!-- metric:u4_centered_batch32_witness -->65<!-- /metric:u4_centered_batch32_witness --> serialized witness bytes for the representative centered-signed batch.

<!-- metric:u4_mirror_batch32_witness -->65<!-- /metric:u4_mirror_batch32_witness --> serialized witness bytes for the representative reflected-domain batch.

<!-- metric:u4_leading_zeros_batch32_witness -->65<!-- /metric:u4_leading_zeros_batch32_witness --> serialized witness bytes for the representative leading-zero batch.

<!-- metric:u4_bit_transitions_batch32_witness -->65<!-- /metric:u4_bit_transitions_batch32_witness --> serialized witness bytes for the representative bit-transition batch.

<!-- metric:u4_trailing_zeros_batch32_witness -->65<!-- /metric:u4_trailing_zeros_batch32_witness --> serialized witness bytes for the representative trailing-zero batch.

<!-- metric:u4_lowbit_batch32_witness -->65<!-- /metric:u4_lowbit_batch32_witness --> serialized witness bytes for the representative lowbit batch.

<!-- metric:u4_gray_inverse_batch32_witness -->65<!-- /metric:u4_gray_inverse_batch32_witness --> serialized witness bytes for the representative inverse-Gray batch.

<!-- metric:u4_power_of_two_batch32_witness -->65<!-- /metric:u4_power_of_two_batch32_witness --> serialized witness bytes for the representative power-of-two batch.

<!-- metric:u4_mod3_batch32_witness -->65<!-- /metric:u4_mod3_batch32_witness --> serialized witness bytes for the representative modulo-three batch.

<!-- metric:u4_lsb_batch32_witness -->65<!-- /metric:u4_lsb_batch32_witness --> serialized witness bytes for the representative LSB batch.

<!-- metric:u4_zero_mask_batch32_witness -->65<!-- /metric:u4_zero_mask_batch32_witness --> serialized witness bytes for the representative zero-mask batch.

<!-- metric:u4_sum_mod16_batch32_witness -->65<!-- /metric:u4_sum_mod16_batch32_witness --> serialized witness bytes for the representative modulo-16 sum batch; its lookup table has <!-- metric:u4_sum_mod16_table_items -->31<!-- /metric:u4_sum_mod16_table_items --> persistent items.

`lexicographic_le_constant(128)` embeds the right-hand vector. Its
representative left witness is <!-- metric:u4_lexicographic_le_constant_128_witness -->257<!-- /metric:u4_lexicographic_le_constant_128_witness --> serialized bytes across <!-- metric:u4_lexicographic_le_constant_128_witness_items -->128<!-- /metric:u4_lexicographic_le_constant_128_witness_items --> data items, with <!-- metric:u4_lexicographic_le_constant_128_hints -->0<!-- /metric:u4_lexicographic_le_constant_128_hints --> hints. It is a fixed-constant witness-shape adapter, not a general locking-byte optimization.

<!-- metric:u4_xor_reduce_batch16_witness -->33<!-- /metric:u4_xor_reduce_batch16_witness --> serialized witness bytes for the representative XOR-reduction batch.
<!-- metric:u4_zero_bitmask_batch32_witness -->65<!-- /metric:u4_zero_bitmask_batch32_witness --> serialized witness bytes for the representative packed zero-bitmask batch.

<!-- metric:u4_bit_reverse_canonical_batch32_witness -->65<!-- /metric:u4_bit_reverse_canonical_batch32_witness --> serialized witness bytes for the representative canonical bit-reversal batch.

<!-- metric:u4_bit_planes_canonical_batch16_witness -->33<!-- /metric:u4_bit_planes_canonical_batch16_witness --> serialized witness bytes for the representative canonical bit-plane batch.
<!-- metric:u4_bit_planes_batch16_witness -->33<!-- /metric:u4_bit_planes_batch16_witness --> serialized witness bytes for the representative checked bit-plane batch.

<!-- metric:u4_bits_canonical_batch32_witness -->65<!-- /metric:u4_bits_canonical_batch32_witness --> serialized witness bytes for the representative canonical big-endian batch.
<!-- metric:u4_bits_be_alt_canonical_batch32_witness -->65<!-- /metric:u4_bits_be_alt_canonical_batch32_witness --> serialized witness bytes for the representative canonical altstack batch.
<!-- metric:u4_bits_le_alt_canonical_batch32_witness -->65<!-- /metric:u4_bits_le_alt_canonical_batch32_witness --> serialized witness bytes for the representative canonical little-endian altstack batch.

The canonical little-endian altstack row measures 1,178 bytes, 893 static
non-push opcodes, and a 189-item peak; it stops before restoring outputs to the
main stack.

<!-- metric:u4_adjacent_delta_batch32_witness -->65<!-- /metric:u4_adjacent_delta_batch32_witness --> serialized witness bytes for the representative adjacent-delta batch.

<!-- metric:u4_vector_rotate_batch32_witness -->65<!-- /metric:u4_vector_rotate_batch32_witness --> serialized witness bytes for the representative vector-rotation batch.

<!-- metric:u4_interleave_batch32_witness -->129<!-- /metric:u4_interleave_batch32_witness --> serialized witness bytes for the representative vector-interleave batch.

The staggered table has 61 setup items and costs 31 bytes to remove. A checked
query costs 22 bytes and restoring its four bits costs another four, so the
complete checked batch is `92 + 26*n` bytes. The existing branch splitter is
`43*n` bytes on the same boundary; the checked table wins from six nibbles.
Unchecked lookup is `92 + 21*n` and wins from five, but is safe only for
previously certified nibbles.

The modulo-16 sum reducer uses a 31-item table for intermediate sums from 0
through 30. It validates each nibble's numeric range and canonical ScriptNum
encoding, folds the result into one accumulator, and removes the table before
returning. For 32 nibbles it measures 592 bytes, 400 static non-push opcodes,
a 66-item combined peak, and a 65-byte witness with zero hints. Its conservative
standalone batch bound is 965 nibbles; callers must subtract unrelated live
state from that limit. This is a checksum fragment, not a terminal predicate.

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
The zero-mask projection uses the existing canonical-nibble verifier followed
by `OP_NUMEQUAL`, so it needs no resident table. A checked 32-nibble batch is
414 bytes, has 318 static non-push opcodes, and peaks at 35 combined items.
That is 26 bytes and 15 items below the existing 16-item table-shaped
parity/LSB projections at the same witness boundary. The output is a numeric
zero predicate per nibble, not a terminal aggregate.

The XOR reduction keeps a 256-item full table while folding a checked batch to
one nibble. Its representative 16-nibble boundary is measured at 740 bytes,
273 combined items, and 33 witness bytes across 16 data items; it is a compact
checksum output, not a byte-cost replacement for the per-item projections.

The popcount table also has 16 items. Its checked 32-nibble batch returns one
numeric weight in `0..=4` per input, avoiding four-bit expansion when a caller
needs Hamming weights rather than individual planes. The representative batch
is 440 bytes with a 50-item peak and 65 serialized witness bytes, versus 924
bytes and 189 items for the checked bit-plane expansion.

The packed zero-bitmask batch consumes eight checked nibbles at a time and
returns one numeric byte mask per group, with bit `i` set when nibble `i` is
zero. The representative 32-nibble batch is 482 bytes and peaks at 36 combined
items: 42 bytes larger than the per-nibble table projection, but with four
output items instead of 32 and no resident table.
The nondecreasing predicate range-checks each nibble, compares each adjacent
pair directly, and folds the results into one bit. It has no table, hints, or
bit expansion, so it is useful when a caller needs a sortedness predicate
rather than the complete adjacent mask.

The exact-sum fold differs from the existing modulo-16 nibble sum: it retains
the full `0..=15*n` total in one ScriptNum and uses no lookup table or hints.

The batch pack reuses the checked high/low nibble-to-byte boundary for every
pair, preserves pair order, and avoids a caller-side sequence of temporary
byte conversions.

The adjacent-delta fragment range-checks a contiguous vector and replaces each
edge with `(next - current) mod 16`. It uses no lookup table or witness hints;
the representative 32-nibble fixture has 31 output items and 65 serialized
witness bytes. The transform is reversible only when its initial nibble is
retained, so it is a sequence adapter rather than a standalone commitment.

The cyclic vector rotation validates the source nibbles once, stages the
permuted copies on the altstack, consumes the original vector, and restores the
rotated order. It uses no lookup table or witness hints; the full input and
output schedules coexist during the permutation, which determines the 499-item
standalone ceiling.

The vector interleave range-checks two equal-width vectors, stages the alternating
copies on the altstack, consumes both inputs, and restores the paired order. It
uses no lookup table or witness hints. Since both input and output vectors are
live during staging, the standalone width ceiling is 249.

The reflected-Gray projection uses the same 16-item checked lookup schedule as
the other one-nibble projections. It maps `x` to `x ^ (x >> 1)`, so adjacent
integer codes differ in one bit; the table is generated in the locking script
and requires no witness hints.

The one-hot table maps nibble `x` to the numeric mask `1 << x`. A checked
32-nibble batch keeps one output per input but uses larger ScriptNum literals
for high selectors; it is intended for selector/category masks, not compact
bit serialization.

The centered-signed table maps `x` to `x` for `0..=7` and to `x - 16` for
`8..=15`, producing a balanced digit in `-8..=7` without changing the one-item
per-input stack shape.

The reflected-domain table maps complementary values `x` and `15-x` to the
same representative `min(x, 15-x)` in `0..=7`. It is useful when a downstream
relation is invariant under that complement symmetry.

The leading-zero table maps zero to four and the nonzero values to the number
of zero bits before their highest set bit. It preserves one output item per
input and exposes a compact magnitude class for nibble-oriented encodings.

The bit-transition table maps each nibble to the number of changes between
adjacent bits in its four-bit representation, a value in `0..=3`. It preserves
one output item per input and exposes local binary edge density without
expanding the nibble into four stack items.

The trailing-zero table maps zero to four and nonzero values to the number of
zero bits following their least significant set bit. It preserves one output
item per input and exposes a compact low-bit alignment class without a
bit-reversal composition.

The lowbit table maps zero to zero and every nonzero nibble to its isolated
lowest set bit, one of `1`, `2`, `4`, or `8`. It retains a power-of-two selector
per input and avoids composing LSB extraction with a shift or a trailing-zero
count.

The inverse-Gray table maps each four-bit reflected-Gray code to its binary
value. It preserves one output item per input and is intended for protocols
that use Gray order to limit adjacent codeword changes.

The power-of-two table maps exactly `1`, `2`, `4`, and `8` to one and all other
nibbles, including zero, to zero. It is a compact validation predicate for
selectors that must be a single set bit.

The modulo-three table maps each nibble to a residue in `0..=2`, providing a
small-radix representation for ternary accumulators without a general modulo
interpreter.
The bit-plane transpose reuses the 61-item checked bit table and adds a static
stack permutation. It has no new witness or hint items; the representative
16-nibble row above includes the reused decomposition and the transpose. Its
standalone peak is `4*n + 61` items; with surrounding state the applicable
bound is `4*n + 61 + preserved_main + preserved_alt <= 1000`, so callers must
reduce the 234-nibble generator ceiling for live state.
The bit-reversal primitive installs 16 table items, checks each nibble, and
uses no witness hints beyond its input nibbles. Its 32-nibble row above is the
representative batch; callers with unrelated live state must reduce the 981
nibble standalone ceiling.
`u4_nibbles_to_bit_reverse_canonical(nibble_count)` uses the same table and
output contract while proving minimal ScriptNum encoding for every hostile
nibble. Its 32-nibble profile is measured separately because the numeric-only
range form remains useful when a caller already owns canonical limbs.
The little-endian row has the same size and stack profile: it changes only the
four values stored in each staggered table group. It is intended for callers
that consume each nibble least-significant-bit first; reversing four output
bits per nibble after the big-endian adapter is a separate composition cost.
The representative little-endian witness is 32 canonical `0x0f` stack items,
serialized as <!-- metric:u4_bits_le_checked_batch32_witness -->65<!-- /metric:u4_bits_le_checked_batch32_witness --> bytes.
The canonical little-endian row uses the same 32-item, 65-byte representative
witness and adds one raw ScriptNum boundary check per nibble.
<!-- metric:u4_bits_le_canonical_batch32_witness -->65<!-- /metric:u4_bits_le_canonical_batch32_witness -->
The canonical altstack row adds one raw ScriptNum boundary check per nibble and
stops before restoring the 128 output bits to the main stack. It measures 1,178
bytes, 893 static non-push opcodes, and a 189-item peak.

## Security

No independent cryptographic security claim. Correctness requires callers to
provide canonical nibbles; not every operation range-checks every input.

For bit conversion, `check_inputs=true` proves the numeric range `0..=15`
before using a value as an `OP_PICK` index. `check_inputs=false` must be used
only when a surrounding fragment already established that range: an invalid
index can otherwise address below the table. The numeric range check does not
by itself prove a byte-unique ScriptNum encoding.
The canonical little-endian adapter performs `verify_canonical_nibble()` on
each hostile input before invoking the checked table path; it rejects negative,
oversized, and non-minimal raw encodings while preserving the same bit order.
The canonical altstack adapter performs `verify_canonical_nibble()` on each
hostile input before the checked table path; it rejects negative, oversized,
and non-minimal raw encodings while preserving the reusable altstack boundary.
The canonical little-endian altstack adapter performs
`verify_canonical_nibble()` on each hostile input before the checked table path;
it rejects negative, oversized, and non-minimal raw encodings while preserving
the reusable altstack boundary.

`compare::lexicographic_le(n)` range-checks two `n`-nibble big-endian vectors,
compares the first differing nibble, consumes both vectors, and returns one
truth value. It accepts widths `1..=498`: the standalone combined peak is
`2*n + 3`, leaving one item at the 498-nibble frontier for surrounding state.
For the representative 128-nibble vectors, the complete witness is
<!-- metric:u4_lexicographic_le_128_witness -->259<!-- /metric:u4_lexicographic_le_128_witness --> bytes across <!-- metric:u4_lexicographic_le_128_witness_items -->256<!-- /metric:u4_lexicographic_le_128_witness_items --> data items and <!-- metric:u4_lexicographic_le_128_hints -->0<!-- /metric:u4_lexicographic_le_128_hints --> hint items; all data items coexist at entry. Numeric range validation does not make non-minimal raw ScriptNum encodings byte-unique under consensus.
Parity uses the same numeric range proof before its `OP_PICK` lookup. Its
output is a ScriptNum bit, not a raw byte or a terminal truth value.
Adjacent delta uses the same numeric range proof before subtraction. The
conditional addition normalizes each result into `0..=15`; it does not prove
byte-unique ScriptNum encodings or bind the initial nibble needed to invert the
transform.

Vector rotation range-checks every source before copying it. The permutation
does not authenticate ordering beyond the supplied stack contract and does not
provide a terminal predicate.

Interleave range-checks every hostile source nibble before copying. It changes
ordering only; it does not bind vector length or provide a terminal predicate.

Gray-code output is a numeric ScriptNum nibble, not a raw bitstring or a
terminal predicate. Numeric range checking does not prove byte-unique ScriptNum
encoding.

One-hot output is a numeric ScriptNum mask in `1..=32768`, not a raw fixed-width
bitstring or a terminal predicate.

Centered output is a signed ScriptNum in `-8..=7`, not a canonical unsigned
nibble or a terminal predicate.

Reflected-domain output is a numeric ScriptNum in `0..=7`; it intentionally
forgets the complement-orientation bit and is not reversible by itself.

Leading-zero output is a numeric ScriptNum in `0..=4`, not a raw bitstring or a
terminal predicate.

Bit-transition output is a ScriptNum count in `0..=3`, not an inter-nibble
transition predicate or a terminal predicate.

Trailing-zero output is a numeric ScriptNum in `0..=4`, not a raw bitstring or
a terminal predicate.

Lowbit output is a numeric power-of-two ScriptNum or zero, not a Boolean bit and
not a terminal predicate.

Inverse-Gray output is a numeric nibble in `0..=15`, not a canonical byte
encoding or a terminal predicate.

Power-of-two output is a numeric ScriptNum bit for nonzero powers of two, not a
proof of canonical byte encoding or a terminal predicate.

Modulo-three output is a numeric residue in `0..=2`, not a terminal predicate
or a byte encoding.

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

For `u4_nibbles_to_be_bits_toaltstack_canonical(n)`, the input contract is the
same as the checked big-endian converter, but every nibble is first checked for
minimal ScriptNum encoding. The preserved main stack remains below the output
bits, which remain on altstack for a following composition.
For `u4_nibbles_to_le_bits_toaltstack_canonical(n)`, the same input contract
applies after every nibble is checked for minimal ScriptNum encoding. The
preserved main stack remains below the output bits, which remain on altstack
for a following composition.

The standalone batch peak is `4*n + 61` combined main/alt-stack items. The
generator rejects `n > 234`, but callers must reduce the batch further for any
unrelated live state.

For `u4_nibbles_to_parity(n)`, the same input ordering is consumed and replaced
one-for-one by parity bits. The standalone peak is `n + 18` during range checks;
the generator rejects `n > 982`, and callers must reduce the batch for unrelated
live state.
For `adjacent_delta::u4_nibbles_to_adjacent_delta(n)`, the input vector is
consumed and replaced by `n-1` forward modulo-16 deltas in input order. The
standalone schedule keeps the `n` input items and up to `n-1` output items
coexisting, so the generator rejects `n > 499` before unrelated state is
accounted for.

For `vector_rotate::u4_nibbles_rotate_left(n)`, the input vector is consumed
and replaced by `nibble[1] ... nibble[n-1] nibble[0]`. The standalone schedule
keeps the input and staged output vectors live together, so callers must reduce
the 499-item generator ceiling for unrelated stack state.

For `interleave::u4_nibbles_interleave(n)`, the input is
`left[0..n] | right[0..n]` and the output is
`left[0], right[0], ..., left[n-1], right[n-1]`. The standalone schedule keeps
both vectors and all staged outputs live, so callers must reduce the 249-wide
generator ceiling for unrelated state.

For `gray::u4_nibbles_to_gray(n)`, the same input ordering is consumed and
replaced one-for-one by reflected Gray-code nibbles. The standalone peak is
`n + 18` during table queries; callers must reduce the 982-item ceiling for
unrelated live state.

For `u4_nibbles_to_one_hot(n)`, the same input ordering is consumed and
replaced one-for-one by `1 << nibble` selector masks. The standalone peak is
`n + 18` during range checks; the generator rejects `n > 982`, and callers must
reduce the batch for unrelated live state.

For `u4_nibbles_to_centered(n)`, the same input ordering is consumed and
replaced one-for-one by centered signed digits. The standalone peak is `n + 18`
during range checks; the generator rejects `n > 982`, and callers must reduce
the batch for unrelated live state.

For `u4_nibbles_to_mirror(n)`, the same input ordering is consumed and replaced
one-for-one by complement-reflected representatives. The standalone peak is
`n + 18` during range checks; the generator rejects `n > 982`, and callers must
reduce the batch for unrelated live state.

For `u4_nibbles_to_leading_zeros(n)`, the same input ordering is consumed and
replaced one-for-one by four-bit leading-zero counts. The standalone peak is
`n + 18` during range checks; the generator rejects `n > 982`, and callers must
reduce the batch for unrelated live state.

For `u4_nibbles_to_bit_transitions(n)`, the same input ordering is consumed and
replaced one-for-one by internal bit-transition counts. The standalone peak is
`n + 18` during range checks; the generator rejects `n > 982`, and callers must
reduce the batch for unrelated live state.

For `u4_nibbles_to_trailing_zeros(n)`, the same input ordering is consumed and
replaced one-for-one by trailing-zero counts. The standalone peak is `n + 18`
during range checks; the generator rejects `n > 982`, and callers must reduce
the batch for unrelated live state.

For `u4_nibbles_to_lowbit(n)`, the same input ordering is consumed and replaced
one-for-one by isolated lowest-set-bit values. The standalone peak is `n + 18`
during range checks; the generator rejects `n > 982`, and callers must reduce
the batch for unrelated live state.

For `gray_inverse::u4_nibbles_from_gray(n)`, the same input ordering is
consumed and replaced one-for-one by decoded binary nibbles. The standalone
peak is `n + 18` during range checks; the generator rejects `n > 982`, and
callers must reduce the batch for unrelated live state.

For `power_of_two::u4_nibbles_to_power_of_two(n)`, the same input ordering is
consumed and replaced one-for-one by nonzero-power-of-two bits. The standalone
peak is `n + 18` during range checks; the generator rejects `n > 982`, and
callers must reduce the batch for unrelated live state.

For `mod3::u4_nibbles_to_mod3(n)`, the same input ordering is consumed and
replaced one-for-one by modulo-three residues. The standalone peak is `n + 18`
during range checks; the generator rejects `n > 982`, and callers must reduce
the batch for unrelated live state.
For `bit_planes::u4_nibbles_to_bit_planes(n, ...)`, the same input contract is
used, but the output is grouped as `plane0[0..n]`, then `plane1`, `plane2`, and
`plane3`, with the final plane-3 bit on top. A sentinel keeps unrelated main
stack items below the generated permutation, and pre-existing altstack items
are preserved. The representative 16-nibble fragment is 776 bytes, uses a
33-byte witness of 16 data items, and peaks at 125 combined items.
For `bit_planes::u4_nibbles_to_bit_planes_canonical(n)`, the same output
contract applies after every input is checked for both the `0..=15` range and
minimal ScriptNum encoding. It adds no hint items, but repeats the canonical
boundary work for each nibble; the representative metric is recorded
separately from the numeric-range-only transpose.
For `bit_reverse::u4_nibbles_to_bit_reverse(n)`, input and output order are
unchanged: each `nibble[i]` is replaced by its bit-reversed value. The checked
standalone peak is `n + 19` combined items, and the generator rejects empty
batches and batches above 981.

## Operational notes

`stack*.rs` contains adapters for `bitcoin-script-stack`; `add.rs`, `logic.rs`,
`rotate.rs`, and `shift.rs` remain generic. `bits.rs` exhaustively tests every
nibble in checked and unchecked mode, rejects malformed numeric inputs in
checked mode, verifies multi-input ordering, and executes the maximum
standalone batch under the strict local stack limit. `parity.rs`, `one_hot.rs`, `centered.rs`, `mirror.rs`, `leading_zeros.rs`, `bit_transitions.rs`, `trailing_zeros.rs`, `lowbit.rs`, `gray_inverse.rs`, `power_of_two.rs`
exhaustively check the 16-value lookup domain, reject malformed
inputs and invalid batch sizes, and measure representative strict batches.

The four-equal-index query is derived from the combined nibble-table sketch in
[`coins/bitcoin-scripts`](https://github.com/coins/bitcoin-scripts/blob/8f442e4bf8a744dd9bf69b2937bdebcaed5cae77/split-into-bits.md).
The published direct table layout is not correct for every nibble under Bitcoin
`OP_PICK` semantics. This implementation substitutes a locally reproduced
61-item staggered layout; see the corresponding negative result.

Canonical input witnesses, including the CompactSize item count: nibble packing uses <!-- metric:u4_pair_to_u8_checked_witness -->5<!-- /metric:u4_pair_to_u8_checked_witness --> bytes across two data items; byte splitting uses <!-- metric:u8_to_u4_pair_checked_witness -->4<!-- /metric:u8_to_u4_pair_checked_witness --> bytes in one data item; canonical-nibble validation uses <!-- metric:u4_canonical_nibble_witness -->3<!-- /metric:u4_canonical_nibble_witness --> bytes in one data item. None requires hints.

The checked u12 triplet fixture uses <!-- metric:u4_triplet_to_u12_checked_witness -->7<!-- /metric:u4_triplet_to_u12_checked_witness --> serialized witness bytes across three data items.

The checked u16 quad fixture uses <!-- metric:u4_quad_to_u16_checked_witness -->9<!-- /metric:u4_quad_to_u16_checked_witness --> serialized witness bytes across four data items.
