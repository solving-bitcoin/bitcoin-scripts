# Arithmetic representations

The table is a navigation aid, not a single benchmark: semantics and boundaries
differ. Follow each catalog configuration before comparing numbers.

| Need | Local construction | Representative script bytes | Main constraint |
| --- | --- | ---: | --- |
| Small constant product | ScriptNum × 13 | 10 | Four-byte ScriptNum domain |
| Canonical ScriptNum boundary | `scriptint::verify_canonical()` | 5 | 4-item peak; rejects raw aliases and oversized items |
| Conditional u32 sign routing | `u32_conditional_negate()` | 83 | 9-item peak; condition normalized before branch |
| Small-field add | M31 u31 add | 18 | Canonical field input |
| Small-field variable multiply | M31 u31 multiply | 1,370 | Witness quotient relation |
| Canonical checked byte boundary | `verify_canonical_byte()` | 12 | 4-item peak; 4-byte witness; rejects noncanonical ScriptNums |
| Checked u32 logical right shift by eight | `u32_rshift8_checked()` | <!-- metric:u32_rshift8_checked -->62<!-- /metric:u32_rshift8_checked --> | <!-- metric:u32_rshift8_checked_stack -->7<!-- /metric:u32_rshift8_checked_stack -->-item peak; 9-byte representative witness; no shared table or hints; generic `u32_shr(8, 2)` is 561 bytes and 272 items with table setup/cleanup |
| Checked u32 logical left shift by eight | `u32_lshift8_checked()` | <!-- metric:u32_lshift8_checked -->56<!-- /metric:u32_lshift8_checked --> | <!-- metric:u32_lshift8_checked_stack -->7<!-- /metric:u32_lshift8_checked_stack -->-item peak; 9-byte witness; no hints or shared table; generic table-backed boundary is 561 bytes and 272 items |
| Checked u32 seven-bit rotation | `u32_rrot7_checked()` | 130 | 8-item peak; 9-byte representative/13-byte maximum witness; rejects raw aliases |
| Canonical checked u32 rotate-right by 8 | `u32_rrot8_checked()` | 57 | 7-item peak; 9-byte witness; reuses byte rotation |
| 32 checked nibbles to 128 bits | u4 staggered batch table | 924 | 189-item peak; tapscript-oriented |
| 32 canonical checked nibbles to 128 bits | u4 canonical big-endian table adapter | 1,306 | 189-item peak; 65-byte witness; rejects raw aliases |
| 32 canonical checked nibbles to 128 big-endian bits on altstack | u4 canonical altstack table adapter | 1,178 | 189-item peak; 65-byte witness; rejects raw aliases |
| Canonical compressed-u32 decode | u32 raw-encoding boundary | 431 | 7-item peak; 7-byte maximum witness; rejects aliases |
| Canonical nonnegative compressed-u32 decode | u32 narrow raw-encoding boundary | 405 | 7-item peak; 6-byte maximum witness; rejects negative values and aliases |
| Canonical u32 byte-word compression | `u32_compress_canonical()` | 130 | 7-item peak; 9-byte representative/13-byte maximum witness; rejects raw limb aliases |
| Checked u31 width-9 decomposition | u31 range boundary | 85 | 10-item peak; 4-byte representative witness; numeric `0..=511` check |
| Canonical checked u31 width-9 decomposition | u31 range plus raw ScriptNum boundary | <!-- metric:u31_bits_canonical_width9 -->90<!-- /metric:u31_bits_canonical_width9 --> | <!-- metric:u31_bits_canonical_width9_stack -->10<!-- /metric:u31_bits_canonical_width9_stack -->-item peak; 4-byte witness; rejects aliases; 0 hints |
| Checked u4 nibble pair to byte | `u4_pair_to_u8(true)` | 20 | 5-item peak; 2 data items; 5-byte witness |
| Checked u4 nibble triplet to u12 | `u4_triplet_to_u12(true)` | <!-- metric:u4_triplet_to_u12_checked -->44<!-- /metric:u4_triplet_to_u12_checked --> | <!-- metric:u4_triplet_to_u12_checked_stack -->6<!-- /metric:u4_triplet_to_u12_checked_stack -->-item peak; 3 data items; 12-bit ScriptNum |
| Checked u4 nibble quad to u16 | `u4_quad_to_u16(true)` | <!-- metric:u4_quad_to_u16_checked -->76<!-- /metric:u4_quad_to_u16_checked --> | <!-- metric:u4_quad_to_u16_checked_stack -->7<!-- /metric:u4_quad_to_u16_checked_stack -->-item peak; 4 data items; 16-bit ScriptNum |
| Checked u4 nibble popcount batch, 32 inputs | `u4_nibbles_to_popcount(32)` | <!-- metric:u4_popcount_batch32 -->440<!-- /metric:u4_popcount_batch32 --> | <!-- metric:u4_popcount_batch32_stack -->50<!-- /metric:u4_popcount_batch32_stack -->-item peak; 65-byte witness; 32 data items; no hints; bit-plane expansion is 924 bytes and 189 items |
| Checked u8 byte to nibble pair | `u8_to_u4_pair(true)` | 62 | 4-item peak; 4-byte witness; two nibble outputs |
| Checked u8 high-bit extraction | `u8_extract_hbit_checked(4)` | 73 | 5-item peak; 4-byte witness; rejects non-byte ScriptNums |
| Canonical checked nibble boundary | `verify_canonical_nibble()` | 10 | 4-item peak; 3-byte witness; rejects noncanonical ScriptNums |
| 32 checked signed radix-32 digits to sign/magnitude bits | signed-window staggered table | 1,866 | 348-item peak; wins bytes only after 8–16 digit crossover |
| Compressed total-domain u32 addition | two-item compressed wire | 1,016 | 11-byte representative witness; byte baseline is 78 bytes and 20-byte witness |
| Fixed-width u4 ordering | `lexicographic_le(128)` | 7,500 | 256 data items; 4,354 non-push opcodes |
| Fixed-width u4 ordering with embedded right vector | `lexicographic_le_constant(128)` | <!-- metric:u4_lexicographic_le_constant_128 -->0<!-- /metric:u4_lexicographic_le_constant_128 --> | <!-- metric:u4_lexicographic_le_constant_128_witness_items -->0<!-- /metric:u4_lexicographic_le_constant_128_witness_items --> witness data items; <!-- metric:u4_lexicographic_le_constant_128_stack -->0<!-- /metric:u4_lexicographic_le_constant_128_stack -->-item peak; embedded vector |
| 32 checked nibbles to leading-zero counts | `u4_nibbles_to_leading_zeros(32)` | 440 | 50-item peak; one output count per input |
| 32 checked nibbles to intra-nibble bit-transition counts | `u4_nibbles_to_bit_transitions(32)` | 440 | 50-item peak; one count per input |
| 32 checked nibbles to trailing-zero counts | `u4_nibbles_to_trailing_zeros(32)` | 440 | 50-item peak; one output count per input |
| 32 checked nibbles to lowest-set-bit selectors | `u4_nibbles_to_lowbit(32)` | 440 | 50-item peak; one selector per input |
| 32 checked Gray nibbles to binary nibbles | `u4_nibbles_from_gray(32)` | 440 | 50-item peak; one decoded nibble per input |
| 32 checked nibbles to nonzero-power-of-two bits | `u4_nibbles_to_power_of_two(32)` | 440 | 50-item peak; one predicate bit per input |
| 32 checked nibbles to modulo-three residues | `u4_nibbles_to_mod3(32)` | 440 | 50-item peak; one residue per input |
| 32 checked nibbles to parity bits | `u4_nibbles_to_parity(32)` | 440 | 50-item peak; one output bit per input |
| 16 checked nibbles to one XOR nibble | `u4_nibbles_to_xor(16)` | 740 | 273-item peak; 256-item full XOR table |
| Variable u32 XNOR | `u32_xnor(0, 1, 3)` | 222 | 272-item peak; 182 static non-push opcodes; shared 256-item XOR table |
| Checked public-constant u4 multiplication | `u4_mul_constant_mod16`, `constant=10` | 6 | 20-item peak; 16-item table; one data item; zero hints |
| Checked u4 square modulo 16 | `u4_square_mod16()` | 6 | 20-item peak; 16-item table; one data item; zero hints |
| 32 checked nibbles nondecreasing predicate | `u4_nibbles_nondecreasing(32)` | 478 | 35-item peak; one output bit; no table |
| 32 checked nibbles to an exact sum | `u4_nibbles_sum_exact(32)` | 497 | 34-item peak; no table; full sum rather than modulo 16 |
| 32 checked nibbles to 16 bytes | `u4_nibbles_to_bytes(32)` | <!-- metric:u4_pack_batch32 -->442<!-- /metric:u4_pack_batch32 --> | <!-- metric:u4_pack_batch32_stack -->52<!-- /metric:u4_pack_batch32_stack -->-item peak; checked pair packing; 65-byte witness; no hints |
| 32 checked nibbles to forward modulo-16 deltas | `u4_nibbles_to_adjacent_delta(32)` | 760 | 64-item peak; 31 output nibbles; no hints |
| 32 checked nibbles cyclically rotated left | `u4_nibbles_rotate_left(32)` | 432 | 64-item peak; no hints; stack permutation |
| 32-wide checked u4 vector interleave | `u4_nibbles_interleave(32)` | 954 | 128-item peak; 129-byte witness; no hints |
| 32 checked nibbles to reflected Gray codes | `u4_nibbles_to_gray(32)` | 440 | 50-item peak; 65-byte witness; no hints |
| 32 checked nibbles to one-hot masks | `u4_nibbles_to_one_hot(32)` | 461 | 50-item peak; 16-bit numeric selector per input |
| 32 checked nibbles to centered signed digits | `u4_nibbles_to_centered(32)` | 447 | 50-item peak; outputs `-8..=7` |
| 32 checked nibbles to complement-reflected representatives | `u4_nibbles_to_mirror(32)` | 440 | 50-item peak; canonical `0..=7` representative |
| u32 population count | `u32_popcount()` | 455 | 262-item peak; 256-item byte table |
| u32 per-byte population counts | `u32_byte_popcounts()` | 452 | 262-item peak; four numeric outputs; 256-item byte table |
| u32 leading zero-byte count | `u32_leading_zero_bytes()` | 159 | 7-item peak; table-free; validates all four byte limbs |
| u32 trailing zero-byte count | `u32_trailing_zero_bytes()` | 147 | 7-item peak; table-free; scans the native top-limb order |
| u32 fixed byte extraction | `u32_extract_byte(0)` | 56 | 7-item peak; validates all four limbs; fixed index |
| u32 per-byte parity projection | `u32_byte_parity()` | <!-- metric:u32_byte_parity -->452<!-- /metric:u32_byte_parity --> | <!-- metric:u32_byte_parity_stack -->262<!-- /metric:u32_byte_parity_stack -->-item peak; four parity outputs; same 256-item table; 3 bytes below whole-word popcount |
| Fused u32 NAND | `u32_nand(0, 1, 3)` | 190 | 272-item peak; shared 256-item Boolean table |
| Fused u32 NOR | `u32_nor(0, 1, 3)` | 346 | 272-item peak; shared 256-item Boolean table |
| 32 checked nibbles to LSB bits | `u4_nibbles_to_lsb(32)` | 440 | 50-item peak; one output bit per input |
| 32 checked nibbles to zero predicates | `u4_nibbles_to_zero_mask(32)` | 414 | 35-item peak; no resident lookup table |
| 32 checked nibbles to four zero bitmasks | `u4_nibbles_to_zero_bitmasks(32)` | 482 | 36-item peak; four output bytes; no resident lookup table |
| 16 checked nibbles to four bit planes | u4 table plus stack transpose | 776 | 125-item peak; 33-byte witness |
| 16 canonical checked nibbles to four bit planes | u4 canonical bit-plane transpose | 966 | 125-item peak; 33-byte witness; rejects raw aliases |
| 32 checked nibble bit reversals | u4 16-item reversal table | 344 | 51-item peak; 65-byte witness |
| 32 checked nibbles to one modulo-16 sum | `u4_nibbles_to_sum_mod16(32)` | 592 | 66-item peak; 65-byte witness; 31-item table |
| 32 canonical checked nibble bit reversals | `u4_nibbles_to_bit_reverse_canonical(32)` | 504 | 51-item peak; 65-byte witness; rejects raw aliases |
| One checked u32 word to little-endian bits | u32 byte splitter | 514 | 9-byte witness; 35-item peak; numeric byte range only |
| Checked u32 byte word to eight bit planes | `u32_to_bit_planes()` | 877 | 9-byte witness; 45-item peak; eight nibble outputs |
| Canonical checked u32 word to little-endian bits | `u32_to_le_bits_canonical()` | 562 | 9-byte representative/13-byte maximum witness; 35-item peak; rejects raw aliases |
| u32 conditional word selection | u32 normalized truthy selector | 9 | 10–30-byte witness; 9-item peak |
| 32 checked nibbles to 128 little-endian bits | u4 mirrored staggered table | 924 | 65-byte witness; 189-item peak; same table cost, no per-nibble reversal |
| 32 canonical checked nibbles to 128 little-endian bits | u4 canonical little-endian table adapter | 1,306 | 189-item peak; 65-byte witness; rejects raw aliases |
| 32 canonical checked nibbles to 128 little-endian bits on altstack | u4 canonical little-endian altstack adapter | 1,178 | 189-item peak; 65-byte witness; rejects raw aliases |
| u32 zero predicate | direct four-limb `OP_0NOTEQUAL`/`OP_BOOLAND` fold | 4 | 5-byte four-limb witness; 4-item peak; canonical byte limbs required |
| u32 zero-byte mask | `u32_to_zero_byte_mask()` | 67 | 13-byte witness; 8-item peak; four-bit per-byte mask |
| u32 per-byte equality mask | `u32_byte_eq_mask()` | 149 | 17-byte eight-item witness; 11-item peak; four lane predicates; no hints |
| u32 per-byte less-than mask | `u32_byte_lessthan_mask()` | 149 | 17-byte eight-item witness; 11-item peak; four lane predicates; no hints |
| u32 byte high-bit mask | `u32_msb_mask()` | 133 | 9-byte witness; 8-item peak; four packed lane bits; no hints |
| Checked u32 rotate-right by sixteen | `u32_rrot16_checked()` | <!-- metric:u32_rrot16_checked -->55<!-- /metric:u32_rrot16_checked --> | <!-- metric:u32_rrot16_checked_stack -->7<!-- /metric:u32_rrot16_checked_stack -->-item peak; <!-- metric:u32_rrot16_checked_witness -->9<!-- /metric:u32_rrot16_checked_witness -->-byte representative witness; reuses one-opcode byte permutation |
| Consuming u32 XOR | `u32_xor_drop(0, 1, 3)` | 202 | Destructive two-word routing; 268-item peak with shared table |
| Consuming u32 AND | `u32_and_drop(0, 1, 3)` | 169 | Destructive two-word routing; 268-item peak with shared table |
| Consuming u32 OR | `u32_or_drop(0, 1, 3)` | 326 | Destructive two-word routing; 268-item peak with shared table |
| Checked u32 zero predicate | `u32_iszero()` | 53 | 6-item peak; no lookup table |
| Stack-preserving u32 copy | `u32_pick(2)` | 8 | 16-item peak; 24-byte witness; copies a word at depth two |
| Wide add | U254 add | 176 | Nine limbs |
| Wide add with bounded limbs | U254 carry-free add | 142 | Nine limbs; each corresponding sum must stay below radix |
| Wide subtract | U254 sub | 190 | Nine limbs; propagates borrows |
| Wide subtract with bounded limbs | U254 borrow-free sub | 107 | Nine limbs; each minuend limb must be at least its subtrahend |
| Wide multiply | U254 multiply | 111,466 | Above optimizer cutoff; unoptimized |
| Ed25519 ordinary-domain multiply | 51 biased centered radix-32 digits, 13 signed tables | <!-- metric:ed25519_field_mul -->9893<!-- /metric:ed25519_field_mul --> | 245-byte/51-item incremental hint; certified operands; 523-item strict peak |
| Ed25519 factor-8 multiply | `E(x)=x/8`, folded normalized Karatsuba | 19,903 | 31-byte/29-item incremental hint; certified encoded operands; 719-item strict peak |
| Native secp256k1 ordinary-domain multiply | 29 balanced radix-512 digits, normalized Karatsuba | 20,500 | 94-byte/67-item incremental hint; certified operands; 757-item strict peak |
| Native secp256k1 factor-16 multiply | `E(x)=x/16`, folded normalized Karatsuba | 20,447 | 37-byte/29-item incremental hint; certified encoded operands; 719-item strict peak |
| Native secp256k1 base-field square | 29 balanced radix-512 digits, symmetry-specialized | 14,541 | 94-byte/67-item incremental hint; certified operand; 614-item strict peak |
| Three native secp256k1 ordinary multiplies | Shared table, destructive third-gate recombination | 59,163 | 280-byte/201-item incremental hint; 993-item strict peak; unoptimized above cutoff |
| Bounded RNS add | Legacy RNS add | 216 | Modulo 69,300 |
| Compressed u32 equality | Canonical two-item ScriptNum wire comparison | 37 | 2 witness items; 11 representative bytes; 5-item peak |
| Compressed u32 unsigned less-than | Canonical two-item ScriptNum ordering | 124 | 2 witness items; 11 representative bytes; 6-item peak |
| Compressed u32 less-than fixed threshold | `u32_compressed_lessthan_constant(0x89abcdef)` | <!-- metric:u32_compressed_lessthan_constant -->127<!-- /metric:u32_compressed_lessthan_constant --> | <!-- metric:u32_compressed_lessthan_constant_stack -->6<!-- /metric:u32_compressed_lessthan_constant_stack -->-item strict peak; one data item; signed threshold encoding |
| Compressed u32 logical right shift | Direct one-item ScriptNum shift by 8 | 500 | 1 witness item; 5-item peak; decode baseline 499 bytes / 7-item peak |
| Compressed u32 logical left shift | Direct one-item ScriptNum shift by 8 | 492 | 1 witness item; 5-item peak; decode baseline 490 bytes / 7-item peak |
| Bounded RNS multiply | Legacy RNS multiply | 1,561 | 903-item peak |
| Exact 256-bit-product RNS add | 75-prime canonical coordinatewise | 1,131 | 513-bit composite range; 151-item peak |
| Exact 256-by-256-bit RNS multiply baseline | 75-prime table/Horner hybrid | 15,624 | No relation carries; 183-item peak |
| Six independent 256-by-256-bit RNS products | Coordinate-major table batch | 64,912 | Includes 450-byte output restoration; 900-item peak |
| Hinted secp256k1 modular multiply, conditional | 42-prime exact-carry verifier | 10,937 | 301 hint bytes; 231-item strict peak; external bindings excluded |
| Hinted secp256k1 modular multiply, standalone-bound | 47-prime limb-bound exact-carry verifier | 51,055 | 868-byte complete data witness; 305-item strict peak; global bindings included; unoptimized above cutoff |
| Hinted secp256k1 modular multiply, composable | 46-prime reusable-certificate verifier | 31,257 | 471 incremental hint bytes; 267-item peak; two adjacent certified operands required |

Selection order: choose semantics and range, then representation compatibility,
then consensus feasibility, and only then minimize bytes. The prime-log profile
keeps canonical operands and covers one unsigned 256-by-256-bit product exactly,
but longer expressions remain modular unless their bound is proved below its
513-bit composite modulus. Range checks and conversion remain outside a row
unless its boundary says otherwise; terminal predicates remain excluded from
both modular-product rows.

The signed-window decoder is a narrow scheduling primitive rather than a
general field representation. At 32 digits its shared 156-item table saves 564
bytes over checked conditional extraction, but raises the peak from 194 to 348
items. The deterministic sweep measures the table at 643 bytes versus 607 for
the branch baseline at eight digits, and 1,051 versus 1,215 at sixteen; short
or stack-constrained callers should keep the branch form.
The compressed u32 addition row is a deliberate witness-width tradeoff: it
saves nine representative witness bytes and six entry items, but expands to
the byte carry chain and costs 1,016 locking bytes versus 78 for the ordinary
adder. It is retained for witness-constrained composition, not as a general
locking-byte winner.

The leading-zero-byte count is a fixed-width prefix classifier rather than a
zero predicate: `u32_iszero()` is only 4 bytes because it discards position,
while this construction spends 159 bytes to preserve the first nonzero index
and validate limbs that are dropped after the decision. It also avoids the
256-item table resident in the population-count construction.

The 9,893-byte Ed25519 row is the current locking-script-size winner for this
field. It keeps host values in the ordinary field domain but uses a unique
51-digit centered stack encoding. Thirteen operand-derived 32-entry tables bind
663 schoolbook products; `32^51=p+19`, one scalar quotient, and 50 carries bind
the complete reduction. Its `fragment-with-memory` boundary includes 2,227
bytes of table setup/routing, 7,299 bytes of folded product/relation, and 367
bytes of cleanup and canonical output restoration. The 11,180-byte raw wrapper
adds certification for both hostile operand vectors and consumes a
representative 398-byte/153-item complete data witness.

The retained Ed25519 factor-8 row uses the same sound normalized-Karatsuba
product boundary as the native secp256k1 factor-16 row. Its modulus identity
`8*512^28=p+19` materially simplifies reduction, but the 646 bound digit
products still dominate total bytes. It remains attractive when its 31-byte
incremental hint or factor-8 circuit domain matters; it is not the current
size winner. Neither sound row substantiates the proposed 2–3 KB estimate;
NR-030 records the missing shifted-product binding in that estimate and the
cost of the repaired lookup-table designs.

Both Ed25519 rows are `locally-reproduced` and `unclassified`. The radix-32
benchmark used `bitcoin-scriptexec` in tapscript context with the 1,000-item
combined stack limit enabled; its generated-Script boundary and adversarial
test suites remain ignored by default. Neither row has Bitcoin Core
differential validation or a complete transaction measurement.

The native 20,500-byte ordinary row checks the same field operation as the 31,257-byte
composable RNS row at a broadly comparable certificate boundary: both consume
two verified-path secp256k1 values, bind hostile reduction hints locally, and
return a reusable certified result. They do not share a stack representation,
so conversion, certificate fan-out, and circuit scheduling remain outside both
numbers. The ordinary native gate's 1,793 bytes of table lifecycle can be
shared: two preloaded products cost an unoptimized 39,400 bytes at an 882-item peak, while
three use a slightly larger destructive relation and cost an unoptimized 59,163 bytes at a
993-item peak.

The 20,447-byte factor-16 row is an exact field multiplication only under its
documented encoding invariant: stored `a=E(x)` and `b=E(y)` produce `E(xy)`.
It has no measured resident-table or batch API, and mixing it with the ordinary
multiply or specialized square requires an explicit conversion strategy whose
Script cost is outside the row.

The native square row is a separate operation, not a multiplication estimate.
It exploits equal operands and uses 435 rather than 646 quarter-square
products. Five unoptimized shared-table squares cost 65,074 bytes and peak at 998 items.
The BN254 `Fq` backend concerns a different modulus and nine-limb
representation; its hinted-operation size is implementation context, not a
ratio for secp256k1 base-field work.

All three exact-carry modular rows are `locally-reproduced` and `unclassified`. The
compact profile's 42-prime product basis is 513 bits. Each packed coordinate
group verifies one exact signed carry equation; only 18 groups include a
remainder-complement residue, whose subbasis product exceeds `2^257`. The
144-item, 301-byte hint is 42 quotient residues, 42 remainder residues, 42
carries, and 18 complement residues.

That compact row is not a complete binding boundary. Every supplied operand
and hint coordinate must be externally tied to the canonical RNS encoding of
its corresponding unsigned integer below `2^256`, and the operands must be
below the target modulus. Local carry equations alone permit wrapped global
relations and shifted operand representatives.

The 47-prime row includes that missing work. Its 299 witness items are 64
centered base-`2^16` limbs, 188 residue-binding carries, and 47 relation
carries. The script range-checks all limbs, proves `lhs`, `rhs`, and remainder
below the target, derives four canonical RNS vectors from the shared limbs,
and checks the product over a 513-bit basis. It needs no complement. Its unoptimized 51,055
bytes split into 1,057 bytes of range checks, 38,796 of residue binding,
10,794 of modular relations, and 400 of routing and output. The 868-byte
witness covers all 299 consumed data items for `(N-1)^2`, not merely the
derived carries. The fragment returns both the 16 remainder limbs and 47
residues. A reusable one-value binding costs 9,773 bytes when a larger program
can certify persistent values at their introduction boundary, but that plain
binder proves only `<2^256`. The `bind_value_below(N)` variant needed for an
otherwise-unchecked field value costs 9,860 bytes. Shared joint-NAF doubling
chains are the main binding reduction; target-aware centering enables the two
widest basis primes while retaining checked ScriptNum prefix bounds.

The 46-prime composable row moves only the operand part of that proof to a
reusable certificate boundary. Its gate spends 443 bytes on q/r limb and field
validation, 9,851 binding q, 9,663 binding r, 10,799 on product relations, and
522 on routing/output. The 170-item, 471-byte `(N-1)^2` witness is incremental:
it excludes the two already-live 46-residue certificates. The matching
field-value binder is 9,832 bytes with a 195-byte, 62-item `N-1` witness and a
72-item peak; the gate contains 20,778 static non-push opcodes and peaks at 267.
Both fragments have zero table push/drop bytes.

The 10,937, 31,257, and 51,055 sizes are not direct optimization comparisons.
The first excludes every global proof; the second requires two certified
operands already adjacent to its hints and excludes certificate fan-out and
all-witness-at-entry routing; the third closes all four value bindings inside
one operation and additionally returns remainder limbs. The 75-prime
15,624-byte no-carry path remains the baseline when relation carries are
unavailable.

The one-shot ordinary product contains 392 bytes of table pushes, 153 bytes of
table cleanup, and 15,081 bytes of computation/routing/output code. The
coordinate-major six-product fragment re-optimizes the table choice for the
batch: 25,510 bytes push tables once per selected coordinate, 6,521 bytes drop
them, 30,229 bytes execute the arithmetic queries, 2,202 bytes route operands
and results, and 450 bytes restore all outputs. It averages 10,819 bytes per
product, but assumes coordinate-major inputs; vector transposition is excluded.
All carry verifiers are table-free. Their bytes are arithmetic, validation,
binding, and routing rather than reusable lookup setup. The composable profile
amortizes certificate work, not static tables; its multi-gate witness scheduling
and certificate duplication/reordering costs remain outside the measured gate.
