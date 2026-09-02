# secp256k1 bigint9 ordinary profile

This implementation uses 29 balanced radix-512 digits and verifies an exact
integer reduction rather than an RNS congruence. It is independent of the
field's [factor-16 profile](factor16/) and [certified RNS backend](../rns/).

The secp256k1 construction represents a field element with 29 balanced
radix-512 digits. The ordinary-domain one-level normalized Karatsuba product
uses 646 signed quarter-square lookups: 196 for the 14-digit low blocks, 225
for the 15-digit high blocks, and 225 for the normalized difference product.
Eleven mixed-width quotient digits and 56 exact radix-512 carries are witness
hints. The remainder is derived by Script, range checked, proved smaller than
`p = 2^256 - 2^32 - 977`, and returned in the same 29-digit representation.

### Parameters

- The modulus, radix, 14/15-digit Karatsuba split, 513-entry quarter-square
  table, quotient chunk widths, and carry count are fixed.
- `preserved_items` is the exact number of unrelated live main-plus-altstack
  items. Generators reject a composition whose declared peak exceeds 1,000.
- `mul_mod_hinted` and `square_mod_hinted` require operand values already
  certified on the same verified path. The `_from_raw_witness` wrappers add
  operand certification at the operation boundary.
- Ordinary-domain preloaded multiplication supports up to three products; the
  selected dispatcher uses the smallest one-shot path for one product, the 85-slot
  normalized-Karatsuba relation for two, and a 57-slot destructive
  recombination for three. Pure-square batches support up to five products.

### Script metrics

Every row is a generated fragment and excludes input pushes, terminal
predicate, output comparison, tapleaf/control-block serialization, and
transaction context. “Certified operands” means that range/canonical binding
was established earlier on the same script path. Witness bytes are consensus
serialization for the stated items and representative input `(p-1)^2`; they
are not maxima.

| Configuration | Locking script | Unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| Ordinary multiply, two certified operands | <!-- metric:secp256k1_field_mul -->20503<!-- /metric:secp256k1_field_mul --> bytes | <!-- metric:secp256k1_field_mul_hint_witness -->94<!-- /metric:secp256k1_field_mul_hint_witness --> bytes / <!-- metric:secp256k1_field_mul_hint_items -->67<!-- /metric:secp256k1_field_mul_hint_items --> incremental hint items | <!-- metric:secp256k1_field_mul_stack -->757<!-- /metric:secp256k1_field_mul_stack --> |
| Ordinary multiply from two raw operand encodings | <!-- metric:secp256k1_field_mul_standalone -->21775<!-- /metric:secp256k1_field_mul_standalone --> bytes | <!-- metric:secp256k1_field_mul_standalone_witness -->160<!-- /metric:secp256k1_field_mul_standalone_witness --> bytes / 125 complete data items | <!-- metric:secp256k1_field_mul_standalone_stack -->757<!-- /metric:secp256k1_field_mul_standalone_stack --> |
| Two ordinary preloaded multiplies, certified operands | <!-- metric:secp256k1_field_mul_batch2 -->39358<!-- /metric:secp256k1_field_mul_batch2 --> bytes | <!-- metric:secp256k1_field_mul_batch2_hint_witness -->187<!-- /metric:secp256k1_field_mul_batch2_hint_witness --> bytes / 134 incremental hint items | <!-- metric:secp256k1_field_mul_batch2_stack -->882<!-- /metric:secp256k1_field_mul_batch2_stack --> |
| Three ordinary preloaded multiplies, certified operands | <!-- metric:secp256k1_field_mul_batch3 -->59145<!-- /metric:secp256k1_field_mul_batch3 --> bytes | <!-- metric:secp256k1_field_mul_batch3_hint_witness -->280<!-- /metric:secp256k1_field_mul_batch3_hint_witness --> bytes / 201 incremental hint items | <!-- metric:secp256k1_field_mul_batch3_stack -->993<!-- /metric:secp256k1_field_mul_batch3_stack --> |
| Square, one certified operand | <!-- metric:secp256k1_field_square -->14541<!-- /metric:secp256k1_field_square --> bytes | <!-- metric:secp256k1_field_square_hint_witness -->94<!-- /metric:secp256k1_field_square_hint_witness --> bytes / 67 incremental hint items | <!-- metric:secp256k1_field_square_stack -->614<!-- /metric:secp256k1_field_square_stack --> |
| Five preloaded squares, certified operands | <!-- metric:secp256k1_field_square_batch5 -->65064<!-- /metric:secp256k1_field_square_batch5 --> bytes | <!-- metric:secp256k1_field_square_batch5_hint_witness -->468<!-- /metric:secp256k1_field_square_batch5_hint_witness --> bytes / 335 incremental hint items | <!-- metric:secp256k1_field_square_batch5_stack -->998<!-- /metric:secp256k1_field_square_batch5_stack --> |

The one-shot multiplication is exactly:

| Component | Bytes |
| --- | ---: |
| Push 513-entry table | <!-- metric:secp256k1_field_mul_table_setup -->1538<!-- /metric:secp256k1_field_mul_table_setup --> |
| Drop table | <!-- metric:secp256k1_field_mul_table_drop -->257<!-- /metric:secp256k1_field_mul_table_drop --> |
| Low/high raw products | <!-- metric:secp256k1_field_mul_raw_products -->9374<!-- /metric:secp256k1_field_mul_raw_products --> |
| Normalized-difference products | <!-- metric:secp256k1_field_mul_difference_products -->4993<!-- /metric:secp256k1_field_mul_difference_products --> |
| Difference normalization | <!-- metric:secp256k1_field_mul_difference_normalization -->1103<!-- /metric:secp256k1_field_mul_difference_normalization --> |
| Coefficient-array routing | <!-- metric:secp256k1_field_mul_coefficient_routing -->173<!-- /metric:secp256k1_field_mul_coefficient_routing --> |
| Karatsuba recombination | <!-- metric:secp256k1_field_mul_coefficient_recombination -->530<!-- /metric:secp256k1_field_mul_coefficient_recombination --> |
| Quotient/carry relation, cleanup, output validation | <!-- metric:secp256k1_field_mul_relation_output -->2535<!-- /metric:secp256k1_field_mul_relation_output --> |
| **Total** | **20,503** |

Thus the static table lifecycle is 1,795 bytes, or 8.8% of one isolated
multiplication. The remaining
<!-- metric:secp256k1_field_mul_computation -->18708<!-- /metric:secp256k1_field_mul_computation -->
bytes are actual per-operation computation and routing. The fragment contains
<!-- metric:secp256k1_field_mul_opcodes -->13039<!-- /metric:secp256k1_field_mul_opcodes -->
static non-push opcodes. The raw wrapper adds
<!-- metric:secp256k1_field_operand_certification -->1272<!-- /metric:secp256k1_field_operand_certification -->
bytes to certify both operands.

For repeated work, the table's 1,795-byte push/drop cost is paid once. Two
preloaded products use
<!-- metric:secp256k1_field_mul_batch2_computation -->37563<!-- /metric:secp256k1_field_mul_batch2_computation -->
bytes of non-table computation, including
<!-- metric:secp256k1_field_mul_batch2_relation -->18405<!-- /metric:secp256k1_field_mul_batch2_relation -->
bytes per normalized-Karatsuba relation, and average 19,679 total bytes each. Three use
<!-- metric:secp256k1_field_mul_batch3_computation -->57350<!-- /metric:secp256k1_field_mul_batch3_computation -->
non-table bytes, including
<!-- metric:secp256k1_field_mul_batch3_relation -->18740<!-- /metric:secp256k1_field_mul_batch3_relation -->
bytes per compact relation, and average 19,715 bytes each; destructive
recombination is slightly larger per gate but is what keeps the strict peak at
993. A resident-table single gate is
<!-- metric:secp256k1_field_mul_resident -->19942<!-- /metric:secp256k1_field_mul_resident -->
bytes; setup plus one final result-preserving cleanup of
<!-- metric:secp256k1_field_mul_resident_cleanup -->315<!-- /metric:secp256k1_field_mul_resident_cleanup -->
bytes totals
<!-- metric:secp256k1_field_mul_resident_total -->21795<!-- /metric:secp256k1_field_mul_resident_total -->
bytes. These resident figures do not include circuit-specific scheduling or
fan-out. Resident lookup memory must be emitted by the locking script through
`table_setup`; witness-supplied entries are not trusted table state.

The specialized square removes the unnecessary second operand and uses 435
quarter-square products. Its one-shot 14,541 bytes split into
<!-- metric:secp256k1_field_square_table_setup -->1538<!-- /metric:secp256k1_field_square_table_setup -->
setup,
<!-- metric:secp256k1_field_square_table_drop -->257<!-- /metric:secp256k1_field_square_table_drop -->
cleanup,
<!-- metric:secp256k1_field_square_diagonals -->406<!-- /metric:secp256k1_field_square_diagonals -->
diagonal-product bytes,
<!-- metric:secp256k1_field_square_off_diagonals -->9744<!-- /metric:secp256k1_field_square_off_diagonals -->
off-diagonal-product bytes, and
<!-- metric:secp256k1_field_square_relation_output -->2596<!-- /metric:secp256k1_field_square_relation_output -->
relation/output bytes. The table lifecycle is 1,795 bytes and computation is
<!-- metric:secp256k1_field_square_computation -->12746<!-- /metric:secp256k1_field_square_computation -->
bytes, with
<!-- metric:secp256k1_field_square_opcodes -->9421<!-- /metric:secp256k1_field_square_opcodes -->
static non-push opcodes.

The five-square batch uses an unbiased table: setup is
<!-- metric:secp256k1_field_square_batch5_table_setup -->1657<!-- /metric:secp256k1_field_square_batch5_table_setup -->
bytes, cleanup is
<!-- metric:secp256k1_field_square_batch5_table_drop -->257<!-- /metric:secp256k1_field_square_batch5_table_drop -->,
each relation is
<!-- metric:secp256k1_field_square_batch5_relation -->12268<!-- /metric:secp256k1_field_square_batch5_relation -->
bytes, and total non-table computation is
<!-- metric:secp256k1_field_square_batch5_computation -->63150<!-- /metric:secp256k1_field_square_batch5_computation -->
bytes. It averages 13,012.8 bytes per square but leaves only two stack items of
consensus headroom.

### Security and hint binding

The small gate is sound only for operands certified as canonical field values.
`certify_value`, `certify_mul_operands`, and the raw wrappers establish that
binding; same-shaped raw digit arrays are not certificates. Lower digits are
checked in `[-256, 256)`, the top digit and exact integer are checked against
the field modulus, and outputs repeat those checks before becoming reusable.

Hints are hostile. Eleven quotient digits and 56 carries prove the exact
integer identity `lhs*rhs = q*p + r` coefficient by coefficient. Script derives
`r`; it is not a witness hint. Quotient digits need not use
the host's canonical mixed-width encoding because only the represented exact
integer matters. Oversized encodings fail closed under four-byte ScriptNum
arithmetic.

Carry-normalizing the Karatsuba differences preserves evaluation at radix 512
but changes the formal coefficient polynomial by multiples of `X-512`.
Consequently, the host generates carries from the exact normalized coefficient
basis verified by Script. Reusing schoolbook-basis carries would be invalid.
Unit tests corrupt the first, middle, and last quotient/carry items, reject
non-field remainders, exercise deterministic boundaries and random values, and
execute at exactly the 1,000-item combined main/altstack limit while preserving
unrelated state.

### Script compatibility and standardness

The arithmetic opcodes are available in tapscript, but these fragments exceed
legacy/P2WSH script-size and opcode-count limits. Local strict
`bitcoin-scriptexec` tapscript tests enforce the 1,000-item stack limit;
Bitcoin Core consensus and relay-policy validation have not been performed.
The evidence is therefore `locally-reproduced` and deployment remains
`unclassified`, not a claim of consensus deployability. The fragments return
field digits, not a terminal boolean, so callers must consume or compare every
output and arrange cleanstack.

### Witness and stack contract

For ordinary multiplication, input is
`preserved | lhs[28..0] | rhs[28..0] | q[10..0] | c[55..0]`, with digit/carry
zero nearest the top; output is `preserved | r[28..0]`. The 67 incremental hint
items serialize in reverse quotient order followed by reverse carry order.
Squaring uses the analogous one-operand layout. Batch group zero is nearest the
top, is processed first, and its result is returned nearest the top. Both main
and altstack items count toward `preserved_items` and the declared peak.

### Comparison boundary

The 20,503-byte ordinary native gate and the 31,278-byte prime-RNS composable gate both
consume two previously certified secp256k1 field values, bind hostile reduction
hints locally, and return a reusable certified result. Their certificate
representations differ: 29 balanced radix digits here versus 46 canonical RNS
residues, so conversion and fan-out costs are circuit-specific. The 10,950-byte
RNS carry gate is not comparable: it omits every global integer binding. The
51,047-byte RNS standalone gate performs four full limb-to-RNS bindings and
returns both limbs and residues, whereas this raw wrapper certifies two native
digit operands and derives the native result directly.

BN254 `Fq` is a different base field with a different nine-limb multiplication
backend and certification convention. Its hinted-multiplication size is
orientation only—not a secp256k1 speedup ratio or interchangeable field
semantics. The checked BN254 inventory currently pins representative additions,
not a like-for-like certified multiplication boundary; OP-006 tracks that gap.
