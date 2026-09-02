# Prime fields

This module contains a native 256-bit secp256k1 base-field backend and two
narrow fields over the generic [`u31`](../u31/) ScriptNum backend. The native
backend verifies an exact integer reduction rather than an RNS congruence;
`f257` and `f12289` serve lookup and Falcon-oriented coefficient workloads.

## secp256k1 base field

The secp256k1 construction represents a field element with 29 balanced
radix-512 digits. The ordinary-domain one-level normalized Karatsuba product
uses 646 signed quarter-square lookups: 196 for the 14-digit low blocks, 225
for the 15-digit high blocks, and 225 for the normalized difference product.
Eleven mixed-width quotient digits and 56 exact radix-512 carries are witness
hints. The remainder is derived by Script, range checked, proved smaller than
`p = 2^256 - 2^32 - 977`, and returned in the same 29-digit representation.

The separate `factor16` profile stores a logical value as `E(x) = x/16 mod p`.
It reuses the same 646-product core, folds `16*a*b` to degree 28, and replaces
the ordinary relation's 67 hints with one signed residual and 28 carries. Its
output is `E(x*y)`, not an ordinary-domain product; `encode`/`decode` are host
helpers, and any in-Script conversion or mixed-profile routing is outside the
reported fragment.

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
  The factor-16 profile currently exposes one-shot and raw-wrapper APIs, not a
  resident-table or batch API.

### Script metrics

Every row is a generated fragment and excludes input pushes, terminal
predicate, output comparison, tapleaf/control-block serialization, and
transaction context. “Certified operands” means that range/canonical binding
was established earlier on the same script path. Witness bytes are consensus
serialization for the stated items and representative input `(p-1)^2`; they
are not maxima.

| Configuration | Locking script | Unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| Ordinary multiply, two certified operands | <!-- metric:secp256k1_field_mul -->20524<!-- /metric:secp256k1_field_mul --> bytes | <!-- metric:secp256k1_field_mul_hint_witness -->94<!-- /metric:secp256k1_field_mul_hint_witness --> bytes / <!-- metric:secp256k1_field_mul_hint_items -->67<!-- /metric:secp256k1_field_mul_hint_items --> incremental hint items | <!-- metric:secp256k1_field_mul_stack -->757<!-- /metric:secp256k1_field_mul_stack --> |
| Ordinary multiply from two raw operand encodings | <!-- metric:secp256k1_field_mul_standalone -->21800<!-- /metric:secp256k1_field_mul_standalone --> bytes | <!-- metric:secp256k1_field_mul_standalone_witness -->160<!-- /metric:secp256k1_field_mul_standalone_witness --> bytes / 125 complete data items | <!-- metric:secp256k1_field_mul_standalone_stack -->757<!-- /metric:secp256k1_field_mul_standalone_stack --> |
| Factor-16 multiply, two certified encoded operands | <!-- metric:secp256k1_field_factor16_mul -->20501<!-- /metric:secp256k1_field_factor16_mul --> bytes | <!-- metric:secp256k1_field_factor16_hint_witness -->37<!-- /metric:secp256k1_field_factor16_hint_witness --> bytes / <!-- metric:secp256k1_field_factor16_hint_items -->29<!-- /metric:secp256k1_field_factor16_hint_items --> incremental hint items | <!-- metric:secp256k1_field_factor16_stack -->719<!-- /metric:secp256k1_field_factor16_stack --> |
| Factor-16 multiply from two raw encoded operands | <!-- metric:secp256k1_field_factor16_standalone -->21777<!-- /metric:secp256k1_field_factor16_standalone --> bytes | <!-- metric:secp256k1_field_factor16_standalone_witness -->103<!-- /metric:secp256k1_field_factor16_standalone_witness --> bytes / 87 complete data items | <!-- metric:secp256k1_field_factor16_standalone_stack -->719<!-- /metric:secp256k1_field_factor16_standalone_stack --> |
| Two ordinary preloaded multiplies, certified operands | <!-- metric:secp256k1_field_mul_batch2 -->39400<!-- /metric:secp256k1_field_mul_batch2 --> bytes | <!-- metric:secp256k1_field_mul_batch2_hint_witness -->187<!-- /metric:secp256k1_field_mul_batch2_hint_witness --> bytes / 134 incremental hint items | <!-- metric:secp256k1_field_mul_batch2_stack -->882<!-- /metric:secp256k1_field_mul_batch2_stack --> |
| Three ordinary preloaded multiplies, certified operands | <!-- metric:secp256k1_field_mul_batch3 -->59163<!-- /metric:secp256k1_field_mul_batch3 --> bytes | <!-- metric:secp256k1_field_mul_batch3_hint_witness -->280<!-- /metric:secp256k1_field_mul_batch3_hint_witness --> bytes / 201 incremental hint items | <!-- metric:secp256k1_field_mul_batch3_stack -->993<!-- /metric:secp256k1_field_mul_batch3_stack --> |
| Square, one certified operand | <!-- metric:secp256k1_field_square -->14543<!-- /metric:secp256k1_field_square --> bytes | <!-- metric:secp256k1_field_square_hint_witness -->94<!-- /metric:secp256k1_field_square_hint_witness --> bytes / 67 incremental hint items | <!-- metric:secp256k1_field_square_stack -->614<!-- /metric:secp256k1_field_square_stack --> |
| Five preloaded squares, certified operands | <!-- metric:secp256k1_field_square_batch5 -->65074<!-- /metric:secp256k1_field_square_batch5 --> bytes | <!-- metric:secp256k1_field_square_batch5_hint_witness -->468<!-- /metric:secp256k1_field_square_batch5_hint_witness --> bytes / 335 incremental hint items | <!-- metric:secp256k1_field_square_batch5_stack -->998<!-- /metric:secp256k1_field_square_batch5_stack --> |

The one-shot multiplication is exactly:

| Component | Bytes |
| --- | ---: |
| Push 513-entry table | <!-- metric:secp256k1_field_mul_table_setup -->1538<!-- /metric:secp256k1_field_mul_table_setup --> |
| Drop table | <!-- metric:secp256k1_field_mul_table_drop -->257<!-- /metric:secp256k1_field_mul_table_drop --> |
| Low/high raw products | <!-- metric:secp256k1_field_mul_raw_products -->9374<!-- /metric:secp256k1_field_mul_raw_products --> |
| Normalized-difference products | <!-- metric:secp256k1_field_mul_difference_products -->5008<!-- /metric:secp256k1_field_mul_difference_products --> |
| Difference normalization | <!-- metric:secp256k1_field_mul_difference_normalization -->1103<!-- /metric:secp256k1_field_mul_difference_normalization --> |
| Coefficient-array routing | <!-- metric:secp256k1_field_mul_coefficient_routing -->173<!-- /metric:secp256k1_field_mul_coefficient_routing --> |
| Karatsuba recombination | <!-- metric:secp256k1_field_mul_coefficient_recombination -->532<!-- /metric:secp256k1_field_mul_coefficient_recombination --> |
| Quotient/carry relation, cleanup, output validation | <!-- metric:secp256k1_field_mul_relation_output -->2539<!-- /metric:secp256k1_field_mul_relation_output --> |
| **Total** | **20,524** |

Thus the static table lifecycle is 1,795 bytes, or 8.7% of one isolated
multiplication. The remaining
<!-- metric:secp256k1_field_mul_computation -->18729<!-- /metric:secp256k1_field_mul_computation -->
bytes are actual per-operation computation and routing. The fragment contains
<!-- metric:secp256k1_field_mul_opcodes -->13043<!-- /metric:secp256k1_field_mul_opcodes -->
static non-push opcodes. The raw wrapper adds
<!-- metric:secp256k1_field_operand_certification -->1276<!-- /metric:secp256k1_field_operand_certification -->
bytes to certify both operands.

The factor-16 profile has a distinct but nearly equal byte split:

| Factor-16 component | Bytes |
| --- | ---: |
| Push 513-entry table | <!-- metric:secp256k1_field_factor16_table_setup -->1538<!-- /metric:secp256k1_field_factor16_table_setup --> |
| Drop table | <!-- metric:secp256k1_field_factor16_table_drop -->257<!-- /metric:secp256k1_field_factor16_table_drop --> |
| Normalized-Karatsuba product generation | <!-- metric:secp256k1_field_factor16_product_generation -->15615<!-- /metric:secp256k1_field_factor16_product_generation --> |
| Folded exact relation and derived digits | <!-- metric:secp256k1_field_factor16_relation -->2674<!-- /metric:secp256k1_field_factor16_relation --> |
| Input/temporary cleanup and output certification | <!-- metric:secp256k1_field_factor16_cleanup -->417<!-- /metric:secp256k1_field_factor16_cleanup --> |
| **Total** | **20,501** |

Its static table lifecycle is the same 1,795 bytes; the other
<!-- metric:secp256k1_field_factor16_computation -->18706<!-- /metric:secp256k1_field_factor16_computation -->
bytes are computation. It contains
<!-- metric:secp256k1_field_factor16_opcodes -->13122<!-- /metric:secp256k1_field_factor16_opcodes -->
static non-push opcodes. The 23-byte locking-script advantage over the ordinary
profile is small; the material difference is 29 rather than 67 hints and 38
fewer peak stack items. Those savings apply only while values stay in the
factor-16 domain.

For repeated work, the table's 1,795-byte push/drop cost is paid once. Two
preloaded products use
<!-- metric:secp256k1_field_mul_batch2_computation -->37605<!-- /metric:secp256k1_field_mul_batch2_computation -->
bytes of non-table computation, including
<!-- metric:secp256k1_field_mul_batch2_relation -->18424<!-- /metric:secp256k1_field_mul_batch2_relation -->
bytes per normalized-Karatsuba relation, and average 19,700 total bytes each. Three use
<!-- metric:secp256k1_field_mul_batch3_computation -->57368<!-- /metric:secp256k1_field_mul_batch3_computation -->
non-table bytes, including
<!-- metric:secp256k1_field_mul_batch3_relation -->18744<!-- /metric:secp256k1_field_mul_batch3_relation -->
bytes per compact relation, and average 19,721 bytes each; destructive
recombination is slightly larger per gate but is what keeps the strict peak at
993. A resident-table single gate is
<!-- metric:secp256k1_field_mul_resident -->19963<!-- /metric:secp256k1_field_mul_resident -->
bytes; setup plus one final result-preserving cleanup of
<!-- metric:secp256k1_field_mul_resident_cleanup -->315<!-- /metric:secp256k1_field_mul_resident_cleanup -->
bytes totals
<!-- metric:secp256k1_field_mul_resident_total -->21816<!-- /metric:secp256k1_field_mul_resident_total -->
bytes. These resident figures do not include circuit-specific scheduling or
fan-out. Resident lookup memory must be emitted by the locking script through
`table_setup`; witness-supplied entries are not trusted table state.

The specialized square removes the unnecessary second operand and uses 435
quarter-square products. Its one-shot 14,543 bytes split into
<!-- metric:secp256k1_field_square_table_setup -->1538<!-- /metric:secp256k1_field_square_table_setup -->
setup,
<!-- metric:secp256k1_field_square_table_drop -->257<!-- /metric:secp256k1_field_square_table_drop -->
cleanup,
<!-- metric:secp256k1_field_square_diagonals -->406<!-- /metric:secp256k1_field_square_diagonals -->
diagonal-product bytes,
<!-- metric:secp256k1_field_square_off_diagonals -->9744<!-- /metric:secp256k1_field_square_off_diagonals -->
off-diagonal-product bytes, and
<!-- metric:secp256k1_field_square_relation_output -->2598<!-- /metric:secp256k1_field_square_relation_output -->
relation/output bytes. The table lifecycle is 1,795 bytes and computation is
<!-- metric:secp256k1_field_square_computation -->12748<!-- /metric:secp256k1_field_square_computation -->
bytes, with
<!-- metric:secp256k1_field_square_opcodes -->9423<!-- /metric:secp256k1_field_square_opcodes -->
static non-push opcodes.

The five-square batch uses an unbiased table: setup is
<!-- metric:secp256k1_field_square_batch5_table_setup -->1657<!-- /metric:secp256k1_field_square_batch5_table_setup -->
bytes, cleanup is
<!-- metric:secp256k1_field_square_batch5_table_drop -->257<!-- /metric:secp256k1_field_square_batch5_table_drop -->,
each relation is
<!-- metric:secp256k1_field_square_batch5_relation -->12268<!-- /metric:secp256k1_field_square_batch5_relation -->
bytes, and total non-table computation is
<!-- metric:secp256k1_field_square_batch5_computation -->63160<!-- /metric:secp256k1_field_square_batch5_computation -->
bytes. It averages 13,014.8 bytes per square but leaves only two stack items of
consensus headroom.

### Security and hint binding

The small gate is sound only for operands certified as canonical field values.
`certify_value`, `certify_mul_operands`, and the raw wrappers establish that
binding; same-shaped raw digit arrays are not certificates. Lower digits are
checked in `[-256, 256)`, the top digit and exact integer are checked against
the field modulus, and outputs repeat those checks before becoming reusable.

Hints are hostile. In the ordinary profile, 11 quotient digits and 56 carries
prove the exact integer identity `lhs*rhs = q*p + r` coefficient by coefficient.
In the factor-16 profile, one signed residual and 28 carries prove the folded
identity `G-t*p=r`, where `G` evaluates to `16*lhs*rhs`. Script derives `r` in
both profiles; it is not a witness hint. Ordinary quotient digits need not use
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
Factor-16 input instead ends in `t | c[27..0]`, and its certified output remains
factor-16 encoded. Squaring uses the analogous ordinary one-operand layout.
Batch group zero is nearest the top, is processed first, and its result is
returned nearest the top. Both main and altstack items count toward
`preserved_items` and the declared peak.

### Comparison boundary

The 20,524-byte ordinary native gate and the 31,281-byte prime-RNS composable gate both
consume two previously certified secp256k1 field values, bind hostile reduction
hints locally, and return a reusable certified result. Their certificate
representations differ: 29 balanced radix digits here versus 46 canonical RNS
residues, so conversion and fan-out costs are circuit-specific. The 10,952-byte
RNS carry gate is not comparable: it omits every global integer binding. The
51,055-byte RNS standalone gate performs four full limb-to-RNS bindings and
returns both limbs and residues, whereas this raw wrapper certifies two native
digit operands and derives the native result directly.

The 20,501-byte factor-16 row has the same exact-integer soundness boundary but
a different semantic encoding. It is like-for-like only when both inputs and
downstream consumers already use `E(x)=x/16`; the ordinary multiply, specialized
square, and preloaded ordinary batches do not preserve that domain. Host-side
`encode`/`decode` do not make an omitted in-Script conversion free.

BN254 `Fq` is a different base field with a different nine-limb multiplication
backend and certification convention. Its hinted-multiplication size is
orientation only—not a secp256k1 speedup ratio or interchangeable field
semantics. The checked BN254 inventory currently pins representative additions,
not a like-for-like certified multiplication boundary; OP-006 tracks that gap.

## Narrow fields: F257 and F12289

`f257` provides centered lookup multiplication and exact squares; `f12289`
provides the coefficient field and radix multiplication used for Falcon
experiments.

### Parameters

- There is no default field:
  - `F257`: `p = 257`.
  - `F12289`: `p = 12,289`.
- Generic `u31` operations use canonical coefficients in `[0, p)`.
- F257 log/exp multiplication and exact-square tables use centered
  coefficients in `[-128, 128]`. `f257::to_centered` and
  `f257::to_canonical` convert representations.
- F257 log/exp queries take `preserved_items`, the exact number of live items
  between table memory and the input. Constant queries also take a
  generation-time `i32` reduced modulo 257.
- F12289 radix generators take a generation-time `u32` constant,
  `radix_bits` in `1..=30`, and either `preserved_items` or a batch `count`.
  There is no default radix width; the measurements use `radix_bits = 7`.
- The generic full and half-table batch APIs are parameterized by a
  generation-time constant and `count`. The measured F257 batches use
  constant `173` and `count = 8`.

### Script metrics

Sizes exclude input pushes and output verification. Maximum stack items include
the main and altstack together. A “memory” size includes table setup and
cleanup; a query excludes that reusable memory. Depth 511/510 models a query
beside a 512-coefficient polynomial state.

| Fragment | Script size | Measured maximum stack |
| --- | ---: | ---: |
| `u31_mul::<F257>()` (31-bit baseline) | <!-- metric:f257_mul_baseline -->1238<!-- /metric:f257_mul_baseline --> bytes | 37 |
| `u31_mul_compact::<F257>()` | <!-- metric:f257_mul_compact -->345<!-- /metric:f257_mul_compact --> bytes | <!-- metric:f257_mul_compact_stack -->15<!-- /metric:f257_mul_compact_stack --> |
| `u31_mul_by_constant_centered::<F257>(173)` | <!-- metric:f257_mul_centered_173 -->132<!-- /metric:f257_mul_centered_173 --> bytes | <!-- metric:f257_mul_centered_stack -->4<!-- /metric:f257_mul_centered_stack --> |
| Full direct-table batch, 8 values | <!-- metric:f257_full_lookup_batch8 -->809<!-- /metric:f257_full_lookup_batch8 --> bytes | <!-- metric:f257_full_lookup_batch8_stack -->266<!-- /metric:f257_full_lookup_batch8_stack --> |
| Half-table batch, 8 values | <!-- metric:f257_half_lookup_batch8 -->573<!-- /metric:f257_half_lookup_batch8 --> bytes | <!-- metric:f257_half_lookup_batch8_stack -->139<!-- /metric:f257_half_lookup_batch8_stack --> |
| F257 log/exp memory | <!-- metric:f257_log_memory -->1196<!-- /metric:f257_log_memory --> bytes | 385 table items |
| Log/exp constant query, depth 511 | <!-- metric:f257_log_constant_query -->44<!-- /metric:f257_log_constant_query --> bytes | <!-- metric:f257_log_constant_stack -->900<!-- /metric:f257_log_constant_stack --> |
| Log/exp variable query, depth 510 | <!-- metric:f257_log_variable_query -->60<!-- /metric:f257_log_variable_query --> bytes | <!-- metric:f257_log_state_stack -->900<!-- /metric:f257_log_state_stack --> |
| Exact-square memory | <!-- metric:f257_square_memory -->499<!-- /metric:f257_square_memory --> bytes | 129 table items |
| Exact-square query, depth 511 | <!-- metric:f257_square_query -->11<!-- /metric:f257_square_query --> bytes | <!-- metric:f257_square_state_stack -->643<!-- /metric:f257_square_state_stack --> |
| `u31_mul_compact::<F12289>()` | <!-- metric:f12289_mul_compact -->517<!-- /metric:f12289_mul_compact --> bytes | <!-- metric:f12289_mul_compact_stack -->20<!-- /metric:f12289_mul_compact_stack --> |
| F12289 radix-128 memory | <!-- metric:f12289_radix128_memory -->781<!-- /metric:f12289_radix128_memory --> bytes | 225 table items |
| F12289 radix-128 query, depth 511 | <!-- metric:f12289_radix128_query -->135<!-- /metric:f12289_radix128_query --> bytes | <!-- metric:f12289_radix128_state_stack -->740<!-- /metric:f12289_radix128_state_stack --> |

For F257, the signed addition chain is best for isolated constants, the
129-item half table becomes smaller at about four repeated uses, and the full
table wins for larger same-constant batches. The 385-item log/exp memory is
shared across different constants and variable products; it amortizes after
roughly fourteen constant products or four variable products. For F12289, the
225-item radix-128 memory beats the average signed addition chain at roughly
nine uses of one constant.

### Security and input validity

These are arithmetic primitives and have no independent cryptographic security
parameter. They inherit any security claim from the protocol and field
parameters in which they are composed.

Inputs are not range-checked. Generic operations expect canonical field
elements; F257 log/exp and square queries expect centered elements. Values
outside the documented representation can produce incorrect arithmetic or make
`OP_PICK` address unrelated stack items. F257 log/exp multiplication returns a
centered field value. `f257::square_from_table` returns the exact, non-modular
integer square in `[0, 16,384]`.

### Script compatibility and standardness

The opcodes are available in legacy script and tapscript. The multiplication
fragments generally exceed the legacy 201-opcode execution limit, so tapscript
is the practical target. P2SH, P2WSH, and bare standard use are unsuitable for
large repeated-table compositions. Enclosing transactions must also respect
policy weight and witness limits.

The fragments leave field elements rather than one boolean, so they do not
satisfy cleanstack alone. The caller must consume or compare every output and
leave one truthy item.

### Witness, hints, and stack contract

No hints are required. A field element occupies one Script-number stack item.
Binary operations consume `... lhs rhs`, with `rhs` on top, and return one
field element.

Lookup queries use `tables | preserved_items | input`. The table and preserved
items remain while the input is replaced by its result. Cleanup requires the
table memory at the top. Batch wrappers handle this with the altstack and
reject compositions that by themselves exceed 1,000 items; callers must count
unrelated live items separately.

The 385-item F257 log/exp memory and 129-item exact-square memory cannot coexist
with a 512-item state under the 1,000-item limit. Install and drop them in
separate multiplication and norm-check phases.

### Operational notes

Correctness tests cover boundary, randomized, and exhaustive table cases.
Regression tests pin serialized sizes and maximum stack depth, while
`tests/primitive_metrics.rs` keeps this README synchronized with generated
scripts.

The existing five-channel RNS primitive is not a competitive backend here. Its
multiplication fragment alone is 1,564 bytes before scalar conversion, CRT
reconstruction, and final reduction. For F12289 its combined modulus 69,300 is
too small to reconstruct an arbitrary canonical product. An RNS-encoded
512-coefficient state would require 2,560 stack items.
