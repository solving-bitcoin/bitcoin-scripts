# Concrete prime fields

Concrete narrow prime fields implemented over the generic [`u31`](../u31/)
ScriptNum backend. `f257` provides centered lookup multiplication and exact
squares; `f12289` provides the coefficient field and radix multiplication used
for Falcon experiments.

## Parameters

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

## Script metrics

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

## Security and input validity

These are arithmetic primitives and have no independent cryptographic security
parameter. They inherit any security claim from the protocol and field
parameters in which they are composed.

Inputs are not range-checked. Generic operations expect canonical field
elements; F257 log/exp and square queries expect centered elements. Values
outside the documented representation can produce incorrect arithmetic or make
`OP_PICK` address unrelated stack items. F257 log/exp multiplication returns a
centered field value. `f257::square_from_table` returns the exact, non-modular
integer square in `[0, 16,384]`.

## Script compatibility and standardness

The opcodes are available in legacy script and tapscript. The multiplication
fragments generally exceed the legacy 201-opcode execution limit, so tapscript
is the practical target. P2SH, P2WSH, and bare standard use are unsuitable for
large repeated-table compositions. Enclosing transactions must also respect
policy weight and witness limits.

The fragments leave field elements rather than one boolean, so they do not
satisfy cleanstack alone. The caller must consume or compare every output and
leave one truthy item.

## Witness, hints, and stack contract

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

## Operational notes

Correctness tests cover boundary, randomized, and exhaustive table cases.
Regression tests pin serialized sizes and maximum stack depth, while
`tests/primitive_metrics.rs` keeps this README synchronized with generated
scripts.

The existing five-channel RNS primitive is not a competitive backend here. Its
multiplication fragment alone is 1,564 bytes before scalar conversion, CRT
reconstruction, and final reduction. For F12289 its combined modulus 69,300 is
too small to reconstruct an arbitrary canonical product. An RNS-encoded
512-coefficient state would require 2,560 stack items.
