# u31 prime-field arithmetic

Bitcoin Script arithmetic for configurable prime fields, with presets for M31
and BabyBear plus the degree-four extensions QM31 and BabyBear4. Concrete
narrow fields are built on this backend in [`../fields`](../fields/). The
original 31-bit implementation is ported from
[`rust-bitcoin-m31-or-babybear`](https://github.com/BitVM/rust-bitcoin-m31-or-babybear/tree/1015e3393c7310f0f30f0b73ff4a7f2bc1a5173e).
Its upstream MIT notice is preserved in [`LICENSE`](LICENSE).

## Parameters

- Base-field configuration is required; there is no default:
  - `M31`: `p = 2^31 - 1`.
  - `BabyBear`: `p = 15 * 2^27 + 1`.
- Canonical `u31` representation: `x` in `[0, p)`.
- Internal `v31` representation: `x - p` in `[-p, 0)`.
- `QM31`: `F_(p²)[y] / (y² - 2 - i)` over `F_p[i] / (i² + 1)`.
- `BabyBear4`: `F_p[x] / (x^4 + 11)`, matching RISC Zero rather than
  Plonky3's `x^4 - 11` convention.
- `u31_mul_by_constant` and `u31ext_mul_u31_by_constant` take a
  generation-time `u32` constant. Their size depends on its relaxed NAF. The
  representative metric uses `0x12345678`.
- `u31_mul_compact` derives the minimum safe operand width from the modulus.
- `u31_mul_by_constant_centered` reduces the constant modulo `p` and emits the
  shorter signed addition chain for `c` or `c - p`.
- Full and symmetry-reduced lookup tables can be installed once and
  reused by several fixed-constant multiplications. Batch wrappers preserve
  input order and reject compositions that by themselves exceed 1,000 stack
  items; callers must also count unrelated live stack items.
- Lookup generators have no implicit defaults:
  - `count` is the contiguous batch size; zero emits an empty fragment.
  - `preserved_items` is the exact number of live items between the table and
    the input operand. Query constructors reject an intrinsically oversized
    layout, but the caller remains responsible for items below the table.
  - A full direct table requires `2 <= p < 1,000`.
  - A symmetry-reduced table requires an odd `3 <= p < 2^31` and enough room
    for its `(p / 2) + 1` entries plus a query.

## Script metrics

Sizes exclude input pushes and output verification. Maximum stack items are
measured with maximum or boundary-valued inputs in the documented
representation and include the main and altstack together.

| Base-field fragment | Script size | Maximum stack items |
| --- | ---: | ---: |
| `u31_add::<M31>()` | <!-- metric:u31_add -->18<!-- /metric:u31_add --> bytes | 3 |
| `u31_sub::<M31>()` | <!-- metric:u31_sub -->12<!-- /metric:u31_sub --> bytes | 3 |
| `u31_mul::<M31>()` | <!-- metric:u31_mul -->1400<!-- /metric:u31_mul --> bytes | 37 |
| `u31_mul_by_constant::<M31>(0x12345678)` | <!-- metric:u31_mul_constant -->736<!-- /metric:u31_mul_constant --> bytes | 4 |

M31 and BabyBear have identical sizes for non-constant base-field operations.
A witness-supplied binary operation uses two stack items and serializes to
<!-- metric:u31_witness_min -->3<!-- /metric:u31_witness_min -->–<!-- metric:u31_witness_max -->11<!-- /metric:u31_witness_max -->
witness bytes, depending on the values.

| Degree-four fragment | Script size | Maximum stack items |
| --- | ---: | ---: |
| `u31ext_add::<QM31>()` | <!-- metric:qm31_add -->84<!-- /metric:qm31_add --> bytes | 9 |
| `u31ext_sub::<QM31>()` | <!-- metric:qm31_sub -->63<!-- /metric:qm31_sub --> bytes | 9 |
| `u31ext_mul::<QM31>()` | <!-- metric:qm31_mul -->13186<!-- /metric:qm31_mul --> bytes | 52 |
| `u31ext_mul::<BabyBear4>()` | <!-- metric:babybear4_mul -->13441<!-- /metric:babybear4_mul --> bytes | 53 |
| `u31ext_mul_u31::<QM31>()` | <!-- metric:qm31_mul_base -->4642<!-- /metric:qm31_mul_base --> bytes | 133 |
| `u31ext_mul_u31_by_constant::<QM31>(0x12345678)` | <!-- metric:qm31_mul_constant -->2950<!-- /metric:qm31_mul_constant --> bytes | 7 |

Degree-four addition and subtraction have the same sizes for QM31 and
BabyBear4. A binary extension operation uses eight witness items and serializes
to <!-- metric:u31ext_witness_min -->9<!-- /metric:u31ext_witness_min -->–<!-- metric:u31ext_witness_max -->41<!-- /metric:u31ext_witness_max -->
witness bytes.

## Security and input validity

These are arithmetic primitives, not commitments, hashes, or authenticated
encryption, so they have no independent cryptographic security parameter.
Generic, direct-table, and half-table inputs are assumed to be canonical field
elements in `[0, p)`. None of the fragments range-check adversarial witness
values. Supplying a value outside the documented representation can invalidate
the arithmetic or address unrelated stack items with `OP_PICK`.

Generic operations return canonical `u31` values. Multiplication uses two-bit
windows, constant multiplication uses relaxed NAF, and degree-four
multiplication uses double Karatsuba. No side-channel claim is made about
generation-time constant selection.

## Script compatibility and standardness

The opcode set is available in legacy script and tapscript. Small operations
such as addition and subtraction can be composed in legacy script, subject to
the enclosing script's policy limits. Multiplication and repeated table queries
generally exceed the legacy 201-opcode execution limit, and degree-four
multiplication also exceeds the legacy 10,000-byte script limit, so tapscript is
the compatible target for those fragments. P2SH, P2WSH, and bare standard use
are unsuitable for the large multiplication fragments.

The fragments return field elements rather than a single boolean and therefore
do not satisfy cleanstack on their own. The caller must consume or compare all
output coefficients and leave one truthy item.

## Witness and hints

No hints are required. A base-field element occupies one Script number. A
degree-four element occupies four items with coefficient zero on top and
coefficient three deepest. For binary operations, the right operand is on top.
Generation-time multiplication constants and lookup memories are public in the
locking script and are not witness items.

## Stack contract

For a base-field binary operation, the main stack ends in `... lhs rhs` with
`rhs` on top; both inputs are consumed and one canonical result is returned.
For degree-four binary operations it ends in `... lhs[3..0] rhs[3..0]`, with
`rhs[0]` on top; eight items are consumed and four canonical result
coefficients are returned. Every public arithmetic fragment balances its own
altstack use.

`u31ext_mul_u31` expects a four-coefficient extension element below one
base-field scalar. `u31ext_copy(offset)` and `u31ext_roll(offset)` count whole
four-item elements from the top, with offset zero denoting the top element.

Lookup query functions take `preserved_items`, the number of live items between
their table memory and input. Table cleanup requires the memory to be at the
top; batch wrappers move inputs and outputs through the altstack to satisfy
that contract.

## Operational notes

Boundary and deterministic randomized tests compare both base and extension
operations with native Rust modular arithmetic. Separate regression assertions
pin serialized sizes and maximum stack depth. The metric snapshot test keeps
the README values synchronized with generated scripts.
