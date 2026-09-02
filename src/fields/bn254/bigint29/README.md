# BN254 bigint29 field backend

Prime fields `Fq` and `Fr` plus extension fields `Fq2`, `Fq6`, and `Fq12`.

## Parameters

- Field moduli: fixed by BN254; `Fq` and `Fr` expose their own constants.
- Representation: `BigIntImpl<254,29>`, nine little-endian limbs with a shorter
  head limb.
- Extension tower and non-residues: fixed by BN254/arkworks.
- Operand depths are generation-time parameters. There is no universal default;
  binary metrics use adjacent elements at base-field coefficient depths
  `(1, 0)`, `(2, 0)`, `(6, 0)`, and `(12, 0)` for `Fq`/`Fr`, `Fq2`, `Fq6`,
  and `Fq12`, respectively.

## Script metrics

Locking-script sizes are operation fragments and exclude operand pushes,
witness-hint pushes, result checks, and a terminal predicate. Maximum stack
items are measured by executing the fragment with the deterministic operands
in `tests/primitive_metrics.rs`; they count the combined main and alt stacks,
including every hint and operand item. The metric executor uses tapscript and
disables the consensus stack limit, so these are `research-unlimited` results.

| Field | Fragment | Locking script | Maximum stack items |
| --- | --- | ---: | ---: |
| `Fq` | `add(1, 0)` | <!-- metric:fq_add -->404<!-- /metric:fq_add --> bytes | <!-- metric:fq_add_stack -->22<!-- /metric:fq_add_stack --> |
| `Fq` | `hinted_mul(1, a, 0, b)` | <!-- metric:fq_mul -->67744<!-- /metric:fq_mul --> bytes | <!-- metric:fq_mul_stack -->297<!-- /metric:fq_mul_stack --> |
| `Fq` | `hinted_square(a)` | <!-- metric:fq_square -->67735<!-- /metric:fq_square --> bytes | <!-- metric:fq_square_stack -->297<!-- /metric:fq_square_stack --> |
| `Fq` | `hinted_inv(a)` | <!-- metric:fq_inv -->67832<!-- /metric:fq_inv --> bytes | <!-- metric:fq_inv_stack -->306<!-- /metric:fq_inv_stack --> |
| `Fr` | `add(1, 0)` | <!-- metric:fr_add -->404<!-- /metric:fr_add --> bytes | <!-- metric:fr_add_stack -->22<!-- /metric:fr_add_stack --> |
| `Fq2` | `add(2, 0)` | <!-- metric:fq2_add -->824<!-- /metric:fq2_add --> bytes | <!-- metric:fq2_add_stack -->40<!-- /metric:fq2_add_stack --> |
| `Fq2` | `hinted_mul(2, a, 0, b)` | <!-- metric:fq2_mul -->190619<!-- /metric:fq2_mul --> bytes | <!-- metric:fq2_mul_stack -->270<!-- /metric:fq2_mul_stack --> |
| `Fq2` | `hinted_square(a)` | <!-- metric:fq2_square -->136834<!-- /metric:fq2_square --> bytes | <!-- metric:fq2_square_stack -->342<!-- /metric:fq2_square_stack --> |
| `Fq6` | `add(6, 0)` | <!-- metric:fq6_add -->2472<!-- /metric:fq6_add --> bytes | <!-- metric:fq6_add_stack -->112<!-- /metric:fq6_add_stack --> |
| `Fq6` | `hinted_mul(6, a, 0, b)` | <!-- metric:fq6_mul -->1066421<!-- /metric:fq6_mul --> bytes | <!-- metric:fq6_mul_stack -->486<!-- /metric:fq6_mul_stack --> |
| `Fq6` | `hinted_square(a)` | <!-- metric:fq6_square -->766199<!-- /metric:fq6_square --> bytes | <!-- metric:fq6_square_stack -->468<!-- /metric:fq6_square_stack --> |
| `Fq12` | `add(12, 0)` | <!-- metric:fq12_add -->5034<!-- /metric:fq12_add --> bytes | <!-- metric:fq12_add_stack -->220<!-- /metric:fq12_add_stack --> |
| `Fq12` | `hinted_mul(12, a, 0, b)` | <!-- metric:fq12_mul -->3217947<!-- /metric:fq12_mul --> bytes | <!-- metric:fq12_mul_stack -->882<!-- /metric:fq12_mul_stack --> |
| `Fq12` | `hinted_square(a)` | <!-- metric:fq12_square -->2155690<!-- /metric:fq12_square --> bytes | <!-- metric:fq12_square_stack -->684<!-- /metric:fq12_square_stack --> |

The addition rows receive the repository's general optimizer. Every hinted
multiplication, square, and inversion row exceeds its 32 KiB input cutoff and
is reported unoptimized.

These are representative arithmetic paths, not a full hint-producing-operation
inventory. Sparse multiplication, Frobenius maps, retained-operand variants,
and validity predicates remain operation- and parameter-specific.

## Security

Field operations provide correctness, not cryptographic security in isolation.
Canonical range checks are required at trust boundaries. The enclosing BN254
protocol has roughly 100-bit pairing security.

## Script compatibility and standardness

Basic additions may fit multiple script types, while hinted extension-field
operations can exceed legacy/P2WSH policy or execution limits. Tapscript is the
intended research target. Callers must arrange final cleanstack behavior.

## Witness and hints

Addition, subtraction, negation, and stack utilities need no hints. Hinted
multiplication, square, inversion, and Frobenius helpers return a script plus an
ordered `Vec<Hint>` that must be serialized into the witness before operands.
