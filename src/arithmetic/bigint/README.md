# Big integer arithmetic

Unsigned fixed-width Script integers split into configurable limbs.

## Parameters

- `BigIntImpl<N_BITS, LIMB_SIZE>`: total width and limb width.
- `N_LIMBS = ceil(N_BITS / LIMB_SIZE)` and the head limb is shortened as
  needed. `LIMB_SIZE` must be below 31 and at least two limbs are required.
- Defaults/type aliases: `U254 = <254,29>`, `U256 = <256,29>`, and
  `U64 = <64,16>`.

## Script metrics

Sizes below are operation fragments for the default `U254`; operands and final
verification are not included. Witness size and maximum depth depend on the
operation and operand placement.

| Fragment | Script size |
| --- | ---: |
| `U254::add(1, 0)` | <!-- metric:u254_add -->176<!-- /metric:u254_add --> bytes |
| `U254::add_nocarry(1, 0)` | <!-- metric:u254_add_nocarry -->142<!-- /metric:u254_add_nocarry --> bytes |
| `U254::sub(1, 0)` | <!-- metric:u254_sub -->190<!-- /metric:u254_sub --> bytes |
| `U254::sub_noborrow(1, 0)` | <!-- metric:u254_sub_noborrow -->107<!-- /metric:u254_sub_noborrow --> bytes |
| `U254::mul()` | <!-- metric:u254_mul -->111466<!-- /metric:u254_mul --> bytes |

`U254::add_nocarry(1, 0)` is a carry-free fragment with an explicit per-limb
carry check: corresponding canonical limbs must sum strictly below their
radix. With two zero-valued operand vectors supplied as the complete
eighteen-item data witness, it uses
<!-- metric:u254_add_nocarry_witness -->19<!-- /metric:u254_add_nocarry_witness --> witness bytes,
<!-- metric:u254_add_nocarry_hints -->0<!-- /metric:u254_add_nocarry_hints --> auxiliary hint items,
and reaches a combined main-plus-alt-stack peak of
<!-- metric:u254_add_nocarry_stack -->19<!-- /metric:u254_add_nocarry_stack --> items.
The tapscript interpreter counts
<!-- metric:u254_add_nocarry_opcodes -->97<!-- /metric:u254_add_nocarry_opcodes --> fragment instructions
for this execution; the terminal truthy opcode is excluded.

The carry-free check does not independently prove that each input limb is a
canonical non-negative ScriptNum. Callers handling hostile witnesses must
compose `check_validity()` before this fragment. Unlike `U254::add(1, 0)`,
which propagates carries and returns modulo `2^254`, this operation rejects a
limb sum at or above its radix and returns the exact wide sum under that
precondition.

`U254::sub_noborrow(1, 0)` is a borrow-free fragment: each corresponding
canonical limb of the first operand must be at least the limb of the second.
It rejects a per-limb underflow and returns the exact difference in the same
layout. With two zero-valued U254 vectors as the complete eighteen-item data
witness, it uses
<!-- metric:u254_sub_noborrow_witness -->19<!-- /metric:u254_sub_noborrow_witness --> witness bytes,
<!-- metric:u254_sub_noborrow_hints -->0<!-- /metric:u254_sub_noborrow_hints --> auxiliary hint items,
and reaches a combined main-plus-alt-stack peak of
<!-- metric:u254_sub_noborrow_stack -->19<!-- /metric:u254_sub_noborrow_stack --> items.
The tapscript interpreter counts
<!-- metric:u254_sub_noborrow_opcodes -->97<!-- /metric:u254_sub_noborrow_opcodes --> fragment instructions;
the terminal truthy opcode is excluded.

The underflow check does not independently prove canonical non-negative input
limbs. Callers handling hostile witnesses must compose `check_validity()` on
both operands first. Unlike `U254::sub(1, 0)`, which propagates borrows and
returns modulo `2^254`, this operation requires every limb comparison to hold
and returns the exact wide difference.

The 176-byte addition uses the repository's general optimizer. The 111,466-byte
multiplication exceeds its 32 KiB input cutoff and is reported unoptimized.

## Security

No cryptographic claim. Arithmetic is modulo `2^N_BITS` where documented;
some variants prevent overflow and others explicitly allow it.

## Script compatibility and standardness

The basic fragments are opcode-compatible with legacy script and tapscript.
Large multiplication and composed field arithmetic may exceed legacy opcode,
script-size, or policy limits. Complete callers must enforce cleanstack.

## Witness and hints

No hints are needed for basic integer arithmetic. Values occupy `N_LIMBS`
stack items in little-endian limb order as documented by `stack.rs`.
