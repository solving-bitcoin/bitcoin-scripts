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
| `U254::mul()` | <!-- metric:u254_mul -->111466<!-- /metric:u254_mul --> bytes |

The 176-byte addition uses the repository's general optimizer. The 111,466-byte
multiplication exceeds its 64 KiB input cutoff and is reported unoptimized.

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
