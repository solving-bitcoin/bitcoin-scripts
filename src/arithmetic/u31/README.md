# Generic u31 field arithmetic

This module is a modulus-agnostic backend for prime fields whose canonical
elements fit in a positive four-byte Script number. Concrete field
configurations live under [`../../fields`](../../fields/), including
[M31](../../fields/m31/), [BabyBear](../../fields/babybear/),
[F257](../../fields/f257/), and [F12289](../../fields/f12289/).

The implementation is ported from
[`rust-bitcoin-m31-or-babybear`](https://github.com/BitVM/rust-bitcoin-m31-or-babybear/tree/1015e3393c7310f0f30f0b73ff4a7f2bc1a5173e);
the upstream MIT notice is preserved in [`LICENSE`](LICENSE).

## Backend contract

- `U31Config` supplies a modulus strictly below `2^31`; there is no default.
- Canonical `u31(x)` is `x` in `[0, p)`. Internal `v31(x)` is `x - p`.
- Binary operations consume `... lhs rhs` and return one canonical value.
- `U31ExtConfig` supplies the base configuration, degree, and multiplication
  formula for an extension field. Coefficient zero is nearest the top.
- Constant multiplication uses a generation-time constant. Compact
  multiplication derives its bit width from the modulus.
- Full and symmetry-reduced lookup tables may be shared across a batch.
  `preserved_items` is the exact number of live items between memory and the
  query; callers must also count unrelated state below the table.
- Generators reject layouts that intrinsically exceed 1,000 combined stack
  items. This does not replace composition-level accounting.

## Validity and deployment

The generic operations do not range-check hostile inputs. A concrete field's
README defines its accepted representation, measured configuration, and any
additional lookup constraints. No hints are required by this backend.

Small additions can be used in legacy script subject to enclosing limits;
multiplication and degree-four extension operations are tapscript-oriented.
Fragments return values rather than a terminal boolean, so callers must
consume all outputs and arrange cleanstack.

Backend tests use local configurations to verify generic boundary and
randomized behavior. Concrete-field metric snapshots are owned by their field
READMEs rather than this machinery module.
