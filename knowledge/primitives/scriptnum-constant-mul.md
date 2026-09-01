# ScriptNum constant multiplication

Generates double-and-add Script for multiplication by a compile-time constant
without disabled `OP_MUL`. Inputs and all intermediates must remain valid
four-byte Script numbers.

- **Position:** smallest local arithmetic construction when one operand is a
  known constant and the value stays in ScriptNum range.
- **Evidence:** locally reproduced with positive and boundary tests.
- **Deployment:** opcode-compatible broadly; complete-script limits still apply.
- **Representative result:** multiplier 13 uses a 10-byte fragment.
- **Alternatives:** u31 constant chains for field values; bigint limbs for wider
  values; lookup tables for repeated modular products.

See the [implementation README](../../src/arithmetic/scriptint/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/scriptnum-constant-mul`.
