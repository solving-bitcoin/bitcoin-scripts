# Hinted ScriptNum division

Verifies a witness-supplied quotient for division by a positive compile-time
constant and derives the Euclidean remainder without `OP_DIV` or `OP_MOD`.

- **Position:** compact local division when the divisor is public and all
  arithmetic fits ScriptNum.
- **Evidence:** locally reproduced, including wrong-hint rejection.
- **Trust boundary:** the quotient is hostile witness data and is constrained
  by recomposition and remainder bounds.
- **Representative result:** `hinted_div_rem(8)` is 13 bytes with a 3–11 byte
  serialized witness in the measured range.
- **Limitation:** not a general wide-integer division primitive.

See the [implementation README](../../src/arithmetic/scriptint/README.md) and
catalog record `arithmetic/scriptnum-hinted-div`.
