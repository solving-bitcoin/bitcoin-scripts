# Multi-limb big integers

Represents fixed-width unsigned values as configurable little-endian limbs and
provides stack, bit, comparison, addition, subtraction, multiplication, and
inversion helpers.

- **Position:** general local backend for values wider than ScriptNum, including
  BN254 base and scalar fields.
- **Evidence:** locally reproduced with deterministic arkworks/native checks.
- **Representative configuration:** U254 uses nine 29-bit limbs; add is 190
  bytes and full multiplication is 111,466 bytes.
- **Tradeoff:** generality and compact stack representation produce very large
  multiplication scripts.
- **Trust boundary:** range and canonical limb constraints must be enforced at
  protocol boundaries.

See the [implementation README](../../src/arithmetic/bigint/README.md) and
catalog record `arithmetic/bigint`.
