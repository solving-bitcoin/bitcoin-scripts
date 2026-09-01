# Residue-number arithmetic

Represents an integer by residues modulo a fixed coprime basis and evaluates
addition, subtraction, and multiplication with lookup tables.

- **Position:** small add/sub fragments and table-driven multiplication for a
  bounded composite modulus.
- **Evidence:** locally reproduced with boundary, random, and exhaustive table
  checks.
- **Representative basis:** `[4, 9, 25, 7, 11]`, product 69,300.
- **Representative results:** add 219 bytes, subtract 221, multiply 1,564 with
  a 903-item peak.
- **Tradeoff:** multiplication is close to the consensus stack ceiling and uses
  an asymmetric indexed-row/ordinary operand encoding.

See the [implementation README](../../src/arithmetic/rns/README.md) and catalog
record `arithmetic/rns`.
