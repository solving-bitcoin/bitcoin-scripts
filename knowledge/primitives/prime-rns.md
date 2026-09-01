# Prime residue-number arithmetic

The implementation now exposes two exact-carry secp256k1 modular-product
profiles with different trust boundaries. The 42-prime profile is the compact
choice when a surrounding protocol already binds every RNS vector. The
36-prime `carry::bound` profile performs those global bindings and field-range
checks inside the measured fragment.

- **Evidence:** `locally-reproduced`. Deterministic correct-product,
  malformed-carry, field-bound, reusable-binding, preserved-state, exact-peak,
  and 1,000-item strict-stack tests execute in a tapscript context under
  `bitcoin-scriptexec`; checked metrics reproduce the values below.
- **Conditional 42-prime profile:** its 513-bit product basis exceeds
  `2^512`. Each coordinate verifies
  `lhs_i * center(rhs_i) - q_i * center(N_i) - r_i = carry_i * p_i`.
  Eighteen selected coordinates also bind `c = N - 1 - r`; their subbasis
  product exceeds `2^257`. The fragment is 10,952 locking-script bytes with a
  301-byte, 144-item hint and a strict 231-item peak.
- **Conditional binding obligation:** the 42-prime fragment assumes every
  supplied `lhs`, `rhs`, `q`, `r`, and partial-complement coordinate is tied to
  the canonical residues of one corresponding unsigned integer below
  `2^256`; `lhs` and `rhs` must also be below `N`. It does not validate operand
  coordinates or provide those global bindings locally.
- **Standalone 36-prime profile:** four hostile values are supplied as 16
  centered base-`2^16` limbs. For every prime, four exact dot-product carries
  derive canonical residues from those same limb vectors before an exact
  multiplication-relation carry is checked. The basis product has 521 bits.
  Limb checks bound all four values below `2^256`; fixed-target comparisons
  prove `lhs`, `rhs`, and `r` below `N`, so no complement is required.
- **Standalone witness and output:** the complete data witness has 244 items:
  64 limbs, 144 residue-binding carries, and 36 relation carries. For
  `(N-1)^2` it serializes to 722 bytes. The fragment returns the 16 centered
  remainder limbs beneath its 36 canonical residues.
- **Standalone metrics:** `carry::bound::mul_mod_hinted` is 88,225
  locking-script bytes, contains 79,271 static non-push opcodes, and reaches a
  strict combined-stack peak of 249 items. Its bytes split into 1,060 for
  range checks, 75,732 for four residue bindings, 11,121 for modular
  relations, and 312 for routing and output. It uses no lookup tables.
- **Reusable binding:** `carry::bound::bind_value` certifies one persistent
  16-limb value and returns both its limbs and 36 residues in 19,147 bytes:
  208 bytes of limb validation, 18,867 bytes of residue binding, and 72 bytes
  of routing. This proves only the unsigned `<2^256` bound.
  `bind_value_below(N)` costs 19,234 bytes and additionally proves the field
  bound required for `lhs`, `rhs`, or `r` unless another fragment establishes
  it. A composed protocol can pay the appropriate binder at value introduction
  instead of repeatedly using the fused standalone verifier.
- **Why the global proof is exact:** the shared limbs prevent coordinates from
  referring to unrelated CRT representatives. With `lhs,rhs,r < N < 2^256`
  and `q < 2^256`, both sides of `lhs*rhs = q*N + r` are below `2^512`.
  Congruence modulo the 521-bit basis product therefore implies ordinary
  integer equality, and `r < N` makes the returned remainder canonical.
- **Wraparound boundary of the conditional profile:** without its external
  quotient binding, `lhs = rhs = 0`, `q = floor(M/N)`, and `r = M mod N`
  satisfy all coordinate relations while returning a wrong nonzero remainder.
  Adding `p_i` to an unchecked operand coordinate and adjusting its carry is a
  second accepted shift. The standalone limb-to-residue bindings close both
  attacks; they remain valid counterexamples to the smaller conditional API.
- **No-carry baseline:** the 75-prime per-coordinate table/Horner hybrid is
  15,628 bytes at a 183-item peak. Its 392 bytes of table pushes and 153 bytes
  of cleanup contrast with the table-free carry profiles. The no-carry
  modular verifier is 25,777 bytes, of which only 183 bytes are table
  lifecycle; like the 42-prime verifier, it excludes the required global
  bindings for its supplied coordinate vectors.
- **Batch result:** `prime::batch::mul(6, ...)` processes six coordinate-major
  products in 64,462 bytes with results on the altstack, or 64,912 bytes after
  restoring all 450 outputs, at a strict 900-item peak. Seven products cannot
  enter this layout because their 1,050 operands already exceed the stack
  limit.
- **Deployment:** `unclassified`. These are generated fragments rather than
  complete leaves. Terminal predicates, tapleaf and control-block
  serialization, transaction weight, Bitcoin Core consensus comparison, and
  relay-policy acceptance remain unmeasured. The 79,271 figure is a static
  opcode count, not an executed-opcode or validation-budget measurement.
- **Research need:** compose reusable bound values through a complete program,
  measure complete leaf and transaction costs, and differentially validate a
  fixed transaction against a pinned Bitcoin Core revision.

See the [standalone-bound source](../../src/arithmetic/rns/prime/carry/bound.rs),
[conditional carry source](../../src/arithmetic/rns/prime/carry.rs),
[no-carry baseline source](../../src/arithmetic/rns/prime.rs),
[implementation README](../../src/arithmetic/rns/README.md),
[lookup comparison](../comparisons/lookup-strategies.md), and catalog record
`arithmetic/prime-rns`.
