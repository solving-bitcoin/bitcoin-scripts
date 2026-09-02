# Prime residue-number arithmetic

The implementation now exposes three exact-carry secp256k1 modular-product
profiles with different trust boundaries. The 42-prime profile is the compact
choice when a surrounding protocol already binds every RNS vector. The
47-prime `carry::bound` profile performs all four global bindings and
field-range checks inside one measured fragment. The 46-prime
`carry::composable` profile certifies field values once, consumes two certified
residue vectors per multiplication, and returns a certificate that another
multiplication can reuse.

- **Evidence:** `locally-reproduced`. Deterministic correct-product,
  malformed-carry, detached-CRT-quotient, wide-centered-product, field-bound,
  reusable-binding, two-gate certificate-chain, preserved-state, exact-peak,
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
- **Standalone 47-prime profile:** four hostile values are supplied as 16
  centered base-`2^16` limbs. For every prime, four exact dot-product carries
  derive canonical residues from those same limb vectors before an exact
  multiplication-relation carry is checked. The basis product has 513 bits.
  Limb checks bound all four values below `2^256`; fixed-target comparisons
  prove `lhs`, `rhs`, and `r` below `N`, so no complement is required.
- **Standalone witness and output:** the complete data witness has 299 items:
  64 limbs, 188 residue-binding carries, and 47 relation carries. For
  `(N-1)^2` it serializes to 868 bytes. The fragment returns the 16 centered
  remainder limbs beneath its 47 canonical residues.
- **Standalone metrics:** `carry::bound::mul_mod_hinted` is 51,055
  locking-script bytes, contains 32,772 static non-push opcodes, and reaches a
  strict combined-stack peak of 305 items. Its bytes split into 1,060 for
  range checks, 38,801 for four residue bindings, 10,794 for modular
  relations, and 400 for routing and output. It uses no lookup tables, so the
  static table-push/drop overhead is zero. Relative to the previous 88,225-byte
  exact-dot profile, the locking fragment is 37,170 bytes (42.1%) smaller.
- **Reusable binding:** `carry::bound::bind_value` certifies one persistent
  16-limb value and returns both its limbs and 47 residues in 9,777 bytes:
  208 bytes of limb validation, 9,475 bytes of residue binding, and 94 bytes
  of routing. This proves only the unsigned `<2^256` bound.
  `bind_value_below(N)` costs 9,864 bytes and additionally proves the field
  bound required for `lhs`, `rhs`, or `r` unless another fragment establishes
  it. A composed protocol can pay the appropriate binder at value introduction
  instead of repeatedly using the fused standalone verifier.
- **Binding optimization:** each exact 16-limb dot selects the shortest of
  independent constant products, one shared width-2 NAF doubling chain, and a
  common-factor form. Every emitted prefix is bounded against four-byte
  ScriptNum arithmetic. Target-aware centering admits the two widest primes;
  generation rejects a target whose relation or fixed-target multiplication
  would have an unsafe transient.
- **Composable 46-prime profile:** `carry::composable::mul_mod_hinted` assumes
  `lhs` and `rhs` are verified-path outputs of its own binder or an earlier
  composable multiplication. It locally range-checks and binds the hostile
  16-limb quotient and remainder, proves `r < N`, checks all 46 exact relation
  carries, consumes both operand certificates, and returns only a certified
  canonical remainder vector. Raw witness residues or independent
  coordinate-local checks do not satisfy the operand precondition.
- **Composable metrics:** the gate is 31,281 locking-script bytes, contains
  20,799 static non-push opcodes, and has a strict 267-item combined-stack
  peak. Its bytes split into 444 of limb/field validation, 9,852 of quotient
  binding, 9,664 of remainder binding, 10,799 of modular relations, and 522 of
  routing/output. Its table push and cleanup are both zero. For `(N-1)^2`, the
  170 incremental q/r limb-and-carry items serialize to 471 bytes; the two
  live 46-residue operand certificates are excluded.
- **Composable introduction binder:** `carry::composable::bind_value` is 9,835
  bytes with 6,168 static non-push opcodes and a strict 72-item peak. It spends
  248 bytes on limb and secp256k1-field validation, 9,487 on residue binding,
  and 100 on routing. The 62-item `N-1` witness serializes to 195 bytes. Unlike
  `carry::bound::bind_value`, it returns only the 46 residues in the composable
  basis and includes the secp256k1 field bound.
- **Composable stack and scheduling boundary:** gate input is `preserved |
  lhs[46] | rhs[46] | q_limbs[16] | r_limbs[16] | 46 reverse-coordinate
  (q_binding,r_binding,relation) groups`; output is `preserved | r[46]`, with
  coordinate zero on top. `preserved` counts both main and alt stack items.
  The measured gate assumes the two certificates and its hints are already
  adjacent in that layout. All-witness-at-entry routing, circuit reordering,
  certificate fan-out, and terminal predicates are excluded. The two-gate
  unit test proves certificate-state chaining by inserting later test inputs
  as script constants; it is not a complete witness scheduler.
- **Why the global proof is exact:** the shared limbs prevent coordinates from
  referring to unrelated CRT representatives. With `lhs,rhs,r < N < 2^256`
  and `q < 2^256`, both sides of `lhs*rhs = q*N + r` are below `2^512`.
  Congruence modulo the 513-bit basis product therefore implies ordinary
  integer equality, and `r < N` makes the returned remainder canonical.
- **Wraparound boundary of the conditional profile:** without its external
  quotient binding, `lhs = rhs = 0`, `q = floor(M/N)`, and `r = M mod N`
  satisfy all coordinate relations while returning a wrong nonzero remainder.
  Adding `p_i` to an unchecked operand coordinate and adjusting its carry is a
  second accepted shift. The standalone limb-to-residue bindings close both
  attacks locally. The composable profile also rejects the detached 257-bit
  quotient, but only when operand certificates have the documented global
  shared-integer provenance; the counterexamples remain valid against the
  smaller conditional API and raw inputs passed across the composable API.
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
- **Native-field comparison:** the separate ordinary-domain balanced-radix
  secp256k1 gate is 20,524 bytes with a 94-byte incremental hint and a
  757-item peak. Its
  boundary is closest to the 31,281-byte composable RNS gate because both
  consume certified operands and return a reusable certificate. It is not a
  replacement when surrounding state is already represented as RNS residues;
  conversion and certificate fan-out are excluded from both measurements. A
  20,501-byte factor-16 native profile reduces the hint to 29 items and peaks
  at 719, but requires the distinct stored encoding `E(x)=x/16`; its conversion
  boundary is likewise excluded.
- **Deployment:** `unclassified`. These are generated fragments rather than
  complete leaves. Terminal predicates, tapleaf and control-block
  serialization, transaction weight, Bitcoin Core consensus comparison, and
  relay-policy acceptance remain unmeasured. The 32,772, 20,799, and 6,168
  figures are static opcode counts, not executed-opcode or validation-budget
  measurements.
- **Research need:** implement and measure an all-witness-at-entry scheduler
  for multi-gate programs, including certificate duplication/reordering; then
  measure complete leaf and transaction costs and differentially validate a
  fixed transaction against a pinned Bitcoin Core revision.

See the [standalone-bound source](../../src/arithmetic/rns/prime/carry/bound.rs),
[composable source](../../src/arithmetic/rns/prime/carry/composable.rs),
[conditional carry source](../../src/arithmetic/rns/prime/carry.rs),
[no-carry baseline source](../../src/arithmetic/rns/prime.rs),
[implementation README](../../src/arithmetic/rns/README.md),
[lookup comparison](../comparisons/lookup-strategies.md), and catalog record
`arithmetic/prime-rns`.
