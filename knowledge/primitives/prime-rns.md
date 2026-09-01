# Prime logarithmic residue-number arithmetic

Represents integers with 75 canonical prime residues and streams affine
signed-logarithm tables one coordinate at a time. The selected modulus is just
large enough to represent every unsigned 256-by-256-bit product without wrap.

- **Position:** exact wide multiplication with much less script and stack than
  the local limb-based U254 multiplier, while retaining coordinatewise add and
  subtract.
- **Evidence:** `locally-reproduced` deterministic capacity checks, exhaustive
  per-prime algebra checks, maximum/random 256-bit products, malformed-range
  tests, preserved-state tests, and an exact 1,000-item stack-boundary test.
  Measurements use `bitcoin-scriptexec` in tapscript context.
- **Basis:** `2` and every odd prime through `383` except `47`; 75 residues,
  `log2(M) = 512.063700...`, and `M > (2^256 - 1)^2`.
- **Measured fragments:** canonical add/sub are 1,134/1,140 bytes at a
  151-item peak. Streamed multiply is 37,471 bytes at a 462-item peak. Two
  maximum-valued 256-bit operands serialize to 332 witness bytes; an arbitrary
  pair of canonical residue vectors can use up to 391 bytes. Both exclude the
  tapscript and control block.
- **Hinted reduction:** for the secp256k1 field modulus, `mul_mod_hinted`
  verifies quotient, remainder, and remainder-complement vectors in 69,199
  script bytes with 477 boundary-case hint-witness bytes and a 612-item peak.
  It returns the canonical remainder without CRT reconstruction.
- **Lookup design:** tiny coordinates use specialized or full canonical
  tables. Larger coordinates use affine signed-projective magnitude logs and
  half exponent tables. Canonical exponent entries win through prime 151;
  centered exponent literals win from 157 onward and are normalized back to
  canonical output.
- **Centered tradeoff:** public centered add/sub is 1,862/1,936 bytes with the
  same 151-item peak. Signed-projective magnitude logs give canonical inputs
  the same asymptotic multiplication-table footprint, so a centered public
  representation no longer buys the expected stack reduction for this design.
- **Trust boundary:** coordinates must be range-checked before table lookup.
  Arithmetic is modulo composite `M`; exact-integer claims additionally need a
  static bound below `M`, and coordinate canonicality alone does not prove that
  an input's CRT representative is below `2^256`. Ordering, sign, ordinary
  integer quotient, and CRT conversion are not coordinatewise.
- **Hint soundness:** hinted reduction additionally assumes all five RNS
  vectors are bound to unsigned integers below `2^256` and both operands are
  below the target modulus. The fragment verifies coordinate canonicality for
  the three hint vectors and checks `r + complement = N - 1`, but it does not
  implement the global 256-bit binding. Without that precondition, wrapped RNS
  hints are not sound.
- **Larger-prime result:** under dense log/exp tables, range grows as
  `log2(p)` while table memory grows as `p`. An inspected search found that a
  minimum-coordinate large-prime basis uses more than three times as many
  table items, so it is dominated for one-shot locking-script bytes.
- **Deployment:** `unclassified`. Strict local stack tests pass, but Bitcoin
  Core consensus and relay-policy validation have not been run. The fragment
  exceeds legacy/P2WSH script-size and opcode-count limits and is only evaluated
  in tapscript context.
- **Research need:** measure complete-tapleaf transaction weight and validation
  behavior against Bitcoin Core, and find the batch/reuse frontier when a
  prime's table can serve several products before cleanup.

See the [source](../../src/arithmetic/rns/prime.rs),
[implementation README](../../src/arithmetic/rns/README.md),
[lookup comparison](../comparisons/lookup-strategies.md), and catalog record
`arithmetic/prime-rns`.
