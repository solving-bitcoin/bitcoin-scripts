# Ed25519 base-field multiplication

## Scope

The local construction implements exact hinted multiplication modulo
`p=2^255-19`, the base field used by Ed25519. This page scopes only that atomic
field gate, not a signature verifier. A separate
[experimental custom BLAKE3/Montgomery-slope verifier](ed25519-blake3-montgomery-slope.md)
now supplies point, scalar, hash, and terminal layers around other focused
field machinery; it is not RFC 8032 Ed25519 and does not change this gate's
standalone boundary.

## Construction

The current size-minimizing backend, `u5_balanced_table`, keeps host values in
the ordinary field domain and encodes each stack value as 51 biased centered
radix-32 digits. Stored `e_i` is in `[0,31]`; arithmetic uses
`d_i=e_i-16`. The centered interval is restricted by a 19-value top gap to
give exactly one encoding of every residue in `[0,p)`.

Script groups the left operand into thirteen limbs and constructs a signed
32-entry table for each limb. Every certified right digit selects one entry
from every table, so all `13*51=663` variable products are bound to the input.
The identity `32^51=p+19` folds the high product half. One hostile scalar
quotient and 50 hostile carries then certify the complete integer relation;
Script derives, range-checks, and canonicalizes the output digits.

The same backend also exposes a circuit-oriented claimed-product gate. Given
certified `lhs`, `rhs`, and `product` vectors, it starts at the quotient and
reconstructs all 50 carries in reverse, closing the low column with the
`+19*q` term. This removes every carry hint: the only auxiliary hint is the
quotient. It does not remove the claimed product from the witness, so a fresh
standalone invocation has 154 complete input items rather than one.

The retained `bigint9` backend instead uses 29 balanced radix-512 digits in the
factor-8 domain `E(x)=x/8 mod p`. Its normalized-Karatsuba product uses 646
quarter-square lookups and the fold `8*512^28=p+19`, followed by one residual
and 28 exact carries. It remains a useful lower-witness baseline and a distinct
representation choice, but it is no longer the locking-script-size winner.

The smaller modulus makes the reduction relation simpler than secp256k1, but
does not make variable multiplication native to Bitcoin Script. The original
2–3 KB 26/25-bit sketch omitted the quotient/carry work needed to bind shifted
partial products. The optimized backends retain the useful operand-specific
table idea while checking a complete exact polynomial identity; NR-030 records
the distinction.

## Evidence

`locally-reproduced`, `unclassified`. Deterministic local tests execute in a
tapscript context with the combined 1,000-item stack limit enabled. For the
radix-32 backend, the release benchmark executed the raw-certification wrapper
once and the compact gate 100 times, checking every returned digit. Active
fast tests cover encoding uniqueness, boundary and seeded host products,
analytic ScriptNum bounds, the exact 663-lookup schedule, and the stack guard.
The generated-Script boundary and adversarial suites remain deliberately
ignored by default. No Bitcoin Core differential validation or complete
transaction exists.

## Costs and boundary

The representative radix-32 measurements use a `fragment-with-memory`
boundary. Both rows include table lifecycle, multiplication, folding, exact
carry checks, cleanup, and canonical output validation. They exclude input
pushes, a terminal predicate or output comparison, transaction/tapleaf
serialization, and all EdDSA layers above field multiplication. The compact
row additionally excludes operand certification.

| Configuration | Script bytes | Witness boundary | Strict peak |
| --- | ---: | --- | ---: |
| Radix-32, two certified operands | 9,893 | 245 bytes / 51 incremental hints | 523 |
| Radix-32, certified claimed-product equality | 9,762 | one quotient hint plus 51 claimed-product digits / 154 complete input items | 525 |
| Radix-32, two raw operand vectors | 11,180 | 398 bytes / 153 complete data items | 523 |
| Retained bigint9 factor-8 gate | 19,903 | 31 bytes / 29 incremental hints | 719 |

The 9,893-byte policy-produced radix-32 gate splits into 2,227 bytes of table
setup/routing, 7,299 bytes of folded product and relation, and 367 bytes of
cleanup/output restoration. It contains 6,449 static non-push opcodes. Witness
sizes are representative for the deterministic benchmark fixture, not maxima.
The compact and raw rows use the same 523-item arithmetic peak; the compact
gate requires its two operands to have been certified earlier on the same
verified path.

The claimed-product row is 9,805 bytes before optimizer rewrites. Its quotient
has at most 22 magnitude bits. The row is useful when the product is already a
required circuit wire; if the product exists only to save carry hints, its 51
digits cost one more entry item than the compute-output gate's 50 carries plus
quotient.

## Dependencies and next work

- [Arithmetic comparison](../comparisons/arithmetic.md)
- [Lookup tables](../techniques/lookup-tables.md)
- [Witness hints](../techniques/witness-hints.md)
- [Negative result NR-030](../negative-results/index.md)
- [Open problem OP-018](../open-problems.md)
- [Custom BLAKE3/Montgomery-slope verifier](ed25519-blake3-montgomery-slope.md)
- [Field-family implementation README](../../src/fields/ed25519/README.md)
- [Retained bigint9 backend README](../../src/fields/ed25519/bigint9/README.md)
