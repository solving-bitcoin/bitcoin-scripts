# Arithmetic representations

The table is a navigation aid, not a single benchmark: semantics and boundaries
differ. Follow each catalog configuration before comparing numbers.

| Need | Local construction | Representative script bytes | Main constraint |
| --- | --- | ---: | --- |
| Small constant product | ScriptNum × 13 | 10 | Four-byte ScriptNum domain |
| Small-field add | M31 u31 add | 18 | Canonical field input |
| Small-field variable multiply | M31 u31 multiply | 1,400 | Witness quotient relation |
| Wide add | U254 add | 190 | Nine limbs |
| Wide multiply | U254 multiply | 111,466 | Very large script |
| Bounded RNS add | Legacy RNS add | 219 | Modulo 69,300 |
| Bounded RNS multiply | Legacy RNS multiply | 1,564 | 903-item peak |
| Exact 256-bit-product RNS add | 75-prime canonical coordinatewise | 1,134 | 513-bit composite range; 151-item peak |
| Exact 256-by-256-bit RNS multiply baseline | 75-prime table/Horner hybrid | 15,628 | No relation carries; 183-item peak |
| Six independent 256-by-256-bit RNS products | Coordinate-major table batch | 64,912 | Includes 450-byte output restoration; 900-item peak |
| Hinted secp256k1 modular multiply, conditional | 42-prime exact-carry verifier | 10,952 | 301 hint bytes; 231-item strict peak; external bindings excluded |
| Hinted secp256k1 modular multiply, standalone-bound | 47-prime limb-bound exact-carry verifier | 51,055 | 868-byte complete data witness; 305-item strict peak; global bindings included |
| Hinted secp256k1 modular multiply, composable | 46-prime reusable-certificate verifier | 31,281 | 471 incremental hint bytes; 267-item peak; two adjacent certified operands required |

Selection order: choose semantics and range, then representation compatibility,
then consensus feasibility, and only then minimize bytes. The prime-log profile
keeps canonical operands and covers one unsigned 256-by-256-bit product exactly,
but longer expressions remain modular unless their bound is proved below its
513-bit composite modulus. Range checks and conversion remain outside a row
unless its boundary says otherwise; terminal predicates remain excluded from
both modular-product rows.

All three exact-carry modular rows are `locally-reproduced` and `unclassified`. The
compact profile's 42-prime product basis is 513 bits. Each packed coordinate
group verifies one exact signed carry equation; only 18 groups include a
remainder-complement residue, whose subbasis product exceeds `2^257`. The
144-item, 301-byte hint is 42 quotient residues, 42 remainder residues, 42
carries, and 18 complement residues.

That compact row is not a complete binding boundary. Every supplied operand
and hint coordinate must be externally tied to the canonical RNS encoding of
its corresponding unsigned integer below `2^256`, and the operands must be
below the target modulus. Local carry equations alone permit wrapped global
relations and shifted operand representatives.

The 47-prime row includes that missing work. Its 299 witness items are 64
centered base-`2^16` limbs, 188 residue-binding carries, and 47 relation
carries. The script range-checks all limbs, proves `lhs`, `rhs`, and remainder
below the target, derives four canonical RNS vectors from the shared limbs,
and checks the product over a 513-bit basis. It needs no complement. Its 51,055
bytes split into 1,060 bytes of range checks, 38,801 of residue binding,
10,794 of modular relations, and 400 of routing and output. The 868-byte
witness covers all 299 consumed data items for `(N-1)^2`, not merely the
derived carries. The fragment returns both the 16 remainder limbs and 47
residues. A reusable one-value binding costs 9,777 bytes when a larger program
can certify persistent values at their introduction boundary, but that plain
binder proves only `<2^256`. The `bind_value_below(N)` variant needed for an
otherwise-unchecked field value costs 9,864 bytes. Shared joint-NAF doubling
chains are the main binding reduction; target-aware centering enables the two
widest basis primes while retaining checked ScriptNum prefix bounds.

The 46-prime composable row moves only the operand part of that proof to a
reusable certificate boundary. Its gate spends 444 bytes on q/r limb and field
validation, 9,852 binding q, 9,664 binding r, 10,799 on product relations, and
522 on routing/output. The 170-item, 471-byte `(N-1)^2` witness is incremental:
it excludes the two already-live 46-residue certificates. The matching
field-value binder is 9,835 bytes with a 195-byte, 62-item `N-1` witness and a
72-item peak; the gate contains 20,799 static non-push opcodes and peaks at 267.
Both fragments have zero table push/drop bytes.

The 10,952, 31,281, and 51,055 sizes are not direct optimization comparisons.
The first excludes every global proof; the second requires two certified
operands already adjacent to its hints and excludes certificate fan-out and
all-witness-at-entry routing; the third closes all four value bindings inside
one operation and additionally returns remainder limbs. The 75-prime
15,628-byte no-carry path remains the baseline when relation carries are
unavailable.

The one-shot ordinary product contains 392 bytes of table pushes, 153 bytes of
table cleanup, and 15,083 bytes of computation/routing/output code. The
coordinate-major six-product fragment re-optimizes the table choice for the
batch: 25,510 bytes push tables once per selected coordinate, 6,521 bytes drop
them, 30,229 bytes execute the arithmetic queries, 2,202 bytes route operands
and results, and 450 bytes restore all outputs. It averages 10,819 bytes per
product, but assumes coordinate-major inputs; vector transposition is excluded.
All carry verifiers are table-free. Their bytes are arithmetic, validation,
binding, and routing rather than reusable lookup setup. The composable profile
amortizes certificate work, not static tables; its multi-gate witness scheduling
and certificate duplication/reordering costs remain outside the measured gate.
