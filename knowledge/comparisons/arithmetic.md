# Arithmetic representations

The table is a navigation aid, not a single benchmark: semantics and boundaries
differ. Follow each catalog configuration before comparing numbers.

| Need | Local construction | Representative script bytes | Main constraint |
| --- | --- | ---: | --- |
| Small constant product | ScriptNum × 13 | 10 | Four-byte ScriptNum domain |
| Small-field add | M31 u31 add | 18 | Canonical field input |
| Small-field variable multiply | M31 u31 multiply | 1,370 | Witness quotient relation |
| 32 checked nibbles to 128 bits | u4 staggered batch table | 924 | 189-item peak; tapscript-oriented |
| Wide add | U254 add | 176 | Nine limbs |
| Wide multiply | U254 multiply | 111,466 | Above optimizer cutoff; unoptimized |
| Ed25519 ordinary-domain multiply | 51 biased centered radix-32 digits, 13 signed tables | <!-- metric:ed25519_field_mul -->9893<!-- /metric:ed25519_field_mul --> | 245-byte/51-item incremental hint; certified operands; 523-item strict peak |
| Ed25519 factor-8 multiply | `E(x)=x/8`, folded normalized Karatsuba | 19,903 | 31-byte/29-item incremental hint; certified encoded operands; 719-item strict peak |
| Native secp256k1 ordinary-domain multiply | 29 balanced radix-512 digits, normalized Karatsuba | 20,500 | 94-byte/67-item incremental hint; certified operands; 757-item strict peak |
| Native secp256k1 factor-16 multiply | `E(x)=x/16`, folded normalized Karatsuba | 20,447 | 37-byte/29-item incremental hint; certified encoded operands; 719-item strict peak |
| Native secp256k1 base-field square | 29 balanced radix-512 digits, symmetry-specialized | 14,541 | 94-byte/67-item incremental hint; certified operand; 614-item strict peak |
| Three native secp256k1 ordinary multiplies | Shared table, destructive third-gate recombination | 59,163 | 280-byte/201-item incremental hint; 993-item strict peak; unoptimized above cutoff |
| Bounded RNS add | Legacy RNS add | 216 | Modulo 69,300 |
| Bounded RNS multiply | Legacy RNS multiply | 1,561 | 903-item peak |
| Exact 256-bit-product RNS add | 75-prime canonical coordinatewise | 1,131 | 513-bit composite range; 151-item peak |
| Exact 256-by-256-bit RNS multiply baseline | 75-prime table/Horner hybrid | 15,624 | No relation carries; 183-item peak |
| Six independent 256-by-256-bit RNS products | Coordinate-major table batch | 64,912 | Includes 450-byte output restoration; 900-item peak |
| Hinted secp256k1 modular multiply, conditional | 42-prime exact-carry verifier | 10,937 | 301 hint bytes; 231-item strict peak; external bindings excluded |
| Hinted secp256k1 modular multiply, standalone-bound | 47-prime limb-bound exact-carry verifier | 51,055 | 868-byte complete data witness; 305-item strict peak; global bindings included; unoptimized above cutoff |
| Hinted secp256k1 modular multiply, composable | 46-prime reusable-certificate verifier | 31,257 | 471 incremental hint bytes; 267-item peak; two adjacent certified operands required |

Selection order: choose semantics and range, then representation compatibility,
then consensus feasibility, and only then minimize bytes. The prime-log profile
keeps canonical operands and covers one unsigned 256-by-256-bit product exactly,
but longer expressions remain modular unless their bound is proved below its
513-bit composite modulus. Range checks and conversion remain outside a row
unless its boundary says otherwise; terminal predicates remain excluded from
both modular-product rows.

The 9,893-byte Ed25519 row is the current locking-script-size winner for this
field. It keeps host values in the ordinary field domain but uses a unique
51-digit centered stack encoding. Thirteen operand-derived 32-entry tables bind
663 schoolbook products; `32^51=p+19`, one scalar quotient, and 50 carries bind
the complete reduction. Its `fragment-with-memory` boundary includes 2,227
bytes of table setup/routing, 7,299 bytes of folded product/relation, and 367
bytes of cleanup and canonical output restoration. The 11,180-byte raw wrapper
adds certification for both hostile operand vectors and consumes a
representative 398-byte/153-item complete data witness.

The retained Ed25519 factor-8 row uses the same sound normalized-Karatsuba
product boundary as the native secp256k1 factor-16 row. Its modulus identity
`8*512^28=p+19` materially simplifies reduction, but the 646 bound digit
products still dominate total bytes. It remains attractive when its 31-byte
incremental hint or factor-8 circuit domain matters; it is not the current
size winner. Neither sound row substantiates the proposed 2–3 KB estimate;
NR-030 records the missing shifted-product binding in that estimate and the
cost of the repaired lookup-table designs.

Both Ed25519 rows are `locally-reproduced` and `unclassified`. The radix-32
benchmark used `bitcoin-scriptexec` in tapscript context with the 1,000-item
combined stack limit enabled; its generated-Script boundary and adversarial
test suites remain ignored by default. Neither row has Bitcoin Core
differential validation or a complete transaction measurement.

The native 20,500-byte ordinary row checks the same field operation as the 31,257-byte
composable RNS row at a broadly comparable certificate boundary: both consume
two verified-path secp256k1 values, bind hostile reduction hints locally, and
return a reusable certified result. They do not share a stack representation,
so conversion, certificate fan-out, and circuit scheduling remain outside both
numbers. The ordinary native gate's 1,793 bytes of table lifecycle can be
shared: two preloaded products cost an unoptimized 39,400 bytes at an 882-item peak, while
three use a slightly larger destructive relation and cost an unoptimized 59,163 bytes at a
993-item peak.

The 20,447-byte factor-16 row is an exact field multiplication only under its
documented encoding invariant: stored `a=E(x)` and `b=E(y)` produce `E(xy)`.
It has no measured resident-table or batch API, and mixing it with the ordinary
multiply or specialized square requires an explicit conversion strategy whose
Script cost is outside the row.

The native square row is a separate operation, not a multiplication estimate.
It exploits equal operands and uses 435 rather than 646 quarter-square
products. Five unoptimized shared-table squares cost 65,074 bytes and peak at 998 items.
The BN254 `Fq` backend concerns a different modulus and nine-limb
representation; its hinted-operation size is implementation context, not a
ratio for secp256k1 base-field work.

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
and checks the product over a 513-bit basis. It needs no complement. Its unoptimized 51,055
bytes split into 1,057 bytes of range checks, 38,796 of residue binding,
10,794 of modular relations, and 400 of routing and output. The 868-byte
witness covers all 299 consumed data items for `(N-1)^2`, not merely the
derived carries. The fragment returns both the 16 remainder limbs and 47
residues. A reusable one-value binding costs 9,773 bytes when a larger program
can certify persistent values at their introduction boundary, but that plain
binder proves only `<2^256`. The `bind_value_below(N)` variant needed for an
otherwise-unchecked field value costs 9,860 bytes. Shared joint-NAF doubling
chains are the main binding reduction; target-aware centering enables the two
widest basis primes while retaining checked ScriptNum prefix bounds.

The 46-prime composable row moves only the operand part of that proof to a
reusable certificate boundary. Its gate spends 443 bytes on q/r limb and field
validation, 9,851 binding q, 9,663 binding r, 10,799 on product relations, and
522 on routing/output. The 170-item, 471-byte `(N-1)^2` witness is incremental:
it excludes the two already-live 46-residue certificates. The matching
field-value binder is 9,832 bytes with a 195-byte, 62-item `N-1` witness and a
72-item peak; the gate contains 20,778 static non-push opcodes and peaks at 267.
Both fragments have zero table push/drop bytes.

The 10,937, 31,257, and 51,055 sizes are not direct optimization comparisons.
The first excludes every global proof; the second requires two certified
operands already adjacent to its hints and excludes certificate fan-out and
all-witness-at-entry routing; the third closes all four value bindings inside
one operation and additionally returns remainder limbs. The 75-prime
15,624-byte no-carry path remains the baseline when relation carries are
unavailable.

The one-shot ordinary product contains 392 bytes of table pushes, 153 bytes of
table cleanup, and 15,081 bytes of computation/routing/output code. The
coordinate-major six-product fragment re-optimizes the table choice for the
batch: 25,510 bytes push tables once per selected coordinate, 6,521 bytes drop
them, 30,229 bytes execute the arithmetic queries, 2,202 bytes route operands
and results, and 450 bytes restore all outputs. It averages 10,819 bytes per
product, but assumes coordinate-major inputs; vector transposition is excluded.
All carry verifiers are table-free. Their bytes are arithmetic, validation,
binding, and routing rather than reusable lookup setup. The composable profile
amortizes certificate work, not static tables; its multi-gate witness scheduling
and certificate duplication/reordering costs remain outside the measured gate.
