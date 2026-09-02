# Native secp256k1 base-field arithmetic

The native backend verifies multiplication and squaring modulo
`p = 2^256 - 2^32 - 977` with balanced radix-512 digits, quarter-square
lookups, and an exact integer carry chain. It does not rely on CRT uniqueness
and therefore has no RNS-wraparound ambiguity.

- **Position:** compact, reusable-certificate secp256k1 base-field arithmetic
  for scripts that can keep 29-digit values live.
- **Evidence:** `locally-reproduced` with boundary, deterministic random,
  malformed-hint, exact ScriptNum-headroom, output-certification, batch-order,
  and strict 1,000-item stack tests.
- **Deployment:** `unclassified`; local tapscript execution is strict for the
  stack limit, but Bitcoin Core consensus and relay policy have not been
  reproduced.

## Construction

A value uses 29 little-endian balanced radix-512 digits, with digit zero
nearest the top of the stack. Multiplication splits each operand into 15- and
14-digit blocks. It computes low and high products directly, carry-normalizes
the two signed block differences to 16 balanced digits, and uses

`A*B = z0 + 512^15 * (z0 + z2 + zd) + 512^30 * z2`,

where `zd = (A0-A1)(B1-B0)`. All 677 signed digit products use one biased
513-entry quarter-square table.

Normalization preserves evaluation at 512 but changes the formal coefficient
polynomial by multiples of `X-512`. Host carry hints are therefore generated
from the same normalized coefficient basis the script verifies. Eleven
mixed-width quotient coefficients and 56 radix-512 carries prove the exact
integer reduction. Script derives the remainder digits, bounds them, proves
the resulting integer below `p`, and returns a reusable certified value.

The square path exploits operand equality, reducing the product core to 435
quarter-square queries. Its relation, remainder derivation, and certification
boundary are otherwise the same.

## Measured configurations

All sizes are operation fragments. They exclude input pushes, terminal
predicate/output comparison, tapleaf/control-block serialization, and
transaction context. Multiplication/square gates require verified-path
certified operands; raw wrappers charge certification explicitly. Witness
bytes are representative consensus serialization for `(p-1)^2`, not maxima.

| Configuration | Script bytes | Incremental hint witness | Strict peak |
| --- | ---: | ---: | ---: |
| One multiplication | 21,291 | 94 bytes / 67 items | 761 |
| Raw two-operand multiplication | 22,567 | 160 bytes / 125 complete items | 761 |
| Two preloaded multiplications | 40,924 | 187 bytes / 134 items | 886 |
| Three preloaded multiplications | 61,536 | 280 bytes / 201 items | 996 |
| One square | 14,543 | 94 bytes / 67 items | 614 |
| Five preloaded squares | 65,074 | 468 bytes / 335 hint items | 998 |

One multiplication contains 1,538 bytes of table pushes and 257 bytes of
table cleanup. The other 19,496 bytes are product, normalization,
recombination, exact-relation, routing, and output-validation work. Its exact
breakdown is 9,374 low/high product bytes, 5,694 normalized-difference product
bytes, 1,165 normalization bytes, 179 coefficient-routing bytes, 540
recombination bytes, and 2,544 relation/output bytes. The 1,795-byte table
lifecycle is 8.4% of an isolated gate.

Preloaded batches pay that table lifecycle once. The retained two-product path
uses the smaller 87-coefficient layout and averages 20,462 bytes. Three
products switch to a 57-slot destructive recombination: it is larger per gate
but averages 20,512 bytes and reaches a 996-item peak, where three copies of
the 87-slot path would exceed the consensus stack ceiling. Circuit-specific
operand scheduling, fan-out, and reordering remain outside these batch
fragments.

One square also pays 1,795 table bytes; its remaining 12,748 bytes are
computation. The five-square batch uses an unbiased shared table: 1,657 bytes
of setup plus 257 of cleanup, and 63,160 bytes of computation. It averages
13,014.8 bytes, but its 998-item peak leaves almost no composition headroom.

## Trust boundary

Witness inputs are hostile. A multiplication gate accepts only two values
that previously passed `certify_value` or an equivalent exact binding on the
same verified path. Its 67 incremental hints are q plus carries; remainder r
is derived, not supplied. The raw wrapper certifies both operands in place.
Quotient coefficients need not be canonical because the verifier only relies
on their exact represented integer; arithmetic overflow makes oversized
hostile coefficients fail closed.

Batch group zero is nearest the stack top and is processed first. Outputs keep
that order and each is certified before return. The `preserved_items` argument
counts unrelated main and altstack state. Tests execute successfully with
preserved state split across both stacks at exactly 1,000 combined items and
reject one additional item.

## Comparison boundary

The closest RNS comparison is the 31,281-byte 46-prime composable gate: it also
consumes two certified secp256k1 values, binds reduction hints locally, and
returns a reusable certificate. The native gate is 9,990 bytes smaller and its
representative incremental witness is 377 bytes smaller, but values have
different live representations; conversion and certificate fan-out are not
included in either fragment.

The 10,952-byte 42-prime carry verifier is not globally sound from raw RNS
vectors and excludes every integer binding, so it is not a smaller substitute.
The 51,055-byte standalone RNS verifier binds four limb values to 47 residue
vectors and returns both limbs and residues; it closes a materially wider
boundary than the native raw wrapper.

BN254 `Fq` multiplication concerns a different modulus, nine-limb backend, and
certificate convention. Its size is useful implementation context, not a
secp256k1 speed ratio. BN254 hinted-operation coverage remains incomplete in
OP-006.

## Search frontier

Inspected clean-sheet alternatives included radix-256 schoolbook and recursive
Karatsuba, mixed-width quotient layouts, balanced 33-digit radix-256, and an
asymmetric centered layout. Their best complete scratch result was 23,870
bytes, above the retained 21,291-byte radix-512 gate. A 57-slot destructive
layout is 418 bytes larger for one gate but is retained selectively for the
three-product batch because its lower peak changes feasibility.

See the [implementation README](../../src/arithmetic/fields/README.md),
[source](../../src/arithmetic/fields/secp256k1.rs),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/secp256k1-field`.
