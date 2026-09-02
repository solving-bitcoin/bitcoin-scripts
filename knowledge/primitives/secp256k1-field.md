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
nearest the top of the stack. Ordinary multiplication splits each operand into
a 14-digit low block and 15-digit high block. It computes low and high products
directly, carry-normalizes the two signed block differences to 15 balanced
digits, and uses

`A*B = z0 + 512^14 * (z0 + z2 + zd) + 512^28 * z2`,

where `zd = (A0-A1)(B1-B0)`. All signed digit products use one biased
513-entry quarter-square table. The current split needs 196 low, 225 high, and
225 difference products: 646 queries total.

Normalization preserves evaluation at 512 but changes the formal coefficient
polynomial by multiples of `X-512`. Host carry hints are therefore generated
from the same normalized coefficient basis the script verifies. Eleven
mixed-width quotient coefficients and 56 radix-512 carries prove the exact
integer reduction. Script derives the remainder digits, bounds them, proves
the resulting integer below `p`, and returns a reusable certified value.

The alternative `factor16` profile stores a logical value as
`E(x)=x/16 mod p`. Since `p=16*512^28-32*512^3-977`, the verifier folds the
exact polynomial for `16*a*b` to degree 28. One signed residual and 28 exact
carries prove the folded relation and Script derives `E(x*y)`. This profile is
closed under multiplication and ordinary field addition only while every
consumer respects the encoding. Its host `encode`/`decode` helpers are not
measured in-Script converters, and the ordinary square/multiply/batch APIs do
not preserve the factor-16 domain.

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
| One ordinary multiplication | 20,500 | 94 bytes / 67 items | 757 |
| Raw ordinary two-operand multiplication | 21,772 | 160 bytes / 125 complete items | 757 |
| One factor-16 multiplication | 20,447 | 37 bytes / 29 items | 719 |
| Raw factor-16 two-operand multiplication | 21,719 | 103 bytes / 87 complete items | 719 |
| Two preloaded ordinary multiplications | 39,400 (unoptimized) | 187 bytes / 134 items | 882 |
| Three preloaded ordinary multiplications | 59,163 (unoptimized) | 280 bytes / 201 items | 993 |
| One square | 14,539 | 94 bytes / 67 items | 614 |
| Five preloaded squares | 65,074 (unoptimized) | 468 bytes / 335 hint items | 998 |

One ordinary multiplication contains 1,536 bytes of table pushes and 257 bytes
of table cleanup. The other 18,707 bytes are product, normalization,
recombination, exact-relation, routing, and output-validation work. Its exact
breakdown is 9,374 low/high product bytes, 4,993 normalized-difference product
bytes, 1,102 normalization bytes, 173 coefficient-routing bytes, 530
recombination bytes, and 2,535 relation/output bytes. The 1,793-byte table
lifecycle is 8.7% of an isolated gate.

The factor-16 gate uses the same 1,793-byte table lifecycle and 18,654 bytes of
computation. Its exact categories are 15,597 product-generation bytes, 2,642
folded-relation bytes, and 415 cleanup/output-certification bytes. It is only
53 locking-script bytes smaller than the ordinary gate, but removes 38 hints
and 38 peak stack items. The representative 37-byte factor-16 hint and 103-byte
raw witness use encoded logical `(p-1)` operands; witness sizes are not maxima.

Preloaded batches pay that table lifecycle once. The retained two-product path
uses the smaller 85-coefficient layout and averages 19,700 bytes. Three
products switch to a 57-slot destructive recombination: it is larger per gate
but averages 19,721 bytes and reaches a 993-item peak, where three copies of
the 85-slot path would exceed the consensus stack ceiling. Circuit-specific
operand scheduling, fan-out, and reordering remain outside these batch
fragments. No factor-16 resident-table or batch fragment is currently measured.

One square also pays 1,793 table bytes; its remaining 12,746 bytes are
computation. The five-square batch uses an unbiased shared table: 1,657 bytes
of setup plus 257 of cleanup, and 63,160 bytes of computation. It averages
13,014.8 bytes, but its 998-item peak leaves almost no composition headroom.

## Trust boundary

Witness inputs are hostile. A multiplication gate accepts only two values that
previously passed `certify_value` or an equivalent exact binding on the same
verified path. The ordinary gate's 67 incremental hints are q plus carries;
the factor-16 gate's 29 are one residual plus carries. Remainder r is derived,
not supplied, and the raw wrappers certify both operands in place. Ordinary
quotient coefficients need not be canonical because the verifier only relies
on their exact represented integer; arithmetic overflow makes oversized
hostile coefficients fail closed. A certified canonical integer alone does
not state whether the surrounding protocol interprets it ordinarily or as
`E(x)`, so that representation invariant is a circuit-level obligation.

Batch group zero is nearest the stack top and is processed first. Outputs keep
that order and each is certified before return. The `preserved_items` argument
counts unrelated main and altstack state. Tests execute successfully with
preserved state split across both stacks at exactly 1,000 combined items and
reject one additional item.

## Comparison boundary

The closest RNS comparison is the 31,257-byte 46-prime composable gate: it also
consumes two certified secp256k1 values, binds reduction hints locally, and
returns a reusable certificate. The 20,500-byte ordinary native gate is 10,757
bytes smaller and its representative incremental witness is 377 bytes smaller,
but values have different live representations; conversion and certificate
fan-out are not included in either fragment. The 20,447-byte factor-16 gate is
an additional 53 bytes smaller and uses only 29 hints, but is comparable only
when the caller already keeps the native values factor-16 encoded.

The 10,937-byte 42-prime carry verifier is not globally sound from raw RNS
vectors and excludes every integer binding, so it is not a smaller substitute.
The unoptimized 51,055-byte standalone RNS verifier binds four limb values to 47 residue
vectors and returns both limbs and residues; it closes a materially wider
boundary than the native raw wrapper.

BN254 `Fq` multiplication concerns a different modulus, nine-limb backend, and
certificate convention. Its size is useful implementation context, not a
secp256k1 speed ratio. BN254 hinted-operation coverage remains incomplete in
OP-006.

## Search frontier

The latest clean-sheet search tested radix-256 schoolbook/Karatsuba, recursively
normalized difference products, centered radix-256 monic folding, Toom splits,
both asymmetric radix-512 orientations, and factor-16 folds. One-layer
radix-256 measured 24,995 bytes; the centered recursive fold measured 24,211.
A second Karatsuba layer on the 15-digit difference branch added 67 bytes after
recombination, despite fewer leaf products. A one-pass factor-16 fold was
invalid because an honest boundary residual reached 68,719,492,368, beyond
four-byte ScriptNum. The retained second fold recodes the tail before its
degree-28 exact relation and measures 20,450 bytes. These are executable search
results for the inspected schedules, not a global lower bound.

See the [implementation overview](../../src/fields/secp256k1/README.md),
[ordinary source](../../src/fields/secp256k1/bigint9/mod.rs),
[factor-16 source](../../src/fields/secp256k1/bigint9/factor16/mod.rs),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/secp256k1-field`.
