# Multi-limb big integers

Represents fixed-width unsigned values as configurable little-endian limbs and
provides stack, bit, comparison, addition, subtraction, multiplication, and
inversion helpers.

- **Position:** general local backend for values wider than ScriptNum, including
  BN254 base and scalar fields.
- **Evidence:** locally reproduced with deterministic arkworks/native checks.
- **Representative configuration:** U254 uses nine 29-bit limbs; ordinary add
  is 176 bytes, carry-free checked add is 142 bytes, ordinary subtraction is
  190 bytes, borrow-free subtraction is 107 bytes, and full multiplication is
  111,466 bytes.
- **Tradeoff:** generality and compact stack representation produce very large
  multiplication scripts.
- **Trust boundary:** range and canonical limb constraints must be enforced at
  protocol boundaries. Carry-free add additionally requires every
  corresponding limb sum to remain below its radix.

## Carry-free addition

The research question is whether a wide addition gate can avoid carry
propagation when a caller already has a per-limb bound. `U254::add_nocarry(1, 0)`
answers yes: it zips two nine-limb values, checks each sum against its limb
radix, parks each result on the altstack, and restores the exact sum in the
original layout. The 142-byte fragment is 34 bytes smaller than the 176-byte
general `U254::add(1, 0)` under the same compilation policy.

The measured boundary is `fragment-only`: input pushes, output comparison,
terminal predicates, and transaction context are excluded from script bytes.
The companion strict tapscript run supplies two zero-valued U254 vectors as
18 data items, for 19 serialized witness bytes, zero auxiliary hint items, a
19-item combined main-plus-alt-stack peak, and 97 executed fragment
instructions. The local result is `locally-reproduced` and `unclassified` for
consensus or relay deployment; it uses the pinned `bitcoin-scriptexec`
interpreter with the combined stack limit enabled.

The threat model includes carry-boundary, negative-limb, and oversized-limb
inputs. The gate rejects a carry boundary. Negative or oversized limbs remain
the caller's responsibility, so a hostile-witness composition must run
`check_validity()` on both operands first. The optimized representation is not
composable with arbitrary canonical values unless this no-carry precondition is
proved by the surrounding circuit.

## Borrow-free subtraction

The research question is whether a wide subtraction gate can avoid borrow
propagation when a caller already has a per-limb ordering proof.
`U254::sub_noborrow(1, 0)` answers yes: it zips two nine-limb values, checks
that each difference is non-negative, parks each exact result on the altstack,
and restores the original layout. Its 107-byte fragment is 83 bytes smaller
than the 190-byte general `U254::sub(1, 0)` under the same compilation policy.

The measured boundary is `fragment-only`: input pushes, output comparison,
terminal predicates, and transaction context are excluded from script bytes.
The companion strict tapscript run supplies two zero-valued U254 vectors as 18
data items, for 19 serialized witness bytes, zero auxiliary hint items, a
19-item combined main-plus-alt-stack peak, and 97 executed fragment
instructions. The local result is `locally-reproduced` and `unclassified` for
consensus or relay deployment; it uses the pinned `bitcoin-scriptexec`
interpreter with the combined stack limit enabled.

The threat model includes per-limb underflow, negative limbs, and oversized
limbs. The gate rejects a negative difference, but it does not independently
prove canonical non-negative input limbs; hostile-witness callers must compose
`check_validity()` on both operands first. The operation is not a replacement
for ordinary subtraction when a borrow may cross a limb boundary.

See the [implementation README](../../src/arithmetic/bigint/README.md) and
catalog record `arithmetic/bigint`.
