# Negative, dominated, and boundary results

These records prevent repeated dead ends. They are scoped observations, not
universal impossibility proofs.

## NR-001: Raw 1,024-byte SHAKE256 output exceeds the stack limit

The current byte-lane SHAKE256 leaves 1,024 output items, already exceeding the
1,000 combined main/altstack consensus limit. A strict construction must reduce
the requested output or consume it incrementally. Evidence: source-level output
shape and implementation README.

## NR-002: F257 log/exp memory cannot coexist with a 512-item state

The 385-item memory plus protocol state and operation temporaries reaches a
measured peak of 900 at the documented depth; the exact-square table uses a
separate 129 items. The implementation documentation concludes the two memories
cannot coexist with a 512-coefficient state and should be phased. Evidence:
checked metric snapshots and stack-limit tests.

## NR-003: Legacy RNS multiplication leaves little composition headroom

The measured legacy RNS multiply peaks at 903 items. It is locally correct, but
only 97 items remain for unrelated state under the consensus ceiling. The
exact-256-bit-product prime-log profile uses a different 513-bit modulus and 75
canonical residues. Its table/Horner hybrid peaks at 183 items, leaving 817
items for unrelated state, but it is not a drop-in replacement at fixed value
range or encoding.

## NR-004: Larger dense-log primes lose byte efficiency

For the streamed signed-log construction, a prime contributes `log2(p)` range
bits while its dense table occupies linear-in-`p` items. An inspected search
found that reducing the exact-product profile to roughly 54 primes in the
587–941 range requires more than three times the table items of the selected
75-prime basis. Larger primes reduce witness coordinates but are dominated for
one-shot locking-script bytes under this lookup model. This result does not
apply when exact relation carries eliminate the dense tables: the separate
carry-optimized verifier uses a 42-prime, 513-bit basis.

## NR-005: Monolithic pairing execution is not a deployment result

The full BN254 Miller-loop test is expensive, ignored by default, and uses a
relaxed executor. Passing it establishes algorithmic evidence, not consensus or
policy feasibility. Protocol chunking and authenticated boundaries are required.

## NR-006: SHA-1 is dominated for new collision-resistant protocols

SHA-1 remains useful for compatibility research, but practical collision
attacks invalidate the ideal collision claim. Its local script is also not
smaller than BLAKE3's measured 64-byte configuration. Semantics differ, so this
is not a universal byte comparison.

## NR-007: Large fragments do not become deployable through opcode compatibility

Many primitives use opcodes present in legacy and tapscript yet exceed script,
opcode, validation, stack, or relay-policy limits once composed. Compatibility
tables must never be interpreted as blanket standardness.

## NR-008: Coordinate carry checks do not provide global RNS binding

The 42-prime carry-optimized modular-product fragment checks exact signed
equations coordinate by coordinate, but those equations alone do not prove
that the supplied vectors encode the claimed unsigned integers below
`2^256`. With product-basis modulus `M`, the unbound witness
`lhs = rhs = 0`, `q = floor(M/N)`, and `r = M mod N` satisfies
`q*N + r = M` and therefore every RNS relation, yet `r` is not the modular
product; the excluded quotient is 257 bits. Separately, because operand
coordinates are not locally range-checked, replacing `lhs_i` by `lhs_i + p_i`
and adjusting the signed carry preserves coordinate acceptance.

These are trust-boundary counterexamples, not failures under the construction's
stated preconditions. Sound use must bind every operand and hint coordinate to
the canonical residues of one corresponding global unsigned value below
`2^256`; the 18-coordinate complement subbasis then supplies the independent
`r < N` argument. Evidence for the implemented verifier and metrics is
`locally-reproduced`; deployment remains `unclassified`.

The separate 36-prime `carry::bound` profile closes this particular boundary
inside its fragment. It range-checks four shared 16-limb values, derives every
canonical coordinate through exact binding carries, proves `lhs`, `rhs`, and
`r` below the target, and only then checks the product relation over a 521-bit
basis. It therefore rejects detached coordinate representatives and needs no
remainder complement. That standalone work costs 88,225 script bytes with a
722-byte, 244-item data witness and a strict 249-item peak. This does not erase
the counterexamples above: they still apply to the smaller 10,952-byte
coordinate-only API and any equivalent verifier that omits global binding.

## NR-009: Square tables and no-hint radix-4 lose to binary carry arithmetic

The prime-RNS optimization search evaluated two multiplication alternatives
that are not selected. A `locally-reproduced` half-square-table prototype used
the identity `4ab = (a+b)^2 - (a-b)^2` but compiled to 32,244 bytes with a
497-item peak before the final carry-basis improvements. It avoided relation
carries, yet remained much larger than the exact-carry verifier.

For the retained 75-prime no-carry representation, an exact generator-cost
comparison measured raw/centered/per-coordinate-best radix-4 variable cores at
24,513/22,019/21,354 bytes, versus 17,703/16,575/16,558 for binary Horner.
Radix-4 won zero coordinates, so adding it to generation cannot shrink the
selected script. These are construction-specific negative results, not claims
that square tables or wider radices are universally inferior.

## NR-010: Two no-carry modular proofs do not amortize their tables

After binary-Horner endpoint optimization, one 75-prime no-carry secp256k1
modular-product verifier is 25,777 bytes. It contains only 123 bytes of table
pushes and 60 bytes of cleanup. A global two-proof strategy search selected
shared tables for 25 coordinates and had an ideal zero-relayout lower bound of
50,657 bytes, 897 below two independent fragments.

The executable proof-major, coordinate-lockstep prototype instead measured
52,048 locking-script bytes, 955 serialized hint-witness bytes, and a strict
753-item peak. Offset-aware table queries and proof-to-coordinate routing added
1,391 bytes, making it 494 bytes larger than the independent 51,554-byte
locking scripts. Three proofs cannot enter this layout because their five
75-coordinate input vectors require 1,125 items before any transient. This is
a `locally-reproduced` negative result for the current layout, not a general
claim against batch verification.

## NR-011: Deterministic Horner bindings lose to centered exact-dot bindings

The global-binding search tested deterministic conversion before selecting the
retained centered base-`2^16` design. Direct power-radix/Horner conversion of
all four values produced roughly 623–647 kB of aggregate generated binding
script across the tested layouts. A tighter 34-prime mixed-radix construction
reduced the complete modular-product verifier to 238,885 bytes, but remained
well above the 88,225-byte, 36-prime exact-dot verifier.

The two discarded figures are measured scratch-prototype boundaries whose
generators are not retained as public deterministic fixtures, so they are
recorded here as `inspected` design-search evidence rather than cataloged
`locally-reproduced` configurations. The retained 88,225-byte profile is
`locally-reproduced` by source, tests, and checked metrics. This comparison
shows domination for the tested bases, representations, and stack layouts; it
does not establish global optimality of centered limbs or exact dot products.

## NR-012: Direct four-opcode hash paths have deterministic aliases

A naïve four-way path that maps digits to SHA256, HASH256, RIPEMD160, and
HASH160 is not binding as a digit sequence. Write SHA-256 as `S` and
RIPEMD-160 as `R`. HASH256 is exactly `SS`, while HASH160 is exactly `SR`.
Consequently, the two-digit path `[1, 2]` executes `SS` followed by `R`, and
the distinct path `[0, 3]` executes `S` followed by `SR`; both are the identical
function `SSR` for every preimage. No cryptanalytic collision is required.

The implemented four-way construction avoids this structural ambiguity by
assigning every digit a fixed two-hash codeword: `SS`, `SR`, `RS`, or `RR`.
For a fixed digit count, distinct digit strings then produce distinct
SHA-256/RIPEMD-160 schedules unless an underlying or cross-function collision
is found. This removes the exact alias but does not turn the non-standard
mixed-hash construction into a cryptographically reviewed scheme.
