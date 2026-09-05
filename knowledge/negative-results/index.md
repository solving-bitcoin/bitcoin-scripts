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

The separate 47-prime `carry::bound` profile closes this particular boundary
inside its fragment. It range-checks four shared 16-limb values, derives every
canonical coordinate through exact binding carries, proves `lhs`, `rhs`, and
`r` below the target, and only then checks the product relation over a 513-bit
basis. It therefore rejects detached coordinate representatives and needs no
remainder complement. That standalone work costs 51,047 script bytes with an
868-byte, 299-item data witness and a strict 305-item peak. This does not erase
the counterexamples above: they still apply to the smaller 10,950-byte
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
modular-product verifier is 25,768 bytes. It contains only 123 bytes of table
pushes and 60 bytes of cleanup. A global two-proof strategy search selected
shared tables for 25 coordinates and had an ideal zero-relayout lower bound of
50,657 bytes, 897 below two independent fragments.

The executable proof-major, coordinate-lockstep prototype instead measured
52,048 locking-script bytes, 955 serialized hint-witness bytes, and a strict
753-item peak. Offset-aware table queries and proof-to-coordinate routing added
1,391 bytes, making it 512 bytes larger than the independent 51,536-byte
locking scripts. Three proofs cannot enter this layout because their five
75-coordinate input vectors require 1,125 items before any transient. This is
a `locally-reproduced` negative result for the current layout, not a general
claim against batch verification.

## NR-011: Alternative global-binding layouts lose to centered exact-dot bindings

The global-binding search tested deterministic conversion before selecting the
retained centered base-`2^16` design. Direct power-radix/Horner conversion of
all four values produced roughly 623–647 kB of aggregate generated binding
script across the tested layouts. A tighter 34-prime mixed-radix construction
reduced the complete modular-product verifier to 238,885 bytes, but remained
well above both the former 88,225-byte exact-dot verifier and the current
51,047-byte, 47-prime verifier.

The later capped-basis search also rejected two closer alternatives. Its best
centered mixed-radix layout was estimated at 52,352 intrinsic bytes before
range validation and routing, or more than approximately 53.5 kB as a complete
standalone fragment. An unsigned base-`2^15` hybrid was 53,517 intrinsic bytes
before range validation and routing. Both already exceed the retained 51,047-
byte standalone verifier before their missing boundary work is added.

For the composable profile, a direct fused-`qN` construction derived each
`q*N mod p_i` term from the quotient limbs inside the product relation, using
grouped equal/opposite coefficients plus joint-NAF and common-factor choices.
Its best executable scratch result was 31,953 bytes, 672 bytes larger than the
retained 31,278-byte separate quotient-binding gate. Eliminating the explicit
q binding therefore reduced witness structure but did not minimize locking
script bytes for the searched bases.

The discarded generators are not retained as public deterministic fixtures.
The early Horner/mixed-radix measurements, capped centered/unsigned estimates,
and fused-`qN` scratch execution are therefore recorded as `inspected`
design-search evidence rather than cataloged `locally-reproduced`
configurations. The retained 51,047-byte standalone and 31,278-byte composable
profiles are `locally-reproduced` by source, tests, and checked metrics. These
comparisons show domination for the tested bases, representations, and stack
layouts; they do not establish global optimality of centered limbs, explicit q
binding, or exact dot products.

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

## NR-013: The published combined nibble table is misaligned

The combined table in `split-into-bits.md` creates four equal indices and then
performs four `OP_PICK OP_TOALTSTACK` queries. Because each query consumes one
index, the first through fourth lookups see three, two, one, and zero remaining
indices above the table. A direct 64-entry table grouped by nibble does not
compensate for those offsets; for example, the as-published layout maps nibble
`2` to four zero bits rather than `0010`.

The retained u4 implementation uses the same equal-index mechanism with a
corrected 61-item staggered table: table depths `4*x-3 ..= 4*x` hold the four
big-endian bits of each nonzero nibble, while nibble zero is answered by its
zero-valued indices. Corrected behavior is `locally-reproduced` exhaustively
over `0..=15`; the upstream-layout diagnosis is `inspected` source analysis.
Source: `coins-bitcoin-scripts-8f442e4b` at
[`split-into-bits.md`](https://github.com/coins/bitcoin-scripts/blob/8f442e4bf8a744dd9bf69b2937bdebcaed5cae77/split-into-bits.md).

## NR-014: The generic roll-table splitter is not a wide-limb improvement

The same upstream page's generic `ROLL` splitter does not directly return
canonical bits. For each high input bit it leaves zero when the bit is set and
the corresponding power of two when it is clear; the low bit remains the final
remainder. Normalizing each high output with `OP_NOT` makes the result
comparable to the existing branch splitter.

Inspected scratch ports measured normalized roll-table versus existing branch
fragments at 36/39 bytes for 4 bits, 92/95 for 8, 204/200 for 15, and 468/418
for 29. The table uses another `2*(n-1)` live items. It saves three bytes only
at the two smallest tested widths and loses for the local 15- and 29-bit limb
uses, so it is not retained as a general splitter. This is an `inspected`
frontier for the tested widths, not a universal domination claim.

## NR-015: The single-ScriptNum right shift omits one 32-bit word

The pinned `op_rshift.md` construction treats ScriptNum's sign as logical bit
31 and the magnitude as the lower 31 bits. That represents almost every raw
32-bit word compactly, but `0x80000000` corresponds to Script's negative-zero
encoding. Numeric comparison sees it as zero, so the construction shifts it to
zero instead of `0x10000000` for a three-bit shift. A protocol that requires
all `2^32` words therefore needs a separate representation or explicit raw-byte
special case.

Inspected scratch ports measured fixed shifts by 3, 7, and 10 at 547, 539, and
525 script bytes with 224, 216, and 210 static non-push opcodes. The existing
four-byte u32 fragments were 545, 266, and 610 bytes respectively, excluding
their shared Boolean-table setup. The ScriptNum method can win for a specific
shift and saves stack items, but these are not like-for-like workload costs and
all three inspected variants exceed the 201-opcode legacy/P2WSH consensus
limit. Tapscript removes that opcode-count limit, but total-domain correctness,
encoding, conversion, and strict Bitcoin Core validation remain open under
OP-014. Source: `coins-bitcoin-scripts-8f442e4b` at
[`op_rshift.md`](https://github.com/coins/bitcoin-scripts/blob/8f442e4bf8a744dd9bf69b2937bdebcaed5cae77/op_rshift.md).

## NR-016: Half XOR tables lose BLAKE3 byte efficiency

The BLAKE3 generator's half-table mode saves 120 persistent stack items, but it
adds sorting and symmetry-recovery work to every nibble XOR. A deterministic
single-block, 29-bit-limb design probe with the selected G-call order measured
87,507 optimized bytes for half tables versus 76,556 for full tables before the
shared limb-validator improvement: a 10,951-byte regression. BLAKE3 performs
1,856 nibble XOR lookups per block, so the per-query penalty dominates the
smaller setup. This is an `inspected` generator result for the current lookup
layout, not a universal claim that half tables are inferior when stack items
are the primary objective.

The retained full-lookup semantics no longer require a rectangular 256-item
matrix. Overlapping the 16 fixed-orientation rows produces a 171-item shortest
common superstring; exhaustive subset DP proves 171 minimal for those rows.
Together with its 16-item selector, it is smaller than the half-table design
without adding symmetry-recovery work to any query.

## NR-017: Consuming both BLAKE3 output halves does not save bytes

Compression finalization currently consumes the first eight state words,
copies the second eight through nibble XOR, and then drops those copied words.
A consume-both prototype removed the final 32 `OP_2DROP` operations, but moving
the second operand changes each lookup depth and required 64 `OP_1SUB`
adjustments. Shallower routing recovered most, but not all, of that cost: on the
pre-scheduling 64-byte, 29-bit baseline it measured 77,781 raw and 76,699
optimized bytes versus 77,777 and 76,695 for the retained copy-and-drop layout,
a four-byte regression in both cases. The prototype passed a deterministic
64-byte differential check. This is an `inspected` result for the current
depth-table lookup scheme; a fused output schedule may have a different
frontier.

The same consume-both idea was retested after short-input specialization. It
passed every length from 0 through 32 but measured 61,083 bytes versus the
61,074-byte copy-and-drop comparison point, a nine-byte regression at the same
peak. This is `locally-reproduced` confirmation that the result persisted on
the later layout.

## NR-018: Eager BLAKE3 routing and message expansion increase script size

Sparse 32-byte u4 prototypes tested moving active lanes into an altstack
quartet, stashing the outputs of early G calls, and pre-expanding permuted
message schedules. Against a 65,532-byte sparse baseline, stashing the first
one, two, or three G outputs measured 66,234, 66,232, and 66,963 bytes. A full
pre-gather search over all 24 quartet layouts bottomed at 71,169 bytes. In a
separate schedule-expansion harness, the 65,718-byte no-expansion case beat the
best nonempty expansion mask at 66,060 bytes; expanding every reusable schedule
reached 68,063 bytes and a peak of 962 items. The retained incremental tracker
therefore avoids the extra `TOALTSTACK`, `FROMALTSTACK`, and routing work.

The active-quartet candidates and representative no-expansion scripts passed
local differential checks. These are `inspected` generator results tied to the
recorded stack layout, not a proof against every fused scheduler. A
branch-based two-input carry prototype was also dominated by 351 bytes at 32
bytes.

A later explicit witness-expanded design supplied seven 64-nibble schedule
copies, range-checked one canonical copy, and equality-bound the other six. It
fit the limit at 906 items but measured 65,651 bytes versus the contemporary
62,647-byte single-copy backend. Without binding or range checks it was 63,091
bytes; destructive per-round consumption saved only four compression bytes,
so input parking and equality checks could not amortize. The bound construction
matched the independent BLAKE3 implementation and rejected unequal copies.

Interleaving the eight dependent stages across four disjoint G calls was also
dominated. Stage chunk sizes one through eight measured 66,433, 64,739, 63,600,
63,763, 63,205, 63,221, 63,125, and 62,647 bytes; whole-G execution was the
minimum. A within-G prototype streamed all three aligned XOR-to-add chains but
reached 66,170 bytes before digest-order cleanup. Even crediting all 2,184 bytes
needed to restore canonical retained-word order leaves a 63,986-byte lower
bound above its 62,647-byte comparison point. The expanded-witness and
stage-chunk results are `locally-reproduced`; the unfinished streamed lower
bound is `inspected` design-search evidence.

On the later independent-digit scheduler, exhaustively restoring the next
message pair before each first-round column bottomed at 61,055 bytes versus
61,026 for retaining the message, a 29-byte regression. Seven witness-supplied
message schedules would fit after packed-table reduction at a projected
927-item peak, but binding six hostile duplicates costs at least 896 bytes
while destructive use can save at most 384 copy bytes. The resulting
512-byte lower-bound regression rules out that expansion before layout and
range-check overhead.

## NR-019: Alternate BLAKE3 digit representations are size-dominated by sparse u4

A byte-radix prototype generated 95,788 bytes before its quick register
scheduler was made output-correct, already roughly 30 kB above the contemporary
sparse-u4 result. The u4 backend benefits structurally because rotations by 16,
12, and 8 bits are nibble permutations and only the seven-bit rotation crosses
digit boundaries. The u8 experiment was stopped rather than polished because
correctness cleanup could not erase the existing size gap. This is an
`inspected` rejected prototype, not a differentially validated u8 construction.

Correct clean-sheet radix-u2 and bitwise backends settled the smaller-radix
side of the same question. For a checked 32-byte input they measured 131,443
bytes at a 450-item peak and 202,577 bytes at a 792-item peak, respectively,
versus the 62,647-byte u4 comparison point. Both implemented all seven rounds,
sparse message words, checked hostile input, and standard u4 digest output, and
matched the independent BLAKE3 crate on deterministic short lengths. A checked
byte-to-u4 input bridge alone was 1,168 bytes versus 451 for direct u4 input.
These results are `differentially-validated` local generator evidence: smaller
tables do not repay doubled or quadrupled digit routing, while byte and wider
radices lose the free 12-bit nibble rotation.

Later clean-sheet kernel searches extended the comparison against the
60,866-byte, 543-item checked direct-u4 frontier. A correct radix-u3 XOR word
costs 132 bytes with 51 table items, versus 88 bytes and 187 items for u4;
two- and three-input additions cost 167 and 221 bytes versus 116 and 155.
Across the measured 224 XOR, 164 two-add, and 52 three-add sites, even an
ultra-favorable XOR-only projection exceeds 69.6 kB, while applying the
measured addition penalties projects roughly 81.5 kB before top-limb and
cross-rotation handling.

Raw-sum add-to-XOR fusion is stack-feasible with the packed XOR rows, but its
repeated 48-entry row selector adds 101 lifecycle bytes and 32 peak items. In a
favorable mixed-phase kernel where aligned rotations are metadata, fused
two-input add/ROR16 costs 227 bytes versus 219 separate and streamed add/ROR7
costs 348 versus 323. Whole-word little-endian storage likewise costs 701 bytes
for a two-input add versus 696 in the retained big-endian layout. Deferred
seven-bit-rotation representations measured 63,358/658 and 62,485/628, while
an extra low-XOR plane measured 62,018/884; none crosses the retained frontier.

The u3, raw-sum, endian, and deferred-rotation kernels executed correctly on
deterministic boundary vectors, so their measured comparisons are
`locally-reproduced`. The full-backend u3 projections and mixed-boundary search
are `inspected` bounds: among eight digit boundaries, canonical u4 uniquely
maximizes aligned boundaries for rotations 7, 8, 12, and 16; a ninth boundary
adds a digit to every add and XOR for only one additional alignment. These
results bound the tested representation families, not every possible BLAKE3
circuit or future opcode set.

## NR-020: Unadjusted BLAKE3 quotient/modulo interleaving is incorrect

An attempted 96-item table placed `sum % 16` and `sum / 16` at adjacent depths
so one absolute index could fetch both. The first lookup retained a copy of that
index, however, shifting the depth seen by the second `OP_PICK`; deterministic
digest comparison exposed the error. The rejected layout must not be cited as a
size improvement.

The retained correction accounts for that shift instead of abandoning
interleaving. Top-relative depths `2*s` and `2*s+1` hold `s mod 16` and
`floor(s/16)`. The first lookup uses an absolute base one item deeper because
the index is retained; after the modulo result moves to altstack, consuming the
unchanged index selects the adjacent carry. At this search stage, a separate
48-item modulo table avoided doubling the most-significant sum whose carry was
discarded, and literal first-column nibbles were folded into the address. The
production backend later replaced that table with two row-zero cycles appended
to the reversed packed-XOR superstring.

On the previous 62,647-byte checked 32-byte backend, corrected interleaving plus
the final-modulo table measured 61,188 bytes; constant-address folding and the
exact-32 final operand order reduced the retained result to 61,074 bytes at a
628-item peak. Every declared length from 1 through 32 matched the independent
BLAKE3 implementation, and an exhaustive sum test covers table indices 0
through 47. The rejected unadjusted form and retained correction are therefore
`locally-reproduced` for this generator. Subsequent XOR/modulo fusion, delayed
table introduction, peepholes, and independent-digit scheduling reduce the
combined frontier to 59,529 bytes; the 61,074-byte figure remains the
like-for-like measurement of the addition change itself.

## NR-021: Higher Winternitz radices lose locking-script bytes

For a 256-bit message, the committed list-pick parameter sweep measured bases
16, 32, 64, 128, and 256 at respectively 4,908, 5,631, 7,169, 10,585, and
16,916 locking-script bytes. Larger radices reduce the number of public
endpoints from 67 to 55, 45, 39, and 34, but the longer static hash/list logic
per chain grows faster than the endpoint commitment shrinks. Base 16 is
therefore the selected locking-size radix among the implementation's supported
power-of-two parameters. This is a `locally-reproduced` result for the current
list-pick layout and fixed 256-bit message, not a proof that base 16 is globally
optimal for every Winternitz verifier, message length, or checksum encoding.

## NR-022: Radix-256 clean-sheet field multipliers lose to normalized radix-512

The native secp256k1 clean-sheet search built executable scratch generators for
several byte-digit layouts before retaining the 29-digit radix-512 design. Full
one-shot sizes for radix-256 schoolbook, one-level Karatsuba, recursive
Karatsuba with cutoff four, a 16-bit quotient layout, and the best asymmetric
centered layout were respectively 28,002, 26,574, 25,666, 24,874, and 23,870
bytes. Their measured strict peaks were 710, 799, 810, 794, and 794. Static
non-push counts were 18,471, 16,198, 15,104, 14,504, and 14,695.

All five paid 1,649 bytes to push and 256 bytes to drop their lookup memory.
The closest asymmetric candidate also needed 111 incremental hint items (113
serialized bytes for its sparse `(p-1)^2` witness), compared with 67 items and
94 bytes for the retained ordinary input. A later asymmetric radix-512 split
reduced the production ordinary gate to 20,503 bytes at a 757-item peak; the
factor-16 encoded profile is 20,450 bytes at a 719-item peak. Both retain the
1,795-byte table lifecycle.

A historical separate 57-slot destructive recombination illustrates why
domination depends on the workload. In that search round it was 21,709 bytes
for one multiplication, 418 bytes larger than the then-retained isolated
layout, but its lower peak permitted a strict three-product shared-table batch.
Current production selects a remapped destructive layout only for the
three-gate dispatcher and keeps the smaller 85-coefficient layout for one and
two ordinary products.

The radix-256 scratch generators are not retained as deterministic fixtures,
so those measurements are `inspected` design-search evidence. They establish a
frontier for the tested radices, quotient layouts, cutoff rules, and stack
schedules, not a proof that radix 512 or one-level Karatsuba is globally
optimal.

## NR-023: Other bounded bitwise checksum partitions do not beat 3+3+4

For the 0–960 `FastWots32` checksum range, a deterministic local search
enumerates one through five power-of-two checksum digits, with one through six
canonical bits per digit and total capacity of at least ten bits. It measures
the exact current bit-branch verifier fragment, including positional
accumulator constants and embedded endpoints. The selected low-to-high widths
`[3, 3, 4]` cost 169 locking bytes and match the minimum of that search; common
`[5, 5]`, `[2, 4, 4]`, and four-or-more-digit layouts are dominated once hash
blocks, endpoint pushes, and ScriptNum constant sizes are included.

This is `locally-reproduced` by
`bitwise_checksum_partition_search_selects_three_three_four`. It establishes an
optimum only within the enumerated canonical-bit branch model and bounds. It is
not a proof against non-positional checksums, Taproot leaf specialization,
different message encodings, or future opcodes.

## NR-024: Additional recursive and one-pass secp256k1 folds are dominated or invalid

The final clean-sheet round tested exact executable schedules around the
asymmetric 14/15-digit radix-512 product. Adding a second Karatsuba layer to the
15-digit normalized-difference branch saved 117 bytes in leaf-product code but
added 176 bytes of recombination and 8 bytes of cleanup, a net 67-byte loss.
A one-layer radix-256 design measured 24,995 bytes. A centered 32-digit
radix-256 recursive product with the secp256k1 monic fold measured 24,211 bytes;
even the impossible lower bound obtained by deleting all 2,261 routing bytes
would have remained 1,426 bytes above the then-retained 20,503-byte gate.

A direct one-pass factor-16 fold looked attractive because
`16*512^28 = p + 32*512^3 + 977`, but its honest boundary residual reached
68,719,492,368 and therefore cannot be consumed by four-byte ScriptNum numeric
opcodes. The retained factor-16 construction folds the degree-28..31 tail a
second time, recodes 977 as `-47 + 2*512`, and pipelines shared coefficient
multiples. It measures 20,450 bytes with a 719-item peak and does not inherit
the oversized residual.

These scratch variants are `inspected` because their temporary generators are
not retained as repository fixtures. The 20,503-byte ordinary and 20,450-byte
factor-16 endpoints are `locally-reproduced` production configurations. The
factor-16 endpoint is not an ordinary-domain drop-in: it requires stored
`E(x)=x/16 mod p` values, so omitted conversions can reverse its 23-byte
one-shot advantage.

## NR-025: BLAKE3 cross-G and final-output fusion do not repay routing

Several bounded searches attempted to consume related BLAKE3 values together
instead of shortening the existing absolute lookups. Pairing final-round G
calls with their output XORs produced a best strict two-lane construction of
60,983 bytes and a relaxed retain-one-lane construction of 60,912 bytes against
the then-current 60,866-byte exact-32 baseline. Both matched the independent
Rust BLAKE3 implementation for every declared short length, but the extra
`OP_1SUB` depth corrections and grouped cleanup exceeded the saved copies.

Within a G call, streaming three aligned XOR results directly into the next
addition generated 66,170 bytes, 3,523 bytes above its comparison point; even
granting free word-order normalization left it larger. A dual-output XOR table
was 8,294 bytes larger, branch-based carry splitting added 1,640 bytes, a
corrected single-base quotient hoist added 1,352 bytes, and a carry-on-altstack
layout added 4,448 bytes. On the packed-table backend, consuming both halves of
the final output remained nine bytes larger. A trace of all 1,792 dynamic XOR
queries found only eight shallow first operands and no adjacent source pair for
which native pair operators repaid the required result preservation.

Table-boundary fusion was likewise bounded. Aliasing the zero at the shift/XOR
boundary saved one pushed value but crossed ScriptNum-width boundaries in two
selector constants, a net one-byte regression. Raw-sum add-to-XOR selectors
and extra low-XOR planes are recorded in NR-019. The retained construction
instead delays shift/addition memory, uses scalar hot-path queries, and only
destructively consumes the final single XOR lookup. These rejected generators
and their deterministic digest checks are `locally-reproduced`; the routing
trace is an `inspected` lower bound for the enumerated native-pair patterns, not
a proof against every fused BLAKE3 circuit.

## NR-026: Three general products are dominated in the fixed Schnorr equation

The affine BIP340 relation needs two products and one square. Treating all three
as ordinary native secp256k1 products gives a 63,219-byte raw-certified shared
batch and a 993-item peak. Three independent raw multipliers total 65,316
bytes. Scheduling the specialized square first while preserving two pending
product groups, then consuming those products in one batch, costs 57,241 bytes
and peaks at 882. It saves 5,978 bytes (9.5%) against the shared all-general
batch and 8,075 bytes (12.4%) against isolated gates.

This is `locally-reproduced` for the exact fixed-instance affine certificate
boundary. It does not establish that affine verification globally dominates a
runtime GLV/Jacobian trace, an x-only proof, or a future batch-constraint
system; those alternatives close different trust and input boundaries.

## NR-027: Untrusted Jacobian public inputs do not shrink the fixed Schnorr leaf

Providing BIP340's public key and nonce as affine `(x,y)` values merely moves
the generator's even-y lift into the witness: Script must still bind x, prove
`y^2 = x^3 + 7`, and enforce normalized even y. Providing arbitrary Jacobian
`(X,Y,Z)` adds a nonzero-Z check plus `x=X/Z^2`, `y=Y/Z^3`, curve, and parity
constraints. The retained generator already promotes trusted lifted affine
points to `(x,y,1)` and uses Jacobian coordinates internally, so neither input
shape removes one of the final 2M/1S affine relations.

This is an `inspected` boundary argument, not a measured universal lower bound.
Full points may still help a spend-time verifier whose surrounding protocol
already authenticates normalized affine coordinates or projective state.

## NR-028: Projective and GLV machinery do not shrink the standalone CSFS trace

In the spend-time verifier, affine inversion is already an off-chain hint.
Script binds the slope to its numerator and denominator with one field product,
so a general affine transition executes 2M+1S and a doubling executes 2M+2S.
Representative mixed-Jacobian formulas instead require roughly 7M+4S per
addition and 2M+5S per doubling before complete exception handling or final
normalization. An untrusted `(X,Y,Z)` input adds nonzero-Z, curve,
normalization, affine-x, and even-y obligations. This is an `inspected`
operation-count comparison; no projective CSFS configuration is claimed as
locally executed.

GLV is likewise dominated for the current position-specific lookup layout.
Splitting both 256-bit dynamic scalars into four roughly 128-bit components
retains approximately the same aggregate number of fixed-window positions,
table entries, and affine additions, while adding scalar-decomposition, sign,
and range constraints. Dynamic wNAF lowers the honest number of nonzero
digits, but an unrolled Script must still carry conditional group logic for
every possible position or authenticate a compressed position list. These are
construction-specific boundary results, not universal claims against GLV,
wNAF, or projective arithmetic.

## NR-029: A 2^32-leaf taptree saves one 32-bit lookup at absurd setup cost

One locally executed CSFS leaf commits to the low 32 bits of `s`, embeds their
signed fixed-base contribution, verifies the corresponding four recoded
digits, and removes four table selections and complete affine transitions.
For the deterministic Schnorr fixture, the ordinary leaf is 8,292,228 bytes
and the specialized leaf is 7,850,893 bytes: 441,335 locking-script bytes
(5.32%) are saved. Arithmetic/input witness serialization falls from 81,740 to
77,869 bytes. A depth-32 control block adds 1,026 serialized bytes relative to
a depth-zero block, leaving a net 444,180-byte reduction in the representative
revealed script-path witness.

The single-leaf result is `locally-reproduced`; the full-tree resource estimate
is `inspected`. A naïve `2^32` materialization at roughly 7.85 MB per leaf is
about 33.7 PB of script data plus billions of hashes, even though only the root
is placed in the output and one path is revealed. The trick does not repair
the verifier's 33,589-item relaxed stack peak or block-weight infeasibility.
Specializing another independent 32-bit chunk through the same Cartesian
lookup raises the conceptual space to `2^64` leaves.

## NR-030: Unbound 4-bit limb tables do not verify 26-by-26-bit products

The proposed Ed25519 multiplier decomposes one 26/25-bit limb into 4-bit
digits and looks up `d*a_i` from a 16-entry table. Each lookup is at most 30
bits and fits positive ScriptNum, but the required shifted sum is a 51–52-bit
integer. Bitcoin Script cannot shift, multiply, or even feed that integer to
an arithmetic opcode. Storing only `d*a_i mod 2^k` also loses the high quotient;
poison gaps constrain a table address but do not bind those omitted bits.

A sound version needs extra digit decomposition plus exact quotient/carry
relations (or an independently bound residue representation) for every shifted
partial. Those checks are absent from the stated roughly 80-byte column loop,
so the roughly 2.3 KB total is not a valid verifier cost.

The repair search retained the operand-derived table idea but changed the
arithmetic granularity. A sound factor-8 radix-16 candidate uses thirteen
balanced 20-bit left limbs, 64 certified right nibbles, 832 lookups, one scalar
quotient, and 63 carries. It measured 11,337 policy-compiled bytes at a
341-item strict peak. The current size winner instead uses 51 biased centered
radix-32 digits, thirteen signed 32-entry tables, 663 lookups, one scalar
quotient, and 50 carries. It measured 9,893 bytes for previously certified
operands and 11,180 bytes with raw operand certification, at a 523-item strict
peak. The retained normalized-Karatsuba factor-8 baseline is 19,903 bytes.

These repaired backends are `locally-reproduced` and `unclassified`; their
strict measurements use `bitcoin-scriptexec` in tapscript context rather than
a complete Bitcoin Core transaction. Generated-Script boundary and
adversarial suites for the new radix-table backends remain ignored by default.
The measured gap between 2.3 KB and 9,893 bytes is principally the cost of
binding all selected products and the complete carry relation, not an omitted
peephole. This result rejects the specified hot loop, not every possible
26/25-bit or 4-bit-table construction.

## NR-031: Packed Ed25519 relation quotients lose to direct q at G29

The byte-minimized mixed affine transition has three exact relation quotients,
all conservatively represented as signed 23-bit values. The 28 transitions in
the G29 fixed-base schedule therefore carry 84 logical hints and 1,932 payload
bits. An executable optimal-item codec stores those bits in 61 physical
compressed-u32 items: 56 transition-local words plus five global bit-plane
words. Sixty-one is the information-theoretic item minimum
`ceil(1932/32)`. All 61 items coexist at entry with 672 trace-data items and
eight scalar items, giving 741 complete entry items. The codec is 23,769
policy-compiled bytes, but 25,570 raw bytes in a multi-megabyte leaf; its
deterministic hint witness is 222 serialized bytes and its focused strict run
peaks at 762 combined main-plus-alt-stack items.

That item-minimum encoding is dominated for the four-million-byte objective.
Keeping every quotient as its own ScriptNum uses 84 hint items, three per
transition, and raises complete entry to 764. Each honest value needs a signed
23-bit slot and at most three payload bytes, not a full 32-bit item. No explicit
range decoder is needed in the integrated path: once the coefficient sources
have their documented bounds, the accepted integer recurrence is `H=q*p`.
Since p is nonzero, q is unique, and the bound on H implies the honest 23-bit
range. A longer-than-four-byte item fails when consumed by Script arithmetic;
an at-most-four-byte nonminimal alias is the same integer and affects policy or
witness malleability, not relation soundness. Direct q thus removes 25,570 raw
locking bytes for 23 additional entry items.

The winning G29 layout has one top width-9 group, twenty lower width-9 groups,
and eight lower width-8 groups. Its identity-safe MSB-first hybrid tries are
923,727 raw bytes. The 28 signed/zero-safe shared-tau relation kernels total
2,940,987 raw bytes: one 116,418-byte packed-current kernel, nineteen
107,259-byte packed-constant chained kernels, and eight 98,331-byte
direct-constant chained kernels. Each signed kernel compiles its smaller
boundary-preserving semantic steps through the repository policy before the
larger wrapper takes the raw path. This saves 78,498 bytes without changing
its input/output contract. Positive, negative, and identity cases were
executed separately before this size-only precompilation change; the optimized
bytecode was regenerated but deliberately not executed. The direct-q
schedule's first arithmetic frontier has an 811-item boundary: 737 unrelated
preserved items plus the 74-item local input. Its previously measured 256-item
local kernel peak gives a modeled 993 combined items; every later arithmetic
frontier is lower.

The previous 31-group candidate is dominated on the joint objective. Its
nonmixed positive subtotal was already 4,093,913 bytes before a sound
signed/zero wrapper, selection routing, output consumption, or transaction
overhead. It could touch exactly 1,000 stack items only by using a larger
sequential first kernel. Moving to 29 groups, mixed negative-product limb
layouts, the bit tries, signed identity tuple, and direct q is what opens both
byte and stack headroom. The superficially similar `27*8 + 4*9` schedule is not
a substitute because it covers only 252 source bits and cannot encode every
canonical scalar below `l`.

The integrated G29 generator now serializes the actual scalar validator and
stream, authenticated tables, sign/identity controls, trace/quotient routing,
and all 28 real kernels. The exact policy-produced fragment is 3,881,402 bytes:
923,727 table bytes, 2,940,987 precompiled-kernel bytes, 791 scalar-validator
bytes, and 15,897 scalar-stream/sign/packet-routing bytes. The final
multi-megabyte composition itself receives `CompileOptions::NONE`. Its
whole-schedule strict execution substitutes peak-equivalent arithmetic bodies
while retaining the real scalar and control path; scalars zero, one, and `l-1`
peak at 993 items. The optimized kernels and full 28-kernel arithmetic run are
deliberately not executed because the generated long-running tests are opt-in.
This distinction prevents the serialized-byte result from being misreported
as a full arithmetic execution.

The codec, pre-step-compilation individual kernels, and integrated
serialization/control schedule are `locally-reproduced`; the optimized kernel
serialization is generation-measured only. Deployment is `unclassified`. This is a
`fragment-only` fixed-base `[s]B` construction, not a complete leaf,
transaction, or EdDSA verifier. Output comparison, clean terminal truth,
complete witness and taproot serialization, executed opcodes, validation
weight, and Bitcoin Core validation remain excluded. Finally, 4,000,000 is a
block-weight limit rather than an available locking-script byte allowance:
transaction and witness overhead must still fit beside any revealed tapleaf.

## NR-032: A monolithic EdDSA-BLAKE3 verifier does not fit the current affine trace

Replacing SHA-512 with BLAKE3 does not remove the double-scalar verification
equation. For a key-specialized custom scheme the remaining group check is

```text
[s]B - [h]A = R,
h = BLAKE3(D32 || A32 || R32 || M32).
```

With fixed `D32,A32`, the first 64-byte BLAKE3 block can be compressed by the
generator. The resulting one-on-chain-compression candidate is 65,208 raw
bytes, consumes exactly 128 checked u4 data items for `R32 || M32`, uses
exactly zero hint items, returns 64 digest nibbles, and has an analytic local
peak of at most 591 items. A host-only deterministic check reconstructs the
same 128-byte unkeyed BLAKE3 digest from the embedded chaining value. The
generated Script itself has not been executed, so these hash-generator results
are `inspected`, not local Script correctness evidence. The ordinary
`BLAKE3(R32 || A32 || M32)` two-compression candidate is 125,687 raw bytes,
uses 192 checked data items and zero hints, and has an analytic local peak of
at most 655.

An initially reported 63,766-byte low-128 fragment attempted to preserve the
H16 linker's 337-item prefix without moving it below BLAKE3's lookup memory.
That layout is invalid: the packed-XOR backend derives table addresses from
`OP_DEPTH`, so its first `OP_PICK` reads the wrong item when a caller prefix is
below the tables. Correct table placement makes the variable-message hash
65,123 bytes and strict-peaks at 928. For the linked fixed message, verifying
and consuming its 64 nibbles before a constant-word compressor instead gives a
64,118-byte policy-compiled binder/hash pair and an 864-item strict peak; both corrected paths
match ordinary host BLAKE3. The invalid 63,766-byte number is not a composable
optimization result.

The optimized G29 `[s]B` fragment and the key-specialized hash total 3,946,610
raw bytes before transcript routing, digest use, `R` binding, the `[h]A` side,
or a terminal predicate. They cannot merely be concatenated under the stack
limit: keeping the hash's 128 input items live raises the scalar frontier from
993 to 1,121, while hashing first would preserve the scalar's 764 entry items
under a hash-local peak of up to 591.

There is a promising transport repair for this narrower hash-plus-`[s]B`
composition. Sixty-four of the 84 q items can carry one transcript byte each
as the injective positive 31-bit value
`P=(byte<<23)+(q+2^22)`. A 139-byte decoder recovers two u4 digits and the exact
signed-23-bit q; using only the last 64 q slots leaves the critical early
frontier unchanged. The complete entry remains 764 items and still contains
84 logical quotient hints, while `R32||M32` adds zero physical items. The
focused decoder/routing model projects approximately 3.957 MB and a 993-item
peak for `[s]B` plus the key-specialized hash. Its final metric run and the real
BLAKE/arithmetic execution were deliberately skipped, so this is an inspected
composition estimate, not a reproduced complete fragment. It also leaves only
about 43 kB of script room and does not address `[h]A`.

The best inspected direct joint-window candidate uses 64 centered radix-16
positions and tables for `s_i*16^i*B - h_i*16^i*A`. It needs 63 affine
transitions. Even granting every transition the smallest currently measured
direct-constant signed kernel, the precompiled kernel subtotal is at least
6,212,940 bytes; approximately 1.31 MB of joint tables puts the construction
near 7.59 MB with the key-specialized hash, before routing, point decoding,
`R` validation, or final comparison.

The stack failure is independent. The current exact affine certificate uses
24 packed trace-data items and three signed-23-bit quotient hints per
transition. Sixty-three transitions therefore require 1,512 trace items and
189 direct hint items, or 1,701 packet items before scalar/hash/R state. Even a
globally optimal packing of the 4,347 quotient bits needs 136 physical items,
leaving 1,648 packet items. Algebraically eliminating the packed `tau` and its
quotient lowers a nonidentity packet to 18 items, but the two next coordinates
alone need `63*16 = 1,008` items. It also replaces six bilinear convolutions
with four bilinear plus two trilinear convolutions: 275,706 elementary digit
terms instead of 15,606, a 17.67-fold expansion. Materializing `x*y` restores
bilinearity but restores the removed witness field and quotient.

This is an `inspected`, `unclassified` negative result for the present exact
affine-certificate and authenticated fixed-window design, not a lower bound on
all possible Ed25519 verification systems. A sound one-coordinate trace,
succinct proof system, or interactive/optimistic trace protocol could change
the boundary. Wider radix, quotient packing, ordinary Straus/JSF recoding,
projective coordinates, and local BLAKE3 optimization do not.

## NR-033: Carry-centered H16 challenge recoding wastes the top table

The former challenge schedule propagated a centered carry through the low
fifteen bytes and left the high digit in `0..=256`. Although valid, that made
the last authenticated challenge table contain 257 leaves while every other
challenge table contained only 129. Its recoder was 580 bytes and the 45
tables occupied 838,456 bytes.

Independently setting `e_i=byte_i-127` gives `e_i in [-127,128]` and
`h=sum(e_i*2^(8i))+K_127`, where `K_127=0x7f7f...7f`. Folding
`-[K_127]A` into the response initializer costs 57 table bytes, but reducing
the challenge-top table to 129 leaves saves 12,441 bytes and removing the
carry chain saves another 191. The resulting 826,072-byte tables and 389-byte
recoder are **12,575 bytes smaller** in the linked leaf. They retain 45 tables,
44 transitions, 792 coexisting entry items, and exactly 88 quotient hints.

Focused host algebra checks the response boundaries, bias identity, torsion
translations, and endpoint; strict Script checks cover byte boundaries
`00,7f,80,ff` with the real 337-item prefix and peak at 371. Both old and new
table serializations were generated without executing the large scripts. This
is `locally-reproduced` at those fragment boundaries and `unclassified`; it is
an exact dominance result for this H16 table layout, not for arbitrary scalar
recodings.

## NR-034: Generic squaring and per-transition powers are dominated in the G32 slope chain

This historical comparison records the `f7bb0c2` G32 layout. The zero-hint
Montgomery-slope relation originally reused the general
bilinear product schedule for `lambda^2` and rebuilt every power of two inside
every quotient-derivation kernel. Both choices preserve correctness, but lose
locking-script bytes in the repeated G32 schedule.

The symmetry-specialized square groups doubled cross terms before the
pseudo-Mersenne fold. In isolation it is 7,984 bytes instead of 10,870 and
reduces variable table updates from 663 to 351. Integrated routing saves 2,887
bytes per transition, or exactly 135,689 across all 47 transitions. Reusing a
four-item `2^23..2^26` pool at the first response transition and a 16-item
`2^15..2^30` pool in each later response/challenge phase saves another 19,365
bytes. The four-item first pool spends 37 bytes relative to the five-item byte
minimum in exchange for a one-item stack margin. These constants are authored
by Script, not witness hints, and add zero entry or witness items.

With the corrected hash compilation policy, the complete-leaf account moves
from 3,155,037 bytes before these two changes, to 3,019,348 after the square
specialization, and finally to the exact 2,999,983-byte serialization with the
split pools. Focused square and pool probes are `locally-reproduced`; the
resulting complete leaf was serialized but not executed. Overall verifier
evidence remains `inspected` and deployment remains `unclassified`. The result
is specific to this radix-32 relation and exact 47-transition layout.

## NR-035: A cross-hash persistent power pool saves 25 bytes but weakens the composition boundary

This historical comparison records the `f7bb0c2` G32 layout, before the
partial-word/Horner changes in NR-036. Keeping the same 16 Script-authored
power constants on the alt stack through
canonical-u5 BLAKE3 and the independent-byte recoder is technically feasible.
A focused strict sentinel probe passes at a combined peak of 934 rather than
the hash helper's empty-boundary peak of 918. It adds no witness data, retains
the same 803 coexisting entry-data items, and uses exactly zero auxiliary hint
items per each of 47 transitions and in total.

The layout makes the response finalizer eight bytes larger because it parks
the pool, then saves 33 bytes by omitting the challenge initializer: a net
25-byte reduction, from that revision's 2,999,983-byte leaf to a projected
2,999,958 bytes. That small win couples both BLAKE3 and the recoder to a
nonempty alt stack and removes their explicit phase-neutral interface. The
production layout therefore retains split response/challenge pools and empty
hash/final alt-stack boundaries. This is a non-selected composability tradeoff,
not a claim that the persistent layout is unsound or larger. The focused
boundary is `locally-reproduced`; the projected alternate whole was not
generated and neither multi-megabyte leaf was executed, so overall evidence
remains `inspected` and deployment `unclassified`.

## NR-036: Full word expansion and separate coefficient passes cost repeated bytes

The retained fast packed decoder expands every signed word through the
31-bit splitter, even where its consumer immediately regroups those bits.
Partial-word decoding keeps the low piece numeric and uses sixteen shared
Script-authored powers for the remaining comparisons. Returning 51 certified
digits costs 4,072 instead of 4,644 policy-produced bytes, but raises the
local combined-stack peak from 81 to 93. This is a byte/stack tradeoff, not
unconditional dominance. Directly returning sixteen centered slope-product
limbs costs 3,590 bytes and peaks at 62 items; it avoids subsequent regrouping.
Each boundary consumes eight coexisting data items and zero hints. The G32
schedule uses 47 digit and 46 grouped decodes, still with zero cumulative
hints. Decoder powers are temporary and included in all peak counts.

The relation generator also avoids five separately reduced low residues,
repeated sparse-coefficient traversals, and a subtraction-oriented carry
recurrence. A reducing Horner pass retains one residue; fused linear updates
retain the same coefficients; starting the carry at `-q` permits addition.
These changes preserve both exact quotient relations, with zero hints per
relation and zero across all 94 invocations. Bounds and source binding are
unchanged; the largest newly introduced Horner temporary is 2,072,011,424.

Against `f7bb0c2`, the first kernel saves 3,700 bytes, each of 45 ordinary
later kernels saves 3,520, and the final u5 kernel saves 1,943: 164,043 kernel
bytes in total. Endpoint-specialized table selection saves another 1,287.
The exact complete serialization decreases from 2,999,983 to 2,834,653 bytes,
a 165,330-byte reduction, while retaining 803 entry data items and zero hints.
The analytical combined peak decreases from 999 to 995. The first-kernel
204-item local bound is checked over all 679 conditional branches by
`ed25519_montgomery_first_stack_bound`, giving 991 with its 787-item prefix;
the schedule maximum occurs at the following transition.

The bounded probes `ed25519_packed_grouped_decode_probe`,
`ed25519_slope_quotient_horner_probe`, and
`ed25519_montgomery_slope_optimized_probe` cover these fragment boundaries.
Decoder outputs are `differentially-validated` against host bit extraction;
relation execution evidence is `locally-reproduced`. Deployment remains
`unclassified`; these probes do not execute a complete scalar/signature leaf.
The whole serialization is `locally-reproduced` at the generation boundary;
the overall verifier remains `inspected` and `unclassified`.
