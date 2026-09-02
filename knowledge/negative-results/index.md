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
remainder complement. That standalone work costs 51,055 script bytes with an
868-byte, 299-item data witness and a strict 305-item peak. This does not erase
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

## NR-011: Alternative global-binding layouts lose to centered exact-dot bindings

The global-binding search tested deterministic conversion before selecting the
retained centered base-`2^16` design. Direct power-radix/Horner conversion of
all four values produced roughly 623–647 kB of aggregate generated binding
script across the tested layouts. A tighter 34-prime mixed-radix construction
reduced the complete modular-product verifier to 238,885 bytes, but remained
well above both the former 88,225-byte exact-dot verifier and the current
51,055-byte, 47-prime verifier.

The later capped-basis search also rejected two closer alternatives. Its best
centered mixed-radix layout was estimated at 52,352 intrinsic bytes before
range validation and routing, or more than approximately 53.5 kB as a complete
standalone fragment. An unsigned base-`2^15` hybrid was 53,517 intrinsic bytes
before range validation and routing. Both already exceed the retained 51,055-
byte standalone verifier before their missing boundary work is added.

For the composable profile, a direct fused-`qN` construction derived each
`q*N mod p_i` term from the quotient limbs inside the product relation, using
grouped equal/opposite coefficients plus joint-NAF and common-factor choices.
Its best executable scratch result was 31,953 bytes, 672 bytes larger than the
retained 31,281-byte separate quotient-binding gate. Eliminating the explicit
q binding therefore reduced witness structure but did not minimize locking
script bytes for the searched bases.

The discarded generators are not retained as public deterministic fixtures.
The early Horner/mixed-radix measurements, capped centered/unsigned estimates,
and fused-`qN` scratch execution are therefore recorded as `inspected`
design-search evidence rather than cataloged `locally-reproduced`
configurations. The retained 51,055-byte standalone and 31,281-byte composable
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
combined frontier to 59,534 bytes; the 61,074-byte figure remains the
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
reduced the production ordinary gate to 20,524 bytes at a 757-item peak; the
factor-16 encoded profile is 20,501 bytes at a 719-item peak. Both retain the
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
would have remained 1,426 bytes above the then-retained 20,524-byte gate.

A direct one-pass factor-16 fold looked attractive because
`16*512^28 = p + 32*512^3 + 977`, but its honest boundary residual reached
68,719,492,368 and therefore cannot be consumed by four-byte ScriptNum numeric
opcodes. The retained factor-16 construction folds the degree-28..31 tail a
second time, recodes 977 as `-47 + 2*512`, and pipelines shared coefficient
multiples. It measures 20,501 bytes with a 719-item peak and does not inherit
the oversized residual.

These scratch variants are `inspected` because their temporary generators are
not retained as repository fixtures. The 20,524-byte ordinary and 20,501-byte
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
