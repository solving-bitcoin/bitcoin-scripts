# Open research problems

Each problem has a falsifiable completion criterion. Update comparisons and
negative results when closing one.

## OP-019 — PRINCEv2 M-hat circuit frontier

Find a smaller repeated M-hat circuit for generation-time-key encryption.
**Complete when:** a fragment below 5,000 policy-produced bytes, including
table setup and cleanup and excluding plaintext pushes/output comparison,
matches the pinned upstream C fixtures plus seeded random keys/plaintexts,
uses zero hints and 16 input data items, and executes with the combined
1,000-item stack limit enabled. Report zero and nonzero keys separately.
The current zero-key baseline is 6,136 bytes and a 633-item peak. Table packing
and algebraic sketches without a priced executable circuit do not satisfy
this criterion; see [the layout search](negative-results/princev2-layout.md).

## OP-001 — Strict execution matrix

Add explicit legacy/P2WSH/tapscript strict and research-unlimited execution
modes. **Complete when:** every cataloged local configuration records its mode,
strict tests enforce relevant limits, and relaxed success is visibly labeled.

## OP-002 — Bitcoin Core differential harness

Validate complete leaves and transactions against a pinned Bitcoin Core
regtest. **Complete when:** deterministic fixtures compare local execution,
consensus acceptance, and `testmempoolaccept` policy results with a recorded Core
commit.

## OP-003 — Complete metric surface

Add executed opcodes, validation weight, complete witness size, and combined
stack peaks where currently null. **Complete when:** every active catalog record
has a representative configuration with a checked boundary or an explicit
reason the metric is instance-specific.

## OP-004 — Prime-log RNS frontier

Complete the exact-256-bit-product prime RNS deployment and batching frontier.
**Complete when:** a full tapleaf and transaction are differentially validated
against a pinned Bitcoin Core revision, complete witness/weight and validation
behavior are recorded, and prime-major batch crossover curves are measured for
stated reuse counts and live operand-state budgets.

Progress: the 15,626-byte, 183-item no-carry 75-prime table/Horner hybrid
remains the baseline. The current `locally-reproduced` flagship instead uses a
42-prime carry-optimized basis whose product is 513 bits. Packed coordinate
groups verify exact signed carry equations, and an
18-coordinate remainder-complement subbasis with product greater than
`2^257` establishes `r < N` once its values are globally bounded. For the
secp256k1 field modulus, the fragment is 10,950 locking-script bytes with a
301-byte serialized hint and a strict 231-item peak. The 144 hint items are 42
quotient residues, 42 remainder residues, 42 relation carries, and 18
complement residues. It is table-free, so none of those 10,950 bytes is
amortizable lookup setup.

A second `locally-reproduced` profile now supplies the previously missing
global binding inside the arithmetic fragment. It represents `lhs`, `rhs`,
quotient, and remainder with 16 centered base-`2^16` limbs each, derives four
canonical RNS vectors with exact binding carries, proves `lhs`, `rhs`, and
remainder below the target, and checks the modular relation over a 47-prime,
513-bit basis. It is 51,047 locking-script bytes with an 868-byte complete
299-item data witness, 32,772 static non-push opcodes, and a strict 305-item
peak. The script is table-free: 38,796 bytes are the four residue bindings,
10,794 are modular relations, 1,057 are range checks, and 400 are routing.
For programs that retain certified values, the separate one-value binder costs
9,773 bytes and returns both the 16 limbs and 47 residues, proving the value
is below `2^256`. Its `bind_value_below(N)` variant costs 9,860 bytes and also
proves the field bound required for operands and remainders.

A third `locally-reproduced` 46-prime profile makes that certificate boundary
composable. Its 9,832-byte binder consumes a 195-byte, 62-item `N-1` witness
and returns only 46 certified field residues at a 72-item peak. A 31,278-byte
multiplication consumes two such verified-path certificates, locally binds q
and r, and returns a new certificate. The `(N-1)^2` incremental witness is 471
bytes/170 items, the gate peak is 267, and its 20,799 static non-push opcodes
split across 443 bytes of validation, 9,851 q binding, 9,663 r binding, 10,799
relation, and 522 routing/output. Both fragments are table-free. The basis
product is 513 bits and 1.01865 times `2^512`.

The ordinary-product batch frontier is now reproduced for one through six
coordinate-major products. Six cost 64,462 bytes with outputs on the altstack,
or 64,912 after restoring all 450 outputs, at a strict 900-item peak. This is
30.8% below six independent returned-output fragments. Seven products begin
with 1,050 operands and are impossible under the current stack limit. A
two-proof no-carry modular batch was also executed and is dominated: 52,048
bytes versus 51,536 independently because routing exceeded table savings.

All profiles remain `unclassified`. The 10,950-byte profile is still
conditional: all supplied coordinates must be externally tied to canonical
encodings of corresponding unsigned integers below `2^256`, and operands must
be below the target. The 51,047-byte profile closes that binding boundary for
one operation, but it is still a fragment rather than a complete tapleaf or
transaction. The 31,278-byte composable gate closes q/r locally and inherits
lhs/rhs certificates, but assumes those vectors and its hints are already
adjacent. Its two-gate unit test inserts later inputs as script constants and
therefore establishes certificate-state reuse, not an all-witness-at-entry
layout. Bitcoin Core consensus and policy validation, executed-opcode and
validation-budget measurement, complete witness and transaction weight, and a
measured circuit scheduler with certificate fan-out/reordering remain open.

## OP-005 — SHAKE256 composable output

Avoid the 1,024-item raw-output failure. **Complete when:** a parameterized or
incremental squeeze passes strict stack checks and is differentially validated
against FIPS 202 for boundary message/output lengths.

## OP-006 — BN254 hinted-operation inventory

Catalog full costs and binding equations for every hint-producing field and
group operation. **Complete when:** each has adversarial-hint tests, witness
bytes, script bytes, stack peak, and reference comparison.

Progress: deterministic fragment bytes and combined main-plus-alt stack peaks
are recorded for addition across `Fq`, `Fr`, `Fq2`, `Fq6`, and `Fq12`, for
hinted multiplication and square across `Fq`, `Fq2`, `Fq6`, and `Fq12`, and
for `Fq` inversion. Witness bytes, adversarial-hint coverage, sparse and
Frobenius variants, retained-operand paths, and the group inventory remain.

## OP-007 — Pairing/Groth16 reproducible configuration

Define one stable four-pair verification instance. **Complete when:** script,
hints, vectors, deterministic generation, total metrics, and arkworks comparison
are checked without relying on an undocumented test fixture.

## OP-008 — Chunked verifier protocol cost

Map a full Groth16 verifier into strict challenge leaves. **Complete when:**
every chunk has authenticated input/output state, strict execution evidence,
transaction weight, and a complete challenge-graph security argument.

## OP-009 — One-time authentication security profiles

Turn parameters into concrete protocol guidance. **Complete when:** Lamport,
HORS, and Winternitz records include domain separation, key lifecycle,
multi-target bounds, message encoding, and end-to-end state transport costs.

Progress: `FastWinternitz` now fixes chain-start domain separation, typed
message/checksum encoding, a consuming in-process key API, numeric witness
bounds, mixed-radix checksum encoding, canonical bitwise witnesses, and
measured Wots32 time/size/stack profiles, including the explicit
script-size/witness-size and raw-chain-length tradeoffs. Durable crash-safe and
distributed one-time state, concrete multi-target bounds, raw ScriptNum
canonicality, and complete state-transport transaction costs remain open.

## OP-010 — External coverage review

Continuously compare this atlas with primary papers and active upstream Bitcoin
Script repositories. **Complete for a review cycle when:** sources are pinned,
new constructions are recorded even if unimplemented, superseded records are
linked, and the catalog-wide `as_of` date is advanced.

## OP-011 — Reproduce Binohash

Implement the specified legacy signature-grinding construction and validate it
against a pinned Bitcoin Core regtest. **Complete when:** extraction correctness,
collision/work parameters, full transaction costs, mutation boundaries, and
malformed/grinding failure cases are reproduced from deterministic fixtures.

## OP-012 — Audit BN254 residue-witness subfield constraints

Determine whether the local `c`, `c_inv`, and `wi` pairing path enforces every
condition required by “On Proving Pairings,” including relevant proper-subfield
constraints highlighted by GHSA-76mq-v757-53gr. **Complete when:** the required
equations are documented, adversarial witnesses are tested, and either the
checks are proven present or the verifier is fixed. Do not infer local
vulnerability from the adjacent advisory without this analysis.

## OP-013 — BLAKE3 circuit-superoptimization frontier

The checked short-input frontier is 59,529 bytes and 527 stack items for 32
bytes. The preceding digit-routing criterion is bounded: a
shortest-common-superstring DP reduced the XOR table, row-zero suffixes fused
the modulo table, table-lifetime search delayed shift/addition memory, and an
independent-nibble backend searched global and per-call rotation orders. Every
retained length from 0 through 32 passed differential and malformed-input
tests. Alternate radices, expanded witness schedules, eager routing,
little-endian state, raw-sum add-to-XOR fusion, final-round pair fusion, and
extra low-XOR planes are measured or bounded in the negative-results index.
Deep state routing still dominates, with 473 items of strict stack headroom in
the representative short configuration.

**Complete when:** a reproducible joint circuit search or proof-producing
superoptimizer covers a precisely stated space of digit lifetimes, G-stage
fusion, lookup layouts, and per-call schedules on the same checked
`fragment-with-memory` boundary; every retained candidate passes all short
lengths and malformed inputs; and it either beats 59,529 bytes below the
1,000-item peak or records a machine-checkable lower bound for that search
space.

## OP-014 — Total-domain ScriptNum right-shift frontier

Determine whether a one-item ScriptNum representation can beat the four-byte
u32 backend for logical right shifts after all representation costs are
included. **Complete when:** shifts `1..=31` are correct for every semantic
32-bit boundary class including `0x80000000`; accepted raw encodings and any
negative-zero special case are explicit; input/output conversion, shared-table
setup, script bytes, executed opcodes, and strict stack peaks are compared on
the same boundary; malformed encodings are rejected; and a complete tapscript
leaf is differentially validated against a pinned Bitcoin Core revision.

## OP-015 — Native secp256k1 field circuit frontier

Turn the native 20,503-byte ordinary multiplication, 20,450-byte factor-16
multiplication, and 14,541-byte square fragments into a complete field-circuit
cost model. **Complete when:** a scheduler records
operand introduction, certificate fan-out, all-witness-at-entry routing, table
lifetime, and output consumption for a deterministic multi-gate circuit;
factor-16 encode/decode boundaries and domain-compatible addition/squaring are
charged explicitly;
representative and maximum witness serialization, executed opcodes, validation
weight, complete tapleaf/transaction weight, and preserved-state headroom are
measured; and at least one complete leaf is differentially validated against a
pinned Bitcoin Core revision. The current ordinary three-multiply and
five-square batches peak at 993 and 998 items, so any claimed larger batch must demonstrate
an explicit strict layout rather than extrapolate byte amortization.

## OP-016 — Spend-time explicit BIP340 verification

Remove the fixed-instance generator trust boundary without falling back to
`OP_CHECKSIG`. **Complete when:** one tapleaf accepts a signature selected in
the unlocking witness, binds `r` and `s` to the BIP340 tagged-hash challenge,
verifies the complete double-scalar multiplication with hostile intermediate
state, stays within consensus stack/element/transaction limits, and is
differentially validated against a pinned Bitcoin Core revision. The current
8,292,228-byte affine prototype meets the hostile spend-time input and
double-scalar semantics under `research-unlimited` execution, but its 32,556-
item witness, 33,589-item peak, and transaction weight are consensus-
incompatible. The separate 58,596-byte construction stays below the stack
limit only by fixing the key, message, and signature before generation and
trusting public challenge/GLV/wNAF/Jacobian work. Neither meets the complete
deployment criterion.

## OP-017 — Point-lock security and deployment validation

Close the remaining gap between functional point-lock tests and protocol
security. **Complete when:** the three-check ECDSA lock is executed as a
complete bare and P2SH transaction against a pinned Bitcoin Core revision, its
related-scriptCode reduced-sighash collision assumption receives a concrete
single- and multi-instance analysis, and its high-S completeness fallback is
confirmed under legacy consensus; the best generic forgery attack against the
60-byte `G/2` ECDSA predicate is reproduced or tightly bounded, reconciling the
conservative roughly 80-bit estimate with the Binohash paper's approximately
97-bit smaller-R search; all three ECDSA leaves are validated against a pinned
Bitcoin Core revision under consensus and applicable relay policy; the
committed-ECDSA setup statement has a byte-exact circuit and proof transcript
for at least one pinned zkVM backend; and the Schnorr adaptor flow is tested
against an independently maintained implementation with explicit nonce,
parity, transcript, and extraction checks.

## OP-018 — Complete explicit Ed25519/EdDSA verification

Build a spend-time Ed25519 verifier on a documented base-field representation.
**Complete when:** canonical compressed-point decoding, curve membership,
the selected subgroup/small-order policy, scalar canonicality modulo the
Ed25519 group order, SHA-512 challenge construction, and the full EdDSA
verification equation are implemented with hostile witness tests; a scheduler
accounts for field-value certification, fan-out, multiplication/squaring,
table lifetime, and authenticated chunk boundaries; complete script, witness,
stack, opcode, validation-weight, and transaction metrics are recorded; and a
deterministic fixture is compared against an independent RFC 8032
implementation and a pinned Bitcoin Core execution environment where
applicable.

Progress: the current ordinary-domain `u5_balanced_table` multiplication uses a
51-digit biased centered radix-32 stack encoding, 663 operand-bound lookups,
one scalar quotient, and 50 carries. Its certified-input gate is 9,893 bytes
with a 245-byte/51-item incremental hint and a strict 523-item peak; the
11,180-byte raw wrapper consumes a representative 398-byte/153-item complete
data witness. The retained bigint9 factor-8 gate is 19,903 bytes with a
31-byte/29-item incremental hint and a 719-item peak, so it remains a distinct
circuit-domain/witness tradeoff rather than the size winner. Both results are
`locally-reproduced` and `unclassified`. Generated-Script boundary and
adversarial tests for the radix-32 backend remain ignored by default.

A fixed-base group layer is now also present. The G29 schedule validates a
canonical scalar from eight packed words, selects one of 29 position tables,
and verifies 28 signed/identity-safe affine transitions. Its byte-minimizing
entry contains 672 hostile trace-data items, 84 direct quotient-hint items
(three per transition), and eight scalar items: exactly 764 items, all
coexisting at entry. Honest quotients use signed 23-bit slots and at most three
ScriptNum payload bytes. A 61-item packed quotient alternative is the physical
minimum for the same 1,932 bits, but adds a 25,570-byte raw decoder and is
therefore not the byte-minimizing choice.

The generator now produces one actual fragment containing the scalar validator
and stream, authenticated bit tries, sign/identity routing, trace and quotient
consumption, and every real affine kernel. Policy-precompiling the signed
kernels' smaller semantic steps saves 78,498 bytes; the final multi-megabyte
composition is 3,881,402 policy-produced bytes, 118,598 below the four-million-
byte comparison line.
The integrated strict schedule has been executed with those control paths and
peak-equivalent arithmetic stubs; scalar zero, one, and `l-1` each reach at
most 993 combined stack items. The positive, negative, and identity kernels
were executed separately before that size-only transformation; the optimized
kernels and full 28-kernel arithmetic schedule were deliberately not run
because generated long-running tests are opt-in. This fixed-base result is
`locally-reproduced` and `unclassified`, not a complete leaf or transaction.
An inspected depth-zero one-input/one-output projection is 3,886,238 WU before
the missing terminal point consumer, leaving 113,762 WU below the block limit
before block-level overhead and exceeding default transaction policy by nearly
an order of magnitude.

For a custom, key-specialized BLAKE3 variant, the fixed transcript prefix
`D32 || A32` can be compiled into the chaining value. The remaining exact
compression of `R32 || M32` measures 65,208 raw bytes, 128 checked u4 data
items, exactly zero hint items, and an analytic local peak of at most 591. The
host chaining computation matches standard unkeyed BLAKE3, but the generated
Script has not been executed. A direct composition with G29 is 3,946,610 bytes
before routing or curve glue but exceeds the stack limit whichever component
runs first. Packing 64 transcript bytes into the spare high bits of 64 existing
q items repairs that narrower coexistence problem with zero additional entry
items: the inspected model projects roughly 3.957 MB at the same 764-item entry
and 993-item frontier. Its final metric run was skipped, and it still omits the
entire `[h]A` side. The best inspected joint `[s]B-[h]A` radix-16 schedule is
instead near 7.59 MB and begins with at least 1,701 trace/hint packet items.
These are scoped results for the current affine trace, not a universal
impossibility result.

A newer candidate maps the verification equation to Montgomery coordinates
and certifies a slope chain with two relations per transition.
Using a 128-bit custom BLAKE3 challenge gives 45 selected groups and 44
transitions. Each transition packet has two packed trace fields (16 circuit-
data items) and exactly **two quotient-hint items**, so all 704 trace-data
items plus all 88 quotient hints total 792 raw witness items at entry. The
schedule carries the scalar inside later q hints; predecoding it into eight
words while restoring q returns 800 items. A full item-accurate synthetic
router is locally reproduced with a 25,231-byte raw/unoptimized fragment and a
strict combined main-plus-alt-stack peak of 813 items. Its complete strict
probe exceeds the centralized policy's 32 KiB cutoff and uses no optimizer. A
correlation-free radix-32 interval model matches the
prototype's exact sparse coefficient representation: the square product uses
`[4x12,3x1]`, sparse u/a fields and continuity products use `[4x3,3x13]`, and
sparse b/v fields use the staggered nine-limb layout `[4,6x7,5]` at offsets
`0,4,10,16,22,28,34,40,46`. The symmetry-specialized square groups doubled
cross terms before folding. Its q lies in `[-3,404,320,3,631,275]`, its
maximum reverse carry is 63,966,197, and maximum modeled ScriptNum arithmetic
is 2,046,918,304, leaving 100,565,343 of headroom. Regular continuity q remains
in `[-3,686,931,3,686,931]`; its complete coefficient, reverse-carry, and
maximum-arithmetic bounds are 2,072,011,424, 66,330,611, and 2,122,579,552.
The latter leaves 24,904,095 below the four-byte limit even after both
sign-routed b inputs are widened to the union `[-16*S_w,16*S_w]`. The first
one-product continuity relation is narrower: with its selected b input widened
the same way, its coefficient is 1,590,195,040, q remains in
`[-1,843,466,1,843,466]` (signed 22-bit), reverse carry is 50,483,722, and
maximum arithmetic is 1,615,479,104. Starting b/v directly with eight
six-digit limbs and one three-digit limb is unsafe at 2,746,042,313 maximum
arithmetic; the staggered four-digit first limb moves the wide sparse terms
away from the largest low product coefficients.

Limbwise sign routing is algebraically valid but creates an important boundary
condition. Negating all grouped limbs reconstructs the exact integer negative
of the original centered representative and hence the correct field element
`-v` modulo `p`; the largest possible six-digit limb is only 554,189,328.
That literal negative is not necessarily the backend's canonical centered
representative of `p-v`. It can differ by `p`, so regrouping the canonical
residue can shift the required continuity quotient by one per affected term.
The implementation now exposes a signed-direct-limb hint/witness boundary that
uses exactly the limbs emitted by the authenticated table. Focused strict
negative first and chained fixtures both pass; each chosen fixture demonstrates
a continuity quotient one below the canonically regrouped helper's value.

Using both ScriptNum signs gives each signed-23-bit q carrier nine metadata
bits, while the first signed-22 continuity q carries ten. The 56 q hints
consumed by the first 28 response transitions therefore carry 505 transcript
bits. The concrete schedule extracts and clears the normally-zero padding bit
from eight early packed trace fields. All eight enter `R32 || M32` in its chunk
order, and the final response q-metadata bit is the forced-zero 513th bit,
without touching future challenge-side packets or adding entry items. Across
all 88 q hints the exact mixed-width channel is 793 bits. Twenty-nine final
challenge-side signed-23 q items provide 261 bits for the 253-bit scalar. The
entry stores response packets before challenge packets so these scalar
carriers are shallow. The q-restoring predecode/repack route is strictly
executed at the synthetic 792-item packet boundary by
`examples/ed25519_h16_scalar_carrier_router.rs`; its raw size is 25,231 bytes,
and a 2,032-byte zero-growth block transpose then creates
challenge-first/response-last execution order. The width-parametric compact
carrier decoder, one-chunk-per-transition pair combiner, and padding-bit codec
are strictly executed by `examples/ed25519_slope_carrier_codec.rs`. The algebra
and interval models are respectively
`examples/ed25519_montgomery_slope_chain_model.rs` and
`examples/ed25519_montgomery_slope_bounds.rs`; carrier fragments, the router,
and the bound model are `locally-reproduced` and `unclassified` at their stated
boundaries.

The historical generation-only linker serialized the matching 45 direct-limb
tables,
all 44 transition bodies, fixed-message BLAKE3 compression, scalar carrier
router and transpose, validator/stream, pair/padding decoders, canonical
transcript unpacking, a 128-byte consume-and-drop message binding, H16
recoding, all physical routing, and the endpoint clean-stack predicate. After
correcting the hash fragment's compilation policy, those components project a
**3,828,057-byte** leaf; the superseded pre-policy whole serialization was
3,826,949 bytes and the corrected whole has not been regenerated. Challenge
byte `b_i` is independently recoded as
`e_i=b_i-127` in `[-127,128]`, with
`h=sum(e_i*2^(8i))+0x7f7f...7f`; the fixed negative bias multiple is absorbed
by the response initializer. This removes the carry chain and shrinks the
challenge-top table from 257 to 129 leaves. Tables plus recoding save 12,575
bytes without changing the 45 tables, 44 transitions, entry items, or hints.
Its corrected component partition sums exactly to the additive projection. Short
strict linker probes reproduce
packet/table/q/prior-state ordering, signed selection, remaining-q decoding,
and fixed-message preservation/rejection. The fixed-message compressor folds
the eight constant `M32` words into table addresses: binder plus hash is 64,118
bytes versus 65,315 for the corrected republish-and-variable-message pair, and
the strict host-differential hash probe peaks at 864 rather than 928. Both need
zero hint items. The strict whole control execution
substitutes peak-equivalent bodies for the multi-megabyte arithmetic and hash
fragments and reaches 999 combined items; the real first/chained local peaks
used at the critical rows are separately reproduced. The superseded whole was
generated but not executed; the corrected whole was not regenerated. See
[`ed25519-blake3-montgomery-slope.md`](primitives/ed25519-blake3-montgomery-slope.md)
for the component boundaries and custom signature definition.

A parallel G29 q-free construction derives each signed-22/23-bit quotient from the
completed relation accumulator instead of accepting it as witness data. Its
entry is exactly 704 trace-data items plus eight scalar words: **712 coexisting
data items and zero auxiliary hints**. It removes the q router, metadata
channel, and packet transpose. Its corrected components project a policy-
compliant **3,896,335-byte** leaf. The sole pre-policy generation produced a
3,895,323-byte whole with 2,087,154 static
non-push opcodes; no corrected whole opcode count is claimed without
regeneration. The projection is 68,278 bytes larger than the hinted projection
because its 44 derived kernels cost 2,982,140 bytes and its later-certified
packed-R hash boundary costs 67,806 bytes. Strict synthetic routing peaks at 763, the packed-R hash
strict-peaks at 824 and matches host BLAKE3, and separately executed derived
kernels imply an analytical worst complete-schedule frontier of **912**. The
multi-megabyte leaf was not executed.

The current successor combines three further changes. First, it uses the
bounded-search G32 response partition—width eight everywhere except lower
positions 21, 25, and 29 at width seven—plus the existing sixteen independent
challenge bytes, for 47 transitions. Second, its final challenge packet carries
51 canonical radix-32 `Rtilde` digits instead of eight packed words; the hash
helper checks and copies those digits into BLAKE3 while preserving the original
field for the fused terminal relation. Third, each curve relation uses a
symmetry-specialized square, and quotient derivation shares Script-authored
power-of-two pools within two phases. The current first transition uses fifteen
powers for bits 16 through 30; later transitions use sixteen powers for bits
15 through 30. The pools add no witness data or hints and leave no residue
across the hash boundary.
The exact entry is **803 coexisting circuit-data items and zero auxiliary hint
items per transition and in total across all 47 transitions**. The analytical
combined main-plus-alt-stack maximum is **995**, including the
script-authored pools; focused routing and individual kernel/hash interfaces
are strict-executed separately. Generated long-running tests and whole-leaf
execution remain opt-in.

The current implementation replaces full-word expansion with partial
decoding into the consumer's exact representation: 46 grouped-u decodes and
47 lambda-digit decodes consume eight data items each, require zero auxiliary
hints per invocation and in total, and have strict local peaks of 62 and 93
items including sixteen temporary Script-authored powers. Its relation
reducers use a single Horner residue and fuse sparse coefficient passes.
[NR-036](negative-results/index.md) records the bounded fragment comparisons.
Acceptance for a further reduction is a smaller policy-produced complete leaf
with all 803 entry items and zero hints retained, a combined-stack bound below
1,000 including decoder/pool coexistence, and focused malformed-input checks
against the original exact relation. Whole-leaf execution and Bitcoin Core
validation remain separate unmet acceptance criteria.

The final policy-produced G32 serialization is **2,834,653 bytes** and contains
1,663,690 static non-push opcodes. Its disjoint component account is exact with
zero cross-component optimizer delta: 1,821,324 response bytes, 945,029
challenge bytes, 67,137 canonical-u5 fixed-message BLAKE3 bytes, 389 recoder
bytes, and 774 scalar-validator bytes. Because the whole leaf exceeds 32 KiB,
the compilation policy applies `CompileOptions::NONE`; the reported whole size
is unoptimized by upstream fixpoint passes. The deterministic production-shaped
host fixture serializes all 803 argument items to 3,863 bytes and commits them
with BLAKE3 digest
`896812f002f5c8b1a2816eed80ceb84e9822a9202ae226771a48091a6ef8c5d1`.
Its exact complete-witness, target, and minimum-block formulas are `S+3,902`,
`S+4,280`, and `S+5,048`; at the measured `S`, they are 2,838,555 bytes,
2,838,933 WU, and 2,839,701 WU, leaving 1,160,299 WU below four million. A
representation-aware conservative argument instead gives target/minimum-block
formulas `S+5,034` and `S+5,802`, leaving 1,159,545 WU.

A historical measured but non-selected lifecycle at `f7bb0c2` carries the
later 16-item Script-authored
power pool through canonical-u5 BLAKE3 and the recoder. It is technically
feasible, uses zero hints, and strict-peaks at 934 inside that boundary, but
saves only 25 bytes: 2,999,958 versus that revision's 2,999,983-byte split. It
also couples the hash and recoder to a nonempty alt stack. Production keeps the
explicit empty hash/final boundaries; [NR-035](negative-results/index.md)
records this operational tradeoff.

The historical hinted G29 transaction envelope is parameterized independently
of its glue. For any final leaf size `S` between 65,536 and `2^32-1`, a conservative
maximum-payload, depth-zero, one-input/one-P2TR-output fixture with these 792
entry arguments has an `S+4,706`-byte witness field and weighs `S+5,084` WU:
the witness has a three-byte count for 794 items, 704 trace values serialized
at their five-byte payload maximum, 88 q carriers at their four-byte maximum,
a five-byte leaf length, and a 33-byte control block. The exact hint count
remains two per transition and 88 total; all hints coexist with all 704
trace-data items at script entry. A minimum current-height witness-committing
coinbase plus the block header and two-transaction count costs another 768 WU.
Thus 3,994,148 bytes is the conservative leaf-size ceiling under that argument
upper bound and minimum block envelope; real miner coinbase data or extra
outputs lower it. At projected leaf size `S=3,828,057`, the transaction is
3,833,141 WU and the minimum block is 3,833,909 WU, leaving 166,091 WU. The deterministic
`examples/ed25519_montgomery_h16_envelope_model.rs` fixture reproduces these
CompactSize, serialized-size, and weight equations with the pinned
`rust-bitcoin` serializer. This serialization evidence is
`locally-reproduced`; deployment remains `unclassified`, and the transaction
is necessarily non-standard under the 400,000-WU default policy limit.
The deterministic honest fixture now fills all 792 argument slots and
serializes them to 3,958 bytes. For that fixture the exact target and
minimum-block formulas improve to `S+4,375` and `S+5,143` WU respectively;
at the projected linked size they leave 166,800 WU. The conservative formulas above
remain the content-independent planning bounds.

For the G29 q-free leaf, the deterministic 712-item argument witness is 3,561
bytes and the exact complete-witness/target/minimum-block formulas are
`S+3,600`, `S+3,978`, and `S+4,746`. At projected `S=3,896,335`, target and minimum block
are 3,900,313 and 3,901,081 WU, leaving 98,919 WU. The five-byte-payload
conservative target/minimum formulas are `S+4,692` and `S+5,460`; they give
3,901,027 and 3,901,795 WU, leaving 98,205 WU. All counts include exactly zero
hint items.

Canonical Edwards-point decoding, a subgroup/small-order policy for runtime
keys, standard SHA-512 challenge construction and reduction, and independent
RFC 8032 differential fixtures remain necessary for the original Ed25519
objective. The BLAKE3 slope construction instead defines a key-specialized
custom scheme with a torsion-shifted Montgomery-u commitment; it is not RFC
8032. The linked benchmark binds the same deterministic `M32` used by its host
signing fixture, but its disclosed fixture secret `a=987654321` makes the
exact leaf forgeable. The fixed `M32` is not a Bitcoin transaction digest and
provides no transaction authorization or replay protection. The custom scheme
also lacks a specified domain-separated nonce derivation; nonce reuse with
Ed25519 or another scheme under the same scalar would disclose the key. Its
pinned challenge takes digest bytes 0 through 15 as a little-endian integer,
and its response transports the 253-bit `C+s` value with three checked zero
high bits. Authorized transaction-message binding, nonce specification,
independent security review, complete transaction execution, and Bitcoin Core
validation remain open. The external-key generator and concrete honest
792-item hinted, 712-item G29 q-free, and 803-item G32 q-free witnesses exist at
host-generation boundaries. The G32 host probe audits all 47 transition pairs
and all 94 exact scalar relations without serializing q; the G29 q-free probe
does the same for its 44 pairs and 88 relations. None has been validated by
executing a complete leaf or by Bitcoin Core.

For the historical hinted baseline, one remaining byte experiment is to leave the BLAKE3 backend's 330 lookup-table
items below `prefix | digest` instead of moving the 337-item prefix during hash
cleanup. The challenge schedule appears to have enough stack room to carry
them and the endpoint could drop them, but this has not been generated or
executed. **Accept when:** an exact linker variant preserves all routing and
clean-stack semantics, stays below 1,000 combined items in a strict schedule,
matches the standard BLAKE3 digest in a focused execution, and reports a
policy-produced leaf smaller than the 3,828,057-byte projection with the same 792 entry items
and exactly 88 hints.
