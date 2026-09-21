# Open research problems

Each problem has a falsifiable completion criterion. Update comparisons and
negative results when closing one.

**Next priority (2026-09-10): OP-001, transaction-aware Taproot execution.**
The interpreter repairs and explicit context-free consensus/policy profiles
are adopted. Next, close the missing commitment and signature context:
**complete when** valid and mutated Taproot commitments, annexes and Schnorr
signatures produce supported local verdicts that agree with pinned Core,
including budgets initialized from the full serialized witness. Unsupported
cases must remain distinct from rejection. The independent Core harness is the
oracle; local fragment acceptance must not be promoted to complete-transaction
validity before those checks exist.

The [checked PRINCE experiment](prince-core-validation.md) adds another bounded
primitive: three exact funded computation leaves are `policy-validated`, and
17 invalid-input/ciphertext fixtures reject. All 40 local/Core profile
comparisons match. The local API still checks only the leaf; complete
transaction and commitment checks come from Core.

The [signature differential experiment](tapscript-signature-validation.md)
isolates 13 remaining disagreements at the resource-repaired interpreter pin,
including six panics. Its complete funded transactions cover CODESEPARATOR,
unknown-key empty signatures, invalid x-only keys and disabled multisig opcodes.
All 20 local/Core comparisons agree after adopting `702544c9`, with zero panics
and two identical reports. These focused repairs are prerequisites to the full
transaction API; fixing them does not itself implement commitment, annex or
full-witness budget checks. The context-free profiles retain their guard.

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
The new checked 6,426-byte zero-key leaf measures input validation and a
terminal predicate as well; it is a separate boundary and does not advance
the sub-5,000-byte fragment objective.

## OP-001 — Strict execution matrix

Add explicit legacy/P2WSH/tapscript strict and research-unlimited execution
modes. **Complete when:** every cataloged local configuration records its mode,
strict tests enforce relevant limits, and relaxed success is visibly labeled.

Initial progress (2026-09-10): the shared tapscript wrapper checked the initial
1,000-item limit, the 520-byte witness-element limit, and combined main/alt
depth after every instruction, including data pushes. Ten deterministic
[resource regression tests](../tests/execution_limits.rs) cover the boundaries
and all helper paths; the first six reproduced false acceptance before the
repair. `ExecuteInfo` records the stack-limit choice and labels count-disabled
execution `research-unlimited`. These are `locally-reproduced` resource checks,
with deployment `unclassified`, not a completed strict consensus matrix.
The [support README](../src/support/README.md) records upstream limitations.

Adoption follow-up: immutable interpreter integration
`4b7269a415f21be3fccee9730547f1426eb80326` contains resource checks, stack-index
bounds, and executed-only minimal-push validation (upstream PRs #18, #19, #20).
The Cargo patch covers both direct execution and `bitcoin-script-stack`;
duplicate wrapper checks are removed. Ten resource tests, 15 profile tests and
the three-slot isolated Winternitz malformed-index regression pass against
that dependency. Historical `ba96bc2` measurements retain their original pins.

The new `support::tapscript` API separates consensus numeric rules from policy
minimality and 80-byte witness-item limits, preserves mandatory `MINIMALIF`,
and implements the sequential `OP_SUCCESSx` pre-scan with correct resource
and parsing precedence. It disables experimental concatenation. Typed outcomes
distinguish executed scripts, pre-scan success, policy rejection, invalid syntax
and unsupported contexts; unsupported cases return no verdict. Existing
research helpers retain their defaults and explicit stack-limit distinction.
Local evidence is `locally-reproduced`, deployment `unclassified` by itself.

Remaining criteria include legacy/P2WSH modes, transaction/commitment and annex
validation, complete signature context/budget, full relay policy, malformed
input handling in older research helpers, and configuration-by-configuration
migration and revalidation. Signature operations, CODESEPARATOR, CLTV/CSV and
policy's upgradeable NOP handling are currently refused conservatively by the
context-free profiles, including when their opcodes appear in dead branches.
The current [44-fixture Core experiment](core-validation.md) reproduces every
consensus/policy expectation and rejection diagnostic, with 86 applicable
local/Core verdict comparisons. Its separate control-block mutation still
demonstrates why local leaf execution cannot establish commitment validity.

## OP-002 — Bitcoin Core differential harness

Validate complete leaves and transactions against a pinned Bitcoin Core
regtest. **Complete when:** deterministic fixtures compare local execution,
consensus acceptance, and `testmempoolaccept` policy results with a recorded Core
commit.

**Completed 2026-09-10 for the initial fixture scope.** The
[pinned Core harness](core-validation.md) compares 24 deterministic complete
Taproot spends against Bitcoin Core v30.3 commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`. It records local execution, independent
block acceptance, standard-policy acceptance, rejection diagnostics, full
witness sizes and transaction weights. All expectations pass. The isolated
HASH160/Preimage16 Winternitz leaf is `differentially-validated` and
`policy-validated` for the recorded message; other catalog configurations retain
their existing classes. Extending coverage to signatures, annexes,
legacy/P2WSH, and other primitives remains under OP-001 and their own deployment
criteria. [NR-045](negative-results/index.md#nr-045-core-differentials-expose-local-executor-boundaries)
records the historical local divergences. The adoption follow-up extends the
oracle to 44 fixtures with explicit local consensus/policy comparisons and
`OP_SUCCESSx`/minimality boundaries. Its separately recorded report preserves
the original 24-fixture baseline and its immutable interpreter provenance.

The PRINCE follow-up records 20 more complete spends, including canonical
nibble and exact-input-count enforcement under consensus. All expectations and
40 local profile comparisons pass, with two identical fresh-node reports.
Coverage of other keys, compositions and primitives remains an explicit
per-configuration obligation.

## OP-003 — Complete metric surface

Add executed opcodes, validation weight, complete witness size, and combined
stack peaks where currently null. **Complete when:** every active catalog record
has a representative configuration with a checked boundary or an explicit
reason the metric is instance-specific.

Progress (2026-09-10): the BLAKE3 table-lifecycle test now measures cleanup
independently, using its declared input layout. Its earlier subtraction of
optimized setup from an optimized unused setup/cleanup pair underflowed on
the unmodified `20a7fb2` baseline. Existing 353-byte setup and 166-byte cleanup
values are retained; no primitive snapshot was refreshed. See
[NR-044](negative-results/index.md#nr-044-optimized-lifecycle-lengths-do-not-isolate-cleanup-cost).

Validation-runtime follow-up: the first 2026-09-10 broad run with
`--skip fields::` was stopped after 22 minutes, so that run is not a full-suite
pass. The exhaustive u8 AND/OR/XOR tests formerly rebuilt table scripts for
all 65,536 pairs. The tests now compile each fixed operation once and supply
canonical ScriptNum witnesses, preserving every pair, carry/borrow result,
rotation amount, and host arithmetic comparison. Selected u4/u32 and RNS loops
receive the same treatment; touched random tests use fixed seeds. All 25
focused arithmetic tests pass in 19.36 seconds in the debug test profile on
macOS ARM64 (one diagnostic run, no timing-dispersion claim). Production
primitive generators and metric snapshots are unchanged. The ten resource
regressions, five active metric snapshots, knowledge validation, upstream-C
host PRINCE check, and corrected BLAKE3 lifecycle test also pass.

The subsequent default-pin broad run completed 408 unit tests with 21 existing
ignored tests and no observed failures. It was stopped after 2,310.48 seconds
with only the old BLAKE3 maximum-altstack test still running, before integration
tests. This run is incomplete. The
[compiler investigation](negative-results/compiler-validation-runtime.md)
found redundant unchanged-run searches, submitted as
[compiler PR #15](https://github.com/BitVM/rust-bitcoin-script/pull/15), and a
separate test-design flaw: constant BLAKE3 results plus unused-output cleanup
allow the optimizer to erase the source-level stack peak. The candidate
compiler reproduces all five active metrics and exact bytes for all 24 Core
fixture records, but remains an isolated experiment rather than the lab's
dependency pin.

The repaired BLAKE3 resource test subsequently passes all 34 configurations
under the unchanged compiler pin in 185.57 seconds, with all 56
[boundary measurements](../tests/data/blake3-resource-boundaries.json)
matching the candidate. Separate default-pin integration tests pass 18 checks
with three existing ignores; six documentation tests pass. Together, the
broad/targeted/integration/doc runs verify all 409 active non-field unit tests,
18 integration tests and six doc tests under the retained pins. The isolated
candidate also completes one uninterrupted non-field suite with those same
pass counts (135.316 seconds command wall time, diagnostic concurrent sample).
The original default-pin broad run remains explicitly incomplete.
**Validation-runtime follow-up completed 2026-09-10.** With repaired interpreter
`4b7269a4` and unchanged compiler `124b561e`, one full
`cargo test --locked -- --skip fields::` run passes 448 tests, with 24 existing
ignores and 143 field tests filtered. It uses
`CARGO_PROFILE_TEST_OPT_LEVEL=1 CARGO_TARGET_DIR=target/nonfield-opt1` to optimize
the host test binaries; debug assertions and overflow checks retain their
defaults, and Script compilation policy is unchanged. Wall time is 175.76
seconds in one reused-build run on Apple M3 Max/macOS ARM64, a diagnostic sample
without dispersion. All five active metric baselines pass unchanged. An earlier
attempt finished the library but encountered a not-yet-written Core report link
in knowledge validation; the final complete run follows publication of that
artifact and passes every integration and documentation test. The broader
OP-003 metric-surface criterion remains open.

Checked-PRINCE follow-up: three new active snapshot rows measure complete leaf,
data witness, full Taproot witness and combined stack peaks separately. Each
has exactly 16 entry data items, zero hints and 18 complete witness items.
Core verifies the full transaction weights. Executed non-push counts remain
null because input validation has branches; static counts are recorded
separately. Existing fragment baselines and their historical pins are retained.
With the provenance and checked-leaf additions, the full non-field suite passes
460 tests (24 existing ignores, 143 field tests filtered), including all six
active metric tests. Three fixture example tests and 30 Python tests pass
separately. The CI workflow now enforces these checks and all three Core
harnesses while retaining the field-test filter.

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

Progress: `shake256_prefix` now parameterizes the output length. Prefixes of
1, 32, 135, 136, 137, and 256 bytes match the independent reference, and the
32-byte prefix peaks at 813 items under the strict local executor. The
representative fragment is still 2,000,127 bytes, and Bitcoin Core/policy
validation plus an incremental consumer remain open.

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

Compatible follow-up improvements add an exact verifier that carries the
residual digit and a staged Horner checksum. Exhaustive chain-digit tests
retain strict range and node-length checks. The relevant cost objective is
script plus serialized witness bytes for the same output contract, since a
smaller locking fragment can require a larger witness. An explicit clamped
lookup profile saves 134 script bytes by adopting the legacy upper-saturation
relation; strict raw-digit rejection remains separate. These improvements do
not resolve the remaining protocol criteria.

Hash choice is now executable for HASH160, SHA-256, and SHA-256 chains with
HASH160 endpoint commitments, including separate
derivation domains, all verifier profiles, independent host vectors, and
compiled cost measurements that account for SHA256-pair fusion. Still open:
quantify concrete forgery bounds for each choice at fixed chain count and
reuse policy. **Acceptance criterion:** a reviewed multi-target analysis of
this unkeyed construction for all three choices, paired with complete-transaction
costs for the same protocol and security target; hash-width bounds alone do
not satisfy it. The default `Preimage16` mode now shortens initial secrets,
while retaining native full-width hash outputs and the selected commitment
width. Include this
mode and the explicit `FullWidth` mode in that analysis: quantify the effect
of the 128-bit start-search space, chain counts, and multi-target attacks,
then compare complete transaction costs under the same stated forgery target.
A 128-bit start is not itself evidence of 128-bit collision resistance or
128-bit end-to-end forgery security.

The SHA-256/HASH160 hybrid now separates 32-byte internal nodes from 20-byte
public commitments. Its bitwise terminal is 3,812 script bytes; a strided
quotient/bit terminal uses 3,961 script bytes but reduces the Preimage16
zero-message fragment-plus-data total to 5,318 bytes. The latter uses 201
coexisting entry data items, zero auxiliary hints, and a 209-item combined
peak, versus 333/0/333 for bitwise. These are `locally-reproduced`,
`research-unlimited` metric results, with separate strict-stack tests. They
do not settle complete-transaction costs or the security criterion above.
Include the hybrid's 160-bit commitment width, approximately 80-bit generic
collision bound, maximum-digit raw-width relaxation, and strided quotient
clamping in the reviewed security model. **Cost acceptance criterion:**
compare all retained profiles over a specified message/checksum distribution
and the same complete protocol transaction, with strict consensus execution;
report both expected and worst-case total weight at the stated forgery target.

The earlier `ConstantSumWinternitz20` implementation losslessly encodes
all unchanged 20-byte inputs into 41 mixed-radix coordinates with sum 321,
eliminating checksum chains. HASH160/Preimage16 measures 2,680 script bytes
and an attained 944-byte maximum signer witness, totaling 3,624 bytes; exact
host counting gives mean total approximately 3,611.841783370768 over all
`2^160` messages, versus the baseline's exactly counted mean of approximately
3,795.262466089252. Its 82 entry data items, zero hints, and 93-item combined
peak are `locally-reproduced`, `research-unlimited` measurements. Independent
Python vectors and exact integer moments do not establish consensus validity
or a cryptographic reduction.

Constant-sum WOTS+ is covered by source `constant-sum-wots-2023`; the additional
Script-specific omission of individual upper-digit guards is a local
inference. Overflow selectors may read foreign stack values. Security relies
on the exact whole-vector sum forcing a decrease in some in-range coordinate
relative to the canonical signer vector, under honestly generated keys and
the chain inversion/collision assumptions. The bounded method adds radix
checks but still accepts valid fixed-sum codewords outside the host's
rank-below-`2^160` image. Neither method recovers or binds original bytes
onchain, and both retain the size-profile raw-width relation.

**Additional acceptance criteria:** independently review a reduction for the
overflow-tolerant whole-vector relation, including foreign-table reads,
mixed radices, raw ScriptNum encodings, and both numeric and strided witnesses;
validate boundary indices and complete leaves against pinned Bitcoin Core;
then compare complete transactions under the same forgery target. The former
`ba96bc2` executor panic at the exact `OP_PICK` bound is repaired by `4b7269a4`
and the exact fixture agrees with Core rejection. Strict table-escape tests
still do not validate all indices or the constant-sum complete protocol.
Any protocol claiming canonical 20-byte binding must additionally implement
and cost-check a rank/byte consumer, or explicitly require only the larger
terminal relation. See the [constant-sum primitive](primitives/winternitz-constant-sum20.md)
and [NR-041](negative-results/index.md#nr-041-20-byte-winternitz-search-and-overflow-relation-boundaries).

The newer [constant-composition implementation](primitives/winternitz-constant-composition20.md)
preserves arbitrary 20-byte inputs using 49 keys and radix-25 multiplicities
`[1 × 15, 2 × 7, 3 × 2, 14]`. Fourteen maximum-digit keys are implicit,
leaving 35 openings and 35 selectors. HASH160/Preimage16 reaches
1,598 + 802 = 2,400 maximum script-plus-signer-witness bytes when the entire
main stack is isolated by an explicit 70-item depth guard. Its combined peak
is 119; the composable 2,498-byte alternative peaks at 120. Both have zero
auxiliary hints. These `locally-reproduced`, `research-unlimited` results
supersede the earlier 3,624-byte combined frontier for terminal verification.

**Further acceptance criteria:** validate the shrinking-pool invariant and
all selector boundaries against pinned Core, extending the exact upper-bound
fixture already repaired locally and checked against Core; review the
fixed-multiset one-time argument with cross-target chains, short starts, and
same-message witness aliases; and reproduce a BitVM3 consumer that binds the
reversible assignment and handles unused ranks without assuming an onchain
byte decoder. A claimed optimum must cover constructions beyond the bounded
composition/routing search. See [NR-042](negative-results/index.md#nr-042-constant-composition-search-and-endpoint-sharing-limits).

## OP-010 — External coverage review

Continuously compare this atlas with primary papers and active upstream Bitcoin
Script repositories. **Complete for a review cycle when:** sources are pinned,
new constructions are recorded even if unimplemented, superseded records are
linked, and the catalog-wide `as_of` date is advanced.

## OP-011 — Reproduce Binohash

The deterministic core is now locally reproduced: selected serialized
signature pushes are removed at opcode boundaries before rust-bitcoin's legacy
sighash, including the out-of-range `SIGHASH_SINGLE` constant. The full
protocol remains open because grinding, valid ECDSA signatures, transaction
mutation boundaries, Script extraction, and pinned Core regtest behavior are
not yet reproduced.

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
60-byte `G/2` ECDSA predicate is reproduced or tightly bounded under adaptive
native digests and malicious setup, distinguishing total-length search from
the Binohash paper's approximately 97-bit smaller-R search (the earlier
roughly 80-bit protocol estimate is withdrawn); all four ECDSA leaves are validated against a pinned
Bitcoin Core revision under consensus and applicable relay policy; the
committed-ECDSA setup statement has a byte-exact circuit and proof transcript
for at least one pinned zkVM backend; and the Schnorr adaptor flow is tested
against an independently maintained implementation with explicit nonce,
parity, transcript, and extraction checks.

The experimental 76-byte two-check variant adds two explicit acceptance
criteria: validate complete bare and P2SH spends, including its high-S
consensus boundary, against pinned Core and compare extraction on those
actual transactions, while testing the valid supplied-digest extractor error
separately; and supply an independently reviewed reduction or a concrete counterexample
for its actual-native-transcript assumption under arbitrary target selection
and retained setup state. A proof limited to adversaries knowing `t` must be
labeled as such and does not close the point-only case. Any claimed work
factor must include adaptive hash/curve strategies and multi-instance setup,
rather than presenting the approximately `2^128` independent-list estimate
as a lower bound. The synthetic supplied-digest counterexample in
[NR-058](negative-results/two-check-point-lock-extraction.md) is already
reproduced; it does not meet the native-transaction counterexample criterion.

Progress: [Core 30.3 validation](../research/pointlocks-2026-09-17/CORE.md)
reproduces all 18 expected two-/three-check outcomes, including exact unpadded
bare/P2SH execution, high-S consensus acceptance, undefined sighash flags, and
four negative mutations per predicate. The representative low-S two-check
P2SH transaction is policy-validated; other positives are consensus-only.
This closes those recorded execution boundaries but leaves the cryptographic
assumptions, multi-instance analysis, and other construction integrations open.

The [HASH160-committed two-check extension](../src/signatures/pointlocks/committed_two_check/README.md)
has locally reproduced one-lock and five-lock execution and sizing. Its
additional acceptance criteria are complete funded P2SH Core validation and
an independently reviewed bound or concrete non-extractable native spend
satisfying both checks and the self-referential HASH160 commitment, including
adversarial setup and multi-lock configurations. BitVM3 integration additionally
requires an explicit selectable digit construction and its binding rules;
acceptance requires demonstrating two alternative values per bit position
under the same funded script and publishing/recovering a 256-byte message.
The fixed-point AND batches do not satisfy that criterion. The
[small-set choice experiment](../research/pointlocks-2026-09-17/one-of-n.md)
now reproduces every branch for up to five embedded-key or seven key-hash
choices, but no succinct 1-of-2,048 construction or complete publication
transaction has been demonstrated. The
[subset experiment](../research/pointlocks-2026-09-17/hors-subsets.md) additionally
reproduces every distinct 2-of-6 selection; witness reordering reduces the
shared-table CHECKSIG predicate from 514 to 512 bytes. The
[multisig Core report](../research/pointlocks-2026-09-17/multisig_core_check.json)
validates recorded funded subset spends and a counterexample to independently
matching full target/companion lists. Complete reversible proof publication and
the original ordinary-digest security argument remain open.
A generic hash
collision or a freely supplied digest alone does not meet that criterion.

The [sum-key construction](../src/signatures/pointlocks/sum_key/README.md)
avoids that particular ordinary-digest gap by locking `T=P+Q` and extracting
`t=-2z/r` for every accepted common digest. Common-G setup, standalone locks,
selected multisig pools, and destructive HASH160 key-table pools have local
reproductions and pinned Core transaction fixtures. This is a separate
construction, not a proof of the older target-key extraction assumption.
Remaining integration criterion: connect its fresh, independently generated
label points to the actual BitVM3 challenge protocol and demonstrate that
every accepted publication has a recoverable proof or the specified failure
consequence. In particular, a variable-subset encoding must prevent third-party removal
of optional revelations while retaining the transaction authorization. A
decoder that merely rejects the resulting wrong global count is insufficient;
independent P2SH scripts enforce only their local ranges. Review multi-instance hiding and the explicit HASH160
collision-binding boundary for malicious setup. Exact accounting and a
correctly encoded example alone do not close these protocol obligations.

The [complete fixed-cardinality publication](../research/pointlocks-2026-09-17/publication_core_check.json)
now passes default Core policy and block validation and independently recovers
the original 256 bytes: 183 P2SH pools, 729 revelations, and 185,146 vB across
creation and two assertions. The
[conditional CSV extension](../research/pointlocks-2026-09-17/sum_csv_core_check.json)
rejects optional-revelation removal at a fixed input sequence in 519 bytes,
but requires an outer authorization mechanism whose presence is unavoidable
and which commits all sequences. Its local Core fixtures and 174,441-vB
publication sizing do not establish that missing protocol binding.

The [complete bare-legacy publication](../research/pointlocks-2026-09-17/bare-publication.md)
now validates 79 seven-of-48 pools at 161,382 vB actual / 161,560 vB canonical
maximum, with 553 independently recovered scalars. Native accepted
surplus-codeword and partial-one-pool controls confirm that total global
decoding and participation remain open. Acceptance requires a total map for
every admitted complete transcript and either enforced participation or a
specified safe partial-publication outcome. Default relay rejects these bare
outputs; the complete setup-time benchmark is still absent.

The [HORS lookup follow-up](../research/pointlocks-2026-09-17/hors-lookup-comparison.md)
reduces the maximum serialization estimate to 153,125 vB with 58 ten-of-57
pools. The remaining validation criterion is independently generated pools,
complete native funding/spending with 580 extracted scalars, 256-byte recovery,
and an end-to-end setup benchmark. Local pool tests and repeated-fixture
serialization do not satisfy that criterion or the sub-100k goal.

The newer [table-first selector](../research/pointlocks-2026-09-17/clamped-lookup.md)
passes 78 native pool controls and lowers the mixed maximum estimate to
151,176 vB. The corresponding full-publication criterion is now 48 independent
pools (ten 12-of-67 and 38 12-of-68), 576 scalar extractions, a 256-byte roundtrip,
accepted-alias decoding and an end-to-end setup benchmark. Native constituent
pool validation does not establish this full-publication criterion.

The [sub-100k investigation](../research/pointlocks-2026-09-17/windowed-publication.md)
recorded a conditional 39,396-vB P2WSH windowed-small-R profile for arbitrary
256-byte data, now **rejected for impractical setup** under
[NR-061](negative-results/windowed-pointlock-setup-cost.md). The active objective
requires practical setup; the former `2^64` research ceiling alone is not
sufficient. Even apart from cost, that family requires an independently reviewed adaptive,
multi-target bound for non-extracting signatures at the 53-byte ceiling,
including arbitrary setup and all consensus-permitted sighash modes; a bound
for the correlated hidden-offset labels in the actual garbled protocol; and
production-parameter native transaction evidence after the specified search.
Reduced-work Core fixtures do not establish those cryptographic conditions.
The complete 59-byte-cap native fixture now passes Core policy and block
validation at 40,656 vB and independently recovers all 840 selected scalars
and the original 256 bytes. The tighter 53-byte production search remains
unperformed.
The expected `2^63.138` SHA256-compression estimate must remain distinct from
a hard `2^64` budget and its modeled failure probability. The helper/input-set
and challenge/refund integration obligations still apply.

The [repeated short-signature probe](../research/pointlocks-2026-09-17/repeated-cap60-sizing.md)
also fails the target: its best sampled three-check layout is 130,182 vB with
placeholder 60-byte signatures, and independent sighash choices invalidate the
assumed shared-digest argument (NR-062). A replacement must establish extraction
for all accepted flags and serialize a full arbitrary-256-byte publication below
100,000 vB with practical setup. Fixed-width representation estimates alone do
not meet that criterion.

The [native distinct-signature follow-up](../research/pointlocks-2026-09-17/distinct-short-signatures.md)
rules out amplifying a legacy constant-digest check merely by requiring
different signature bytes. A maliciously selected committed key admits16
exact60 encodings sharing one r and digest, without its scalar being used to
construct them; extraction is equivalent to the lifted nonce point's DLP.
Core validates the existing max60 predicate and pairwise-distinct batches up
to eight. This closes a concrete malicious-setup counterexample boundary for
that legacy branch, not the extraction question for anchored P2WSH. A future
repair must distinguish algebraically independent conditions from byte aliases.

Separately, the [conditional compressed-proof experiment](../research/pointlocks-2026-09-17/conditional-proof-compression.md)
has a policy-validated 92,706-vB synthetic 128-byte publication with the sum-key
primitive. Closing its application boundary requires confirming the original
256-byte proof format permits that lossless compression and validating the
adapted verifier; this does not close the arbitrary-256-byte target.

The [anchored CODESEPARATOR candidate](../research/pointlocks-2026-09-17/anchored-codesep.md)
now has a complete honest256-byte fixture at96,176 vB, accepted by Core30.3
policy and mined on isolated regtest. Independent extraction recovers460
selected scalars. Point-lock generation plus public verification measures
66.23 ms median with15 workers on an Apple M5 Pro (first sample127.57 ms),
excluding VSS and garbling. This is honest-execution evidence only. Closing
the objective additionally requires extraction for unknown distinct nonces
under all accepted sighashes and malicious/adaptive setup; a complete retry
algorithm; compatible publicly checked garbled-label translation with its
complete setup cost; and binding the mandatory input set and
challenge graph. The documented alternative-nonce search cost model is not
a hardness bound. The one-point Core differential also establishes that the
pinned local interpreter includes the executed CODESEPARATOR incorrectly
in SegWit-v0 scriptCode; those native results must use Core as authority.

The [affine-nonce extraction extension](../research/pointlocks-2026-09-17/nonce-relation-extraction.md)
now handles nondegenerate known affine relations, including signed GLV nonces
with distinct r values, in both anchored and direct extractors. A transparent
unknown-log construction reproduces the zero-determinant refusal boundary.
This narrows the unresolved transcript set without proving that every accepted
publication falls in an extractable case. Closing extraction still requires
covering unrelated nonces and excluding or handling all admissible degenerate
cases under actual native hashing and malicious setup.

The [cross-key nonce graph](../research/pointlocks-2026-09-17/cross-key-nonce-extraction.md)
now extracts every component whose verified scalar equations have full rank.
Tests cover cases missed by each per-key extractor, and an offline replay
recovers all 475 labels in the 98,323-vB fixture. A synthetic unknown-log
three-key/six-context graph still has nullity one despite ten cycles. The
acceptance criterion remains all accepted native transcripts: unresolved
components must either admit another efficient extractor or be excluded at
the explicitly stated security level under malicious setup and all permitted
sighashes. Counting shared contexts or graph cycles does not meet that gate.

For public garbling checks, the [scalar AND experiment](../research/pointlocks-2026-09-17/public-algebraic-gate.md)
shows that correct public point equations can still disclose an alternative
message's complete input labels. This happens even with six distinct
commitments, without obtaining an incorrect output label. A replacement
translator must therefore establish the required input-label restriction
after every permitted opening as well as public correctness; a guarantee
only about the final output is insufficient. See NR-069.

The [vector-label gate](../research/pointlocks-2026-09-17/vector-label-gates.md)
now supplies a public point-only check with a one-opening discrete-log
argument for a single gate. Two scalars per input label avoid the earlier
alternative-input recovery, but require four scalar openings per gate.
The single-scalar linear interface cannot meet both input-label restriction
and output authenticity (NR-072). Closing this branch requires a native
delivery or nonlinear compression that preserves the public check and label
restriction within the full 100,000-vB budget. A packing point equation alone
does not certify the digit ranges, and no full-verifier composition or setup
benchmark is supplied by the local gate.

The [shared-coordinate follow-up](../research/pointlocks-2026-09-17/shared-vector-gates.md)
reduces a binary gate to three scalar openings, but its direct independent
2,048-bit legacy layer still has a 181,248-vB signature-push floor. The new
NR-073 theorem also covers correlated scalar forms: all t-subsets preserving
candidate privacy cannot linearly deliver exactly one of two fixed hidden
labels when N>=t+2. At 5-of-54, even one protected linear secret is recoverable
from at most 5/54 of the choices. Closing this route therefore needs a bound
nonlinear decoder, a different authenticated selection family or another
native disclosure interface, with the original full-size/setup requirements.

The [ratio-label probe](../research/pointlocks-2026-09-17/ratio-labels.md)
tests one such proposed nonlinear step. Labels a/b with fixed public affine
point endpoints still require both scalar forms in the disclosed span, unless
their value is already a publicly checkable constant (NR-074). A falsifiable
next step is to give either a native relative-log opening, or additional
publicly checked nonlinear metadata, and show how it delivers a fixed hidden
verifier label while preserving alternative-label exclusion. Count its full
setup generation and public verification; an honest ratio example alone does
not meet this criterion.

The [DH quartet follow-up](../research/pointlocks-2026-09-17/dh-quartet-labels.md)
does deliver two secret point-valued labels per scalar opening, with a
correlated profile that publicly rejects exact label collisions. Closing this
branch requires a composable verifier that accepts these implicit DH labels
and publicly binds its entries to them without revealing alternative labels.
It must also measure the full transaction and setup boundaries. The
existing point-only input checker does not verify
garbling ciphertexts or certify secret entropy. An independent-coordinate
quadratic construction cannot simply replace the 5-of-54 decoder: its total
two-label interface stops at three missing scalars (NR-075).

The [fixed-digest nonce wrapper](../research/pointlocks-2026-09-17/fixed-digest-nonce.md)
closes the small native-opening requirement for the correlated quartet:
23 positive and eight negative cases reproduce in Core, with independent
hash/extraction checks. Its explicit four-key table repeated 1,024 times
already consumes 139,264 legacy vB before signatures or transaction costs.
The next falsifiable target is a different table/label representation with
full authenticated transactions below 100,000 vB and publicly checked verifier
binding, followed by a whole-instance generation and public-check benchmark.
The fixed-digest filter's reduced-sighash collision assumption and P2SH script
commitment must be included in the final construction's stated assumptions.

The [correlated quadratic bound](../research/pointlocks-2026-09-17/correlated-quadratic-labels.md)
now covers linear correlations that preserve every unselected candidate
against all t-subsets. Two fixed hidden quadratic point labels still require
N-t<=3. A proposed high-rate replacement must therefore exhibit additional
checked nonlinear metadata, a different native choice family, or a genuinely
different reconstruction interface; an honest correlated example alone is
insufficient. Under the stated leading-form premise, 5-of-54 needs degree
sum at least 50, without any claim that such higher-degree labels suffice.
Closing this branch still requires full verifier binding and the original
complete-transaction/setup criteria.

The [dual-anchor/sum-key shortcut](../research/pointlocks-2026-09-17/dual-anchor-sum-collapse.md)
now has a Core-validated counterexample (NR-068). Its common-digest long
opening is publicly computable and extracts only a public key sum. A viable
dynamic-key repair must demonstrate that every extracted scalar reconstructs
the intended precommitted target, admit practical honest openings, and reject
this public simulation under consensus rather than relying on high-S policy.

The [distinct-target anchor follow-up](../research/pointlocks-2026-09-17/two-target-anchors.md)
does supply an exact extraction equation for two prebound label choices.
Its native digests prescribe the opening nonce's x-coordinate, leaving
efficient honest opening unresolved. Closing this branch requires actual
post-funding transaction hashes and a practical opening algorithm, not the
synthetic digests used in its 31 curve fixtures. Setup and opening timing,
label privacy and complete publication costs must all be counted (NR-071).

The [direct-key follow-up](../research/pointlocks-2026-09-17/direct-context.md)
fits six native contexts into a Core-validated 98,706-vB honest publication,
with point-lock-only generation/checking at 46.59 ms median (first 130.23 ms).
Its removal of the anchor permits staged ACP|NONE, ACP|SINGLE, SINGLE and ALL
searches. Closing extraction requires accounting for that field-dependency
structure, not multiplying six independent rare-event probabilities. See
[NR-065](negative-results/direct-context-staged-grinding.md).

The [subset-to-label experiment](../research/pointlocks-2026-09-17/subset-translation.md)
now translates the existing native report's 460 scalars to 2,070 binary rank
labels using actual retained tables. Generation plus opened-table audit takes
1.590 s median for all 115 pools, excluding VSS/garbled copies. An opened audit
needs every secret and is not the required public setup check. Closing this
part requires a construction that rejects maliciously encrypted label rows at
setup, or otherwise proves every accepted publication supplies usable labels,
with all garbling-copy costs counted. The concrete counterexamples are in
[NR-064](negative-results/subset-translation-binding.md).

The [threshold-complement bridge](../research/pointlocks-2026-09-17/complement-translation.md)
replaces the combinatorial subset table with 281,750 encrypted shares and
actual per-pool garbled rank decoders. Generation and an all-secrets audit take
72.64 ms median for all 115 pools. Missing diagonal shares prevent the selected
zero-labels from being interpolated. Its malicious-ciphertext test still
preserves public points and label hashes while blocking a valid future opening.
An affine-mask public-check repair exposes all eight scalars in a full-rank
8-candidate counterexample. Closing this part requires a public binding method
that preserves hidden alternative labels, costs for all needed garbling copies,
and a connection to the full garbled verifier. An opened audit that
reveals shared point scalars cannot serve as a safe cut-and-choose check.

The [total garbled message decoder](../research/pointlocks-2026-09-17/total-message-decoder.md)
now composes those rank labels into 2,048 message labels under an explicit
modulo-2^2048 rule. This covers all complete valid codewords and all possible
messages, including overflow aliases. Generation takes 341.82 ms median and
an all-secrets audit 348.66 ms; the combined median is 701.05 ms. The decoder
implementation and surplus-codeword rule are locally reproduced. Closing the
goal still requires public malicious-setup binding, all-consensus extraction,
the full verifier/copy setup and enforcement of mandatory pool participation;
an offchain validity output does not enforce that transaction requirement.

The follow-up [NR-063](negative-results/anchored-rounds-and-four-roots.md)
verifies all256 raw ECDSA hash types and uncompressed/hybrid keys under Core
consensus. General extraction must cover those policy-rejected cases too.
Adding rounds in the current layout costs111,372 vB at d=6 in the bounded
scan; its explicit-table representation alone exceeds100,000 vB at d>=11.
The alternative four-recovery-key theorem gives exact extraction, but cheap
constant-digest setup reduces hiding to an interval-DLP search near2^64.17
group operations. A successful repair must avoid these specific limits;
they do not establish a general impossibility theorem.

The [typed-selector layout](../research/pointlocks-2026-09-17/typed-selector-layout.md)
now improves five-context serialization to 94,120 vB and six contexts to 105,039
vB. Small Core fixtures establish selection under the required public
non-DER table check, not full publication soundness. Closing this route still
requires actual full-size signatures/transactions, complete setup measurement,
unknown-nonce extraction and publicly bound garbled labels; selector savings
alone do not discharge those requirements.

The [shared-anchor-context optimization](../research/pointlocks-2026-09-17/shared-anchor-context.md)
reduces the five/six-context estimates further to 94,005/103,345 vB; six-context
small fixtures pass native Core checks. The extractor now includes relations
to the anchor itself, with a scoped nondegeneracy argument for shared nonzero
digests and signed GLV nonces. Completion still requires all accepted nonce
families and flags, actual full-size transactions, publicly bound labels, and
the complete setup benchmark. The numerical goal is not achieved by counting
the six-context spending transaction alone.

The [round-major variant](../research/pointlocks-2026-09-17/round-major-contexts.md)
now includes creation and reaches 98,334 vB for six contexts in its sizing
fixture. Core validates the complete 5-of-54 pool at 201 opcodes, as well as
small selector controls. The [fully signed95-pool follow-up](../research/pointlocks-2026-09-17/round-major-publication.md)
now passes Core at98,323 vB with475 recovered scalars and a full message
roundtrip. Point-lock-only generation/checking takes89.63 ms median with15
workers. General extraction, cross-label effects of shared contexts,
public garbling binding and full setup timing
remain acceptance gates. Six contexts do not establish a security level
merely by fitting the byte budget or succeeding with known nonces.

The [95-pool total decoder](../research/pointlocks-2026-09-17/round-major-message-decoder.md)
now connects all 475 native scalar openings to 2,048 message labels and the
original 256 bytes. Its modulo rule covers all complete valid codewords,
including aliases. Fresh translation/decoder generation takes 364.16 ms
median; generation plus an audit requiring every secret takes 733.29 ms.
This closes the decoder adaptation gate. Public setup verification is absent;
complete-protocol label privacy, mandatory participation or safe abort, general
extraction and full verifier/setup measurement remain required.

The [native participation follow-up](../research/pointlocks-2026-09-17/pool-participation.md)
confirms that the same funded instance permits four newly signed one-pool
spends, leaving 94 pools unspent. Closing this gate requires a complete
transaction/challenge graph in which every successful publication supplies
all required labels, or partial spending provably permits only a safe abort.
The repair must reject or safely contain these retained-creator cases, count
all added transactions and outputs, and still satisfy the byte/setup limits.
Reusing stale signatures fails, but that is not the relevant model (NR-070).

The [scalar-linear complement obstruction](../research/pointlocks-2026-09-17/complement-linear-obstruction.md)
now excludes a direct linear repair for n>=t+2 under the stated scalar privacy
and complement-reconstruction requirements. A future bridge must escape that
model while supplying the missing public setup binding; merely lowering the
rank of the affine-mask matrix does not suffice. See [NR-066](negative-results/linear-complement-labels.md).

The [direct binary-label rank bound](../research/pointlocks-2026-09-17/binary-linear-label-rank.md)
additionally rules out reducing the number of scalar-linear openings merely
by correlating the final binary label masks: for the complete authenticated
k-bit interface, one-message privacy forces rank k for every selection.
At k=2,048, a guarded legacy signature per opening already exceeds the byte
goal. A successful repair must escape that direct-linear interface while
preserving public setup binding and one-opening privacy; the existing nonlinear
message decoder is not excluded by this result.

The [fixed four-root orbit candidate](../research/pointlocks-2026-09-17/four-root-orbit.md)
binds a full canonical scalar at the legacy constant, avoiding the old
inverse-r label's interval weakness. Its explicit four-key tables still have
an optimistic131,601-vB payload-only floor. Making this route goal-compliant
requires a different representation or cheap native-witness setup, compatible
public garbling checks, and all usual native/benchmark evidence. Its random-
oracle nonconstant-digest bound is not an unconditional SHA256 theorem.
The [fixed-orbit sharing bound](../research/pointlocks-2026-09-17/orbit-key-sharing.md)
extends this obstacle to ideal reuse: four checks with 40-byte openings cost
at least 116,700 vB in the stated explicit-subset model. Two overlapping
openings expose the global base ratio and propagate through their sharing
component. An escape must demonstrate both a smaller complete representation
and one-opening privacy for its actual permitted selection family, rather than
counting shared keys while ignoring their scalar relations.
The [graph/privacy refinement](../research/pointlocks-2026-09-17/orbit-private-sharing-bound.md)
also closes the two-key numerical escape for 40-byte openings: 110,865 vB
without privacy and 116,643 vB with the necessary no-extra-label condition.
The search must change that commitment/representation interface rather than
implement the already-excluded fixed-orbit table as another native fixture.

The [DDH batch-select probe](../research/pointlocks-2026-09-17/ddh-batch-select.md)
offers an aggregate-scalar input-label interface, with a512-byte raw opening
for2048 bits at its eight-block setting. It supplies no Bitcoin binding of
the message-dependent aggregate point and no public ciphertext setup check.
An additive wrapper over separately opened point-lock scalars leaks coefficient
differences and all free-XOR alternatives (NR-067). Closing this direction
requires native aggregate-only extraction plus public setup binding, or a
new translation whose privacy explicitly tolerates the constituent openings.
The reported generation/opened-audit times do not close the public setup gate.
The [linear-disclosure characterization](../research/pointlocks-2026-09-17/ddh-linear-leakage.md)
further requires that any native wrapper of this exact matrix layout reveal
no scalar-linear key information outside the intended aggregate's span.
Known public affine relations between its row bases are unsafe too. Transparent
hash-and-lift rows remove that particular parameter problem, but neither they
nor redundant aggregate disclosures close the ciphertext-validation gap.
The [masked-audit follow-up](../research/pointlocks-2026-09-17/ddh-masked-audit.md)
sharpens the criterion: do not expose informative row actions even if their
scalars remain hidden, and demonstrate that accepted mask relations cannot
absorb false ciphertext claims. The fixed-before-commitment challenge in the
tested certificate fails that check. This is not a general impossibility
result or an objection to proper DLEQ proofs; the no-ZKP constraint remains.

The [Argo MAC / Duty-Free Bits review](../research/pointlocks-2026-09-17/arithmetic-garbling-interface.md)
provides an inspected separated arithmetic-garbling API and two passing
upstream tests. An integration is accepted only with explicit native
publication-to-input-label binding, public malicious-setup checks, appropriate
CRT smudging and complete setup/communication accounting. The reviewed
component functionality alone does not close OP-017.

The [WOTS-to-Lamport follow-up](../research/pointlocks-2026-09-17/wots-translation-boundary.md)
adds another compact translation interface with reproduced access counts and
small-instance polynomial reconstruction. A changed ciphertext still passes
the WOTS endpoint checks and yields the wrong intended label. To use this
route for the goal, publicly bind the masked table to its intended labels
under malicious setup, and supply the required algebraic point-lock interface
or a justified replacement. The source's508-bit BABE cost and7.60-s setup
figures do not establish this2048-bit, sub2-second complete construction.

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

## OP-019: Integrate signed-window decoding into a complete scalar schedule

The new signed radix-32 decoder is only a representation bridge. Its local
32-digit row saves 564 script bytes over conditional extraction but spends 348
combined stack items, and no complete scalar multiplication currently consumes
its sign/magnitude output. **Accept when:** a deterministic complete scalar
window schedule uses the decoder with an explicit output contract, measures
all surrounding state and terminal checks under the strict 1,000-item limit,
and either beats the branch schedule for the same scalar objective or records
the composed layout as dominated.

## OP-020 — Bound-start hash paths and Binohash composition

The optional-SHA256 binary path has a deterministic first-bit substitution
when its starting preimage is free (NR-056). **Complete when:** a complete
wrapper independently binds the start, rejects the known substituted opening,
uses normalized retained bits in any Lamport binding, and is checked against a
pinned Bitcoin Core revision in each claimed script context. Report pinning,
signature and binding costs, complete witness items (including zero or explicit
hint counts), combined stack peak, static legacy opcodes and policy results.
State the remaining cryptographic assumptions separately from execution tests.

## OP-021 — Secretless exact-output covenant under 2^64 work

Find an existing-opcode construction binding amounts, order and scriptPubKeys
of all outputs, with less than 2^64 honest total work including setup and its
verification. The creator keeps all internal state and may prepare forbidden
spends before funding. The depositor may verify the intended allowed spend
before publishing the concrete funding transaction.

**Complete when:** a reproducible construction supplies its script, complete
funding/spending transactions, explicit funding dependencies, deterministic
vectors, exact hint/data counts, combined stack/opcode/weight costs and pinned
Core consensus checks; and its security model establishes strictly greater
attack work while allowing retained-state replay and pre-funding preparation.
State the work unit and probability target. Parallel runtime and free public
setup do not substitute for total work. Separate measured facts, assumptions
and estimates; standard relay is a separate result.

The [current investigation](../research/covenant-2026-09-17/README.md) has a
consensus-checked DER-only gate and free-signature counterexample, but no
complete bridge. [NR-057](negative-results/secretless-covenant-search.md)
records scoped exclusions. A new native common-nonce relation or different
asymmetric binding needs an executable verifier, not host equality.

The [seven-direction follow-up](../research/covenant-2026-09-17/seven/README.md)
supplies a 199-opcode native two-hit candidate with a fixed first nonce,
about 56 bits of second-nonce entropy, 60 control hints, and peak 64 by
inspection. Observable routing fragments and a complete recovery-key-set
relation were checked against Core. The next concrete obligation is a
mandatory intended-output reference evaluator sharing authenticated data
with the native checks. The full PoW witness, concrete adaptive hash-path
security analysis and total-work accounting are not yet supplied.

The [current continuation](../research/covenant-2026-09-17/continuation/STATE.md)
adds actual hash-derived ECDSA signatures, reusable-root cost accounting and
an explicit functional-verifier interface. R6 also counts all modular and
nonce-sign intervals of the public Binohash length puzzle, reducing its
specified zero-prefix search cost by almost two bits; four small-difficulty
intervals pass Core policy. This improves native cost accounting but leaves
the mandatory intended-output evaluator and complete asymmetric-work proof
unresolved.

[R8's interval/congruence join](../research/covenant-2026-09-17/continuation/r8_batch_incidence.md)
replaces the naive Cartesian scan for small known nonce scalars with a
concrete range filter and exact residue test. Four actual 70-byte signatures
found this way pass Core consensus and policy; three negative cases fail.
The large expected-work estimates remain close to the budget before full
curve, memory and matching costs. A successful extension must account for
those costs and constrain every accepted nonce choice, or otherwise supply
the retained-state output asymmetry. The duplicate-signature multisig and
coupled-DER follow-ups are specific incomplete relations, not a general
exclusion of new algebraic constructions.

[R9 proves the three-common-key implication for every shared valid ECDSA signature](../research/covenant-2026-09-17/continuation/r9_recovery_audit.md),
including all second-x recovery cases. Exact polynomial enumeration and an
independent matrix certificate exclude every exceptional translated
four-point set. The 75-byte, 47-opcode variable-signature interface passes
four positive same-context Core/policy fixtures and four negative fixtures;
the CODESEPARATOR variant is 76 bytes and 48 opcodes. A new constructive use
must supply a mandatory intended-output reference context or evaluator,
rather than repeat two identical native contexts. This theorem supplies
scalar equality, not native access to digest bytes.

[R10 provides a same-input constant/ALL reference interface](../research/covenant-2026-09-17/continuation/r10_reference_interface.md)
and a [packed-seed affine checker](../research/covenant-2026-09-17/continuation/r10_parameter_frontier.md)
with 58 opcodes remaining in its 37-stage configuration. The next falsifiable
step is an actual output-related reference function, including native
bindings for its readable inputs and outputs, within the combined resource
and total-work budget. The literal fixed digest target and assumed reusable
native variants do not meet that criterion. The formal free-r product
relation of [parallel cycles](../research/covenant-2026-09-17/continuation/r10_parallel_cycles.md)
also requires an actual nonce construction, including every recovery branch.

[R11 now supplies a pairwise endomorphism construction](../research/covenant-2026-09-17/continuation/r11_endomorphism.md)
for free signatures, with funded Core/policy-positive examples. The remaining
acceptance criterion is a native binding of a genuine reference hash/root to
these pairs with cheaper preparation for the intended outputs. Alternatively,
the concrete recovery-table route needs one fully self-consistent
funding/table construction, including the actual txid dependency and complete
setup cost. Its table-free scriptCode alone does not satisfy that criterion.

[R13/R14](../research/covenant-2026-09-17/continuation/STATE.md)
exclude the tested free-h orbit query, all-three-short hash-signature orbit,
affine three-key orbit, full four-common-key endomorphism transport, direct
ECDSA-table transfer to tapscript, and ordinary finite ancestor staging.
These are scoped exclusions. **Next falsifiable orbit target:** an executed
native predicate connecting three-key recovery subsets across different
signatures, or one short signature to longer orbit signatures, with every
point relation and readable h enforced. Supply actual output-dependent
digests and a complete work bound; neither an assumed orbit nor a free
witness integer satisfies this target.

[R15](../research/covenant-2026-09-17/continuation/r15_three_common_keys.md)
supplies the finite geometric test for fixed nonzero affine parameters:
`n²(X−v)^4−16w²(X³+7)=0`, with `(v,w)=−(b/a)G`, followed by both exact
integer branch filters. The next acceptance test is a complete native
C/ALL witness satisfying this geometry and the actual digest equations,
with the hash-selected r/s retained and every setup cost counted. A host
selection of the desired endomorphism parameter is not native enforcement.

[R16](../research/covenant-2026-09-17/continuation/r16_three_key_support.md)
bounds the complete target-digest support of each fixed constant-context
alpha by `5*(p-n-1)`, for all affine maps. With separate fresh independent
source/native hash answers, `2^64` total queries succeed with probability
at most approximately `2^-44.08044`; shared or correlated answers require
separate analysis. The next falsifiable three-key target is a concrete
correlated construction with exact serialized hash inputs, Script-enforced
relationships and full joint search costs, or a different reference
interface. Merely choosing additional translations cannot escape the
support theorem. The [native small-curve closure](../research/covenant-2026-09-17/continuation/r16_native_translation.md)
supplies reproducible actual transaction digests but still substitutes a
complete toy logarithm table and a source-hash scalar projection.

[R17](../research/covenant-2026-09-17/continuation/r17_shared_source.md)
now supplies actual shared-answer byte identities, without a second source
preimage search, but still no accepted signatures or enforced source
provenance. Its [exceptional diagonal family](../research/covenant-2026-09-17/continuation/r17_correlated_diagonal.md)
requires `rho=r*Z0/C < p-n`, `Z0*V+256*C*G=O`, and a computable fixed q
mapping the source triple by `U -> ((rho/r)*U+256*G)/q` to three target
recovery roots. The next falsifiable target is such a witness above the
fully excluded r<=32767 range, or a constructive ordinary-branch solver,
followed by a raw-hash transaction hit, native exact-output enforcement and
a complete cost bound. The exceptional scalar identity alone meets none of
those remaining criteria.

[R18](../research/covenant-2026-09-17/continuation/r18_endomorphism_resultant.md)
completely excludes nonzero translations with the six slopes `+/-lambda^k`
for three-root recovery transport. The [independent certificate](../research/covenant-2026-09-17/continuation/r18_resultant_audit.md)
covers all roots and integer branches, so new constructive work must use
another slope or interface. Its [inverse generators](../research/covenant-2026-09-17/continuation/r18_diagonal_solver.md)
exclude only target rho<=256 across the full exceptional source domain;
their complete domain sizes do not establish expected work.

The [distinct-input lemma](../research/covenant-2026-09-17/continuation/r18_mandatory_reference.md)
also removes exact ordinary-preimage reuse between actual native checks in
different inputs within either ECDSA hashing family. A mandatory external
reference still needs a different enforced relation, not an assumed empty
scriptCode or an optional coinput.

[R19's complete doubled-slope test](../research/covenant-2026-09-17/continuation/r19_even_slopes.md)
also excludes `+/-2*lambda^k` for every translation, with all exceptional
denominators handled. Inverting maps gives the same result for
`+/-lambda^k/2`. General q remains open; a new multiplier should be tied
to a concrete solver rather than another unmotivated bounded scan.

The [new BCH verifier source](../research/covenant-2026-09-17/continuation/r19_reference_sources.md)
provides an explicit acceptance target for a BTC substitute: force every
producer and checker to execute from its authenticated spent locking
script and bind them to the same actual transcript. Witness-byte presence
or terminal-only binding is insufficient. Replace its BCH introspection
with an existing-BTC-native relation, or execute the complete reference
within the mandatory input, while counting funding and setup costs.

[R20's funded Core counterexample](../research/covenant-2026-09-17/continuation/r20_taproot_reference_core.md)
makes both obligations explicit: two different valid helper data rows keep
the same main DEFAULT signature, and a retained-key signer can replace the
helper by signing again. Acceptance for a new cross-input candidate now
requires an actual fixed main output for which every accepting spend both
executes the intended checker and enforces the same semantic data (or a
proved unique transaction-derived value). Input-script commitment alone
meets neither full criterion. The [full functional-signature audit](../research/covenant-2026-09-17/continuation/r20_functional_signature_spec.md)
also requires replacing retained master signing authority, not merely
issuing a restricted key to another party. No full solution is established.

[R21's canonical-pair classification](../research/covenant-2026-09-17/continuation/r21_canonical_affine.md)
distinguishes native uniqueness of the unordered pair from a usable main-input
key. A fixed affine aggregate `uR+vG` is invariant as an x-only key under
swapping the pair when u=0 **or** v=0; the fixed-coefficient branches give
a public signing scalar or, when the asymmetric branch works at two distinct
digests, a digest-independent key. Nonlinear key-dependent weights escape
that classification, but no native aggregate binding or honest signer is
supplied. The new host results are `locally-reproduced`, their general
derivations `inspected`, and deployment remains `unclassified`.

**Next canonical-interface acceptance criterion:** give complete funding and
spending bytes that force the auxiliary checker to execute, enforce that
the main native key/value is the specified function of its actual canonical
pair, and supply an honest signing/setup algorithm below 2^64 total work.
Establish the required greater work for different outputs despite retained
setup state and fresh signatures, including helper substitution/omission.
Account for the
funding return dependency if the aggregate enters a locking commitment;
pair uniqueness alone does not create cross-input data access.

The [hash-weight cancellation analysis](../research/covenant-2026-09-17/continuation/r21_hash_weight_cost.md)
and [independent audit](../research/covenant-2026-09-17/continuation/r21_hash_weight_audit.md)
scope the next cost claim: equal full hash weights have bound `2Q*pmax`
for one source fixed before all point-hash answers, or `2MQ*pmax` for M
sources fixed beforehand. Adaptive source choice needs separate analysis;
the general collision bound `binom(Q,2)*pmax`, capped at one, still applies.
Charge setup,
discarded trials and both endpoint queries, including final candidate
verification. A proposed continuation must specify that chronology and its
oracle assumptions, or supply a different signing route. These bounds
cover only cancellation for this aggregate; a nonzero unknown-point
coefficient does not prove arbitrary Schnorr signing impossible.

**Next orbit-interface acceptance criterion:** natively enforce the point
relation or a replacement readable reference for actual output-dependent
digests, including the real hash-derived short signature and all funding
and search work. [R21's extractor](../research/covenant-2026-09-17/continuation/r21_orbit_interface.md)
assumes the orbit; it does not authenticate it. In the common antipodal-pair
case, native checks give `ri/r0=zi/C`, while the orbit requires
`si/ri=+/-s0/(lambda^i*r0)`. Equal long-signature digests cannot complete
that orbit; the approximately 2^192 target-pair support yields probability
bounds only with the stated independent-digest assumptions. A new candidate
must enforce these additional relations, justify any correlated native
contexts, or explicitly use another interface. Connected antipodal-pair
graphs either collapse to the same pair or supply the conditional public
nonce-log extractor; non-antipodal four-root cases remain outside that
lemma. None of these R21 results supplies the missing native bridge or a
complete solution to OP-021.

**R22 positive native progress:** the
[two-context SINGLE guard](../research/covenant-2026-09-17/continuation/r22_single_guard.md)
now enforces the actual constant digest C for a long ECDSA pair edge,
unless two distinct native hashes collide modulo n. This qualification
includes unequal 256-bit hashes differing by n. The signature must exceed
57 bytes, excluding four-root recovery; the same two distinct compressed
keys are checked in both actual CODESEPARATOR contexts. It permits all
eight effective SINGLE flags and supplies no output commitment.
The 49-byte redeem script executes 32 non-push opcodes and four ECDSA
checks. Its three non-hint entry items coexist, its combined stack peak
is six, and it requires zero hint items per invocation or complete
fixture. The separate helper input contributes one non-hint witness item
on its own stack; full spend/serialization metrics are in the report.
All [ten Core cases](../research/covenant-2026-09-17/continuation/r22_single_guard_core.json)
match expectations, four positive and six negative; the positives include
the same witness with a changed recipient. Positive executions are
`differentially-validated` / `consensus-validated`, negative executions
`differentially-validated` / `consensus-incompatible`. This is consensus-only,
with default policy rejecting the legacy CODESEPARATOR. The general
collision argument remains `inspected`.

**Next guarded-graph acceptance criterion:** compose the guard into an
actual long-signature C graph, checking that every required edge executes,
that canonical distinct keys and the length bound survive composition,
and that the processed scriptCodes still yield distinct ordinary
preimages after FindAndDelete. Supply valid signatures for the genuine
funded ALL digest and a compulsory fixed reference to the allowed outputs.
For a fixed source pair `K±=±(s/r)R-(z/r)G`, the scoped
[path conditions](../research/covenant-2026-09-17/continuation/r22_native_relation.md)
are `z/r=C*S_m` for an odd path and `log_G(R)=C*r*S_m/s` for an even path,
where `S_m=sum((-1)^(m-i)/r_i)` and R's sign follows the first endpoint.
Choosing denominators alone does not create valid nonce points or
signatures; odd reversal does not order the pair. Demonstrate an honest
spend, complete per-input item/stack/opcode/byte bounds and a retained-state
work advantage over fresh witnesses for disallowed outputs. The 49-byte
guard alone, or a freely recomputable C edge, does not satisfy this test.

**Next TapTweak-interface acceptance criterion:** the
[public edge-first construction](../research/covenant-2026-09-17/continuation/r22_taptweak_interface.md)
starts from an even-y I and a real tree root M, obtains the range-checked
native tweak t and `O=I+tG`, then for public `a!=0` sets
`R=(I+(t/2)G)/a`, `r=x(R) mod n`, `s=a*r mod n`, `z*=t*r/2 mod n`.
Its 64 host pairs reproduce `{I,-O}` with finite distinct keys and exactly
two nonce roots, without point logarithms. This is
`locally-reproduced` / `unclassified` evidence on manufactured digests.
A continuation must solve
`z_native(T,input,scriptCode,flag)=(t/2)*(x((I+(t/2)G)/a) mod n) mod n`,
using the actual funding and spend bytes, and make the native control-block
endpoints equal the keys used by compulsory ECDSA checks. Witness copies
are not authenticated by the control block alone. Retained knowledge of
I's scalar gives an unrestricted Taproot key-path spend and must not be
assumed erased. Include the real leaf/tree commitments, any return
dependency through funding, all search/setup work and the allowed-output
advantage. Neither the host construction nor its special `a=1` DER-length
exclusion resolves the general family or closes OP-021.
