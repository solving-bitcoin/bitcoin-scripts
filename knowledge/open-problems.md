# Open research problems

Each problem has a falsifiable completion criterion. Update comparisons and
negative results when closing one.

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

Progress: the 15,628-byte, 183-item no-carry 75-prime table/Horner hybrid
remains the baseline. The current `locally-reproduced` flagship instead uses a
42-prime carry-optimized basis whose product is 513 bits. Packed coordinate
groups verify exact signed carry equations, and an
18-coordinate remainder-complement subbasis with product greater than
`2^257` establishes `r < N` once its values are globally bounded. For the
secp256k1 field modulus, the fragment is 10,952 locking-script bytes with a
301-byte serialized hint and a strict 231-item peak. The 144 hint items are 42
quotient residues, 42 remainder residues, 42 relation carries, and 18
complement residues. It is table-free, so none of those 10,952 bytes is
amortizable lookup setup.

A second `locally-reproduced` profile now supplies the previously missing
global binding inside the arithmetic fragment. It represents `lhs`, `rhs`,
quotient, and remainder with 16 centered base-`2^16` limbs each, derives four
canonical RNS vectors with exact binding carries, proves `lhs`, `rhs`, and
remainder below the target, and checks the modular relation over a 47-prime,
513-bit basis. It is 51,055 locking-script bytes with an 868-byte complete
299-item data witness, 32,772 static non-push opcodes, and a strict 305-item
peak. The script is table-free: 38,801 bytes are the four residue bindings,
10,794 are modular relations, 1,060 are range checks, and 400 are routing.
For programs that retain certified values, the separate one-value binder costs
9,777 bytes and returns both the 16 limbs and 47 residues, proving the value
is below `2^256`. Its `bind_value_below(N)` variant costs 9,864 bytes and also
proves the field bound required for operands and remainders.

A third `locally-reproduced` 46-prime profile makes that certificate boundary
composable. Its 9,835-byte binder consumes a 195-byte, 62-item `N-1` witness
and returns only 46 certified field residues at a 72-item peak. A 31,281-byte
multiplication consumes two such verified-path certificates, locally binds q
and r, and returns a new certificate. The `(N-1)^2` incremental witness is 471
bytes/170 items, the gate peak is 267, and its 20,799 static non-push opcodes
split across 444 bytes of validation, 9,852 q binding, 9,664 r binding, 10,799
relation, and 522 routing/output. Both fragments are table-free. The basis
product is 513 bits and 1.01865 times `2^512`.

The ordinary-product batch frontier is now reproduced for one through six
coordinate-major products. Six cost 64,462 bytes with outputs on the altstack,
or 64,912 after restoring all 450 outputs, at a strict 900-item peak. This is
30.8% below six independent returned-output fragments. Seven products begin
with 1,050 operands and are impossible under the current stack limit. A
two-proof no-carry modular batch was also executed and is dominated: 52,048
bytes versus 51,554 independently because routing exceeded table savings.

All profiles remain `unclassified`. The 10,952-byte profile is still
conditional: all supplied coordinates must be externally tied to canonical
encodings of corresponding unsigned integers below `2^256`, and operands must
be below the target. The 51,055-byte profile closes that binding boundary for
one operation, but it is still a fragment rather than a complete tapleaf or
transaction. The 31,281-byte composable gate closes q/r locally and inherits
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

The checked short-input frontier is 59,534 bytes and 527 stack items for 32
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
lengths and malformed inputs; and it either beats 59,534 bytes below the
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

Turn the native 20,524-byte ordinary multiplication, 20,501-byte factor-16
multiplication, and 14,543-byte square fragments into a complete field-circuit
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
