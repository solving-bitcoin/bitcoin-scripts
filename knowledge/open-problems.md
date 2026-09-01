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
remainder below the target, and checks the modular relation over a 36-prime,
521-bit basis. It is 88,225 locking-script bytes with a 722-byte complete
244-item data witness, 79,271 static non-push opcodes, and a strict 249-item
peak. The script is table-free: 75,732 bytes are the four residue bindings,
11,121 are modular relations, 1,060 are range checks, and 312 are routing.
For programs that retain certified values, the separate one-value binder costs
19,147 bytes and returns both the 16 limbs and 36 residues, proving the value
is below `2^256`. Its `bind_value_below(N)` variant costs 19,234 bytes and also
proves the field bound required for operands and remainders.

The ordinary-product batch frontier is now reproduced for one through six
coordinate-major products. Six cost 64,462 bytes with outputs on the altstack,
or 64,912 after restoring all 450 outputs, at a strict 900-item peak. This is
30.8% below six independent returned-output fragments. Seven products begin
with 1,050 operands and are impossible under the current stack limit. A
two-proof no-carry modular batch was also executed and is dominated: 52,048
bytes versus 51,554 independently because routing exceeded table savings.

Both profiles remain `unclassified`. The 10,952-byte profile is still
conditional: all supplied coordinates must be externally tied to canonical
encodings of corresponding unsigned integers below `2^256`, and operands must
be below the target. The 88,225-byte profile closes that binding boundary for
one operation, but it is still a fragment rather than a complete tapleaf or
transaction. Bitcoin Core consensus and policy validation, executed-opcode and
validation-budget measurement, complete witness and transaction weight, and
dependent workloads that reuse certified values remain open.

## OP-005 — SHAKE256 composable output

Avoid the 1,024-item raw-output failure. **Complete when:** a parameterized or
incremental squeeze passes strict stack checks and is differentially validated
against FIPS 202 for boundary message/output lengths.

## OP-006 — BN254 hinted-operation inventory

Catalog full costs and binding equations for every hint-producing field and
group operation. **Complete when:** each has adversarial-hint tests, witness
bytes, script bytes, stack peak, and reference comparison.

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
