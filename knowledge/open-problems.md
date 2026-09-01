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

Progress: an exhaustive per-prime root/bias search selected a 75-prime hybrid;
its 37,471-byte multiplication, 462-item peak, canonical add/sub, strict stack
boundary, and 513-bit capacity are locally reproduced. A secp256k1-field hinted
reduction is also reproduced at 69,199 bytes, 477 reduction-hint bytes, and a
612-item peak, conditional on external global 256-bit bindings. Bitcoin Core
consensus and policy validation, a concrete global binding construction,
complete transaction weight, and reuse-inclusive workloads remain open.

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
