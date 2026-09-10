# Taproot signature semantics against pinned Bitcoin Core

Question: does the local interpreter agree with Bitcoin Core on CODESEPARATOR
positions, empty signatures with unknown key types, invalid Schnorr keys and
disabled Tapscript multisig opcodes? The comparison objective is exact acceptance
and rejection diagnostics for funded transactions, before and after narrow
interpreter repairs. This is a correctness experiment, not an optimization.

The repaired integration matches **all 20 local/Core verdicts and rejection
diagnostics**, eliminating all 13 baseline disagreements and six panics. Two
fresh Core runs produce byte-identical reports. The transactions, scripts,
witnesses, signatures and Core results are unchanged between baseline and repair.

## Reproduce

```sh
cargo test --locked --example tapscript_signature_fixtures
python3 -m unittest discover -s tools -p 'test_tapscript_signature_regtest.py'
python3 tools/tapscript_signature_regtest.py --download-core
```

After the first download, omit `--download-core`. The experiment reuses the
[hash-verified Core release and isolated regtest runner](core-validation.md):
v30.3, commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`, wallets and P2P disabled,
fixed block times and an explicitly standard-policy mempool. It never uses an
existing node. `generateblock` independently validates complete transactions;
`testmempoolaccept` measures the pinned default policy separately.

The [Rust generator](../examples/tapscript_signature_fixtures.rs) first emits
funding commitments. After the runner confirms funding, it receives that exact
transaction ID and constructs each spend using real prevouts. Public deterministic
keys use signing seed `[0x23;32]` and internal-key seed `[0x01;32]`. Every fixture
receives 1,000,000 satoshis and pays a 10,000-satoshi fee. These keys are test data.

Every generated leaf goes through `compile_with_policy()` once. The final
serialization supplies the Tapleaf hash, signature digest, execution and metrics.
Witness-controlled comparisons and branches keep the separator prefixes
observable after optimization. Rust/Python transaction serialization must agree;
Core independently checks txid, wtxid, size, weight and virtual size. The runner
also verifies the single resolved interpreter against the compiled Cargo lockfile
provenance. Missing local verdicts and panics never count as rejection.

- [Runner](../tools/tapscript_signature_regtest.py) and
  [offline guard tests](../tools/test_tapscript_signature_regtest.py).
- [Baseline at `4b7269a4`](../tests/data/tapscript-signatures-v30.3.baseline-4b7269.json).
- [Repaired integration report](../tests/data/tapscript-signatures-v30.3.json).
- Fresh strict output defaults to `target/tapscript-signatures-v30.3.json`.
  `--allow-local-mismatches` explicitly records a historical baseline; it cannot
  waive a Core expectation, rejection-diagnostic mismatch or infrastructure error.

## Baseline findings

All 20 Core consensus/policy expectations and exact rejection diagnostics pass.
The baseline interpreter `4b7269a415f21be3fccee9730547f1426eb80326` has **13 local
disagreements**, including **six panics**. Core accepts 11 transactions under
consensus and six under policy.

| Case | Core result | Baseline local result |
| --- | --- | --- |
| Correct CODESEPARATOR signatures, ordinary/skipped prefix | Accept | Reject |
| Signatures committing to separator byte offset | Reject: Schnorr signature | Accept |
| Empty unknown-key CHECKSIG followed by NOT | Consensus accept; policy discourages key type | Reject |
| Empty unknown-key CHECKSIGVERIFY | Reject; policy reports key type first | Accept |
| Empty unknown-key CHECKSIGADD with unchanged-accumulator check | Consensus accept; policy discourages key type | Reject |
| Invalid 32-byte x-only key, 64-byte or 65-byte ALL signature | Reject: Schnorr signature | Panic |
| Invalid key with explicit DEFAULT or invalid hash-type byte | Reject: signature hash type | Panic |
| Executed CHECKMULTISIG / CHECKMULTISIGVERIFY | Reject: unavailable in Tapscript | Panic |

The seven controls cover a valid no-separator signature, three nonempty unknown-key
signatures, an empty signature with an invalid 32-byte key, and the two multisig
opcodes in skipped branches. These agree with Core already.

The final ordinary-prefix separator is at opcode position **3**, byte offset
**5**; the skipped-prefix fixture uses position **6**, offset **8**. These values
refer to policy-produced bytecode including initial padding cleanup. A data push
counts once regardless of encoded size; parsed instructions in skipped branches
still count, but only an executed separator updates the committed position.
[BIP342](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0342.mediawiki#common-signature-message-extension)
and [Core's signature rules](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp)
define the expected behavior.

## Adopted repairs and upstream contributions

The lab pins the single interpreter integration
[`702544c9a045ac4fc14846da6da6559e2b7cd9d1`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/commit/702544c9a045ac4fc14846da6da6559e2b7cd9d1)
for both direct execution and `bitcoin-script-stack`. The compiler remains at
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`. Historical primitive metrics and the
earlier 24- and 44-fixture reports keep their original attribution.

| Contribution | Immutable source | Submission |
| --- | --- | --- |
| CODESEPARATOR implementation, by Sander Bosma | `4c9bf94e1508df9c77a579dde1831c88ab24cabb` | Existing [BitVM #16](https://github.com/BitVM/rust-bitcoin-scriptexec/pull/16) |
| Eight additional CODESEPARATOR regression groups | `474a6b6f0a67338ea61287cabf06c92fb0b7a3e0` | [Tests to the author's branch](https://github.com/bob-collective/rust-bitcoin-scriptexec/pull/1) |
| Empty-signature semantics for unknown key types | `f4e05a47dbdb465e8dbe970531825a973f0836d1` | [BitVM #21](https://github.com/BitVM/rust-bitcoin-scriptexec/pull/21) |
| Invalid-key/multisig errors and missing SINGLE output ordering | `2efd48f793b972edda33cdcf39b47d99ab6e6547`, `47e080651a1df90e67cce7c05a846f8befd8c08b` | [BitVM #22](https://github.com/BitVM/rust-bitcoin-scriptexec/pull/22) |

These submissions remain unmerged at recording time. The integrated upstream
suite passes **57 tests**. The additional missing-SIGHASH_SINGLE-output test
covers both SINGLE variants, all three signature opcodes and valid/invalid keys.
It is `locally-reproduced` with deployment `unclassified`, checked against Core
source; that two-input shape is outside this 20-transaction Core corpus.
Malformed caller-supplied transaction context still produces a distinct panic,
and legacy/Segwit multisig remains outside the panic repair's scope.

Report SHA256 values:

- Baseline: `76252837e2471217e5e116d5fb1c2f3dcac9a30b9b261e33c671fec614fd1753`.
- Repaired and repeat: `08f89daebd637ce79cce01239fd19b21c16712feb089dfd5d3d59b6a75d60683`.

## Measurement boundary and remaining work

Boundary: **complete-transaction:** each isolated leaf includes witness inputs,
constants, cleanup, terminal predicate, output, script/control block and witness
serialization. No batch or repeated configuration is measured. Every fixture
has **zero auxiliary hint items and zero hint bytes**. All data items coexist
at entry; two are ordinary 32-byte padding items removed by initial `OP_2DROP`.
They are included in data counts, witness sizes and the combined main-plus-alt
stack peak. Complete Taproot witness counts additionally include script and
control block. Surrounding protocol state would share Bitcoin's 1,000-item bound.
Across the 20 final fixtures, leaf sizes are 3–43 bytes, data counts are 2–5,
complete witness counts are 4–7, combined stack peaks are 2–5, complete witness
sizes are 105–214 bytes, and transaction weights are 483–592 WU (121–148 vbytes).
These ranges describe different complete leaves, not an algorithmic comparison.

The padding keeps these single-signature cases away from a known local API
limitation: the interpreter initializes its budget from serialized **data**
witness items, omitting script/control block/annex. The report names these
budget measurements explicitly. They are not complete Taproot validation budgets.
Every fixture has a conservative data-only budget floor of at least 67 after
at most one charge. The dependency's remaining-budget statistic can be stale
on instruction failure, so it is null for errored executions; a conservative
bound is reported separately rather than treating the stale counter as measured.
No fixture contains an annex or probes budget exhaustion. CODESEPARATOR's adopted
upstream counter counts parsed instructions, including pushes and skipped code;
it is not an executed non-push opcode measurement.

Local execution uses direct `Exec`, a full `TxTemplate`, consensus numeric
settings, mandatory minimal IF, no experimental concatenation and the combined
stack limit. Its deployment class alone remains `unclassified`. Evidence is
`differentially-validated` for the exact Core comparisons. Core-accepted fixtures
are `consensus-validated` or `policy-validated`; Core-rejected fixtures are
`consensus-incompatible`. These results do not strengthen unrelated catalog
measurements or remove the public context-free profiles' unsupported-opcode guard.

The next acceptance criterion remains [OP-001](open-problems.md#op-001--strict-execution-matrix):
complete local commitment/annex validation and budgets initialized from the full
serialized witness, with valid and mutated transactions matching pinned Core.
