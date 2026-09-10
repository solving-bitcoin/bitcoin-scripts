# Pinned Bitcoin Core differential validation

Question: do explicit local consensus and policy profiles agree with Bitcoin
Core on resource limits, minimal encoding, OP_SUCCESS ordering and one complete
constant-composition Winternitz spend? The current experiment establishes those
outcomes for **44 deterministic fixtures**, including rejected inputs. The
original 24-fixture report is retained as a historical dependency baseline.
It does not generalize one successful profile to the entire primitive catalog.

The separate [funded signature experiment](tapscript-signature-validation.md)
adds transaction-aware signature cases and preserves its own before/after
reports. The 24- and 44-fixture artifacts on this page keep their recorded pins.

## Reproduce

```sh
cargo test --locked --test execution_limits
cargo test --locked --test tapscript_profiles
cargo test --locked --example core_validation_fixtures
python3 -m unittest discover -s tools -p 'test_core_regtest.py'
python3 tools/core_regtest.py --download-core
python3 tools/kb.py best signature/winternitz-constant-composition20 script_bytes --execution policy-validated
```

The first run downloads an official Bitcoin Core archive into ignored
`target/core-regtest/`. Later runs omit `--download-core` and work offline once
Rust dependencies are available. The runner verifies the pinned archive SHA256
on every run and extracts only `bitcoind`. Supported archives cover macOS ARM64
and x86-64, Linux AArch64 and x86-64; this recorded run used macOS ARM64.
The manifest pins **v30.3**, commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`, to the
[official checksums](https://bitcoincore.org/bin/bitcoin-core-30.3/SHA256SUMS).
The executable SHA256 and version string are also recorded; this does not
rebuild Core from source or independently attest the release build.

Every run starts a fresh temporary regtest directory, disables wallets and
P2P connections, uses local cookie-authenticated RPC, and removes its node data
after stopping. It never uses an existing node or real funds. The public test
internal key is derived from `[0x01;32]`; these fixtures are not funding templates.
Block times, keys, messages, transaction amounts and fixture ordering are fixed.

- [Runner](../tools/core_regtest.py) and [release manifest](../tools/bitcoin_core_release.json).
- [Rust fixture generator](../examples/core_validation_fixtures.rs): full bytecode,
  data witnesses, Taproot commitments, local outcomes and explicit expectations.
- [Current profile report](../tests/data/core-validation-v30.3.profiles.json): source/binary pins,
  fixture SHA256, transaction identities/weights, raw Core results and local differences.
- [Historical 24-fixture report](../tests/data/core-validation-v30.3.json): the
  original `ba96bc2` interpreter observations, preserved without regeneration.
- Fresh output defaults to `target/core-validation.profiles.json`; `--output PATH` chooses
  another location. Do not overwrite the committed report without reviewing
  the intended experiment change.

## Independent acceptance checks

The runner mines 101 blocks to a deterministic P2WSH `OP_TRUE` output, spends a
mature coinbase to one Taproot output per fixture, and confirms that funding
transaction. Each fixture then spends its own output, paying 10,000 satoshis
and producing one P2WSH output. A real script/control-block commitment is checked.
SegWit and Taproot activation is asserted through `getdeploymentinfo`.

`testmempoolaccept` measures policy with **`-acceptnonstdtxn=0`** explicitly set
(regtest would otherwise accept nonstandard transactions). Other policy options
are the pinned release defaults. Separately, `generateblock` receives the raw
transaction directly, bypassing the mempool. Core's pinned
[`generateblock` implementation](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/rpc/mining.cpp)
uses `TestBlockValidity` before generating and connecting the block. Successful
results are checked for the expected height and included transaction ID.

Only Core's script-validation error with RPC code -25 is treated as a
consensus rejection. Transport failures, decoding failures and missing inputs
fail the run. Expected rejection categories also match the pinned diagnostics;
an unrelated commitment failure cannot satisfy a stack-boundary test. Core
reports both oversized and nonminimal ScriptNums as `unknown error`, so their
finer labels describe the specific fixture mutations rather than distinct Core
error codes. An executed nonminimal push instead reports `Data push larger than
necessary`; its separate category prevents confusing these checks. All raw
reasons are retained. `decoderawtransaction` independently
checks every transaction's txid, wtxid, serialized size, weight and vsize;
Rust and Python also agree on the complete serialized witness size.

## Explicit local profiles, recorded 2026-09-10

The new `support::tapscript::execute_tapscript` API keeps the caller's exact
policy-compiled `ScriptBuf` and requires `TapscriptProfile::Consensus` or
`TapscriptProfile::Policy`. The recorded 44-fixture report uses the unmerged fork
integration commit
[`4b7269a415f21be3fccee9730547f1426eb80326`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/commit/4b7269a415f21be3fccee9730547f1426eb80326),
which incorporates the three separately submitted interpreter corrections below.
The later signature integration `702544c9` also passes all 44 fixtures and 86
applicable local/Core comparisons; the committed report remains at its original pin.
The runner verifies the resolved graph through `cargo metadata --locked`: exactly
one interpreter package must match the fixture's immutable fork source and commit.
Legacy research helpers retain their default minimal-number option and
experimental `OP_CAT`; their outcomes remain visible in the report's `local`
field. The explicit profiles are recorded separately under `local_profiles`.

| Rule | Local Consensus profile | Local Policy profile |
| --- | --- | --- |
| Minimal encoding of consumed numbers and executed pushes | Optional | Required |
| Minimal IF/NOTIF input | Required | Required |
| Initial data item of 81–520 bytes | Allowed | Rejected before script parsing |
| Decoded OP_SUCCESS, including opcode 126 formerly named OP_CAT | Immediate leaf acceptance | Discouraged |
| Entry/per-step stack limits and 520-byte elements | Enforced when execution applies | Enforced when execution applies |

The profile settings follow the pinned
[Core execution rules](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L1827-L1865),
[policy flags](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/policy/policy.h#L110-L128)
and [witness-data policy](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/policy/policy.cpp#L307-L326).
The 80-byte check applies to initial witness data, not constants pushed by the
script. Consensus MINIMALIF remains enabled when numeric minimality is disabled.
Push encoding is checked only when a push executes, so a nonminimal push in a
skipped branch passes both profiles.

All **44 Core consensus/policy expectations and exact rejection diagnostics
pass**. For 43 fixtures, both supported local profile verdicts also agree with
Core. The remaining fixture changes only the control-block parity bit: both
local profiles must accept the unchanged leaf while Core must reject its
commitment. The runner explicitly permits only that named exception to profile
equality. Missing verdicts, panics, initialization errors and unsupported
opcodes fail the comparison; none can count as a consensus rejection.
There are no explicit-profile panics. The preserved legacy helper still panics
on malformed script syntax in the two malformed-prefix/suffix fixtures; those
historical-API outcomes remain separate from the explicit profile verdicts.

| Added boundary | Core consensus | Core policy | Explicit local profiles |
| --- | --- | --- | --- |
| Nonminimal push, executed / skipped | Accept / accept | Reject / accept | Agree |
| IF witness empty or `01` / `00` or `02` | Accept / reject | Accept / reject | Agree |
| Script push of 520 / 521 bytes | Accept / reject | Accept / reject | Agree |
| OP_SUCCESS80, OP_SUCCESS126, OP_SUCCESS254 | Accept | Reject | Agree |
| OP_SUCCESS with 1,001 initial items | Accept | Reject: discouraged opcode | Agree |
| OP_SUCCESS with a 521-byte witness item | Accept | Reject: witness-item policy | Agree |
| OP_SUCCESS in a skipped branch or after OP_RETURN | Accept | Reject | Agree |
| OP_SUCCESS after a nonminimal or oversized script push | Accept | Reject | Agree |
| Malformed push before / after OP_SUCCESS | Reject / accept | Reject / reject | Agree |
| Byte `7e` inside push data, followed by a false result | Reject | Reject | Agree |

The scan decodes instructions, so an OP_SUCCESS-valued payload byte cannot
trigger unconditional acceptance. Once an OP_SUCCESS is decoded, later
malformed bytes, stack limits, branch execution and the final stack no longer
control consensus acceptance. These ordering rules are explicit in the pinned
[BIP342 specification](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0342.mediawiki#specification).
An `OpSuccess` outcome carries no fabricated execution statistics; it is not
experimental concatenation. Complete Taproot commitments are still checked by
Core before these leaf rules apply.

These profiles are bounded fragment APIs, with local deployment `unclassified`.
They do not establish full transaction validity, annex policy or relay acceptance.
Signature, timelock and other unsupported context-dependent opcodes return no
verdict; the policy profile also conservatively refuses upgradeable NOPs even
inside dead branches. This scope contains no such unsupported fixture. All
witness/data items coexist at entry and every measured fixture uses **zero
auxiliary hint items**. Only the independent Core run supplies consensus/policy
deployment labels for these exact transactions.

## Historical 24-fixture baseline, recorded 2026-09-10

The original 24 consensus/policy expectations and rejection diagnostics pass; two fresh
runs on the recorded platform produce byte-identical reports. Evidence
is `differentially-validated` for these comparisons. A rejected fixture is
`consensus-incompatible`; successful ones are `consensus-validated` or
`policy-validated` according to the separately recorded policy result.

| Case | Core consensus | Core policy | Local stack-limited tapscript |
| --- | --- | --- | --- |
| 1,000 / 1,001 initial items | Accept / reject | Accept / reject | Agrees after wrapper repair |
| 80 / 81 / 520 / 521-byte data item | Accept / accept / accept / reject | Accept / reject / reject / reject | Agrees with consensus |
| Transient combined depth 1,000 / 1,001 | Accept / reject | Accept / reject | Agrees after wrapper repair |
| `OP_PICK` / `OP_ROLL` exact upper boundary | Reject | Reject | Panics |
| Valid Winternitz leaf | Accept | Accept | Accept |
| Winternitz control-block parity mutation | Reject | Reject | Accepts the leaf; does not validate its commitment |
| Winternitz exact-pool selector | Reject | Reject | Panics |
| Winternitz nonminimal numeric selector | Accept | Reject | Rejects under default minimal-number option |

Negative selectors, larger pool indices, oversized ScriptNums, mutated nodes,
and wrong signature-item counts are also rejected as expected.

The valid `ConstantCompositionWinternitz20<Hash160,Preimage16>` isolated leaf
uses seed `[0x42;32]`, message `00254a6f94b9de03284d7297bce1062b50759abf`, and
the verifier followed by terminal `OP_TRUE`. Whole-script repository policy
compilation produces **1,599 locking-script bytes**. Its serialized data witness
is **796 bytes**, and the full Taproot witness (data, script, 33-byte control
block and all count/length prefixes) is **2,432 bytes**. The spending transaction
has 94 base bytes, 2,528 total bytes, **2,810 weight units / 703 vbytes**.
The 1,599 script bytes are already inside the 2,432 witness bytes; do not add
them again when comparing complete transaction costs.

There are **70 signature data items, zero auxiliary hint items and zero hint
bytes per invocation**. All 70 data items coexist at entry; the complete witness
has 72 items including script/control block. The local combined main/alt peak is
**119**, including staged signature data and 49 embedded commitments. This is
one isolated invocation; no repeated configuration is measured. Surrounding
live state shares the 1,000-item limit, and the isolated verifier rejects extra
main-stack data. Static non-push count is 567; executed-opcode and validation
budget counters remain unavailable rather than being inferred from unreliable
local counters. The local run is stack-limited tapscript, deployment
`unclassified` on its own; Core supplies this fixture's `policy-validated` result.

The catalog's older fragment measurements remain `locally-reproduced` and
`research-unlimited`. A separate complete-leaf configuration records this
result with schema 1.1 configuration-level qualifiers; `best` filters use those
qualifiers while `list` retains the conservative record-level defaults. Other
hash profiles, composable variants, mainnet propagation and full
BitVM protocol transactions were not exercised. The original 24 fixtures contain
no `OP_SUCCESSx` or experimental `OP_CAT`. The current experiment above adds an
explicit OP_SUCCESS comparison; full consensus and policy coverage remains
incomplete. See [OP-001 and OP-002](open-problems.md)
and [NR-045](negative-results/index.md#nr-045-core-differentials-expose-local-executor-boundaries).

The interpreter corrections are submitted upstream as
[resource checks #18](https://github.com/BitVM/rust-bitcoin-scriptexec/pull/18)
and [stack-index bounds #19](https://github.com/BitVM/rust-bitcoin-scriptexec/pull/19),
followed by [executed-push minimality #20](https://github.com/BitVM/rust-bitcoin-scriptexec/pull/20).
The historical report retains the original dependency and local resource
wrapper repair. The current profile report uses the explicit fork integration
pin; neither report assumes these PRs have merged upstream.
