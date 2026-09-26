# Complete-witness signature budgets against Bitcoin Core

Question: can the lab reproduce Tapscript signature-budget boundaries when the
budget includes the complete serialized witness, rather than only its initial
data stack? The comparison objective is exact acceptance and rejection
categories for funded spends, including empty signatures and serialization
boundaries. This is a correctness experiment, not an optimization.

All **32 full-witness local/Core comparisons match**, including rejection
categories. Core accepts 15 spends under consensus and 10 under its default
policy. Sixteen cases exhaust the signature budget; a seventeenth rejects an
empty `OP_CHECKSIGVERIFY` at a remaining budget of zero. The preserved data-only
constructor disagrees on 16 cases: 15 false rejections and one wrong rejection
category. The comparison uses both constructors at the same repaired revision,
not a run of a historical dependency pin.

## Reproduce

```sh
cargo test --locked --test tapscript_budget --test execution_limits
cargo test --locked --example tapscript_budget_fixtures
python3 -m unittest discover -s tools -p 'test_tapscript_budget_regtest.py'
python3 tools/tapscript_budget_regtest.py --download-core
```

The runner reuses the [hash-verified Core release harness](core-validation.md):
Bitcoin Core v30.3 at `49faec4f87f5cd19c88db01a82e5c68b087c8227`. It starts a fresh
isolated regtest node with fixed block times, wallets and networking disabled,
and `-acceptnonstdtxn=0`. `testmempoolaccept` measures policy; `generateblock`
independently measures complete-transaction consensus acceptance. It never
connects to an existing node. The report records archive and binary hashes.

The [generator](../examples/tapscript_budget_fixtures.rs) first emits the funding
commitments, then signs the actual funded outpoints supplied by the
[runner](../tools/tapscript_budget_regtest.py). Signing seed `[0x23;32]` and
internal-key seed `[0x01;32]` are public test data. Each fixture receives
1,000,000 satoshis and pays a 10,000-satoshi fee. All signature checks use a
valid 32-byte key and real Schnorr signatures; annex cases commit to the annex
in the signature digest. Python independently reconstructs each witness and
transaction, and Core checks txid, wtxid, size, weight and virtual size.

All leaves use `compile_with_policy()`. Their final serializations are below
32 KiB and use `CompileOptions::ALL`; the same bytes supply the Tapleaf hash,
signature digest, local execution and metrics. The generator checks that all
intended signature opcodes remain after compilation. CHECKSIG/CHECKSIGADD
results are retained on the alt stack and checked before clean-stack completion;
this prevents the optimizer from replacing the intended operation with VERIFY.

- [Stored report](../tests/data/tapscript-budget-v30.3.json), with all transactions,
  witnesses, metrics, rejection diagnostics and resolved dependency identities.
- [Offline failure guards](../tools/test_tapscript_budget_regtest.py), including
  missing verdicts, wrong error categories, manifest drift and independent
  witness/budget serialization checks.
- Fresh output defaults to `target/tapscript-budget-v30.3.json`.
  `--allow-local-mismatches` permits a diagnostic local mismatch only; it never
  waives a Core expectation, rejection-category or infrastructure failure.

Two fresh nodes produced byte-identical stored reports, SHA256
`1dd0aa2a14d0c4275c41b0bd633bfb6cf0f29d32838e5bb82dc424e74daf1d46`.

## Accounting and API boundary

[BIP342](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0342.mediawiki)
and [pinned Core](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp)
initialize the budget to `50 + serialized complete witness bytes`. This includes
the CompactSize item count and each item length, data, script, control block and
optional annex. Each executed nonempty signature consumes 50 units. Exact zero
is allowed; a charge taking the budget negative fails. Empty signatures consume
nothing, but an empty CHECKSIGVERIFY still fails its own predicate.

`Exec::new_tapscript(options, tx_template)` derives the leaf, data stack, annex
and budget from the selected input. Supplied leaf/annex context must agree with
the witness; a missing context is derived automatically. It checks the input
index, prevout cardinality and control-block shape/current leaf version. These
initialization errors are distinct from executed-script rejection. Unknown
future leaf versions are unsupported by this API, not proven consensus-invalid.
Signature charges remain visible in statistics even when the opcode fails.

The lab's `try_dry_run_taproot_input` exposes this fallible constructor;
`dry_run_taproot_input` remains its convenience wrapper. Both retain research
options, including experimental OP_CAT. The experiment instead disables OP_CAT,
allows consensus numeric encodings and enforces entry/per-instruction resource
limits. This is still leaf execution: neither constructor verifies the Taproot
output commitment, transaction validity, complete relay policy or OP_SUCCESS
precedence. Core independently supplies complete-transaction evidence here.

`Exec::new` and `with_stack` keep their historical data-only budget behavior.
The experiment runs the same script, data, transaction and annex signature
context through both paths on the same dependency revision. Only the new path
receives the complete-witness budget; the legacy output is a counterexample,
not an alternative consensus verdict. Other fragment helpers and historical
reports retain their original boundaries.

## Measured boundaries

Every invocation and every repeated-check configuration below uses **zero hint
items and zero hint bytes**. All data items coexist at leaf entry. Script,
control block and annex contribute to witness bytes and budget but are removed
before the initial data stack. Data counts, complete witness counts and combined
main-plus-alt stack peaks are distinct. Peaks range from 4 to 251 with the
1,000-item limit enforced; these bounded leaves do not establish capacity for an
arbitrary larger composition. Repeated checks reuse a signature in Script, but
each nonempty invocation is charged independently.

The table includes the complete leaf, initial data, terminal checks and complete
witness serialization. `Checks` counts nonempty signature invocations; each
`empty-at-zero` leaf additionally executes one empty-signature opcode. Sizes
and peaks are local measurements, independently checked against Core for
serialized transaction/witness sizes. Dynamic executed-opcode counts are not
available; the report records static counts separately. Initial/remaining
budget is measured, including the failing charge. `P` means `policy-validated`,
`C` means `consensus-validated` only, and `R` means `consensus-incompatible` for
that exact fixture. All recorded comparisons are `differentially-validated`;
local execution alone remains `unclassified`.

| Fixture | Leaf B | Full witness B | Data/full items | Checks | Initial/remaining budget | Stack peak | Core |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `checksig-exact-zero` | 27 | 200 | 3/5 | 5 | 250/0 | 8 | P |
| `checksig-one-unit-short` | 27 | 199 | 3/5 | 5 | 249/-1 | 8 | R |
| `checksig-next-charge-short` | 32 | 200 | 3/5 | 6 | 250/-50 | 9 | R |
| `checksig-empty-at-zero` | 35 | 200 | 3/5 | 5 | 250/0 | 9 | P |
| `checksigverify-exact-zero` | 11 | 150 | 3/5 | 4 | 200/0 | 4 | P |
| `checksigverify-one-unit-short` | 11 | 149 | 3/5 | 4 | 199/-1 | 4 | R |
| `checksigverify-next-charge-short` | 13 | 150 | 3/5 | 5 | 200/-50 | 4 | R |
| `checksigverify-empty-at-zero` | 15 | 150 | 3/5 | 4 | 200/0 | 4 | R |
| `checksigadd-exact-zero` | 42 | 200 | 3/5 | 5 | 250/0 | 9 | P |
| `checksigadd-one-unit-short` | 42 | 199 | 3/5 | 5 | 249/-1 | 9 | R |
| `checksigadd-next-charge-short` | 50 | 200 | 3/5 | 6 | 250/-50 | 10 | R |
| `checksigadd-empty-at-zero` | 52 | 200 | 3/5 | 5 | 250/0 | 10 | P |
| `control-depth-1-exact-zero` | 13 | 200 | 3/5 | 5 | 250/0 | 4 | P |
| `control-depth-1-one-unit-short` | 13 | 199 | 3/5 | 5 | 249/-1 | 4 | R |
| `control-depth-6-exact-zero` | 19 | 350 | 3/5 | 8 | 400/0 | 4 | P |
| `control-depth-6-one-unit-short` | 19 | 349 | 3/5 | 8 | 399/-1 | 4 | R |
| `control-depth-7-exact-zero` | 21 | 400 | 3/5 | 9 | 450/0 | 4 | P |
| `control-depth-7-one-unit-short` | 21 | 399 | 3/5 | 9 | 449/-1 | 4 | R |
| `annex-1-exact-zero` | 11 | 150 | 3/6 | 4 | 200/0 | 4 | C |
| `annex-1-one-unit-short` | 11 | 149 | 3/6 | 4 | 199/-1 | 4 | R |
| `annex-252-exact-zero` | 23 | 450 | 3/6 | 10 | 500/0 | 4 | C |
| `annex-252-one-unit-short` | 23 | 449 | 3/6 | 10 | 499/-1 | 4 | R |
| `annex-253-exact-zero` | 23 | 450 | 3/6 | 10 | 500/0 | 4 | C |
| `annex-253-one-unit-short` | 23 | 449 | 3/6 | 10 | 499/-1 | 4 | R |
| `witness-count-252-exact-zero` | 150 | 550 | 250/252 | 12 | 600/0 | 250 | P |
| `witness-count-252-one-unit-short` | 150 | 549 | 250/252 | 12 | 599/-1 | 250 | R |
| `witness-count-253-exact-zero` | 151 | 550 | 251/253 | 12 | 600/0 | 251 | P |
| `witness-count-253-one-unit-short` | 151 | 549 | 251/253 | 12 | 599/-1 | 251 | R |
| `data-element-252-exact-zero` | 23 | 450 | 4/6 | 10 | 500/0 | 4 | C |
| `data-element-252-one-unit-short` | 23 | 449 | 4/6 | 10 | 499/-1 | 4 | R |
| `data-element-253-exact-zero` | 23 | 450 | 4/6 | 10 | 500/0 | 4 | C |
| `data-element-253-one-unit-short` | 23 | 449 | 4/6 | 10 | 499/-1 | 4 | R |

The 12 basic cases cover CHECKSIG, CHECKSIGVERIFY and CHECKSIGADD at exact zero,
one unit short, an additional charge of 50, and an empty check after exhaustion.
The 20 paired boundary cases cover control depths 1/6/7, annex lengths 1/252/253,
complete witness counts 252/253, and data-element lengths 252/253. Annexes and
252/253-byte data elements reject default policy as `bad-witness-nonstandard`,
independently of their consensus budget result.

A 252-to-253-byte element changes its length prefix from one to three bytes.
Control depths 6 and 7 have 225- and 257-byte control blocks, crossing the same
prefix boundary. The witness-count pair has 250/251 data items plus script and
control block, so its **complete** item count crosses 252/253. Discarded padding
is tuned per fixture to reach the specified budget; paired variants are not
an estimate of isolated serialization deltas. Independent upstream unit tests
also isolate exact 252/253 script lengths and the maximum control depth of 128;
those additional shapes are `locally-reproduced`, not Core-validated here.

The smallest false rejection is an 11-byte CHECKSIGVERIFY leaf with three data
items and five complete witness items. Its data serialization is 104 bytes, but
its complete witness is 150 bytes. Four nonempty checks cost 200: the correct
initial budget is 200, while the old constructor starts at 154 and rejects.
See [NR-064](negative-results/index.md#nr-064-data-only-signature-budgets-falsely-reject-complete-spends).

## Provenance and remaining work

The experiment adopts interpreter integration
[`f678467784475b1072557de70166514e52753f66`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/f678467784475b1072557de70166514e52753f66),
which retains the resource/signature repairs at `702544c9` and adds standalone
patch `9b1eddeb4735d1c607fc066aa5290c23b9d8baa1`
([upstream PR #23](https://github.com/BitVM/rust-bitcoin-scriptexec/pull/23)).
All 66 integrated interpreter tests pass, including nine new budget/context
tests. The compiler remains `124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`; other
Cargo pins and historical reports are unchanged. Fresh generator provenance
comes from the build-time embedded lockfile.

Taproot commitment validation, broader transaction contexts and full relay-policy
handling remain under [OP-001](open-problems.md#op-001--strict-execution-matrix).
This contribution does not promote other primitive configurations or turn the
context-free profiles into transaction validators.
