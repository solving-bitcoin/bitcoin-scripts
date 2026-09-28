# Five-byte CHECKSEQUENCEVERIFY operands against Bitcoin Core

Question: does the local interpreter apply BIP112's five-byte ScriptNum rule and
BIP68's sequence mask without panicking or changing a valid spend's result? The
comparison objective is exact consensus and default-policy acceptance and
rejection categories for funded Taproot script-path transactions. This is a
correctness experiment, not an optimization.

The old interpreter panicked on the valid operand `2^32`, encoded as
`00 00 00 00 01`, when `nVersion=2` and the selected `nSequence=0`. It converted
the whole positive five-byte number to `u32` with `expect`. Pinned Core masks
away all but the type bit (22) and low 16 bits before comparing. The repaired
integration **matches Core on all 19 funded consensus and 19 policy comparisons**,
including error categories. Core accepts 10 under consensus and eight under
default policy. Two fresh isolated Core runs produced byte-identical reports,
SHA256 `84528efd5d999cd367e776797291bf05f34f0bfe341bc4140118a3e18aade2fc`.

## Reproduce

```sh
cargo test --locked --example tapscript_csv_fixtures
python3 -m unittest discover -s tools -p 'test_tapscript_csv_regtest.py'
python3 tools/tapscript_csv_regtest.py --download-core
```

The [generator](../examples/tapscript_csv_fixtures.rs) builds policy-compiled
three-byte CSV or CLTV leaves and public deterministic Taproot commitments.
It first emits funding outputs, then constructs spends from the confirmed
outpoints passed by the [runner](../tools/tapscript_csv_regtest.py). Each output
receives 1,000,000 satoshis; each spend pays a 10,000-satoshi fee. Core v30.3
at `49faec4f87f5cd19c88db01a82e5c68b087c8227` runs with wallets and network
disabled and fixed block times. The runner mines 16 blocks after funding so
positive five-unit BIP68 height/time locks are mature. It measures policy with
`testmempoolaccept` and independently measures consensus by connecting a block
with `generateblock`. Python reconstructs the transaction with each fixture's
version and sequence; Core independently checks txid, wtxid, size, vsize and
weight. The report records the verified Core archive and binary hashes.

The [stored report](../tests/data/tapscript-csv-v30.3.json) contains all 19
transactions, witnesses, exact Core diagnostics, local outcomes and resolved
Git pins. [Offline guards](../tools/test_tapscript_csv_regtest.py) reject
missing local verdicts, wrong error categories, funding-manifest drift and
incorrect witness/budget accounting. A fresh run writes
`target/tapscript-csv-v30.3.json` by default. Diagnostic
`--allow-local-mismatches` never waives a Core expectation or infrastructure
failure.

## Boundary and results

[BIP112](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0112.mediawiki)
allows nonnegative ScriptNums up to five bytes. The CSV operand's bit 31 is a
no-op switch; otherwise the comparison uses bit 22 and the low 16 bits. The
input's bit 31 disables BIP68 and makes an active CSV check fail. Values with
relevant bits beyond `u32` must therefore be masked before narrowing. A six-byte
number still fails numeric parsing; a negative number fails before masking.
The CLTV control demonstrates that a five-byte number above the transaction's
32-bit `nLockTime` fails its own check without a panic.

Each fixture has **one input data item and zero auxiliary hint items/bytes**.
That one item coexists at entry with no other data. The complete Taproot witness
has three items: operand, final policy-produced leaf and 33-byte control block.
The local combined main-plus-alt stack peak is one, with the 1,000-item check
enabled. Leaf size is three bytes; complete witness serialization is 40–46
bytes, including count and length prefixes. There are no signature checks, so
initial and remaining signature budget are equal. Static non-push opcode counts
are recorded; dynamic executed-opcode counts are unavailable. All leaves are
below 32 KiB and use `CompileOptions::ALL`; the final compiled bytes supply the
commitment, execution and metrics.

`P` means `policy-validated`, `C` means `consensus-validated` only and `R` means
`consensus-incompatible` for the exact funded fixture. Evidence is
`differentially-validated`; local leaf execution alone remains `unclassified`.
`Data/full B` are serialized data-only/complete witness sizes. The full
transaction, including funding age and script commitment, is validated by Core.

| Fixture | Operand hex | Data/full B | Local peak | Core |
| --- | --- | ---: | ---: | --- |
| `csv-zero-control` | `∅` | 2/40 | 1 | P |
| `csv-high-zero` | `0000000001` | 7/45 | 1 | P |
| `csv-high-bit-38` | `0000000040` | 7/45 | 1 | P |
| `csv-high-height-exact` | `0500000001` | 7/45 | 1 | P |
| `csv-high-height-short` | `0600000001` | 7/45 | 1 | R |
| `csv-high-time-exact` | `0500400001` | 7/45 | 1 | P |
| `csv-high-time-short` | `0600400001` | 7/45 | 1 | R |
| `csv-height-to-time` | `0100000001` | 7/45 | 1 | R |
| `csv-time-to-height` | `0100400001` | 7/45 | 1 | R |
| `csv-reserved-middle-bits` | `0500004001` | 7/45 | 1 | P |
| `csv-version-one` | `0000000001` | 7/45 | 1 | R |
| `csv-input-disabled` | `0000000001` | 7/45 | 1 | R |
| `csv-operand-disabled` | `0000008001` | 7/45 | 1 | P |
| `csv-max-five-byte-disabled` | `ffffffff7f` | 7/45 | 1 | P |
| `csv-negative` | `81` | 3/41 | 1 | R |
| `csv-six-byte` | `000000008000` | 8/46 | 1 | R |
| `csv-nonminimal-zero` | `00` | 3/41 | 1 | C |
| `csv-nonminimal-one` | `0100` | 4/42 | 1 | C |
| `cltv-five-byte-overflow-control` | `0000000001` | 7/45 | 1 | R |

The two nonminimal-number cases pass consensus and fail default policy. The
unfixed `2^32` case is the exact local panic reproduced before patching, while
Core accepts it under consensus and policy. At the adopted revision it is an
ordinary successful local execution. The comparison does not reinterpret an
interpreter panic as a Core rejection.

## Provenance and limits

The lab adopts immutable interpreter integration
[`a09e87af444034698697f0a2267e755cf72f9aed`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/a09e87af444034698697f0a2267e755cf72f9aed),
which retains the prior resource, signature and complete-witness budget repairs
and adds standalone CSV repair `6bb5e342fabc3780bd2b83cba237275892844bcc`
([upstream PR #24](https://github.com/BitVM/rust-bitcoin-scriptexec/pull/24)).
The standalone patch was based directly on upstream `ba96bc2`; its pre-fix
regression panicked on `2^32`, and all 20 post-fix upstream tests pass. All 74
tests in the combined integration pass. The compiler remains
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`. Older Core and metric reports
keep their original pins.

Local `Exec::new_tapscript` checks the selected transaction input's version and
sequence during CSV execution but has no funding height, median-time history or
full transaction-validity model. The 16-block preparation lets Core establish
maturity for this corpus; it does not make local execution a BIP68 validator.
The context-free consensus/policy fragment profiles still refuse CSV as
unsupported. Commitment validation and a chain-aware timelock verdict remain
[open under OP-001](open-problems.md#op-001--strict-execution-matrix).
See [NR-065](negative-results/index.md#nr-065-narrowing-five-byte-csv-operands-before-masking-panics).

## Confirmed-output BIP68 maturity follow-up, 2026-09-28

Question: when a CSV leaf itself succeeds, can a local chain-aware preflight
distinguish an immature transaction from the same funded spend at its first
eligible height and median-time-past (MTP)? The comparison objective is the
consensus and default-policy verdict for the two exact boundaries, with leaf
execution retained as a separate diagnostic.

[BIP68](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0068.mediawiki)
and [pinned Core's sequence-lock calculation](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/consensus/tx_verify.cpp)
use the input's confirmation height for height locks and the MTP of the block
before confirmation for time locks. The candidate block's height and its
parent's MTP must exceed the calculated last-invalid values. A time unit is
512 seconds, the low 16 sequence bits encode the relative duration, bit 22
selects time, and bit 31 disables the lock. The new
[`support::bip68` preflight](../src/support/bip68.rs) checks every input's ordered
outpoint and confirmed chain facts; missing or inconsistent context yields
`Unsupported`, not rejection. It does not execute a Script or establish full
transaction validity.

The [separate maturity runner](../tools/tapscript_maturity_regtest.py) reuses
the earlier 19-output funding manifest and selects its CSV5 height and time
leaves without altering the historical report. It funds them on a fresh regtest
chain with 512-second block spacing.
The funding output confirms at height **102**; the MTP of its parent block is
**1800049152**. Both leaf executions accept throughout. At tip 105, candidate
height 106 and parent MTP `base + 2048` are one height/time unit short: the local
preflight says `Premature`, Core rejects both transactions in block validation
as `bad-txns-nonfinal`, and `testmempoolaccept` reports `non-BIP68-final`.
At tip 106, candidate height 107 and parent MTP `base + 2560` are exactly
eligible: the preflight says `Mature`, Core policy accepts both, and one block
confirms both spends. Calling the preflight without chain facts reports
`Unsupported` for each exact transaction. These are **four stage-by-case
comparisons**, each against both Core consensus and policy; all eight outcomes
match. The two immature states are `consensus-incompatible` and the two mature
states are `policy-validated` for these funded transactions. Evidence is
`differentially-validated` for the recorded cases.

Each leaf is the final 3-byte policy-produced `OP_CSV OP_DROP OP_TRUE` script.
Each complete witness is 45 bytes: one 5-byte operand data item, script, and
33-byte control block. There are **zero hint items per invocation**; the one
data item enters the leaf alone, and the combined main-plus-alt-stack peak is
one with the 1,000-item limit enabled. Transaction weight is 423 WU per spend.
The initial and remaining signature budget is 95 because neither leaf uses a
signature. The static non-push count is two; dynamic executed-opcode counts
remain unavailable. No repetition or batching is measured.

Reproduce with `cargo test --locked bip68::tests`,
`cargo build --locked --example bip68_maturity_probe`,
`python3 tools/test_tapscript_maturity_regtest.py`, and
`python3 tools/tapscript_maturity_regtest.py --download-core` on a machine
without the pinned Core archive. Two fresh-node runs produced byte-identical
[stored reports](../tests/data/tapscript-maturity-v30.3.json), SHA256
`c8e4e05222280a178b5efeb20f6098154dc04ae874894c2cf4f70f00405a73fc`.
The report records the pinned Core binary and commit, full funded transactions,
block identities, MTP values, local leaf outcomes and exact rejection reasons.

The preflight supports confirmed prevouts whose height and MTP facts come from
the same candidate chain. It does not verify that those facts are authentic,
model same-block or mempool parent outputs, enforce absolute finality, validate
UTXO existence, or implement full relay policy. Local `Exec::new_tapscript`
still has no chain history; an accepted leaf must not be presented as a mature
transaction. These wider transaction-context obligations remain under
[OP-001](open-problems.md#op-001--strict-execution-matrix).
