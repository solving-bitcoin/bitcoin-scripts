# Reduced four-mode legacy transaction pinning

- **Question:** Can four signature-size checks with the paper's ordered legacy
  sighash modes coexist in one funded transaction, while later field choices
  preserve earlier signatures?
- **Comparison objective:** Sign one two-input, two-output bare legacy spend;
  mutate one field at a time; compare host digests and Bitcoin Core v30.3 block
  verdicts for the complete transactions.
- **Evidence:** `differentially-validated` for this deterministic fixture.
  **Execution:** `consensus-validated`; default relay policy rejects the valid
  spend as `bad-txns-nonstandard-inputs`.

## Construction and parameters

The complete locking script is compiled with the repository's
`compile_with_policy()` and is 159 bytes. It has four
`OP_SIZE 71 OP_EQUALVERIFY <compressed public key>
OP_CHECKSIG[VERIFY]` checks, separated by three executed
`OP_CODESEPARATOR`s. The checks use `NONE|ANYONECANPAY` (`82`), `NONE` (`02`),
`ALL|ANYONECANPAY` (`81`), then `ALL` (`01`). The final `OP_CHECKSIG` supplies
the terminal truth value and all four signatures are consumed. All four keys
are fixed public test keys. Each signature is exactly 71 bytes including its
sighash byte. These are cheap size predicates, not a hard grind.

The first signature is found by changing the selected input's sequence; the
second by choosing one of 64 funded helper prevouts; the third by changing
one OP_RETURN byte; and the fourth by changing the helper input's sequence.
The first matching deterministic signatures took **6, 3, 2, and 1 attempts**
respectively. No RNG is used. The selected input is index 1. The helper input
is index 0 and spends a confirmed P2SH `OP_TRUE` output. The selected input
spends a confirmed bare output with the four-check script. The funding
transaction has 64 helper outputs, one bare output, and one change output.
The spend transfers 1,980,000 sat from two 1,000,000-sat outputs and pays a
20,000-sat fee.

At each `OP_CODESEPARATOR`, legacy `scriptCode` starts after the last executed
separator and omits remaining separators. The Rust generator signs those exact
suffixes. Later field choices leave the earlier signatures byte-identical.

| Field changed after signing | 82 | 02 | 81 | 01 |
| --- | :---: | :---: | :---: | :---: |
| Version, selected sequence, or locktime | changes | changes | changes | changes |
| Helper prevout | same | changes | same | changes |
| OP_RETURN data | same | same | changes | changes |
| Helper sequence | same | same | same | changes |

All six field-mutated complete spends fail Core consensus at input 1. Four
additional spends truncate one signature each to 70 bytes while retaining
its sighash byte; Core rejects each at `OP_EQUALVERIFY`. The unmutated
spend enters a connected block. The host digest equalities show which earlier
signatures remain valid; Core's final block verdict alone does not identify
that boundary. The checked [report](../../tests/data/binohash-four-mode-pinning-v30.3.json)
includes raw funding and spend transactions, all four signatures and digests,
per-mutation digests, malformed-size controls, Core policy and consensus
results, and the verified Core archive and executable hashes. The Core revision is
[`49faec4f87f5cd19c88db01a82e5c68b087c8227`](https://github.com/bitcoin/bitcoin/tree/49faec4f87f5cd19c88db01a82e5c68b087c8227).

## Cost and stack boundary

The complete legacy spend is 439 stripped and total bytes, 1,756 WU, and
439 vbytes. Its two scriptSigs are 2 and 288 bytes. It has **zero witness
items, zero hint items, and zero serialized witness
bytes**. All four signature items coexist at script entry. The script has 15
static non-push opcodes, including the three separators. Its opcode-level
combined main-plus-alt-stack bound is five items for this input shape; an
instrumented Core stack peak and executed-opcode count were not measured.
The separate funding transaction is 2,310 stripped bytes, 2,315 total bytes,
9,245 WU, and 2,312 vbytes. Neither funding size nor its fee is folded into
the spend figure. The bare script is below the legacy 10,000-byte script
limit, and the observed spend satisfies consensus; it is not relay-standard.

## Reproduce and limitations

```sh
cargo test --locked --example binohash_four_mode_pinning
python3 tools/binohash_four_mode_pinning_regtest.py --download-core
cargo test --locked --test primitive_metrics binohash_four_mode
```

This checks four-mode *composition and field commitments* at a tiny work
factor. It does not reproduce the paper's two-round subset grinding, 9-byte
SIGHASH_SINGLE anchor, collision resistance, authenticated Script extraction,
or a full protocol cost. The signatures are public fixtures, and the bare
prevout is funded by direct block construction because default policy rejects
the spend. P2SH, P2WSH, and tapscript are separate execution contexts; this
result applies to bare legacy Script. The [reported protocol](../../knowledge/primitives/binohash.md)
and [OP-011](../../knowledge/open-problems.md#op-011--reproduce-binohash)
remain open.

Primary sources: [Binohash §3.1](https://robinlinus.com/binohash.pdf) and
Bitcoin Core's pinned [`SignatureHash` implementation](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).
