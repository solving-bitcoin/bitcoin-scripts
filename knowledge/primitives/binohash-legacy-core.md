# Binohash legacy core

This contribution reproduces the deterministic core of a Binohash-style
transaction digest: legacy `FindAndDelete` removes selected serialized
signature pushes from `scriptCode`, and the resulting script is passed to the
legacy signature-hash algorithm.

## Scope

The helper accepts a transaction, input index, raw `scriptCode`, candidate
dummy-signature byte vectors, selected candidate indices, and a raw legacy
sighash type. It returns the 32-byte legacy digest. Deletion is performed only
at opcode boundaries, matching the legacy signature-hash construction model.

The host helper stops before the probabilistic parts of the published
Binohash protocol. A separate fixed two-choice fixture constructs valid ECDSA
signatures and executes complete legacy `OP_CHECKMULTISIG` spends. It does not
grind signatures, prove the two-round collision/work bound, or expose a digest
to a Script consumer.

## Evidence

Evidence is `locally-reproduced` for the deterministic core. Focused tests
cover opcode-boundary deletion versus embedded bytes, subset-dependent digest
changes, invalid selection/input errors, and the out-of-range-input
`SIGHASH_SINGLE` digest constant. The external
[`binohash-experiments`](https://github.com/aaron-recompile/binohash-experiments)
suite also passes its eight covered Python tests with `PYTHONPATH=src` and
`python-bitcoinlib`.

The [six-mode mutation matrix](../../research/binohash-sighash-matrix/README.md)
checks eight transaction-field mutations against a fixed two-input,
two-output host-side template. It separates the `ALL`, `NONE`, `SINGLE`, and
`ANYONECANPAY` commitment boundaries and reproduces the non-committing
out-of-range `SIGHASH_SINGLE` digest. Its evidence is `locally-reproduced` and
its execution class is `unclassified`; it does not execute a signed spend.

The host-only configuration remains `locally-reproduced` and `unclassified`.
The [funded two-choice fixture](../../research/binohash-legacy-core/README.md)
is `differentially-validated` against pinned Bitcoin Core v30.3 commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`. Core mines both selected
spends under consensus and rejects both unchanged puzzle signatures when their
pool selection is flipped. This checks the local digest through ECDSA
verification, rather than comparing a Core-exposed digest. Core's default
relay policy rejects even the valid spends with `Signature is found in
scriptCode`, so this configuration is `consensus-validated`, not
`policy-validated`.

The P2SH locking scriptPubKey is 23 bytes and its raw redeemScript is 220
bytes. Complete two-input, one-output valid
transactions weigh 1,744 and 1,740 WU, including scriptSigs of 2 and 297/296
bytes respectively. No witness or hint items are used. Maximum combined stack
peak and executed opcodes were not measured. The
[checked report](../../tests/data/binohash-core-v30.3.json) records both full
serialized transactions, Core verdicts, and archive/binary hashes. These are
costs of a reduced two-choice fixture, not of full Binohash.

## Security and limitations

This is not a cryptographic security claim for Binohash. FindAndDelete and
legacy sighash behavior are necessary mechanics, not sufficient evidence for
the paper's collision-resistance or honest-work bounds. The candidate set,
selection rule, transaction template, ECDSA signature validity, and downstream
Script authentication all remain protocol obligations.

See the [implementation README](../../src/introspection/README.md), the
[transaction-introspection protocol page](../protocols/transaction-introspection.md),
and `OP-011`.
