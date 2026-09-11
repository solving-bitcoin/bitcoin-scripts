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

The implementation deliberately stops before the probabilistic parts of the
published Binohash protocol: it does not grind ECDSA signatures, prove the
two-round collision/work bound, execute a complete legacy `OP_CHECKMULTISIG`
spend, or expose transaction fields to a Script consumer.

## Evidence

Evidence is `locally-reproduced` for the deterministic core. Focused tests
cover opcode-boundary deletion versus embedded bytes, subset-dependent digest
changes, invalid selection/input errors, and the out-of-range-input
`SIGHASH_SINGLE` digest constant. The external
[`binohash-experiments`](https://github.com/aaron-recompile/binohash-experiments)
suite also passes its eight covered Python tests with `PYTHONPATH=src` and
`python-bitcoinlib`.

The execution class is `unclassified`: the helper uses rust-bitcoin's legacy
sighash serializer, but no complete transaction has been compared against a
pinned Bitcoin Core regtest from this repository.

## Security and limitations

This is not a cryptographic security claim for Binohash. FindAndDelete and
legacy sighash behavior are necessary mechanics, not sufficient evidence for
the paper's collision-resistance or honest-work bounds. The candidate set,
selection rule, transaction template, ECDSA signature validity, and downstream
Script authentication all remain protocol obligations.

See the [implementation README](../../src/introspection/README.md), the
[transaction-introspection protocol page](../protocols/transaction-introspection.md),
and `OP-011`.
