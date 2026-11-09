# Legacy transaction introspection

This module contains host-side research helpers for transaction-dependent
legacy Script behavior. They are not tapscript fragments and must not be
executed with the repository's default tapscript-only assumptions.

## Binohash core

`binohash::find_and_delete` removes canonical serialized signature pushes only
when they occur at parsed Script opcode boundaries. It removes repeated exact
pushes, but leaves non-minimal encodings and matching bytes inside another
push's payload untouched. This matches Bitcoin Core v30.3 commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`; truncated payload and
incomplete `PUSHDATA2`/`PUSHDATA4` length-header tests check parser parity
only and are not consensus-valid Script evidence.
`binohash::binohash_digest` then passes the mutated `scriptCode` to
rust-bitcoin's legacy sighash implementation. This reproduces the deterministic
mutation boundary used by a Binohash-style subset grind. A separate
[funded Core fixture](../../research/binohash-legacy-core/README.md)
constructs fixed ECDSA signatures and executes two complete P2SH spends. The
proof-of-work search and digest extraction into Script remain outside this
helper.

The focused tests cover canonical direct/`PUSHDATA1`/`PUSHDATA2` deletion,
embedded and non-minimal encodings, malformed parser termination,
subset-dependent digests, the legacy `SIGHASH_SINGLE` bug constant, invalid
selections, and invalid input indices. The host helper alone remains
`unclassified`; the separate funded configuration is
`differentially-validated` against Core v30.3 and `consensus-validated`, but
fails default relay policy. The PUSHDATA boundary tests use arbitrary byte
vectors to exercise the public host helper; they do not claim that vectors
larger than Bitcoin's DER-signature bound are valid signatures.
