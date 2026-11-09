# Binohash Appendix B single-round resource profile

The [static generator](../../examples/binohash_appendix_b_resources.rs) follows
the paper's Appendix B.1 single-round locking-script structure and compiles
it through the repository's script policy. The [checked report](../../tests/data/binohash-appendix-b-resources.json)
records `n=10,t=5` and `n=120/147/151,t=8`. Evidence is
`locally-reproduced` for serialized sizes and static opcode counts; execution
is `unclassified`.

At `n=120,t=8`, the final policy-produced locking script is 3,950 bytes,
versus the paper's approximate 3,964-byte single-round expression. It has 84
serialized non-push opcodes and would incur a 93-opcode Core count if its
`OP_CHECKMULTISIG` with nine public keys executes. The `n=147` and `n=151`
scripts are 4,803 and 4,927 bytes, two bytes above the corresponding paper
approximations. Number-push encoding changes across pool-size boundaries;
the approximate formula is not an exact byte budget. These are one-round
figures and exclude pinning and a second round.

The embedded nine-byte DER-shaped values are placeholders without ECDSA key
recovery; the twenty-byte values are not authenticated preimage commitments.
No unlocking script or witness is built. The [implementation README](../../research/binohash-appendix-b-resources/README.md)
defines the cost boundary and Core opcode accounting. The actual
stack peak, complete transaction weight, consensus verdict, and full
protocol resource margin remain open under [OP-011](../open-problems.md#op-011--reproduce-binohash).
