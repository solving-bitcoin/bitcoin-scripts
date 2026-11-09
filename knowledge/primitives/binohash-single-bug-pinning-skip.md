# Binohash SIGHASH_SINGLE bug pinning-skip boundary

The [nine-byte anchor](binohash-single-anchor.md) validates a fixed embedded
legacy signature only when its input index exceeds the output count. The
[adversarial regression](../../research/binohash-single-bug-pinning-skip/README.md)
checks nine field mutations that keep this condition true: version, locktime,
selected and other prevouts, selected and other sequences, output value, output
script, and all eight together. The same signature and 45-byte redeemScript
produce the legacy `01 00…00` digest for every row. Pinned Bitcoin Core v30.3
commit `49faec4f87f5cd19c88db01a82e5c68b087c8227` confirms all nine
disjoint funded P2SH spends in a block. Adding a second output or moving the
anchor to input index 0 crosses the boundary, changes the local digest, and
causes direct Core block rejection. Evidence is `differentially-validated` and
execution is `consensus-validated` for this reduced fixture.

Default relay policy rejects the nine valid spends because the signature is
found in `scriptCode` (`CONST_SCRIPTCODE`), so none is `policy-validated`. Each
spend uses two inputs, one output, zero witness items and **zero hint items**.
The P2SH locking scriptPubKey is 23 bytes; the anchor redeemScript is 45
bytes. The seven variants retaining the original destination weigh 732 WU;
the output-script and combined variants weigh 688 WU. Both scriptSigs are 2
and 46 bytes. The [checked report](../../tests/data/binohash-single-bug-pinning-skip-v30.3.json)
records all serialized transactions, Core verdicts, release hashes and node
options. Costs exclude the separate funding transaction. Combined stack peak
and executed opcode count are not measured.

The bug digest commits to no transaction fields while the selected output is
absent. This is a pinning-skip regression, not a full Binohash grind or
collision-security result. A construction requiring those fields to be bound
needs a separate authenticated predicate or an existing selected output.
[OP-011](../open-problems.md#op-011--reproduce-binohash) remains open.
