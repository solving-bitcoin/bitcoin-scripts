# Funded committed ECDSA point lock

- **Question:** Does the existing SHA-256 committed point-lock predicate spend a
  funded legacy P2SH output under the historical SIGHASH_SINGLE bug, and do
  transaction-context and commitment mutations fail for the expected reasons?
- **Comparison objective:** Compare deterministic Rust-generated complete
  transactions, signature extraction, consensus verdicts, and default regtest
  relay-policy verdicts with Bitcoin Core v30.3, commit
  `49faec4f87f5cd19c88db01a82e5c68b087c8227`.
- **Execution class:** The exact funded valid P2SH transaction is
  `policy-validated`; the two controls fail consensus and policy.
- **Evidence:** `differentially-validated` for this exact fixture. No off-chain
  setup-proof backend or full Binohash protocol is exercised.

## Parameters and reproduction

The public signing scalar is `[02; 32]`, target scalar `[03; 32]`, and
substituted-signature nonce scalar `[04; 32]`. These are deterministic public
**test** values, not production secrets. The point lock uses the public key
`P = xG`, target `T = tG`, and exact commitment
`SHA256(DER(r,s) || 0x03) =
6722af45456e2349afdac2c3866299335433d5d02edd34b1af4dd8eb5b140a1d`.
The legacy bug digest bytes are `01` followed by 31 zero bytes. The point-lock
input is index 1 of two inputs, with only one output. Each confirmed P2SH
prevout carries 1,000,000 sat; the valid transaction pays a 20,000-sat fee.
The runner creates a fresh regtest node and supplies the confirmed funding
transaction ID and destination script to the Rust generator; neither has a
user default. Script generation uses `compile_with_policy()` and its final
71-byte redeemScript is fully optimized under the repository's 32-KiB cutoff.

```sh
cargo test --locked --example binohash_committed_point_core
python3 tools/binohash_committed_point_regtest.py --download-core
python3 -m unittest discover -s tools -p 'test_binohash_committed_point_regtest.py'
python3 tools/kb.py validate
```

The runner downloads the platform-specific Core release archive from the
[official v30.3 release](https://bitcoincore.org/bin/bitcoin-core-30.3/),
checks its hash against the pinned
[`SHA256SUMS`](https://bitcoincore.org/bin/bitcoin-core-30.3/SHA256SUMS),
and records the archive and binary hashes. The checked
[report](../../tests/data/binohash-committed-point-v30.3.json) is from the
macOS ARM64 release. A second fresh-node run produced byte-identical JSON.

## Result and costs

| Transaction | Change | Core consensus | Default regtest policy |
| --- | --- | --- | --- |
| Valid | Exact committed signature; input 1 has no corresponding output | Accepted in block | Accepted by `testmempoolaccept` |
| Wrong signature | Different valid ECDSA signature from the same public signing key | Fails `OP_EQUALVERIFY` | Fails `OP_EQUALVERIFY` |
| Added output | A second output gives input 1 a corresponding output | Fails final `OP_CHECKSIG` | Fails `NULLFAIL` |

The valid signature is 71 bytes including the `0x03` sighash flag. Local
extraction recovers `[03; 32]` from that signature and public signing scalar;
this checks the intended low-S sign correction. The controls isolate the two
on-chain dependencies: signature-byte commitment and historical bug placement.

The P2SH scriptPubKey is 23 bytes. The policy-produced redeemScript is 71
bytes. The complete valid two-input, one-output legacy transaction weighs
1,124 WU (281 bytes and vbytes), including scriptSigs of 2 and 144 bytes.
There are **zero hint stack items** and **zero witness items**; all unlocking
data is in the scriptSig. The point predicate has a three-item main-stack peak
when considered alone, but combined stack peak and dynamically executed opcode
count for the complete P2SH spend were not measured. No repeated or batched
configuration is claimed, so no composition bound under the 1,000-item
main-plus-alt-stack limit is inferred. The table above compares identical
funding, input, and output boundaries except for the stated mutation; the
added-output transaction necessarily has a larger output serialization.

## Stack, compatibility, and security boundary

The point scriptSig pushes the signature and redeemScript. The redeemScript
runs `OP_DUP OP_SHA256 <h> OP_EQUALVERIFY <P> OP_CHECKSIG`, leaving one truthy
item on success and no altstack state. The other P2SH input uses `OP_TRUE` to
place the point lock at index 1. The exact successful transaction is a clean
legacy P2SH spend and meets Core's default regtest relay policy. Bare legacy
opcode compatibility is separate from policy; P2WSH does not have the legacy
SIGHASH_SINGLE bug digest, and tapscript uses Schnorr rather than ECDSA.

The SHA-256 commitment authorizes these exact signature bytes. The scalar
`x` is public and is **not** an authorization secret. A real counterparty must
validate a byte-exact off-chain proof that committed DER `r` corresponds to
`x(T) mod n`, including encoding and target binding; that proof and its
soundness are not tested here. The bigint signing helpers are not constant-time.
This fixture does not test Binohash grinding, a Script-readable digest, or
whole-protocol security. See the [primitive page](../../knowledge/primitives/point-locks.md),
[implementation README](../../src/signatures/pointlocks/README.md), and
`OP-017` for the remaining work.
