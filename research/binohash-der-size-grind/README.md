# Deterministic exact DER-size ECDSA grind

- **Question:** With one fixed legacy transaction digest and key, can varying
  only ECDSA nonce data find a signature of a chosen serialized size that a
  Script predicate and Bitcoin Core both accept?
- **Comparison objective:** Compare the selected 70-byte signature with an
  otherwise valid 72-byte signature and a corrupted 70-byte signature in
  complete funded P2SH spends.
- **Evidence:** `differentially-validated`; the valid spend is
  `policy-validated` under pinned Bitcoin Core v30.3 default relay policy.

## Construction and parameters

The one-input, one-output transaction has a fixed legacy `SIGHASH_ALL` digest
throughout the nonce search. A public test key signs that digest with
`secp256k1::sign_ecdsa_with_noncedata`. For counter `i`, the 32-byte
additional nonce data is `SHA256(0x5a repeated 32 times || i as little-endian
u32)`. No RNG is used. The maximum is 10,000 candidates. The first exact
70-byte DER-plus-sighash signature occurs at counter **187**, after **188**
trials. Counter 0 produces a valid ECDSA signature of 72 bytes. These are
observations for this fixed funded transaction; they are not a work estimate
for the full Binohash protocol.

The policy-compiled redeemScript performs
`OP_SIZE 70 OP_EQUALVERIFY <compressed public key> OP_CHECKSIG`. Its final
boolean is the terminal predicate; the valid spend has a clean final stack.
The scriptSig pushes one signature followed by the redeemScript. Both the
70-byte and 72-byte signatures verify locally against the same ECDSA digest.
For the third control, one DER payload byte of the selected 70-byte signature
is changed while preserving strict DER and the sighash byte; it fails local
ECDSA verification.

Pinned Core accepts the selected signature into a block and under default
`testmempoolaccept` policy. It rejects the 72-byte signature at
`OP_EQUALVERIFY`, and rejects the corrupted 70-byte signature at
`OP_CHECKSIG`. The [checked report](../../tests/data/binohash-der-size-grind-v30.3.json)
records raw funding and spend transactions, the deterministic seed and
counter, signatures, digest, Core archive/binary hashes, and consensus and
policy verdicts. Core revision:
[`49faec4f87f5cd19c88db01a82e5c68b087c8227`](https://github.com/bitcoin/bitcoin/tree/49faec4f87f5cd19c88db01a82e5c68b087c8227).

## Costs and stack boundary

The complete P2SH locking scriptPubKey is 23 bytes; its policy-compiled
redeemScript is 39 bytes with three static non-push opcodes. The complete
legacy spend is **205 stripped and total bytes, 820 WU, and 205 vbytes**,
including the 111-byte scriptSig and one 990,000-sat output. It spends a
confirmed 1,000,000-sat output and pays a 10,000-sat fee. There are **zero
witness items, zero hint items, and zero serialized witness bytes**. Its
scriptSig has two data items at entry (signature and redeemScript); the
redeemScript consumes the signature. Exact Core stack peak and executed
opcode count were not measured. The separate funding transaction is 126
stripped bytes, 131 total bytes, 509 WU, and 128 vbytes; those costs are not
included in the spend figure.

## Reproduction and limits

```sh
cargo test --locked --example binohash_der_size_grind
python3 tools/binohash_der_size_grind_regtest.py --download-core
python3 -m unittest discover -s tools -p 'test_binohash_der_size_grind_regtest.py'
```

This is a single signature-size puzzle at modest difficulty. It does not
select a subset, pin multiple transaction fields, perform two rounds, extract
a digest into Script, or establish collision resistance. The secret key and
nonce seed are public test fixtures, so there is no one-time-key security
claim. The result applies to this legacy P2SH script; P2WSH and tapscript
have different signature-hash behavior. A full Binohash implementation still
requires the [OP-011](../../knowledge/open-problems.md#op-011--reproduce-binohash)
acceptance criteria.

Primary sources: [Binohash §3.1](https://robinlinus.com/binohash.pdf),
and [Bitcoin Core's pinned legacy signature-hash code](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).
