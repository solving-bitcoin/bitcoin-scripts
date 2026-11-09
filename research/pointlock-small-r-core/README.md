# Funded G/2 small-R point-lock differential

- **Question:** Does the existing 40-byte legacy `G/2` point lock admit an
  honest funded P2SH spend under Bitcoin Core consensus and default relay
  policy, while rejecting an otherwise valid ECDSA signature over the 60-byte
  limit?
- **Comparison objective:** Compare the same confirmed prevout and actual
  SIGHASH_ALL digest with an honest `G/2` signature and an ordinary long
  signature. Check that the signature Core decodes yields the public test
  scalar through the local extractor.
- **Threat boundary:** The point lock accepts *any* valid signature of at most
  60 bytes. This experiment does not establish a generic forgery bound, a
  complete Binohash protocol, or bare/P2WSH deployment.
- **Evidence:** `differentially-validated` for this one complete P2SH spend;
  honest spend `policy-validated`, overlength control
  `consensus-incompatible`.

## Reproduce

```sh
cargo test --locked --example pointlock_small_r_core_fixtures
python3 -m unittest discover -s tools -p 'test_pointlock_small_r_regtest.py'
python3 tools/pointlock_small_r_regtest.py --download-core
python3 tools/kb.py validate
```

The [checked report](../../tests/data/pointlock-small-r-core-v30.3.json) used
Bitcoin Core v30.3, commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`. The runner verifies the
official archive checksum before extraction, starts an isolated, walletless
regtest node, mines and confirms a P2SH funding output, probes policy with
`testmempoolaccept`, and probes consensus with `generateblock`. It compares
Core-decoded transaction identity, weight, size, scriptSig and the published
signature against the Rust fixture. All keys are fixed public test vectors;
there is no RNG. The node has no P2P connections and uses no real funds.

The generator uses the repository's `compile_with_policy()` output for every
script byte, signature hash, P2SH commitment, and metric. The complete lock is
`OP_SIZE 60 OP_LESSTHANOREQUAL OP_VERIFY <T> OP_CHECKSIG`; unlike the local
legacy interpreter test, the Core fixture uses no NOP padding. The legacy
SIGHASH_ALL digest comes from the actual transaction and redeemScript.

## Checked result

| Case | Signature item | P2SH scriptSig | Complete transaction | Core consensus | Default relay policy |
| --- | ---: | ---: | ---: | --- | --- |
| Known `G/2` nonce | 60 bytes | 102 bytes | 784 WU / 196 vB | accepted in block 103 | accepted |
| Ordinary ECDSA nonce | 72 bytes | 114 bytes | 832 WU / 208 vB | rejected at `OP_VERIFY` | rejected at `OP_VERIFY` |

The locking P2SH scriptPubKey is 23 bytes; the redeemScript is 40 bytes and is
already included in each scriptSig. Each transaction has one legacy input and
one output. There are zero witness items and zero hint items per invocation;
all one signature data items are present at script entry. The local fragment
has a three-item main-plus-alt-stack peak and four executed non-push opcodes.
The complete Core transaction's peak and executed opcode count are not
measured, so no batched composition bound is inferred from that local peak.
The funding transaction and refund branches are excluded from spend weight.

The fixed signing key is `07` repeated 32 times, with public point `T = tG`.
The local `extract_from_g_half` helper tries both nonce signs after low-S
normalization and recovers this exact scalar from the honest signature and
actual digest. Core's decoded scriptSig contains those same signature bytes.
This checks extraction for the honest path; it does not make the script a proof
that every accepted signature used the `G/2` nonce.

The primary construction source is the [Binohash paper](https://robinlinus.com/binohash.pdf),
sections 2.1.1–2.1.4. The script implementation and extraction relation are
described in the [point-lock primitive page](../../knowledge/primitives/point-locks.md).
`OP-017` tracks the unresolved generic security bound and remaining deployment
configurations.
