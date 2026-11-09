# Legacy sighash-byte consensus and policy census

- **Question:** Can every raw ECDSA sighash flag byte sign a legacy P2SH spend
  under consensus, and which bytes pass default relay policy?
- **Comparison objective:** Sign 256 otherwise identical one-input, one-output
  P2SH templates, each funded by a distinct confirmed output, using every
  byte `0x00..0xff`. Compare rust-bitcoin's local legacy digest and ECDSA
  signature with pinned Bitcoin Core v30.3 block and mempool verdicts.
- **Execution class:** `differentially-validated`, `consensus-validated` for all
  256 signed spends. Only the six canonical flag-byte configurations are
  `policy-validated` under this node's documented default policy. The other
  250 are consensus-valid but policy-rejected.

## Reproduce

```sh
cargo test --locked --example binohash_sighash_flag_fixtures
python3 tools/binohash_sighash_flags_regtest.py --download-core
python3 -m unittest discover -s tools -p 'test_binohash_sighash_flags_regtest.py'
```

The [checked report](../../tests/data/binohash-sighash-flags-v30.3.json)
records the pinned Core release/commit and archive/binary hashes, a confirmed
funding transaction, all 256 local digests and policy results, one complete
sample transaction, and the block containing all 256 disjoint spends. Two
fresh-node runs produced byte-identical reports. The node has
`-acceptnonstdtxn=0`; `testmempoolaccept` was called on each funded spend
before mining. Exactly `01`, `02`, `03`, `81`, `82`, and `83` were accepted by
policy. Each other byte was rejected as `Signature hash type missing or not
understood`, yet all 256 transactions were accepted together in one Core block.
Changing the `01` signature's trailing flag to `21` without re-signing failed
consensus; sharing `ALL` field coverage does not make those raw flags
interchangeable. A separate host calculation holds the outpoint and every
other transaction field fixed; its 256 raw-flag digests are distinct. The
funded spends necessarily use different outpoints to avoid double-spending.

## Parameters and costs

The deterministic generator uses public test key `[7;32]`, one confirmed
100,000-sat P2SH prevout per flag, a 10,000-sat spend fee, one P2WSH destination
output, and no RNG. The redeemScript is `<compressed pubkey> OP_CHECKSIG` (35
bytes); the P2SH scriptPubKey is 23 bytes. Complete signed transactions weigh
804–812 WU, with 107–109-byte scriptSigs. The canonical `01` sample weighs
808 WU with a 108-byte scriptSig. These measurements include the complete
one-input, one-output spend and scriptSig but exclude the separate funding
transaction. There are zero witness items and **zero hint items** in each
spend. Combined stack peak and executed opcode count are unmeasured.

## Boundary

This fixture uses a plain P2SH `OP_CHECKSIG` to isolate raw flag handling. It
does not embed or delete signature pushes, select subsets, grind a puzzle, pin
transaction fields, or authenticate a Binohash digest. The 256 distinct local
digests in one template do not establish independence, usable entropy, or any
collision-security bound for the paper's construction. A protocol that uses
noncanonical flag bytes must account for their default-policy rejection and
their interaction with every other signature in its full script. `OP-011`
remains open.

Primary sources: [Binohash §2.4](https://robinlinus.com/binohash.pdf),
[Bitcoin Core v30.3 interpreter](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp),
and the [pinned Core release manifest](../../tools/bitcoin_core_release.json).
