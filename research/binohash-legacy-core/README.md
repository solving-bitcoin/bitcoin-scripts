# Binohash legacy core reproduction

- **Question:** Can the deterministic FindAndDelete plus legacy-sighash core of
  Binohash be reproduced locally without conflating it with tapscript execution?
- **Hypothesis:** Opcode-boundary deletion followed by rust-bitcoin's legacy
  sighash gives a stable subset-dependent digest, including the historical
  `SIGHASH_SINGLE` bug constant.
- **Threat model:** Candidate signatures and selected indices are hostile;
  malformed selections and invalid input indices must fail. Full Binohash
  security additionally requires valid legacy signatures and a pinned transaction
  template.
- **Comparison objective:** Compare two selected signature pushes and their
  corresponding signed digests against complete funded Bitcoin Core spends.
- **Execution class:** host-side digest serialization is `unclassified`; the
  funded two-choice spends are `consensus-validated` and fail default policy.
- **Hard constraints:** deletion only at Script opcode boundaries; the raw
  sighash flag fits the single trailing legacy ECDSA signature byte; no
  tapscript or policy assumptions.

## Reproduction

```sh
cargo test --locked binohash --lib
cargo test --locked --example binohash_core_fixtures
python3 tools/binohash_core_regtest.py --download-core
python3 -m unittest discover -s tools -p 'test_binohash_core_regtest.py'
```

The external reference suite can be checked with:

```sh
PYTHONPATH=src uv run --with python-bitcoinlib python -m unittest discover -s tests -p 'test_*.py'
```

## Result

The Rust core covers aligned deletion, subset-dependent legacy digests, the
`SIGHASH_SINGLE` bug constant, hostile input handling, and the one-byte sighash
boundary. With one fixed transaction and scriptCode, the raw rust-bitcoin
digests for `0x00` and `0x100` differ; the helper accepts `0x00` and `0xff`
but rejects `0x100` and larger values. This prevents a host-only digest from
being mistaken for one selectable by a legacy ECDSA signature. It does not
establish default relay policy acceptance for `0xff`; see
[NR-111](../../knowledge/negative-results/index.md#nr-111-high-byte-legacy-sighash-types-are-host-only-digests).
The external experiment repository passes eight covered Python tests. The
checked [Core v30.3 report](../../tests/data/binohash-core-v30.3.json) records
two complete funded legacy P2SH spends, each with a different selected pool
signature. Both reach a valid block under Core consensus, while default relay
policy rejects them with `Signature is found in scriptCode`. Switching the
selection without re-signing the puzzle fails consensus for each spend.

The fixture uses two public test keys, fixed deterministic ECDSA signatures,
one output, and the legacy `SIGHASH_SINGLE` bug at input index 1. It performs
no grinding and does not extract a digest into Script. The two transactions
spend disjoint pairs of confirmed P2SH outputs; the first input is an `OP_TRUE`
funding helper and the second executes the Binohash-style redeemScript. The
P2SH locking scriptPubKey is 23 bytes; the redeemScript is 220 raw consensus
bytes. The selected transactions weigh 1,744
and 1,740 WU, including both inputs, their scriptSigs, one output, and no
witness. There are **zero hint items** and zero witness items. Combined stack
peak and executed opcode count are not measured. These fixed example costs
must not be extrapolated to the paper's two-round protocol.

The raw redeemScript deliberately bypasses the repository's generated-script
optimizer: exact embedded signature pushes are the behavior under test. This
exception is confined to the Core fixture and does not change the compilation
policy for generated scripts.

## Parameters and stack contract

The fixture fixes two candidate signatures, one selected signature per spend,
two transaction inputs, one output, a 1,000,000-sat value per input, and a
20,000-sat spend fee. The Core runner supplies a confirmed funding txid and
destination script; the generator has no default for either. The host digest
helper separately takes the transaction, input index, raw scriptCode, candidate
signature vectors, selected indices, and sighash flag, with no defaults. Its
public `u32` flag argument must be in `0x00..=0xff`; a larger value returns
`InvalidHashType` before digest construction.

The P2SH scriptSig pushes a CHECKMULTISIG dummy, a puzzle signature, a branch
selector, and the redeemScript. The branch pushes one embedded pool signature;
the redeemScript then checks the puzzle and pool signatures with
`OP_CHECKMULTISIG` and ends with its boolean result. Both branches are
complete locking conditions. Exact combined main-plus-alt-stack peak is
unmeasured, so the fixture does not establish a repetition bound under the
1,000-item limit.

## Compatibility, security, and integration

This exact construction uses legacy P2SH sighash semantics. P2WSH and
tapscript use different signature-hash rules and are not validated by this
fixture; the raw redeemScript is not offered as a bare-script spend. The
candidate signatures are public test fixtures, not one-time secrets. Their
selection is controlled by the scriptSig, so a real protocol must bind its
grinding and mutation rules and must authenticate any extracted digest.
Default Core policy rejects the valid transactions; direct block inclusion
here demonstrates only consensus validity.

The corresponding catalog configuration is
`introspection/binohash-legacy-core#funded-two-choice-core-v30.3`. The
[primitive page](../../knowledge/primitives/binohash-legacy-core.md) and
[comparison](../../knowledge/comparisons/introspection.md) retain separate
boundaries for the host helper, funded fixture, and reported full protocol.
`OP-011` tracks the remaining work.
