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
- **Comparison objective:** Establish the deterministic core boundary before
  attempting grinding or complete regtest validation.
- **Execution class:** host-side legacy serialization; `unclassified`.
- **Hard constraints:** deletion only at Script opcode boundaries; raw sighash
  flags preserved; no tapscript or policy assumptions.

## Reproduction

```sh
cargo test --locked binohash --lib
```

The external reference suite can be checked with:

```sh
PYTHONPATH=src uv run --with python-bitcoinlib python -m unittest discover -s tests -p 'test_*.py'
```

## Result

The Rust core passes four focused tests: aligned deletion, subset-dependent
legacy digests, the `SIGHASH_SINGLE` bug constant, and hostile input handling.
The external experiment repository passes eight covered Python tests. No
complete transaction or Core differential result is claimed.
