# Binohash legacy CODESEPARATOR and FindAndDelete comparison

- **Question:** Does pinned Bitcoin Core use the suffix after the last executed
  legacy `OP_CODESEPARATOR`, ignore a separator in a dead branch as a boundary,
  omit separator opcodes when serializing scriptCode, and apply
  `FindAndDelete` only within that operative suffix?
- **Comparison objective:** Authenticate four locally derived wrong scriptCode
  views against complete, independently funded Core spends.
- **Execution class:** `differentially-validated` and `consensus-validated` for
  this exact fixture; rejected by default relay policy.
- **Threat model:** A signer that uses the full redeemScript, a dead separator,
  an unstripped separator, or the wrong selected-signature set must not create a
  valid spend.

## Script and signing views

The P2SH scriptSig supplies the CHECKMULTISIG dummy, a puzzle signature, a
boolean selector, and the redeemScript. The redeemScript duplicates and saves
the selector, then follows this reduced structure:

```text
IF <pool-before> ENDIF
OP_CODESEPARATOR
NOTIF <pool-after> ENDIF
OP_0 OP_IF OP_CODESEPARATOR OP_ENDIF
2 <puzzle-key> <pool-key> 2 OP_CHECKMULTISIG
```

The actual generator includes the stack moves needed to preserve the selector.
The first separator is always executed. The second is parsed but lies in a dead
branch. The two fixed pool signatures are valid for the historical
`SIGHASH_SINGLE` bug digest at input index 1 with one output.

For the before-boundary selection, the supplied pool signature does not occur
in the operative suffix, so its `FindAndDelete` target is absent. For the
after-boundary selection, the canonical embedded pool-signature push is removed
from the suffix. In both cases, the unexecuted separator opcode is omitted when
serializing the legacy sighash scriptCode. rust-bitcoin intentionally delegates
`OP_CODESEPARATOR` evaluation to its caller, so the fixture records both the
raw suffixes and the exact separator-stripped scripts passed to its legacy
sighash API.

Each valid spend has four controls signed by the same puzzle key:

- `wrong_full_boundary`: signs from the beginning of the redeemScript;
- `wrong_dead_boundary`: treats the separator in the dead branch as executed;
- `wrong_retained_dead_separator`: keeps the parsed dead separator byte in the
  serialized scriptCode;
- `wrong_find_and_delete`: removes the after-boundary signature for the
  before-boundary selection, or fails to remove it for the after-boundary
  selection.

All five local digest views per selection are distinct. Core accepts the
correct spend and rejects all four controls under consensus.

## Reproduction

```sh
cargo test --locked --example binohash_codesep_fixtures
python3 tools/binohash_codesep_regtest.py --download-core
python3 -m unittest discover -s tools -p 'test_binohash_codesep_regtest.py'
```

The checked report pins Bitcoin Core v30.3 commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227` and the official archive and
binary hashes. A temporary isolated node runs with networking and wallet
disabled. The runner confirms two pairs of easy/P2SH outputs, probes rejected
controls without changing chain height, and mines the valid spends in separate
blocks.

## Costs and policy

- P2SH scriptPubKey: 23 bytes.
- RedeemScript: 229 bytes.
- Each complete valid spend: 1,780 WU, two inputs, one output.
- Valid input scriptSigs: 2 bytes and 306 bytes.
- Witness items: 0; hint items: 0.
- Combined main-plus-alt-stack peak and executed opcodes: unmeasured.

Every valid and control transaction is rejected by default mempool policy with
`Using OP_CODESEPARATOR in non-witness script`. Since that check occurs at the
executed separator, the report does not claim an independent policy verdict for
the later `FindAndDelete` mutation. Core block inclusion establishes consensus
validity only.

This is a fixed no-grinding fixture. It does not measure proof-of-work,
transaction pinning, two-round extraction, collision resistance, or Binohash
economics. Its public pool keys and signatures are test data, not one-time
authentication material.
