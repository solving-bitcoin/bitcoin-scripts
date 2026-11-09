# Legacy Binohash sighash commitment matrix

- **Question:** Which transaction-field mutations alter the host-side legacy
  digest when one embedded signature push is selected for `FindAndDelete`?
- **Comparison objective:** Apply the same eight deterministic mutations to a
  two-input, two-output template under each of the six canonical ECDSA sighash
  flags, without changing the selected script or input index.
- **Execution class:** `locally-reproduced`, `unclassified`. The test invokes
  `binohash_digest` and rust-bitcoin's legacy serializer; it does not execute a
  locking script or ask Bitcoin Core for a consensus/policy verdict.

The selected input is index 1. Its `scriptCode` contains two distinct dummy
signature pushes followed by `OP_TRUE`; index 0 is deleted before hashing.
Input values are not part of the legacy sighash API. The table states whether
the digest changes after exactly one mutation (✓) or remains identical (—):

| Mutation | ALL | NONE | SINGLE | ACP&#124;ALL | ACP&#124;NONE | ACP&#124;SINGLE |
| --- | :---: | :---: | :---: | :---: | :---: | :---: |
| Version | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Locktime | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Selected prevout | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Selected sequence | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Other prevout | ✓ | ✓ | ✓ | — | — | — |
| Other sequence | ✓ | — | — | — | — | — |
| Selected output | ✓ | — | ✓ | ✓ | — | ✓ |
| Other output | ✓ | — | — | ✓ | — | — |

`ACP` means `ANYONECANPAY`. The test also removes the selected output, making
input index 1 exceed the output count. Under `SIGHASH_SINGLE` and
`ANYONECANPAY|SIGHASH_SINGLE`, the legacy bug then returns the same `01 00…00`
digest even after the version, selected prevout, and remaining output change.
That is a non-committing boundary, not a useful Binohash nonce.

Run `cargo test --locked --test binohash_sighash_matrix`. The test uses fixed
transaction fields and no RNG. It measures no script bytes, witness bytes,
stack peak, opcodes, validation budget, or complete transaction weight because
it does not build or execute a spend. There are no witness hints. A real pinning
claim needs signed spends, explicit puzzle checks, and Core validation for the
specific script and transaction template; `OP-011` remains open.

Primary sources: [Binohash §2.4 and §3.1](https://robinlinus.com/binohash.pdf)
and Bitcoin Core's
[`SignatureHash` implementation at `49faec4f`](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).
