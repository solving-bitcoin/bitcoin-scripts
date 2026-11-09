# Legacy SIGHASH_SINGLE bug pinning-skip regression

- **Question:** Which transaction-field changes can preserve an embedded
  legacy `SIGHASH_SINGLE` signature when its input index remains outside the
  output range?
- **Comparison objective:** Apply eight single-field mutations and one combined
  mutation to disjoint, funded two-input P2SH spends. Compare the local
  `FindAndDelete`-aware digest with pinned Bitcoin Core v30.3 consensus and
  default relay policy. Cross the input/output boundary in two controls.
- **Evidence:** `differentially-validated`; the nine mutant spends are
  `consensus-validated` in a block and two controls are rejected by Core block
  validation. Default policy rejects all nine valid spends under
  `CONST_SCRIPTCODE`; none is `policy-validated`.

The redeemScript pushes the fixed nine-byte DER-plus-flag signature
`300602010102010103`, its recovered compressed public key, and `OP_CHECKSIG`.
The first input is a P2SH `OP_TRUE` spend. With one output and the anchor at
input index 1, the legacy `SIGHASH_SINGLE` bug returns `01 00…00` before it
serializes transaction fields. The signature is embedded in `scriptCode`, so
Core's legacy `FindAndDelete` removes it during `OP_CHECKSIG`. This is a public
test vector, not a secret key or a Binohash security construction.

| Mutation from the base template | Bug digest retained | Core block result |
| --- | :---: | --- |
| Version | yes | accepted |
| Locktime | yes | accepted |
| Selected prevout | yes | accepted |
| Selected sequence | yes | accepted |
| Other prevout | yes | accepted |
| Other sequence | yes | accepted |
| Output value | yes | accepted |
| Output script | yes | accepted |
| All eight fields together | yes | accepted |
| Add a second output | no | rejected |
| Move anchor to input index 0 | no | rejected |

The funding transaction provides a distinct pair of confirmed prevouts for
each row, plus alternate outputs for both prevout-mutation rows. Pair rebasing
changes transaction bytes between rows but cannot affect the bug digest. Each
row retains one output, places the anchor at input index 1, and uses the exact
same embedded signature and redeemScript. The locktime mutation to height 1 is
already final on the funded chain; the sequence changes keep BIP68 disabled.
The two controls make the selected output index exist, so Core computes a
transaction-dependent digest and rejects the unchanged signature. A fixed
public test input and no RNG make the generator deterministic.

## Reproduce and costs

```sh
cargo test --locked --example binohash_single_bug_pinning_skip
python3 tools/binohash_single_bug_pinning_skip_regtest.py --download-core
python3 -m unittest discover -s tools -p 'test_binohash_single_bug_pinning_skip_regtest.py'
```

The [checked report](../../tests/data/binohash-single-bug-pinning-skip-v30.3.json)
records the pinned Core release, archive and binary hashes, node options,
funding transaction, every serialized spend, local digest, and verdict. The
P2SH locking scriptPubKey is 23 bytes and the anchor redeemScript is 45 bytes.
Each spend has two inputs, one output, zero witness items and **zero hint
items**. The seven variants retaining the original destination weigh 732 WU;
the output-script and combined variants weigh 688 WU. Each has 2-byte and
46-byte scriptSigs. The report records every complete transaction weight and
both scriptSig lengths. These costs exclude the separate funding transaction. Combined stack
peak and executed opcode count are unmeasured.

This is an adversarial boundary regression: a `SIGHASH_SINGLE` signature used
while its selected output is absent cannot pin transaction version, locktime,
inputs, sequences, or the existing output in this fixture. The result does not
reproduce the full two-round Binohash grind, a chosen digest or a Script
consumer. A protocol relying on a signature to bind any of these fields must
supply a separate authenticated predicate or ensure the selected output exists.
The valid spends are consensus accepted but default-policy rejected because
Core finds the signature in `scriptCode`.

Primary sources: [Binohash §2.3–2.4](https://robinlinus.com/binohash.pdf),
[Bitcoin Core v30.3 legacy sighash and interpreter](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp),
and the [pinned release manifest](../../tools/bitcoin_core_release.json).
