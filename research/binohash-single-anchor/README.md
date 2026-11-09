# Nine-byte legacy SIGHASH_SINGLE anchor

- **Question:** Can a strict-DER nine-byte ECDSA signature with a recovered
  public key be embedded in a legacy locking script so that it verifies only
  when the historical `SIGHASH_SINGLE` out-of-range condition holds?
- **Comparison objective:** Compare one valid funded P2SH spend with two
  otherwise identical boundary-crossing controls under pinned Bitcoin Core
  v30.3 consensus and default relay policy.
- **Execution class:** `differentially-validated`, `consensus-validated` for
  the valid funded spend. Default relay policy rejects it.

## Parameters

The generator requires a funding txid and destination script; neither has a
default. It fixes two 1,000,000-sat P2SH inputs, a 20,000-sat spending fee,
and a deterministic DER signature with `r = s = 1` and sighash byte `0x03`:
`30 06 02 01 01 02 01 01 03`. The first eight bytes are the DER sequence;
`0x06` is the length of the enclosed six bytes, and the ninth byte is the
legacy `SIGHASH_SINGLE` flag. The public key is recovered for the fixed digest
`01 00…00` using recovery ID 0 and checked by local ECDSA verification. This
is a public test vector; no key secrecy is claimed.

The anchor redeemScript embeds that signature and the recovered compressed
public key, followed by `OP_CHECKSIG`. The scriptSig supplies only the
redeemScript. A separate P2SH `OP_TRUE` input occupies index 0. With one
output, the anchor is at input index 1, so Core's legacy `SIGHASH_SINGLE` bug
uses the fixed digest. The controls add a second output or move the anchor to
input index 0. Both make the selected output index exist, and the same
signature fails.

## Reproduction and metrics

```sh
cargo test --locked --example binohash_single_bug_anchor
python3 tools/binohash_single_anchor_regtest.py --download-core
python3 -m unittest discover -s tools -p 'test_binohash_single_anchor_regtest.py'
```

The checked [Core report](../../tests/data/binohash-single-anchor-v30.3.json)
pins commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`, the release
archive hash, and the binary hash. Two fresh-node runs were byte-identical.
The P2SH locking scriptPubKey is 23 bytes, its raw redeemScript is 45 bytes,
and the complete valid two-input, one-output transaction weighs 732 WU. Its
scriptSigs are 2 and 46 bytes. These costs include both inputs, all scriptSig
bytes, one output, and complete serialization; they exclude the funding
transaction and every other Binohash stage. There are zero witness items and
zero hint items. The combined main-plus-alt-stack peak and executed opcode
count were not measured.

The valid transaction is mined under Core consensus, while both controls fail
at `OP_CHECKSIG`. Default mempool policy rejects the valid transaction with
`Signature is found in scriptCode` (`CONST_SCRIPTCODE`); block inclusion is
therefore not a default-relay result.

## Security and compatibility

The embedded signature is transaction-independent only while the anchor input
index is at least the output count. It does not pin any transaction field or
provide Binohash collision resistance. The recovered public key is a test
artifact and does not authenticate a user. The raw script intentionally avoids
the repository's generated-script optimizer because exact embedded bytes are
the consensus behavior under test. This is a legacy P2SH fixture. P2WSH and
tapscript use different sighash rules and are not exercised; bare legacy
script is not exercised. The script ends in one CHECKSIG boolean, so a valid
spend has a clean final stack.

The catalog record is `introspection/binohash-single-anchor`. See its
[primitive page](../../knowledge/primitives/binohash-single-anchor.md), the
[comparison](../../knowledge/comparisons/introspection.md), and
[OP-011](../../knowledge/open-problems.md#op-011--reproduce-binohash). The
primary source is [Binohash §2.3–2.4](https://robinlinus.com/binohash.pdf);
the oracle is pinned to [Bitcoin Core's legacy signature-hash code](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).
