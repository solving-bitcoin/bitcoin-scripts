# Checked u4 least-significant-bit projection

`arithmetic::u4::lsb::u4_nibbles_to_lsb` consumes a contiguous batch of
canonical four-bit limbs, proves each value is in `0..=15`, and replaces it
with its least-significant bit. It avoids materializing the other three bits
when a bit-oriented encoding needs only the low bit.

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top.
- **Output:** `preserved | lsb[0] | ... | lsb[n-1]`, with the last bit on top.
- **Evidence:** `differentially-validated` by all-nibble ordering tests,
  malformed input tests, batch-size boundary tests, a strict metric fixture,
  and one complete Taproot spend accepted by Bitcoin Core v30.3.
- **Representative result:** 440 locking-script bytes, 65 serialized witness
  bytes across 32 data items, 50 combined stack items, and no hints. The
  fragment contains 328 static non-push opcodes; this is not an executed-opcode
  or deployment claim.
- **Execution class:** `policy-validated` for the exact Core fixture below.
  The strict local executor uses a tapscript context and the combined stack
  limit; the broader 32-nibble fragment remains `unclassified`.

The fixture `u4-lsb-0123456789abcdef` supplies the sixteen canonical nibbles
`0..=15`, appends equality checks for the reversed output order, and is
accepted by both Bitcoin Core v30.3 consensus and its default relay policy.
The complete leaf uses 16 data items, zero hints, 264 locking-script bytes,
32 serialized data-witness bytes, and a 34-item local peak. Reproduce it with:

```sh
python3 tools/core_regtest.py --download-core \
  --output target/ci-reports/core-validation-u4-lsb.json
```

This validates one 16-nibble complete transaction, not the 32-nibble metric
configuration or arbitrary compositions.

This is a projection fragment, not a complete locking script. Callers still
need any terminal predicate, clean-stack rule, and byte-unique ScriptNum
binding required by their protocol.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-lsb`.
