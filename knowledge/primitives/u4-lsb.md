# Checked u4 least-significant-bit projection

`arithmetic::u4::lsb::u4_nibbles_to_lsb` consumes a contiguous batch of
range-checked four-bit limbs, proves each value is in `0..=15`, and replaces it
with its least-significant bit. It avoids materializing the other three bits
when a bit-oriented encoding needs only the low bit.

- **Input:** `preserved | nibble[0] | ... | nibble[n-1]`, with the last nibble
  on top.
- **Output:** `preserved | lsb[0] | ... | lsb[n-1]`, with the last bit on top.
- **Evidence:** `locally-reproduced` by all-nibble ordering tests, malformed
  input tests at every position, preserved-state and batch-size boundary tests,
  and a strict metric fixture. A separately scoped complete Taproot spend is
  differentially validated by Bitcoin Core v30.3.
- **Representative result:** 440 locking-script bytes, 65 serialized witness
  bytes across 32 data items, 50 combined stack items, and no hints. The
  fragment contains 328 static non-push opcodes; this is not an executed-opcode
  or deployment claim.
- **Execution class:** `unclassified` for the reusable fragment. The separate
  complete-leaf fixture below is `policy-validated`.

The fixture `u4-lsb-0123456789abcdef` supplies nibbles `0..=15` in canonical
ScriptNum encodings, appends equality checks for the reversed output order, and is
accepted by both Bitcoin Core v30.3 consensus and its default relay policy.
The complete leaf uses 16 data items, zero incremental hints, and 18 total
witness items at entry (the sixteen data items, leaf script, and control block).
It has a 264-byte policy-compiled locking script, 184 static non-push opcodes,
32 serialized data-witness bytes, 333 serialized Taproot witness bytes, and a
34-item combined main/alt-stack peak under the strict local helper. The local
measurement uses `execute_raw_script_with_inputs_strict` in tapscript context;
it enforces the stack limit but does not perform full transaction validation.
Core v30.3 commit `49faec4f87f5cd19c88db01a82e5c68b087c8227` validates the
complete regtest spend under consensus and default relay policy. Reproduce it with:

```sh
python3 tools/core_regtest.py --download-core \
  --output target/ci-reports/core-validation-u4-lsb.json
```

This validates one 16-nibble complete transaction and terminal equality
predicate, not the 32-nibble metric configuration or arbitrary compositions.
The fragment measurement above retains its local evidence and deployment scope.

This is a projection fragment, not a complete locking script. Numeric range
checking does not establish canonical or byte-unique ScriptNum encoding.
Callers still need any terminal predicate and clean-stack rule required by
their protocol.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-lsb`.
