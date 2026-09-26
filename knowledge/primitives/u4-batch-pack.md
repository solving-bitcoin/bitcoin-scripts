# Checked u4 batch nibble packing

## Question

Can a checked even-length u4 vector be packed into bytes in one stack-safe
fragment while preserving pair order and surrounding state?

## Construction

`u4_nibbles_to_bytes(n)` consumes `n` numeric nibbles and returns `n/2` bytes,
packing each adjacent high/low pair with the existing checked pair primitive.
The input vector remains on the main stack while packed outputs are staged on
the altstack, then the original inputs are removed and bytes are restored in
input order.

## Evidence

- evidence: `locally-reproduced`
- execution: `unclassified`
- representative configuration: 32 hostile nibble items, 16 output bytes
- comparison: batch scheduling versus repeated caller-managed pair fragments

The implementation tests all pair positions, invalid and odd widths, hostile
nibbles, exact ScriptNum boundary encodings, the combined stack frontier, and
surrounding main/alt-stack preservation. It is a fragment, not a complete
locking script, and makes no consensus, policy, or cryptographic-security
claim.

Malformed-input coverage uses four runtime witness items and exercises `-1`,
`16`, and a five-byte ScriptNum encoding at every position. The generated
fragment is compiled through `ScriptCompilation::compile_with_policy()` and run
with `execute_script_with_inputs_strict()`; the harness uses `OP_2DROP OP_TRUE`
to consume the two hypothetical outputs from a successful pack, so leftover
outputs cannot hide a missing range check. It distinguishes `OP_VERIFY`
failures from ScriptNum overflow. The valid control uses the same cleanup.
This helper runs in the repository's
pinned tapscript interpreter and enforces stack and witness-element limits, but
does not establish full consensus or relay-policy validity. Compiler and
interpreter commits are pinned in `Cargo.lock` and are available through
[`support::provenance`](../../src/support/provenance.rs).

## Limitations

The standalone batch ceiling is 664 nibbles before accounting for unrelated
live stack state. It emits byte ScriptNums, not raw byte-vector serialization;
callers must add terminal predicates and any encoding policy they require.
