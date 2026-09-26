# TapBranch tagged hash over u4 nodes

This fragment computes BIP341's `TapBranch` tagged SHA-256 hash over two
already ordered 32-byte nodes represented as 128 range-checked u4 stack items.
It returns the 32-byte digest as 64 most-significant-nibble-first items.

## Contract

The witness order is `left[0] ... left[63] right[0] ... right[63]`, with two
items per byte. Zero is the empty vector and `1..=15` is the one-byte numeric
encoding. The fragment checks numeric range before routing, but does not prove
minimal ScriptNum encoding. The caller must enforce `left <= right` in BIP341's
lexicographic byte order; the fragment intentionally does not add that
comparator.

The fragment inserts the fixed prefix
`SHA256("TapBranch") || SHA256("TapBranch")` and reuses the repository's u4
SHA-256 circuit. It is a fragment, not a complete locking script: callers must
add output comparison and a clean-stack terminal predicate.

## Evidence and cost

Evidence is `locally-reproduced`. Range-rejection, short-witness, and
surrounding-stack tests use the strict local tapscript-context helper, which
enforces stack and element limits but does not establish consensus or policy
validity. Digest vectors and reversed-order mismatch use the stack-disabled
`execute_script_with_inputs` helper and are `research-unlimited` execution
checks. Deployment is `unclassified`: no complete Bitcoin Core spend has been
validated.

| Fragment | Script bytes | Witness bytes | Witness items | Hints | Peak items |
| --- | ---: | ---: | ---: | ---: | ---: |
| `tapbranch_hash_u4()` | <!-- metric:tapbranch_hash_u4 -->1106723<!-- /metric:tapbranch_hash_u4 --> | <!-- metric:tapbranch_hash_u4_witness -->161<!-- /metric:tapbranch_hash_u4_witness --> | <!-- metric:tapbranch_hash_u4_witness_items -->128<!-- /metric:tapbranch_hash_u4_witness_items --> | <!-- metric:tapbranch_hash_u4_hints -->0<!-- /metric:tapbranch_hash_u4_hints --> | <!-- metric:tapbranch_hash_u4_stack -->969<!-- /metric:tapbranch_hash_u4_stack --> |

The generated script is above the repository's 32-KiB optimizer cutoff, so the
reported script size is unoptimized. Its static non-push opcode count is
<!-- metric:tapbranch_hash_u4_opcodes -->671155<!-- /metric:tapbranch_hash_u4_opcodes -->. Tapscript removes the legacy 10,000-byte script-size and 201-opcode
limits, but the 1,000-item combined stack limit, 520-byte element limit,
witness weight, and execution budget still apply. A complete transaction using
this fragment is expected to exceed standard transaction-weight policy; that
policy observation is not a consensus verdict.

## Open boundary

The compact native-byte adapter and in-script lexicographic ordering remain
open under [OP-021](../open-problems.md#op-021--taproot-merkle-path-verifier).
This circuit supplies a measured fixed-prefix construction, not a resolution
of that open problem.

## Reproduction

```sh
cargo test --locked commitments::tapbranch
cargo test --locked --test primitive_metrics tapbranch_metrics_are_current -- --exact
python3 tools/kb.py validate
```

The implementation is
[`src/commitments/tapbranch.rs`](../../src/commitments/tapbranch.rs), and the
construction follows [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki).
