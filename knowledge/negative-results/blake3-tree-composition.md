# BLAKE3 tree composition boundary

## Question

Can the current Script BLAKE3 construction be extended to messages spanning
multiple 1,024-byte chunks without first adding a parent-node compression
primitive?

## Result

No. The public generator accepts at most 1,024 bytes and its block flags only
cover the chunk path: the first block receives `CHUNK_START`, the final block
receives `CHUNK_END`, and the one-chunk case receives both. The implementation
does not expose the BLAKE3 `PARENT` compression that combines two child chaining
values, nor the binary-tree scheduling needed to reduce multiple chunks to one
root.

The boundary is locally reproduced by the existing `test_max_length` and
`test_too_long` tests: a 1,024-byte input reaches the supported path, while a
1,025-byte input is rejected before script generation. This is an API-boundary
result, not a claim that multi-chunk BLAKE3 is impossible in Bitcoin Script.

The BLAKE3 specification requires chunk chaining and parent-node compression
for inputs beyond one chunk. The repository's existing single-chunk fragment
therefore cannot be priced as a tree verifier by extrapolating its 1,024-byte
configuration. No script-byte, witness-byte, or stack metric is reported for
the missing parent primitive.

## Follow-up

Implement a standalone parent compression fragment over two 32-byte child
chaining values, then compose it with two strict 1,024-byte chunk outputs.
Close this result only when the parent and two-chunk root match the pinned BLAKE3
reference vectors, reject malformed child-word encodings and extra witness
items, and report the complete tree's script, witness, and combined-stack
metrics under the repository execution class.

Evidence is `locally-reproduced` for the current length boundary and
`inspected` for the missing tree API. Deployment remains `unclassified` for
the absent construction.

Primary source: `blake3-spec` in `knowledge/references/sources.json`.
