# Taproot Merkle-path verifier negative result

- **Question:** Can current Bitcoin Script verify one dynamic Taproot Merkle
  branch using only native byte-string/hash opcodes?
- **Hypothesis:** A compact native verifier is unavailable because TapBranch
  hashes the lexicographically ordered concatenation of two 32-byte nodes, but
  Script cannot concatenate or split arbitrary byte strings.
- **Comparison objective:** Distinguish the missing native byte boundary from
  the repository's mixed-hash path commitments, which deliberately nest fixed
  hash outputs and therefore do not implement TapBranch.
- **Threat model:** Leaf hashes, sibling nodes, and left/right selectors are
  hostile. A verifier that hashes an unbound 64-byte witness blob is unsound
  because it does not prove that the blob contains the separately supplied
  nodes.
- **Execution class:** `unclassified`; this is an inspected negative result,
  not an executed Script primitive.
- **Hard constraints:** no disabled opcode assumptions, no opaque host-side
  concatenation, and the Taproot `TapBranch` tag and lexicographic ordering
  must remain exact.

## Result

`OP_SHA256` hashes one stack item, but current Script has no enabled native
byte concatenation or split operation that can construct and bind
`left || right` from two hostile 32-byte stack items. The existing mixed-hash
path is not a substitute: it hashes a preimage through nested SHA256/RIPEMD160
branches and ends in HASH160, rather than reproducing TapBranch's tagged
SHA256. A u4 SHA256 circuit could implement the byte boundary, but that is the
full hash-circuit problem and requires a separate costed construction; no
compact native adapter is retained here.

The relevant local reference is
[`knowledge/bitcoin-script-reference.md`](../../knowledge/bitcoin-script-reference.md)
for opcode availability and Taproot branch semantics. See NR-047 and OP-020.
