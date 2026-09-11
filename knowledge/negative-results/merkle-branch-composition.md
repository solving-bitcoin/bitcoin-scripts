# Standard Merkle branch composition without `OP_CAT`

## Question

Can the repository's existing commitment primitives verify a conventional
Bitcoin Merkle branch, whose step hashes `HASH256(left || right)`, while
keeping the current Script opcode set and a useful cost boundary?

## Result

Not with the compact unary hash-path interface. Bitcoin Script hashes one
stack element at a time, while `OP_CAT` is disabled. Two sibling stack items
therefore cannot be assembled into the 64-byte preimage required by a standard
Merkle step. The existing mixed-hash path is not a substitute: it repeatedly
hashes one state item with unary SHA-256 or RIPEMD-160 and adds a terminal
RIPEMD-160, rather than authenticating a left/right concatenation.

The closest local workaround is the existing byte-oriented SHA-256 generator
over 64 one-byte stack items. A deterministic compile-only probe measured:

| Boundary | Script bytes | Static non-push opcodes | Maximum witness bytes | Hints |
| --- | ---: | ---: | ---: | ---: |
| One 64-byte SHA-256 layer | 1,060,200 | 770,481 | 129 | 0 |

The 129-byte witness is the maximum serialized witness for 64 one-byte data
items and excludes a separate orientation item. This is only the first SHA-256
layer; standard Bitcoin Merkle branches require double SHA-256, per-level
left/right routing, and conversion of the 32-byte result into the next
64-byte input. Those costs are not included, so the measured row is a lower
boundary for the workaround rather than a complete verifier metric.

The closest existing construction is the 31-bit mixed-hash path at 520 script
bytes, 78 witness bytes, and a 34-item measured peak, but it commits to a
different unary hash-state function. Treating it as a Merkle proof would be a
semantic error, not an optimization.

Evidence is `locally-reproduced` for the workaround serialization and
`inspected` for the opcode/semantic boundary. No consensus, policy, or
cryptographic deployment claim is made.

Reproduce the pinned boundary with:

```sh
cargo run --locked --example merkle_branch_boundary
```

Primary references: `bip-342` and `fips-180-4` in
`knowledge/references/sources.json`; the disabled-opcode rule is detailed in
`knowledge/bitcoin-script-reference.md`.

## Follow-up

Close this result only after a standard `HASH256(left || right)` branch is
implemented with an enabled concatenation primitive or a purpose-built bounded
compression circuit, then measured with direction bits, malformed sibling
encodings, extra witness items, double hashing, and a strict combined-stack
execution test.
