# NR-064: Standard Merkle branch composition without `OP_CAT`

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

The measured profile is the existing byte-oriented `sha2_u32::sha256(64)`
generator over 64 one-byte stack items. A deterministic compile-only probe
measured:

| Boundary | Script bytes | Static non-push opcodes | Maximum witness bytes | Hints |
| --- | ---: | ---: | ---: | ---: |
| One 64-byte SHA-256 layer | 1,060,200 unoptimized | 770,481 | 129 fixture / 193 max | 0 |

The 129-byte witness is the one-byte fixture; canonical two-byte ScriptNum
payloads such as `[ff,00]` make the 64-item data witness 193 bytes. Both rows
exclude orientation, script and control-block items. This is only the first
SHA-256 layer; standard Bitcoin Merkle branches require double SHA-256,
per-level left/right routing, and conversion of the 32-byte result into the
next 64-byte input. Those costs are not included, so this is a
backend-specific compile-only profile, not a universal cost lower bound or a
complete verifier metric.

The existing 31-bit mixed-hash path is a different unary hash-state function,
not a Merkle proof. Taproot `TapBranch` is also a distinct tagged-SHA256
construction over lexicographically ordered nodes; see [NR-057](index.md#nr-057-native-taproot-merkle-branch-adapter-is-not-available),
[OP-021](../open-problems.md#op-021--taproot-merkle-path-verifier), and the
ordered-node work from PR #17.

Evidence is `locally-reproduced` for the serialization profile and
`inspected` for the opcode/semantic distinction. No consensus, policy, or
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
