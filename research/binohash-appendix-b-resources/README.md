# Binohash Appendix B single-round resource profile

- **Question:** What serialized locking-script sizes and legacy opcode charges
  result from the paper's Appendix B.1 single-round generator at its illustrative
  and proposed pool sizes?
- **Comparison objective:** Measure the repository policy-compiled bytecode
  alongside the paper's `244 + 31n` per-round size estimate for the same `n`
  and `t`. Keep this fragment separate from Stage 1 and two-round composition.
- **Evidence:** `locally-reproduced` for bytecode and static counts.
  **Execution class:** `unclassified`; this profile does not sign or spend.

## Construction

`examples/binohash_appendix_b_resources.rs` follows the pushes and opcodes of
[Binohash Appendix B.1](https://robinlinus.com/binohash.pdf). It uses `n`
distinct, deterministic, nine-byte DER-shaped signature placeholders, `n`
deterministic 20-byte hash placeholders, and a fixed compressed puzzle public
key. The source PDF had SHA-256
`1be2b63034a86db1f9f4a35c7963248d307583723079ff25284a9fc4affee94a`
when fetched on 2026-11-09. There is no random seed. The signatures are **not** recovered ECDSA
signatures and the hashes are **not** commitments to supplied preimages.
The example calls `ScriptCompilation::compile_with_policy()` on the complete
single-round generated script and counts the resulting serialized instructions.
All four configurations are below the 32 KiB optimizer cutoff, so their
reported bytes are the final optimized serialization.

Core's legacy `EvalScript` counts each opcode greater than `OP_16` and adds
the public-key count when `OP_CHECKMULTISIG` executes. The profile therefore
reports both the static non-push count and the conditional Core count with
`t+1` pubkeys. The conditional count is an arithmetic projection from
the serialized script and [Core v30.3 source](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp),
not an observed execution trace.

## Measured boundary

The checked [report](../../tests/data/binohash-appendix-b-resources.json)
records `n=10,t=5`, `n=120,t=8`, `n=147,t=8`, and `n=151,t=8`. Its locking
script includes the embedded signature and hash pushes, selection and hash
checks, puzzle-size check, puzzle public key, and terminal
`OP_CHECKMULTISIG`. It excludes the four pinning signatures, a second round,
any HORS/Lamport consumer, the unlocking script, funding and spending
transactions, and witness serialization. **No unlocking data, witness, or hint
items are supplied by this static profile**; their count, serialized bytes, and
combined main-plus-alt-stack peak need a complete executable fixture.

| `n,t` | Final policy bytes | Paper one-round estimate | Byte delta | Static non-push opcodes | Core charge if multisig executes | P2SH redeem limit |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `10,5` | 444 | not defined for `t=5` | — | 54 | 60 | fits 520 bytes |
| `120,8` | 3,950 | 3,964 | −14 | 84 | 93 | exceeds 520 bytes |
| `147,8` | 4,803 | 4,801 | +2 | 84 | 93 | exceeds 520 bytes |
| `151,8` | 4,927 | 4,925 | +2 | 84 | 93 | exceeds 520 bytes |

For `t=8`, each round contains `31n` bytes of nine-byte signature and
20-byte hash payloads including one-byte push prefixes. The residual 230
bytes at `n=120` and 246 bytes at `n=147/151` include the puzzle public key,
selection code, constants, and whole-script optimizer effects. Larger pool
indices cross Script number encoding boundaries. The paper's expression is
an approximation; the measured delta changes sign across those boundaries.
The `n=10,t=5` row is an illustrative fragment, so the paper's `t=8` byte
formula is not applied to it. The 93-opcode Core charge for `t=8` includes
nine pubkey charges added at `OP_CHECKMULTISIG`; counting only 84 serialized
non-push opcodes would understate the legacy limit.

The generated locking script is a fragment of the proposed protocol. It has
a terminal `OP_CHECKMULTISIG` boolean only if valid signatures, openings,
indices, and public keys are supplied in the required stack order. This
profile cannot establish clean-stack behavior, ECDSA validity, index
canonicality, relay policy, or consensus validity. In particular, Appendix
B.1's `OP_MIN` bounds an index but does not bind its raw value, as documented
in [NR-110](../../knowledge/negative-results/index.md#nr-110-clamped-hors-openings-do-not-bind-raw-binohash-indices).

## Reproduce

```sh
cargo test --locked --example binohash_appendix_b_resources
cargo run --locked --quiet --example binohash_appendix_b_resources
```

The [parameter frontier](../binohash-parameters/README.md) remains a paper
formula and independent-subset model. A complete two-round, signed Core
fixture is required before its full-script size, stack bound, and work-factor
claims can be upgraded.
