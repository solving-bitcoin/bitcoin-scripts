# Checked u32 byte-equality mask

## Research question

Can two hostile, byte-oriented u32 values expose equality of each byte lane
without a 256-entry Boolean table or auxiliary witness hints? The comparison
objective is not to beat `u32_equal()`: it is to retain four independently
addressable predicates for a caller that needs lane routing or selective
validation.

## Semantics and boundary

`arithmetic::u32::byte_eq_mask::u32_byte_eq_mask()` consumes two u32 words in
the normal most-significant-byte-first representation and returns one numeric
ScriptNum:

```text
mask = 8*(a[0] == b[0]) + 4*(a[1] == b[1])
     + 2*(a[2] == b[2]) + 1*(a[3] == b[3])
```

Bit 3 is the most-significant-byte comparison; bit 0 is the least-significant
byte comparison. All eight inputs must be minimally encoded ScriptNums in
`0..=255`. The fragment consumes the words and leaves only the mask. It is a
fragment, not a complete locking script: callers still need a terminal
predicate or a consuming use of the mask.

The threat model treats every byte and its raw ScriptNum encoding as hostile.
The implementation validates both members of every lane before `OP_EQUAL`, so
an invalid byte cannot be hidden by a mismatch in the other word. No
cryptographic security claim is made, and no hint items are used.

## Evidence and cost

The result is `locally-reproduced` with the repository's strict local tapscript
executor. The representative boundary includes zip routing, all eight
canonical-byte checks, four equality predicates, mask packing, and no terminal
predicate or witness push in the locking script.

| Configuration | Script | Witness | Data items | Hint items | Combined peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| two checked u32 words, `0x42424242` each | 149 bytes | 17 bytes | 8 | 0 | 11 | 100 |
| maximum canonical witness (`0xff` in every limb) | 149 bytes | 25 bytes | 8 | 0 | — | 100 |

The local executor does not provide a useful dynamic opcode count for this
fragment, so the table records the static non-push count separately. Validation
weight and complete transaction witness cost are not measured here. The local
run is `unclassified` for deployment: it is not a Bitcoin Core consensus or
relay-policy differential result, and it does not establish a complete
Taproot-spend budget.

## Closest comparison

`u32_equal()` is 18 bytes and returns one aggregate Boolean. The mask costs 131
additional locking bytes and peaks two items higher because it preserves four
results instead of folding them immediately. That cost is intentional: it
buys per-lane information. A caller needing only all-byte equality should keep
using `u32_equal()`; a caller needing a packed selector can consume the mask
once instead of rebuilding four byte comparisons.

The construction is also different from a zero-byte mask: it compares two
independent words and can represent mixed equality patterns such as `0b1010`.
It does not require the 256-item Boolean table used by byte-wise AND/OR/XOR.

## Scheduling result

A first direct loop compared the next byte pair while leaving the previous
equality result on the main stack. That result sat above the next pair, so later
`OP_SWAP` operations consumed the wrong items. The retained schedule moves each
comparison result to the altstack immediately, restores the four results in
lane order, and only then packs them. This is a stack-scheduling requirement,
not an optimization claim.

## Reproduction

```sh
cargo test --locked byte_eq_mask --lib
cargo test --locked --test primitive_metrics u32_byte_eq_mask_metrics_are_current
python3 tools/kb.py validate
```

Correctness tests cover all-equal, no-equal, mixed boundary patterns,
deterministic random words, every numeric out-of-range limb, and a
noncanonical raw zero witness in every input position.
