# Checked u32 byte-less-than mask

## Research question

Can two hostile byte-oriented u32 values expose the four independent unsigned
byte-lane ordering predicates without a 256-entry Boolean table or auxiliary
witness hints? The objective is to preserve lane-local ordering information,
not to replace the cheaper lexicographic `u32_lessthan()` primitive.

## Semantics and boundary

`arithmetic::u32::byte_less_mask::u32_byte_lessthan_mask()` consumes the top two
u32 words in the normal most-significant-byte-first representation. For lower
word `a` and upper word `b`, it returns:

```text
mask = 8*(a[0] < b[0]) + 4*(a[1] < b[1])
     + 2*(a[2] < b[2]) + 1*(a[3] < b[3])
```

Bit 3 describes the most-significant byte and bit 0 the least-significant
byte. All eight inputs must be minimally encoded ScriptNums in `0..=255`.
The fragment consumes both words and returns one numeric mask; it does not
include a terminal predicate.

The threat model treats every byte and raw witness encoding as hostile. Both
members of every lane are checked before `OP_GREATERTHAN`, so an invalid limb
cannot be hidden by a different comparison result. No cryptographic security
claim or hint binding is involved.

## Evidence and cost

The result is `locally-reproduced` with the repository's strict local tapscript
executor. The boundary includes word routing, eight canonical-byte checks,
four lane comparisons, mask packing, and excludes input pushes and a terminal
predicate.

| Configuration | Script | Witness | Data items | Hint items | Combined peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| two checked u32 words, `0x42424242` each | 149 bytes | 17 bytes | 8 | 0 | 11 | 100 |
| maximum canonical witness (`0xff` in every limb) | 149 bytes | 25 bytes | 8 | 0 | — | 100 |

Dynamic opcode counting and validation-weight reporting are unavailable for
this local fragment. Deployment remains `unclassified`: no Bitcoin Core
consensus or relay-policy differential validation was performed, and this is
not a complete Taproot-spend budget.

## Closest comparison

`u32_lessthan()` is 38 bytes and performs a lexicographic whole-word
comparison. The mask costs 111 additional locking bytes and peaks two items
higher because it retains four lane predicates. That cost is useful only when
the caller needs independent byte routing or per-lane threshold checks; callers
needing one word-order Boolean should keep the existing comparator.

The mask also differs from a zero-byte or equality mask: it preserves ordering
for every lane, including mixed patterns where the whole-word ordering would
not identify the individual byte relations.

## Reproduction

```sh
cargo test --locked byte_less_mask --lib
cargo test --locked --test primitive_metrics u32_byte_less_mask_metrics_are_current
python3 tools/kb.py validate
```

Tests cover equal, all-less, mixed boundary patterns, deterministic random
words, unrelated main/altstack preservation, every numeric out-of-range limb,
and a noncanonical raw zero witness in every position.
