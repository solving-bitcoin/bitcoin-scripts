# Carry-checked distinct nibble set mask

Encode a fixed-length sequence of canonical, hostile nibble inputs as one
ScriptNum whose bit `x` indicates the presence of value `x`. Repeated
values fail verification. The output describes an unordered set.

## Parameters and stack contract

`u4_distinct_to_set_mask(n)` requires an explicit count in `0..=16`.
With stacks written bottom to top, it consumes the exact main-stack suffix
`x[0] ... x[n-1]` and leaves one canonical numeric mask in `0..=65535`.
An empty input yields zero. Temporary table, accumulator, and altstack
state are removed, preserving the caller's deeper main and altstack items.
The caller must use or remove the mask and satisfy the terminal predicate.

The fold sums `1 << x` for every checked input. Binary carries replace
two copies of a power of two with one copy of the next power. Each carry
reduces the total number of summands by one. Thus the bit count of the
canonical sum equals `n` exactly when no input was repeated. The maximum
intermediate sum is `16 * 32768 = 524288`, within the positive ScriptNum
arithmetic range. Partial sets require a sum at most 65,535 and a
bit count of `n`. A full set uses direct equality to 65,535, the only
16-bit mask with 16 set bits. A singleton requires only input validation.

For nonempty inputs the combined peak is at most `n + 20` plus preserved
caller state. All `n` ordinary inputs coexist at entry. The width-16
boundary test reaches exactly 1,000 items with 964 preserved items and
rejects with 965. There are no hints. Outputs or other data held for a
later invocation count as preserved items.

## Script metrics

Both complete leaves include the same canonical checks, one-hot fold,
cleanup, byte equality against the expected mask, and terminal true.
The [pairwise baseline](../../../../research/carry-distinct-u4/baseline.rs)
verifies every pair is byte-distinct before the common fold. Canonical
validation within the fold then excludes aliases. The fixture is the
first `n` items of `(7 * i + 3) mod 16`, a permutation. Data-witness
serialization includes the CompactSize count and item lengths, excluding
the leaf, control block, annex, and transaction. The peak covers both
stacks. Executed non-push counts include visited branch delimiters; the
carry-check count depends on the set bits.

| Inputs | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (serialized bytes) | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | Carry check | <!-- metric:distinct_mask_4_carry_script -->324<!-- /metric:distinct_mask_4_carry_script --> | <!-- metric:distinct_mask_4_carry_witness -->9<!-- /metric:distinct_mask_4_carry_witness --> | 4 | 0 (0 bytes) | <!-- metric:distinct_mask_4_carry_stack -->24<!-- /metric:distinct_mask_4_carry_stack --> | <!-- metric:distinct_mask_4_carry_executed -->140<!-- /metric:distinct_mask_4_carry_executed --> |
| 4 | Pairwise | <!-- metric:distinct_mask_4_pairwise_script -->154<!-- /metric:distinct_mask_4_pairwise_script --> | <!-- metric:distinct_mask_4_pairwise_witness -->9<!-- /metric:distinct_mask_4_pairwise_witness --> | 4 | 0 (0 bytes) | <!-- metric:distinct_mask_4_pairwise_stack -->24<!-- /metric:distinct_mask_4_pairwise_stack --> | <!-- metric:distinct_mask_4_pairwise_executed -->85<!-- /metric:distinct_mask_4_pairwise_executed --> |
| 8 | Carry check | <!-- metric:distinct_mask_8_carry_script -->389<!-- /metric:distinct_mask_8_carry_script --> | <!-- metric:distinct_mask_8_carry_witness -->17<!-- /metric:distinct_mask_8_carry_witness --> | 8 | 0 (0 bytes) | <!-- metric:distinct_mask_8_carry_stack -->28<!-- /metric:distinct_mask_8_carry_stack --> | <!-- metric:distinct_mask_8_carry_executed -->200<!-- /metric:distinct_mask_8_carry_executed --> |
| 8 | Pairwise | <!-- metric:distinct_mask_8_pairwise_script -->365<!-- /metric:distinct_mask_8_pairwise_script --> | <!-- metric:distinct_mask_8_pairwise_witness -->17<!-- /metric:distinct_mask_8_pairwise_witness --> | 8 | 0 (0 bytes) | <!-- metric:distinct_mask_8_pairwise_stack -->28<!-- /metric:distinct_mask_8_pairwise_stack --> | <!-- metric:distinct_mask_8_pairwise_executed -->239<!-- /metric:distinct_mask_8_pairwise_executed --> |
| 12 | Carry check | <!-- metric:distinct_mask_12_carry_script -->453<!-- /metric:distinct_mask_12_carry_script --> | <!-- metric:distinct_mask_12_carry_witness -->24<!-- /metric:distinct_mask_12_carry_witness --> | 12 | 0 (0 bytes) | <!-- metric:distinct_mask_12_carry_stack -->32<!-- /metric:distinct_mask_12_carry_stack --> | <!-- metric:distinct_mask_12_carry_executed -->256<!-- /metric:distinct_mask_12_carry_executed --> |
| 12 | Pairwise | <!-- metric:distinct_mask_12_pairwise_script -->687<!-- /metric:distinct_mask_12_pairwise_script --> | <!-- metric:distinct_mask_12_pairwise_witness -->24<!-- /metric:distinct_mask_12_pairwise_witness --> | 12 | 0 (0 bytes) | <!-- metric:distinct_mask_12_pairwise_stack -->32<!-- /metric:distinct_mask_12_pairwise_stack --> | <!-- metric:distinct_mask_12_pairwise_executed -->473<!-- /metric:distinct_mask_12_pairwise_executed --> |
| 16 | Carry check | <!-- metric:distinct_mask_16_carry_script -->316<!-- /metric:distinct_mask_16_carry_script --> | <!-- metric:distinct_mask_16_carry_witness -->32<!-- /metric:distinct_mask_16_carry_witness --> | 16 | 0 (0 bytes) | <!-- metric:distinct_mask_16_carry_stack -->36<!-- /metric:distinct_mask_16_carry_stack --> | <!-- metric:distinct_mask_16_carry_executed -->189<!-- /metric:distinct_mask_16_carry_executed --> |
| 16 | Pairwise | <!-- metric:distinct_mask_16_pairwise_script -->1121<!-- /metric:distinct_mask_16_pairwise_script --> | <!-- metric:distinct_mask_16_pairwise_witness -->32<!-- /metric:distinct_mask_16_pairwise_witness --> | 16 | 0 (0 bytes) | <!-- metric:distinct_mask_16_pairwise_stack -->36<!-- /metric:distinct_mask_16_pairwise_stack --> | <!-- metric:distinct_mask_16_pairwise_executed -->787<!-- /metric:distinct_mask_16_pairwise_executed --> |

## Security, compatibility and execution

A canonical distinct input maps to the exact unordered set. The raw sum
alone is insufficient when the mask weight is unchecked. For example,
`[0, 0, 2]` sums to 6 and passes a sum-only leaf committed to 6. The
weight check rejects that witness. Permutations of the same set preserve
the output, so it cannot bind input order. There are no keys or
cryptographic security assumptions.

All measured leaves use `CompileOptions::ALL` through the central policy,
the pinned local tapscript Consensus profile with the 520-byte item and
1,000-item combined-stack limits, and zero signature validation charge.
Evidence is `locally-reproduced`; execution is `unclassified`. The
opcodes are available in bare, P2SH, P2WSH, and tapscript, but legacy
opcode counts and script-size limits have separate constraints. No
complete spend or relay policy was tested for any context. See
[script types](../../../../docs/script-types.md) and
[standardness](../../../../docs/standardness.md).

## Reproduction

```sh
cargo test --locked --lib arithmetic::u4::distinct_mask::tests
cargo test --locked --test primitive_metrics distinct_mask_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

Tests cover all ordered nibble pairs, deterministic restricted alphabets,
all supported counts, corruptions at every position, malformed encodings,
wrong masks and input counts, forged carry cases, and the combined-stack
frontier. See the [knowledge entry](../../../../knowledge/primitives/u4-distinct-mask.md).
