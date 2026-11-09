# Carry-out of canonically compressed u32 words

Check the final unsigned carry of two hostile words directly in the
canonical compressed ScriptNum representation used by the u32 module.
The fragment avoids expanding the words into eight byte limbs.

## Parameters and stack contract

`u32_compressed_carry()` takes no generation parameters. Main starts
with `caller | a b`. Each operand is the minimal signed ScriptNum for
`word as i32`. The sole valid five-byte item is the exact encoding of
`-2147483648`, representing unsigned `0x80000000`. The fragment consumes
both words and returns the canonical bit `[a+b >= 2^32]`. Both caller
stacks survive. A zero carry is data, so a standalone leaf verifies
the expected bit and adds terminal true.

## Construction

The three operand classes are `0` for a nonnegative compressed value,
`2` for an ordinary negative value, and `3` for the exact five-byte
sentinel. The sum of the class tags distinguishes all carry cases.

| Tag sum | Operand classes | Carry |
| ---: | --- | --- |
| 0 | Both nonnegative | 0 |
| 2 | Nonnegative and ordinary negative | 1 exactly when the signed sum is nonnegative |
| 3 | Nonnegative and sentinel | 0 |
| 4, 5, 6 | Both high-half words | 1 |

The mixed ordinary signed sum stays within four bytes. Sentinel bytes
are matched by raw equality and are never used as a numeric operand.
Other inputs are width-checked and compared to their minimally encoded
numeric round trip before use.

## Script metrics

Every row measures a complete leaf with both canonical-word checks,
exact carry comparison and terminal true. The
[baselines](../../../../research/compressed-u32-carry/baseline.rs)
compute carry as `~b < a` using the existing unsigned compressed
comparator, or expand both words and run a carry-only byte ripple.
They use the same compressed input and witness bytes.

Data witness bytes include the count and item lengths, excluding
the leaf, control block, annex and transaction. Both data items
coexist at entry. Peak includes both stacks. Executed non-push
operations include branch delimiters processed by the interpreter.

| Operands | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (bytes) | Combined peak | Executed non-push ops |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `0 + 1` | Sign classes | <!-- metric:compressed_carry_low_classes_script -->69<!-- /metric:compressed_carry_low_classes_script --> | <!-- metric:compressed_carry_low_classes_witness -->4<!-- /metric:compressed_carry_low_classes_witness --> | 2 | 0 (0 bytes) | <!-- metric:compressed_carry_low_classes_stack -->6<!-- /metric:compressed_carry_low_classes_stack --> | <!-- metric:compressed_carry_low_classes_executed -->38<!-- /metric:compressed_carry_low_classes_executed --> |
| `0 + 1` | Complement comparison | <!-- metric:compressed_carry_low_complement_script -->153<!-- /metric:compressed_carry_low_complement_script --> | <!-- metric:compressed_carry_low_complement_witness -->4<!-- /metric:compressed_carry_low_complement_witness --> | 2 | 0 (0 bytes) | <!-- metric:compressed_carry_low_complement_stack -->6<!-- /metric:compressed_carry_low_complement_stack --> | <!-- metric:compressed_carry_low_complement_executed -->78<!-- /metric:compressed_carry_low_complement_executed --> |
| `0 + 1` | Expanded ripple | <!-- metric:compressed_carry_low_ripple_script -->912<!-- /metric:compressed_carry_low_ripple_script --> | <!-- metric:compressed_carry_low_ripple_witness -->4<!-- /metric:compressed_carry_low_ripple_witness --> | 2 | 0 (0 bytes) | <!-- metric:compressed_carry_low_ripple_stack -->11<!-- /metric:compressed_carry_low_ripple_stack --> | <!-- metric:compressed_carry_low_ripple_executed -->620<!-- /metric:compressed_carry_low_ripple_executed --> |
| `0x7fffffff + 0x80000000` | Sign classes | <!-- metric:compressed_carry_sentinel_classes_script -->69<!-- /metric:compressed_carry_sentinel_classes_script --> | <!-- metric:compressed_carry_sentinel_classes_witness -->12<!-- /metric:compressed_carry_sentinel_classes_witness --> | 2 | 0 (0 bytes) | <!-- metric:compressed_carry_sentinel_classes_stack -->6<!-- /metric:compressed_carry_sentinel_classes_stack --> | <!-- metric:compressed_carry_sentinel_classes_executed -->31<!-- /metric:compressed_carry_sentinel_classes_executed --> |
| `0x7fffffff + 0x80000000` | Complement comparison | <!-- metric:compressed_carry_sentinel_complement_script -->153<!-- /metric:compressed_carry_sentinel_complement_script --> | <!-- metric:compressed_carry_sentinel_complement_witness -->12<!-- /metric:compressed_carry_sentinel_complement_witness --> | 2 | 0 (0 bytes) | <!-- metric:compressed_carry_sentinel_complement_stack -->6<!-- /metric:compressed_carry_sentinel_complement_stack --> | <!-- metric:compressed_carry_sentinel_complement_executed -->70<!-- /metric:compressed_carry_sentinel_complement_executed --> |
| `0x7fffffff + 0x80000000` | Expanded ripple | <!-- metric:compressed_carry_sentinel_ripple_script -->912<!-- /metric:compressed_carry_sentinel_ripple_script --> | <!-- metric:compressed_carry_sentinel_ripple_witness -->12<!-- /metric:compressed_carry_sentinel_ripple_witness --> | 2 | 0 (0 bytes) | <!-- metric:compressed_carry_sentinel_ripple_stack -->11<!-- /metric:compressed_carry_sentinel_ripple_stack --> | <!-- metric:compressed_carry_sentinel_ripple_executed -->616<!-- /metric:compressed_carry_sentinel_ripple_executed --> |
| `0x7fffffff + 0x80000001` | Sign classes | <!-- metric:compressed_carry_mixed_classes_script -->69<!-- /metric:compressed_carry_mixed_classes_script --> | <!-- metric:compressed_carry_mixed_classes_witness -->11<!-- /metric:compressed_carry_mixed_classes_witness --> | 2 | 0 (0 bytes) | <!-- metric:compressed_carry_mixed_classes_stack -->6<!-- /metric:compressed_carry_mixed_classes_stack --> | <!-- metric:compressed_carry_mixed_classes_executed -->38<!-- /metric:compressed_carry_mixed_classes_executed --> |
| `0x7fffffff + 0x80000001` | Complement comparison | <!-- metric:compressed_carry_mixed_complement_script -->153<!-- /metric:compressed_carry_mixed_complement_script --> | <!-- metric:compressed_carry_mixed_complement_witness -->11<!-- /metric:compressed_carry_mixed_complement_witness --> | 2 | 0 (0 bytes) | <!-- metric:compressed_carry_mixed_complement_stack -->6<!-- /metric:compressed_carry_mixed_complement_stack --> | <!-- metric:compressed_carry_mixed_complement_executed -->75<!-- /metric:compressed_carry_mixed_complement_executed --> |
| `0x7fffffff + 0x80000001` | Expanded ripple | <!-- metric:compressed_carry_mixed_ripple_script -->912<!-- /metric:compressed_carry_mixed_ripple_script --> | <!-- metric:compressed_carry_mixed_ripple_witness -->11<!-- /metric:compressed_carry_mixed_ripple_witness --> | 2 | 0 (0 bytes) | <!-- metric:compressed_carry_mixed_ripple_stack -->11<!-- /metric:compressed_carry_mixed_ripple_stack --> | <!-- metric:compressed_carry_mixed_ripple_executed -->622<!-- /metric:compressed_carry_mixed_ripple_executed --> |
| `0x80000000 + 0xffffffff` | Sign classes | <!-- metric:compressed_carry_high_classes_script -->69<!-- /metric:compressed_carry_high_classes_script --> | <!-- metric:compressed_carry_high_classes_witness -->9<!-- /metric:compressed_carry_high_classes_witness --> | 2 | 0 (0 bytes) | <!-- metric:compressed_carry_high_classes_stack -->5<!-- /metric:compressed_carry_high_classes_stack --> | <!-- metric:compressed_carry_high_classes_executed -->31<!-- /metric:compressed_carry_high_classes_executed --> |
| `0x80000000 + 0xffffffff` | Complement comparison | <!-- metric:compressed_carry_high_complement_script -->153<!-- /metric:compressed_carry_high_complement_script --> | <!-- metric:compressed_carry_high_complement_witness -->9<!-- /metric:compressed_carry_high_complement_witness --> | 2 | 0 (0 bytes) | <!-- metric:compressed_carry_high_complement_stack -->6<!-- /metric:compressed_carry_high_complement_stack --> | <!-- metric:compressed_carry_high_complement_executed -->72<!-- /metric:compressed_carry_high_complement_executed --> |
| `0x80000000 + 0xffffffff` | Expanded ripple | <!-- metric:compressed_carry_high_ripple_script -->912<!-- /metric:compressed_carry_high_ripple_script --> | <!-- metric:compressed_carry_high_ripple_witness -->9<!-- /metric:compressed_carry_high_ripple_witness --> | 2 | 0 (0 bytes) | <!-- metric:compressed_carry_high_ripple_stack -->11<!-- /metric:compressed_carry_high_ripple_stack --> | <!-- metric:compressed_carry_high_ripple_executed -->618<!-- /metric:compressed_carry_high_ripple_executed --> |

## Security, compatibility and composition

The verifier accepts only canonical compressed u32 encodings and
makes no authentication claim. The caller must bind the words and
interpret the carry. Bare, P2SH and P2WSH share the opcodes, with
different size and policy limits. See the
[script-type](../../../../docs/script-types.md) and
[standardness](../../../../docs/standardness.md) references.

All fixtures use central compile policy `ALL` and the stack-limited
local tapscript Consensus profile with a synthetic transaction and
zero signature charge. The same valid fixtures pass the local Policy
profile. Evidence is `locally-reproduced`; execution is
`unclassified`. Each invocation uses two ordinary items and zero
hints. Both caller stacks and every preloaded future pair contribute
to the combined 1,000-item limit. Reserve six live items for one
invocation with unknown operands, plus both caller stacks. The
mixed fixture reaches 1,000 with 994 caller items and fails with one
more.

## Reproduction

```sh
cargo test --locked --lib arithmetic::u32::carry::tests
cargo test --locked --test primitive_metrics compressed_carry_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

The suite uses the host `u32::overflowing_add` predicate, signed and
unsigned boundaries, all class pairs and both operand orientations.
It also checks 256 deterministic pairs with StdRng seed
`0x374341525259`, hostile aliases, and preservation of caller data.
See the [knowledge page](../../../../knowledge/primitives/compressed-u32-carry.md).
