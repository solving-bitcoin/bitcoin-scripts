# Paired signed ScriptNum extrema

Consume a hostile signed vector and return its exact minimum
and maximum together.

## Parameters and stack contract

`signed_min_max(width)` takes a generation-time width in
`1..=997`, with no default. Main starts with
`caller | x[0] ... x[width-1]`. Every input must be a canonical
ScriptNum of at most four bytes. Success consumes the vector
and returns `caller | minimum maximum`, with maximum on top.
Both outputs are canonical and both caller stacks survive.
A singleton is checked and duplicated.

At width two or more, one comparison orders the first pair.
For each subsequent pair, compare the two values once and route
its lower value only to the minimum update and its higher value
only to the maximum update. If one input remains, update both
extrema using that input. The
[streaming baseline](../../../research/paired-signed-extrema/baseline.rs)
uses the same first-pair initialization and updates both extrema
independently for every remaining item. The fragment leaves two
items, so a caller must consume or verify them before a complete
leaf can succeed with a clean stack.

## Script metrics

The [fixture](../../../research/paired-signed-extrema/fixture.rs)
alternates signed values close to the four-byte endpoints. Both
complete leaves check the exact two outputs and finish with true.
All data items coexist at entry. Data witness includes item count
and lengths, excluding leaf, control block, annex and transaction.
Peak combines both stacks. Executed non-push counts include
encountered branch delimiters.

The value comparison column counts executed `OP_GREATERTHAN`,
`OP_MIN` and `OP_MAX`. It excludes width guards and exact output
checks. For `n >= 2`, the paired schedule uses
`ceil(3*n/2)-2` value comparisons, while streaming uses `2*n-3`.

| Width | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (bytes) | Combined peak | Executed non-push ops | Value comparisons |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | Paired updates | <!-- metric:extrema_2_paired_script -->37<!-- /metric:extrema_2_paired_script --> | <!-- metric:extrema_2_paired_witness -->11<!-- /metric:extrema_2_paired_witness --> | 2 | 0 (0 bytes) | <!-- metric:extrema_2_paired_stack -->5<!-- /metric:extrema_2_paired_stack --> | <!-- metric:extrema_2_paired_executed -->21<!-- /metric:extrema_2_paired_executed --> | <!-- metric:extrema_2_paired_comparisons -->1<!-- /metric:extrema_2_paired_comparisons --> |
| 2 | Streaming updates | <!-- metric:extrema_2_streaming_script -->37<!-- /metric:extrema_2_streaming_script --> | <!-- metric:extrema_2_streaming_witness -->11<!-- /metric:extrema_2_streaming_witness --> | 2 | 0 (0 bytes) | <!-- metric:extrema_2_streaming_stack -->5<!-- /metric:extrema_2_streaming_stack --> | <!-- metric:extrema_2_streaming_executed -->21<!-- /metric:extrema_2_streaming_executed --> | <!-- metric:extrema_2_streaming_comparisons -->1<!-- /metric:extrema_2_streaming_comparisons --> |
| 32 | Paired updates | <!-- metric:extrema_32_paired_script -->487<!-- /metric:extrema_32_paired_script --> | <!-- metric:extrema_32_paired_witness -->161<!-- /metric:extrema_32_paired_witness --> | 32 | 0 (0 bytes) | <!-- metric:extrema_32_paired_stack -->35<!-- /metric:extrema_32_paired_stack --> | <!-- metric:extrema_32_paired_executed -->396<!-- /metric:extrema_32_paired_executed --> | <!-- metric:extrema_32_paired_comparisons -->46<!-- /metric:extrema_32_paired_comparisons --> |
| 32 | Streaming updates | <!-- metric:extrema_32_streaming_script -->487<!-- /metric:extrema_32_streaming_script --> | <!-- metric:extrema_32_streaming_witness -->161<!-- /metric:extrema_32_streaming_witness --> | 32 | 0 (0 bytes) | <!-- metric:extrema_32_streaming_stack -->35<!-- /metric:extrema_32_streaming_stack --> | <!-- metric:extrema_32_streaming_executed -->411<!-- /metric:extrema_32_streaming_executed --> | <!-- metric:extrema_32_streaming_comparisons -->61<!-- /metric:extrema_32_streaming_comparisons --> |
| 128 | Paired updates | <!-- metric:extrema_128_paired_script -->1927<!-- /metric:extrema_128_paired_script --> | <!-- metric:extrema_128_paired_witness -->641<!-- /metric:extrema_128_paired_witness --> | 128 | 0 (0 bytes) | <!-- metric:extrema_128_paired_stack -->131<!-- /metric:extrema_128_paired_stack --> | <!-- metric:extrema_128_paired_executed -->1596<!-- /metric:extrema_128_paired_executed --> | <!-- metric:extrema_128_paired_comparisons -->190<!-- /metric:extrema_128_paired_comparisons --> |
| 128 | Streaming updates | <!-- metric:extrema_128_streaming_script -->1927<!-- /metric:extrema_128_streaming_script --> | <!-- metric:extrema_128_streaming_witness -->641<!-- /metric:extrema_128_streaming_witness --> | 128 | 0 (0 bytes) | <!-- metric:extrema_128_streaming_stack -->131<!-- /metric:extrema_128_streaming_stack --> | <!-- metric:extrema_128_streaming_executed -->1659<!-- /metric:extrema_128_streaming_executed --> | <!-- metric:extrema_128_streaming_comparisons -->253<!-- /metric:extrema_128_streaming_comparisons --> |
| 997 | Paired updates | <!-- metric:extrema_997_paired_script -->14962<!-- /metric:extrema_997_paired_script --> | <!-- metric:extrema_997_paired_witness -->4988<!-- /metric:extrema_997_paired_witness --> | 997 | 0 (0 bytes) | <!-- metric:extrema_997_paired_stack -->1000<!-- /metric:extrema_997_paired_stack --> | <!-- metric:extrema_997_paired_executed -->12957<!-- /metric:extrema_997_paired_executed --> | <!-- metric:extrema_997_paired_comparisons -->1494<!-- /metric:extrema_997_paired_comparisons --> |
| 997 | Streaming updates | <!-- metric:extrema_997_streaming_script -->14962<!-- /metric:extrema_997_streaming_script --> | <!-- metric:extrema_997_streaming_witness -->4988<!-- /metric:extrema_997_streaming_witness --> | 997 | 0 (0 bytes) | <!-- metric:extrema_997_streaming_stack -->1000<!-- /metric:extrema_997_streaming_stack --> | <!-- metric:extrema_997_streaming_executed -->12957<!-- /metric:extrema_997_streaming_executed --> | <!-- metric:extrema_997_streaming_comparisons -->1991<!-- /metric:extrema_997_streaming_comparisons --> |

Both schedules tie in script bytes, witness bytes, and peak on
these fixtures. Each subsequent pair that skips its conditional
swap saves one executed non-push operation relative to streaming.
The width-997 fixture takes every swap and ties in total operations.
See the [comparison](../../../knowledge/comparisons/signed-min-max.md).

## Security, compatibility and composition

Both width and canonical encoding are checked before using any
hostile operand in a value comparison. The extrema specify a
numeric relation on the input vector. They do not encode order,
multiplicity, or provenance.

Each invocation uses `width` ordinary items and zero hints.
The measured width-997 leaves peak at 1,000 with no caller state.
At width 995 the paired schedule preserves one item on each
caller stack at exactly 1,000. One additional item fails.
Remaining inputs and retained outputs add to the combined limit.

All measured leaves compile with policy `ALL`. The stack-limited
local tapscript Consensus profile uses a synthetic transaction,
experimental OP_CAT disabled, and zero signature charge. The
measured fixtures also pass the local Policy profile. The opcodes
exist in bare, P2SH, P2WSH and tapscript, subject to context-specific
[script-type](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md) limits.
Evidence is `locally-reproduced`. Execution is `unclassified`.

## Reproduction

```sh
cargo test --locked --lib arithmetic::extrema::tests
cargo test --locked --test primitive_metrics signed_extrema_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

The tests enumerate short signed vectors, reject numeric aliases
and oversized operands, exercise both extrema, and check exact
stack limits. See the
[knowledge page](../../../knowledge/primitives/signed-min-max.md).
