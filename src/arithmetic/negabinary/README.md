# Checked negabinary decoding

Decode a fixed-width base −2 vector of hostile raw bits to a
canonical signed ScriptNum without a separate sign item.

## Parameters and stack contract

`decode_negabinary(width)` takes a generation-time width in
`1..=32`, with no default. Main starts with
`caller | bit[0] ... bit[width-1]`, where bit zero is least
significant and the most significant bit is on top. Each item
must be exactly empty or `01`. The fragment consumes the bits
and returns the canonical signed value. Both caller stacks survive.
The caller supplies a result predicate and cleanup.

Every width through 31 fits. Width 31 represents values from
−715,827,882 through 1,431,655,765. Width 32 mathematically
represents −2,863,311,530 through 1,431,655,765. The checked
decoder accepts the intersection with the four-byte ScriptNum
range, from −2,147,483,647 through 1,431,655,765.

## Construction

The recurrence processes the most significant digit first.
For next bit `d` and accumulator `x`, it computes
`d-x-x` with two subtractions. The first difference fits
in four bytes for every possible prefix. A final width-32
result can be five bytes. Script checks its size without
reading it as a number and rejects values wider than four.

The [matched multiply-first baseline](../../../research/checked-negabinary-decoder/baseline.rs)
uses `d-(x+x)` for smaller prefixes. Its last width-32
step checks positive headroom and handles the valid
`x=2^30, d=1` cancellation explicitly.

## Script metrics

Every leaf verifies each exact result, consumes it and
leaves true. Single fixtures use −37 at width eight,
1,431,655,765 at width 31, and −2,147,483,647 at width 32.
The 16-call fixture cycles those two wide extrema plus −1
and zero in the order in the
[fixture generator](../../../research/checked-negabinary-decoder/fixture.rs).
All bits coexist at entry, and calls consume records from
the top. Data witness bytes include item count and lengths,
excluding leaf, control block, annex and transaction.
Peak combines both stacks. Executed non-push counts include
encountered branch delimiters.

| Width | Calls | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (bytes) | Combined peak | Executed non-push ops |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 8 | 1 | Two subtractions | <!-- metric:negabinary_8_subtract_script -->103<!-- /metric:negabinary_8_subtract_script --> | <!-- metric:negabinary_8_subtract_witness -->14<!-- /metric:negabinary_8_subtract_witness --> | 8 | 0 (0 bytes) | <!-- metric:negabinary_8_subtract_stack -->11<!-- /metric:negabinary_8_subtract_stack --> | <!-- metric:negabinary_8_subtract_executed -->84<!-- /metric:negabinary_8_subtract_executed --> |
| 8 | 1 | Checked multiply first | <!-- metric:negabinary_8_multiply_script -->103<!-- /metric:negabinary_8_multiply_script --> | <!-- metric:negabinary_8_multiply_witness -->14<!-- /metric:negabinary_8_multiply_witness --> | 8 | 0 (0 bytes) | <!-- metric:negabinary_8_multiply_stack -->11<!-- /metric:negabinary_8_multiply_stack --> | <!-- metric:negabinary_8_multiply_executed -->84<!-- /metric:negabinary_8_multiply_executed --> |
| 31 | 1 | Two subtractions | <!-- metric:negabinary_31_subtract_script -->405<!-- /metric:negabinary_31_subtract_script --> | <!-- metric:negabinary_31_subtract_witness -->48<!-- /metric:negabinary_31_subtract_witness --> | 31 | 0 (0 bytes) | <!-- metric:negabinary_31_subtract_stack -->34<!-- /metric:negabinary_31_subtract_stack --> | <!-- metric:negabinary_31_subtract_executed -->337<!-- /metric:negabinary_31_subtract_executed --> |
| 31 | 1 | Checked multiply first | <!-- metric:negabinary_31_multiply_script -->405<!-- /metric:negabinary_31_multiply_script --> | <!-- metric:negabinary_31_multiply_witness -->48<!-- /metric:negabinary_31_multiply_witness --> | 31 | 0 (0 bytes) | <!-- metric:negabinary_31_multiply_stack -->34<!-- /metric:negabinary_31_multiply_stack --> | <!-- metric:negabinary_31_multiply_executed -->337<!-- /metric:negabinary_31_multiply_executed --> |
| 32 | 1 | Two subtractions | <!-- metric:negabinary_32_subtract_script -->422<!-- /metric:negabinary_32_subtract_script --> | <!-- metric:negabinary_32_subtract_witness -->35<!-- /metric:negabinary_32_subtract_witness --> | 32 | 0 (0 bytes) | <!-- metric:negabinary_32_subtract_stack -->35<!-- /metric:negabinary_32_subtract_stack --> | <!-- metric:negabinary_32_subtract_executed -->351<!-- /metric:negabinary_32_subtract_executed --> |
| 32 | 1 | Checked multiply first | <!-- metric:negabinary_32_multiply_script -->444<!-- /metric:negabinary_32_multiply_script --> | <!-- metric:negabinary_32_multiply_witness -->35<!-- /metric:negabinary_32_multiply_witness --> | 32 | 0 (0 bytes) | <!-- metric:negabinary_32_multiply_stack -->35<!-- /metric:negabinary_32_multiply_stack --> | <!-- metric:negabinary_32_multiply_executed -->352<!-- /metric:negabinary_32_multiply_executed --> |
| 32 | 16 | Two subtractions | <!-- metric:negabinary_batch_subtract_script -->6705<!-- /metric:negabinary_batch_subtract_script --> | <!-- metric:negabinary_batch_subtract_witness -->595<!-- /metric:negabinary_batch_subtract_witness --> | 512 | 0 (0 bytes) | <!-- metric:negabinary_batch_subtract_stack -->515<!-- /metric:negabinary_batch_subtract_stack --> | <!-- metric:negabinary_batch_subtract_executed -->5616<!-- /metric:negabinary_batch_subtract_executed --> |
| 32 | 16 | Checked multiply first | <!-- metric:negabinary_batch_multiply_script -->7057<!-- /metric:negabinary_batch_multiply_script --> | <!-- metric:negabinary_batch_multiply_witness -->595<!-- /metric:negabinary_batch_multiply_witness --> | 512 | 0 (0 bytes) | <!-- metric:negabinary_batch_multiply_stack -->515<!-- /metric:negabinary_batch_multiply_stack --> | <!-- metric:negabinary_batch_multiply_executed -->5680<!-- /metric:negabinary_batch_multiply_executed --> |

## Security, compatibility and composition

Canonical byte checks reject zero aliases, negative zero,
other digits, and malformed items. No witness item is trusted
as a number before it has passed the bit check. The exact
numeric value does not authenticate the witness's provenance.

A width-`w` call uses `w` ordinary items and zero hints. For
preloaded width-32 batches that check and remove each output,
the subtraction schedule peaks at `32*n+3` before caller
state. The 31-call fixture reaches exactly 1,000 with five
caller items across the two stacks. One more item fails.

All measured leaves compile with policy `ALL`. The pinned
local tapscript Consensus profile uses the 520-byte element
and 1,000-item combined limits, experimental OP_CAT disabled,
a synthetic transaction and zero signature charge. The metric
fixtures also pass the local Policy profile. The opcodes
exist in bare, P2SH, P2WSH and tapscript, with context-specific
[script-type](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md) limits.
Evidence is `locally-reproduced`. Execution is `unclassified`.

## Reproduction

```sh
cargo test --locked --lib arithmetic::negabinary::tests
cargo test --locked --test primitive_metrics checked_negabinary_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

Tests cover every 16-bit vector against a host positional sum,
signed extrema, overflowing final results, hostile bit aliases,
and both caller stacks at the exact batch frontier. See the
[knowledge page](../../../knowledge/primitives/negabinary-decoder.md).
