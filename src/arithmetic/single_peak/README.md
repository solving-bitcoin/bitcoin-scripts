# Strict single peak of signed ScriptNums

Verify that a hostile signed sequence rises strictly to one interior
peak and falls strictly afterward. Return the zero-based peak index.

## Parameters and stack contract

`verify_single_peak(width)` takes a generation-time width in
`3..=998`, with no default. Main starts with
`caller | x[0] ... x[width-1]`, and returns
`caller | peak_index`. Every input must fit in four bytes and is
compared as a signed ScriptNum. The index is canonical and lies in
`1..=width-2`. Both caller stacks survive. The caller supplies any
terminal predicate and result cleanup.

The scan starts by verifying the rightmost strict descent. It then
walks from right to left, rejecting equal adjacent values. Let `b`
be the current left-to-right ascent bit and `c` the accumulated
ascent count. Require `b >= (c != 0)` before adding `b` to `c`.
That condition prevents another descent after the ascent phase
begins. A positive final count proves the left side exists, and
equals the peak index.

## Script metrics

The [baseline](../../../research/strict-signed-single-peak/baseline.rs)
uses the same checked comparisons and count. A branch tests the
current edge direction before updating the phase. Both complete
leaves verify the exact peak index and finish with true.

The [fixture](../../../research/strict-signed-single-peak/fixture.rs)
rises by 50 from zero up to its chosen peak and then falls by 37.
All ordinary items coexist at entry. Data witness bytes include
the item count and lengths, excluding leaf, control block, annex
and transaction framing. Peak includes both stacks. Executed
non-push counts include branch delimiters processed by the
interpreter.

| Width | Peak index | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (bytes) | Combined peak | Executed non-push ops |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 32 | 1 | Arithmetic phase check | <!-- metric:single_peak_32_1_arithmetic_script -->556<!-- /metric:single_peak_32_1_arithmetic_script --> | <!-- metric:single_peak_32_1_arithmetic_witness -->90<!-- /metric:single_peak_32_1_arithmetic_witness --> | 32 | 0 (0 bytes) | <!-- metric:single_peak_32_1_arithmetic_stack -->34<!-- /metric:single_peak_32_1_arithmetic_stack --> | <!-- metric:single_peak_32_1_arithmetic_executed -->521<!-- /metric:single_peak_32_1_arithmetic_executed --> |
| 32 | 1 | Branched phase check | <!-- metric:single_peak_32_1_branch_script -->649<!-- /metric:single_peak_32_1_branch_script --> | <!-- metric:single_peak_32_1_branch_witness -->90<!-- /metric:single_peak_32_1_branch_witness --> | 32 | 0 (0 bytes) | <!-- metric:single_peak_32_1_branch_stack -->34<!-- /metric:single_peak_32_1_branch_stack --> | <!-- metric:single_peak_32_1_branch_executed -->494<!-- /metric:single_peak_32_1_branch_executed --> |
| 32 | 30 | Arithmetic phase check | <!-- metric:single_peak_32_30_arithmetic_script -->557<!-- /metric:single_peak_32_30_arithmetic_script --> | <!-- metric:single_peak_32_30_arithmetic_witness -->93<!-- /metric:single_peak_32_30_arithmetic_witness --> | 32 | 0 (0 bytes) | <!-- metric:single_peak_32_30_arithmetic_stack -->34<!-- /metric:single_peak_32_30_arithmetic_stack --> | <!-- metric:single_peak_32_30_arithmetic_executed -->521<!-- /metric:single_peak_32_30_arithmetic_executed --> |
| 32 | 30 | Branched phase check | <!-- metric:single_peak_32_30_branch_script -->650<!-- /metric:single_peak_32_30_branch_script --> | <!-- metric:single_peak_32_30_branch_witness -->93<!-- /metric:single_peak_32_30_branch_witness --> | 32 | 0 (0 bytes) | <!-- metric:single_peak_32_30_branch_stack -->34<!-- /metric:single_peak_32_30_branch_stack --> | <!-- metric:single_peak_32_30_branch_executed -->494<!-- /metric:single_peak_32_30_branch_executed --> |
| 128 | 53 | Arithmetic phase check | <!-- metric:single_peak_128_arithmetic_script -->2285<!-- /metric:single_peak_128_arithmetic_script --> | <!-- metric:single_peak_128_arithmetic_witness -->375<!-- /metric:single_peak_128_arithmetic_witness --> | 128 | 0 (0 bytes) | <!-- metric:single_peak_128_arithmetic_stack -->130<!-- /metric:single_peak_128_arithmetic_stack --> | <!-- metric:single_peak_128_arithmetic_executed -->2153<!-- /metric:single_peak_128_arithmetic_executed --> |
| 128 | 53 | Branched phase check | <!-- metric:single_peak_128_branch_script -->2666<!-- /metric:single_peak_128_branch_script --> | <!-- metric:single_peak_128_branch_witness -->375<!-- /metric:single_peak_128_branch_witness --> | 128 | 0 (0 bytes) | <!-- metric:single_peak_128_branch_stack -->130<!-- /metric:single_peak_128_branch_stack --> | <!-- metric:single_peak_128_branch_executed -->2030<!-- /metric:single_peak_128_branch_executed --> |
| 998 | 497 | Arithmetic phase check | <!-- metric:single_peak_998_arithmetic_script -->17946<!-- /metric:single_peak_998_arithmetic_script --> | <!-- metric:single_peak_998_arithmetic_witness -->2993<!-- /metric:single_peak_998_arithmetic_witness --> | 998 | 0 (0 bytes) | <!-- metric:single_peak_998_arithmetic_stack -->1000<!-- /metric:single_peak_998_arithmetic_stack --> | <!-- metric:single_peak_998_arithmetic_executed -->16943<!-- /metric:single_peak_998_arithmetic_executed --> |
| 998 | 497 | Branched phase check | <!-- metric:single_peak_998_branch_script -->20937<!-- /metric:single_peak_998_branch_script --> | <!-- metric:single_peak_998_branch_witness -->2993<!-- /metric:single_peak_998_branch_witness --> | 998 | 0 (0 bytes) | <!-- metric:single_peak_998_branch_stack -->1000<!-- /metric:single_peak_998_branch_stack --> | <!-- metric:single_peak_998_branch_executed -->15950<!-- /metric:single_peak_998_branch_executed --> |

## Security, compatibility and composition

Every value is hostile. Width checks precede numeric comparisons.
Within-width numeric aliases follow the execution profile. Equal
numeric values form a plateau even when their raw encodings differ.
The result establishes a shape relation on supplied numbers. A
caller handles provenance and any exact byte commitments separately.

Each invocation uses `width` ordinary inputs and zero hints.
Combined peak is `width+2` before both caller stacks. The arithmetic
schedule fits width 998 alone and width 996 with two preserved
caller items at exactly 1,000. Additional preloaded data and retained
outputs reduce available room.

All measured leaves use policy `ALL`, stack-limited local tapscript
Consensus, experimental OP_CAT disabled, a synthetic transaction
and zero signature charge. The measured fixtures also pass the local
Policy profile. The opcodes exist in bare, P2SH, P2WSH and tapscript,
subject to context-specific
[script-type](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md) limits.
Evidence is `locally-reproduced`. Execution is `unclassified`.

## Reproduction

```sh
cargo test --locked --lib arithmetic::single_peak::tests
cargo test --locked --test primitive_metrics signed_single_peak_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

Tests enumerate short signed sequences, exercise extrema and
malformed encodings, reject repeated turns, and preserve both
caller stacks at the exact frontier. See the
[knowledge page](../../../knowledge/primitives/signed-single-peak.md).
