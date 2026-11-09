# Uniform circular step over canonical nibbles

Verify that adjacent hostile nibble values all move the same shortest
distance around the 16-value circle, allowing the direction to change.
The fragment consumes the input and returns the common distance in
`0..=8`. There are no hints.

## Parameters and stack contract

`u4_uniform_lee_step(n)` requires an explicit count from 2 through 997.
With stacks written bottom to top, the main suffix changes from
`x[0] ... x[n-1]` to a canonical ScriptNum distance. The first and last
items are not compared as an extra edge. A mismatch fails verification.
Every input is byte-canonical and range-checked. The scan removes its
own scratch state and preserves both caller stacks for an exact suffix.
The caller must use or remove the output and satisfy a terminal predicate
with a clean stack.

For an edge, let `a = abs(x - y)`. The circular distance is
`min(a, 16-a) = 8 - abs(a-8)`. The reverse scan compares
`abs(a-8)` instead of converting every edge to the final distance.
It saves the common comparison value on the altstack and restores
the distance once. The intermediate ranges are bounded by 16 in
magnitude. No lookup table is needed.

The combined peak is at most `n + 3` plus preserved caller items.
The local width-997 test reaches 1,000. Width 995 also reaches 1,000
with two preserved items, and adding another fails. All `n` ordinary
items coexist at entry. Hints occupy zero items and zero bytes.
Any values held for a later invocation count as preserved caller state.

## Script metrics

Both complete leaves check every edge, compare the same output against
canonical ScriptNum 3, and leave one true item. The
[direct baseline](../../../../research/uniform-u4-lee-step/baseline.rs)
uses the identical scan and evaluates `min(a, 16-a)` on every edge.
The fixture begins at 14. At each index `i >= 1` it adds 3 modulo 16
except when `i` is divisible by three, when it subtracts 3. Serialized
witness bytes include the CompactSize count and item prefixes, excluding
the leaf, control block, annex, and transaction. Combined peak includes
both stacks. Executed counts include non-push operations in the
complete leaf. Both measured schedules are branch-free.

| Inputs | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (serialized bytes) | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | Centered magnitude | <!-- metric:lee_step_2_centered_script -->35<!-- /metric:lee_step_2_centered_script --> | <!-- metric:lee_step_2_centered_witness -->5<!-- /metric:lee_step_2_centered_witness --> | 2 | 0 (0 bytes) | <!-- metric:lee_step_2_centered_stack -->5<!-- /metric:lee_step_2_centered_stack --> | <!-- metric:lee_step_2_centered_executed -->25<!-- /metric:lee_step_2_centered_executed --> |
| 2 | Direct distance | <!-- metric:lee_step_2_direct_script -->34<!-- /metric:lee_step_2_direct_script --> | <!-- metric:lee_step_2_direct_witness -->5<!-- /metric:lee_step_2_direct_witness --> | 2 | 0 (0 bytes) | <!-- metric:lee_step_2_direct_stack -->5<!-- /metric:lee_step_2_direct_stack --> | <!-- metric:lee_step_2_direct_executed -->25<!-- /metric:lee_step_2_direct_executed --> |
| 4 | Centered magnitude | <!-- metric:lee_step_4_centered_script -->77<!-- /metric:lee_step_4_centered_script --> | <!-- metric:lee_step_4_centered_witness -->9<!-- /metric:lee_step_4_centered_witness --> | 4 | 0 (0 bytes) | <!-- metric:lee_step_4_centered_stack -->7<!-- /metric:lee_step_4_centered_stack --> | <!-- metric:lee_step_4_centered_executed -->59<!-- /metric:lee_step_4_centered_executed --> |
| 4 | Direct distance | <!-- metric:lee_step_4_direct_script -->80<!-- /metric:lee_step_4_direct_script --> | <!-- metric:lee_step_4_direct_witness -->9<!-- /metric:lee_step_4_direct_witness --> | 4 | 0 (0 bytes) | <!-- metric:lee_step_4_direct_stack -->7<!-- /metric:lee_step_4_direct_stack --> | <!-- metric:lee_step_4_direct_executed -->63<!-- /metric:lee_step_4_direct_executed --> |
| 32 | Centered magnitude | <!-- metric:lee_step_32_centered_script -->665<!-- /metric:lee_step_32_centered_script --> | <!-- metric:lee_step_32_centered_witness -->62<!-- /metric:lee_step_32_centered_witness --> | 32 | 0 (0 bytes) | <!-- metric:lee_step_32_centered_stack -->35<!-- /metric:lee_step_32_centered_stack --> | <!-- metric:lee_step_32_centered_executed -->535<!-- /metric:lee_step_32_centered_executed --> |
| 32 | Direct distance | <!-- metric:lee_step_32_direct_script -->724<!-- /metric:lee_step_32_direct_script --> | <!-- metric:lee_step_32_direct_witness -->62<!-- /metric:lee_step_32_direct_witness --> | 32 | 0 (0 bytes) | <!-- metric:lee_step_32_direct_stack -->35<!-- /metric:lee_step_32_direct_stack --> | <!-- metric:lee_step_32_direct_executed -->595<!-- /metric:lee_step_32_direct_executed --> |
| 128 | Centered magnitude | <!-- metric:lee_step_128_centered_script -->2681<!-- /metric:lee_step_128_centered_script --> | <!-- metric:lee_step_128_centered_witness -->248<!-- /metric:lee_step_128_centered_witness --> | 128 | 0 (0 bytes) | <!-- metric:lee_step_128_centered_stack -->131<!-- /metric:lee_step_128_centered_stack --> | <!-- metric:lee_step_128_centered_executed -->2167<!-- /metric:lee_step_128_centered_executed --> |
| 128 | Direct distance | <!-- metric:lee_step_128_direct_script -->2932<!-- /metric:lee_step_128_direct_script --> | <!-- metric:lee_step_128_direct_witness -->248<!-- /metric:lee_step_128_direct_witness --> | 128 | 0 (0 bytes) | <!-- metric:lee_step_128_direct_stack -->131<!-- /metric:lee_step_128_direct_stack --> | <!-- metric:lee_step_128_direct_executed -->2419<!-- /metric:lee_step_128_direct_executed --> |

## Security, compatibility and execution

The relation permits direction changes and does not bind a particular
walk, orientation, or starting point. For example, both `[0, 3, 6]`
and `[14, 1, 14]` have common distance 3. It supplies no cryptographic
authentication or keys. A caller requiring externally committed
data must bind the same inputs separately.

All measured leaves use `CompileOptions::ALL` through the central
policy and the pinned local tapscript Consensus profile, with the
520-byte item and 1,000-item combined-stack limits and zero signature
validation charge. Evidence is `locally-reproduced` and execution is
`unclassified`. Stack and arithmetic opcodes are available in bare,
P2SH, P2WSH, and tapscript, with legacy size and opcode-count limits
evaluated separately. See [script types](../../../../docs/script-types.md)
and [standardness](../../../../docs/standardness.md).

## Reproduction

```sh
cargo test --locked --lib arithmetic::u4::lee_step::tests
cargo test --locked --test primitive_metrics lee_step_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

Tests check all ordered pairs and triples against a host model using
forward and backward modular differences. They also exercise direction
changes, zero and antipodal steps, malformed inputs at every position,
a wrong output, input-count mismatches, and the stack frontier. See the
[knowledge entry](../../../../knowledge/primitives/u4-lee-step.md).
