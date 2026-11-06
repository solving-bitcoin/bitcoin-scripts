# Signed saturating ScriptNum addition

`arithmetic::saturating::saturating_add()` consumes two at-most-four-byte
ScriptNums, returning the canonical encoding of their sum clamped to
`[-2,147,483,647, 2,147,483,647]`. There are no parameters or hints.
For an exact two-item suffix it preserves both caller stacks. The output is
numeric, so consume or check it before the terminal predicate of a complete
leaf.

## Parameters

The clamp endpoints are fixed by the four-byte ScriptNum range. The generator
takes no parameters.

## Script metrics

| Schedule | Leaf bytes | Data witness bytes | Data items | Hint items | Peak | In-range ops | Positive overflow ops | Negative overflow ops |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Encoded-width detection | <!-- metric:saturating_width_script -->32<!-- /metric:saturating_width_script --> | <!-- metric:saturating_width_witness -->8<!-- /metric:saturating_width_witness --> | 2 | 0 | <!-- metric:saturating_width_stack -->4<!-- /metric:saturating_width_stack --> | <!-- metric:saturating_width_inrange_executed -->12<!-- /metric:saturating_width_inrange_executed --> | <!-- metric:saturating_width_positive_executed -->13<!-- /metric:saturating_width_positive_executed --> | <!-- metric:saturating_width_negative_executed -->13<!-- /metric:saturating_width_negative_executed --> |
| Pre-addition headroom | <!-- metric:saturating_headroom_script -->32<!-- /metric:saturating_headroom_script --> | <!-- metric:saturating_headroom_witness -->8<!-- /metric:saturating_headroom_witness --> | 2 | 0 | <!-- metric:saturating_headroom_stack -->4<!-- /metric:saturating_headroom_stack --> | <!-- metric:saturating_headroom_inrange_executed -->11<!-- /metric:saturating_headroom_inrange_executed --> | <!-- metric:saturating_headroom_positive_executed -->11<!-- /metric:saturating_headroom_positive_executed --> | <!-- metric:saturating_headroom_negative_executed -->11<!-- /metric:saturating_headroom_negative_executed --> |

The three fixtures use `(MAX, -1)`, `(MAX, 1)` and `(-MAX, -1)`. Leaves
verify the same expected canonical output bytes for each input and leave
true. Compilation uses whole-leaf policy `ALL`. Witness serialization
includes count and length prefixes and excludes script, control block,
annex and transaction. Both data items coexist at entry. Dynamic counts
include active non-push opcodes and encountered branch delimiters.

Measurements are `locally-reproduced` and `unclassified`. The local
tapscript `Consensus` profile enforces stack limits and MINIMALIF, disables
numeric minimality and experimental OP_CAT, and uses a synthetic transaction.
No signatures are executed.

## Security

The operand alias rules follow the execution profile. Inputs should be
authenticated or checked for canonical encodings where the enclosing
protocol depends on them. Saturation is intentionally many-to-one and
changes mixed-sign results if an application changes the fold order.
The arithmetic supplies no cryptographic authentication or one-time key.

## Script compatibility and standardness

The opcodes exist in bare script, P2SH, P2WSH and tapscript. The bare script
and P2SH execution and their relay conditions are unclassified. P2WSH execution
and relay conditions are also unclassified. Tapscript evidence here is the
stack-limited local profile only. See [script types](../../../docs/script-types.md)
and [standardness](../../../docs/standardness.md).

## Witness and hints

The two ordinary items are `lhs rhs` bottom to top, both interpreted as
at-most-four-byte ScriptNums. Neither item is a hint. There are zero hint
items and zero serialized hint bytes. Each preloaded invocation contributes
its full two-item input to the combined limit.

## Stack contract

`caller | lhs rhs -> caller | result`. Altstack is unused. The peak is
four items plus all preserved main- and alt-stack state.

## Operational notes and knowledge-base integration

See the [research note](../../../knowledge/primitives/scriptnum-saturation.md)
for the matched baseline, arithmetic argument, tests and reproduction commands.
The catalog entry is `arithmetic/scriptnum-saturation`. See the
[arithmetic comparison](../../../knowledge/comparisons/arithmetic.md#signed-saturating-scriptnum-addition)
and the [negative result](../../../knowledge/negative-results/scriptnum-saturation.md).
