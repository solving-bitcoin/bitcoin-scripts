# Exact signed ScriptNum arithmetic progression

Verify a sequence of hostile signed ScriptNums by comparing consecutive
differences to a single carried difference. The difference is compared
as canonical bytes emitted by arithmetic.

## Parameters and stack contract

`verify_arithmetic_progression(n)` accepts generation-time widths
`3..=998`, with no default. It consumes the exact top suffix
`x[0] ... x[n-1]`, in that bottom-to-top order. Every item must have
at most four bytes and is read as a ScriptNum, giving values in
`[-2147483647,2147483647]`. The fragment preserves both caller stacks
and leaves no result. Append a terminal true for an otherwise empty
complete leaf, or consume caller state as required.

The first checked subtraction forms the backward step
`x[n-2] - x[n-1]`. The script maintains the current right neighbor
and this step on main while consuming the remaining operands. Each
backward subtraction emits a canonical ScriptNum encoding; equality
uses exact bytes. The saved step never becomes a numeric operand.

## Script metrics

Both leaves include every width check, progression test, cleanup and
terminal true. The [cross-sum baseline](../../../research/signed-arithmetic-progression/baseline.rs)
checks each triple as `left + right = 2*middle`, comparing arithmetic
results by raw equality. It has the same witness encoding and predicate.

The 3-value fixture is constant at the positive limit. The 32-value
fixture starts at the negative limit and increases by 71,390,911. The
128-value fixture starts at the positive limit and decreases by
17,000,000. The 998-value fixture is all zero. Witness bytes include
the serialized item count and lengths, excluding leaf, control block,
annex and transaction framing. All data coexist at entry. Peak combines
main and alt stacks. Executed non-push operations exclude all pushes.

| Values | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (bytes) | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 3 | Carried difference | <!-- metric:progression_3_carried_script -->25<!-- /metric:progression_3_carried_script --> | <!-- metric:progression_3_carried_witness -->16<!-- /metric:progression_3_carried_witness --> | 3 | 0 (0 bytes) | <!-- metric:progression_3_carried_stack -->5<!-- /metric:progression_3_carried_stack --> | <!-- metric:progression_3_carried_executed -->20<!-- /metric:progression_3_carried_executed --> |
| 3 | Local cross-sums | <!-- metric:progression_3_crossed_script -->24<!-- /metric:progression_3_crossed_script --> | <!-- metric:progression_3_crossed_witness -->16<!-- /metric:progression_3_crossed_witness --> | 3 | 0 (0 bytes) | <!-- metric:progression_3_crossed_stack -->5<!-- /metric:progression_3_crossed_stack --> | <!-- metric:progression_3_crossed_executed -->19<!-- /metric:progression_3_crossed_executed --> |
| 32 | Carried difference | <!-- metric:progression_32_carried_script -->344<!-- /metric:progression_32_carried_script --> | <!-- metric:progression_32_carried_witness -->160<!-- /metric:progression_32_carried_witness --> | 32 | 0 (0 bytes) | <!-- metric:progression_32_carried_stack -->34<!-- /metric:progression_32_carried_stack --> | <!-- metric:progression_32_carried_executed -->281<!-- /metric:progression_32_carried_executed --> |
| 32 | Local cross-sums | <!-- metric:progression_32_crossed_script -->401<!-- /metric:progression_32_crossed_script --> | <!-- metric:progression_32_crossed_witness -->160<!-- /metric:progression_32_crossed_witness --> | 32 | 0 (0 bytes) | <!-- metric:progression_32_crossed_stack -->34<!-- /metric:progression_32_crossed_stack --> | <!-- metric:progression_32_crossed_executed -->338<!-- /metric:progression_32_crossed_executed --> |
| 128 | Carried difference | <!-- metric:progression_128_carried_script -->1400<!-- /metric:progression_128_carried_script --> | <!-- metric:progression_128_carried_witness -->640<!-- /metric:progression_128_carried_witness --> | 128 | 0 (0 bytes) | <!-- metric:progression_128_carried_stack -->130<!-- /metric:progression_128_carried_stack --> | <!-- metric:progression_128_carried_executed -->1145<!-- /metric:progression_128_carried_executed --> |
| 128 | Local cross-sums | <!-- metric:progression_128_crossed_script -->1649<!-- /metric:progression_128_crossed_script --> | <!-- metric:progression_128_crossed_witness -->640<!-- /metric:progression_128_crossed_witness --> | 128 | 0 (0 bytes) | <!-- metric:progression_128_crossed_stack -->130<!-- /metric:progression_128_crossed_stack --> | <!-- metric:progression_128_crossed_executed -->1394<!-- /metric:progression_128_crossed_executed --> |
| 998 | Carried difference | <!-- metric:progression_998_carried_script -->10970<!-- /metric:progression_998_carried_script --> | <!-- metric:progression_998_carried_witness -->1001<!-- /metric:progression_998_carried_witness --> | 998 | 0 (0 bytes) | <!-- metric:progression_998_carried_stack -->1000<!-- /metric:progression_998_carried_stack --> | <!-- metric:progression_998_carried_executed -->8975<!-- /metric:progression_998_carried_executed --> |
| 998 | Local cross-sums | <!-- metric:progression_998_crossed_script -->12959<!-- /metric:progression_998_crossed_script --> | <!-- metric:progression_998_crossed_witness -->1001<!-- /metric:progression_998_crossed_witness --> | 998 | 0 (0 bytes) | <!-- metric:progression_998_crossed_stack -->1000<!-- /metric:progression_998_crossed_stack --> | <!-- metric:progression_998_crossed_executed -->10964<!-- /metric:progression_998_crossed_executed --> |

## Security, compatibility and composition

Both schedules enforce input width before any arithmetic. Numeric
aliases at most four bytes may reach the arithmetic in the local
Consensus profile. The local Policy profile requires minimal ScriptNums.
This checks a relation on decoded numbers, so a protocol that commits
to exact operand bytes needs a separate binding.

Adjacent differences and cross-sums can have magnitude up to
`4294967294` and may need five bytes. Their canonical byte encodings
are valid equality operands. A successful sequence of at least three
values has absolute step at most `2147483647` because the total span
includes at least two steps. Malformed sequences can still produce
a wide intermediate difference before rejection. Even a valid constant
sequence can produce wide cross-sums. See the
[negative result](../../../knowledge/negative-results/signed-progression.md).

Each call starts with `n` ordinary data items and zero hints. The
carried schedule peaks at `n+2` plus both caller stacks. The tests
reach 1,000 standalone with 998 values and at 996 values with one
item on each caller stack. Preloaded future calls also use stack slots.

The measured policy-compiled leaves use `ALL`. The stack-limited local
tapscript Consensus profile runs with experimental OP_CAT disabled,
520-byte elements, a synthetic transaction and zero signature charge.
The measured leaves also pass the local Policy profile. These opcodes
exist in bare, P2SH, P2WSH and tapscript. The applicable
[script-type](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md) bounds require
context-specific checks. Evidence is `locally-reproduced`;
execution is `unclassified`.

## Reproduction

```sh
cargo test --locked --lib arithmetic::progression::tests
cargo test --locked --test primitive_metrics signed_progression_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

Both schedules match the host predicate across every triple in
`[-8,8]`, signed endpoints, positive and negative steps, and
every single-position mutation of a 32-value fixture. Tests cover
oversized values, numeric aliases, caller state and the exact frontier.
See the [knowledge page](../../../knowledge/primitives/signed-progression.md).
