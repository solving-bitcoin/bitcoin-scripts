# Hinted floor midpoint of signed ScriptNums

Verify the floor of the mean of two hostile signed ScriptNums
with a canonical proposed-result hint and no separate parity item.

## Parameters and stack contract

`verify_floor_midpoint()` has no generation parameters. Main
starts with `caller | a b q`. Each input is at most four bytes
and the proposed midpoint `q` must be a canonical ScriptNum.
The fragment consumes all three items and returns the verified
canonical `q`. Both caller stacks survive. The caller must
bind or consume the result and supply any terminal predicate.

Let `s = a+b`. Exactly one integer `q` satisfies
`s = 2*q` or `s = 2*q+1`. The script first compares the canonical
encodings of `s` and `2*q` byte-for-byte. If they differ, it compares
`s` with `q+(q+1)`, after checking that `q+1` fits in a numeric
operand. Canonical arithmetic results may be five bytes and are
used only by raw equality. For `q=2147483647`, a correct sum can
only take the even branch.

## Script metrics and witness layout

Both schedules verify the same floor midpoint and require the same
canonical proposed-result hint. The
[explicit parity baseline](../../../research/hinted-signed-midpoint/baseline.rs)
also takes a mandatory parity hint after each `q`. Tapscript
MINIMALIF checks that hint as exactly empty or `01`. Both schedules
verify the exact returned value after each call and finish with true.
Batches preload all records in listed order and consume them in
reverse. Each returned value is checked and removed before the
next call.

Let `M=2147483647`. The even fixture is `(M,M)`, the odd fixture
is `(-M,-M+1)`, and the
[mixed batches](../../../research/hinted-signed-midpoint/fixture.rs)
cycle `(M,M), (-M,-M+1), (-M,M), (0,-1)`. Data witness bytes include
the overall item count and every item length. They exclude leaf,
control block, annex and transaction framing. Hint bytes include
each hint's own length prefix and exclude the shared item count.
Peak combines both stacks. Executed non-push counts include control
delimiters processed by the interpreter.

| Fixture | Calls | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items | Total data items | Serialized hint bytes | Combined peak | Executed non-push ops |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Even maximum | 1 | Implicit parity | <!-- metric:midpoint_even_implicit_script -->49<!-- /metric:midpoint_even_implicit_script --> | <!-- metric:midpoint_even_implicit_witness -->16<!-- /metric:midpoint_even_implicit_witness --> | 2 | 1 | 3 | <!-- metric:midpoint_even_implicit_hints -->5<!-- /metric:midpoint_even_implicit_hints --> | <!-- metric:midpoint_even_implicit_stack -->6<!-- /metric:midpoint_even_implicit_stack --> | <!-- metric:midpoint_even_implicit_executed -->26<!-- /metric:midpoint_even_implicit_executed --> |
| Even maximum | 1 | Explicit parity | <!-- metric:midpoint_even_explicit_script -->47<!-- /metric:midpoint_even_explicit_script --> | <!-- metric:midpoint_even_explicit_witness -->17<!-- /metric:midpoint_even_explicit_witness --> | 2 | 2 | 4 | <!-- metric:midpoint_even_explicit_hints -->6<!-- /metric:midpoint_even_explicit_hints --> | <!-- metric:midpoint_even_explicit_stack -->7<!-- /metric:midpoint_even_explicit_stack --> | <!-- metric:midpoint_even_explicit_executed -->26<!-- /metric:midpoint_even_explicit_executed --> |
| Odd negative wide | 1 | Implicit parity | <!-- metric:midpoint_odd_implicit_script -->49<!-- /metric:midpoint_odd_implicit_script --> | <!-- metric:midpoint_odd_implicit_witness -->16<!-- /metric:midpoint_odd_implicit_witness --> | 2 | 1 | 3 | <!-- metric:midpoint_odd_implicit_hints -->5<!-- /metric:midpoint_odd_implicit_hints --> | <!-- metric:midpoint_odd_implicit_stack -->6<!-- /metric:midpoint_odd_implicit_stack --> | <!-- metric:midpoint_odd_implicit_executed -->33<!-- /metric:midpoint_odd_implicit_executed --> |
| Odd negative wide | 1 | Explicit parity | <!-- metric:midpoint_odd_explicit_script -->47<!-- /metric:midpoint_odd_explicit_script --> | <!-- metric:midpoint_odd_explicit_witness -->18<!-- /metric:midpoint_odd_explicit_witness --> | 2 | 2 | 4 | <!-- metric:midpoint_odd_explicit_hints -->7<!-- /metric:midpoint_odd_explicit_hints --> | <!-- metric:midpoint_odd_explicit_stack -->7<!-- /metric:midpoint_odd_explicit_stack --> | <!-- metric:midpoint_odd_explicit_executed -->30<!-- /metric:midpoint_odd_explicit_executed --> |
| Mixed batch | 128 | Implicit parity | <!-- metric:midpoint_128_implicit_script -->5889<!-- /metric:midpoint_128_implicit_script --> | <!-- metric:midpoint_128_implicit_witness -->1475<!-- /metric:midpoint_128_implicit_witness --> | 256 | 128 | 384 | <!-- metric:midpoint_128_implicit_hints -->416<!-- /metric:midpoint_128_implicit_hints --> | <!-- metric:midpoint_128_implicit_stack -->387<!-- /metric:midpoint_128_implicit_stack --> | <!-- metric:midpoint_128_implicit_executed -->3776<!-- /metric:midpoint_128_implicit_executed --> |
| Mixed batch | 128 | Explicit parity | <!-- metric:midpoint_128_explicit_script -->5633<!-- /metric:midpoint_128_explicit_script --> | <!-- metric:midpoint_128_explicit_witness -->1667<!-- /metric:midpoint_128_explicit_witness --> | 256 | 256 | 512 | <!-- metric:midpoint_128_explicit_hints -->608<!-- /metric:midpoint_128_explicit_hints --> | <!-- metric:midpoint_128_explicit_stack -->515<!-- /metric:midpoint_128_explicit_stack --> | <!-- metric:midpoint_128_explicit_executed -->3584<!-- /metric:midpoint_128_explicit_executed --> |
| Mixed batch | 249 | Implicit parity | <!-- metric:midpoint_249_implicit_script -->11457<!-- /metric:midpoint_249_implicit_script --> | <!-- metric:midpoint_249_implicit_witness -->2870<!-- /metric:midpoint_249_implicit_witness --> | 498 | 249 | 747 | <!-- metric:midpoint_249_implicit_hints -->811<!-- /metric:midpoint_249_implicit_hints --> | <!-- metric:midpoint_249_implicit_stack -->750<!-- /metric:midpoint_249_implicit_stack --> | <!-- metric:midpoint_249_implicit_executed -->7342<!-- /metric:midpoint_249_implicit_executed --> |
| Mixed batch | 249 | Explicit parity | <!-- metric:midpoint_249_explicit_script -->10959<!-- /metric:midpoint_249_explicit_script --> | <!-- metric:midpoint_249_explicit_witness -->3243<!-- /metric:midpoint_249_explicit_witness --> | 498 | 498 | 996 | <!-- metric:midpoint_249_explicit_hints -->1184<!-- /metric:midpoint_249_explicit_hints --> | <!-- metric:midpoint_249_explicit_stack -->999<!-- /metric:midpoint_249_explicit_stack --> | <!-- metric:midpoint_249_explicit_executed -->6970<!-- /metric:midpoint_249_explicit_executed --> |
| Mixed batch | 332 | Implicit parity | <!-- metric:midpoint_332_implicit_script -->15273<!-- /metric:midpoint_332_implicit_script --> | <!-- metric:midpoint_332_implicit_witness -->3821<!-- /metric:midpoint_332_implicit_witness --> | 664 | 332 | 996 | <!-- metric:midpoint_332_implicit_hints -->1079<!-- /metric:midpoint_332_implicit_hints --> | <!-- metric:midpoint_332_implicit_stack -->999<!-- /metric:midpoint_332_implicit_stack --> | <!-- metric:midpoint_332_implicit_executed -->9794<!-- /metric:midpoint_332_implicit_executed --> |

## Security, compatibility and composition

All inputs are hostile. Width checks precede numeric use.
Within-width aliases for `a` and `b` follow the execution profile.
Both schedules independently require a canonical `q`. The result
binds a numeric relation to the supplied operands. Caller code
handles authentication and any exact byte commitments.

For `n >= 1` calls, the implicit schedule has `2*n` ordinary items
and `n` hints at entry. The baseline has `2*n` ordinary items and
`2*n` hints. Peaks at the measured boundary are `3*n+3` and
`4*n+3`, before caller state. An implicit 332-call batch and an
explicit 249-call batch each reach 1,000 with one preserved caller
item. Another call fails for each schedule even without that
caller item. All hints coexist at entry.

Measurements use policy `ALL` and stack-limited local tapscript
Consensus with a synthetic transaction, experimental OP_CAT
disabled, and zero signature charge. Measured fixtures also pass
the local Policy profile. The primary construction uses internally
generated conditionals and has opcodes available in bare, P2SH,
P2WSH and tapscript. The baseline uses native tapscript MINIMALIF
for exact parity encoding. See the
[script-type](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md) limits.
Evidence is `locally-reproduced`. Execution is `unclassified`.

## Reproduction

```sh
cargo test --locked --lib arithmetic::midpoint::tests
cargo test --locked --test primitive_metrics hinted_midpoint_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

Tests check the exact floor, wrong midpoint and parity hints, signed
endpoints, raw aliases, malformed suffixes and both batch frontiers.
See the [knowledge page](../../../knowledge/primitives/hinted-midpoint.md).
