# Opposite-case ASCII pair check

Verify that two hostile raw stack items are opposite-case forms of the same
ASCII letter. The fragment uses one alphabet interval and one numeric gap.

## Parameters and stack contract

`verify_opposite_ascii_case_pair()` takes no generation parameters. It
consumes `caller | left right` in either orientation and preserves both
caller stacks. Each letter must be exactly one raw byte. A failed check
aborts execution. Success leaves no result item. A standalone leaf appends
`OP_TRUE` after all pairs and relies on clean stack for the exact data shape.

For ASCII uppercase bytes 65 through 90, the corresponding lowercase
bytes are 32 greater. With both items one byte long, acceptance requires
`65 <= min(left, right) < 91` and `abs(left - right) == 32`. The first
condition restricts both successful numeric inputs to positive one-byte
ScriptNums, whose encoding equals the ASCII byte. The subtraction remains
well inside the four-byte numeric range. The mapping is given in RFC 20 §2.

## Script metrics

All leaves consume the same interleaved witness pairs and leave one true
item. All pairs coexist at entry. Values cycle from A to Z and alternate
orientation. The single pair has lowercase on top. Data witness bytes
include the serialized item count and item lengths, excluding the leaf,
control block, annex and transaction. The executed count excludes pushes
and includes control delimiters processed by the interpreter. Peak is the
combined main and alt stacks. The two alternate schedules are in the
[research baseline](../../../research/ascii-opposite-case/baseline.rs).

| Pairs | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (bytes) | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Shared interval and gap | <!-- metric:ascii_case_1_range_gap_script -->21<!-- /metric:ascii_case_1_range_gap_script --> | <!-- metric:ascii_case_1_range_gap_witness -->5<!-- /metric:ascii_case_1_range_gap_witness --> | 2 | 0 (0 bytes) | <!-- metric:ascii_case_1_range_gap_stack -->5<!-- /metric:ascii_case_1_range_gap_stack --> | <!-- metric:ascii_case_1_range_gap_executed -->12<!-- /metric:ascii_case_1_range_gap_executed --> |
| 1 | Synthesize raw mate | <!-- metric:ascii_case_1_mate_script -->32<!-- /metric:ascii_case_1_mate_script --> | <!-- metric:ascii_case_1_mate_witness -->5<!-- /metric:ascii_case_1_mate_witness --> | 2 | 0 (0 bytes) | <!-- metric:ascii_case_1_mate_stack -->5<!-- /metric:ascii_case_1_mate_stack --> | <!-- metric:ascii_case_1_mate_executed -->12<!-- /metric:ascii_case_1_mate_executed --> |
| 1 | Independent folds | <!-- metric:ascii_case_1_fold_script -->46<!-- /metric:ascii_case_1_fold_script --> | <!-- metric:ascii_case_1_fold_witness -->5<!-- /metric:ascii_case_1_fold_witness --> | 2 | 0 (0 bytes) | <!-- metric:ascii_case_1_fold_stack -->7<!-- /metric:ascii_case_1_fold_stack --> | <!-- metric:ascii_case_1_fold_executed -->26<!-- /metric:ascii_case_1_fold_executed --> |
| 128 | Shared interval and gap | <!-- metric:ascii_case_128_range_gap_script -->2561<!-- /metric:ascii_case_128_range_gap_script --> | <!-- metric:ascii_case_128_range_gap_witness -->515<!-- /metric:ascii_case_128_range_gap_witness --> | 256 | 0 (0 bytes) | <!-- metric:ascii_case_128_range_gap_stack -->259<!-- /metric:ascii_case_128_range_gap_stack --> | <!-- metric:ascii_case_128_range_gap_executed -->1536<!-- /metric:ascii_case_128_range_gap_executed --> |
| 128 | Synthesize raw mate | <!-- metric:ascii_case_128_mate_script -->3969<!-- /metric:ascii_case_128_mate_script --> | <!-- metric:ascii_case_128_mate_witness -->515<!-- /metric:ascii_case_128_mate_witness --> | 256 | 0 (0 bytes) | <!-- metric:ascii_case_128_mate_stack -->259<!-- /metric:ascii_case_128_mate_stack --> | <!-- metric:ascii_case_128_mate_executed -->1536<!-- /metric:ascii_case_128_mate_executed --> |
| 128 | Independent folds | <!-- metric:ascii_case_128_fold_script -->5761<!-- /metric:ascii_case_128_fold_script --> | <!-- metric:ascii_case_128_fold_witness -->515<!-- /metric:ascii_case_128_fold_witness --> | 256 | 0 (0 bytes) | <!-- metric:ascii_case_128_fold_stack -->261<!-- /metric:ascii_case_128_fold_stack --> | <!-- metric:ascii_case_128_fold_executed -->3328<!-- /metric:ascii_case_128_fold_executed --> |

## Security, compatibility and composition

Both input bytes are hostile. The interval excludes punctuation pairs
separated by 32. Exact raw sizes exclude numeric aliases such as `41 00`.
This verifies one ASCII relation and makes no authentication claim.
Bare, P2SH, P2WSH and tapscript share the opcodes. The applicable
[script-type](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md) bounds must be checked for
each context.

The pinned local tapscript profiles enforce the 520-byte element and
1,000-item combined limits. Both accept the measured leaves. Measurements
use the stack-limited local Consensus profile with zero signature charge.
Policy compilation applies `ALL` to all fixtures. Evidence is
`locally-reproduced` and execution is `unclassified`.

With `n >= 1` preloaded pairs and `c` caller items across both stacks,
the shared interval and gap schedule peaks at `2*n+c+3`. The standalone
frontier is 498 pairs. At 497 pairs, three caller items give peak 1,000,
and one more item fails. Every pair supplies two ordinary items and zero
hints, including at the frontier.

## Reproduction

```sh
cargo test --locked --lib support::ascii_case::tests
cargo test --locked --test primitive_metrics ascii_opposite_case_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

The focused suite compares all 65,536 ordered byte pairs with the host
predicate for all three schedules under both local profiles. It also
checks malformed items, numeric aliases, both caller stacks and the exact
combined frontier. See the
[knowledge page](../../../knowledge/primitives/ascii-opposite-case.md).
