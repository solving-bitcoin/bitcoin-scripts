# Earliest minimum over u4 inputs

Compute both the minimum nibble and its first zero-based position among
canonical, adversarially supplied ScriptNums. The packed-table fragment uses
one priority accumulator and a fixed 16-entry table. It has no witness hints.

## Parameters and stack contract

`u4_earliest_argmin(n)` requires an explicit width from 1 through 980.
With stacks written bottom to top, the main stack suffix changes from
`x[0] ... x[n-1]` to `minimum index`. Both outputs are canonical ScriptNums.
Every input is validated, including those that cannot beat the best score.
The fragment expects exactly that suffix, preserves deeper main-stack items,
and restores the altstack after temporarily saving the priority during table
cleanup. A leaf must use or remove its outputs and satisfy the terminal
predicate and clean-stack requirement.

Let `P` be the next power of two at least `n`. The score `value * P + index`
sorts first by value and then by index because every index is below `P`.
A reverse scan minimizes this score starting from sentinel `16 * P`.
The table provides `value * P` and four binary thresholds split the result
back into its value and index. At the largest width the sentinel is 16,384,
within the ScriptNum arithmetic range. The combined peak is at most
`n + 20` plus the preserved caller state. With two caller items, width 978
reaches 1,000 and an additional caller item fails the local stack limit.

## Script metrics

All schedules consume the same complete data witness at entry and use the
same terminal predicate. It checks the index, checks the minimum, and leaves
one true item. Reported locking-script bytes include setup, input checks,
cleanup, and that predicate. Serialized data includes the CompactSize item
count and per-item lengths and excludes the leaf, control block, annex, and
transaction. The inputs are `(7 * i mod 15) + 1` except for zeros at
`floor(n / 3)` and `n - 1`. There are no hints, and each input occupies one
ordinary item. Stack peak combines main and alt stacks. The opcode trace
counts executed non-push instructions and branch delimiters visited by the
interpreter, so branch-heavy rows are specific to this witness.

| Width | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (serialized bytes) | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | Packed table | <!-- metric:u4_argmin_4_table_script -->162<!-- /metric:u4_argmin_4_table_script --> | <!-- metric:u4_argmin_4_table_witness -->7<!-- /metric:u4_argmin_4_table_witness --> | 4 | 0 (0 bytes) | <!-- metric:u4_argmin_4_table_stack -->24<!-- /metric:u4_argmin_4_table_stack --> | <!-- metric:u4_argmin_4_table_executed -->77<!-- /metric:u4_argmin_4_table_executed --> |
| 4 | Packed shift | <!-- metric:u4_argmin_4_shift_script -->125<!-- /metric:u4_argmin_4_shift_script --> | <!-- metric:u4_argmin_4_shift_witness -->7<!-- /metric:u4_argmin_4_shift_witness --> | 4 | 0 (0 bytes) | <!-- metric:u4_argmin_4_shift_stack -->8<!-- /metric:u4_argmin_4_shift_stack --> | <!-- metric:u4_argmin_4_shift_executed -->75<!-- /metric:u4_argmin_4_shift_executed --> |
| 4 | Two registers | <!-- metric:u4_argmin_4_direct_script -->95<!-- /metric:u4_argmin_4_direct_script --> | <!-- metric:u4_argmin_4_direct_witness -->7<!-- /metric:u4_argmin_4_direct_witness --> | 4 | 0 (0 bytes) | <!-- metric:u4_argmin_4_direct_stack -->9<!-- /metric:u4_argmin_4_direct_stack --> | <!-- metric:u4_argmin_4_direct_executed -->64<!-- /metric:u4_argmin_4_direct_executed --> |
| 32 | Packed table | <!-- metric:u4_argmin_32_table_script -->708<!-- /metric:u4_argmin_32_table_script --> | <!-- metric:u4_argmin_32_table_witness -->63<!-- /metric:u4_argmin_32_table_witness --> | 32 | 0 (0 bytes) | <!-- metric:u4_argmin_32_table_stack -->52<!-- /metric:u4_argmin_32_table_stack --> | <!-- metric:u4_argmin_32_table_executed -->413<!-- /metric:u4_argmin_32_table_executed --> |
| 32 | Packed shift | <!-- metric:u4_argmin_32_shift_script -->847<!-- /metric:u4_argmin_32_shift_script --> | <!-- metric:u4_argmin_32_shift_witness -->63<!-- /metric:u4_argmin_32_shift_witness --> | 32 | 0 (0 bytes) | <!-- metric:u4_argmin_32_shift_stack -->36<!-- /metric:u4_argmin_32_shift_stack --> | <!-- metric:u4_argmin_32_shift_executed -->659<!-- /metric:u4_argmin_32_shift_executed --> |
| 32 | Two registers | <!-- metric:u4_argmin_32_direct_script -->727<!-- /metric:u4_argmin_32_direct_script --> | <!-- metric:u4_argmin_32_direct_witness -->63<!-- /metric:u4_argmin_32_direct_witness --> | 32 | 0 (0 bytes) | <!-- metric:u4_argmin_32_direct_stack -->37<!-- /metric:u4_argmin_32_direct_stack --> | <!-- metric:u4_argmin_32_direct_executed -->484<!-- /metric:u4_argmin_32_direct_executed --> |
| 128 | Packed table | <!-- metric:u4_argmin_128_table_script -->2540<!-- /metric:u4_argmin_128_table_script --> | <!-- metric:u4_argmin_128_table_witness -->255<!-- /metric:u4_argmin_128_table_witness --> | 128 | 0 (0 bytes) | <!-- metric:u4_argmin_128_table_stack -->148<!-- /metric:u4_argmin_128_table_stack --> | <!-- metric:u4_argmin_128_table_executed -->1565<!-- /metric:u4_argmin_128_table_executed --> |
| 128 | Packed shift | <!-- metric:u4_argmin_128_shift_script -->3764<!-- /metric:u4_argmin_128_shift_script --> | <!-- metric:u4_argmin_128_shift_witness -->255<!-- /metric:u4_argmin_128_shift_witness --> | 128 | 0 (0 bytes) | <!-- metric:u4_argmin_128_shift_stack -->132<!-- /metric:u4_argmin_128_shift_stack --> | <!-- metric:u4_argmin_128_shift_executed -->3091<!-- /metric:u4_argmin_128_shift_executed --> |
| 128 | Two registers | <!-- metric:u4_argmin_128_direct_script -->2937<!-- /metric:u4_argmin_128_direct_script --> | <!-- metric:u4_argmin_128_direct_witness -->255<!-- /metric:u4_argmin_128_direct_witness --> | 128 | 0 (0 bytes) | <!-- metric:u4_argmin_128_direct_stack -->133<!-- /metric:u4_argmin_128_direct_stack --> | <!-- metric:u4_argmin_128_direct_executed -->1924<!-- /metric:u4_argmin_128_direct_executed --> |

The packed-shift baseline uses the same score and final split, computing the
scaled value with the existing constant multiplier. The two-register
baseline holds the best value and index and replaces them on a smaller or
equal value during its reverse scan. It has neither a table nor a final
split. Both baselines are under
[`research/packed-u4-argmin/`](../../../../research/packed-u4-argmin/).
The table costs more script and peak stack at width four. At width 128 it
saves 397 leaf bytes and 359 executed non-push operations against two
registers on this fixture, at the cost of 15 additional peak items.

## Security, compatibility and execution

The relation concerns only the items supplied to the fragment. An enclosing
construction must bind the same items if the minimum is meant to describe
data committed elsewhere. A forged tie position, nonminimal encoding, or
out-of-range item cannot satisfy the tested leaf for a fixed input vector.
There is no cryptographic security parameter or one-time key.

All measured leaves use `CompileOptions::ALL` via the repository policy,
the pinned local tapscript Consensus profile with the 520-byte item and
1,000-item combined-stack limits, and no signature validation charge.
Evidence is `locally-reproduced` and deployment is `unclassified`.
The fragment uses ordinary stack, flow-control, and arithmetic opcodes
available in bare, P2SH, P2WSH, and tapscript contexts. Bare, P2SH, and P2WSH
also have context-specific size and legacy opcode-count constraints. No
complete spend or relay policy was tested for any of these contexts.
See [script types](../../../../docs/script-types.md) and
[standardness](../../../../docs/standardness.md).

## Reproduction

```sh
cargo test --locked --lib arithmetic::u4::argmin::tests
cargo test --locked --test primitive_metrics u4_argmin_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

The checks cover all ordered nibble pairs, an exhaustive restricted alphabet
through width four, deterministic vectors with repeated minima, malformed encodings at every
position, forged minimum and index claims, wrong input counts, and a
composed stack-limit case. See the [knowledge entry](../../../../knowledge/primitives/u4-argmin.md).
