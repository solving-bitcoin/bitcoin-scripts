# Opaque lag-match count

Count byte-for-byte matches between positions separated by a fixed,
non-wrapping offset in one hostile opaque vector.

## Parameters and stack contract

`count_opaque_lag_matches(width, lag)` uses a generation-time width
in `2..=999` and a lag in `1..width`, with no defaults. The main stack
starts with `caller | x[0] ... x[width-1]`. The output is
`caller | count`, a canonical ScriptNum in `0..=width-lag`.
Both caller stacks survive. The caller consumes or binds the count
and supplies any terminal predicate.

The count is the number of `i` in `0..width-lag` for which
`x[i] == x[i+lag]` by raw equality. The first comparison creates
the accumulator without pushing an initial zero. Each remaining
comparison copies the earlier member from one fixed depth, consumes
the current later member, and updates the count. The `lag` original
items left at the end are removed while the count is parked on alt.

## Script metrics

Both [comparison schedules](../../../research/opaque-lag-match-count/baseline.rs)
use the same data and exact output. Eager destructive comparison
pushes zero before the first pair. The nondestructive schedule
copies both operands and retains the input until cleanup.

Every leaf includes the count, cleanup, exact output comparison
and terminal true. The fixture repeats seven classes in runs of
four. Each class `c` is encoded by `c % 3 + 1` copies of byte `c`.
Data witness bytes include count and item lengths, excluding
leaf, control block, annex and transaction. Every input coexists
at entry. Peak combines both stacks, and executed counts exclude
pushes. All fixtures compile with policy `ALL`.

| Width | Lag | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (bytes) | Combined peak | Executed non-push ops |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 32 | 1 | Deferred accumulator | <!-- metric:opaque_lag_32_deferred_script -->157<!-- /metric:opaque_lag_32_deferred_script --> | <!-- metric:opaque_lag_32_deferred_witness -->89<!-- /metric:opaque_lag_32_deferred_witness --> | 32 | 0 (0 bytes) | <!-- metric:opaque_lag_32_deferred_stack -->33<!-- /metric:opaque_lag_32_deferred_stack --> | <!-- metric:opaque_lag_32_deferred_executed -->124<!-- /metric:opaque_lag_32_deferred_executed --> |
| 32 | 1 | Eager accumulator | <!-- metric:opaque_lag_32_eager_script -->161<!-- /metric:opaque_lag_32_eager_script --> | <!-- metric:opaque_lag_32_eager_witness -->89<!-- /metric:opaque_lag_32_eager_witness --> | 32 | 0 (0 bytes) | <!-- metric:opaque_lag_32_eager_stack -->34<!-- /metric:opaque_lag_32_eager_stack --> | <!-- metric:opaque_lag_32_eager_executed -->126<!-- /metric:opaque_lag_32_eager_executed --> |
| 32 | 1 | Copy both operands | <!-- metric:opaque_lag_32_copying_script -->238<!-- /metric:opaque_lag_32_copying_script --> | <!-- metric:opaque_lag_32_copying_witness -->89<!-- /metric:opaque_lag_32_copying_witness --> | 32 | 0 (0 bytes) | <!-- metric:opaque_lag_32_copying_stack -->35<!-- /metric:opaque_lag_32_copying_stack --> | <!-- metric:opaque_lag_32_copying_executed -->142<!-- /metric:opaque_lag_32_copying_executed --> |
| 128 | 28 | Deferred accumulator | <!-- metric:opaque_lag_128_deferred_script -->618<!-- /metric:opaque_lag_128_deferred_script --> | <!-- metric:opaque_lag_128_deferred_witness -->365<!-- /metric:opaque_lag_128_deferred_witness --> | 128 | 0 (0 bytes) | <!-- metric:opaque_lag_128_deferred_stack -->129<!-- /metric:opaque_lag_128_deferred_stack --> | <!-- metric:opaque_lag_128_deferred_executed -->415<!-- /metric:opaque_lag_128_deferred_executed --> |
| 128 | 28 | Eager accumulator | <!-- metric:opaque_lag_128_eager_script -->621<!-- /metric:opaque_lag_128_eager_script --> | <!-- metric:opaque_lag_128_eager_witness -->365<!-- /metric:opaque_lag_128_eager_witness --> | 128 | 0 (0 bytes) | <!-- metric:opaque_lag_128_eager_stack -->130<!-- /metric:opaque_lag_128_eager_stack --> | <!-- metric:opaque_lag_128_eager_executed -->417<!-- /metric:opaque_lag_128_eager_executed --> |
| 128 | 28 | Copy both operands | <!-- metric:opaque_lag_128_copying_script -->857<!-- /metric:opaque_lag_128_copying_script --> | <!-- metric:opaque_lag_128_copying_witness -->365<!-- /metric:opaque_lag_128_copying_witness --> | 128 | 0 (0 bytes) | <!-- metric:opaque_lag_128_copying_stack -->131<!-- /metric:opaque_lag_128_copying_stack --> | <!-- metric:opaque_lag_128_copying_executed -->467<!-- /metric:opaque_lag_128_copying_executed --> |
| 998 | 27 | Deferred accumulator | <!-- metric:opaque_lag_998_deferred_script -->5845<!-- /metric:opaque_lag_998_deferred_script --> | <!-- metric:opaque_lag_998_deferred_witness -->2853<!-- /metric:opaque_lag_998_deferred_witness --> | 998 | 0 (0 bytes) | <!-- metric:opaque_lag_998_deferred_stack -->999<!-- /metric:opaque_lag_998_deferred_stack --> | <!-- metric:opaque_lag_998_deferred_executed -->3899<!-- /metric:opaque_lag_998_deferred_executed --> |
| 998 | 27 | Eager accumulator | <!-- metric:opaque_lag_998_eager_script -->5848<!-- /metric:opaque_lag_998_eager_script --> | <!-- metric:opaque_lag_998_eager_witness -->2853<!-- /metric:opaque_lag_998_eager_witness --> | 998 | 0 (0 bytes) | <!-- metric:opaque_lag_998_eager_stack -->1000<!-- /metric:opaque_lag_998_eager_stack --> | <!-- metric:opaque_lag_998_eager_executed -->3901<!-- /metric:opaque_lag_998_eager_executed --> |
| 999 | 27 | Deferred accumulator | <!-- metric:opaque_lag_999_deferred_script -->5851<!-- /metric:opaque_lag_999_deferred_script --> | <!-- metric:opaque_lag_999_deferred_witness -->2856<!-- /metric:opaque_lag_999_deferred_witness --> | 999 | 0 (0 bytes) | <!-- metric:opaque_lag_999_deferred_stack -->1000<!-- /metric:opaque_lag_999_deferred_stack --> | <!-- metric:opaque_lag_999_deferred_executed -->3903<!-- /metric:opaque_lag_999_deferred_executed --> |

## Security, compatibility and composition

Opaque witness items are compared as raw bytes. For example, an
empty item and the single byte `00` are different even though
they can denote the same numeric zero. The count reveals no
positions. A protocol needs a separate binding for any required
sequence provenance or position-specific claim.

All `width` ordinary inputs and zero hints coexist at entry.
The deferred accumulator peaks at `width+1` plus caller state.
It handles 999 inputs alone and 997 with one preserved item on
each stack, both at exactly 1,000. The eager comparison fails at
999 because it creates state before copying any operand. Future
inputs and earlier retained outputs also count as caller state.

The measured leaves use stack-limited local tapscript Consensus,
a synthetic transaction, experimental OP_CAT disabled, and zero
signature charge. Local Policy accepts the metric fixtures and
limits individual witness items to 80 bytes. The local Consensus
profile allows 520-byte items. The opcodes exist in bare, P2SH,
P2WSH and tapscript, subject to context-specific
[script-type](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md) limits.
Evidence is `locally-reproduced`; execution is `unclassified`.

## Reproduction

```sh
cargo test --locked --lib support::lag_count::tests
cargo test --locked --test primitive_metrics opaque_lag_count_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

The focused tests cover every binary vector through width eight
at every valid lag, unequal numeric aliases, oversized raw items,
wrong counts, malformed suffixes, and exact caller-state limits.
See the [knowledge page](../../../knowledge/primitives/opaque-lag-count.md).
