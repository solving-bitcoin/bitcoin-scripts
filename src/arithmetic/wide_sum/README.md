# Exact wide ScriptNum sum with two numeric outputs

Add two hostile signed ScriptNums and return an exact sum representation
whose two canonical items remain usable by numeric opcodes.

## Parameters and stack contract

`split_scriptnum_sum()` takes no generation parameters. It consumes
`caller | a b` and returns `caller | residual class`. Each input has
at most four bytes. Let `M = 2147483647`. The exact sum is
`residual + class*M`. Both caller stacks survive.

| Sum range | Class | Residual range |
| --- | ---: | --- |
| `[-2*M, -M-1]` | -1 | `[-M, -1]` |
| `[-M, M]` | 0 | `[-M, M]` |
| `[M+1, 2*M]` | 1 | `[1, M]` |

These intervals give one descriptor per sum. Compare two generated
descriptors by class first, then residual within the same class.
The fragment returns data. A complete leaf must consume or bind
both outputs and supply its own terminal predicate.

## Construction

Validate both input widths, then compute a raw sum. The sum fits in
one numeric item if its encoding is at most four bytes. A wider
result implies that both original operands have the same sign.
Drop the wide bytes and choose a signed boundary using one operand.
Subtract that boundary from the operand before adding the other.
Each numeric input and corrected result then fits in four bytes.

The [matched headroom baseline](../../../research/exact-signed-sum-spill/baseline.rs)
instead checks signed headroom before addition. Both schedules
compute the same representation.

## Script metrics

Rows for one split include both guards, exact checks for both
outputs, and terminal true. The ordering fixture computes two
splits and checks the generated descriptors lexicographically,
then verifies the Boolean result and leaves true. The
[ordering fixture](../../../research/exact-signed-sum-spill/fixture.rs)
is a research consumer of generated descriptors.

Data witness includes item count and item lengths and excludes
leaf, control block, annex and transaction. Every ordinary item
coexists at entry. Peak combines both stacks. Executed non-push
counts include processed branch delimiters. All rows use central
compilation policy `ALL`.

| Fixture | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (bytes) | Combined peak | Executed non-push ops |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `M + (-M)` | Post-add size | <!-- metric:wide_sum_central_post_script -->49<!-- /metric:wide_sum_central_post_script --> | <!-- metric:wide_sum_central_post_witness -->11<!-- /metric:wide_sum_central_post_witness --> | 2 | 0 (0 bytes) | <!-- metric:wide_sum_central_post_stack -->5<!-- /metric:wide_sum_central_post_stack --> | <!-- metric:wide_sum_central_post_executed -->22<!-- /metric:wide_sum_central_post_executed --> |
| `M + (-M)` | Pre-add headroom | <!-- metric:wide_sum_central_pre_script -->69<!-- /metric:wide_sum_central_pre_script --> | <!-- metric:wide_sum_central_pre_witness -->11<!-- /metric:wide_sum_central_pre_witness --> | 2 | 0 (0 bytes) | <!-- metric:wide_sum_central_pre_stack -->4<!-- /metric:wide_sum_central_pre_stack --> | <!-- metric:wide_sum_central_pre_executed -->27<!-- /metric:wide_sum_central_pre_executed --> |
| `M + 1` | Post-add size | <!-- metric:wide_sum_positive_post_script -->49<!-- /metric:wide_sum_positive_post_script --> | <!-- metric:wide_sum_positive_post_witness -->8<!-- /metric:wide_sum_positive_post_witness --> | 2 | 0 (0 bytes) | <!-- metric:wide_sum_positive_post_stack -->5<!-- /metric:wide_sum_positive_post_stack --> | <!-- metric:wide_sum_positive_post_executed -->27<!-- /metric:wide_sum_positive_post_executed --> |
| `M + 1` | Pre-add headroom | <!-- metric:wide_sum_positive_pre_script -->69<!-- /metric:wide_sum_positive_pre_script --> | <!-- metric:wide_sum_positive_pre_witness -->8<!-- /metric:wide_sum_positive_pre_witness --> | 2 | 0 (0 bytes) | <!-- metric:wide_sum_positive_pre_stack -->4<!-- /metric:wide_sum_positive_pre_stack --> | <!-- metric:wide_sum_positive_pre_executed -->28<!-- /metric:wide_sum_positive_pre_executed --> |
| `-M - 1` | Post-add size | <!-- metric:wide_sum_negative_post_script -->49<!-- /metric:wide_sum_negative_post_script --> | <!-- metric:wide_sum_negative_post_witness -->8<!-- /metric:wide_sum_negative_post_witness --> | 2 | 0 (0 bytes) | <!-- metric:wide_sum_negative_post_stack -->5<!-- /metric:wide_sum_negative_post_stack --> | <!-- metric:wide_sum_negative_post_executed -->27<!-- /metric:wide_sum_negative_post_executed --> |
| `-M - 1` | Pre-add headroom | <!-- metric:wide_sum_negative_pre_script -->69<!-- /metric:wide_sum_negative_pre_script --> | <!-- metric:wide_sum_negative_pre_witness -->8<!-- /metric:wide_sum_negative_pre_witness --> | 2 | 0 (0 bytes) | <!-- metric:wide_sum_negative_pre_stack -->4<!-- /metric:wide_sum_negative_pre_stack --> | <!-- metric:wide_sum_negative_pre_executed -->28<!-- /metric:wide_sum_negative_pre_executed --> |
| `M + 1 < M + 2` | Post-add size | <!-- metric:wide_sum_order_post_script -->106<!-- /metric:wide_sum_order_post_script --> | <!-- metric:wide_sum_order_post_witness -->15<!-- /metric:wide_sum_order_post_witness --> | 4 | 0 (0 bytes) | <!-- metric:wide_sum_order_post_stack -->7<!-- /metric:wide_sum_order_post_stack --> | <!-- metric:wide_sum_order_post_executed -->63<!-- /metric:wide_sum_order_post_executed --> |
| `M + 1 < M + 2` | Pre-add headroom | <!-- metric:wide_sum_order_pre_script -->146<!-- /metric:wide_sum_order_pre_script --> | <!-- metric:wide_sum_order_pre_witness -->15<!-- /metric:wide_sum_order_pre_witness --> | 4 | 0 (0 bytes) | <!-- metric:wide_sum_order_pre_stack -->6<!-- /metric:wide_sum_order_pre_stack --> | <!-- metric:wide_sum_order_pre_executed -->65<!-- /metric:wide_sum_order_pre_executed --> |

## Security, compatibility and composition

Input width is checked before arithmetic. Within-width numeric
aliases follow the active profile. The local Consensus profile
permits them and local Policy requires minimal numbers. The
numeric relation does not authenticate raw witness bytes. The
ordering consumer assumes Script-generated descriptors. An arbitrary
witness claiming to contain a descriptor would need separate class,
range and provenance checks.

Both measured profiles use pinned local tapscript execution with
the 520-byte element and 1,000-item combined limits. The trace uses
the local Consensus profile with experimental OP_CAT disabled,
a synthetic transaction and zero signature charge. Each split
needs two ordinary inputs and zero hints. The ordering fixture
starts with four ordinary inputs and zero hints. All preserved
caller state and parked descriptors count toward the stack bound.
The post-add split reserves five live items before caller state.
Its negative-wide fixture reaches exactly 1,000 with 995 caller
items, and one more fails.

The opcodes exist in bare, P2SH, P2WSH and tapscript. Each context
has its own [script-type](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md) limits. Evidence is
`locally-reproduced`; execution is `unclassified`.

## Reproduction

```sh
cargo test --locked --lib arithmetic::wide_sum::tests
cargo test --locked --test primitive_metrics wide_sum_split_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

The tests check exact host reconstruction, signed endpoints,
numeric aliases, oversized items, caller stacks and composed ordering.
The deterministic full-width test uses StdRng seed `0x5350494c4c`.
See the [knowledge page](../../../knowledge/primitives/wide-scriptnum-sum.md).
