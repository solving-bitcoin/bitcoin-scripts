# Unique mismatch index of opaque item vectors

Locate the sole index at which two fixed-width vectors differ by raw
byte equality. Both vectors are hostile. The fragment rejects equal
vectors and vectors with at least two mismatches.

## Parameters and stack contract

`unique_mismatch_index(n)` takes a generation-time width in `1..=500`,
with no default. From bottom to top, the main suffix is
`a[0] b[0] ... a[n-1] b[n-1]`. Success consumes all pairs and returns
one canonical zero-based index. Both caller stacks survive. Index
zero is data. A complete leaf should compare or consume the result
and supply the intended terminal predicate.

The fragment scans pairs from the top. It consumes the first pair
before allocating one private altstack item. That item is zero until
a mismatch is found, then it stores the original index plus one.
A later mismatch must find that state equal to zero, so a second
mismatch fails. The final check requires a nonzero state and converts
it to a zero-based index.

## Script metrics

Every row measures a complete leaf that includes all comparisons,
uniqueness, exact index equality and terminal true. The
[baseline](../../../research/opaque-single-mismatch/baseline.rs) parks
every equality flag on alt before decoding a unique false index.
Both use the same deterministic fixture. Each left item is its
two-byte little-endian index, and its right counterpart matches except
at the listed mismatch, where the right item is raw `ff`.

Data witness bytes include serialized count and item lengths, and
exclude leaf, control block, annex and transaction framing. All
ordinary items coexist at entry. Stack peak combines both stacks.
The executed non-push count includes processed branch delimiters.

| Pairs | Mismatch index | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (bytes) | Combined peak | Executed non-push ops |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0 | Fused reverse scan | <!-- metric:unique_mismatch_1_fused_script -->8<!-- /metric:unique_mismatch_1_fused_script --> | <!-- metric:unique_mismatch_1_fused_witness -->6<!-- /metric:unique_mismatch_1_fused_witness --> | 2 | 0 (0 bytes) | <!-- metric:unique_mismatch_1_fused_stack -->2<!-- /metric:unique_mismatch_1_fused_stack --> | <!-- metric:unique_mismatch_1_fused_executed -->6<!-- /metric:unique_mismatch_1_fused_executed --> |
| 1 | 0 | Materialized equality mask | <!-- metric:unique_mismatch_1_dense_script -->15<!-- /metric:unique_mismatch_1_dense_script --> | <!-- metric:unique_mismatch_1_dense_witness -->6<!-- /metric:unique_mismatch_1_dense_witness --> | 2 | 0 (0 bytes) | <!-- metric:unique_mismatch_1_dense_stack -->2<!-- /metric:unique_mismatch_1_dense_stack --> | <!-- metric:unique_mismatch_1_dense_executed -->10<!-- /metric:unique_mismatch_1_dense_executed --> |
| 32 | 0 | Fused reverse scan | <!-- metric:unique_mismatch_32_fused_script -->278<!-- /metric:unique_mismatch_32_fused_script --> | <!-- metric:unique_mismatch_32_fused_witness -->192<!-- /metric:unique_mismatch_32_fused_witness --> | 64 | 0 (0 bytes) | <!-- metric:unique_mismatch_32_fused_stack -->64<!-- /metric:unique_mismatch_32_fused_stack --> | <!-- metric:unique_mismatch_32_fused_executed -->106<!-- /metric:unique_mismatch_32_fused_executed --> |
| 32 | 0 | Materialized equality mask | <!-- metric:unique_mismatch_32_dense_script -->279<!-- /metric:unique_mismatch_32_dense_script --> | <!-- metric:unique_mismatch_32_dense_witness -->192<!-- /metric:unique_mismatch_32_dense_witness --> | 64 | 0 (0 bytes) | <!-- metric:unique_mismatch_32_dense_stack -->64<!-- /metric:unique_mismatch_32_dense_stack --> | <!-- metric:unique_mismatch_32_dense_executed -->165<!-- /metric:unique_mismatch_32_dense_executed --> |
| 128 | 43 | Fused reverse scan | <!-- metric:unique_mismatch_128_fused_script -->1144<!-- /metric:unique_mismatch_128_fused_script --> | <!-- metric:unique_mismatch_128_fused_witness -->770<!-- /metric:unique_mismatch_128_fused_witness --> | 256 | 0 (0 bytes) | <!-- metric:unique_mismatch_128_fused_stack -->256<!-- /metric:unique_mismatch_128_fused_stack --> | <!-- metric:unique_mismatch_128_fused_executed -->394<!-- /metric:unique_mismatch_128_fused_executed --> |
| 128 | 43 | Materialized equality mask | <!-- metric:unique_mismatch_128_dense_script -->1145<!-- /metric:unique_mismatch_128_dense_script --> | <!-- metric:unique_mismatch_128_dense_witness -->770<!-- /metric:unique_mismatch_128_dense_witness --> | 256 | 0 (0 bytes) | <!-- metric:unique_mismatch_128_dense_stack -->256<!-- /metric:unique_mismatch_128_dense_stack --> | <!-- metric:unique_mismatch_128_dense_executed -->645<!-- /metric:unique_mismatch_128_dense_executed --> |
| 500 | 499 | Fused reverse scan | <!-- metric:unique_mismatch_500_fused_script -->4865<!-- /metric:unique_mismatch_500_fused_script --> | <!-- metric:unique_mismatch_500_fused_witness -->3002<!-- /metric:unique_mismatch_500_fused_witness --> | 1000 | 0 (0 bytes) | <!-- metric:unique_mismatch_500_fused_stack -->1000<!-- /metric:unique_mismatch_500_fused_stack --> | <!-- metric:unique_mismatch_500_fused_executed -->1507<!-- /metric:unique_mismatch_500_fused_executed --> |
| 500 | 499 | Materialized equality mask | <!-- metric:unique_mismatch_500_dense_script -->4866<!-- /metric:unique_mismatch_500_dense_script --> | <!-- metric:unique_mismatch_500_dense_witness -->3002<!-- /metric:unique_mismatch_500_dense_witness --> | 1000 | 0 (0 bytes) | <!-- metric:unique_mismatch_500_dense_stack -->1000<!-- /metric:unique_mismatch_500_dense_stack --> | <!-- metric:unique_mismatch_500_dense_executed -->2505<!-- /metric:unique_mismatch_500_dense_executed --> |

## Security, compatibility and composition

`OP_EQUAL` compares exact bytes, including empty values, zero encodings,
duplicates and arbitrary nonnumeric items. This is a relation on the
supplied pair sequence. A protocol must bind the origin or intended
alignment of the vectors separately.

Each invocation has `2*n` ordinary data items and zero hints. The fused
and dense schedules reach a combined peak of `2*n` with no caller state,
so 500 pairs fit exactly in the local stack-limited profile. At 499 pairs
the test preserves one main and one alt caller item at 1,000, and one
more fails. A variant that creates state before consuming any pair
requires 1,001 at width 500. Remaining inputs, retained outputs and
both caller stacks count during composition.

All measured leaves compile with policy `ALL`. The stack-limited
local tapscript Consensus profile uses the 520-byte element bound,
a synthetic transaction, experimental OP_CAT disabled and zero
signature charge. The fixtures also pass the local Policy profile,
whose data item cap is 80 bytes. The opcodes exist in bare, P2SH,
P2WSH and tapscript, with different applicable resource and policy
limits. See [script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md). Evidence is
`locally-reproduced`; execution is `unclassified`.

## Reproduction

```sh
cargo test --locked --lib support::mismatch::tests
cargo test --locked --test primitive_metrics opaque_mismatch_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

Tests enumerate every equality mask through eight pairs and verify the
host index or reject. They also check a second mismatch, wrong output,
short and long suffixes, byte-size boundaries and exact live-state limits.
See the [knowledge page](../../../knowledge/primitives/opaque-unique-mismatch.md).
