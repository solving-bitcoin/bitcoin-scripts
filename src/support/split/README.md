# Stable split of opaque stack items

Route interleaved opaque payloads and hostile binary flags into two stable
subsequences. False payloads stay on main and true payloads move to alt.

## Parameters and stack contract

`stable_split_items(n)` accepts the generation-time pair count `0..=499`.
There is no default. From bottom to top, main starts with
`caller | payload[0] flag[0] ... payload[n-1] flag[n-1]`. On success it holds
`caller | false payloads in input order | false_count`, with a canonical
numeric count on top. Alt holds `alt_caller | true payloads in input order`.
The caller infers the true count as `n - false_count` and consumes both
outputs before the leaf ends. At `n=0`, main gains a zero count and alt is
unchanged.

The initial cursor is `2*n`. At every iteration it equals twice the
number of unprocessed pairs plus the number of processed false payloads.
The next payload and flag can be rolled out at the same depth because the
first roll puts its payload above the cursor. Processing a false flag
replaces two input items with one false payload on main, reducing the
cursor by one. Processing a true flag removes both inputs from main and
appends the payload to alt, reducing the cursor by two. After the last
pair the cursor is the false count.

## Script metrics

All rows use the same deterministic two-byte little-endian payloads and
alternating flags, starting with true. The measured complete leaves check
the returned false count, compare every opaque output on both stacks, and
leave one true item. The [baseline](../../../research/opaque-stable-bipartition/baseline.rs)
maintains a false count and recomputes roll depth from that count and the
generation-time number of remaining pairs.

Data witness bytes include the item count and item-length prefixes.
Leaf, control block, annex and transaction framing are excluded. Peak is
the combined main and alt stacks. Executed non-push counts include
processed branch delimiters. Both profiles accept the measured leaves.
The trace uses the stack-limited local Consensus profile, a synthetic
transaction, experimental OP_CAT disabled, and zero signature charge.
All measured leaves compile with policy `ALL`.

| Pairs | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (bytes) | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 32 | Single cursor | <!-- metric:stable_split_32_cursor_script -->533<!-- /metric:stable_split_32_cursor_script --> | <!-- metric:stable_split_32_cursor_witness -->145<!-- /metric:stable_split_32_cursor_witness --> | 64 | 0 (0 bytes) | <!-- metric:stable_split_32_cursor_stack -->66<!-- /metric:stable_split_32_cursor_stack --> | <!-- metric:stable_split_32_cursor_executed -->337<!-- /metric:stable_split_32_cursor_executed --> |
| 32 | Recomputed depth | <!-- metric:stable_split_32_recomputed_script -->644<!-- /metric:stable_split_32_recomputed_script --> | <!-- metric:stable_split_32_recomputed_witness -->145<!-- /metric:stable_split_32_recomputed_witness --> | 64 | 0 (0 bytes) | <!-- metric:stable_split_32_recomputed_stack -->67<!-- /metric:stable_split_32_recomputed_stack --> | <!-- metric:stable_split_32_recomputed_executed -->385<!-- /metric:stable_split_32_recomputed_executed --> |
| 128 | Single cursor | <!-- metric:stable_split_128_cursor_script -->2119<!-- /metric:stable_split_128_cursor_script --> | <!-- metric:stable_split_128_cursor_witness -->579<!-- /metric:stable_split_128_cursor_witness --> | 256 | 0 (0 bytes) | <!-- metric:stable_split_128_cursor_stack -->258<!-- /metric:stable_split_128_cursor_stack --> | <!-- metric:stable_split_128_cursor_executed -->1345<!-- /metric:stable_split_128_cursor_executed --> |
| 128 | Recomputed depth | <!-- metric:stable_split_128_recomputed_script -->2743<!-- /metric:stable_split_128_recomputed_script --> | <!-- metric:stable_split_128_recomputed_witness -->579<!-- /metric:stable_split_128_recomputed_witness --> | 256 | 0 (0 bytes) | <!-- metric:stable_split_128_recomputed_stack -->259<!-- /metric:stable_split_128_recomputed_stack --> | <!-- metric:stable_split_128_recomputed_executed -->1537<!-- /metric:stable_split_128_recomputed_executed --> |
| 499 | Single cursor | <!-- metric:stable_split_499_cursor_script -->8242<!-- /metric:stable_split_499_cursor_script --> | <!-- metric:stable_split_499_cursor_witness -->2249<!-- /metric:stable_split_499_cursor_witness --> | 998 | 0 (0 bytes) | <!-- metric:stable_split_499_cursor_stack -->1000<!-- /metric:stable_split_499_cursor_stack --> | <!-- metric:stable_split_499_cursor_executed -->5241<!-- /metric:stable_split_499_cursor_executed --> |

## Security, compatibility and composition

Native tapscript MINIMALIF rejects flags other than empty and `01`.
Payloads are arbitrary bytes. The split certifies routing only.
A protocol that relies on flag meaning or on the origin of a payload
must bind those facts separately. Callers must know the exact suffix size
and preserve room for both output groups.

There are `2*n` ordinary data items and zero hints, all at entry. Combined
peak for `n>=1` is `2*n+2` plus live caller items on both stacks. A 499-pair
leaf reaches 1,000 with no caller items. At 498 pairs, a caller main item
and a caller alt item fit exactly, and one more fails. All retained prior
outputs and preloaded future witnesses count toward the same limit.
The recomputed depth requires another live item and rejects at 499.

The opcodes exist in bare, P2SH, and P2WSH scripts, where the exact native
tapscript flag contract cannot be assumed. These contexts also have
different script or opcode size limits. Local tapscript Consensus checks
520-byte elements and local Policy checks the 80-byte witness item cap.
See the [script-type](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md) references. Evidence is
`locally-reproduced`; execution is `unclassified`.

## Reproduction

```sh
cargo test --locked --lib support::split::tests
cargo test --locked --test primitive_metrics stable_bipartition_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

Tests cover all masks through eight pairs against the host stable
partition, hostile flags in every position, duplicate and opaque
payloads, payload and count mutations, element-size boundaries, and
the exact live-stack frontier. See the
[knowledge page](../../../knowledge/primitives/stable-bipartition.md).
