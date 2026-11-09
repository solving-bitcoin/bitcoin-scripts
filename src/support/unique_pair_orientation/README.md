# Unique opaque pair orientation

`opaque_pair_orientations(width)` consumes independent quartets
of opaque stack items. It accepts each quartet only when exactly
one orientation is a byte-for-byte match and returns that orientation
as a canonical bit.

## Parameters and stack contract

Choose a generation-time width in `1..=249` with no default.
Main starts with `caller | a0 b0 c0 d0 ... a[n-1] b[n-1] c[n-1] d[n-1]`.
The fragment consumes these `4*n` data items and leaves
`caller | bit0 ... bit[n-1]`. A zero means `(a,b) = (c,d)` and a
one means `(a,b) = (d,c)`. Both caller stacks survive. A caller
must consume or check the bits before terminating a clean-stack leaf.

Comparing `b` with `d` routes the quartet to its only possible
orientation if a unique match exists. On the straight path the
script verifies `a == c` and `a != b`. On the reversed path it
verifies `b == c` and `a == d`, so the branch condition already
establishes `a != b`. Both schedules consume quartets from the
top, stage private bits on alt, and restore them in original order.

## Script metrics and witness

The matched eager baseline computes both orientation flags
and requires that they differ. Both complete leaves check every
output bit and end in true. The deterministic fixture uses
three-byte payloads and either a straight, reversed or alternating
orientation as labeled. All data items coexist at entry. Witness
bytes include the data count and per-item lengths and exclude leaf,
control block, annex, and transaction. Peak combines both stacks.
Executed non-push counts include encountered branch delimiters.
Neither schedule uses any hints, tables, or signature validation.

| Quartets | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 straight | Branch | <!-- metric:opaque_orientation_straight_branch_script -->23<!-- /metric:opaque_orientation_straight_branch_script --> | <!-- metric:opaque_orientation_straight_branch_witness -->17<!-- /metric:opaque_orientation_straight_branch_witness --> | 4 | 0 (none) | <!-- metric:opaque_orientation_straight_branch_stack -->6<!-- /metric:opaque_orientation_straight_branch_stack --> | <!-- metric:opaque_orientation_straight_branch_executed -->14<!-- /metric:opaque_orientation_straight_branch_executed --> |
| 1 straight | Eager | <!-- metric:opaque_orientation_straight_eager_script -->23<!-- /metric:opaque_orientation_straight_eager_script --> | <!-- metric:opaque_orientation_straight_eager_witness -->17<!-- /metric:opaque_orientation_straight_eager_witness --> | 4 | 0 (none) | <!-- metric:opaque_orientation_straight_eager_stack -->8<!-- /metric:opaque_orientation_straight_eager_stack --> | <!-- metric:opaque_orientation_straight_eager_executed -->21<!-- /metric:opaque_orientation_straight_eager_executed --> |
| 1 reversed | Branch | <!-- metric:opaque_orientation_reversed_branch_script -->23<!-- /metric:opaque_orientation_reversed_branch_script --> | <!-- metric:opaque_orientation_reversed_branch_witness -->17<!-- /metric:opaque_orientation_reversed_branch_witness --> | 4 | 0 (none) | <!-- metric:opaque_orientation_reversed_branch_stack -->6<!-- /metric:opaque_orientation_reversed_branch_stack --> | <!-- metric:opaque_orientation_reversed_branch_executed -->11<!-- /metric:opaque_orientation_reversed_branch_executed --> |
| 1 reversed | Eager | <!-- metric:opaque_orientation_reversed_eager_script -->23<!-- /metric:opaque_orientation_reversed_eager_script --> | <!-- metric:opaque_orientation_reversed_eager_witness -->17<!-- /metric:opaque_orientation_reversed_eager_witness --> | 4 | 0 (none) | <!-- metric:opaque_orientation_reversed_eager_stack -->8<!-- /metric:opaque_orientation_reversed_eager_stack --> | <!-- metric:opaque_orientation_reversed_eager_executed -->21<!-- /metric:opaque_orientation_reversed_eager_executed --> |
| 128 alternating | Branch | <!-- metric:opaque_orientation_128_branch_script -->3071<!-- /metric:opaque_orientation_128_branch_script --> | <!-- metric:opaque_orientation_128_branch_witness -->2051<!-- /metric:opaque_orientation_128_branch_witness --> | 512 | 0 (none) | <!-- metric:opaque_orientation_128_branch_stack -->514<!-- /metric:opaque_orientation_128_branch_stack --> | <!-- metric:opaque_orientation_128_branch_executed -->1854<!-- /metric:opaque_orientation_128_branch_executed --> |
| 128 alternating | Eager | <!-- metric:opaque_orientation_128_eager_script -->3071<!-- /metric:opaque_orientation_128_eager_script --> | <!-- metric:opaque_orientation_128_eager_witness -->2051<!-- /metric:opaque_orientation_128_eager_witness --> | 512 | 0 (none) | <!-- metric:opaque_orientation_128_eager_stack -->516<!-- /metric:opaque_orientation_128_eager_stack --> | <!-- metric:opaque_orientation_128_eager_executed -->2942<!-- /metric:opaque_orientation_128_eager_executed --> |
| 249 alternating | Branch | <!-- metric:opaque_orientation_249_branch_script -->5975<!-- /metric:opaque_orientation_249_branch_script --> | <!-- metric:opaque_orientation_249_branch_witness -->3987<!-- /metric:opaque_orientation_249_branch_witness --> | 996 | 0 (none) | <!-- metric:opaque_orientation_249_branch_stack -->998<!-- /metric:opaque_orientation_249_branch_stack --> | <!-- metric:opaque_orientation_249_branch_executed -->3610<!-- /metric:opaque_orientation_249_branch_executed --> |
| 249 alternating | Eager | <!-- metric:opaque_orientation_249_eager_script -->5975<!-- /metric:opaque_orientation_249_eager_script --> | <!-- metric:opaque_orientation_249_eager_witness -->3987<!-- /metric:opaque_orientation_249_eager_witness --> | 996 | 0 (none) | <!-- metric:opaque_orientation_249_eager_stack -->1000<!-- /metric:opaque_orientation_249_eager_stack --> | <!-- metric:opaque_orientation_249_eager_executed -->5725<!-- /metric:opaque_orientation_249_eager_executed --> |

The branch schedule ties eager in serialized leaf and data witness
bytes and saves two peak items in each matched row. It executes
3,610 non-push operations at 249 quartets versus 5,725 for eager.
See the [comparison](../../../knowledge/comparisons/opaque-pair-orientation.md).

## Security and composition

All four payloads are hostile and remain opaque. Empty bytes,
raw zero and raw negative zero are distinct payloads. Match
requires exact byte equality, and equal members cannot establish
a unique orientation. The relation is local to each quartet.
It does not authenticate payloads or permit matching across
quartets. The returned bits are computed by the script.

The branch schedule needs two temporary items above the complete
`4*n` inputs. The eager schedule needs four. At 249 quartets the
branch schedule preserves one item on each caller stack at peak
1,000. The eager schedule reaches 1,000 on its own. Each invocation
has exactly zero hint items and zero hint bytes, including at this
batch limit. Other live state and any retained outputs count
against the same limit.

## Compatibility and evidence

Measured leaves compile with policy `ALL`. The local stack-limited
tapscript Consensus profile uses a synthetic transaction with
experimental OP_CAT disabled. The local Policy profile also
accepts the measured fixtures. Boundary tests exercise 520-byte
payload acceptance and 521-byte rejection in the former, and
80-byte acceptance and 81-byte rejection in the latter.

The opcodes are available in bare script, P2SH, P2WSH, and
tapscript. Bare script and P2WSH retain their older limits and P2SH
also has the redeem-script push bound. The local harness tests only
the tapscript context. See the [script-type limits](../../../docs/script-types.md)
and [standardness](../../../docs/standardness.md). Evidence is
`locally-reproduced`. Execution is `unclassified`.

## Reproduction

```sh
cargo test --locked --lib support::unique_pair_orientation::tests
cargo test --locked --test primitive_metrics opaque_pair_orientation_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

See the [knowledge entry](../../../knowledge/primitives/opaque-pair-orientation.md).
