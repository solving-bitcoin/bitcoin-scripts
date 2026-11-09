# Runtime left rotation of opaque stack items

Rotate a fixed-width stack suffix by a hostile runtime offset while
preserving the opaque payload bytes and both caller stacks. Removing
each routed item avoids keeping an additional copy of the input vector.

## Parameters and stack contract

`rotate_opaque_left(n)` requires an explicit width in `1..=996`.
With stacks written bottom to top, it consumes
`x[0] ... x[n-1] k` and returns
`x[k] ... x[n-1] x[0] ... x[k-1]`. The offset must be a canonical
ScriptNum in `0 <= k < n`. Payloads can be arbitrary byte vectors up
to 520 bytes in the measured profile. An exact input suffix is
required. Deeper main items and pre-existing altstack state survive.
A complete leaf must consume or verify the outputs and finish cleanly.

The script visits output positions from last to first. Initialize the
payload depth to `n-k`. Whenever that depth equals the remaining
payload count, wrap it to zero. Removing the selected item means
its predecessor remains at the same depth, until the bottom item is
removed and the depth wraps. The temporary result order on the
altstack reverses the traversal once. The depth only wraps once
for each valid offset, including the zero offset at the first iteration.

The combined peak is `n+4` plus preserved caller items. There are
`n+1` ordinary witness items at entry, including the offset, which
specifies the requested transformation. There are zero hints.
The standalone width-996 case reaches 1,000 items. Width 994
has room for two preserved items and rejects with three.

## Script metrics

The [copying baseline](../../../research/runtime-opaque-rotation/baseline.rs)
shares the canonical offset check. It copies each selected payload
to altstack and keeps the originals until every output has been
selected. Both leaves include all setup and cleanup, byte equality
on every output in the same order, and terminal true. Fixture payload
`i` is the two-byte little-endian index `i`. The offset is `n-2`.
Data witness bytes include the CompactSize count and item lengths
and exclude the leaf, control block, annex, and transaction. The
combined peak covers both stacks. Executed non-push counts include
branch delimiters encountered by the interpreter.

| Payloads | Offset | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (serialized bytes) | Combined peak | Executed non-push ops |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 8 | 6 | Destructive | <!-- metric:opaque_rotation_8_roll_script -->141<!-- /metric:opaque_rotation_8_roll_script --> | <!-- metric:opaque_rotation_8_roll_witness -->27<!-- /metric:opaque_rotation_8_roll_witness --> | 9 | 0 (0 bytes) | <!-- metric:opaque_rotation_8_roll_stack -->12<!-- /metric:opaque_rotation_8_roll_stack --> | <!-- metric:opaque_rotation_8_roll_executed -->89<!-- /metric:opaque_rotation_8_roll_executed --> |
| 8 | 6 | Copying | <!-- metric:opaque_rotation_8_copy_script -->155<!-- /metric:opaque_rotation_8_copy_script --> | <!-- metric:opaque_rotation_8_copy_witness -->27<!-- /metric:opaque_rotation_8_copy_witness --> | 9 | 0 (0 bytes) | <!-- metric:opaque_rotation_8_copy_stack -->18<!-- /metric:opaque_rotation_8_copy_stack --> | <!-- metric:opaque_rotation_8_copy_executed -->103<!-- /metric:opaque_rotation_8_copy_executed --> |
| 32 | 30 | Destructive | <!-- metric:opaque_rotation_32_roll_script -->543<!-- /metric:opaque_rotation_32_roll_script --> | <!-- metric:opaque_rotation_32_roll_witness -->99<!-- /metric:opaque_rotation_32_roll_witness --> | 33 | 0 (0 bytes) | <!-- metric:opaque_rotation_32_roll_stack -->36<!-- /metric:opaque_rotation_32_roll_stack --> | <!-- metric:opaque_rotation_32_roll_executed -->329<!-- /metric:opaque_rotation_32_roll_executed --> |
| 32 | 30 | Copying | <!-- metric:opaque_rotation_32_copy_script -->609<!-- /metric:opaque_rotation_32_copy_script --> | <!-- metric:opaque_rotation_32_copy_witness -->99<!-- /metric:opaque_rotation_32_copy_witness --> | 33 | 0 (0 bytes) | <!-- metric:opaque_rotation_32_copy_stack -->66<!-- /metric:opaque_rotation_32_copy_stack --> | <!-- metric:opaque_rotation_32_copy_executed -->379<!-- /metric:opaque_rotation_32_copy_executed --> |
| 128 | 126 | Destructive | <!-- metric:opaque_rotation_128_roll_script -->2178<!-- /metric:opaque_rotation_128_roll_script --> | <!-- metric:opaque_rotation_128_roll_witness -->387<!-- /metric:opaque_rotation_128_roll_witness --> | 129 | 0 (0 bytes) | <!-- metric:opaque_rotation_128_roll_stack -->132<!-- /metric:opaque_rotation_128_roll_stack --> | <!-- metric:opaque_rotation_128_roll_executed -->1289<!-- /metric:opaque_rotation_128_roll_executed --> |
| 128 | 126 | Copying | <!-- metric:opaque_rotation_128_copy_script -->2515<!-- /metric:opaque_rotation_128_copy_script --> | <!-- metric:opaque_rotation_128_copy_witness -->387<!-- /metric:opaque_rotation_128_copy_witness --> | 129 | 0 (0 bytes) | <!-- metric:opaque_rotation_128_copy_stack -->258<!-- /metric:opaque_rotation_128_copy_stack --> | <!-- metric:opaque_rotation_128_copy_executed -->1483<!-- /metric:opaque_rotation_128_copy_executed --> |
| 499 | 497 | Destructive | <!-- metric:opaque_rotation_499_roll_script -->8856<!-- /metric:opaque_rotation_499_roll_script --> | <!-- metric:opaque_rotation_499_roll_witness -->1503<!-- /metric:opaque_rotation_499_roll_witness --> | 500 | 0 (0 bytes) | <!-- metric:opaque_rotation_499_roll_stack -->503<!-- /metric:opaque_rotation_499_roll_stack --> | <!-- metric:opaque_rotation_499_roll_executed -->4999<!-- /metric:opaque_rotation_499_roll_executed --> |
| 499 | 497 | Copying | <!-- metric:opaque_rotation_499_copy_script -->9749<!-- /metric:opaque_rotation_499_copy_script --> | <!-- metric:opaque_rotation_499_copy_witness -->1503<!-- /metric:opaque_rotation_499_copy_witness --> | 500 | 0 (0 bytes) | <!-- metric:opaque_rotation_499_copy_stack -->1000<!-- /metric:opaque_rotation_499_copy_stack --> | <!-- metric:opaque_rotation_499_copy_executed -->5749<!-- /metric:opaque_rotation_499_copy_executed --> |

## Security, compatibility and execution

The fragment enforces the supplied offset and returns the exact
payload bytes in rotated order. A terminal output check may accept
more than one offset for periodic inputs, such as offsets 0 and 2 for
`[a,b,a,b]`. The relation does not authenticate an externally committed
vector or select a unique offset from output equality alone.

All measured leaves use `CompileOptions::ALL` via the repository policy,
the pinned local tapscript Consensus profile with the 520-byte item and
1,000-item combined-stack limits, and zero signature validation charge.
Evidence is `locally-reproduced` and execution is `unclassified`.
The opcodes are available in bare, P2SH, P2WSH and tapscript, with
legacy opcode-count and size limits evaluated separately. See
[script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md).

## Reproduction

```sh
cargo test --locked --lib support::rotation::tests
cargo test --locked --test primitive_metrics opaque_rotation_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

The tests check every offset through width 12, byte-preserving routing
of 520-byte and nonnumeric items, hostile offsets and input shapes,
periodic payloads, and standalone and composed stack frontiers. See
the [knowledge entry](../../../knowledge/primitives/opaque-runtime-rotation.md).
