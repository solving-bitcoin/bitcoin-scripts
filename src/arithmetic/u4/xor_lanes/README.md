# Checked XOR reduction with signed packed lanes

Reduce hostile canonical nibbles to one XOR nibble. A 16-entry table maps
each nibble to four binary digits separated into count lanes. Script
derives their parities directly, with no witness hints.

## Parameters and stack contract

`u4_xor_packed_lanes(n)` requires an explicit count in `1..=254`.
With stacks written bottom to top, the main suffix changes from
`x[0] ... x[n-1]` to a single canonical nibble. All input encodings are
checked before lookup. The fragment removes its temporary table and
accumulator and preserves deeper main-stack items and the existing
altstack. A caller must use or remove the result and satisfy a terminal
predicate with a clean stack.

For `n <= 127` each lane uses the smallest power-of-two base greater
than `n`. Count sums cannot carry into adjacent lanes. For `128..=254`,
use base 256 and start the top lane at `-floor(n/2)`. Its signed count
lies in `-127..=127`, and the lower three lanes contribute less than
`2^24`, so the accumulator and all partial sums fit four-byte ScriptNum
arithmetic. If the final accumulator is negative, add `2^31` as two
`2^30` operations. This preserves the bit at each lane's parity
position, including bit 24 because `2^31 / 2^24 = 128` is even.
The decoder uses descending binary thresholds and inverts the highest
parity when the initial bias is odd.

The combined peak is at most `n + 20` plus preserved caller items.
The width-254 test reaches exactly 1,000 with 726 preserved items and
rejects with one more. All ordinary data coexist at entry. Hints use
zero items and zero bytes per invocation. Values held for other
invocations count as caller state.

## Script metrics

Both zero-hint baselines and the packed schedule use the same canonical
guard and terminal byte equality against the expected nibble. Leaves
include table setup, data validation, reduction, cleanup and terminal
true. Data serialization includes CompactSize count and item lengths
and excludes the leaf, control block, annex, and transaction. Input
item `i` is `(7*i + 5*floor(i/3)) mod 16`. At width 128 the high bit of
item 2 is cleared to exercise the negative signed state. The width-254
fixture has a nonnegative signed state. The trace counts executed
non-push instructions and visited branch delimiters. It is fixture-specific.

| Inputs | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (serialized bytes) | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | Packed lanes | <!-- metric:xor_lanes_2_packed_script -->145<!-- /metric:xor_lanes_2_packed_script --> | <!-- metric:xor_lanes_2_packed_witness -->4<!-- /metric:xor_lanes_2_packed_witness --> | 2 | 0 (0 bytes) | <!-- metric:xor_lanes_2_packed_stack -->22<!-- /metric:xor_lanes_2_packed_stack --> | <!-- metric:xor_lanes_2_packed_executed -->71<!-- /metric:xor_lanes_2_packed_executed --> |
| 2 | Triangular | <!-- metric:xor_lanes_2_triangular_script -->287<!-- /metric:xor_lanes_2_triangular_script --> | <!-- metric:xor_lanes_2_triangular_witness -->4<!-- /metric:xor_lanes_2_triangular_witness --> | 2 | 0 (0 bytes) | <!-- metric:xor_lanes_2_triangular_stack -->156<!-- /metric:xor_lanes_2_triangular_stack --> | <!-- metric:xor_lanes_2_triangular_executed -->107<!-- /metric:xor_lanes_2_triangular_executed --> |
| 2 | Full table | <!-- metric:xor_lanes_2_full_script -->426<!-- /metric:xor_lanes_2_full_script --> | <!-- metric:xor_lanes_2_full_witness -->4<!-- /metric:xor_lanes_2_full_witness --> | 2 | 0 (0 bytes) | <!-- metric:xor_lanes_2_full_stack -->259<!-- /metric:xor_lanes_2_full_stack --> | <!-- metric:xor_lanes_2_full_executed -->161<!-- /metric:xor_lanes_2_full_executed --> |
| 16 | Packed lanes | <!-- metric:xor_lanes_16_packed_script -->534<!-- /metric:xor_lanes_16_packed_script --> | <!-- metric:xor_lanes_16_packed_witness -->32<!-- /metric:xor_lanes_16_packed_witness --> | 16 | 0 (0 bytes) | <!-- metric:xor_lanes_16_packed_stack -->36<!-- /metric:xor_lanes_16_packed_stack --> | <!-- metric:xor_lanes_16_packed_executed -->273<!-- /metric:xor_lanes_16_packed_executed --> |
| 16 | Triangular | <!-- metric:xor_lanes_16_triangular_script -->622<!-- /metric:xor_lanes_16_triangular_script --> | <!-- metric:xor_lanes_16_triangular_witness -->32<!-- /metric:xor_lanes_16_triangular_witness --> | 16 | 0 (0 bytes) | <!-- metric:xor_lanes_16_triangular_stack -->170<!-- /metric:xor_lanes_16_triangular_stack --> | <!-- metric:xor_lanes_16_triangular_executed -->373<!-- /metric:xor_lanes_16_triangular_executed --> |
| 16 | Full table | <!-- metric:xor_lanes_16_full_script -->775<!-- /metric:xor_lanes_16_full_script --> | <!-- metric:xor_lanes_16_full_witness -->32<!-- /metric:xor_lanes_16_full_witness --> | 16 | 0 (0 bytes) | <!-- metric:xor_lanes_16_full_stack -->273<!-- /metric:xor_lanes_16_full_stack --> | <!-- metric:xor_lanes_16_full_executed -->455<!-- /metric:xor_lanes_16_full_executed --> |
| 128 | Packed lanes | <!-- metric:xor_lanes_128_packed_script -->2520<!-- /metric:xor_lanes_128_packed_script --> | <!-- metric:xor_lanes_128_packed_witness -->246<!-- /metric:xor_lanes_128_packed_witness --> | 128 | 0 (0 bytes) | <!-- metric:xor_lanes_128_packed_stack -->148<!-- /metric:xor_lanes_128_packed_stack --> | <!-- metric:xor_lanes_128_packed_executed -->1570<!-- /metric:xor_lanes_128_packed_executed --> |
| 128 | Triangular | <!-- metric:xor_lanes_128_triangular_script -->3531<!-- /metric:xor_lanes_128_triangular_script --> | <!-- metric:xor_lanes_128_triangular_witness -->246<!-- /metric:xor_lanes_128_triangular_witness --> | 128 | 0 (0 bytes) | <!-- metric:xor_lanes_128_triangular_stack -->282<!-- /metric:xor_lanes_128_triangular_stack --> | <!-- metric:xor_lanes_128_triangular_executed -->2501<!-- /metric:xor_lanes_128_triangular_executed --> |
| 128 | Full table | <!-- metric:xor_lanes_128_full_script -->3685<!-- /metric:xor_lanes_128_full_script --> | <!-- metric:xor_lanes_128_full_witness -->246<!-- /metric:xor_lanes_128_full_witness --> | 128 | 0 (0 bytes) | <!-- metric:xor_lanes_128_full_stack -->385<!-- /metric:xor_lanes_128_full_stack --> | <!-- metric:xor_lanes_128_full_executed -->2807<!-- /metric:xor_lanes_128_full_executed --> |
| 254 | Packed lanes | <!-- metric:xor_lanes_254_packed_script -->4536<!-- /metric:xor_lanes_254_packed_script --> | <!-- metric:xor_lanes_254_packed_witness -->490<!-- /metric:xor_lanes_254_packed_witness --> | 254 | 0 (0 bytes) | <!-- metric:xor_lanes_254_packed_stack -->274<!-- /metric:xor_lanes_254_packed_stack --> | <!-- metric:xor_lanes_254_packed_executed -->2958<!-- /metric:xor_lanes_254_packed_executed --> |
| 254 | Triangular | <!-- metric:xor_lanes_254_triangular_script -->7058<!-- /metric:xor_lanes_254_triangular_script --> | <!-- metric:xor_lanes_254_triangular_witness -->490<!-- /metric:xor_lanes_254_triangular_witness --> | 254 | 0 (0 bytes) | <!-- metric:xor_lanes_254_triangular_stack -->408<!-- /metric:xor_lanes_254_triangular_stack --> | <!-- metric:xor_lanes_254_triangular_executed -->4895<!-- /metric:xor_lanes_254_triangular_executed --> |
| 254 | Full table | <!-- metric:xor_lanes_254_full_script -->7086<!-- /metric:xor_lanes_254_full_script --> | <!-- metric:xor_lanes_254_full_witness -->490<!-- /metric:xor_lanes_254_full_witness --> | 254 | 0 (0 bytes) | <!-- metric:xor_lanes_254_full_stack -->511<!-- /metric:xor_lanes_254_full_stack --> | <!-- metric:xor_lanes_254_full_executed -->5453<!-- /metric:xor_lanes_254_full_executed --> |

The full baseline reuses the repository's XOR reduction schedule with a
canonical guard. The triangular baseline uses the repository's 136-entry
XOR table, sixteen lookup offsets, and sorted-pair access. See the
[matched baseline source](../../../../research/signed-xor-lanes/baseline.rs).

## Security, compatibility and execution

All operands are validated canonical nibbles, and the output is their
deterministic XOR. Two valid inputs with the same XOR can pass the same
leaf, including `[0, 0, 0, 0]` and `[3, 9, 3, 9]`. The result provides
no message authentication, key material, or binding to input order.

All measured leaves use `CompileOptions::ALL` via the central policy,
the pinned local tapscript Consensus profile with the 520-byte item and
1,000-item combined-stack limits, and zero signature validation charge.
Evidence is `locally-reproduced`; execution is `unclassified`. These
stack, arithmetic, and control-flow opcodes are available in bare,
P2SH, P2WSH, and tapscript contexts. Legacy limits and relay rules
require separate evaluation. See [script types](../../../../docs/script-types.md)
and [standardness](../../../../docs/standardness.md).

## Reproduction

```sh
cargo test --locked --lib arithmetic::u4::xor_lanes::tests
cargo test --locked --test primitive_metrics xor_lanes_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

Tests cover all ordered nibble pairs, host XOR at the signed transition
and maximum count, negative normalization, bias parity, hostile
encodings, wrong outputs and counts, and both caller stacks.
See the [knowledge entry](../../../../knowledge/primitives/u4-xor-lanes.md).
