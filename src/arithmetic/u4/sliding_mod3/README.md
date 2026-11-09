# Sliding modulo-three sums over u4 inputs

Consume canonical, hostile nibble inputs and return the exact sum modulo
three for every overlapping window of a fixed public width. A single
resident table handles both input projection and output reduction. There
are no hints.

## Parameters and stack contract

`u4_sliding_mod3(n, window)` requires explicit input count `1..=981` and
window width `1..=min(7, n)`. With stacks written bottom to top, it changes
the main-stack suffix `x[0] ... x[n-1]` to
`residue[0] ... residue[n-window]`. Both inputs and outputs are canonical
ScriptNums. The suffix must have the specified number of data items.
Deeper main-stack items and the existing altstack are preserved. The
fragment temporarily stages projected nibbles and computed residues on
the altstack and removes all its own scratch state. Its caller must
consume the outputs or enforce a terminal predicate with a clean stack.

The table projects each nibble to `0..=2`. The rightmost projected
window has exact sum at most `2 * 7 = 14` and is reduced by the same
16-entry table. Scanning right to left, update the previous residue with
incoming minus outgoing. The signed result is in `-2..=4`; adding three
gives a lookup argument in `1..=7` with the same residue. An output is
pushed to the altstack before consuming its outgoing nibble. Restoring
outputs returns increasing window-start order.

The combined peak is at most `n + 19` plus preserved caller items.
Every ordinary input is present at entry. Width-seven cases reach exactly
1,000 at 981 standalone inputs or 979 inputs with two preserved items.
A third preserved item in the latter case rejects. Outputs from one
fragment count as live caller state if held for a later invocation.

## Script metrics

The rolling and [rescan baseline](../../../../research/sliding-u4-mod3/baseline.rs)
share the canonical projection and the resident table. The baseline computes
each window sum separately by copying its projected inputs. Both policy-
compiled leaves include setup, all validation, cleanup, a byte-equality
check of every output, and terminal true. Witness bytes include the data
item count and per-item lengths and exclude the leaf, control block, annex,
and transaction. Input item `i` is `(11 * i + 3 * floor(i/4)) mod 16`.
The combined peak covers both stacks, and executed non-push operations
include any visited branch delimiters. The leaves are branch-free.

| Inputs | Window | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (serialized bytes) | Combined peak | Executed non-push ops |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | 1 | Rolling | <!-- metric:sliding_mod3_4_1_roll_script -->129<!-- /metric:sliding_mod3_4_1_roll_script --> | <!-- metric:sliding_mod3_4_1_roll_witness -->8<!-- /metric:sliding_mod3_4_1_roll_witness --> | 4 | 0 (0 bytes) | <!-- metric:sliding_mod3_4_1_roll_stack -->23<!-- /metric:sliding_mod3_4_1_roll_stack --> | <!-- metric:sliding_mod3_4_1_roll_executed -->87<!-- /metric:sliding_mod3_4_1_roll_executed --> |
| 4 | 1 | Rescan | <!-- metric:sliding_mod3_4_1_rescan_script -->128<!-- /metric:sliding_mod3_4_1_rescan_script --> | <!-- metric:sliding_mod3_4_1_rescan_witness -->8<!-- /metric:sliding_mod3_4_1_rescan_witness --> | 4 | 0 (0 bytes) | <!-- metric:sliding_mod3_4_1_rescan_stack -->23<!-- /metric:sliding_mod3_4_1_rescan_stack --> | <!-- metric:sliding_mod3_4_1_rescan_executed -->84<!-- /metric:sliding_mod3_4_1_rescan_executed --> |
| 32 | 2 | Rolling | <!-- metric:sliding_mod3_32_2_roll_script -->898<!-- /metric:sliding_mod3_32_2_roll_script --> | <!-- metric:sliding_mod3_32_2_roll_witness -->62<!-- /metric:sliding_mod3_32_2_roll_witness --> | 32 | 0 (0 bytes) | <!-- metric:sliding_mod3_32_2_roll_stack -->51<!-- /metric:sliding_mod3_32_2_roll_stack --> | <!-- metric:sliding_mod3_32_2_roll_executed -->640<!-- /metric:sliding_mod3_32_2_roll_executed --> |
| 32 | 2 | Rescan | <!-- metric:sliding_mod3_32_2_rescan_script -->956<!-- /metric:sliding_mod3_32_2_rescan_script --> | <!-- metric:sliding_mod3_32_2_rescan_witness -->62<!-- /metric:sliding_mod3_32_2_rescan_witness --> | 32 | 0 (0 bytes) | <!-- metric:sliding_mod3_32_2_rescan_stack -->51<!-- /metric:sliding_mod3_32_2_rescan_stack --> | <!-- metric:sliding_mod3_32_2_rescan_executed -->671<!-- /metric:sliding_mod3_32_2_rescan_executed --> |
| 32 | 7 | Rolling | <!-- metric:sliding_mod3_32_7_roll_script -->856<!-- /metric:sliding_mod3_32_7_roll_script --> | <!-- metric:sliding_mod3_32_7_roll_witness -->62<!-- /metric:sliding_mod3_32_7_roll_witness --> | 32 | 0 (0 bytes) | <!-- metric:sliding_mod3_32_7_roll_stack -->51<!-- /metric:sliding_mod3_32_7_roll_stack --> | <!-- metric:sliding_mod3_32_7_roll_executed -->608<!-- /metric:sliding_mod3_32_7_roll_executed --> |
| 32 | 7 | Rescan | <!-- metric:sliding_mod3_32_7_rescan_script -->1278<!-- /metric:sliding_mod3_32_7_rescan_script --> | <!-- metric:sliding_mod3_32_7_rescan_witness -->62<!-- /metric:sliding_mod3_32_7_rescan_witness --> | 32 | 0 (0 bytes) | <!-- metric:sliding_mod3_32_7_rescan_stack -->51<!-- /metric:sliding_mod3_32_7_rescan_stack --> | <!-- metric:sliding_mod3_32_7_rescan_executed -->883<!-- /metric:sliding_mod3_32_7_rescan_executed --> |
| 128 | 7 | Rolling | <!-- metric:sliding_mod3_128_7_roll_script -->3548<!-- /metric:sliding_mod3_128_7_roll_script --> | <!-- metric:sliding_mod3_128_7_roll_witness -->249<!-- /metric:sliding_mod3_128_7_roll_witness --> | 128 | 0 (0 bytes) | <!-- metric:sliding_mod3_128_7_roll_stack -->147<!-- /metric:sliding_mod3_128_7_roll_stack --> | <!-- metric:sliding_mod3_128_7_roll_executed -->2528<!-- /metric:sliding_mod3_128_7_roll_executed --> |
| 128 | 7 | Rescan | <!-- metric:sliding_mod3_128_7_rescan_script -->5599<!-- /metric:sliding_mod3_128_7_rescan_script --> | <!-- metric:sliding_mod3_128_7_rescan_witness -->249<!-- /metric:sliding_mod3_128_7_rescan_witness --> | 128 | 0 (0 bytes) | <!-- metric:sliding_mod3_128_7_rescan_stack -->147<!-- /metric:sliding_mod3_128_7_rescan_stack --> | <!-- metric:sliding_mod3_128_7_rescan_executed -->3859<!-- /metric:sliding_mod3_128_7_rescan_executed --> |

## Security, compatibility and execution

Every supplied item is canonical and checked before lookup. Incorrect
output claims fail byte equality in the measured leaf. The residue vector
does not authenticate the original input. All-zero and all-three vectors
have the same residues, and both satisfy the zero-residue leaf. No keys,
hints, or cryptographic security assumptions apply.

Evidence is `locally-reproduced`; execution is `unclassified`. All measured
leaves use `CompileOptions::ALL` via the central compilation policy, the
pinned local tapscript Consensus profile with the 520-byte item and
1,000-item combined-stack limits, and zero signature validation charge.
The opcodes are available in bare, P2SH, P2WSH, and tapscript. Legacy opcode
and script-size limits must be evaluated separately for bare script, P2SH,
and P2WSH. See [script types](../../../../docs/script-types.md) and
[standardness](../../../../docs/standardness.md).

## Reproduction

```sh
cargo test --locked --lib arithmetic::u4::sliding_mod3::tests
cargo test --locked --test primitive_metrics sliding_mod3_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

The host oracle recomputes each raw window independently. Tests cover
exhaustive small residue patterns, width and count limits, malformed
items at each position, wrong outputs, wrong input counts, caller-state
preservation, and an explicit residue collision.
See the [knowledge entry](../../../../knowledge/primitives/u4-sliding-mod3.md).
