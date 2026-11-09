# Decode a single interval from binary flags

`arithmetic::interval_mask::decode_single_run(n)` accepts exactly one nonempty
contiguous run of true flags and returns its zero-based start and length.
Every witness item is hostile. Native tapscript MINIMALIF enforces exact
empty or `01` flag bytes.

## Parameters

The fixed width `n` is set at generation time and has no default. Use
`1..=998` without preserved state. Account for both caller stacks at
composition time.

## Script metrics

| 32 flags, indices 5 through 12 true | Leaf bytes | Data witness bytes | Data items | Hint items | Combined peak | Executed non-push ops |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Signed-length state | <!-- metric:single_run_signed32_script -->602<!-- /metric:single_run_signed32_script --> | <!-- metric:single_run_signed32_witness -->41<!-- /metric:single_run_signed32_witness --> | 32 | 0 (none) | <!-- metric:single_run_signed32_stack -->33<!-- /metric:single_run_signed32_stack --> | <!-- metric:single_run_signed32_executed -->352<!-- /metric:single_run_signed32_executed --> |
| Separate closed flag | <!-- metric:single_run_flag32_script -->698<!-- /metric:single_run_flag32_script --> | <!-- metric:single_run_flag32_witness -->41<!-- /metric:single_run_flag32_witness --> | 32 | 0 (none) | <!-- metric:single_run_flag32_stack -->35<!-- /metric:single_run_flag32_stack --> | <!-- metric:single_run_flag32_executed -->354<!-- /metric:single_run_flag32_executed --> |

Both checked leaves verify the exact canonical start and length, then leave
one true item. Whole-leaf compilation uses `ALL`. The witness includes all
flags with count and length prefixes. It excludes script, control block,
annex and transaction. The opcode trace counts active non-push operations
and encountered branch delimiters. No signatures execute.

## Security

The checked flags describe the interval. The caller supplies any necessary
authentication, including who can choose those flags. No one-time key
or cryptographic assumptions are used.

## Script compatibility and standardness

The evidence is `locally-reproduced` and execution is `unclassified`.
The local tapscript `Consensus` profile enables MINIMALIF and resource
limits with numeric minimality and experimental OP_CAT disabled. Bare,
P2SH and P2WSH contexts do not inherit tapscript's native canonical-flag
guarantee. See [script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md).

## Witness and hints

Bottom to top, supply `flag[n-1] ... flag[0]`. There are `n` ordinary
entry items and exactly zero hint items or hint bytes. Preloading additional
invocations adds all their data items to the live resource boundary.

## Stack contract

`caller | flag[n-1] ... flag[0] -> caller | start length`. The altstack is
unused. The caller must establish an exact input suffix and consume or verify
both outputs when adding a terminal predicate. Budget at most `n + 2` live
items in addition to both preserved caller stacks.

## Operational notes and knowledge-base integration

The [research note](../../../knowledge/primitives/single-run-mask.md) gives
the state invariants, evidence and reproduction. See catalog
`arithmetic/single-run-mask` and the
[comparison](../../../knowledge/comparisons/stack-selection.md).
