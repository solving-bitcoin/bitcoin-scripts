# Longest common prefix of opaque item vectors

`support::common_prefix::opaque_common_prefix_len(n)` consumes two
fixed-width raw-item vectors and returns their canonical common-prefix
length. The function compares the full bytes of corresponding items.
All witness data are hostile.

## Parameters

Width `n` is a generation-time value in `0..=499`, with no default. Zero
returns zero. Budget all caller items when choosing a nonzero width.

## Script metrics

| Pairs | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 32 | Reverse mismatch | <!-- metric:opaque_prefix_reverse32_script -->292<!-- /metric:opaque_prefix_reverse32_script --> | <!-- metric:opaque_prefix_reverse32_witness -->193<!-- /metric:opaque_prefix_reverse32_witness --> | 64 | 0 (none) | <!-- metric:opaque_prefix_reverse32_stack -->66<!-- /metric:opaque_prefix_reverse32_stack --> | <!-- metric:opaque_prefix_reverse32_executed -->165<!-- /metric:opaque_prefix_reverse32_executed --> |
| 32 | Forward state | <!-- metric:opaque_prefix_forward32_script -->334<!-- /metric:opaque_prefix_forward32_script --> | <!-- metric:opaque_prefix_forward32_witness -->193<!-- /metric:opaque_prefix_forward32_witness --> | 64 | 0 (none) | <!-- metric:opaque_prefix_forward32_stack -->67<!-- /metric:opaque_prefix_forward32_stack --> | <!-- metric:opaque_prefix_forward32_executed -->225<!-- /metric:opaque_prefix_forward32_executed --> |
| 128 | Reverse mismatch | <!-- metric:opaque_prefix_reverse128_script -->1256<!-- /metric:opaque_prefix_reverse128_script --> | <!-- metric:opaque_prefix_reverse128_witness -->771<!-- /metric:opaque_prefix_reverse128_witness --> | 256 | 0 (none) | <!-- metric:opaque_prefix_reverse128_stack -->258<!-- /metric:opaque_prefix_reverse128_stack --> | <!-- metric:opaque_prefix_reverse128_executed -->657<!-- /metric:opaque_prefix_reverse128_executed --> |
| 128 | Forward state | <!-- metric:opaque_prefix_forward128_script -->1458<!-- /metric:opaque_prefix_forward128_script --> | <!-- metric:opaque_prefix_forward128_witness -->771<!-- /metric:opaque_prefix_forward128_witness --> | 256 | 0 (none) | <!-- metric:opaque_prefix_forward128_stack -->259<!-- /metric:opaque_prefix_forward128_stack --> | <!-- metric:opaque_prefix_forward128_executed -->897<!-- /metric:opaque_prefix_forward128_executed --> |

Both leaves check the same canonical prefix length and finish with one true
item. Whole-leaf optimizer `ALL` compiles validation, routing, comparisons
and terminal checks. Witness bytes include all entry data with count and
length prefixes, excluding script, control block, annex and transaction.
All inputs coexist at entry. Executed counts include encountered branch
delimiters. There are no signatures.

## Security

The result describes equality of witness bytes only. The caller binds the
vectors or their meaning where required. Later equal values never extend
the prefix after an earlier mismatch. No keys or cryptographic assumptions
are used.

## Script compatibility and standardness

Bare, P2SH and P2WSH execution is unclassified. The tests use the local
tapscript `Consensus` profile with stack limits and MINIMALIF enabled,
numeric minimality and experimental OP_CAT disabled and synthetic
transaction context. Evidence is `locally-reproduced`; execution is
`unclassified`. See [script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md).

## Witness and hints

Supply `left[0] ... left[n-1] right[0] ... right[n-1]` bottom to top.
Each payload is arbitrary raw data within the entry element limit. Each
invocation has `2n` ordinary items and zero hint items or bytes.
Preloading future invocations counts all their data against the live limit.

## Stack contract

`caller | left | right -> caller | prefix_len`. Altstack is unused.
The peak is at most `2n+2` plus caller state for `n>=1`, or one plus
caller state for `n=0`. The caller establishes an exact suffix and
consumes or verifies the length before its terminal predicate.

## Operational notes and knowledge-base integration

See the [research note](../../../knowledge/primitives/opaque-common-prefix.md)
for the matched forward baseline, exact stack boundaries and reproduction.
