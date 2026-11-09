# Two distinct SHA-256 openings from one public pool

Verify that two opaque, adversarially supplied byte strings hash to two
different digests from one public list. Destructive selection uses two
routing hints and removes each chosen slot before the next lookup.
There is no output item on success.

## Parameters and stack contract

`verify_two_distinct_sha256_openings(digests)` requires an explicit list
of 2 through 993 distinct 32-byte SHA-256 digests. It checks public
uniqueness during generation. With stacks written bottom to top, the
main-stack suffix is `second_preimage second_rank first_preimage first_rank`.
The first rank is a canonical ScriptNum in `0..n`. The second rank is
a canonical ScriptNum in `0..n-1` for the list after removing the first
selected digest. For original distinct positions `i` and `j`, the ranks
are `i` and `j - (j > i)`. Either opening order is supported.

Both ranks are checked for canonical encoding and range before selecting
a digest with `OP_ROLL`. Native `OP_SHA256` and byte equality verify
each preimage against the removed digest. The fragment consumes both
preimages, the hints, and its table, preserving both caller stacks for
an exact suffix. A complete leaf must add a terminal predicate.

The combined peak is `n + 7` plus preserved caller state. All two
preimage items and both hints coexist at entry. At width 993 the strict
local run reaches 1,000 items. At width 991 two caller items fit and a
third fails. For two independent invocations with four further witness
items preloaded, the first invocation must satisfy `n + 11 <= 1000`
before accounting for any other caller state.

## Script metrics

All rows are complete leaves with the same two-preimage relation and a
terminal true. Setup, hash checks, and cleanup are included. Fixed
indices share the same resident list and check that the original
indices differ. The scan takes only `second_preimage first_preimage`,
checks that the two hashes differ, and requires exactly two total hits
against the unique pool. Every digest is embedded once in each script.
All three run two native SHA-256 instructions and no signature checks.

Preimage `i` is 32 bytes, with its first four bytes the little-endian
index and the rest `0x42`. The opened slots are `(0, n-1)` at width
three and `(1, n-1)` elsewhere. Witness bytes include the CompactSize
count and item-length prefixes. They exclude the leaf, control block,
annex and transaction. Hint bytes are the incremental serialized
item costs relative to the same two preimages without hints, with
the count prefix one byte in all rows. The peak covers both stacks
and executed counts cover non-push instructions.

| Digests | Schedule | Leaf bytes | Data witness bytes | Total entry items | Hint items | Incremental hint bytes | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 3 | Destructive ranks | <!-- metric:sha256_pool_3_ranks_script -->133<!-- /metric:sha256_pool_3_ranks_script --> | <!-- metric:sha256_pool_3_ranks_witness -->70<!-- /metric:sha256_pool_3_ranks_witness --> | 4 | <!-- metric:sha256_pool_3_ranks_hints -->2<!-- /metric:sha256_pool_3_ranks_hints --> | <!-- metric:sha256_pool_3_ranks_hint_bytes -->3<!-- /metric:sha256_pool_3_ranks_hint_bytes --> | <!-- metric:sha256_pool_3_ranks_stack -->10<!-- /metric:sha256_pool_3_ranks_stack --> | <!-- metric:sha256_pool_3_ranks_executed -->25<!-- /metric:sha256_pool_3_ranks_executed --> |
| 3 | Fixed indices | <!-- metric:sha256_pool_3_fixed_script -->142<!-- /metric:sha256_pool_3_fixed_script --> | <!-- metric:sha256_pool_3_fixed_witness -->70<!-- /metric:sha256_pool_3_fixed_witness --> | 4 | <!-- metric:sha256_pool_3_fixed_hints -->2<!-- /metric:sha256_pool_3_fixed_hints --> | <!-- metric:sha256_pool_3_fixed_hint_bytes -->3<!-- /metric:sha256_pool_3_fixed_hint_bytes --> | <!-- metric:sha256_pool_3_fixed_stack -->10<!-- /metric:sha256_pool_3_fixed_stack --> | <!-- metric:sha256_pool_3_fixed_executed -->32<!-- /metric:sha256_pool_3_fixed_executed --> |
| 3 | Scan | <!-- metric:sha256_pool_3_scan_script -->141<!-- /metric:sha256_pool_3_scan_script --> | <!-- metric:sha256_pool_3_scan_witness -->67<!-- /metric:sha256_pool_3_scan_witness --> | 2 | <!-- metric:sha256_pool_3_scan_hints -->0<!-- /metric:sha256_pool_3_scan_hints --> | <!-- metric:sha256_pool_3_scan_hint_bytes -->0<!-- /metric:sha256_pool_3_scan_hint_bytes --> | <!-- metric:sha256_pool_3_scan_stack -->6<!-- /metric:sha256_pool_3_scan_stack --> | <!-- metric:sha256_pool_3_scan_executed -->33<!-- /metric:sha256_pool_3_scan_executed --> |
| 32 | Destructive ranks | <!-- metric:sha256_pool_32_ranks_script -->1112<!-- /metric:sha256_pool_32_ranks_script --> | <!-- metric:sha256_pool_32_ranks_witness -->71<!-- /metric:sha256_pool_32_ranks_witness --> | 4 | <!-- metric:sha256_pool_32_ranks_hints -->2<!-- /metric:sha256_pool_32_ranks_hints --> | <!-- metric:sha256_pool_32_ranks_hint_bytes -->4<!-- /metric:sha256_pool_32_ranks_hint_bytes --> | <!-- metric:sha256_pool_32_ranks_stack -->39<!-- /metric:sha256_pool_32_ranks_stack --> | <!-- metric:sha256_pool_32_ranks_executed -->39<!-- /metric:sha256_pool_32_ranks_executed --> |
| 32 | Fixed indices | <!-- metric:sha256_pool_32_fixed_script -->1119<!-- /metric:sha256_pool_32_fixed_script --> | <!-- metric:sha256_pool_32_fixed_witness -->71<!-- /metric:sha256_pool_32_fixed_witness --> | 4 | <!-- metric:sha256_pool_32_fixed_hints -->2<!-- /metric:sha256_pool_32_fixed_hints --> | <!-- metric:sha256_pool_32_fixed_hint_bytes -->4<!-- /metric:sha256_pool_32_fixed_hint_bytes --> | <!-- metric:sha256_pool_32_fixed_stack -->39<!-- /metric:sha256_pool_32_fixed_stack --> | <!-- metric:sha256_pool_32_fixed_executed -->46<!-- /metric:sha256_pool_32_fixed_executed --> |
| 32 | Scan | <!-- metric:sha256_pool_32_scan_script -->1388<!-- /metric:sha256_pool_32_scan_script --> | <!-- metric:sha256_pool_32_scan_witness -->67<!-- /metric:sha256_pool_32_scan_witness --> | 2 | <!-- metric:sha256_pool_32_scan_hints -->0<!-- /metric:sha256_pool_32_scan_hints --> | <!-- metric:sha256_pool_32_scan_hint_bytes -->0<!-- /metric:sha256_pool_32_scan_hint_bytes --> | <!-- metric:sha256_pool_32_scan_stack -->6<!-- /metric:sha256_pool_32_scan_stack --> | <!-- metric:sha256_pool_32_scan_executed -->265<!-- /metric:sha256_pool_32_scan_executed --> |
| 129 | Destructive ranks | <!-- metric:sha256_pool_129_ranks_script -->4368<!-- /metric:sha256_pool_129_ranks_script --> | <!-- metric:sha256_pool_129_ranks_witness -->71<!-- /metric:sha256_pool_129_ranks_witness --> | 4 | <!-- metric:sha256_pool_129_ranks_hints -->2<!-- /metric:sha256_pool_129_ranks_hints --> | <!-- metric:sha256_pool_129_ranks_hint_bytes -->4<!-- /metric:sha256_pool_129_ranks_hint_bytes --> | <!-- metric:sha256_pool_129_ranks_stack -->136<!-- /metric:sha256_pool_129_ranks_stack --> | <!-- metric:sha256_pool_129_ranks_executed -->88<!-- /metric:sha256_pool_129_ranks_executed --> |
| 129 | Fixed indices | <!-- metric:sha256_pool_129_fixed_script -->4375<!-- /metric:sha256_pool_129_fixed_script --> | <!-- metric:sha256_pool_129_fixed_witness -->72<!-- /metric:sha256_pool_129_fixed_witness --> | 4 | <!-- metric:sha256_pool_129_fixed_hints -->2<!-- /metric:sha256_pool_129_fixed_hints --> | <!-- metric:sha256_pool_129_fixed_hint_bytes -->5<!-- /metric:sha256_pool_129_fixed_hint_bytes --> | <!-- metric:sha256_pool_129_fixed_stack -->136<!-- /metric:sha256_pool_129_fixed_stack --> | <!-- metric:sha256_pool_129_fixed_executed -->95<!-- /metric:sha256_pool_129_fixed_executed --> |
| 129 | Scan | <!-- metric:sha256_pool_129_scan_script -->5559<!-- /metric:sha256_pool_129_scan_script --> | <!-- metric:sha256_pool_129_scan_witness -->67<!-- /metric:sha256_pool_129_scan_witness --> | 2 | <!-- metric:sha256_pool_129_scan_hints -->0<!-- /metric:sha256_pool_129_scan_hints --> | <!-- metric:sha256_pool_129_scan_hint_bytes -->0<!-- /metric:sha256_pool_129_scan_hint_bytes --> | <!-- metric:sha256_pool_129_scan_stack -->6<!-- /metric:sha256_pool_129_scan_stack --> | <!-- metric:sha256_pool_129_scan_executed -->1041<!-- /metric:sha256_pool_129_scan_executed --> |
| 993 | Destructive ranks | <!-- metric:sha256_pool_993_ranks_script -->33807<!-- /metric:sha256_pool_993_ranks_script --> | <!-- metric:sha256_pool_993_ranks_witness -->72<!-- /metric:sha256_pool_993_ranks_witness --> | 4 | <!-- metric:sha256_pool_993_ranks_hints -->2<!-- /metric:sha256_pool_993_ranks_hints --> | <!-- metric:sha256_pool_993_ranks_hint_bytes -->5<!-- /metric:sha256_pool_993_ranks_hint_bytes --> | <!-- metric:sha256_pool_993_ranks_stack -->1000<!-- /metric:sha256_pool_993_ranks_stack --> | <!-- metric:sha256_pool_993_ranks_executed -->1015<!-- /metric:sha256_pool_993_ranks_executed --> |
| 993 | Fixed indices | <!-- metric:sha256_pool_993_fixed_script -->33815<!-- /metric:sha256_pool_993_fixed_script --> | <!-- metric:sha256_pool_993_fixed_witness -->72<!-- /metric:sha256_pool_993_fixed_witness --> | 4 | <!-- metric:sha256_pool_993_fixed_hints -->2<!-- /metric:sha256_pool_993_fixed_hints --> | <!-- metric:sha256_pool_993_fixed_hint_bytes -->5<!-- /metric:sha256_pool_993_fixed_hint_bytes --> | <!-- metric:sha256_pool_993_fixed_stack -->1000<!-- /metric:sha256_pool_993_fixed_stack --> | <!-- metric:sha256_pool_993_fixed_executed -->1023<!-- /metric:sha256_pool_993_fixed_executed --> |
| 993 | Scan | <!-- metric:sha256_pool_993_scan_script -->42711<!-- /metric:sha256_pool_993_scan_script --> | <!-- metric:sha256_pool_993_scan_witness -->67<!-- /metric:sha256_pool_993_scan_witness --> | 2 | <!-- metric:sha256_pool_993_scan_hints -->0<!-- /metric:sha256_pool_993_scan_hints --> | <!-- metric:sha256_pool_993_scan_hint_bytes -->0<!-- /metric:sha256_pool_993_scan_hint_bytes --> | <!-- metric:sha256_pool_993_scan_stack -->6<!-- /metric:sha256_pool_993_scan_stack --> | <!-- metric:sha256_pool_993_scan_executed -->7953<!-- /metric:sha256_pool_993_scan_executed --> |

The 3, 32 and 129 rows use `CompileOptions::ALL`. The 993 rows are
unoptimized under the central policy because their digest pushes
alone exceed 32 KiB. See the [baseline and fixtures](../../../research/distinct-sha256-openings/).

## Security, compatibility and execution

Two distinct public digest values cannot both equal the SHA-256 of
the same byte string. The verifier proves this opening relation and
does not bind a message to specific indices, hide the opened slots,
or impose freshness. Disclosed preimages can be reused wherever
the same digest pool is accepted. Setup must use preimages appropriate
to its external protocol; this experiment does not assign security
bounds.

The measured leaves run in the pinned local tapscript Consensus
profile with the 520-byte data-item and 1,000-item combined-stack
limits. Evidence is `locally-reproduced` and deployment is
`unclassified`. The opcodes are available in bare script, P2SH,
P2WSH and tapscript, with separate legacy size and opcode-count
limits. No funded spend or relay policy was tested. See
[script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md).

## Reproduction

```sh
cargo test --locked --lib commitments::sha256_pool::tests
cargo test --locked --test primitive_metrics sha256_pool_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

Tests check all ordered opening pairs in three pools, duplicate attempts,
malformed ranks at both positions, wrong preimages and witness shapes,
opaque size limits, duplicate public digests, and caller-state survival.
See the [knowledge entry](../../../knowledge/primitives/sha256-pair-pool.md).
