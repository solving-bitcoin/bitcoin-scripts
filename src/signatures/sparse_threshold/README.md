# Sparse exact-threshold tapscript signatures

`signatures::sparse_threshold::verify_sparse_threshold(keys, k)` checks
`k` nonempty signatures for distinct keys from a fixed x-only key list.
Witness signatures and key depths are hostile. The fragment consumes them
and its key table, preserving both caller stacks for an exact suffix.

## Parameters

The x-only public key list contains distinct keys. The required count
`k` is positive, at most the list length `n`, with `n + 2k <= 996`.
There are no defaults. Each depth refers to the original key table, with
depth zero referring to its last key.

## Script metrics

| Threshold | Schedule | Leaf bytes | Data witness bytes | Complete witness bytes | Ordinary items | Hint items | Hint bytes | Peak | Executed non-push ops | Initial budget | Charged |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 of 16 | Indexed | <!-- metric:sparse_threshold_16_script -->635<!-- /metric:sparse_threshold_16_script --> | <!-- metric:sparse_threshold_16_data -->268<!-- /metric:sparse_threshold_16_data --> | <!-- metric:sparse_threshold_16_full -->940<!-- /metric:sparse_threshold_16_full --> | 4 | 4 | <!-- metric:sparse_threshold_16_hintbytes -->7<!-- /metric:sparse_threshold_16_hintbytes --> | <!-- metric:sparse_threshold_16_peak -->28<!-- /metric:sparse_threshold_16_peak --> | <!-- metric:sparse_threshold_16_executed -->77<!-- /metric:sparse_threshold_16_executed --> | <!-- metric:sparse_threshold_16_budget -->990<!-- /metric:sparse_threshold_16_budget --> | <!-- metric:sparse_threshold_16_charged -->200<!-- /metric:sparse_threshold_16_charged --> |
| 4 of 16 | Dense | <!-- metric:dense_threshold_16_script -->546<!-- /metric:dense_threshold_16_script --> | <!-- metric:dense_threshold_16_data -->273<!-- /metric:dense_threshold_16_data --> | <!-- metric:dense_threshold_16_full -->856<!-- /metric:dense_threshold_16_full --> | 16 | 0 | <!-- metric:dense_threshold_16_hintbytes -->0<!-- /metric:dense_threshold_16_hintbytes --> | <!-- metric:dense_threshold_16_peak -->17<!-- /metric:dense_threshold_16_peak --> | <!-- metric:dense_threshold_16_executed -->17<!-- /metric:dense_threshold_16_executed --> | <!-- metric:dense_threshold_16_budget -->906<!-- /metric:dense_threshold_16_budget --> | <!-- metric:dense_threshold_16_charged -->200<!-- /metric:dense_threshold_16_charged --> |
| 2 of 64 | Indexed | <!-- metric:sparse_threshold_64_script -->2197<!-- /metric:sparse_threshold_64_script --> | <!-- metric:sparse_threshold_64_data -->134<!-- /metric:sparse_threshold_64_data --> | <!-- metric:sparse_threshold_64_full -->2368<!-- /metric:sparse_threshold_64_full --> | 2 | 2 | <!-- metric:sparse_threshold_64_hintbytes -->3<!-- /metric:sparse_threshold_64_hintbytes --> | <!-- metric:sparse_threshold_64_peak -->72<!-- /metric:sparse_threshold_64_peak --> | <!-- metric:sparse_threshold_64_executed -->67<!-- /metric:sparse_threshold_64_executed --> | <!-- metric:sparse_threshold_64_budget -->2418<!-- /metric:sparse_threshold_64_budget --> | <!-- metric:sparse_threshold_64_charged -->100<!-- /metric:sparse_threshold_64_charged --> |
| 2 of 64 | Dense | <!-- metric:dense_threshold_64_script -->2178<!-- /metric:dense_threshold_64_script --> | <!-- metric:dense_threshold_64_data -->193<!-- /metric:dense_threshold_64_data --> | <!-- metric:dense_threshold_64_full -->2408<!-- /metric:dense_threshold_64_full --> | 64 | 0 | <!-- metric:dense_threshold_64_hintbytes -->0<!-- /metric:dense_threshold_64_hintbytes --> | <!-- metric:dense_threshold_64_peak -->65<!-- /metric:dense_threshold_64_peak --> | <!-- metric:dense_threshold_64_executed -->65<!-- /metric:dense_threshold_64_executed --> | <!-- metric:dense_threshold_64_budget -->2458<!-- /metric:dense_threshold_64_budget --> | <!-- metric:dense_threshold_64_charged -->100<!-- /metric:dense_threshold_64_charged --> |

Both fixtures use exact leaf commitments, deterministic default-sighash
signatures and whole-leaf optimizer `ALL`. Data-witness serialization
includes item count and length prefixes and excludes script and control
block. The complete witness includes both, with no annex. All data and hints
coexist at entry. Hint bytes include each hint's length prefix. The dense
column counts empty placeholders as ordinary data. The budget is
`50 + complete serialized witness bytes` and charges 50 per nonempty check.

## Security

The generator rejects duplicate public keys. Canonical, strictly increasing
depths must fall inside the fixed key table before routing. Each signature is
checked by `OP_CHECKSIGVERIFY` under its selected 32-byte key. The caller
binds the input suffix, key list and required threshold. The enclosing
protocol governs key control and the sighash policy. No novel signature scheme
or security bound is asserted.

## Script compatibility and standardness

This is a tapscript fragment. Bare script, P2SH and P2WSH use different
signature semantics. The local transaction-aware fixture checks the
Taproot commitment and signatures with complete witness budget accounting.
Execution is `unclassified` and evidence is `locally-reproduced`.
See [script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md).

## Witness and hints

Supply `signature[k-1] depth[k-1] ... signature[0] depth[0]` bottom to top.
The consumed depths strictly increase. Each depth is a canonical ScriptNum
and is counted as a routing hint. There are `k` ordinary signatures plus
`k` hint items at entry. Add all preloaded inputs to the combined limit.

## Stack contract

`caller | signed depth pairs -> caller`. Altstack is unused. The combined
peak is at most `n + 2k + 4` plus both caller stacks. The fragment leaves
no Boolean result; a complete leaf includes an explicit terminal predicate.

## Operational notes and knowledge-base integration

See the [research note](../../../knowledge/primitives/sparse-tapscript-threshold.md)
for the comparison, case construction and deterministic reproduction.
