# Weighted native Schnorr quorum

A tapscript fragment verifies that valid Schnorr signatures from distinct
public key slots meet an explicit weighted threshold. Each group shares
one native signature-count accumulator. The group weight is applied
after its count is known.

## Parameters and stack contract

`verify_weighted_quorum(groups, threshold)` takes an explicit ordered
slice of `(weight, keys)` groups. Each group is nonempty. Weights
are in `1..=16`, there are 1 through 995 distinct typed x-only keys,
and the threshold is positive and at most the sum of all weights.
The first listed key has its signature on top of the witness stack.
In flattening order, each key has exactly one signature item,
including an empty vector for an absent signature. The fragment
consumes those items and leaves no output. Both caller stacks are
preserved for the exact suffix, and the caller adds the terminal
predicate for a complete leaf.

Native `OP_CHECKSIGADD` counts valid signatures within each group.
The weighted total is temporarily on the altstack. After multiplying
the count by its public weight, add it to the total and continue.
The threshold check runs after every key has been checked. The
largest possible weighted sum is 15,920. With the existing constant
multiplier, a weight up to 16 needs at most four extra main-stack
items above the group count, after that group has consumed at
least one signature. The resulting combined bound is `n+5` plus
preserved caller state. At width 995, the one-key group of weight
15 followed by 994 weight-one keys reaches exactly 1,000.

## Script metrics

The per-key baseline uses native `OP_CHECKSIG` and applies the
weight to each result individually. Both complete leaves use the
same public key groups, threshold, signer indices and terminal true.
Signatures are generated separately for the exact policy-produced
leaf and transaction digest. Each data witness contains `n`
ordinary signature slots and zero hints. All slots coexist at entry.

| Keys | Threshold | Schedule | Leaf bytes | Serialized data witness | Complete witness bytes | Ordinary items | Nonempty signatures | Hint items (serialized bytes) | Combined peak | Executed non-push ops | Validation charge |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 3 | 6 | Grouped | <!-- metric:weighted_quorum_3_grouped_script -->125<!-- /metric:weighted_quorum_3_grouped_script --> | <!-- metric:weighted_quorum_3_grouped_data -->132<!-- /metric:weighted_quorum_3_grouped_data --> | <!-- metric:weighted_quorum_3_grouped_complete -->292<!-- /metric:weighted_quorum_3_grouped_complete --> | 3 | 2 | 0 (0 bytes) | <!-- metric:weighted_quorum_3_grouped_stack -->5<!-- /metric:weighted_quorum_3_grouped_stack --> | <!-- metric:weighted_quorum_3_grouped_executed -->20<!-- /metric:weighted_quorum_3_grouped_executed --> | <!-- metric:weighted_quorum_3_grouped_charge -->100<!-- /metric:weighted_quorum_3_grouped_charge --> |
| 3 | 6 | Per-key | <!-- metric:weighted_quorum_3_direct_script -->121<!-- /metric:weighted_quorum_3_direct_script --> | <!-- metric:weighted_quorum_3_direct_data -->132<!-- /metric:weighted_quorum_3_direct_data --> | <!-- metric:weighted_quorum_3_direct_complete -->288<!-- /metric:weighted_quorum_3_direct_complete --> | 3 | 2 | 0 (0 bytes) | <!-- metric:weighted_quorum_3_direct_stack -->5<!-- /metric:weighted_quorum_3_direct_stack --> | <!-- metric:weighted_quorum_3_direct_executed -->19<!-- /metric:weighted_quorum_3_direct_executed --> | <!-- metric:weighted_quorum_3_direct_charge -->100<!-- /metric:weighted_quorum_3_direct_charge --> |
| 6 | 7 | Grouped | <!-- metric:weighted_quorum_6_grouped_script -->227<!-- /metric:weighted_quorum_6_grouped_script --> | <!-- metric:weighted_quorum_6_grouped_data -->199<!-- /metric:weighted_quorum_6_grouped_data --> | <!-- metric:weighted_quorum_6_grouped_complete -->461<!-- /metric:weighted_quorum_6_grouped_complete --> | 6 | 3 | 0 (0 bytes) | <!-- metric:weighted_quorum_6_grouped_stack -->8<!-- /metric:weighted_quorum_6_grouped_stack --> | <!-- metric:weighted_quorum_6_grouped_executed -->23<!-- /metric:weighted_quorum_6_grouped_executed --> | <!-- metric:weighted_quorum_6_grouped_charge -->150<!-- /metric:weighted_quorum_6_grouped_charge --> |
| 6 | 7 | Per-key | <!-- metric:weighted_quorum_6_direct_script -->237<!-- /metric:weighted_quorum_6_direct_script --> | <!-- metric:weighted_quorum_6_direct_data -->199<!-- /metric:weighted_quorum_6_direct_data --> | <!-- metric:weighted_quorum_6_direct_complete -->471<!-- /metric:weighted_quorum_6_direct_complete --> | 6 | 3 | 0 (0 bytes) | <!-- metric:weighted_quorum_6_direct_stack -->8<!-- /metric:weighted_quorum_6_direct_stack --> | <!-- metric:weighted_quorum_6_direct_executed -->36<!-- /metric:weighted_quorum_6_direct_executed --> | <!-- metric:weighted_quorum_6_direct_charge -->150<!-- /metric:weighted_quorum_6_direct_charge --> |
| 32 | 28 | Grouped | <!-- metric:weighted_quorum_32_grouped_script -->1112<!-- /metric:weighted_quorum_32_grouped_script --> | <!-- metric:weighted_quorum_32_grouped_data -->609<!-- /metric:weighted_quorum_32_grouped_data --> | <!-- metric:weighted_quorum_32_grouped_complete -->1758<!-- /metric:weighted_quorum_32_grouped_complete --> | 32 | 9 | 0 (0 bytes) | <!-- metric:weighted_quorum_32_grouped_stack -->34<!-- /metric:weighted_quorum_32_grouped_stack --> | <!-- metric:weighted_quorum_32_grouped_executed -->49<!-- /metric:weighted_quorum_32_grouped_executed --> | <!-- metric:weighted_quorum_32_grouped_charge -->450<!-- /metric:weighted_quorum_32_grouped_charge --> |
| 32 | 28 | Per-key | <!-- metric:weighted_quorum_32_direct_script -->1254<!-- /metric:weighted_quorum_32_direct_script --> | <!-- metric:weighted_quorum_32_direct_data -->609<!-- /metric:weighted_quorum_32_direct_data --> | <!-- metric:weighted_quorum_32_direct_complete -->1900<!-- /metric:weighted_quorum_32_direct_complete --> | 32 | 9 | 0 (0 bytes) | <!-- metric:weighted_quorum_32_direct_stack -->34<!-- /metric:weighted_quorum_32_direct_stack --> | <!-- metric:weighted_quorum_32_direct_executed -->194<!-- /metric:weighted_quorum_32_direct_executed --> | <!-- metric:weighted_quorum_32_direct_charge -->450<!-- /metric:weighted_quorum_32_direct_charge --> |
| 64 | 40 | Grouped | <!-- metric:weighted_quorum_64_grouped_script -->2200<!-- /metric:weighted_quorum_64_grouped_script --> | <!-- metric:weighted_quorum_64_grouped_data -->833<!-- /metric:weighted_quorum_64_grouped_data --> | <!-- metric:weighted_quorum_64_grouped_complete -->3070<!-- /metric:weighted_quorum_64_grouped_complete --> | 64 | 12 | 0 (0 bytes) | <!-- metric:weighted_quorum_64_grouped_stack -->66<!-- /metric:weighted_quorum_64_grouped_stack --> | <!-- metric:weighted_quorum_64_grouped_executed -->81<!-- /metric:weighted_quorum_64_grouped_executed --> | <!-- metric:weighted_quorum_64_grouped_charge -->600<!-- /metric:weighted_quorum_64_grouped_charge --> |
| 64 | 40 | Per-key | <!-- metric:weighted_quorum_64_direct_script -->2502<!-- /metric:weighted_quorum_64_direct_script --> | <!-- metric:weighted_quorum_64_direct_data -->833<!-- /metric:weighted_quorum_64_direct_data --> | <!-- metric:weighted_quorum_64_direct_complete -->3372<!-- /metric:weighted_quorum_64_direct_complete --> | 64 | 12 | 0 (0 bytes) | <!-- metric:weighted_quorum_64_direct_stack -->66<!-- /metric:weighted_quorum_64_direct_stack --> | <!-- metric:weighted_quorum_64_direct_executed -->386<!-- /metric:weighted_quorum_64_direct_executed --> | <!-- metric:weighted_quorum_64_direct_charge -->600<!-- /metric:weighted_quorum_64_direct_charge --> |
| 995 | 15 | Grouped | <!-- metric:weighted_quorum_995_grouped_script -->33857<!-- /metric:weighted_quorum_995_grouped_script --> | <!-- metric:weighted_quorum_995_grouped_data -->1062<!-- /metric:weighted_quorum_995_grouped_data --> | <!-- metric:weighted_quorum_995_grouped_complete -->34956<!-- /metric:weighted_quorum_995_grouped_complete --> | 995 | 1 | 0 (0 bytes) | <!-- metric:weighted_quorum_995_grouped_stack -->1000<!-- /metric:weighted_quorum_995_grouped_stack --> | <!-- metric:weighted_quorum_995_grouped_executed -->1017<!-- /metric:weighted_quorum_995_grouped_executed --> | <!-- metric:weighted_quorum_995_grouped_charge -->50<!-- /metric:weighted_quorum_995_grouped_charge --> |
| 995 | 15 | Per-key | <!-- metric:weighted_quorum_995_direct_script -->35837<!-- /metric:weighted_quorum_995_direct_script --> | <!-- metric:weighted_quorum_995_direct_data -->1062<!-- /metric:weighted_quorum_995_direct_data --> | <!-- metric:weighted_quorum_995_direct_complete -->36936<!-- /metric:weighted_quorum_995_direct_complete --> | 995 | 1 | 0 (0 bytes) | <!-- metric:weighted_quorum_995_direct_stack -->1000<!-- /metric:weighted_quorum_995_direct_stack --> | <!-- metric:weighted_quorum_995_direct_executed -->2999<!-- /metric:weighted_quorum_995_direct_executed --> | <!-- metric:weighted_quorum_995_direct_charge -->50<!-- /metric:weighted_quorum_995_direct_charge --> |

Data serialization includes the CompactSize item count and slot
lengths. The complete witness includes the leaf and the single
33-byte control block, and has no annex. The transaction body is
outside both byte columns. The peak covers main and alt stacks.
The trace counts executed non-push instructions in the branch-free
leaf. Each nonempty valid signature charges 50 budget units. The
initial budget is 50 plus the complete witness bytes. Width 995 is
unoptimized under the central policy because even its key pushes
exceed 32 KiB. Other rows use `CompileOptions::ALL`.

The [fixture](../../../tests/support/weighted_quorum.rs) fixes the
outpoint, output amounts, internal key and deterministic Schnorr
signing inputs. It verifies the script-path commitment, then runs
the exact signed synthetic transaction with the pinned transaction-aware
interpreter, stack limits on, numeric minimality and OP_CAT off, and
complete-witness budget accounting.

## Security, compatibility and execution

Keys are typed 32-byte x-only values and duplicates reject during
generation. Empty signature items contribute zero. Invalid nonempty
signatures fail the tested leaf even if other valid signatures
already reach the threshold. The enclosing policy must account for
any other leaves or a Taproot key path. Fixture keys are deterministic
and the synthetic prevout was not funded.

The grouped schedule requires tapscript's native `OP_CHECKSIGADD`.
Bare script, P2SH and P2WSH do not provide its tapscript Schnorr
semantics. See [script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md). Evidence is
`locally-reproduced`, deployment is `unclassified`, and no
cryptographic security bound or complete spend classification is claimed.

## Reproduction

```sh
cargo test --locked --test weighted_quorum_contract
cargo test --locked --test primitive_metrics weighted_quorum_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

Tests cover all 64 subsets of six keys, wrong leaves and transactions,
malformed nonempty signatures, swapped or repeated signatures,
wrong witness counts, generator validation, and the exact combined
stack limit. See the
[knowledge entry](../../../knowledge/primitives/weighted-schnorr-quorum.md).
