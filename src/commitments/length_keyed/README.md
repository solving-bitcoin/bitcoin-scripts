# Length-keyed SHA-256 opening

Verify one opaque preimage against the public digest assigned to its
exact byte length. The preimage supplies its own selector through
`OP_SIZE`.

## Parameters and stack contract

`verify_length_keyed_sha256(first_length, commitments, block_size)`
takes three generation parameters and has no defaults.

- `first_length` is in `0..=520`.
- `commitments` is a nonempty contiguous table. Slot `i` commits to a
  preimage of length `first_length + i`, at most 520.
- `block_size` is in `1..=commitments.len()`. Size one uses a separate
  branch for each digest. Size equal to the table uses one resident
  table. Intermediate sizes put tables behind branches.

Main starts with `caller | preimage`. Success consumes the preimage
and leaves both caller stacks as they were. The caller supplies
any required continuation and terminal predicate.

## Construction

The fragment checks the actual size against the contiguous public
range before hashing once. A binary dispatch selects a block by
length. A multi-entry block subtracts its first length, parks the
derived index, and pushes the block's digests in reverse order.
`OP_ROLL` selects the indicated digest. The rest of the selected
table is cleared before raw equality. A one-entry block compares
its literal directly. No inactive block pushes any digest.

## Script metrics

The leaves include range validation, one SHA-256, dispatch, table
lifecycle where applicable, equality and terminal true. All
schedules use the same data witness. Fixture byte `i` is
`(17*i + length) mod 256`; the public digests are computed with
the existing host SHA-256 helper. Data witness bytes include count
and item length. Leaf, control block, annex and transaction
framing are excluded. Peak combines both stacks. Executed
non-push counts include processed control delimiters.

| First length | Digests | Opened length | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (bytes) | Combined peak | Executed non-push ops |
| ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 16 | 32 | 31 | One digest per branch | <!-- metric:length_sha256_32_tree_script -->1317<!-- /metric:length_sha256_32_tree_script --> | <!-- metric:length_sha256_32_tree_witness -->33<!-- /metric:length_sha256_32_tree_witness --> | 1 | 0 (0 bytes) | <!-- metric:length_sha256_32_tree_stack -->5<!-- /metric:length_sha256_32_tree_stack --> | <!-- metric:length_sha256_32_tree_executed -->112<!-- /metric:length_sha256_32_tree_executed --> |
| 16 | 32 | 31 | Eight digests per block | <!-- metric:length_sha256_32_blocked_script -->1112<!-- /metric:length_sha256_32_blocked_script --> | <!-- metric:length_sha256_32_blocked_witness -->33<!-- /metric:length_sha256_32_blocked_witness --> | 1 | 0 (0 bytes) | <!-- metric:length_sha256_32_blocked_stack -->10<!-- /metric:length_sha256_32_blocked_stack --> | <!-- metric:length_sha256_32_blocked_executed -->31<!-- /metric:length_sha256_32_blocked_executed --> |
| 16 | 32 | 31 | Full table | <!-- metric:length_sha256_32_full_script -->1091<!-- /metric:length_sha256_32_full_script --> | <!-- metric:length_sha256_32_full_witness -->33<!-- /metric:length_sha256_32_full_witness --> | 1 | 0 (0 bytes) | <!-- metric:length_sha256_32_full_stack -->34<!-- /metric:length_sha256_32_full_stack --> | <!-- metric:length_sha256_32_full_executed -->30<!-- /metric:length_sha256_32_full_executed --> |
| 0 | 128 | 79 | One digest per branch | <!-- metric:length_sha256_128_tree_script -->5238<!-- /metric:length_sha256_128_tree_script --> | <!-- metric:length_sha256_128_tree_witness -->81<!-- /metric:length_sha256_128_tree_witness --> | 1 | 0 (0 bytes) | <!-- metric:length_sha256_128_tree_stack -->5<!-- /metric:length_sha256_128_tree_stack --> | <!-- metric:length_sha256_128_tree_executed -->404<!-- /metric:length_sha256_128_tree_executed --> |
| 0 | 128 | 79 | Eight digests per block | <!-- metric:length_sha256_128_blocked_script -->4407<!-- /metric:length_sha256_128_blocked_script --> | <!-- metric:length_sha256_128_blocked_witness -->81<!-- /metric:length_sha256_128_blocked_witness --> | 1 | 0 (0 bytes) | <!-- metric:length_sha256_128_blocked_stack -->10<!-- /metric:length_sha256_128_blocked_stack --> | <!-- metric:length_sha256_128_blocked_executed -->71<!-- /metric:length_sha256_128_blocked_executed --> |
| 0 | 128 | 79 | Full table | <!-- metric:length_sha256_128_full_script -->4306<!-- /metric:length_sha256_128_full_script --> | <!-- metric:length_sha256_128_full_witness -->81<!-- /metric:length_sha256_128_full_witness --> | 1 | 0 (0 bytes) | <!-- metric:length_sha256_128_full_stack -->130<!-- /metric:length_sha256_128_full_stack --> | <!-- metric:length_sha256_128_full_executed -->77<!-- /metric:length_sha256_128_full_executed --> |
| 0 | 521 | 519 | One digest per branch | <!-- metric:length_sha256_521_519_tree_script -->21744<!-- /metric:length_sha256_521_519_tree_script --> | <!-- metric:length_sha256_521_519_tree_witness -->523<!-- /metric:length_sha256_521_519_tree_witness --> | 1 | 0 (0 bytes) | <!-- metric:length_sha256_521_519_tree_stack -->5<!-- /metric:length_sha256_521_519_tree_stack --> | <!-- metric:length_sha256_521_519_tree_executed -->1589<!-- /metric:length_sha256_521_519_tree_executed --> |
| 0 | 521 | 519 | Eight digests per block | <!-- metric:length_sha256_521_519_blocked_script -->18070<!-- /metric:length_sha256_521_519_blocked_script --> | <!-- metric:length_sha256_521_519_blocked_witness -->523<!-- /metric:length_sha256_521_519_blocked_witness --> | 1 | 0 (0 bytes) | <!-- metric:length_sha256_521_519_blocked_stack -->10<!-- /metric:length_sha256_521_519_blocked_stack --> | <!-- metric:length_sha256_521_519_blocked_executed -->227<!-- /metric:length_sha256_521_519_blocked_executed --> |
| 0 | 521 | 519 | Full table | <!-- metric:length_sha256_521_519_full_script -->17471<!-- /metric:length_sha256_521_519_full_script --> | <!-- metric:length_sha256_521_519_full_witness -->523<!-- /metric:length_sha256_521_519_full_witness --> | 1 | 0 (0 bytes) | <!-- metric:length_sha256_521_519_full_stack -->523<!-- /metric:length_sha256_521_519_full_stack --> | <!-- metric:length_sha256_521_519_full_executed -->273<!-- /metric:length_sha256_521_519_full_executed --> |
| 0 | 521 | 520 | One digest per branch | <!-- metric:length_sha256_521_520_tree_script -->21744<!-- /metric:length_sha256_521_520_tree_script --> | <!-- metric:length_sha256_521_520_tree_witness -->524<!-- /metric:length_sha256_521_520_tree_witness --> | 1 | 0 (0 bytes) | <!-- metric:length_sha256_521_520_tree_stack -->5<!-- /metric:length_sha256_521_520_tree_stack --> | <!-- metric:length_sha256_521_520_tree_executed -->1589<!-- /metric:length_sha256_521_520_tree_executed --> |
| 0 | 521 | 520 | Eight digests per block | <!-- metric:length_sha256_521_520_blocked_script -->18070<!-- /metric:length_sha256_521_520_blocked_script --> | <!-- metric:length_sha256_521_520_blocked_witness -->524<!-- /metric:length_sha256_521_520_blocked_witness --> | 1 | 0 (0 bytes) | <!-- metric:length_sha256_521_520_blocked_stack -->5<!-- /metric:length_sha256_521_520_blocked_stack --> | <!-- metric:length_sha256_521_520_blocked_executed -->218<!-- /metric:length_sha256_521_520_blocked_executed --> |
| 0 | 521 | 520 | Full table | <!-- metric:length_sha256_521_520_full_script -->17471<!-- /metric:length_sha256_521_520_full_script --> | <!-- metric:length_sha256_521_520_full_witness -->524<!-- /metric:length_sha256_521_520_full_witness --> | 1 | 0 (0 bytes) | <!-- metric:length_sha256_521_520_full_stack -->523<!-- /metric:length_sha256_521_520_full_stack --> | <!-- metric:length_sha256_521_520_full_executed -->273<!-- /metric:length_sha256_521_520_full_executed --> |

## Security, compatibility and composition

The preimage is hostile, and the digest table and its length labels
are public script constants. Exactly one digest is assigned to each
length. A caller that needs to accept several commitments at one
length needs another distinguishing input or predicate. The fragment
checks a native SHA-256 relation and makes no separate security claim.

There is one ordinary item and zero hints, all at entry. If the
selected block has `k` digests, reserve `max(5, k+2)` live items
plus both caller stacks. The 521-digest full table reaches 523
items before caller state. With 477 caller items it reaches the
1,000-item combined limit, and the next item fails. Eight-entry
blocks fit that witness and caller state. A partial final block
can have a smaller peak than the configured maximum.

Every measured leaf uses central compile policy `ALL` and
stack-limited local tapscript Consensus with a synthetic transaction,
experimental OP_CAT disabled, and zero signature charge. The local
Policy profile accepts the 31- and 79-byte fixtures and rejects
519- and 520-byte witnesses by its 80-byte cap. Bare, P2SH and P2WSH
share the opcodes, with different
[script-type](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md) limits.
Evidence is `locally-reproduced`; execution is `unclassified`.

## Reproduction

```sh
cargo test --locked --lib commitments::length_keyed::tests
cargo test --locked --test primitive_metrics length_keyed_sha256_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

The tests exercise every length and block size in an offset
17-slot table, wrong digests and swapped length labels, malformed
entry shape, the 520-byte boundary, both local profiles, and
the exact full-table caller frontier. See the
[knowledge page](../../../knowledge/primitives/length-keyed-sha256.md).
