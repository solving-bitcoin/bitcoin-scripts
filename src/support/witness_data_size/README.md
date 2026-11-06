# Serialized witness-data byte cap

Verify an upper bound on the serialization of a fixed number of opaque,
adversarially supplied stack items. The fragment preserves those items
and checks the size they would have as a standalone witness data vector.
There are no hints.

## Parameters and stack contract

`verify_data_witness_size_at_most(items, cap)` requires an explicit
nonnegative cap at most 2,147,483,647 bytes. The input count may be zero.
For a tight cap there may be at most 997 data items, and otherwise at most
996. The fragment expects the top `items` stack elements, each at most 520
bytes in the measured execution context. It leaves both stacks intact
and no result, failing verification if the cap is exceeded. Deeper
caller items are excluded from the count and cap. A leaf must still
consume the data as required and satisfy a terminal predicate.

For `n` items define `base = CompactSizeWidth(n) + n`. The exact cost is
`base + sum(len) + 2 * count(len >= 253)`. The formula uses the 520-byte
data-item limit so each item-length prefix is either one or three bytes.
If `cap < base + 253`, every accepted item is shorter than 253 because
the raw lengths are nonnegative and even one longer item makes the lower
bound exceed the cap. Thus the tight schedule omits all long-prefix tests.
For other caps the branch-free exact route adds twice the comparison
result for each item. Both schedules use `OP_SIZE` on temporary copies,
leaving the original bytes and order intact.

The nonempty combined peaks are `n + 3` for the tight route and `n + 4`
for the exact route, plus preserved caller state. The all-entry witness
has exactly `n` ordinary data items and zero hints. At 997 tight items
or 996 exact items, the local run reaches 1,000 and an extra caller item
fails. With zero input items the count prefix alone costs one byte.

## Script metrics

Both complete leaves check the same cap, drop the same preserved inputs,
and leave one true item. The baseline always checks the item prefix and
uses a branch to add two bytes for a long item. Serialized data includes
the count and per-item CompactSize prefixes and excludes the leaf, control
block, annex, and transaction. Fixture item `i` repeats byte
`(i mod 256) XOR 0xa5` for its listed length. The peak includes both
stacks. The executed count includes visited branch delimiters and depends
on the number of long items for the conditional baseline.

| Count | Cap (bytes) | Payload lengths | Schedule | Leaf bytes | Data witness bytes | Ordinary items | Hint items (serialized bytes) | Combined peak | Executed non-push ops |
| ---: | ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 32 | 161 | all length 4 | Selected route | <!-- metric:witness_cap_tight32_checked_script -->199<!-- /metric:witness_cap_tight32_checked_script --> | <!-- metric:witness_cap_tight32_checked_witness -->161<!-- /metric:witness_cap_tight32_checked_witness --> | 32 | 0 (0 bytes) | <!-- metric:witness_cap_tight32_checked_stack -->35<!-- /metric:witness_cap_tight32_checked_stack --> | <!-- metric:witness_cap_tight32_checked_executed -->146<!-- /metric:witness_cap_tight32_checked_executed --> |
| 32 | 161 | all length 4 | Always conditional | <!-- metric:witness_cap_tight32_branch_script -->487<!-- /metric:witness_cap_tight32_branch_script --> | <!-- metric:witness_cap_tight32_branch_witness -->161<!-- /metric:witness_cap_tight32_branch_witness --> | 32 | 0 (0 bytes) | <!-- metric:witness_cap_tight32_branch_stack -->36<!-- /metric:witness_cap_tight32_branch_stack --> | <!-- metric:witness_cap_tight32_branch_executed -->274<!-- /metric:witness_cap_tight32_branch_executed --> |
| 32 | 286 | all length 4 | Selected route | <!-- metric:witness_cap_wide_short32_checked_script -->455<!-- /metric:witness_cap_wide_short32_checked_script --> | <!-- metric:witness_cap_wide_short32_checked_witness -->161<!-- /metric:witness_cap_wide_short32_checked_witness --> | 32 | 0 (0 bytes) | <!-- metric:witness_cap_wide_short32_checked_stack -->36<!-- /metric:witness_cap_wide_short32_checked_stack --> | <!-- metric:witness_cap_wide_short32_checked_executed -->306<!-- /metric:witness_cap_wide_short32_checked_executed --> |
| 32 | 286 | all length 4 | Always conditional | <!-- metric:witness_cap_wide_short32_branch_script -->487<!-- /metric:witness_cap_wide_short32_branch_script --> | <!-- metric:witness_cap_wide_short32_branch_witness -->161<!-- /metric:witness_cap_wide_short32_branch_witness --> | 32 | 0 (0 bytes) | <!-- metric:witness_cap_wide_short32_branch_stack -->36<!-- /metric:witness_cap_wide_short32_branch_stack --> | <!-- metric:witness_cap_wide_short32_branch_executed -->274<!-- /metric:witness_cap_wide_short32_branch_executed --> |
| 32 | 1062 | 252, 253, 520 and 29 empty | Selected route | <!-- metric:witness_cap_wide_mixed32_checked_script -->455<!-- /metric:witness_cap_wide_mixed32_checked_script --> | <!-- metric:witness_cap_wide_mixed32_checked_witness -->1062<!-- /metric:witness_cap_wide_mixed32_checked_witness --> | 32 | 0 (0 bytes) | <!-- metric:witness_cap_wide_mixed32_checked_stack -->36<!-- /metric:witness_cap_wide_mixed32_checked_stack --> | <!-- metric:witness_cap_wide_mixed32_checked_executed -->306<!-- /metric:witness_cap_wide_mixed32_checked_executed --> |
| 32 | 1062 | 252, 253, 520 and 29 empty | Always conditional | <!-- metric:witness_cap_wide_mixed32_branch_script -->487<!-- /metric:witness_cap_wide_mixed32_branch_script --> | <!-- metric:witness_cap_wide_mixed32_branch_witness -->1062<!-- /metric:witness_cap_wide_mixed32_branch_witness --> | 32 | 0 (0 bytes) | <!-- metric:witness_cap_wide_mixed32_branch_stack -->36<!-- /metric:witness_cap_wide_mixed32_branch_stack --> | <!-- metric:witness_cap_wide_mixed32_branch_executed -->276<!-- /metric:witness_cap_wide_mixed32_branch_executed --> |
| 253 | 256 | all empty | Selected route | <!-- metric:witness_cap_tight253_checked_script -->1763<!-- /metric:witness_cap_tight253_checked_script --> | <!-- metric:witness_cap_tight253_checked_witness -->256<!-- /metric:witness_cap_tight253_checked_witness --> | 253 | 0 (0 bytes) | <!-- metric:witness_cap_tight253_checked_stack -->256<!-- /metric:witness_cap_tight253_checked_stack --> | <!-- metric:witness_cap_tight253_checked_executed -->1141<!-- /metric:witness_cap_tight253_checked_executed --> |
| 253 | 256 | all empty | Always conditional | <!-- metric:witness_cap_tight253_branch_script -->4040<!-- /metric:witness_cap_tight253_branch_script --> | <!-- metric:witness_cap_tight253_branch_witness -->256<!-- /metric:witness_cap_tight253_branch_witness --> | 253 | 0 (0 bytes) | <!-- metric:witness_cap_tight253_branch_stack -->257<!-- /metric:witness_cap_tight253_branch_stack --> | <!-- metric:witness_cap_tight253_branch_executed -->2153<!-- /metric:witness_cap_tight253_branch_executed --> |

## Security, compatibility and execution

Lengths come directly from the bytes being checked. A caller must keep
the same stack suffix if the limit is meant to cover later-consumed
data. Equal lengths can describe different content. This check provides
no authentication and does not count a script, control block, annex, or
other transaction data. A subset's standalone count prefix can differ
from the full witness's prefix.

The measured leaves use `CompileOptions::ALL` via the repository policy,
the pinned local tapscript Consensus profile with the 520-byte item and
1,000-item combined-stack limits, and zero signature validation charge.
The local Policy profile separately rejects an 81-byte entry item, even
when it satisfies the fragment's cap. Evidence is `locally-reproduced`;
execution is `unclassified`. The opcodes are available in bare, P2SH,
P2WSH and tapscript contexts. Legacy script and opcode-count limits and
relay constraints must be evaluated separately. See
[script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md).

## Reproduction

```sh
cargo test --locked --lib support::witness_data_size::tests
cargo test --locked --test primitive_metrics witness_data_cap_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

The tests compare with independent host witness serialization at both
CompactSize transitions, exercise hostile count and item-size cases,
and verify caller-state preservation. See the
[knowledge entry](../../../knowledge/primitives/witness-data-size.md).
