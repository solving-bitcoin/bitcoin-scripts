# NR-078: Forward stable filtering and redundant flag guards

Forward ROLL consumption stages retained items in original order on altstack;
restoring them reverses the output. Omitting the final reversal passes a count
check but fails the exact asymmetric payload checks with `EqualVerify`. The
same clean-success assertion detects that ordering mutation. Correcting order
requires conditional reversal: at 32 all-retained pairs it costs 970 fragment /
1,070 leaf bytes, peak 66, versus backward 496/596/65 under the same native
MINIMALIF flags. Both use 64 entry data items, zero hints and 129 serialized
witness bytes, include identical output checks and use optimizer `ALL`.

Explicit numeric range/canonical checks are redundant to native tapscript
MINIMALIF for this exact binary flag domain. Backward guarded selection costs
816/916 bytes and peaks at 68; forward guarded selection 1,290/1,390/68.
Both guarded variants reach 1,000 items at 498 pairs and fail at 499 with typed
`StackSize` at 1,001. This is context-specific dominance, not permission to
remove guards from legacy truthy IF or numeric selector APIs.

Discarding payloads cannot rescue entry violations. Every 521-byte payload
rejects `PushSize` before its flag is consumed; local policy rejects 81- and
520-byte payloads even when discarded. The 500-pair native research baseline
starts with exactly 1,000 data items and fails at count initialization.
For 499 retained 520-byte payloads, the checked literal leaf grows to
270,319 bytes, explicitly unoptimized `NONE`, while the fragment is 8,339 bytes
`ALL`. Opaque routing does not by itself make a whole transaction practical.

These are `locally-reproduced`, `unclassified` exact local tapscript-profile
results, not global lower bounds or complete Core/policy validation. There are
zero hints in all configurations and `2n` ordinary items at entry; report peaks
include both stacks. Source/dependency/artifact pins and deterministic witness
specifications are in the [reproduction guide](../../research/stable-stack-compaction/README.md).
Dynamic executed-opcode counts are unavailable; zero signature charge is not
a transaction budget. Protocol composition remains
[OP-036](../open-problems.md#op-036--stable-selection-protocol-composition).

## Sparse indices at full density

At `n = k = 32`, a valid index list names every payload. The index leaf saves
one serialized witness byte against the all-true flag leaf but spends 196 more
script bytes, three more peak items and 126 more executed non-push operations.
The one-byte saving comes from canonical zero encoding as the empty item.

The matched identity baseline provides only the payloads and emits the fixed
count. It costs 97 script bytes, 65 witness bytes, 32 data items, a peak of 33
and 32 executed non-push operations. The full index and flag leaves cost
792/128/64/68/575 and 596/129/64/65/449, respectively, in the same units.
All three need zero hints, check the same exact outputs and count, and use
optimizer `ALL` under the local stack-limited tapscript `Consensus` profile.
Identity's dominance applies to the full-subset contract.

Output checks alone also cannot distinguish two positions holding the same
bytes. The focused test selects each position from a pair of equal items and
both witnesses pass the same checked leaf. A position-sensitive caller needs a
separate binding. See the [reproduction](../primitives/indexed-selection.md#composition-and-reproduction).
