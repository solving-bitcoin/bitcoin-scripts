# Stable stack selection schedules

Compare stable filtering of opaque payloads under the same native tapscript
MINIMALIF flag contract, then compare explicit canonical/range guard variants
separately. All rows below use 32 one-byte `42` payloads with all flags `01`:
64 ordinary data items, zero hints, 129 serialized witness bytes, all at entry.

| Schedule / flag validation | Fragment bytes | Complete checked leaf | Combined peak |
| --- | ---: | ---: | ---: |
| Backward, native MINIMALIF (public) | 496 | 596 | 65 |
| Forward ROLL plus reversal, native MINIMALIF | 970 | 1,070 | 66 |
| Backward, explicit numeric/canonical guards | 816 | 916 | 68 |
| Forward ROLL plus reversal, explicit guards | 1,290 | 1,390 | 68 |

Fragments include validation, count, routing, discard cleanup and stable
restoration; exclude input pushes and terminal checks. Leaves check the same
count and every retained raw payload, then leave TRUE. All use policy `ALL`.
Native backward saves 474 bytes and one live item against matched native
forward. Removing guards accounts for a separate 320-byte saving and three
items; it must not be attributed to routing. At 499 pairs, native backward /
forward fragment bytes are 8,339 / 18,800 and peaks 999 / 1,000. Explicit guards
reach 1,000 at 498 pairs and fail at 499. These are scoped configurations.

For a separate [raw multiset comparison](../primitives/opaque-multiset.md),
both width-16 leaves verify two lists have identical raw multiplicities.
Bounded deletion hints lower script bytes from 1,477 to 219 and executed
non-push operations from 599 to 151. They add 15 hint items and 27 witness
bytes to the same 32 ordinary payload items, and raise combined peak from
34 to 50. Two preloaded hinted invocations have 64 payload items plus
30 hints and peak at 97. These figures use a complete local checked-leaf
boundary and carry unclassified execution.

The existing `u32_conditional_select` selects one of two four-item vectors.
Its numeric truthy condition is normalized by OP_0NOTEQUAL, accepts numeric
aliases when allowed by the profile, and rejects overlong numbers. It is not
a substitute for variable-length filtering or native exact binary validation.
The shared contract audit preserves that API and makes no limb-validity claim.

Every configuration is `locally-reproduced` / `unclassified`, using the explicit
local `Consensus` tapscript profile with stack checks and native MINIMALIF,
numeric minimality off, OP_CAT disabled and a synthetic data-only transaction
context. Static counts are recorded; executed non-push counts and complete
transaction budgets are unavailable. The 499-pair complete leaf binding 520-byte
payloads is 270,319 bytes, explicitly unoptimized `NONE`; fragment remains
`ALL`. Local policy rejects payloads over 80 bytes even when discarded.

The [single-run mask decoder](../primitives/single-run-mask.md) checks that
binary flags form one nonempty interval and returns its start and length.
It has no payload inputs. At 32 flags and eight selected positions, its
signed-length schedule is 602 bytes, compared with 698 for a separate closed
flag. Both use a 41-byte serialized witness, 32 ordinary items and zero
hints. Their combined peaks are 33 and 35, and their executed non-push
counts are 352 and 354. These are matched interval predicates under the
same local profile, a separate contract from stable payload compaction.

See the [source-bound report](../../research/stable-stack-compaction/README.md),
[primitive](../primitives/stable-selection.md),
[NR-078](../negative-results/stable-selection.md) and
[composition obligations](../techniques/composition.md#stable-selection-with-native-binary-flags).

## Fixed-count sparse indices versus binary flags

| Retained from 32 | Encoding | Complete leaf bytes | Witness bytes | Data items | Hint items | Peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | Indices | 114 | 72 | 36 | 0 | 40 | 87 |
| 4 | Flags | 511 | 101 | 64 | 0 | 65 | 309 |
| 16 | Indices | 402 | 96 | 48 | 0 | 52 | 297 |
| 16 | Flags | 547 | 113 | 64 | 0 | 65 | 369 |
| 32 | Indices | 792 | 128 | 64 | 0 | 68 | 575 |
| 32 | Flags | 596 | 129 | 64 | 0 | 65 | 449 |
| 32 | Identity | 97 | 65 | 32 | 0 | 33 | 32 |

Each leaf checks the same count and ordered raw bytes for its subset. Payload
`i` is `0x20 + i`, and the retained original depths are
`floor(j * 32 / k)` for `0 <= j < k`. Witness includes every entry item
and its serialization overhead, excluding script, control block, annex and
transaction. All rows are `ALL`, `locally-reproduced` and `unclassified`
with the stack-limited local tapscript `Consensus` profile. Opcode traces
include active non-push operations and encountered branch delimiters.

For sparse subsets, the index schedule saves bytes and live items. Its
`n + k + 4` bound admits 995 payloads when retaining one, with no caller state.
Flags support variable counts and fit up to 499 pairs. At full density,
the identity baseline consumes no selectors and is cheapest on every
measured resource except hints, which tie. See
[indexed selection](../primitives/indexed-selection.md) for the boundary,
assumptions and reproduction, and
[NR-078](../negative-results/stable-selection.md#sparse-indices-at-full-density)
for the dominated case.
