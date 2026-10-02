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

See the [source-bound report](../../research/stable-stack-compaction/README.md),
[primitive](../primitives/stable-selection.md),
[NR-078](../negative-results/stable-selection.md) and
[composition obligations](../techniques/composition.md#stable-selection-with-native-binary-flags).
