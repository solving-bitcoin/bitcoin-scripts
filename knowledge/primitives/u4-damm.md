# Checked decimal Damm fold

`arithmetic::u4::damm::u4_decimal_digits_to_damm(n)` implements one fixed
Damm transition table over hostile numeric decimal Script digits. It starts
at zero, consumes digits left to right, returns a canonical state and preserves
both caller stacks. The table is resident for the whole fold, then removed.
There are n ordinary entry data items, zero hints and no externally supplied
state. Numeric aliases are accepted when the profile allows them; ASCII text
and byte-unique encodings are outside the contract.

Question: can a resident transition table amortize a nonlinear finite-state fold
against per-digit row tables or balanced dispatch? Hypothesis: persistent memory
saves bytes on batches but limits live input/caller capacity. Compare identical
numeric validation, input order, state-zero initialization, table lifecycle and
terminal boundaries. All witnesses are hostile. Hard constraints: central
compilation policy, four-byte ScriptNum digits in 0..=9, 520-byte entry elements,
1,000 combined items and observable preservation of every caller item.

The matrix and reference fold are inspected at
[CheckDigits.Net 734afa2d3596862ef4c3bb3ec404b512b96b8965](https://github.com/KnowledgeForwardSolutions/CheckDigits.Net/tree/734afa2d3596862ef4c3bb3ec404b512b96b8965).
Exact upstream sources and MIT license are preserved. The original dissertation
could not be fetched; no thesis table inspection is claimed. Damm is an
established checksum, not a claimed new algorithm. Atlas absence identified a
coverage gap. The new result is the Script scheduling/composition frontier.

| Same 32 mixed digits | Fragment / checked leaf bytes | Combined peak |
| --- | ---: | ---: |
| Resident 100-entry table (public) | 766 / 769 | 136 |
| First-row dispatch warmup then resident | 829 / 832 | 135 |
| First-row table then dynamic ten-entry rows | 5,652 / 5,655 | 42 |
| Balanced table-free dispatch | 27,809 / 27,812 | 35 |

All use ALL, 32 ordinary entry items, zero hints and 61 canonical witness bytes.
Fragments include all setup, validation, routing and cleanup; exclude input
pushes and terminal predicates. Leaves bind the final numeric state and TRUE.
Witness includes count/length prefixes, excludes script/control block/annex.
At two digits resident 191 bytes beats row-table 206, but peaks at 106 rather
than 12. At one digit it loses: 172/105 versus row-table 27/11 and dispatch 81/4.
Thus this is a byte objective for batches, not universal dominance.

At 128 mixed digits resident uses 2,686 bytes / peak 232, versus row-table
23,124/138 ALL and table-free 113,731/131 explicitly **unoptimized NONE**.
The resident public frontier is 896 digits: 18,046/18,049 fragment/leaf bytes,
1,705 canonical witness bytes / 896 data items / zero hints / peak 1,000.
A four-byte alias of every same digit reaches the full allowed witness maximum
4,483 bytes with the same output and peak. The next unbounded research digit
fails typed StackSize at 1,001. Every caller main/alt item reduces capacity.

The report also prices independent folds with all messages preloaded and every
result bound. Two 32-digit folds have 64 data items / 0 hints, 67 fixture witness
bytes and peak 168; 28 folds have 896 / 0, 927 bytes and peak 1,000. A 29th fold
fails at 1,001. Whole-artifact byte counts and cross-component optimizer deltas
are recorded, rather than multiplying standalone bytes and assuming additivity.

The fixed table's row/column permutations, zero diagonal and all 1,000 adjacent
pair relations are checked exhaustively. From those finite properties, single
numeric substitutions and adjacent unequal numeric swaps in fixed-length valid
codewords change final state; column permutations preserve differences through
any suffix. The suite also executes all three-digit codewords and mutations.
This is error detection, not cryptographic authentication: `000` and `130` are
both valid, an attacker can compute any new check digit, leading zeros do not
bind length, and numeric aliases deliberately leave state unchanged.

Evidence is `locally-reproduced`; deployment is `unclassified` for every
configuration. Explicit local Consensus tapscript checks resources, enables
MINIMALIF, permits nonminimal numbers, disables experimental OP_CAT and uses
a synthetic empty transaction/data-only budget. Local Policy rejection of
aliases or oversized items is separate from relay validation. Static counts
are recorded; dynamic executed non-push counts and complete transaction budget
are unavailable. No signature executes and charged signature weight is zero.

The [shared contract suite](../../tests/damm_contract.rs) audits all schedules
and the existing two sum siblings under their own numeric/canonical contracts.
It covers hostile positions, aliases, short inputs, asymmetric order, observable
main/alt caller state, exact limits, preloaded independent results, local policy
and compiled validation/terminal bypasses with valid controls and the same typed
assertion. Existing APIs and sibling catalog evidence remain unchanged.

See [implementation](../../src/arithmetic/u4/damm/README.md),
[source-pinned reproduction](../../research/damm-finite-state/README.md),
[lookup comparison](../comparisons/lookup-strategies.md#damm-finite-state-folds),
[NR-079](../negative-results/damm-finite-state.md) and OP-037. A real authenticated
consumer and complete Core/policy transaction validation remain open.
