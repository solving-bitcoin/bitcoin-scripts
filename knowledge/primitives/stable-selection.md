# Stable selection of opaque stack items

`support::selection::compact_selected_items(n)` consumes `n` uninterpreted
payload/canonical-binary-flag pairs and returns the retained payloads in their
original order followed by their exact canonical count. It preserves both
caller stacks, uses no resident table and requires zero hints. Native
tapscript MINIMALIF enforces exact empty/`01` flags; this guarantee is specific
to that context. Selection provides no authentication or payload validity.

## Research framing

Question: can stable compaction of opaque runtime-selected items avoid forward
ROLL routing and output reversal while staying composable under the combined
1,000-item bound? Hypothesis: consuming pairs backward stages selected payloads
on altstack in the order needed for stable restoration. Compare both schedules
with identical flags, inputs, count and terminal checks. Every witness item is
hostile. Hard constraints are the compilation policy, 520-byte elements,
observable preservation of both caller stacks and exact typed rejections.

Stable subsequence filtering is established terminology: immutable
[C++ draft [alg.copy]](https://github.com/Eelis/draft/blob/c7015b485cc3db8efaa9dfb9ff0809c5394a4ed1/source/algorithms.tex)
specifies stable `copy_if`. It supplies semantic context, not a Script cost or
security claim. Catalog absence established a coverage gap, not global novelty.

## Reproduced configurations

| Native all-retained fixture | Reverse fragment / leaf | Matched forward fragment / leaf | Reverse / forward peak | Witness bytes | Data / hints |
| --- | ---: | ---: | ---: | ---: | ---: |
| 32 one-byte payloads | 496 / 596 | 970 / 1,070 | 65 / 66 | 129 | 64 / 0 |
| 128 one-byte payloads | 2,032 / 2,421 | 4,331 / 4,720 | 257 / 258 | 515 | 256 / 0 |
| 499 one-byte payloads | 8,339 / 9,841 | 18,800 / 20,302 | 999 / 1,000 | 1,999 | 998 / 0 |

All listed scripts use optimizer `ALL`. Fragments exclude input pushes and
terminal predicates; leaves check count and every retained raw payload and
leave one true item. Witness includes all `2n` data items and serialization
prefixes, including discarded payloads, excluding script/control block/annex.
With all 32 flags false, reverse leaf is 499 bytes and witness 97 bytes;
data/hint counts and combined peak remain 64/0/65.

For 499 retained 520-byte payloads, fragment remains 8,339 bytes (`ALL`), witness
is 261,978 bytes, and complete literal-checking leaf is 270,319 bytes,
**unoptimized** (`NONE`) because raw whole-leaf serialization exceeds 32 KiB.
Local policy rejects these entry elements, even if flags discard them.
Fragment maximum witness size ranges over all allowed flags and payloads;
the catalog's all-retained literal leaves bind a fixed successful witness and
use that witness size as their maximum.

Combined peak is 1 at `n=0`, at most 4 at `n=1` (3 if discarded), and `2n+1`
at `n>=2`, plus both caller stacks. At 499 pairs one caller item fits at 1,000;
two fail at 1,001. The 500-pair native research baseline fails at count
initialization. Public constructors reject `n>499`. Every preloaded future
invocation contributes its full input items; zero hints do not remove data
coexistence constraints.

## Evidence and obligations

All configurations are `locally-reproduced` and `unclassified`. Execution uses
the explicit local `Consensus` tapscript profile: MINIMALIF and stack checks
enabled, numeric minimality disabled, experimental OP_CAT disabled, synthetic
empty transaction, data-only witness, no signatures. Executed non-push opcode
counts and complete transaction budget are unavailable. Static counts and zero
signature-weight charge are recorded separately. No Core or deployment claim
is transferred from other profile fixtures.

The [shared contract suite](../../tests/selection_contract.rs) covers four
filter families and the existing numeric word selector. It checks every mask
through eight pairs, asymmetric long vectors, empty/nonnumeric/520-byte
payloads, malformed flags at every position, short inputs, exact boundaries,
both caller stacks, count/output bindings and compiled bypass mutations with
valid controls and the same typed-error assertion. The word selector accepts
numeric aliases under the nonminimal-number profile; its at-most-four-byte
condition contract and API are preserved. Selecting raw bytes does not prove
that they are valid u32 limbs.

The caller must bind selector meaning, retained vector/count and a terminal
predicate. Dropped payload substitutions leave output unchanged by design.
Bare, P2SH and P2WSH compatibility cannot inherit tapscript's flag guarantee;
the 32-pair fragment also exceeds their legacy opcode limit. Policy and full
Taproot validation remain open under OP-036.

Reproduce from the [source-pinned guide](../../research/stable-stack-compaction/README.md).
The [report](../../research/stable-stack-compaction/metrics.json) binds every row
to source hashes, lockfile dependency pins, flags, payloads, witness/script
hashes, whole-artifact compilation options, expected/actual outputs and cost
boundaries. See the [implementation README](../../src/support/selection/README.md),
[comparison](../comparisons/stack-selection.md),
[negative result](../negative-results/stable-selection.md) and catalog
`support/stable-selection`.
