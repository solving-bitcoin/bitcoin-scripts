# Checked u4 embedded-threshold trichotomy

`arithmetic::u4::trichotomy::u4_nibbles_to_trichotomy` consumes a contiguous
batch of canonical u4 nibbles and replaces each item with one numeric class:
`0` for less-than, `1` for equal, and `2` for greater-than an embedded public
threshold.

## Boundary and comparison

Every hostile nibble is range-checked before classification. Generation rejects
a non-u4 threshold, an empty batch, and a batch over the standalone strict-stack
ceiling. The fragment preserves unrelated lower main-stack and alt-stack state
and returns classes in the original order.

The numeric range check does not enforce byte-unique ScriptNum encoding. A
caller that needs canonical witness bytes must compose the existing
`verify_canonical_nibble()` boundary before this classifier.

The representative configuration uses threshold `5` over 16 canonical one-byte
witness nibbles. It includes range checks, two comparisons, branch selection,
and output restoration; it excludes input pushes, the terminal predicate,
unrelated live state, and transaction context. No hints are required.

This single pass exposes all three relations. It avoids composing separate
threshold and equality masks when a caller needs bucket labels or can count the
resulting `0/1/2` classes later. It is not a histogram or terminal predicate.

Evidence is `locally-reproduced`; execution is `unclassified`. The strict local
executor enforces the combined 1,000-item stack limit. No Bitcoin Core
consensus or relay-policy validation is claimed.

## Reproduction

```sh
cargo test --locked arithmetic::u4::trichotomy::tests --lib
cargo test --locked --test primitive_metrics u4_trichotomy_metrics_are_current -- --exact
python3 tools/kb.py validate
```
