# Standalone PRINCEv2 M-hat experiment

## Question

Can the repeated four-block PRINCEv2 M-hat layer be exposed as a reusable
checked Script fragment below 5,000 policy-produced bytes without auxiliary
hints or exceeding the strict 1,000-item tapscript stack limit?

## Hypothesis and comparison

The full zero-key PRINCEv2 fragment is 6,136 bytes because it repeats M-hat
inside S-box, key, round-constant, and ShiftRows logic. Reusing its packed
table layout and stack scheduler while removing those unrelated actions should
leave a much smaller linear-layer fragment. The closest retained comparison is
the complete zero-key encryption fragment; the old fresh-pair-table helper is a
test-only baseline and is not a composable production construction.

## Boundary and threat model

The measured boundary is `fragment-with-memory`: numeric `0..=15` checks,
packed lookup setup, four M-hat blocks, output restoration, and cleanup. It
excludes input pushes, output consumption, transaction framing, and unrelated
live state. Witness input is hostile numeric ScriptNum data; range failures,
negative values, and missing state items must fail before lookup depths are
used. Minimally encoded byte serialization is a caller-level obligation.

## Result

The fragment is 1,565 bytes, uses 16 data items and zero hints, reaches a
strict 633-item combined peak, and has 827 static non-push operations. The
local executor reports no useful dynamic opcode count for this run. The
result is `locally-reproduced` and `unclassified` for deployment; it is a
linear subconstruction, not a complete encryption proof.

## Reproduction

```sh
cargo test --locked optimized_m_layer --lib
cargo test --locked --test primitive_metrics prince_metrics_are_current
cargo run --locked --release --example prince_m_layer_benchmark
python3 tools/kb.py validate
```

