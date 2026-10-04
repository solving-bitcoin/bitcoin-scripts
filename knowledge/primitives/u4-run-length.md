# Checked u4 run-length expansion

`arithmetic::u4::run_length::u4_expand_canonical_runs` consumes a fixed number
of `(symbol, length)` pairs and returns the expanded nibble vector. Lengths
are in `1..=width-run_count+1`, sum to `width`, and adjacent symbols differ.
Symbols are canonical ScriptNums in `0..=15`.

- **Input:** `preserved | symbol[0] | length[0] | ... | symbol[n-1] | length[n-1]`,
  with the last length on top.
- **Output:** `preserved | nibble[0] | ... | nibble[width-1]`, with the last
  nibble on top.
- **Evidence:** `locally-reproduced` by boundary vectors, hostile items at
  every pair position, load-bearing checks for range, adjacency, exact width,
  and canonical re-encoding, and a strict 1,000-item frontier.
- **Representative result:** 321 locking-script bytes for width 16 and two
  runs, 8 serialized witness bytes, 4 payload items, 0 hints, and a 20-item
  combined peak.
- **Execution class:** `unclassified`. The strict local executor uses a
  tapscript context with the combined stack limit. No Bitcoin Core consensus
  or relay-policy transaction has been tested.

## Research framing

- **Question:** when does a canonical run-length witness reduce the entry
  item count of a u4 vector, and does that reduction also reduce
  script-plus-witness bytes versus checking the nibbles in place?
- **Hypothesis:** entry items fall when the average run is longer than two
  nibbles. The countdown expander does not repay those savings in bytes at
  width 16.
- **Comparison objective:** compare `u4_expand_canonical_runs(16, run_count)`
  with an in-place canonical nibble check of the same 16 outputs. Both are
  policy-compiled fragments. Witness bytes include only payload. Terminal
  predicates and transaction context are excluded on both sides.
- **Threat model:** every symbol and length is hostile. The script enforces
  range, canonical ScriptNum encoding, positive bounded lengths, adjacent
  inequality, and the exact sum. A zero-length pair is rejected because
  expansion would otherwise omit its symbol while the sum could still match.
- **Hard constraints:** BIP342 minimal-if, the 1,000-item combined stack, the
  repository compilation policy, and a compile-time run count. There are no
  hint items. All payload items coexist at script entry.

## Measured configurations

Both fixtures include length and symbol checks, the sum check, adjacent
inequality, countdown emission, and restoration to the main stack. They
exclude input pushes, witness serialization from the script, terminal
predicates, unrelated live state, and transaction context. Interpreter
`a09e87af444034698697f0a2267e755cf72f9aed` and `rust-bitcoin-script`
`124b561e` are the pins in `Cargo.lock`. Execution options are the strict
tapscript helper: stack limit on, minimal data on, minimal-if on.

The two-run witness is `(0, 8)` then `(15, 8)`. Its policy script SHA256 is
`00c8ca6ef44237329a54df1e49adeb7944393d22a7f1ed7065a207b0849d08f1`.

| Metric | Two runs | Eight length-2 runs |
| --- | ---: | ---: |
| Script bytes | 321 | 867 |
| Serialized witness bytes | 8 | 29 |
| Data items | 4 | 16 |
| Hint items | 0 | 0 |
| Maximum combined stack items | 20 | 21 |
| Static non-push opcodes | 271 | 709 |
| Executed opcodes | unavailable | unavailable |
| Validation weight | unavailable | unavailable |

The eight-run witness alternates symbols `0, 1` with every length equal to 2.
Its 21-item peak is that witness, not the shape-wide bound. The bound
`max(2*run_count+5, width+run_count+2)` is 26 for eight runs of width 16 and
is pinned by the formula test on worst-case lengths. Callers add preserved
main-stack and altstack items to the bound. The tapscript opcode counter
includes skipped countdown bodies, so it is not reported as executed opcodes.

In-place checking of the same two-run nibbles costs 206 script bytes and 25
witness bytes across 16 items. The two-run expander saves 12 entry items and
17 witness bytes, and spends 115 extra script bytes. Combined bytes rise from
231 to 329. The length-2 and length-1 shapes are worse. Details are in
[NR-073](../negative-results/index.md#nr-073-fixed-count-u4-run-length-expansion-loses-combined-bytes).

A length greater than 1 used directly as `OP_IF` fails with
`TapscriptMinimalIf`. The countdown uses `OP_GREATERTHAN` so the condition is
a minimal 0 or 1.

The 271 and 709 static non-push counts exceed the 201-opcode limit for bare,
P2SH, and P2WSH script. These rows are tapscript-oriented fragments, not
complete leaves.

## Reproduction

```sh
CARGO_INCREMENTAL=0 cargo test --locked arithmetic::u4::run_length --lib
CARGO_INCREMENTAL=0 cargo test --locked --test primitive_metrics u4_run_length_metrics_are_current
python3 tools/kb.py validate
```

This result does not claim consensus validity, relay-policy acceptance, or
cryptographic security.

See the [implementation README](../../src/arithmetic/u4/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and catalog record
`arithmetic/u4-run-length`.
