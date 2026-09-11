# Signed radix-32 decoder experiment

- **Question:** Can ScriptNum's native sign bit plus a shared 5-bit table beat
  conditional extraction for batches of signed radix-32 digits?
- **Hypothesis:** The table wins bytes after setup amortization while staying
  under the 1,000-item combined stack limit.
- **Comparison objective:** Minimize locking-script bytes for a checked batch;
  treat strict combined stack peak as a hard constraint.
- **Execution class:** `unclassified`; local tapscript execution only.
- **Deterministic vectors:** repeated canonical digit `31`; exhaustive
  correctness covers every digit in `[-31,31]`.

## Reproduction

```sh
cargo test --locked arithmetic::signed_window --lib
cargo test --locked --test primitive_metrics signed_window_metrics_are_current
cargo run --locked --release --example signed_window_benchmark
```

The retained table profile is 1,866 bytes for 32 digits and peaks at 348
items. The branch baseline is 2,430 bytes and peaks at 194 items. The table
loses at eight digits and wins at sixteen, so callers should select it only
when byte savings justify its resident stack memory.

## Falsification coverage

Tests cover every valid signed digit, batch order, `-32` and `32`, non-minimal
ScriptNum encoding, the maximum strict batch, and the first over-limit batch.
No Bitcoin Core or complete scalar-verifier differential test has been run.
