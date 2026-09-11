# Compressed total-domain u32 equality

This research fixture measures `u32_compressed_equal()` against the existing
four-byte `u32_equal()` operation. It validates the exact compressed ScriptNum
wire boundary before comparing two hostile inputs.

The representative fixture uses `0x01020304`; the maximum witness fixture uses
the `0x80000000` sentinel. Reproduce it with:

```sh
cargo test --locked u32_compressed_equal --lib
cargo test --locked --test primitive_metrics u32_compressed_equal_metrics_are_current
cargo run --locked --release --example u32_compressed_equal_benchmark
```

The local result is `locally-reproduced` under `research-unlimited` execution
classification for this fragment. The strict executor enforces the combined
1,000-item stack limit, but this work does not claim Bitcoin Core or relay
policy validation.
