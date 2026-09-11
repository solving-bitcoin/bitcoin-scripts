# Compressed total-domain u32 unsigned less-than

This fixture measures `u32_compressed_lessthan()` against the existing
four-byte `u32_lessthan()` operation. It validates exact compressed ScriptNum
wire encodings, maps signed compressed words to a sign bit and legal low-31
value, and corrects ordering across the sign boundary.

The representative fixture compares `0x01020304 < 0x05060708`; the boundary
fixture includes `0 < 0x80000000`. Reproduce it with:

```sh
cargo test --locked u32_compressed_lessthan --lib
cargo test --locked --test primitive_metrics u32_compressed_lessthan_metrics_are_current
cargo run --locked --release --example u32_compressed_lessthan_benchmark
```

The result is `locally-reproduced` under an `unclassified` deployment class.
Strict execution enforces the combined 1,000-item stack limit, but this work
does not claim Bitcoin Core or relay-policy validation.
