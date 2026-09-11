# Compressed u32 logical right shift

This experiment tests whether the compressed one-item u32 representation can
perform logical right shifts directly. The implementation validates the
canonical compressed ScriptNum, separates its sign-carried high bit from a
legal 31-bit magnitude, uses a generated threshold ladder for division by
`2^shift`, and restores the high-bit contribution.

The representative measurement is `u32_compressed_rshift(8)` on
`0x89abcdef`. The direct fragment is 500 locking bytes, uses one six-byte
serialized witness item, and peaks at five stack items. The local
decode-byte-shift-reencode baseline is 499 bytes with the same witness and a
seven-item peak. The sentinel-boundary witness is seven serialized bytes.

Run:

```sh
cargo test --locked u32_compressed_rshift --lib
cargo run --locked --release --example u32_compressed_rshift_benchmark
```

Results are locally reproduced under strict tapscript execution. They are not
Bitcoin Core or relay-policy validation.
