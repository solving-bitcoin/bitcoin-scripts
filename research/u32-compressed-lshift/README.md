# Compressed u32 logical left shift

This experiment evaluates direct modulo-`2^32` left shifts over the
repository's one-item compressed u32 representation. It checks canonical
ScriptNum wire encodings, removes the sign-carried high bit for nonzero
shifts, repeatedly doubles the safe 31-bit magnitude, and re-centers overflow
as a negative compressed ScriptNum.

At shift 8, the direct fragment is 492 locking bytes, uses one six-byte
serialized witness item, and peaks at five stack items. The local
decode-byte-shift-reencode baseline is 490 bytes with the same witness and a
seven-item peak. The sentinel-boundary witness is seven serialized bytes.

Run:

```sh
cargo test --locked u32_compressed_lshift --lib
cargo run --locked --release --example u32_compressed_lshift_benchmark
```

Results are locally reproduced under strict tapscript execution. They are not
Bitcoin Core or relay-policy validation.
