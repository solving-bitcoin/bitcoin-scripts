# Compressed u32 addition experiment

## Question

Does a canonical one-item ScriptNum wire reduce witness and entry-stack cost
enough to justify wrapping the existing byte-oriented modulo-`2^32` adder?

## Hypothesis

The compressed form should remove six of the eight byte-word data items and
reduce witness serialization, but its two full ScriptNum expanders and
canonicality checks should dominate locking-script bytes.

## Result

At `0xa5c319e7 + 0x12345678`, compressed addition is 1,016 script bytes,
11 witness bytes, 2 data items, and an 11-item strict peak. The four-byte
baseline is 78 script bytes, 20 witness bytes, 8 data items, and a 10-item
peak. Dynamic opcode counting is unavailable; the static counts are 765 and
51 respectively. The compressed construction is thus useful only under a
witness-width objective and is recorded as a dominated locking-byte tradeoff.

## Reproduction

```sh
cargo test --locked compressed_add --lib
cargo test --locked --test primitive_metrics u32_compressed_add_metrics_are_current
cargo run --locked --release --example u32_compressed_add_benchmark
```

