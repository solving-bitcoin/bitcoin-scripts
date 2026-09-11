# Total-domain compressed u32 logical right shift

## Question

Can the one-item compressed u32 wire implement logical right shifts for every
semantic 32-bit word, including `0x80000000`, without accepting ambiguous raw
ScriptNum encodings?

## Hypothesis and objective

Canonical raw-wire certification plus the existing u32 rotate/mask helpers
should close the negative-zero gap and reduce witness item count from four to
one. The comparison minimizes witness serialization and entry stack items
under a common strict tapscript boundary; locking-script bytes and static
opcode count are secondary costs.

## Threat model and execution class

The compressed word is hostile witness data. Non-minimal encodings, negative
zero, invalid five-byte values, and wrong-width items must be rejected before
numeric decoding. The local result is `locally-reproduced` and
`unclassified`: it uses the pinned local tapscript interpreter and strict
1,000-item stack checks, without Bitcoin Core or relay-policy differential
validation.

## Deterministic vectors and boundary

Every shift `1..=31` is tested for `0`, `0x7fffffff`, `0x80000000`, and
`0xffffffff`; mixed values `0x01020304` and `0xa5c319e7` use shifts 3, 11,
19, and 27. Malformed vectors include non-minimal `1`, negative zero, an
invalid five-byte word, and a six-byte word. Metrics use shift 7 and
`0xa5c319e7`, with table setup/cleanup, output cleanup, and `OP_TRUE` included;
input pushes and transaction framing are excluded.

## Reproduction

```sh
cargo test --locked arithmetic::u32::rshift --lib
cargo test --locked --test primitive_metrics total_domain_rshift_metrics_are_current
cargo run --locked --release --example u32_total_domain_rshift_benchmark
python3 tools/kb.py validate
```

The four-byte rotate/mask construction is the direct baseline. The compressed
wire wins witness bytes and entry item count but loses locking-script bytes;
that tradeoff is retained as a reproducible frontier result rather than being
presented as a universal optimization.
