# Compressed total-domain u32 logical right shift

## Research question

Can a single canonical compressed u32 ScriptNum implement a logical right shift
without first expanding into four byte limbs?

## Construction

`u32_compressed_rshift(shift)` accepts one compressed ScriptNum representing a
32-bit unsigned word and supports `shift` in `1..=31`. It first checks the
canonical wire boundary, maps the sign-carried high bit and the remaining
value into a legal sign/magnitude pair, divides the 31-bit magnitude by a
compile-time power of two using threshold subtraction, and restores the
logical high-bit contribution. The result is a positive canonical ScriptNum
for every nonzero shift.

The fragment contract is:

```text
... word -> ... (word >> shift)
```

Both the compressed input and output are data items; no auxiliary hints are
required. The fragment does not provide a terminal predicate or clean-stack
wrapper.

## Measured boundary

All measurements use the repository's policy compilation and strict local
`bitcoin-scriptexec` tapscript executor with the 1,000-item stack limit. They
exclude input pushes, the terminal predicate, transaction framing, and
unrelated live stack state.

| Configuration | Script bytes | Witness bytes | Data items | Peak |
| --- | ---: | ---: | ---: | ---: |
| Direct compressed shift by 8 | 500 | 6 representative / 7 sentinel-boundary maximum | 1 | 5 |
| Decode, byte-shift, re-encode baseline | 499 | 6 representative / 7 sentinel-boundary maximum | 1 | 7 |

The direct form is effectively equal in locking bytes to the local
decode-shift-reencode baseline at shift 8, while saving two live stack items.
It is a representation and stack-shape result, not a general byte reduction;
script size varies with the generated shift ladder.

## Evidence and limitations

Evidence is `locally-reproduced`; deployment is `unclassified`. Boundary and
deterministic random tests cover every shift from 1 through 31, including
`0x80000000`, and malformed/trailing encodings are rejected. The baseline is
an executable local composition of the existing `u32_uncompress`, a byte
shift-by-8 adapter, and `u32_compress`; it is not an independent Bitcoin Core
implementation. Complete transaction validation, relay policy, and a pinned
Core differential remain open under OP-002, OP-003, and OP-014.

Reproduce with:

```sh
cargo test --locked u32_compressed_rshift --lib
cargo run --locked --release --example u32_compressed_rshift_benchmark
```
