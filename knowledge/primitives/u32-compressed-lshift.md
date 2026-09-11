# Compressed total-domain u32 logical left shift

## Research question

Can a canonical one-item compressed u32 ScriptNum implement a modulo-`2^32`
logical left shift without expanding into four byte limbs?

## Hypothesis and threat model

The sign-carried high bit is irrelevant after any nonzero left shift. If the
remaining 31-bit magnitude is doubled repeatedly and recentered whenever it
crosses `2^30`, the result can remain a canonical compressed ScriptNum at each
step. The witness input is hostile and must pass the exact compressed-wire
check; there is no cryptographic security claim and no auxiliary hint.

## Construction

`u32_compressed_lshift(shift)` supports `shift` in `1..=31`. It validates the
input, extracts the lower 31-bit magnitude, and applies a compile-time number
of checked doublings. A doubling below `2^30` remains positive. A doubling at
or above that threshold is reduced modulo `2^32` and represented as the
corresponding negative ScriptNum, which is normalized before the next step.

The fragment contract is:

```text
... word -> ... ((word << shift) mod 2^32)
```

## Measured boundary

Measurements use policy compilation and strict local `bitcoin-scriptexec` in a
tapscript context with the 1,000-item stack limit. They exclude input pushes,
the terminal predicate, transaction framing, and unrelated live state.

| Configuration | Script bytes | Witness bytes | Data items | Peak |
| --- | ---: | ---: | ---: | ---: |
| Direct compressed shift by 8 | 492 | 6 representative / 7 sentinel-boundary maximum | 1 | 5 |
| Decode, byte-shift, re-encode baseline | 490 | 6 representative / 7 sentinel-boundary maximum | 1 | 7 |

The direct construction is two bytes larger at shift 8 but saves two live
stack items. It is therefore a stack-shape primitive and a useful compressed
representation experiment, not a general locking-byte improvement. Generated
script size varies with the requested shift.

## Evidence and limitations

Evidence is `locally-reproduced`; deployment is `unclassified`. Deterministic
boundary tests cover every shift in `1..=31`; deterministic random vectors
cover selected widths, and malformed, negative-zero, and padded inputs are
rejected. The baseline is an executable local composition of the existing
compressed decoder, a four-byte shift-by-8 adapter, and the existing encoder;
it is not an independent Core implementation. Complete transaction, policy,
and pinned Bitcoin Core differential validation remain open under OP-002,
OP-003, and OP-020.

Reproduce with:

```sh
cargo test --locked u32_compressed_lshift --lib
cargo run --locked --release --example u32_compressed_lshift_benchmark
```
