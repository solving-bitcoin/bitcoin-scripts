# Compressed total-domain u32 unsigned less-than

## Research question

Can unsigned less-than over the repository's four-byte u32 representation be
performed directly on two canonical compressed ScriptNum words without
expanding either word into four byte limbs?

## Hypothesis and construction

The compressed wire value is a signed ScriptNum: values below `2^31` are
nonnegative and values at or above `2^31` are negative. Within either sign
half, signed ordering is already unsigned ordering; only cross-sign pairs
need correction. `u32_compressed_lessthan()` therefore validates both raw
encodings, maps each word to `(sign, low31)` while treating the five-byte
`0x80000000` sentinel as `(1, 0)`, compares the legal 31-bit values, and
applies the sign correction.

The witness is hostile. Non-minimal encodings, negative zero, and invalid
five-byte values are rejected before normalization. The operation follows the
existing comparator contract `... a b -> ... (a < b)`, consumes both words,
and preserves unrelated lower stack state.

## Comparison objective and boundary

The objective is witness width and live stack-item count compared with
`u32_lessthan()` under the same two-word operation and terminal-check boundary.
The fragment-with-memory boundary includes both canonical-wire checks,
sign/magnitude normalization, comparison, and sign correction. It excludes
input pushes, terminal predicates, and transaction framing.

| Construction | Script bytes | Representative witness | Sentinel-boundary witness | Data items | Peak items | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Compressed ScriptNum unsigned less-than | 124 | 11 bytes | 8 bytes | 2 | 6 | 72 |
| Four-byte `u32_lessthan()` baseline | 38 | 17 bytes | not measured | 8 | 9 | 32 |

The compressed form saves six representative witness bytes and six entry
items, and reduces the measured peak by three items, but costs 86 locking
bytes. It is a witness-shape primitive, not a general locking-byte
optimization.

## Evidence and execution class

Evidence is `locally-reproduced`; deployment is `unclassified`. Deterministic
tests cover all pairings of eight semantic boundary values, 256 pairs from a
fixed ChaCha20 seed, the signed boundary, the five-byte sentinel, equal
values, and malformed encodings. The benchmark uses the locked
`bitcoin-scriptexec` revision in tapscript mode with the combined 1,000-item
stack limit enabled. Dynamic opcode counts are unavailable from the local
executor. No Bitcoin Core, complete-transaction, relay-policy, or
cryptographic claim is made.

## Reproduction

```sh
cargo test --locked u32_compressed_lessthan --lib
cargo test --locked --test primitive_metrics u32_compressed_lessthan_metrics_are_current
cargo run --locked --release --example u32_compressed_lessthan_benchmark
python3 tools/kb.py validate
```
