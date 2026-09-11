# Compressed total-domain u32 addition

## Research question

Can the existing four-byte u32 carry chain be exposed over two canonical
compressed ScriptNum words without losing total-domain correctness at the
`0x80000000` sentinel and malformed-input boundaries?

## Construction and threat model

`u32_compressed_add()` consumes the top two compressed u32 ScriptNums, checks
their exact canonical wire encodings, expands them with `u32_uncompress()`,
reuses `u32_add_drop()` for modulo-`2^32` addition, and recompresses the result.
The result is one canonical compressed ScriptNum. The two inputs are hostile;
non-minimal aliases, negative zero, wrong five-byte values, and malformed
widths are rejected before expansion. The operation preserves unrelated items
below its two input words, subject to the documented altstack composition
boundary.

## Comparison objective and boundary

The objective is serialized witness width and entry-item count, compared with
the existing four-byte `u32_add_drop(0, 1)` under the same two-word operation
and terminal cleanup. The `fragment-with-memory` boundary includes both wire
certificates, expansion, the byte carry chain, and recompression; it excludes
input pushes, witness serialization from locking-script bytes, terminal
predicates, and transaction framing.

| Construction | Script bytes | Representative witness | Maximum witness | Data items | Peak items | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Compressed ScriptNum add | 1,016 | 11 | 13 | 2 | 11 | 765 |
| Four-byte baseline | 78 | 20 | 20 | 8 | 10 | 51 |

The compressed form saves nine representative witness bytes and six entry
items, but costs 938 more locking bytes and one stack item. It is therefore a
witness-width primitive, not a general byte-size improvement. The local
executor reports no useful dynamic opcode count; validation-weight delta is
zero in the strict tapscript fixture.

## Evidence and execution class

Evidence is `locally-reproduced`; deployment is `unclassified`. Deterministic
tests cover zero, carry, wraparound, signed-boundary, and all-ones cases plus
64 pairs from the fixed ChaCha20 seed `0x43304144`. Adversarial tests reject non-minimal one,
negative zero, an invalid five-byte value, and a non-minimal second operand.
The strict fixture uses the locked `bitcoin-scriptexec` revision in tapscript
mode with the combined 1,000-item stack limit enabled. No Bitcoin Core,
complete-transaction, relay-policy, or cryptographic claim is made.

## Reproduction

```sh
cargo test --locked compressed_add --lib
cargo test --locked --test primitive_metrics u32_compressed_add_metrics_are_current
cargo run --locked --release --example u32_compressed_add_benchmark
python3 tools/kb.py validate
```
