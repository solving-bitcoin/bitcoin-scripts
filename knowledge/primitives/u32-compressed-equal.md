# Compressed total-domain u32 equality

## Research question

Can equality over the repository's four-byte u32 representation be exposed
over two canonical compressed ScriptNum words without expanding either word?

## Construction and threat model

`u32_compressed_equal()` consumes the top two compressed u32 ScriptNums,
checks their exact canonical encodings, and compares the wire values directly.
The `0x80000000` value is the one accepted five-byte sentinel; all other
values must round-trip through the ScriptNum zero-add canonicalization check.
The two inputs are hostile. Non-minimal encodings, negative zero, and an
invalid five-byte value are rejected before comparison. The result is one
Boolean and unrelated lower stack state is preserved.

## Comparison objective and boundary

The objective is witness item count and serialization, compared with
`u32_equal()` under the same two-word equality and terminal-check boundary.
The fragment-with-memory boundary includes canonical-wire checks and the
equality operation; it excludes input pushes, terminal predicates, and
transaction framing.

| Construction | Script bytes | Representative witness | Maximum witness | Data items | Peak items | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Compressed ScriptNum equality | 37 | 11 | 13 | 2 | 5 | 21 |
| Four-byte `u32_equal()` baseline | 18 | 17 | 17 | 8 | 9 | 16 |

The compressed form saves six witness items and six representative witness
bytes, but costs 19 locking bytes. It is therefore useful when witness shape
or live item count matters, not as a universal script-byte optimization.

## Evidence and execution class

Evidence is `locally-reproduced`; deployment is `unclassified`. Deterministic
tests cover zero, positive values, the signed boundary, the `0x80000000`
sentinel, all-ones, equal and unequal pairs, plus malformed encodings. The
strict fixture uses the locked `bitcoin-scriptexec` revision in tapscript mode
with the combined 1,000-item stack limit enabled. Dynamic opcode counts are
not available from the local executor. No Bitcoin Core, complete-transaction,
relay-policy, or cryptographic claim is made.

## Reproduction

```sh
cargo test --locked u32_compressed_equal --lib
cargo test --locked --test primitive_metrics u32_compressed_equal_metrics_are_current
cargo run --locked --release --example u32_compressed_equal_benchmark
python3 tools/kb.py validate
```
