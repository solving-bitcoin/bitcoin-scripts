# Fused u32 XNOR adapter

## Research question

Can the existing shared byte XOR table implement a variable-input u32 XNOR
adapter without duplicating a 256-entry lookup table or changing the u32 stack
contract?

## Construction and threat model

`u32_xnor(a, b, stack_size)` copies the selected word pair, applies the
existing table-backed byte XOR four times, and computes `255 - xor` for each
byte. The byte operands are hostile witness values, so the underlying XOR
table's range behavior remains part of the construction's safety boundary.
No cryptographic security claim is made.

## Boundary and comparison

The representative fragment boundary includes word routing, four table-backed
XNOR byte operations, and output routing. It excludes table setup and cleanup,
witness pushes, terminal predicates, and transaction framing. The closest
existing variable construction is `u32_xor`; XNOR adds one complement schedule
per byte while preserving the same 256-item shared table.

| Construction | Locking script | Witness | Hint items | Peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Fused XNOR, two u32 words | 222 | 0 bytes | 0 | 272 | 182 |

The metric row is refreshed by the focused primitive-metrics test in CI. The
table is shared with XOR, AND, and OR adapters; no per-invocation hints are
required.

## Evidence and execution class

The implementation is currently `inspected`; focused CI is the executable
reproduction gate. Deployment is `unclassified`. The script preserves the
selected input word and unrelated caller stack state under the existing u32
router contract.

Static opcode count is not a dynamic execution or validation-weight claim. No
Bitcoin Core differential, relay-policy, or complete-transaction validation is
claimed.

## Stack contract

Before: `... | word[a] | word[b] | table`, with the shared table below the
working words according to `stack_size`.

After: `... | word[a] | XNOR(word[a], word[b])`; the selected word is preserved,
the second word is consumed, and the table remains available for the caller.
The fragment does not provide a terminal predicate or clean-stack wrapper.

## Reproduction

```sh
cargo test --locked arithmetic::u32::xnor::tests --lib
cargo test --locked --test primitive_metrics u32_xnor_metrics_are_current -- --exact
python3 tools/kb.py validate
```

The full repository test suite is intentionally not included in this focused
contribution run.
