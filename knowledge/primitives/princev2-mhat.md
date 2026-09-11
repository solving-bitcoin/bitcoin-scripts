# PRINCEv2 standalone M-hat layer

## Research question

Can PRINCEv2's four repeated M-hat blocks be exposed as a reusable Bitcoin
Script fragment below the OP-019 5,000-byte frontier while retaining strict
stack execution and zero auxiliary hints?

## Construction

`prince_m_layer()` consumes the 16 MSB-first u4 state nibbles used by
`prince_encrypt()` and returns the transformed 16-nibble state in the same
order. It first checks every numeric input is in `0..=15`, then reuses the
packed lookup memory and quartet scheduler already used by the optimized
PRINCEv2 generator. It omits key whitening, S-boxes, round constants, and
ShiftRows. The transformation is the PRINCEv2 M-layer and is an involution.

The fragment preserves unrelated stack items below the 16-state input. It
does not enforce minimally encoded witness bytes; callers that require a
canonical wire encoding must add that policy at the surrounding boundary.

## Measured boundary

The `fragment-with-memory` boundary includes numeric range checks, packed table
setup, all four M-hat blocks, output ordering, and table cleanup. It excludes
input pushes, output consumption, tapleaf/control-block bytes, and transaction
framing. The representative witness contains 16 nibble data items and zero
auxiliary hints; all data items coexist at entry.

| Configuration | Script bytes | Witness bytes | Hints | Peak items | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Zero-key packed layout, state `0x0123456789abcdef` | 1,565 | 32 (33 max) | 0 | 633 | 827 |

The local executor reported no useful dynamic opcode count for this run, so
static non-push operations are reported separately. The measured validation
weight delta was zero. The result is `locally-reproduced` in a tapscript
fixture with the combined 1,000-item stack limit enabled and remains
`unclassified` for deployment.

## Correctness and adversarial coverage

Deterministic tests compare zero, all-nibble-maximum, and
`0x0123456789abcdef` states against the native PRINCEv2 M-layer reference.
They also reject an out-of-range nibble, a negative ScriptNum, and a short
state. The benchmark executes the representative state under the strict local
interpreter and reports the same boundary metrics.

## Comparison and limitation

The complete zero-key PRINCEv2 encryption fragment is 6,136 bytes and has the
same measured 633-item peak. The standalone linear layer is therefore below
the OP-019 5,000-byte fragment target, but it is not an encryption leaf and
does not close the full-key/full-plaintext differential criterion. Complete
transaction, Bitcoin Core, relay-policy, and canonical-byte validation remain
open.

## Reproduction

```sh
cargo test --locked optimized_m_layer --lib
cargo test --locked --test primitive_metrics prince_metrics_are_current
cargo run --locked --release --example prince_m_layer_benchmark
```

## Provenance

- PRINCEv2 reference: `princev2-reference`, pinned to the repository's
  immutable C revision in `knowledge/references/sources.json`.
- Script compilation: the locked `rust-bitcoin-script` revision through
  `ScriptCompilation::compile_with_policy()`.
- Execution: the locked `bitcoin-scriptexec` revision in tapscript mode with
  the combined stack limit enabled.

