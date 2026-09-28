# PRINCEv2 standalone M-hat layer

## Research question

Can PRINCEv2's four repeated M-hat blocks be exposed as a reusable Bitcoin
Script fragment below the OP-019 5,000-byte frontier while retaining strict
stack execution and zero auxiliary hints?

## Construction

`prince_m_layer()` consumes the 16 MSB-first u4 state nibbles used by
`prince_encrypt()` and returns the transformed 16-nibble state in the same
order. It first certifies every input nibble is canonically encoded (the
empty byte vector for zero; a single byte with value `1..=15` otherwise, the
same per-nibble convention `prince_verify` uses), restoring and checking each
of the 16 altstack positions independently, then reuses the packed lookup
memory and quartet scheduler already used by the optimized PRINCEv2
generator. It omits key whitening, S-boxes, round constants, and ShiftRows.
The transformation is the PRINCEv2 M-layer and is an involution.

The fragment preserves unrelated stack items below the 16-state input. It
rejects out-of-range values and non-minimally encoded ScriptNums (e.g. a
two-byte encoding of a small value, or a byte with the sign bit set) at every
position; callers still own complete protocol binding at the surrounding
boundary.

## Measured boundary

The `fragment-with-memory` boundary includes canonical nibble checks, packed
table setup, all four M-hat blocks, output ordering, and table cleanup. It
excludes input pushes, output consumption, tapleaf/control-block bytes, and
transaction framing. The representative witness contains 16 nibble data items
and zero auxiliary hints; all data items coexist at entry.

| Configuration | Script bytes | Witness bytes | Hints | Peak items | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Zero-key packed layout, state `0x0123456789abcdef` | 1,707 | 32 (33 max) | 0 | 633 | 937 |

In Tapscript the local executor's `opcode_count` counts every parsed
instruction, pushes and untaken branches included (1,608 for the benchmark
leaf), so it is not a dynamic executed-opcode count; static non-push operations
are reported instead. The measured validation
weight delta was zero. The result is `locally-reproduced` in a tapscript
fixture with the combined 1,000-item stack limit enabled and remains
`unclassified` for deployment.

## Correctness and adversarial coverage

Deterministic tests compare zero, all-nibble-maximum, and
`0x0123456789abcdef` states against the native PRINCEv2 M-layer reference.
A dedicated all-position test certifies that every one of the 16 nibble
positions independently rejects an out-of-range value (`16`, `-1`) and a
non-minimal encoding (a two-byte zero, a two-byte one, the single-byte alias
`0x00`, a byte with the sign bit set), with a canonical all-zero control succeeding, under
`TapscriptProfile::Consensus` with a complete leaf; a short state is rejected
separately. The benchmark executes the representative state under the strict
local interpreter and reports the same boundary metrics.

## Comparison and limitation

The complete zero-key PRINCEv2 encryption fragment is 6,136 bytes and has the
same measured 633-item peak. The standalone linear layer is therefore below
the OP-019 5,000-byte fragment target, but it is not an encryption leaf and
does not close the full-key/full-plaintext differential criterion. Complete
transaction, Bitcoin Core, and relay-policy validation remain open.

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
