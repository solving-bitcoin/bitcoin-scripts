# Checked AES-128 MixColumns

This page records a standalone checked AES MixColumns fragment extracted from
the repository's AES-128 u4 implementation. It applies the AES linear column
transform to one 128-bit state, without a key, SubBytes, or ShiftRows.

## Research question and objective

Can the existing AES `xtime` sharing and 832-item lookup memory expose a
reusable checked MixColumns layer without duplicating the full AES round?

The comparison is against the existing embedded-key `aes128_encrypt` fragment.
The objective is a composable linear state transform, not a replacement for
AES encryption.

## Semantics and threat model

`aes128_mix_columns()` consumes exactly 32 canonical ScriptNum nibbles. Nibble 0
(the high nibble of byte 0) is on top and nibble 31 is deepest. Every item must
be minimally encoded, in `0..=15`; the fragment rejects non-canonical and
out-of-range values. It returns 32 MixColumns output nibbles in the same state
order and restores the surrounding main- and alt-stack state.

The witness is hostile. Each nibble is range-checked and its raw encoding is
checked before table indexing. MixColumns is a public linear transform, so this
fragment provides no secrecy, authentication, or independent cryptographic
security claim. Callers need their own terminal predicate and clean-stack
handling.

## Evidence and execution class

The evidence level is `locally-reproduced`: deterministic vectors compare the
Script fragment with the repository's native MixColumns reference, while
malformed inputs and surrounding stack state are tested separately. The result
is `unclassified`, not a consensus or relay-policy claim. Measurements use the
repository's strict Script interpreter and combined stack limit; no Bitcoin
Core transaction experiment was run.

## Measured result

The boundary includes checked input validation, shared lookup setup, all four
column transforms, and table cleanup. It excludes witness pushes and output
comparison. The witness has 32 data items and zero hints.

| Configuration | Script bytes | Witness bytes | Peak items | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: |
| Checked MixColumns, canonical 7 nibbles | 3,738 | 65 | 908 | 1,959 |
| Checked MixColumns, canonical 15 nibbles | 3,738 | 65 | 908 | 1,959 |

The shared lookup memory contains 832 items. The measured peak remains below
the 1,000-item combined stack limit, but the static opcode count exceeds the
legacy 201-non-push limit. This is a research Tapscript fragment, not a bare
Script, P2SH, or P2WSH deployment claim.

## Comparison

The zero-key full AES-128 fragment is 25,388 bytes with a 908-item peak and a
33–65-byte plaintext witness. Standalone MixColumns is 21,650 bytes smaller
at the same measured peak, but it computes only one linear round layer and
does not provide AES encryption or cryptographic security by itself.

## Reproduction

```sh
cargo test --locked ciphers::aes::tests::mix_columns --lib
cargo test --locked --test primitive_metrics aes_mix_columns_metrics_are_current
python3 tools/kb.py validate
```

See the [implementation README](../../src/ciphers/aes/README.md), the
[AES cipher comparison](../comparisons/ciphers.md), and catalog record
`cipher/aes128-mixcolumns`.
