# Checked AES-128 SubBytes

This page records a standalone checked AES S-box fragment extracted from the
repository's AES-128 u4 implementation. It substitutes all 16 bytes of one
128-bit state, but does not apply ShiftRows, MixColumns, or a key.

## Research question and objective

Can the existing 832-item shared AES lookup memory expose a reusable checked
SubBytes fragment that is materially smaller than full AES-128 while remaining
composable under the 1,000-item Tapscript stack limit?

The comparison is against the existing embedded-key `aes128_encrypt` fragment.
The goal is a reusable state transform, not an AES encryption replacement.

## Semantics and threat model

`aes128_sub_bytes()` consumes exactly 32 canonical ScriptNum nibbles. Nibble 0
(the high nibble of byte 0) is on top and nibble 31 is deepest. Each item must
be minimally encoded, in `0..=15`; the fragment rejects non-canonical encodings
and out-of-range values. It returns the 32 S-box output nibbles in the same
order, with an empty altstack relative to its entry state.

The witness is hostile. The fragment validates the range and raw encoding of
every nibble before using it as a lookup input. The public AES S-box is not a
secret and this fragment provides no authentication, key secrecy, or
side-channel claim. Callers still need a terminal predicate and clean-stack
handling when using it as a locking-script component.

## Evidence and execution class

The evidence level is `locally-reproduced`: deterministic tests compare the
fragment with the native AES S-box reference, reject malformed and boundary
inputs, and check preservation of surrounding main- and alt-stack state.
The result is `unclassified`, not a claim of consensus or policy deployment.
Local execution uses the repository's strict Script interpreter and combined
stack limit. No Bitcoin Core transaction or relay-policy experiment was run.

## Measured result

The metric boundary includes the shared lookup-table setup, checked input
validation, all 16 substitutions, and table cleanup. It excludes witness
pushes and output comparison. The witness has 32 data items and zero hints.

| Configuration | Script bytes | Witness bytes | Peak items | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: |
| Checked SubBytes, canonical 7 nibbles | 2,147 | 65 | 897 | 1,031 |
| Checked SubBytes, canonical 15 nibbles | 2,147 | 65 | 897 | 1,031 |

The fragment reuses an 832-item table and stays below the 1,000-item combined
stack limit in the measured boundary, but its static opcode count exceeds the
legacy 201-non-push limit. The result is therefore a research Tapscript
fragment, not a bare-script, P2SH, or P2WSH deployment claim.

## Comparison

The existing zero-key full AES-128 fragment is 25,388 bytes with a 908-item
peak and 33–65-byte plaintext witness. SubBytes is 23,241 bytes smaller and
has an 11-item lower measured peak, but it computes only the public S-box layer;
the size difference is not a security or functionality equivalence.

## Reproduction

```sh
cargo test --locked ciphers::aes::tests::sub_bytes --lib
cargo test --locked --test primitive_metrics aes_sub_bytes_metrics_are_current
python3 tools/kb.py validate
```

See the [implementation README](../../src/ciphers/aes/README.md), the
[AES cipher comparison](../comparisons/ciphers.md), and catalog record
`cipher/aes128-subbytes`.
