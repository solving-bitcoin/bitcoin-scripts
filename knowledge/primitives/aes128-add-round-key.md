# Checked AES-128 AddRoundKey boundary

`aes128_add_round_key` consumes 32 canonical u4 state nibbles and XORs them
with one generation-time AES-128 round key. It returns the same nibble order:
byte 0's high nibble is on top and byte 15's low nibble is deepest.

- **Question:** can the fused AES AddRoundKey operation be exposed as a
  reusable round boundary without changing the full encryptor's cost?
- **Hypothesis:** the existing shared 832-item AES table can serve 32 checked
  keyed XORs, making a composable keyed boundary without adding a new table.
- **Comparison:** the standalone boundary is compared with the full AES
  generator, which intentionally fuses AddRoundKey into neighboring transforms
  and therefore remains cheaper as a complete encryption path.
- **Threat model:** all state nibbles are hostile witness items; each is
  checked for minimal ScriptNum encoding and numeric range `0..=15` before
  lookup. The embedded key is public, and the fragment does not authenticate
  the state or provide a terminal predicate.
- **Execution:** `locally-reproduced`, `research-unlimited`; the local strict
  executor measures the fragment in tapscript context with the 1,000-item
  combined stack limit. No Bitcoin Core transaction validation is claimed.

The representative profile uses an all-zero key, 32 canonical `0x0f` witness
nibbles, zero hints, and includes table setup, checked queries, output cleanup,
and the strict combined stack peak. The full AES implementation continues to
use fused transforms; this boundary is retained for composition and testing,
not as a whole-cipher size optimization.

See the [AES implementation README](../../src/ciphers/aes/README.md),
[cipher comparison](../comparisons/ciphers.md), and catalog record
`cipher/aes128-add-round-key`.
