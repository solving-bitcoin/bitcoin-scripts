# PRINCEv2

Bitcoin Script implementation of PRINCEv2 encryption for one 64-bit block with
a generation-time 128-bit key.

## Parameters

- Block size: fixed at 64 bits, represented by 16 nibbles.
- Key size: fixed at 128 bits and embedded in the generated locking fragment;
  no default key exists. The metric uses the all-zero key because key values
  can slightly affect push encodings.
- Encryption only; no public decryption script is currently exposed.

## Script metrics

The locking-fragment metric excludes the output comparison. The plaintext
witness size is Bitcoin witness serialization for 16 canonical script-number
nibbles; it varies only with the number of zero nibbles.

| Fragment | Script size |
| --- | ---: |
| `prince_encrypt(0)` | <!-- metric:prince_encrypt -->7685<!-- /metric:prince_encrypt --> bytes |
| Plaintext witness, all-zero block | <!-- metric:prince_witness_min -->17<!-- /metric:prince_witness_min --> bytes |
| Plaintext witness, no zero nibbles | <!-- metric:prince_witness_max -->33<!-- /metric:prince_witness_max --> bytes |

The fragment consists of a 7,547-byte optimized engine and a 188-byte adapter
that embeds the key and preserves this crate's stack convention. Maximum
combined main/alt-stack depth is 681 items. Tests pin both measurements and run
the published vector plus varied key/plaintext pairs against the Rust reference.

The engine is generated and cached by a native Rust translation of BitVM's
[`prince_v2_optimized10.js`](https://github.com/BitVM/bitvm-js/blob/b931a6711ab332fd5923e708c869bed02e39984e/scripts/opcodes/PRINCEv2/prince_v2_optimized10.js),
pinned to commit `b931a6711ab332fd5923e708c869bed02e39984e`. Tests pin the
generated engine's exact byte length and SHA-256 digest.

## Security

PRINCEv2 has a 128-bit key and 64-bit block. Exhaustive key search is nominally
128-bit, while generic block collisions occur around `2^32` blocks and codebook
coverage at `2^64`. This implementation makes no side-channel claim and should
not be treated as an authenticated-encryption mode.

## Script compatibility and standardness

The fragment uses legacy-compatible stack and arithmetic opcodes, but exceeds
the legacy 201-opcode execution limit. Tapscript is therefore the compatible
script type; bare script, P2SH, and P2WSH are not. The fragment alone does not
satisfy cleanstack because it intentionally returns 16 ciphertext nibbles. A
caller must compare or consume all 16 and leave one truthy item.

## Witness and hints

No hints. The plaintext is 16 canonical nibbles with nibble 0 (the most
significant nibble) on top and nibble 15 deepest. The key is public in the
locking script. `key` is a `u128` whose upper 64 bits are PRINCEv2 `k0` and
lower 64 bits are `k1`; the adapter handles the optimized engine's internal
nibble order.
