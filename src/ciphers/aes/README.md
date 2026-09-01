# AES-128

Bitcoin Script implementation of AES-128 encryption for one 128-bit block with
a generation-time key.

## Parameters

- Block size: fixed at 128 bits, represented by 32 nibbles.
- Key size: fixed at 128 bits. `aes128_encrypt` takes a required `[u8; 16]`
  key and embeds its expanded round keys in the generated fragment; there is no
  default key. Metrics use the all-zero key.
- Encryption only. No public decryption or block-cipher mode is exposed.
- `aes128_expand_key`, `aes128_encrypt_ref`, and `bytes_to_nibbles` are provided
  for key expansion, native reference checks, and stack encoding.

## Script metrics

The locking-fragment metric excludes plaintext pushes and output comparison.
Its exact size is mildly key-dependent because zero XOR constants are omitted
and Script-number push widths vary.

| Fragment | Size/depth |
| --- | ---: |
| `aes128_encrypt([0; 16])` | <!-- metric:aes128_encrypt -->25515<!-- /metric:aes128_encrypt --> bytes |
| Plaintext witness, all-zero block | <!-- metric:aes128_witness_min -->33<!-- /metric:aes128_witness_min --> bytes |
| Plaintext witness, no zero nibbles | <!-- metric:aes128_witness_max -->65<!-- /metric:aes128_witness_max --> bytes |
| Maximum combined main/alt-stack depth | <!-- metric:aes128_stack -->908<!-- /metric:aes128_stack --> items |

The generator uses one 832-item shared lookup memory. It fuses the initial
AddRoundKey into the first SubBytes pass, SubBytes with ShiftRows, and
MixColumns with each following AddRoundKey. Each column's `xtime` values are
computed once and reused by adjacent output rows. The most frequently accessed
tables occupy the shallowest stack positions.

Tests execute the FIPS-197 known-answer vector and the all-zero vector, compare
the native reference against three published vectors, and pin the zero-key
size and maximum stack depth.

## Security

AES-128 has a 128-bit key and a 128-bit block. Its nominal exhaustive-key-search
security is 128 bits, while generic block collisions appear after roughly
`2^64` blocks. This primitive encrypts exactly one block and provides neither
authentication nor a mode of operation; callers must supply those properties.
The embedded key is public and this implementation makes no side-channel claim.

## Script compatibility and standardness

The fragment uses arithmetic and stack opcodes available in both legacy Script
and Tapscript, but its size and opcode count exceed the legacy limits. It is
therefore usable as Tapscript, not as bare script, P2SH, or P2WSH. Tapscript
removes the 10,000-byte script-size and 201-non-push-opcode limits while retaining
the 1,000-item combined-stack limit, which this implementation satisfies.

The fragment alone does not satisfy Tapscript's cleanstack rule because it
intentionally returns 32 ciphertext nibbles. A caller must compare or consume
all outputs and leave exactly one truthy stack item. Inputs must already be
canonical integers in `0..=15`; this fragment does not independently range-check
them.

## Witness and hints

No hints are required. The witness supplies 32 plaintext nibbles. Nibble 0
(byte 0's high nibble) is on top and nibble 31 (byte 15's low nibble) is
deepest. The generated fragment returns ciphertext in the same order. The key
is not part of the witness because it is embedded in the script.
