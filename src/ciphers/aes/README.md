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
- `aes128_shift_rows` exposes the zero-memory state permutation used inside the
  fused encryptor. It moves 32 nibble items and does not validate their range.
- `aes128_add_round_key` exposes one checked keyed-XOR boundary with the same
  32-nibble state layout; its 128-bit key is embedded at generation time.
- `aes128_sub_bytes` applies the checked AES S-box to one 128-bit block without
  a key or ShiftRows/MixColumns.

- `aes128_mix_columns` applies the checked AES linear MixColumns layer without a key or the other round layers.

## Script metrics

The locking-fragment metric excludes plaintext pushes and output comparison.
Its exact size is mildly key-dependent because zero XOR constants are omitted
and Script-number push widths vary.

| Fragment | Size/depth |
| --- | ---: |
| `aes128_encrypt([0; 16])` | <!-- metric:aes128_encrypt -->25388<!-- /metric:aes128_encrypt --> bytes |
| `aes128_encrypt(00..0f)` | <!-- metric:aes128_fips_encrypt -->25449<!-- /metric:aes128_fips_encrypt --> bytes |
| `aes128_encrypt([0xff; 16])` | <!-- metric:aes128_all_ones_encrypt -->25520<!-- /metric:aes128_all_ones_encrypt --> bytes |
| Plaintext witness, all-zero block | <!-- metric:aes128_witness_min -->33<!-- /metric:aes128_witness_min --> bytes |
| Plaintext witness, no zero nibbles | <!-- metric:aes128_witness_max -->65<!-- /metric:aes128_witness_max --> bytes |
| Maximum combined main/alt-stack depth | <!-- metric:aes128_stack -->908<!-- /metric:aes128_stack --> items |
| `aes128_shift_rows()` | <!-- metric:aes128_shift_rows -->117<!-- /metric:aes128_shift_rows --> bytes |
| ShiftRows witness, 32 data items | <!-- metric:aes128_shift_rows_witness -->65<!-- /metric:aes128_shift_rows_witness --> bytes |
| ShiftRows maximum combined depth | <!-- metric:aes128_shift_rows_stack -->33<!-- /metric:aes128_shift_rows_stack --> items; <!-- metric:aes128_shift_rows_opcodes -->88<!-- /metric:aes128_shift_rows_opcodes --> static non-push opcodes |
| `aes128_add_round_key([0; 16])` | <!-- metric:aes128_add_round_key -->1874<!-- /metric:aes128_add_round_key --> bytes |
| AddRoundKey witness, 32 canonical nibbles | <!-- metric:aes128_add_round_key_witness -->65<!-- /metric:aes128_add_round_key_witness --> bytes |
| AddRoundKey maximum combined depth | <!-- metric:aes128_add_round_key_stack -->899<!-- /metric:aes128_add_round_key_stack --> items |
| AddRoundKey static non-push opcodes | <!-- metric:aes128_add_round_key_opcodes -->887<!-- /metric:aes128_add_round_key_opcodes --> |
| `aes128_sub_bytes` | <!-- metric:aes128_sub_bytes -->2147<!-- /metric:aes128_sub_bytes --> bytes |
| SubBytes witness, canonical 7 nibbles | <!-- metric:aes128_sub_bytes_witness -->65<!-- /metric:aes128_sub_bytes_witness --> bytes |
| SubBytes witness, canonical 15 nibbles | <!-- metric:aes128_sub_bytes_witness_max -->65<!-- /metric:aes128_sub_bytes_witness_max --> bytes |
| SubBytes maximum combined main/alt-stack depth | <!-- metric:aes128_sub_bytes_stack -->897<!-- /metric:aes128_sub_bytes_stack --> items |
| SubBytes static non-push opcodes | <!-- metric:aes128_sub_bytes_opcodes -->1031<!-- /metric:aes128_sub_bytes_opcodes --> |
| SubBytes shared lookup items | <!-- metric:aes128_sub_bytes_table_items -->832<!-- /metric:aes128_sub_bytes_table_items --> |
| `aes128_mix_columns` | <!-- metric:aes128_mix_columns -->3738<!-- /metric:aes128_mix_columns --> bytes |
| MixColumns witness, canonical 7 nibbles | <!-- metric:aes128_mix_columns_witness -->65<!-- /metric:aes128_mix_columns_witness --> bytes |
| MixColumns witness, canonical 15 nibbles | <!-- metric:aes128_mix_columns_witness_max -->65<!-- /metric:aes128_mix_columns_witness_max --> bytes |
| MixColumns maximum combined main/alt-stack depth | <!-- metric:aes128_mix_columns_stack -->908<!-- /metric:aes128_mix_columns_stack --> items |
| MixColumns static non-push opcodes | <!-- metric:aes128_mix_columns_opcodes -->1959<!-- /metric:aes128_mix_columns_opcodes --> |
| MixColumns shared lookup items | <!-- metric:aes128_mix_columns_table_items -->832<!-- /metric:aes128_mix_columns_table_items --> |

The embedded key changes constant-push widths and fused table choices. The
three deterministic profiles above span 25,388 bytes for the zero key, 25,449
bytes for the FIPS key `00..0f`, and 25,520 bytes for the all-ones key; all
three execute at a 908-item combined peak. These are reproducible key profiles,
not an exhaustive proof of the maximum possible key-specific serialization.

The generator uses one 832-item shared lookup memory. It fuses the initial
AddRoundKey into the first SubBytes pass, SubBytes with ShiftRows, and
MixColumns with each following AddRoundKey. Each column's `xtime` values are
computed once and reused by adjacent output rows. The most frequently accessed
tables occupy the shallowest stack positions.

`aes128_shift_rows()` is the extracted stack-only permutation: it uses the
existing column-major nibble order, moves no lookup memory, and preserves raw
item encodings byte-for-byte. Its fragment boundary excludes input pushes,
output checks, transaction context, and any nibble-range validation; callers
must establish canonical `0..=15` nibbles when the state is witness-backed.
It measures <!-- metric:aes128_shift_rows -->117<!-- /metric:aes128_shift_rows -->
locking bytes, a <!-- metric:aes128_shift_rows_witness -->65<!-- /metric:aes128_shift_rows_witness -->-byte
32-item witness, and <!-- metric:aes128_shift_rows_stack -->33<!-- /metric:aes128_shift_rows_stack -->
combined stack items with no auxiliary hints.

`aes128_add_round_key` uses the same 832-item memory and returns the state after
XORing each canonical nibble with a generation-time round key. It is a
composition boundary, not a smaller AES encryption path: the full encryptor
continues to fuse AddRoundKey into SubBytes/ShiftRows and MixColumns to avoid
repeating setup and cleanup.

The standalone `aes128_sub_bytes` fragment reuses the same 832-item memory,
checks every witness nibble for canonical `0..=15` encoding, and removes the
temporary table before returning. It returns the 32 substituted nibbles in
state order and requires no hints.

Tests execute the FIPS-197 known-answer vector and the all-zero and all-ones
vectors, compare the native reference against three published vectors, and pin
the deterministic key-profile sizes and maximum stack depth. SubBytes and MixColumns tests cover boundary/random vectors,
non-canonical and out-of-range nibbles, and preservation of surrounding stack
state.

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
intentionally returns 32 state nibbles. A caller must compare or consume
all outputs and leave exactly one truthy stack item. Standalone AddRoundKey
SubBytes, and MixColumns validate canonical integer encoding and the `0..=15` range for
every input nibble; `aes128_encrypt` retains its caller-validated contract.

## Witness and hints

No hints are required. These fragments consume 32 witness nibbles, with nibble 0
(byte 0's high nibble) on top and nibble 31 (byte 15's low nibble) deepest.
`aes128_encrypt` returns ciphertext in the same order and embeds its key in the
script; `aes128_sub_bytes` and `aes128_mix_columns` return transformed states without keys.
