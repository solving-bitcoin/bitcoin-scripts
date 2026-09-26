# Block ciphers

| Construction | Block/key | Script bytes | Witness bytes | Peak items |
| --- | --- | ---: | ---: | ---: |
| PRINCEv2 u4 | 64-bit block / embedded 128-bit key | 6,136 | 17–33 | 633 |
| AES-128 u4 | 128-bit block / embedded 128-bit key | 25,388 zero-key; 25,449 FIPS; 25,520 all-ones | 33–65 | 908 |
| AES-128 ShiftRows | 32-nibble state permutation | <!-- metric:aes128_shift_rows -->117<!-- /metric:aes128_shift_rows --> | <!-- metric:aes128_shift_rows_witness -->65<!-- /metric:aes128_shift_rows_witness -->; 32 data items | <!-- metric:aes128_shift_rows_stack -->33<!-- /metric:aes128_shift_rows_stack --> items |
| Checked AES-128 AddRoundKey | 32 checked u4 state nibbles / embedded 128-bit key | <!-- metric:aes128_add_round_key -->1874<!-- /metric:aes128_add_round_key --> | <!-- metric:aes128_add_round_key_witness -->65<!-- /metric:aes128_add_round_key_witness --> | <!-- metric:aes128_add_round_key_stack -->899<!-- /metric:aes128_add_round_key_stack --> |
| Checked AES-128 SubBytes | 128-bit state / no key | 2,147 | 65 | 897 |
| Checked AES-128 MixColumns | 128-bit state / no key | 3,738 | 65 | 908 |

PRINCEv2 is smaller locally but is not a semantic replacement for AES-128.
The ShiftRows row is a reusable stack-permutation boundary, not a cipher or
security claim; its 32 witness items and raw-item preservation are measured
without the full AES lookup memory.

Checked SubBytes is a reusable public S-box layer, not a block-cipher
replacement: it omits key addition, ShiftRows, and MixColumns. Its row includes
the checked 32-nibble boundary, shared lookup setup, and cleanup, and excludes
input pushes and output comparison.

Checked MixColumns is a reusable public linear layer, not a block-cipher
replacement: it omits SubBytes, ShiftRows, and key addition. Its row includes
the checked 32-nibble boundary, shared lookup setup, and cleanup, and excludes
input pushes and output comparison.

The PRINCE row uses the zero key, includes table setup and cleanup, and excludes
input pushes/output checks. Per-key fused-row selection changes both bytes
and stack use; the published nonzero key is 6,292 bytes with a 685-item peak.
Both PRINCE configurations have zero hints and 16 plaintext data items. Strict
tapscript fragment execution is recorded; these fragment rows remain
`unclassified`.
Protocol requirements and cryptographic assumptions dominate this choice.

AES sizes are key-dependent because round keys are embedded and the generator
fuses constant-specific table paths. The three reported keys are deterministic
profiles, not a universal size maximum; their equal 908-item peaks show that
the measured variation is in serialization rather than the shared live-memory
boundary.

The separate `prince_verify` boundary includes exact input count, canonical
nibble validation, ciphertext comparisons and a clean truthy result:

| Checked PRINCE key / plaintext | Leaf bytes | Complete witness bytes | Peak items | Transaction weight |
| --- | ---: | ---: | ---: | ---: |
| Zero / zero | 6,426 | 6,480 | 633 | 6,858 WU |
| Zero / all-ones | 6,426 | 6,496 | 633 | 6,874 WU |
| Published / published | 6,582 | 6,651 | 685 | 7,029 WU |

All three exact spends are `differentially-validated` and `policy-validated`
against pinned Core v30.3. Each has 16 simultaneous entry data items, zero hints,
and 18 complete witness items including leaf and control block. These complete
leaf costs have a different boundary from the fragment comparison above. See
[the experiment](../prince-core-validation.md) for parameters and 17 rejecting
controls. No checked AES leaf was measured here.
