# Block ciphers

| Construction | Block/key | Script bytes | Witness bytes | Peak items |
| --- | --- | ---: | ---: | ---: |
| PRINCEv2 u4 | 64-bit block / embedded 128-bit key | 6,136 | 17–33 | 633 |
| AES-128 u4 | 128-bit block / embedded 128-bit key | 25,388 | 33–65 | 908 |

PRINCEv2 is smaller locally but is not a semantic replacement for AES-128.

The PRINCE row uses the zero key, includes table setup and cleanup, and excludes
input pushes/output checks. Per-key fused-row selection changes both bytes
and stack use; the published nonzero key is 6,292 bytes with a 685-item peak.
Both PRINCE configurations have zero hints and 16 plaintext data items. Strict
tapscript fragment execution is recorded; these fragment rows remain
`unclassified`.
Protocol requirements and cryptographic assumptions dominate this choice.

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
