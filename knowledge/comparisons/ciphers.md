# Block ciphers

| Construction | Block/key | Script bytes | Witness bytes | Peak items |
| --- | --- | ---: | ---: | ---: |
| PRINCEv2 u4 | 64-bit block / embedded 128-bit key | 6,136 | 17–33 | 633 |
| AES-128 u4 | 128-bit block / embedded 128-bit key | 25,388 | 33–65 | 908 |

PRINCEv2 is smaller locally but is not a semantic replacement for AES-128.

The PRINCE row uses the zero key, includes table setup and cleanup, and excludes
input pushes/output checks. Per-key fused-row selection changes both bytes
and stack use; the published nonzero key is 6,292 bytes with a 685-item peak.
Both have zero hints and 16 plaintext data items. Strict tapscript fixture
execution is recorded; complete transaction/relay-policy validation is open.
Protocol requirements and cryptographic assumptions dominate this choice.
