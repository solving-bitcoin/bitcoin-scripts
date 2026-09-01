# One-time authentication

| Construction | Authenticated object | Script bytes | Witness bytes | Missing protocol work |
| --- | --- | ---: | ---: | --- |
| Lamport 2-bit | One value in 0..3 | 96 | 11 | Reject rather than clamp invalid values |
| HORS-like n32/t8 | Explicit subset | 833 | 280 | Message-to-index derivation |
| Wots32 base16 | 32-byte message | 4,908 | 1,477 | Key lifecycle and composition policy |

All are one-time. Comparing them as interchangeable signatures requires fixing
message semantics, key/public commitment cost, forgery target, reuse policy,
and whether the recovered value must remain on the stack.
