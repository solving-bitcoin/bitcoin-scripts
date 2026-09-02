# Hash constructions

Measured fragments exclude input pushes and output comparison.

| Construction | Configuration | Script bytes | Evidence | Principal limitation |
| --- | --- | ---: | --- | --- |
| BLAKE3 limb29 | 64-byte input | 76,481 | Differentially validated | Single 1,024-byte chunk only; includes table memory |
| SHA-1 u32 | 32-byte input | 209,726 | Differentially validated | Collision-broken compatibility hash |
| RIPEMD-160 u32 | 32-byte input | 244,063 | Differentially validated | 160-bit output |
| SHA-256 u4 | 32-byte input | 332,942 | Differentially validated | Large research fragment |
| SHA-256 u32 | 32-byte input | 512,428 | Differentially validated | Larger than local u4 variant |
| SHAKE256 byte | 1,024-byte output | unmeasured | Locally implemented | Raw output exceeds 1,000 items |

BLAKE3's row is not directly comparable with the 32-byte hash rows without
fixing message length and full semantics. For protocol selection, include
representation conversion, digest comparison, and any state-compression role.
Its checked generator applies the pinned peephole optimizer to a fixed point;
the row is `fragment-with-memory` because it owns full lookup-table setup and
cleanup. Its local differential/peak executor disables the stack-limit check,
so this result remains `research-unlimited` rather than consensus-validated.
