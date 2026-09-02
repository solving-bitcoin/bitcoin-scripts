# Hash constructions

Measured fragments exclude input pushes and output comparison.

| Construction | Configuration | Script bytes | Evidence | Principal limitation |
| --- | --- | ---: | --- | --- |
| BLAKE3 sparse direct u4 | 32-byte input | 59,529 | differentially-validated | Fixed length at generation time; at most 32 bytes |
| BLAKE3 limb29 | 64-byte input | 72,293 | differentially-validated | Single 1,024-byte chunk only; includes table memory |
| SHA-1 u32 | 32-byte input | 209,726 | differentially-validated | Collision-broken compatibility hash |
| RIPEMD-160 u32 | 32-byte input | 244,063 | differentially-validated | 160-bit output |
| SHA-256 u4 | 32-byte input | 332,942 | differentially-validated | Large research fragment |
| SHA-256 u32 | 32-byte input | 512,428 | differentially-validated | Larger than local u4 variant |
| SHAKE256 byte | 32-byte input, 1,024-byte output | 15,927,814 | locally-reproduced | Raw output exceeds 1,000 items |

BLAKE3's 64-byte row is not directly comparable with the 32-byte hash rows
without fixing message length and full semantics. The short direct-u4 row does
use a 32-byte input, but its 64-item input representation differs from each
other backend. For protocol selection, include
representation conversion, digest comparison, and any state-compression role.
Its checked generator applies the pinned peephole optimizer to a fixed point;
the row is `fragment-with-memory` because it owns full lookup-table setup and
cleanup. The short-profile executor enforces the 1,000-item local limit, but it
is not a pinned Bitcoin Core consensus run, so the result remains
`research-unlimited` rather than consensus-validated.

Every nontrivial row in the table exceeds the repository optimizer's 32 KiB
input cutoff and is unoptimized by those upstream passes. BLAKE3 still applies
its separately documented pinned peephole pass before the repository
compilation policy.
