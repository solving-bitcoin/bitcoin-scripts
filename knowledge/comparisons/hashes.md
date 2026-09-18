# Hash constructions

Measured fragments exclude input pushes and output comparison.

| Construction | Configuration | Script bytes | Evidence | Principal limitation |
| --- | --- | ---: | --- | --- |
| BLAKE3 sparse direct u4 | 32-byte input | 59,534 | differentially-validated | Fixed length at generation time; at most 32 bytes |
| BLAKE3 sparse direct u4, low 128 bits | 32-byte input | 59,105 | differentially-validated | Fixed length at generation time; standard digest prefix only |
| BLAKE3 limb29 | 64-byte input | 72,293 | differentially-validated | Single 1,024-byte chunk only; includes table memory |
| SHA-1 u32 | 32-byte input | 205,558 | differentially-validated | Collision-broken compatibility hash |
| RIPEMD-160 u32 | 32-byte input | 240,223 | differentially-validated | 160-bit output |
| HASH160 SHA-256 → RIPEMD-160 | 32-byte input | 752,651 | differentially-validated | Large composed research fragment |
| HASH160 shared byte table | 32-byte input | 752,327 | differentially-validated | Saves 324 bytes by sharing the 256-item lookup |
| SHA-256 u4 | 32-byte input | 332,942 | differentially-validated | Large research fragment |
| SHA-256 u4 shared lookup | 80-byte input, two chunks | 736,595 | locally-reproduced | 905-item strict peak; 11-byte saving per extra chunk over table reload |
| SHA-256 u4 midstate | 64-byte prefix + 16-byte suffix | 332,830 | locally-reproduced | 32 nibble witness items (48-byte fixture, 65-byte maximum); 969-item peak; caller binds the state |
| SHA-256 u32 | 32-byte input | 512,428 | differentially-validated | Larger than local u4 variant |
| SHA-256 u32 midstate | 64-byte fixed prefix + 16-byte suffix | 530,686 | differentially-validated | 16 byte witness items (33-byte fixture, 49-byte maximum); caller must bind the supplied midstate |
| SHAKE256 byte | 32-byte input, 1,024-byte output | 15,927,814 | locally-reproduced | Raw output exceeds 1,000 items |
| SHAKE256 byte prefix | 32-byte input, 32-byte output | 2,000,127 | locally-reproduced | Strict stack-compatible locally; still a 2 MB fragment |
| SHAKE256 byte prefix | 32-byte input, 137-byte output | 3,989,612 | locally-reproduced | Rate-crossing prefix; 893-item strict peak |

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

The u4 midstate continuation is smaller than the corresponding u32 boundary
but carries twice as many suffix witness items and a higher measured stack peak
(969 versus 856); both require the caller to bind the supplied state to the
fixed prefix.

Every nontrivial row in the table exceeds the repository optimizer's 32 KiB
input cutoff and is unoptimized by those upstream passes. BLAKE3 still applies
its separately documented pinned peephole pass before the repository
compilation policy.

The prefix row is a distinct cost point, not a claim that the full XOF is
deployable: it only materializes the requested output blocks. Its 813-item
strict local peak stays below the 1,000-item limit for the representative
32-byte prefix, but Bitcoin Core and relay policy have not been run and the
2,000,127-byte fragment remains impractical as a standard script.
