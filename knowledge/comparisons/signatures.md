# One-time authentication

| Construction | Authenticated object | Script bytes | Witness bytes | Stack peak | Verification work / missing protocol work |
| --- | --- | ---: | ---: | ---: | --- |
| Lamport 2-bit | One value in 0..3 | 96 | 11 | not recorded | Reject rather than clamp invalid values |
| HORS-like n32/t8 | Explicit subset | 809 | 280 | not recorded | Message-to-index derivation |
| Legacy Wots32 list-pick | 32-byte message | 4,908 | 1,477 | not recorded | 15 hashes for digits below 8, seven otherwise; clamps above-range digits |
| FastWots32 bitwise | 32-byte message | 4,325 | 1,680–1,942 | 334 | Canonical bits; exact suffix hashes; relaxed chain-item length; recovers message |
| FastWots32 bitwise + clear | 32-byte message | 4,208 | 1,938–1,942 | 334 | Branch-fused checksum; consumes message; terminal predicate excluded |
| FastWots32 size lookup | 32-byte message | 4,605 | 1,476–1,542 | 141 | Strict numeric digits; relaxed raw chain-item length; recovers message |
| FastWots32 size lookup + clear | 32-byte message | 4,543 | 1,476–1,542 | 141 | Same chain relation; consumes message; terminal predicate excluded |
| FastWots32 exact | 32-byte message | 5,342 | 1,476–1,542 | 137 | Exact suffix hashes; 498 on the balanced vector |
| FastWots32 strict lookup | 32-byte message | 5,013 | 1,476–1,542 | 143 | 729 hashes on the balanced vector; explicit range check |
| FastWots32 exact + clear | 32-byte message | 5,408 | 1,476–1,542 | 137 | Fused checksum accumulator; terminal predicate excluded |

Locking figures are `fragment-only`; witness figures are full serialized item
vectors. Fast stack peaks are from complete local compositions, but the metric
executor disables the consensus stack check and therefore remains
`research-unlimited`. Separate strict local tests stay below 1,000 items. The
balanced-vector message and all other boundaries are recorded in the
[implementation README](../../src/signatures/winternitz/README.md).

There is no universal winner. The Fast bitwise recovery fragment is 583 bytes
(11.9%) smaller than the legacy list-pick fragment; its terminal form is 700
bytes (14.3%) smaller. Canonical `MINIMALIF` bits drive complementary hash
blocks, a `[8,8,16]` checksum covers the 0–960 range, and recovery rebuilds the
same 64 nibbles. The gain costs 333 witness items and a larger serialized
witness. Like the numeric size profile, it omits an explicit 20-byte check on
each chain item: a maximum digit equality forces 20 bytes, while smaller digits
admit an arbitrary-length HASH160 preimage before the first hash. The
strict-encoding lookup profile retains explicit 20-byte checks at 5,013 bytes.

The legacy and Fast rows are not wire-compatible: chain-start derivation,
message digit order, checksum digit order, and witness pair order differ. All
constructions are one-time. Comparing them as interchangeable signatures also
requires fixing key/public commitment cost, forgery target, durable reuse
policy, raw ScriptNum canonicality, whether the recovered value must remain on
the stack, and whether tapscript `MINIMALIF` is available.
