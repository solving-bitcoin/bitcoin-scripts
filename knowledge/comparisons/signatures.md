# One-time authentication

| Construction | Authenticated object | Script bytes | Witness bytes | Stack peak | Verification work / missing protocol work |
| --- | --- | ---: | ---: | ---: | --- |
| Lamport 2-bit | One value in 0..3 | 96 | 11 | not recorded | Reject rather than clamp invalid values |
| HORS-like n32/t8 | Explicit subset | 833 | 280 | not recorded | Message-to-index derivation |
| Legacy Wots32 list-pick | 32-byte message | 4,908 | 1,477 | not recorded | 15 hashes for digits below 8, seven otherwise; clamps above-range digits |
| FastWots32 size lookup | 32-byte message | 4,640 | 1,477–1,542 | 143 | Strict numeric digits; relaxed raw chain-item length; recovers message |
| FastWots32 size lookup + clear | 32-byte message | 4,575 | 1,477–1,542 | 143 | Same chain relation; consumes message; terminal predicate excluded |
| FastWots32 exact | 32-byte message | 5,452 | 1,477–1,542 | 137 | Exactly `15-d` hashes; 510 on the balanced vector |
| FastWots32 strict lookup | 32-byte message | 5,050 | 1,477–1,542 | 143 | 741 hashes on the balanced vector; explicit range check |
| FastWots32 exact + clear | 32-byte message | 5,515 | 1,477–1,542 | 137 | Fused checksum accumulator; terminal predicate excluded |

Locking figures are `fragment-only`; witness figures are full serialized item
vectors. Fast stack peaks are from complete local compositions, but the metric
executor disables the consensus stack check and therefore remains
`research-unlimited`. Separate strict local tests stay below 1,000 items. The
balanced-vector message and all other boundaries are recorded in the
[implementation README](../../src/signatures/winternitz/README.md).

There is no universal winner. The Fast size recovery fragment is 268 bytes
(5.5%) smaller than the legacy list-pick fragment and rejects numeric digits
above 15 instead of clamping them. It obtains that reduction through witness
pair/checksum ordering and by omitting an explicit 20-byte check on each chain
item: digit 15 equality still forces 20 bytes, while smaller digits admit an
arbitrary-length HASH160 preimage before the first hash. The strict-encoding
lookup profile retains explicit 20-byte checks at 5,050 bytes. The Fast exact
profile spends another 402 bytes and reduces balanced-vector HASH160 calls by
31.2%. Its 5,452-byte script is 126 bytes smaller than the legacy 5,578-byte
binary-search verifier, which targets the same exact chain suffix.

The legacy and Fast rows are not wire-compatible: chain-start derivation,
message digit order, checksum digit order, and witness pair order differ. All
constructions are one-time. Comparing them as interchangeable signatures also
requires fixing key/public commitment cost, forgery target, durable reuse
policy, raw ScriptNum canonicality, whether the recovered value must remain on
the stack, and whether tapscript `MINIMALIF` is available.
