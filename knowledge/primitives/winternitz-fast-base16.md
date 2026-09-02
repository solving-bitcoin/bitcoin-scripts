# Fast base-16 Winternitz signatures

Implements a new fixed-message-length HASH160 Winternitz path with a consuming
one-time key API, domain-separated chain starts, canonical host-side message
encoding, a speed-oriented exact-hash verifier, a smaller eight-value lookup
verifier, and a checksum-fused terminal verifier.

- **Question:** for 32-byte messages and 20-byte public endpoints fixed in the
  locking fragment, can tapscript verification execute exactly the required
  chain suffix while keeping script and stack costs close to the existing
  list-pick implementation?
- **Comparison objective:** first minimize executed HASH160 calls; then report
  locking bytes, serialized witness bytes, static non-push opcodes, and combined
  stack peak without treating any one ordering as universal.
- **Position:** the exact profile shares 8/4/2/1 conditional blocks and executes
  `15 - d` hashes for digit `d`. The lookup profile executes 15 hashes below 8
  and seven otherwise, trading latency for 402 fewer locking bytes.
- **Representative result:** `FastWots32` recovery is 5,452 bytes exact or
  5,050 bytes lookup, with a 1,477-byte deterministic zero-message witness and
  137/143-item measured peaks. On the fixed balanced vector the profiles execute
  510 and 741 HASH160 calls respectively.
- **Legacy comparison:** the existing binary-search verifier is 5,578 bytes, so
  the new exact recovery path is 126 bytes smaller at the same exact-chain
  objective. The existing 4,908-byte list-pick path is still 142 bytes smaller
  than the new strict lookup path, but it clamps digits above 15 instead of
  rejecting their raw numeric value.
- **Evidence:** `locally-reproduced` by host key/signature generation, two Script
  verifier strategies, a separately generated fixed Python HASH160 vector,
  malformed-input tests, checksum mutation with recomputed valid chains, and
  checked metric snapshots.
- **Execution:** `research-unlimited`. Metrics use the local tapscript executor
  through `execute_raw_script_with_inputs`, which disables the stack limit.
  Separate local tests execute the same compositions with the strict-stack
  helper below 1,000 items, but there is no pinned Bitcoin Core transaction or
  policy reproduction.
- **Security boundary:** this is classic unkeyed HASH160-chain Winternitz, not
  WOTS+. RFC 8391's WOTS+ uses addressed keyed chain functions. Keys remain
  strictly one-time, raw in-range ScriptNum canonicality is a caller obligation,
  and durable prevention of seed reuse is outside the consuming Rust type.
- **Stack contract:** the recovery profiles consume 134 witness items and leave
  64 message nibbles in high/low byte order. The terminal profile consumes the
  message and checksum and requires a caller-supplied final predicate.

See the [implementation README](../../src/signatures/winternitz/README.md),
[legacy Winternitz page](winternitz-base16.md),
[signature comparison](../comparisons/signatures.md), RFC 8391 source
`rfc-8391`, BIP 342 source `bip-342`, and catalog record
`signature/winternitz-fast-base16`.
