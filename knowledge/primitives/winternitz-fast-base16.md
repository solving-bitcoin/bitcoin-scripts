# Fast base-16 Winternitz signatures

Implements a new fixed-message-length HASH160 Winternitz path with a consuming
one-time key API, domain-separated chain starts, canonical host-side message
encoding, a locking-size-oriented lookup verifier, a strict-chain-encoding
lookup verifier, a speed-oriented exact-hash verifier, and terminal variants.

- **Question:** for 32-byte messages and 20-byte public endpoints fixed in the
  locking fragment, can tapscript verification execute exactly the required
  chain suffix while keeping script and stack costs close to the existing
  list-pick implementation?
- **Comparison objective:** first minimize locking-script bytes; then separately
  report serialized witness bytes, executed HASH160 calls, static non-push
  opcodes, combined stack peak, and any accepted-relation tradeoff.
- **Position:** the exact profile shares 8/4/2/1 conditional blocks and executes
  `15 - d` hashes for digit `d`. The lookup profile executes 15 hashes below 8
  and seven otherwise, trading latency for 402 fewer locking bytes.
- **Representative result:** `FastWots32` size recovery is 4,640 bytes, or 4,575
  bytes when the message is consumed, with a 1,477-byte deterministic zero-
  message witness and a 143-item measured peak. Strict-chain lookup is 5,050
  bytes and exact-hash recovery is 5,452 bytes.
- **Legacy comparison:** size recovery is 268 bytes (5.5%) smaller than the
  4,908-byte legacy list-pick path and rejects numeric digits above 15 instead
  of clamping them. It omits explicit chain-item length checks; strict-chain
  lookup retains those checks. The exact path remains 126 bytes smaller than
  the 5,578-byte legacy binary verifier at the same exact-chain objective.
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
- **Size-profile boundary:** signer-produced chain nodes are 20 bytes, but the
  size verifier also accepts arbitrary-length HASH160 preimages for digits below
  15. Digit 15 compares directly with the 20-byte endpoint. This changes raw
  signature canonicality, not the strict `0..=15` numeric digit relation.
- **Stack contract:** the recovery profiles consume 134 witness items and leave
  64 message nibbles in high/low byte order. The terminal profile consumes the
  message and checksum and requires a caller-supplied final predicate.

See the [implementation README](../../src/signatures/winternitz/README.md),
[legacy Winternitz page](winternitz-base16.md),
[signature comparison](../comparisons/signatures.md), RFC 8391 source
`rfc-8391`, BIP 342 source `bip-342`, and catalog record
`signature/winternitz-fast-base16`.
