# BLAKE3 XOF output boundary

The local BLAKE3 generators implement the unkeyed 32-byte digest only. They do
not expose the root output-block counter needed to continue the BLAKE3 XOF
stream. The independent `blake3` crate produces 64 bytes for the same 32-byte
message, while the local API fixes the output contract at 32 bytes.

The reproducible probe is:

```sh
cargo run --locked --example blake3_xof_boundary
```

It records the 64-byte reference XOF request and the current 32-byte local
contract. On the pinned local generator, the 32-byte message profile is 65,167
policy-produced script bytes. This result does not claim that a 64-byte
extension is impossible.
Adding XOF output requires pricing the additional root-output compression,
output routing, cleanup, and stack coexistence under a stated output length.

Evidence: `locally-reproduced`; deployment: `research-unlimited` for the
existing fragment.
