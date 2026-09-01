# Four-way mixed-hash integer path

Authenticates base-4 digits through fixed-length SHA-256/RIPEMD-160 schedules
and reconstructs a 1–31-bit non-negative Script integer.

- **Position:** reduces verifier size, serialized opening size, and peak stack
  occupancy versus the measured binary mixed-hash path.
- **Construction:** each most-significant-first digit selects a two-hash
  codeword: `0 -> SS`, `1 -> SR`, `2 -> RS`, or `3 -> RR`, where `S` is
  SHA-256 and `R` is RIPEMD-160. A final RIPEMD-160 yields 20 bytes.
- **Evidence:** `locally-reproduced` with all-codeword, integer-boundary,
  malformed-encoding, wrong-opening, wrong-preimage, selector-range, odd-width,
  and strict-stack tests. Execution is `research-unlimited` because the metric
  witness executor disables its stack-limit check.
- **Representative result:** 31 bits use a 453-byte fragment, 61-byte
  serialized witness, and 19 stack items. The binary path uses 520 bytes, 78
  witness bytes, and 34 items under the same metric boundary.
- **Security:** hiding requires a secret high-entropy preimage. The final
  160-bit digest caps generic collision resistance at 80 bits, and binding
  additionally relies on the non-standard mixed-hash schedule.
- **Structural constraint:** all digit codewords have exactly two hashes. A
  direct mapping to the four single opcodes SHA256/HASH256/RIPEMD160/HASH160 is
  deterministically ambiguous and must not be substituted.
- **Deployment:** tapscript-only. The compact selector-range proof relies on
  consensus `MINIMALIF` and is unsafe under legacy/P2WSH consensus semantics
  without explicit range checks. Bitcoin Core consensus and policy validation
  have not been performed.

See the [implementation README](../../src/commitments/README.md), the
[commitment comparison](../comparisons/commitments.md), negative result
`NR-012`, and catalog record `commitment/four-way-hash-path-integer`.
