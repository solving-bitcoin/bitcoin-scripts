# Mixed-hash integer path

Authenticates a bit path by selecting SHA-256 or RIPEMD-160 at each branch and
returns the reconstructed non-negative Script integer.

- **Position:** compact integer authentication with a simple witness, but an
  unconventional mixed-hash security assumption.
- **Evidence:** locally reproduced with canonical-bit, wrong-opening, and
  boundary tests.
- **Representative result:** 31 bits use a 520-byte fragment, 78-byte serialized
  witness, and 34 stack items.
- **Security:** hiding requires a secret high-entropy preimage; the final
  160-bit digest caps generic collision resistance at 80 bits.
- **Deployment:** wider variants exceed legacy opcode limits and are primarily
  tapscript research constructions.

See the [implementation README](../../src/commitments/README.md) and catalog
record `commitment/hash-path-integer`.
