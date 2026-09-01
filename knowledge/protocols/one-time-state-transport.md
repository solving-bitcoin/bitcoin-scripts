# One-time authenticated state transport

BitVM-style protocols may authenticate intermediate state with one-time hash
constructions so a later script can recover and check individual digits.

## Dependency map

```text
State value
├── digitization (bit, nibble, byte, limb, or field coefficient)
├── message/domain encoding
├── one-time key generation and public commitment
├── witness signature/opening
├── Script verification and recovered value layout
└── enforced key lifecycle across transaction graph
```

Lamport 2-bit, HORS-like subsets, and base-16 Winternitz solve different parts
of this problem. The HORS module does not derive indices from a message. The
Lamport helper authenticates only two bits. Winternitz provides typed message
APIs but requires strict one-time key management and can make state transport
witness-heavy.

Protocol evaluation must count public commitment placement, witness
serialization, recovered-state cleanup, and the transaction graph that prevents
key reuse.
