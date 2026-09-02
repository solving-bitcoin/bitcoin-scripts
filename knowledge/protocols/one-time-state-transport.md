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

The Fast Winternitz path makes the transport boundary more explicit. Numeric
profiles use 134 digit/chain items; the 4,325-byte bitwise recovery profile uses
333 items, peaks at 334, and returns the same 64 high/low nibbles. Its canonical
bits and the exact verifier depend on tapscript `MINIMALIF`. The 4,208-byte
terminal profile clears the message when transport is unnecessary. The
consuming Rust key prevents ordinary same-process reuse only. Transaction-graph
state, crash rollback, restored seeds, distributed signers, and raw ScriptNum
canonicality remain protocol obligations. Size profiles relax raw chain-item
length; protocols requiring exactly 20-byte signature nodes should use the
5,013-byte strict-chain profile. Fast and legacy witnesses are not
wire-compatible.

Protocol evaluation must count public commitment placement, witness
serialization, recovered-state cleanup, and the transaction graph that prevents
key reuse.
