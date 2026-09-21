# Windowed point locks fail the practical-setup requirement

The [windowed small-R experiment](../../research/pointlocks-2026-09-17/windowed-publication.md)
sizes to 39,396 vB for arbitrary 256-byte publication, but needs approximately
`2^63.138` SHA256 compression calls in expectation at its proposed parameters.
The user rejected this setup cost as impractical. The historical `2^64`
research ceiling is not an appropriate definition of acceptable setup cost.
This family is therefore rejected as a solution, not recommended for further
byte-level optimization.

The cheap, 59-byte-cap fixture remains useful execution evidence: 9,165 digest
trials, 40,656 vB, 840 extracted scalars, and exact recovery of the 256-byte
payload under Core policy and block validation. It demonstrates honest
execution, not extraction from every accepted witness. Neither its size guard
nor the 53-byte guard algebraically forces the nonce to be `+/-G/2`.

Increasing the permitted signature size reduces honest search but does not
preserve a proved extraction guarantee. Narrowing the hidden scalar offsets
at the 53-byte cap cannot remove the underlying short-s digest-search density.
Choosing the base after observing the digest changes the committed keys and
reintroduces the funding dependency. No practical repair of this family has
been established.

Evidence: `locally-reproduced` production-profile serialization and `inspected`
work estimates; production deployment remains `unclassified`. The separate
reduced-work fixture is `differentially-validated` and `policy-validated` at
its own parameters. Rejecting the setup cost does not invalidate those recorded
measurements or establish a universal impossibility result.

The practical, algebraic, no-ZKP sum-key baseline remains 185,146 vB. The
92,706-vB [compressed-payload experiment](../../research/pointlocks-2026-09-17/conditional-proof-compression.md)
supports 128 bytes and only helps the application if its actual proof format
can be compressed accordingly; that application integration is unimplemented.
It is not a solution for arbitrary future 256-byte payloads.

The remaining objective is practical setup, no setup ZKP, and less than
100,000 combined creation-and-spending vbytes, with a defensible extraction
guarantee. No construction meeting all these requirements is established here.
