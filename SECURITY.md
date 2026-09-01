# Security status

This is research software. It contains experimental, non-standard,
research-unlimited, compatibility-only, and explicitly consensus-incompatible
constructions. It has not been audited as a library for protecting funds.

Catalog evidence levels describe reproduction confidence; they are not security
certifications. In particular:

- local `bitcoin-scriptexec` success is not Bitcoin consensus authority;
- witness hints are safe only when every required relation and range is bound;
- one-time authentication keys must never be reused;
- curve points require protocol-appropriate validity and subgroup handling;
- large fragments may exceed consensus, validation, transaction, or relay
  policy limits even when their opcodes are available.

For a suspected vulnerability, prefer a private GitHub security advisory for
`solving-bitcoin/bitcoin-scripts` rather than disclosing an exploitable issue in
a public ticket. Include the affected construction, threat model, minimal
reproduction, execution mode, and whether any deployed funds are known to rely
on it.
