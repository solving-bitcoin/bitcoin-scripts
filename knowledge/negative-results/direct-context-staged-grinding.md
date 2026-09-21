# Direct repeated keys permit staged sighash searches

The [direct-key variant](../../research/pointlocks-2026-09-17/direct-context.md)
fits six separated short-signature checks per label into a Core-validated
98,706-vB honest 256-byte publication. It removes the anchor and uses an
explicitly clamped table-index mapping. Point-lock-only generation and public
checking take 46.59 ms median, with a 130.23-ms first sample.

This is not a demonstrated cryptographic improvement. Native BIP143 digest
tests show that ACP|NONE, ACP|SINGLE, SINGLE and ALL contexts can be addressed
in stages: change own sequence, corresponding output, another input outpoint,
then a noncorresponding output. Later changes preserve earlier groups under
a static key. A malicious owner can sign authorization afterward. The anchor's
ALL-dependent recovered key prevented this particular preservation.

A scoped heuristic model for groups 2,1,1,2 estimates a strategy with about
2^61.91 nonce point trials and 2^61.69 scalar checks, plus native hashing and
ancestor work. No rare search or non-extracting native spend was run. These
estimates are not lower bounds or generic impossibility theorems. The actual
hash dependencies invalidate treating all six checks as one joint search.

Evidence: **differentially-validated** for honest Core transactions and seven
negative controls; **locally-reproduced** for native hash dependencies;
**inspected** for the staged-search model. Honest transactions are
**policy-validated**; general extraction and the protocol are **unclassified**.
