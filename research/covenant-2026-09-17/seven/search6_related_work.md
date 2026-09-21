# Search 6: ColliderScript, ColliderVM, Binohash, and QSB

Date: 2026-09-17. Question: can these constructions supply an existing-opcode,
complete exact-output covenant below `2^64` honest total work, including setup,
when the creator retains every key, preimage, and search result and can prepare
alternatives before funding? **No complete candidate was found in this bounded
review.** This is a scoped construction audit, not an impossibility result.

Primary-source claims are `reported`; the combination audit below is
`inspected` / `unclassified`. No new Script was executed. No byte, opcode,
witness, hint-item, or stack-peak measurement is claimed. No field tests ran.

## Names and source versions

- **ColliderScript:** ePrint 2024/1802, revision **2024-11-15**. The archive
  still identifies this as its last revision. It bridges big and small Script
  through 160-bit collisions; its reported spend cost is about `2^86` hash
  queries, with additional preprocessing. Its short-input security assumption
  must not be replaced by a generic claim that SHA-1 has 80-bit collision
  security. [Paper and version history](https://eprint.iacr.org/2024/1802).
- **ColliderVM:** ePrint 2025/591, revision **2025-04-10**, still the archive's
  last revision. It separates transaction-flow enforcement through presigning
  from data consistency through collision commitments. Section 2.1 footnotes
  5 and 8 explicitly require signer key deletion; footnote 10 distinguishes
  logic persistence from data persistence. Thus its published protocol does
  not satisfy the retained-state setup model. This says nothing against the
  independent usefulness of its commitment and decomposition techniques.
  [Paper and version history](https://eprint.iacr.org/2025/591).
- **Binohash:** the 33-page *Transaction Introspection Without Softforks*
  document provides a readable subset digest. Its central bridge application
  checks transaction properties in BitVM; section 7.1 delegates proper sighash
  mode checks to that verifier. Appendix D merges dummy signatures and HORS
  commitments through polyglot digests, with reported preparation of about
  `2^53.5` hashes. This is useful budget optimization, not a standalone
  exact-output predicate. [Paper](https://robinlinus.com/binohash.pdf).
- **QSB:** Avihu Mordechai Levy's *Quantum-Safe Bitcoin Transactions Without
  Softforks*, source pinned to commit
  `2c9172051d5c150ef0a994ca6b988a08a3ef9e85`. It substitutes a hash-to-DER puzzle
  for signature-length work and uses a hardcoded `SIGHASH_ALL` signature.
  Its authorization layer remains HORS. Searches for the literal combination
  “PQB” and “Binohash” did not identify another primary construction; **QSB is
  the likely intended work, not a proven synonym for PQB**.
  [Pinned source](https://raw.githubusercontent.com/avihu28/Quantum-Safe-Bitcoin-Transactions/2c9172051d5c150ef0a994ca6b988a08a3ef9e85/paper/QSB.tex).

Local source fingerprints are in `search6_sources.json`. The ePrint dates and
QSB commit identify versions; the Binohash URL is mutable, so its local-copy
fingerprint identifies the inspected bytes rather than promising URL stability.

## Concrete combination: QSB digest plus a shared-root execution proof

The strongest concrete route found here is:

1. Derive the actual spending transaction's readable QSB digest `D`.
2. Supply a commitment `alpha` to an execution trace computing that digest
   for some transaction whose full ordered output vector is `O*`.
3. Check all local computation predicates `g_i(alpha, a_i)` and require that
   the trace's resulting digest equals `D`.

This is a real relation to target, rather than treating a readable digest as
an automatically readable output vector. In symbols, the desired implication
is

```
NativeDigest(T_actual, D)
AND VerifyAll(alpha, openings, funding_context, O*, D)
  => outputs(T_actual) = O*
```

The implication additionally requires the precise collision/second-preimage
assumption appropriate to an adversarial creator choosing both transactions
before funding. Pinning signatures, recovery branches, permitted encodings,
scriptCode deletions, and sighash flags must agree on both sides.

ColliderVM Appendix A supplies a decomposition into predicates sharing a
commitment `alpha`; its Merkle openings reduce the live memory needed by each
predicate. **It does not by itself enforce that every predicate executes.**
That is the role of the presigned flow elsewhere in the protocol. Merely
moving these predicates to additional inputs or later transactions does not
make them mandatory. If the creator retains the signer keys, a transaction
that bypasses that flow remains available. If each check can choose its own
root, local correctness also fails to establish one global computation.

The remaining alternatives are therefore concrete but unresolved:

- Fit all required computation/proof checks and the digest extraction in one
  applicable Script execution, respecting its actual 201-opcode legacy budget.
- Supply a different, retained-state-safe mechanism that forces every check
  and a common root across executions.

QSB's fixed ALL signature removes an identified sighash ambiguity, and
Binohash's polyglots reduce resource costs. Both improve ingredients in this
candidate. Neither supplies the missing mandatory execution relation. A
transparent proof system could in principle supply it, but naming a proof
system or a public Merkle root is not an executable verifier.

## Avoid two overstatements

**“Retained HORS breaks Binohash.”** Too broad. An owner with all preimages
can authorize a freshly computed digest, which defeats the naive self-binding
application. It does not by itself give two distinct transactions the same
digest. A correctly enforced external proof about that digest could still
use its collision resistance. The missing piece is the mandatory proof, not
the bare existence of readable transaction information.

**“QSB has only a partial implementation.”** Outdated as an unqualified
statement. A dated author-team announcement reports a mainnet demonstration
on **2026-08-26**, linking transaction
`305a24ffea912b9cf428f29ebf952321c96dab5bab284fc0d0801562f5abab07`.
The repository's default README still contains an older unchecked broadcast
status. The announcement establishes a `reported` deployment claim here;
this review did not independently re-execute that transaction or audit its
quantum-security proof. A successful QSB transaction is also not evidence for
the stronger retained-state covenant property.
[Dated author-team announcement](https://starkware.co/blog/the-first-quantum-safe-bitcoin-transaction-has-been-mined/).

The known SHA-1 chosen-prefix results are another separate statement: their
attack model appends suffixes to supplied prefixes. The author project reports
about `2^63.4` work, but it does not provide the restricted collision needed
between an exact 64-byte Schnorr signature and an exact 20-byte bridge value.
No later primary-source construction closing that restriction was located in
this bounded search. This is an applicability gap, not a proof of restricted
SHA-1 hardness. [Attack authors' project](https://sha-mbles.github.io/).

## Falsifiable next result

Provide the complete bytecode and transaction family for the displayed
`NativeDigest AND VerifyAll` relation, or for an alternative native relation.
Show that changed outputs are rejected even when the creator retains all
setup state. Include all funding retries, preprocessing and verification in
the sub-`2^64` honest-work claim, and report exact witness/data items, hint
items, combined stack peak and complete consensus costs. The
[public-bridge audit](search4_public_bridge.md) gives the corresponding
funding-dependency and accepting-label counterexamples.
