# Binohash 2-of-3 subset and Script-consumer fixture

This reduced single-round experiment follows the paper's `OP_ROLL` subset
selection and signature-size predicate at toy scale. Three fixed embedded
legacy signatures yield three possible two-signature subsets. Locally
computed `FindAndDelete` digests differ for all three; a signed candidate
subsets `[0,1]` and `[0,2]` are each accepted in a pinned Bitcoin Core v30.3
block using disjoint funded outputs. The selected indices also survive
signature verification and choose different later HASH160 preimage checks.

The [implementation README](../../research/binohash-subset/README.md) defines
the input order, raw Script, funding search, and complete cost boundary. The
[checked report](../../tests/data/binohash-subset-v30.3.json) records the
funding and two spending transactions, each spend's three candidate digest and
signature-size outcomes, Core verdicts, and release provenance. Independent Core execution
gives this exact configuration `differentially-validated` evidence and
`consensus-validated` execution. The digest comparison is indirect: Core
verifies the ECDSA signature over its own legacy sighash; it does not expose
the digest through an RPC.

The 23-byte P2SH locking script commits to a 493-byte redeemScript. The
complete selected spends each weigh 2,908 WU and have no witness or auxiliary hint
items. For each spend, a changed pair with the original signature, reversed indices,
duplicate and out-of-range indices, noncanonical negative-zero, a wrong
preimage, and a valid oversized signature
all fail Core consensus. The correctly signed spends still fail default
relay policy under `CONST_SCRIPTCODE`.

This fixture has no Stage 1 transaction pinning, no meaningful grinding work,
no two-round digest, and no downstream authentication. Its three public
preimages only demonstrate that Script can consume the selected pair. It does
not upgrade the [reported full Binohash protocol](binohash.md) or close
`OP-011`.
