# ALL authorization does not force every point-lock pool to participate

The [native participation experiment](../../research/pointlocks-2026-09-17/pool-participation.md)
uses the exact scripts and commitments of the full 95-pool, 98,323-vB
round-major candidate. A creator retaining its signing secrets can spend one
pool alone, or the helper and one pool, while leaving 94 pools unspent.
Four such partial spends and the complete control pass default Core 30.3
policy and mined consensus. All five selected scalars are recovered from
each partial witness; this is intended disclosure, not a failure of those
individual openings.

Three controls using stale full-spend authorizations or opening witnesses
fail policy and consensus. The distinction is therefore between committing
to a chosen transaction and enforcing which transaction an authorizer may
choose. An ALL signature does the former; the current predicate supplies no
additional complete-input-set condition.

This rejects treating any accepted pool spend as the complete publication.
It does not establish an application theft, refute the individual extraction
primitive, or rule out a transaction graph that safely treats partial spends
as aborts. Such a graph must be implemented and counted before completing the
publication claim. An offchain completeness check alone is insufficient.

Evidence: **differentially-validated**. Positive native cases:
**policy-validated**. Complete-protocol deployment: **unclassified**. Exact
witness, hint and stack accounting, full raw transactions, provenance and the
reproduction command are in the linked experiment.
