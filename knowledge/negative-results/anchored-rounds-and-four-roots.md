# Anchored repetition and four-root extraction leave the point-lock goal open

The [round-count analysis](../../research/pointlocks-2026-09-17/anchored-rounds-limits.md)
checks every sighash byte on Core: all256 pass consensus, whereas six pass
policy. These honest fixtures extract correctly; they are not non-extracting
attacks. Uncompressed and hybrid keys also pass consensus and are now handled
by the experimental extractor.

In a4,708-profile scan, the existing five-round layout fits at96,190 vB with
placeholder maximum-length authorizations; its funded fixture is96,176 vB.
The best sampled six-round row costs111,372 vB before splitting its oversized
spend. This is a bounded scan, not a global optimum. Separately, an entropy
bound for explicit HASH160 tables with tau40, compressed key33 and d exact
60-byte signatures per selection exceeds100,000 vB at d>=11 even with free
execution and framing. Other representations are outside the bound.

The [typed-selector follow-up](../../research/pointlocks-2026-09-17/typed-selector-layout.md)
reduces five-context serialization to 94,120 vB and six contexts to 105,039 vB,
including every creation/spending transaction and mandatory authorization.
The six-context spend itself fits 100,000 vB; adding creation still exceeds
the combined target. The new rule replaces explicit bounds with a proved
type distinction plus a public rejection of DER-shaped table elements.
Core accepts all 24 small positive fixtures and rejects 14 malformed ones.
These local selector tests do not prove general extraction or fund the
full-size placeholder rows. The previous 111,372-vB scan is not a lower bound.

The [shared-anchor-context variant](../../research/pointlocks-2026-09-17/shared-anchor-context.md)
further lowers the five/six-context estimates to 94,005/103,345 vB while
retaining distinct short contexts. Its small six-context native fixtures
pass the same 24 positive/14 negative selection cases. Six contexts exceed
the combined target in that layout; general extraction and public label
binding are not resolved by that representation change.

The later [round-major layout](../../research/pointlocks-2026-09-17/round-major-contexts.md)
does cross the six-context serialization threshold at 98,334 vB including
creation, and Core validates its full-pool script. Thus the earlier scan
must not be used to exclude six contexts generally. Its later
[full native publication](../../research/pointlocks-2026-09-17/round-major-publication.md)
costs98,323 vB with real signatures and a complete honest-message roundtrip.
It still supplies no all-consensus extraction proof, public garbling binding
or complete-goal setup benchmark.

The [four-recovery-key alternative](../../research/pointlocks-2026-09-17/four-recovery-keys.md)
gives exact extraction t=-4z/r from one signature under four distinct keys.
Its cheap constant-digest setup, however, satisfies rT=-4CG with0<r<p-n. This
permits an interval-DLP search on a square-root scale near2^64.17 group
operations. The reproduced25-byte signatures do not preserve hiding. No
native transaction or compact shared-key alphabet is established for it.

Evidence: **differentially-validated** for the Core flag/key fixtures,
**locally-reproduced** for serialization and four-root curve checks, and
**inspected** for the entropy and interval-DLP arguments. Deployment is
**consensus-validated** only for the reported positive Core fixtures and
**unclassified** for the candidates and size scans. These are scoped results,
not a universal impossibility theorem.

## Shared nonce graphs require a rank condition

The [cross-key extraction follow-up](../../research/pointlocks-2026-09-17/cross-key-nonce-extraction.md)
rules out inferring extraction merely from several shared nonces or cycles.
A transparent unknown-log construction supplies three keys, six shared
nonces and one common digest per round: 18 valid equations, nine scalar
variables, rank eight and ten degenerate cycles. This control assigns
unrestricted-length signature rows and digests algebraically; it is not a
native cap60 counterexample or a hash-preimage construction. Nondegenerate
cycles do extract, and the new helper replays all 475 honest native labels.
Evidence is **locally-reproduced**, deployment **unclassified** for this
offchain rank boundary. No existing Core result or heuristic hardness bound
is upgraded.

## Fixed four-root orbits avoid the interval label but remain too large

The [fixed-orbit follow-up](../../research/pointlocks-2026-09-17/four-root-orbit.md)
uses r0=2 and a full scalar s to commit to the unordered four-point set
{sR0,-sR0,sR1,-sR1}. Its stabilizer check establishes unique canonical scalar
openings at the SINGLE constant. Other accepted digests lie in a fixed small
set, with an explicitly stated random-oracle query bound. This is a different
commitment from the weak inverse-r sum label above, not a retroactive repair
of it.

The new explicit legacy representation nevertheless costs at least131,601 vB
for all2048-bit subset messages even when granted one raw20-byte hash per
four-key packet, free signature/transaction bytes, and only132 raw key bytes
per selected candidate. Implicit sets, algebraic decompression and other
representations are outside this bound. Curve equations and numerical bounds
are **locally-reproduced**; deployment is **unclassified**. No Core or complete
setup result is claimed.

The [key-sharing extension](../../research/pointlocks-2026-09-17/orbit-key-sharing.md)
shows that each fixed-orbit verification key belongs to at most two canonical
labels. Even ideal reuse therefore costs at least 116,700 legacy vB for four
checked keys and 40-byte signatures, with all framing and verification free.
A hypothetical sufficient three-key set still has a 106,828-vB floor with
ideal sharing, or 112,556 vB without sharing even when signatures are free.
Two overlapping scalar openings additionally reveal the fixed base ratio;
any unselected labels in their sharing component then become recoverable.
The executable propagation controls use known-ratio bases, explicitly not
native ECDSA root sets. These are scoped algebraic/counting results, not a
global point-lock impossibility theorem or an attack on existing native locks.

The [graph/privacy refinement](../../research/pointlocks-2026-09-17/orbit-private-sharing-bound.md)
closes the hypothetical two-key, 40-byte-opening row as well. Counting fixed
key-sharing graphs gives a 110,865-vB floor even without privacy. Once any
shared pair is opened, its disclosed global ratio propagates from selected
labels in other components too. Selections avoiding extra scalar disclosure
must be independent sets or unions of whole components, giving a 116,643-vB
floor. Four focused host tests reproduce 1,030 graph selections and three
synthetic curve controls. This remains **locally-reproduced** algebra/counting
evidence with **unclassified** deployment, not a new native result.
