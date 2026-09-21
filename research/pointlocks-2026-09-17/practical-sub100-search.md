# Practical sub-100,000-vbyte publication search

The objective is an arbitrary future 256-byte payload, practical noninteractive
algebraic setup, no setup ZKP, and less than 100,000 vbytes including creation
and consumption of all publication outputs. There is no complete construction
meeting those conditions in this note.

The user has since quantified practical setup as ideally under100 ms, with
1–2 seconds only marginally acceptable; off-chain storage is irrelevant. The
unfinished [anchored CODESEPARATOR candidate](anchored-codesep.md) now has a
fully signed, Core-policy-accepted and mined96,176-vB honest fixture, with460
independently recovered scalars and a256-byte roundtrip. Its point-lock setup
and public checking take66.23 ms median using15 workers on an Apple M5 Pro
(first sample127.57 ms). That boundary excludes VSS/garbling integration.
General extraction and protocol integration remain open. The later total
garbled decoder supplies encoding semantics for complete valid pool openings.
A concrete alternative-nonce search strategy is now costed separately;
repetition alone is not a security proof. This is not yet a solution.

The [nonce-relation extractor](nonce-relation-extraction.md) now adds an exact
branch for nondegenerate public affine relations between reconstructed ECDSA
nonces, including distinct-r signed GLV cases. Eighteen focused test methods
pass across the helper and existing wrappers. A zero-determinant control stays
unresolved, as do unrelated nonce families. No size, native execution or
general hardness improvement follows from this offchain extension.

The [cross-key graph extractor](cross-key-nonce-extraction.md) now also uses
nondegenerate cycles involving several label keys. Eight focused tests pass,
including cases missed by every per-key check and a degenerate six-context
control. Replaying the full native 98,323-vB fixture recovers all 475 scalars
from actual transaction-derived equations. No extra onchain data is needed,
but unrelated nonce components and the full extraction requirement remain open.

The [public algebraic gate probe](public-algebraic-gate.md) tests an alternative
to the encrypted translator. Its scalar AND relations are publicly checkable
and evaluate correctly, but selected labels for 01 or 10 reveal all labels
for 00. Public offsets can make every commitment distinct without repairing
that disclosure. Four deterministic tests reproduce this boundary; the
privacy-free source's weaker output-authenticity theorem is not contradicted.

The [two-coordinate gate follow-up](vector-label-gates.md) achieves public
algebraic checking and a one-opening discrete-log argument for full input
labels at the single-gate boundary. The direct legacy wrapper for its
2,048-bit input interface has a 241,664-vB signature-push floor, so it is not
a publication solution. One-scalar linear AND labels cannot retain both
input restriction and output authenticity; nonlinear compression or a
different native delivery remains necessary for this route.

The [shared-coordinate optimization](shared-vector-gates.md) lowers the
binary gate from four scalar openings to three, with a 181,248-vB direct
legacy floor for an independent 2,048-bit layer. Its correlated-subset theorem
rules out a total linear hidden-binary-label decoder for all 5-of-54 choices,
even with public linear correlations. More such sharing does not supply the
missing bridge; nonlinear binding or a different disclosure interface remains
the relevant next direction. Existing nonlinear measurements are unaffected.

The [ratio-label follow-up](ratio-labels.md) examines a/b as a concrete
nonlinear replacement. For fixed publicly affine point endpoints it requires
both scalar forms, except for already public constants. Nine focused tests,
including twelve exact DLP embeddings, corroborate this restricted boundary.
A successful next decoder needs an additional public nonlinear relation or
a different native opening, not only relative-log notation for linear forms.

The [DH quartet selector](dh-quartet-labels.md) gives a positive offchain
alternative: one of four scalar openings computes two secret point-valued
labels. A correlated two-scalar setup publicly excludes all exact output-label
equalities. Its scalar count would require 60,416 vB in guarded legacy
signature pushes alone, before keys, scripts and complete transactions; this
is not a new sub-100k fixture. Public garbling binding remains open.
Independent-coordinate quadratic DH labels cannot extend
directly to the full 5-of-54 alphabet (NR-075).

The [fixed-digest nonce wrapper](fixed-digest-nonce.md) now supplies native
openings for the four correlated targets. Three known-key contexts plus one
derived-key check use 86 script bytes standalone or 199 bytes for a quartet.
Core and independent Rust checks reproduce the small fixtures. However,
1,024 explicit candidate-key tables alone consume 139,264 legacy vB; even an
idealized four-HASH160 table plus selected key costs 120,832 vB before any
signatures or framing. These are layout-specific floors, not a universal
bound. Full garbling binding, a smaller native representation and complete
setup measurement remain necessary.

The [correlated quadratic analysis](correlated-quadratic-labels.md) extends
the DH subset obstruction beyond independent inputs. Full t-subset scalar
privacy forces every t+1 candidate forms to be independent. A degree bound
then requires N-t<=3 for two hidden quadratic point labels, including vector
labels. The full 5-of-54 alphabet therefore needs a different reconstruction
interface or choice family; correlated degree-two metadata alone is not the
missing compression. Eight focused tests include 44 exact field ranks and
34 curve views, with no new native or whole-setup measurement.

The [typed-selector layout](typed-selector-layout.md) now lowers five-context
serialization to 94,120 vB with all creation, spending and authorizations
included. Its small native selector fixtures pass 24 positive and 14 negative
Core checks. The best sampled six-context layout is still 105,039 vB. Full-size
signatures in that scan are placeholders; these figures do not replace the
96,176-vB funded fixture or establish extraction, setup timing or garbling.

The [shared-anchor-context variant](shared-anchor-context.md) lowers the
five/six-context estimates to 94,005/103,345 vB. Separate small six-context
Core fixtures pass 24 positive and 14 negative cases. Including the anchor
nonce in the extractor adds twelve exact relation cases, with eight further
synthetic equal-digest cases. Unrelated nonces and public garbling binding
remain open; these savings do not yet produce the required construction.

The [round-major witness layout](round-major-contexts.md) now lowers the
five/six-context estimates to **90,114/98,334 vB**, with all creation,
consumption and authorizations included. Six contexts use 95 five-of-54
pools. Core validates both small selection fixtures and the actual 201-opcode
full-pool script: 18 positive and 19 negative cases across the two reports.
The subsequent [complete native publication](round-major-publication.md)
replaces placeholders with real signatures at **98,323 vB**. Core accepts
and mines both transactions, rejects three malformed full spends, and an
independent decoder recovers all475 scalars and the256-byte payload. Its
point-lock-only setup/public checks take89.63 ms median with15 workers
(154.47 ms first sample). General extraction, public garbling binding and
complete-goal setup remain open.

The [95-pool total decoder](round-major-message-decoder.md) now reproduces
the native payload through all 475 scalars, encrypted complement shares and
garbled rank/message circuits. The modulo-2^2048 rule also handles every
surplus codeword. Fresh generation takes 364.16 ms median; generation plus
an all-secrets audit takes 733.29 ms. It adds no onchain bytes. Public setup
verification, general extraction and complete protocol integration remain open.

The [native participation probe](pool-participation.md) additionally confirms
that the retained creator can re-sign a spend of one funded pool without the
other 94. The helper can be omitted or included; all four partial cases pass
Core, while three stale-signature controls fail. A complete transaction graph
must enforce availability of all required labels on successful publication,
or establish safe abort semantics for these partial spends (NR-070).

The [dual-anchor/sum-key replacement](dual-anchor-sum-collapse.md) is now
refuted by a native public-opening counterexample. It would reduce reliance
on short-signature heuristics, but Core accepts an opening built without the
target scalar: the extracted sum is already public. Two positive variants
and seven rejecting controls reproduce the precise boundary. This does not
affect the existing exact-60-byte anchored candidate.

The [two distinct target anchors](two-target-anchors.md) repair that algebraic
collapse and yield exact extraction of one of two prebound label scalars.
They instead prescribe the nonce x-coordinate from the native digests; knowing
the ordinary signing keys does not supply that nonce logarithm. Eight tests
and 31 synthetic curve cases establish the equations, not practical native
opening or a publication solution (NR-071).

The [direct-key six-context variation](direct-context.md) removes the anchor
and fits a Core-policy-validated honest fixture into 98,706 vB. Point-lock-only
generation and checking take 46.59 ms median (first sample 130.23 ms). Native
digest tests, however, demonstrate staged ACP|NONE/ACP|SINGLE/SINGLE/ALL searches
that preserve earlier conditions. Removing the anchor removes its ALL-dependent
key coupling. This is not an established strengthening of extraction; see
[NR-065](../../knowledge/negative-results/direct-context-staged-grinding.md).

The [subset translation follow-up](subset-translation.md) recovers 2,070 binary
rank-input labels from the existing report's 460 scalars. A full 26.5-million-row
translation takes 1.590 s median for generation plus an audit with all secrets
opened. It establishes neither public setup validation nor multi-copy garbling
integration. The remaining challenge is binding the encrypted translation to
the intended labels, as well as the still-open point-lock extraction argument.

The [threshold-complement follow-up](complement-translation.md) now provides
an alternative with 4.51 MB of encrypted shares and real per-pool garbled rank
decoders. Generation plus an all-secrets audit takes 72.64 ms median for all
115 pools; cached native scalar openings reproduce the original message
through those decoders. This resolves a translation-size/time bottleneck under
honest setup, not public malicious-setup verification or point-lock extraction.

The [total message decoder](total-message-decoder.md) now evaluates the full
base-230,300 integer modulo 2^2048 inside a garbled circuit. All complete valid
codewords, including surplus ones, map to one message, and every 256-byte
message remains representable. The composed 460-scalar path yields 2,048
message labels. Generation takes 341.82 ms median, the all-secrets audit
348.66 ms, and their combined median is 701.05 ms. This adds zero onchain
data, but does not provide public setup verification, the full BitVM3 verifier,
mandatory-input binding or general extraction.

The [consensus and round-count follow-up](anchored-rounds-limits.md) confirms
all256 ECDSA hash-type bytes and uncompressed/hybrid keys on Core. A bounded
scan puts the existing six-round layout at111,372 vB; a representation-specific
entropy bound excludes eleven or more rounds even with free verification and
framing. The [four-recovery-key alternative](four-recovery-keys.md) has exact
algebraic extraction and cheap25-byte signatures, but its honest target admits
an interval-DLP search near2^64.17 group operations. Neither closes the goal.

The [fixed four-root orbit](four-root-orbit.md) provides a new way to bind a
full canonical scalar instead of the earlier inverse-r interval label. Its
explicit legacy representation still has a131,601-vB optimistic floor; no
native script or full protocol is claimed. The [scalar-linear complement
obstruction](complement-linear-obstruction.md) rules out repairing the current
4-of-50 encrypted bridge merely through public scalar-linear equations.
These results direct the search toward a genuinely different representation
or nonlinear public binding.

The [fixed-orbit sharing analysis](orbit-key-sharing.md) now also bounds ideal
reuse: each key serves at most two canonical labels. Four checked keys with
40-byte openings still cost at least 116,700 vB; even a hypothetically correct
three-key variant costs 106,828 vB with perfect sharing. Revealing overlapping
labels exposes the base ratio and propagates openings along their component.
This narrows the useful search to a different commitment/check interface or
representation, rather than dropping only the fourth check.

The [graph/privacy refinement](orbit-private-sharing-bound.md) closes the
remaining two-key numerical gap in that model: fixed two-key packets and
40-byte openings cost at least 110,865 vB even without privacy, or 116,643 vB
when the known cross-component scalar disclosure is excluded. Six bounded
graphs reproduce 1,030 subset cases; a separate group control demonstrates
propagation into another partially selected component. This excludes spending
further native-implementation effort on that explicit fixed-orbit layout;
it does not exclude other commitment interfaces or parameter families.

The [direct binary-label rank bound](binary-linear-label-rank.md) further
excludes replacing the nonlinear translation with public linear interpolation
of fewer than 2,048 field openings into the complete 2,048-bit input-label
interface. A dependence enables an unauthorized one-bit message change.
With one guarded legacy sum-key signature per opening, signature pushes alone
cost at least 120,832 vB. This bound permits correlated masks but excludes
nonlinear decoders and different message-authentication interfaces.

The [DDH batch-select follow-up](ddh-batch-select.md) tests a different
representation: a complete2048-bit label vector can be delivered from eight
scalar keys plus the public message,512 raw opening bytes, using17.64 MB of
offchain ciphertext payload. Generation takes695.61 ms median and an audit
with every secret takes890.47 ms. Neither native aggregate-key binding nor
public ciphertext verification exists. Replacing the aggregate key with
separately opened common-shift point-lock shares leaks all alternative labels
under free-XOR; see [NR-067](../../knowledge/negative-results/ddh-batch-select-share-disclosure.md).
These are offchain payload and audit measurements, not a sub100k construction.
The [next interface analysis](ddh-linear-leakage.md) rules out every additional
nonredundant scalar-linear disclosure in that local DDH layout, extending the
common-shift counterexample. It also identifies public affine row relations
as sufficient to reveal label differences. A native aggregate connection must
avoid those disclosures and still solve public ciphertext binding.
The [masked extension](ddh-masked-audit.md) shows that an informative group
action alone can expose the same alternatives. Hiding its scalar with a
fresh mask is insufficient when the corresponding mask action is public;
letting mask points float instead defeats the tested fixed-challenge audit.
This narrows that proposed audit interface, not all masked constructions.

The [Argo MAC / Duty-Free Bits interface review](arithmetic-garbling-interface.md)
adds useful arithmetic-garbling machinery and two passing focused upstream
tests. Duty-Free Bits has a separated evaluator API, but it still consumes
already selected input labels. Native publication, public setup binding and
the complete setup benchmark remain independent requirements. Published
component speedups must not be counted as having solved these requirements.

The [WOTS-to-Lamport interface audit](wots-translation-boundary.md) inspects a
newer primary source and reproduces13,056 threshold-deficit checks plus64
selected-label reconstructions. Small chunks reduce its algebraic table count,
but a changed ciphertext still leaves every WOTS endpoint valid. The source's
own protocol/audit and timing boundary are different from this goal. This is
an alternative offchain access structure, not a native point lock or a public
malicious-setup verification method.

The exact sum-key P2SH publication fixture remains 185,146 vbytes, including
one creation and two spending transactions. The separately
[validated bare-legacy publication](bare-publication.md) now costs 161,382 vB
actual / 161,560 vB canonical maximum across funding and one spend. Core block
validation and independent 553-scalar/256-byte recovery pass, but default relay
rejects the custom bare scripts. Partial spends and surplus codewords remain
accepted protocol-boundary controls. The 39,396-vbyte windowed estimate
is rejected for impractical setup; the 92,706-vbyte compressed-proof fixture
carries only 128 bytes and does not meet the arbitrary-256-byte objective.

## Repeated native checks

The [repeated capped-signature experiment](repeated-cap60-sizing.md) replaces
setup grinding with several checks on public scalar multiples of each label.
Its best sampled three-check layout costs 130,182 vbytes before splitting the
oversized spending transaction. Sighash choices also remain unrestricted, so
the proposed shared-digest argument is unestablished. The serialization probe
does not produce valid native publication signatures.

The [native byte-distinct follow-up](distinct-short-signatures.md) excludes
replacing separate digest contexts by signature-byte inequality on the legacy
constant branch. A transparently constructed committed key admits16 exact60
encodings sharing one equation. The existing max60 lock and all-pairs-distinct
batches of up to eight pass Core; two ordinary low-S flags also pass policy.
This is a malicious-setup counterexample for that legacy alternative, not an
attack on the anchored P2WSH candidate or the exact sum-key construction.

## Dynamic intermediate points

A path of exact sum-key predicates can use witness-supplied intermediate
points, with committed endpoints P_0=T and P_L=G. Each edge checks the same
signature under its two adjacent points. Each signature must exceed 57 bytes;
adjacent keys must be distinct and use canonical 33-byte compressed encoding.
These conditions give, for that edge's actual common digest z_i,

    P_(i-1) + P_i = c_i G,       c_i = -2 z_i / r_i mod n.

Consequently,

    t = (-1)^L [1 - sum_i (-1)^(L-i) c_i] mod n.

Intermediate points cancel, so extraction itself does not require their
discrete logarithms or a common digest across different edges. This is an
algebraic observation, not a compiled or Core-validated path implementation.

For an honest opener using one native digest z, independently chosen known
nonces determine r_i and hence the c_i. The final point must still equal G.
Thus the nonce choices must satisfy a prescribed alternating sum of inverse
x-coordinates. Choosing the endpoint after solving this sum changes the funded
script and its digest. A generalized birthday search is not practical setup;
no cheap closure algorithm has been found. The path therefore removes one
form of self-reference without solving the honest-opening problem.

## Implicit linear labels

An algebraic alphabet can escape an explicit candidate table. Take ten
independent secret scalars x_0,...,x_9 and public points X_j=x_jG. Encode a
2048-bit message as nine base-n digits d_0,...,d_8, and define

    c(m) = (1, d_0, ..., d_8),
    y(m) = x_0 + sum_j d_j x_(j+1),
    Y(m) = X_0 + sum_j d_j X_(j+1).

Setup and calculation of an honest opening are ordinary scalar/point
arithmetic. For different messages the normalized coefficient vectors are not
scalar multiples. One revealed linear projection therefore does not by itself
linearly determine another. This is a one-time algebraic observation, not a
complete computational proof for a publication protocol.

The missing Script operation is decisive: authenticate the witness-selected
coefficients and check that the revealed scalar corresponds to Y(m), rather
than to an unrelated supplied point. Current native signature checks do not
directly verify this variable-coefficient point equation. An off-chain
calculation of Y(m) cannot replace the on-chain binding. No executable
sub-100k construction or garbling integration has been supplied.

## Acceptance criterion

A new candidate must provide actual funded transactions, a cheap honest
opening algorithm for every message, and extraction or the required protocol
failure consequence for every accepted witness. Account for all outputs,
inputs, scripts, signatures, hints and setup work. Any new assumption must be
stated separately from serialization and honest-execution evidence.

Evidence for the path and projection observations: `inspected`. Deployment:
`unclassified`. The linked repeated-check measurements have their own more
limited `locally-reproduced` evidence. None establishes impossibility of the
original objective.
