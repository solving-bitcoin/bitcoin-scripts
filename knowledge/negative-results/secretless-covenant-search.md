# Secretless exact-output covenant search

Question: can existing opcodes bind all output amounts, ordering and scripts
with less than 2^64 honest total work while the creator keeps every setup
secret and may prepare alternatives before funding? The
[research report](../../research/covenant-2026-09-17/README.md) records no
complete solution. These exclusions are specific to the constructions analyzed.

## Free identical ECDSA pairs do not imply equal digests

For distinct reduced digests z1,z2, choose r=x(G), s=(z1-z2)/2 and
d=-(z1+z2)/(2r), modulo the secp256k1 order. The same signature/key pair
verifies through nonce points G and -G. The raw legacy vector
`OP_2DUP OP_CHECKSIGVERIFY OP_CODESEPARATOR OP_CHECKSIG` consequently accepts
arbitrary output variants with a newly calculated witness pair.

Independent affine equations, OpenSSL and funded P2SH transactions against
Core 30.3 commit `49faec4f87f5cd19c88db01a82e5c68b087c8227` confirm this.
Evidence is `differentially-validated`; positive counterexample spends are
`consensus-validated` and fail standard CODESEPARATOR policy. This does not
break the fixed r=s=1 signature. The report gives exact zero-hint metrics.

## Two symmetric direct paths remain too costly

The recovery-free DER predicate has modeled probability `780555/2^65`, or
W≈45.425859. Even granting one independent bit per four-opcode optional hash
step, spending all 201 Legacy opcodes on two paths permits only 25 bits each.
The sparse two-hit search exponent is at least 2W-25≈65.85 before other work.
Shared prefixes do not enlarge useful suffix entropy in this model. This
`inspected`, `unclassified` calculation excludes these direct path families
only, not more compact native nonce functions or different rare predicates.

The [seven-agent follow-up](../../research/covenant-2026-09-17/seven/README.md)
escapes this restricted family: fix the first nonce, then use three-opcode
two-state routing for the second. Its native-side candidate has 199 opcodes
and about 56 effective nonce bits. The full two-hit PoW has not been mined,
and the common arithmetic/output representation is still missing. Eight
observable routing fragments passed Core consensus and policy; they omit
the PoW and native root-binding gates. Thus the old bound must not be used
as an exclusion of every native two-hit pair under 201 opcodes.

## Count ColliderScript preparation

For ideal independent 160-bit hash outputs on disjoint 20-/64-byte input
domains, Q total fresh queries give cross-collision success at most Q²/2^162.
Including tables, Q<2^64 gives success below 2^-34. This `inspected`,
`unclassified` argument is confined to the corrected ColliderScript bridge
and ideal-oracle model. It is not a SHA-1 or universal covenant lower bound.

The derivative `OP_SHA256 OP_0 OP_CHECKSIG OP_NOT` is a consensus-checked
DER-only gate, but has no transaction binding by itself. Core accepted the
same known preimage for two recipients of the same funded outpoint. Making
a public puzzle cheaper does not establish an honest/attacker work gap.
See [OP-021](../open-problems.md#op-021--secretless-exact-output-covenant-under-264-work).

## Native cycles and extra execution do not automatically close the gap

The [second investigation](../../research/covenant-2026-09-17/second_pass.md)
adds twelve Core cases. A free eight-key ECDSA cycle with 16 native checks
closes without hash search when the relative nonce signs multiply to -1;
both recipient variants of one funded outpoint are accepted. In separate
fixtures, extra bare scriptSig computation can be replaced by its endstack
pushes without changing the ALL signature, while P2SH rejects non-push
scriptSigs. A SINGLE-bug condition accepts multiple different helper-input
programs and recipients. These are `differentially-validated` scoped results;
positive fixture spends are `consensus-validated`, not valid covenants.

A host partition also bounds fixed-nonce, common-digest offset-key length
oracles to at most 64m complete answer vectors for m fixed keys. This
`locally-reproduced`, `unclassified` result does not cover arbitrary nonce
multipliers or independently changing signature contexts.

## More native equality still needs a reference computation

The follow-up derives exact scalar-digest equality using the fixed r=s=1
signature and both distinct compressed recovery keys in each context.
Same-context execution and malformed cases were checked against Core. This
repairs the free-pair equality shortcut but does not supply a native context
containing a separately checked intended output list.

At fixed output count, equality of ordinary legacy preimages is invariant
under changing output amounts and scripts. The tested cross-format
legacy/BIP143 exact-overlap candidate also requires
`H256(X)=CompactSize(input_count)||X[:remaining_bytes]`, where X is the actual
outpoint vector. Its entire 256-bit target is fixed by X before hashing;
the ideal-function success bound is Q/2^256. These are scoped `inspected`
arguments with `locally-reproduced`, `unclassified` host fixtures, not general
bounds on native digest relations or real SHA256 cryptanalysis.

Public garbling and static relations among Binohash/QSB digest indices still
need a mandatory evaluator for the intended transaction. Retained HORS
preimages invalidate authorization-only self-binding, not digest collision
resistance itself. The linked follow-up records these distinctions and the
remaining common-reference-verifier obligation.

## A hash-derived signature still needs output and proof binding

The [R5 Core fixtures](../../research/covenant-2026-09-17/continuation/r5_root_core.md)
verify an actual public SHA256 preimage as an ECDSA signature using its `r+n`
nonce-point branch. The same preimage/key pair permits changing amounts,
scripts, output count and order because its flag is NONE. Six variants pass
default policy. A context-inequality guard rejects the SINGLE bug but retains
this NONE example; two guarded spends pass consensus and fail policy.
Three malformed vectors fail. These results are `differentially-validated`;
they do not execute a complete proof verifier or covenant.

The [root-reuse analysis](../../research/covenant-2026-09-17/continuation/r5_root_chronology.md)
quantifies when proof-root mining and native pinning multiply and when genuine
reuse can amortize them. Its `locally-reproduced`, `unclassified` strategy
model leaves a concrete reusable-function-verifier route open. An ordinary
single-transaction trace cannot be silently reused for different native
inputs or include its own hash-derived recovery calculation without a
dependency cycle. The same-hash correlation case is explicitly outside the
independent-gate estimate.

The [Tapscript continuation](../../research/covenant-2026-09-17/continuation/r5_tapscript_reference.md)
reproduces every 3-of-8 CHECKSIGADD success pattern for two output lists under
retained public signing keys. Such patterns do not provide a transaction-fixed
proof query. Fixing only the Schnorr nonce leaves the variable scalar bytes
unbound; an explicit fixed signature table supplies that binding but exceeds
the total-work budget in the scoped ideal model. These are host results,
`locally-reproduced`, `unclassified`, not general impossibility claims.

## R6 narrows function and correlated-root replacements

The [explicit sumcheck lookup attempt](../../research/covenant-2026-09-17/continuation/r6_function_commitment.md)
ends at an off-Boolean-cube function evaluation; an ordinary table membership
opening does not authenticate that value. Its direct 77-round implementation
already requires 616 generously counted field operations/comparisons. A
readable hash-path root binds short parameters, but not arbitrary later wire
values. These are scoped host results, `locally-reproduced`, `unclassified`.

The [correlated-root study](../../research/covenant-2026-09-17/continuation/r6_correlated_root.md)
supplies an eight-opcode cross-key signature cycle, with a small-curve
reproduction but no affordable full-size short-cycle solver or output
advantage. Its separate affine digest/signature cancellation really works
algebraically, but forces nonce 256G, whose r requires 33 DER bytes and cannot
fit a 20-/32-byte hash-derived signature. This excludes the fixed-r affine
family, not its variable-r extension or all correlated commitments.

The [adaptive hash-graph analysis](../../research/covenant-2026-09-17/continuation/r6_scalar_bridge.md)
extends the ideal collision bound to positive full-hash-equality bridges
whose reference values come from short bound seeds and native hash paths.
It includes all setup/search queries and explicitly excludes native group
relations and real SHA1 cryptanalysis. These host results have evidence
`locally-reproduced` and deployment `unclassified`.

## R7/R8 distinguish native relations from affordable output binding

The [authenticated polynomial quotient](../../research/covenant-2026-09-17/continuation/r7_specialized_verifier.md)
can target any chosen N−1 challenge points even when its coefficients were
committed before the challenge. Its explicit small authentication already
exceeds 201 opcodes. A public or retained KZG evaluation scalar admits false
openings, reproduced on secp256k1. This excludes the examined replacement,
not transparent commitments in general.

The [duplicate-signature multisig](../../research/covenant-2026-09-17/continuation/r8_nonce_binding.md)
really binds a relation between r and the native digest. In the stated
two-recovery-root family, r is a digest-scaled value rather than a fixed
selected nonce. Fixed keys turn the known-nonce strategy into full scalar
matching; free witness keys allow public signing for other output lists.
The exceptional four-root cases are outside that scoped calculation.

The [coupled-DER family](../../research/covenant-2026-09-17/continuation/r8_coupled_der.md)
constructively cancels the layout constant using two short signatures and
affine-related keys. Its fixed-r target space remains far too small for
the specified native-hash search, and fixing keys before funding removes
the apparent free-s domain. These are `locally-reproduced`, `unclassified`
results, not a general impossibility claim.

The naive mixed-portfolio Cartesian scan is **not** a lower bound: the new
[interval join](../../research/covenant-2026-09-17/continuation/r8_batch_incidence.md)
avoids it. The [expected-cost audit](../../research/covenant-2026-09-17/continuation/r8_portfolio_costs.md)
also separates a trial's success probability from expected total work.
Neither the faster join nor its small Core fixtures establish sub-2^64
full work or the missing covenant asymmetry.

## R9 closes a recovery exception while leaving the reference obligation

Three distinct common keys are now sufficient for equal scalar digests for
**any** shared valid ECDSA signature on secp256k1. The
[exact proof and independent certificate](../../research/covenant-2026-09-17/continuation/r9_recovery_audit.md)
cover all r+n cases; this supersedes the earlier r=2-only corollary rather
than implying a covenant impossibility. The variable-signature layout has
four Core/policy-positive same-context witnesses and four negative cases.
There is still no native context representing the independently checked
intended outputs.

The distinct [hash-as-Schnorr-key route](../../research/covenant-2026-09-17/continuation/r9_hash_xonly.md)
really permits acyclic post-funding proof selection and forces DEFAULT. A
liftable root does not provide a signing witness. Known-log or known-nonce
solvers retain a reusable signing scalar; the examined unknown-log affine
nonce instead requires a full challenge match in its stated model. These
are scoped host results, `locally-reproduced` and `unclassified`.

The [numeric root](../../research/covenant-2026-09-17/continuation/r9_numeric_root.md)
binds one readable ScriptNum with separate hash-path mining hints. Its
198-opcode root/pin candidate remains unmined and does not authenticate
arbitrary subsequent computation. Its finite root domain must be included
before using the R5 renewal estimate. It does not replace a general
functional commitment or validate the allowed-output reference.

## R10 refines the mandatory reference and finite-domain questions

The [same-input reference interface](../../research/covenant-2026-09-17/continuation/r10_reference_interface.md)
can use out-of-range SINGLE for one signature and ALL for another signature
on the same locked input. It does not require an optional external verifier.
The exact numerical-signature version forces a full ALL digest target; the
different-signature two-root version leaves both a digest/r ratio and a
nonce-point relation. Neither is a complete cheap output reference.

[Parallel key cycles](../../research/covenant-2026-09-17/continuation/r10_parallel_cycles.md)
with two distinct keys at every vertex impose local pair-center equations,
not merely one arbitrary sum, when each signature has two recovery roots.
The four-root pair states and the formal free-r multiplicative relaxation
remain explicit. These scoped results do not exclude every nonce solver.

The [packed numeric seed](../../research/covenant-2026-09-17/continuation/r10_parameter_frontier.md)
provides many legitimate roots for the same small affine function, so the
earlier fixed-seed shortage must not be generalized to every numeric-root
verifier. Its 143-opcode candidate still leaves the native transaction
inputs/outputs of that affine function unbound. Its sub-2^64 enumeration
figure counts primitive hashes, not full covenant work. All these new host
results are `locally-reproduced` and `unclassified`.

## R11 constructs the free ratio and isolates reference restrictions

The [endomorphism lattice](../../research/covenant-2026-09-17/continuation/r11_endomorphism.md)
does realize a cross-signature ratio after a native digest is known without
individual nonce logarithms. The earlier logarithm obstacle must therefore
not be treated as a general exclusion of free-signature pairs. Three
[Core/policy-positive alternatives](../../research/covenant-2026-09-17/continuation/r11_endomorphism_core.md)
spend the same locked outpoint with publicly recomputed witnesses; their
different outputs exhibit the still-missing asymmetry.

The [fixed-endomorphism hash-root model](../../research/covenant-2026-09-17/continuation/r11_endomorphism_root_cost.md)
applies only when alpha is constrained to a fresh hash result and the nonce
map comes from that finite catalogue. Its adaptive-total-query bound uses
Q(Q−1)/2 possible cross-list index pairs, not the fixed-cap Q²/4 factor.
It is not a lower bound against all accepted native pairs or future solvers.

The [concrete native table](../../research/covenant-2026-09-17/continuation/r11_lookup_reference.md)
fits the small lookup budget and supplies actual byte/key binding. Its
remaining generation cycle is table → funding txid → native ALL digest →
table keys. CODESEPARATOR removes only the direct table-to-scriptCode edge.
The [PIPEs v2 source audit](../../research/covenant-2026-09-17/continuation/r11_reference_sources.md)
identifies a different exact mismatch: a valid witness authorizes arbitrary
messages, even granting ideal setup. Neither scoped result excludes a new
construction with a mandatory message-dependent signing relation.

[R12's reversed hash direction](../../research/covenant-2026-09-17/continuation/r12_live_reference.md)
keeps full-length alpha signatures and supplies a large scalar family of
valid witnesses for one actual digest. SHA256(alpha) can be searched without
per-trial curve work and bound to the same native signature in a 55-byte
predicate. The implemented h remains free, and a proposed DER-hash recovery
key remains free and unmined. Neither supplies intended-output computation.
The scalar family changes alpha, so it is not a supply of L variants for a
fixed authenticated root. These are `locally-reproduced`, `unclassified`
host results, not new Core or covenant claims.

## R13/R14 distinguish an orbit identity from an enforced native relation

[Same-key hash closure](../../research/covenant-2026-09-17/continuation/r13_gamma_closure.md)
removes the free recovery key but also removes R12's apparent large supply
of matching hash outputs: each fixed gamma has at most four predecessors
in a preselected scalar family. The ideal expected number of closed pairs
over that entire family is at most `4*p_DER`. Adaptively selected families
are outside this count; the public-offset vectors do not close the hash.

The [literal-table Taproot transfer](../../research/covenant-2026-09-17/continuation/r13_table_commitment.md)
has a concrete Core counterexample: 33-byte keys select tapscript's unknown
key type, so identical witnesses at the same funded outpoint allow different
outputs. These cases are `consensus-validated` but rejected by policy. The
32-byte-key replacement rejects the short DER signature. Known internal
scalars permit ordinary key-path spends; fixing a NUMS internal key does
not repair the table checks or the delayed-opening equation.

The [three-point orbit](../../research/covenant-2026-09-17/continuation/r13_orbit_query.md)
really satisfies `sum(x)=h*p` with h=1 or 2. Three native signatures alone
do not enforce orbit membership or the claimed h. The complete
[short-coordinate enumeration](../../research/covenant-2026-09-17/continuation/r14_orbit_observable.md)
finds exactly one coordinate orbit when all three r fit 32-byte DER
signatures; h is then always 2. A fresh uniform hash contains one of its
three fixed r values with probability `32895/2^192`, even allowing every
fitting s and every flag. This is a scoped ideal hash-query count, not a
general covenant lower bound or exclusion of one short plus long signatures.

[Denser native key graphs](../../research/covenant-2026-09-17/continuation/r14_orbit_binding.md)
have separate exact obstructions: one signature cannot verify under an
affine lambda-orbit of three distinct keys at a common digest; and four
common keys across different signatures cannot transport a nonce by a
nonidentity endomorphism. Polynomial and independent matrix certificates
cover the former, while the latter uses the complete recovery-set centers.
Three-key subsets across different signatures remain a separate question.

[Mandatory SegWit staging](../../research/covenant-2026-09-17/continuation/r14_table_chronology.md)
can publish rows after fixing a transaction's txid, but publication alone
does not authenticate later native keys. Authenticating them through an
ancestor P2WSH commitment propagates that commitment through all mandatory
outpoints. This excludes the examined acyclic wrapper strategy, not every
simultaneous-equation solver. Except for the explicitly linked Core cases,
these results are `locally-reproduced`, `unclassified` host mathematics.

The [R15 subset classification](../../research/covenant-2026-09-17/continuation/r15_three_common_keys.md)
now gives a complete quartic test for each fixed nonzero affine translation
in that remaining three-key case. Real mismatched-pair examples occur on
small curves and are independently enumerated; they must not be discarded
using the four-key center argument. The native C/ALL equations, exact
integer branch gaps and hash-selected signature still have to be satisfied.
Sixteen full-size translation samples are not a density or work bound.

[R16's five-center support theorem](../../research/covenant-2026-09-17/continuation/r16_three_key_support.md)
now covers every affine parameter choice: for each fixed alpha at constant
C, at most `5*(p-n-1)` target digest scalars can support three common group
keys, even with arbitrary target signatures. Counting positive 32-byte DER
source answers, the native reduction bias and adaptively allocated queries
gives success probability at most approximately `2^-44.08044` at `2^64`
total queries in the explicitly independent-answer model. This is not a
bound for shared answers such as alpha equal to the native digest. The
support theorem is checked by 594,285 exhaustive small-curve comparisons.
The separate [native translation reproduction](../../research/covenant-2026-09-17/continuation/r16_native_translation.md)
derives `rj*(si*V-C*G)=-ri*z_ALL*G` and closes two actual transaction-hash
instances on a small curve. Its retained logarithm table and hash-to-scalar
projection do not implement secp256k1 or raw-hash DER. The reported BSGS
costs describe that algorithm, not a universal work lower bound. These
results are `locally-reproduced`, deployment `unclassified`.

[R17's shared-source vectors](../../research/covenant-2026-09-17/continuation/r17_shared_source.md)
show that the excluded shared-answer case is concretely available: hashing
`SHA256(actual_ALL_preimage)` once in Script gives the actual ALL hash.
Eight byte identities reproduce this without another preimage search;
none supplies a valid DER witness or native output enforcement. The
[diagonal reduction](../../research/covenant-2026-09-17/continuation/r17_correlated_diagonal.md)
finds an exceptional all-s family when `rho=r*Z0/C` and
`Z0*V+256*C*G=O`, with a separately required third-key map. All 8,388,352
actual layout/flag cases for r=1..32767 fail its necessary small-rho test.
That bounded exclusion covers neither larger r nor the ordinary branch.
Both results are `locally-reproduced`, `unclassified`; the R16 independent
answer probability must not be applied to this shared hash.

## R18 closes all translations for the six endomorphism slopes

The [complete elimination](../../research/covenant-2026-09-17/continuation/r18_endomorphism_resultant.md)
excludes every nonzero affine translation with slope
`+/-1,+/-lambda,+/-lambda^2` carrying three secp256k1 recovery roots to
three recovery roots. Twelve resultants of degree at most 80 yield 29
field roots in aggregate; none satisfies its exact source integer branch.
The [independent audit](../../research/covenant-2026-09-17/continuation/r18_resultant_audit.md)
reconstructs the resultants via Euclidean remainders, verifies all Frobenius
gcds and root products, and includes positive small-curve controls with
other slopes. This is a complete exclusion for the six stated slopes,
not for arbitrary affine scalars. R17 therefore cannot choose its q merely
to make the induced slope one of those six values.

The [diagonal inverse generators](../../research/covenant-2026-09-17/continuation/r18_diagonal_solver.md)
solve the first exceptional predicate by quadratic inversion for rho or
unique inversion modulo `2^248` for an integer quotient. The reverse
certificate excludes rho=1..256 for every admissible source r and all eight
constant-SINGLE flags. The full enumeration-domain sizes are not expected
work or lower bounds; no midpoint or third-key candidate was found.

The separate [cross-input preimage result](../../research/covenant-2026-09-17/continuation/r18_mandatory_reference.md)
uses the surviving signature opcode to rule out an empty active legacy
scriptCode. Exact ordinary preimages cannot be shared by distinct inputs
within either the legacy or BIP143 hashing family. Constant SINGLE, hash
collisions, scalar relations and cross-format constructions are explicitly
outside that exclusion. All new R18 results are `locally-reproduced`,
deployment `unclassified`, with no new Core or complete covenant claim.

## R19 covers doubled slopes, including exceptional and zero translations

[R19](../../research/covenant-2026-09-17/continuation/r19_even_slopes.md)
excludes all affine three-root transports with slopes `+/-2*lambda^k`,
including zero translation. Twelve degree-39 polynomials, twelve degree-six
polynomials and three exceptional-denominator certificates cover every
case. The [independent audit](../../research/covenant-2026-09-17/continuation/r19_even_slopes_audit.md)
rebuilds all 27 certificates and includes four positive small-curve maps.
The B=3A exception is explicitly tested; clearing denominators alone loses
the target-gap condition there. Inverting maps also excludes
`+/-lambda^k/2`, but implies nothing about factor four or arbitrary slopes.
These are `locally-reproduced`, `unclassified` host results.

A [new pinned source inspection](../../research/covenant-2026-09-17/continuation/r19_reference_sources.md)
finds explicit execution binding in a BCH FRI-STARK verifier: the mandatory
input checks all other spent locking scripts and reads their shared data.
It uses native BCH introspection and CAT/SPLIT, which do not implement the
missing BTC interface. Its distinction between displayed witness bytes
and actually executed programs supplies a concrete test for future BTC
candidates. Source evidence is `inspected`; execution claims remain
`reported`, with no local or BTC execution attributed to them.

## R20 separates mandatory execution from shared data

The [funded mixed-input counterexample](../../research/covenant-2026-09-17/continuation/r20_taproot_reference_core.md)
spends the same NUMS Taproot output and same auxiliary P2SH checker with
two different valid ECDSA rows, while retaining exactly the same main
DEFAULT signature. Both 406-byte/1,147-WU variants are `policy-validated`,
evidence `differentially-validated`. DEFAULT commits input scripts but
omits their unlocking data. A fresh signature under the public leaf key
also authorizes replacement or omission of the helper; the old signature
rejects. All eight Core controls meet their expectations. This excludes
the claimed implication from input-script commitment to compulsory shared
data, not all possible multi-input constructions. A canonical transaction-
derived value or another explicit binding could change the premise.

The [new functional-signature source audit](../../research/covenant-2026-09-17/continuation/r20_functional_signature_spec.md)
inspects the full ePrint 2026/1346 specification: setup retains the ordinary
base signing key, while restricted keys constrain recipients without it.
Its guarantees do not constrain a setup creator retaining that key.
The [functional-adaptor implementation audit](../../research/covenant-2026-09-17/continuation/r20_reference_sources.md)
identifies the same retained-key boundary in another concrete codebase.
These are `inspected` source results, with any proposed BTC composition
`unclassified`. They do not establish that every functional-signature
approach is impossible or that an OP_RETURN transaction wrapper cannot work.

## R21 classifies canonical interfaces without supplying the native bridge

The [canonical-pair analysis](../../research/covenant-2026-09-17/continuation/r21_canonical_affine.md)
reuses the prior native uniqueness of `P+=(sR-zG)/r` and
`P-=(-sR-zG)/r`; it does not claim a new Core primitive. For fixed scalar
coefficients, `A=aP+ + bP- + cG=uR+vG`, with
`u=(a-b)s/r` and `v=c-(a+b)z/r`. Swapping the pair preserves a finite
x-only key exactly when **u=0 or v=0**. The first branch has a public
signing scalar. For fixed asymmetric coefficients, the second branch
holds at two distinct digests only if `a+b=c=0`, making the aggregate
digest-independent. Knowing the scalar of an aggregate with u nonzero
reveals the nonce logarithm; this is not a claim that one Schnorr signature
reveals that scalar or that every signing algorithm must compute it.

The nonlinear aggregate `F=H(P)P+H(Q)Q` is permutation-invariant
and can retain a nonzero R component. It escapes that fixed-coefficient
classification. No native binding from the actual auxiliary pair to the
main CHECKSIG key, or honest signer for that aggregate, is supplied.
Canonical auxiliary values do not become accessible to another input merely
because DEFAULT commits their spent locking script. Embedding the aggregate
after computing the native digest also reintroduces the funding dependency.

The [hash-weight cost analysis](../../research/covenant-2026-09-17/continuation/r21_hash_weight_cost.md)
and [independent audit](../../research/covenant-2026-09-17/continuation/r21_hash_weight_audit.md)
bound only cancellation of this aggregate's unknown-point coefficient.
For a source fixed before all point-hash answers, candidate pairs are edges
of a fixed degree-two translation graph, giving `min(1,2Q*pmax)` success;
a catalogue of M sources fixed beforehand gives `min(1,2MQ*pmax)`.
Here pmax is the maximum scalar hash-output probability. Q includes setup,
discarded candidates and both endpoint evaluations, including the final
verifier's queries. Selecting the source after observing hashes invalidates
the fixed-graph bound; the general bound is instead
`min(1,binom(Q,2)*pmax)`. At Q=2^64, ideal SHA256 reduced modulo n gives
2^-190 for one fixed source and less than 2^-128 for adaptive source choice;
ideal 160-bit hashes give 2^-95 and less than 2^-33 respectively. These
are ideal-oracle bounds on equal full hash weights, not all nonlinear
interfaces, native signing methods or known-nonce constructions.

The [one-short/two-long orbit interface](../../research/covenant-2026-09-17/continuation/r21_orbit_interface.md)
has a separate conditional extractor. If shared-key signatures already
have nonces `epsilon_i*lambda^j_i*R`, set
`a_i=epsilon_i*lambda^j_i*s_i/r_i`, `b_i=z_i/r_i`. Native verification
gives `K=a_i*R-b_i*G`: either both coefficients agree, or the transcript
computes `log_G(R)=(b_i-b_j)/(a_i-a_j)`. This formula does not authenticate
its orbit premise. Connected antipodal-pair graphs without such extraction
collapse to the same two keys; a four-key star is a reproduced positive
on the extraction branch. Non-antipodal short-signature recovery pairs
remain outside this statement.

For one 32-byte source signature on C=2^248 and a common antipodal key pair,
native checks force `ri/r0=zi/C`; the orbit additionally requires
`si/ri=+/-s0/(lambda^i*r0)`. Equal long-signature digests cannot complete
that orbit. For differing digests, its ordered target-pair support is at
most `2*(2^191-1+(p-n)-1)`, approximately 2^192. The approximately 2^-320
single-pair probability assumes independent uniform canonical digests
(the coarse reduced-256-bit bound is approximately 2^-318). Independence
of actual native contexts is not established, and this is not a general
adaptive-search bound.

R21's host controls and exact counts are `locally-reproduced`; its general
derivations are `inspected`, with deployment `unclassified`. There is no
new Script/Core execution, native bridge or complete covenant. A positive
continuation must enforce the aggregate/orbit relation on actual native
data, supply the honest signer and complete funding dependencies, and
establish the retained-state output work gap with all preparation charged.

## R22 supplies a constant-digest guard and a public Taproot edge

The [two-context SINGLE guard](../../research/covenant-2026-09-17/continuation/r22_single_guard.md)
is a positive native primitive. It checks one signature longer than 57
bytes under two distinct canonical compressed keys, before and after a
CODESEPARATOR. The length guard excludes four-root recovery, so the same
complete antipodal pair in both contexts forces equal digest scalars.
The processed scriptCodes are 48 and 13 bytes; their ordinary legacy
preimages differ for every non-bug flag. Acceptance therefore requires
the out-of-range SINGLE constant `C=2^248` or a collision of distinct
native hashes **after reduction modulo n**. The latter includes unequal
256-bit hashes differing by n, not only a bitwise hash collision. This is
a computational constant-digest guard, not an unconditional flag reader.
It admits all eight effective SINGLE flag bytes
`03,23,43,63,83,a3,c3,e3` and does not bind the outputs.

The [Core fixture](../../research/covenant-2026-09-17/continuation/r22_single_guard_core.json)
at Bitcoin Core 30.3 commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`
matches all ten expectations: four positive and six negative cases.
The positives include the identical witness with a different recipient,
SINGLE with ANYONECANPAY, and an undefined upper flag bit. Ordinary ALL,
NONE and in-range SINGLE, duplicate keys, a short signature and an
uncompressed key are rejected. Positive executions are
`differentially-validated` / `consensus-validated`; negative executions are
`differentially-validated` / `consensus-incompatible`. This is consensus-only:
default policy rejects legacy CODESEPARATOR, with a further flag-policy
failure for the undefined-flag positive. The collision argument is
`inspected`, and the 768 host flag/context checks are `locally-reproduced`.

For the complete positive fixture, the P2SH locking script is 23 bytes,
the redeem script is 49 bytes with 32 executed non-push opcodes and four
native ECDSA checks, and the outer P2SH adds two non-push opcodes. Redeem
entry has three non-hint data items, all present together; there are zero
hint items per invocation and in the complete fixture. Its combined
main-plus-alt-stack peak is six. The scriptSig has four pushes including
the redeem script and serializes to 190 bytes. A separate OP_TRUE P2WSH
helper input has one non-hint witness item and its own stack peak of one;
the complete spend therefore uses four data items across two executions.
The witness section is four bytes including the legacy input's empty
witness vector, with two additional marker/flag bytes: 313 base bytes,
319 total bytes and 1258 WU. These are raw consensus-boundary fixture
measurements, not compiler/library metrics.

This discharges the actual-C premise for long edges in the
[native path equations](../../research/covenant-2026-09-17/continuation/r22_native_relation.md),
subject to the reduced-hash collision assumption. For a fixed ALL source
pair `K±=±(s/r)R-(z/r)G`, an m-edge antipodal C path has
`S_m=sum((-1)^(m-i)/r_i)` and endpoint relation
`K_m=(-1)^m*K_0-2*C*S_m*G`. Closing it between the two source members gives
`z/r=C*S_m` for odd m, or `log_G(R)=C*r*S_m/s` for even m, with R oriented
by the first source key. These are necessary equations for complete valid
graphs, not arbitrary signing impossibility results. The denominators
must still be valid nonce coordinates with actual signatures. Odd-path
reversal does not order the source pair. A fixed catalogue of M literal C
signatures can distinguish it by membership only on at most 8M candidate
digest scalars; this does not cover variable-edge networks. These host
controls are `locally-reproduced` / `unclassified`, and the derivations are
`inspected`.

The [Taproot edge-first interface](../../research/covenant-2026-09-17/continuation/r22_taptweak_interface.md)
is separately constructive. For an even-y internal point I, a real tree
root M, and native valid tweak `t=H_TapTweak(x(I)||M)`, let `O=I+tG` and
`J=I+(t/2)G`. For public `a!=0`, set `R=J/a`, `r=x(R) mod n`,
`s=a*r mod n` and `z*=t*r/2 mod n`. With the stated nonzero/finite and
exactly-two-root conditions, this produces the full ECDSA recovery pair
`{I,-O}` without knowing either point's logarithm. All 64 deterministic
pairs pass, including all output/midpoint parity combinations, but z* is
manufactured. These are `locally-reproduced` / `unclassified` host vectors,
not native transaction witnesses. The simple `a=1` choice cannot itself be
an exact 20-/32-byte hash-derived signature because its strict DER plus
flag length is odd; that exclusion does not extend to general a.

The remaining native equation is
`z_native(T,input,scriptCode,flag)=(t/2)*(x((I+(t/2)G)/a) mod n) mod n`.
The control block authenticates its own endpoints but does not expose or
bind Script-readable copies used by a separate ECDSA input. A known
internal scalar also supplies an unrestricted key-path scalar. The next
constructive test is therefore either a composed guarded C graph with
valid witnesses for a real funded ALL digest and a fixed output reference,
or a solution to this TapTweak native equation with mandatory endpoint
binding and no retained-key bypass. Both must include funding dependencies,
complete resource costs and the retained-state output work gap. The guard's
exact three-item entry and distinct post-FindAndDelete scriptCodes must be
rechecked when composing it; it is not already a complete graph or covenant.
