# Transaction introspection with Binohash

Binohash is an external reported construction whose primary source uses legacy
signature behavior and proof-of-work grinding to expose a collision-resistant
transaction digest to Script without a consensus change.

```text
Transaction mutations and legacy sighash
├── FindAndDelete / OP_CHECKMULTISIG behavior
├── subset and nonce grinding
├── two-round digest extraction
├── Script-readable digest
└── Lamport authentication into a later verification protocol
```

The repository now has a narrow host-side [legacy core reproduction](../primitives/binohash-legacy-core.md)
for opcode-boundary deletion, subset-dependent legacy sighashes, and the
`SIGHASH_SINGLE` bug constant. It does not implement the two-round grinding
protocol, ECDSA nonce generation, or a complete legacy spend. Do not model
Binohash with the default tapscript executor: its legacy signature context and
transaction template are essential semantics. Full reproduction still requires
a pinned Bitcoin Core regtest, exact grinding parameters, mutation constraints,
and complete transaction costs. See `introspection/binohash` and `OP-011`.

A digest extraction protocol is not automatically a covenant against a
creator retaining all authentication secrets. The separate
[secretless exact-output investigation](../../research/covenant-2026-09-17/README.md)
checks this stronger requirement, reproduces a free-signature counterexample
and a DER-only gate against Bitcoin Core, and leaves the complete asymmetric
binding open under OP-021. Its scoped negative results are NR-057.

The [seven-direction continuation](../../research/covenant-2026-09-17/seven/README.md)
improves the native nonce encoding and adds Core-checked routing and recovery
relations. A readable digest and a public common root still require mandatory
evaluation of the intended transaction; retained HORS keys do not invalidate
the digest's collision resistance by themselves.

The [ongoing continuation](../../research/covenant-2026-09-17/continuation/STATE.md)
adds a pinning-aware analysis of proof-query subsets, an ECDSA/Taproot/Schnorr
hybrid calculation, and inspected source boundaries for further no-CAT
verifiers. None yet supplies the mandatory reference evaluation.

The [R6 length-puzzle calculation](../../research/covenant-2026-09-17/continuation/r6_length_puzzle.md)
counts modular wrap and nonce-sign normalization in the public `s=2(z+1)`
strategy. For an exact 55-byte signature its uniform-digest hit probability
is `255/2^48`, or about `2^40.006` expected queries, rather than the paper's
zero-prefix strategy of about `2^42`. The 59-byte analogue was exercised in
four distinct hit intervals against Core, all passing policy. The 55-byte
count is analytical, not a mined witness. Full Binohash collision accounting
has not been recalculated; QSB's separate hash-to-DER probability is unchanged.

The [R8 portfolio join](../../research/covenant-2026-09-17/continuation/r8_batch_incidence.md)
uses small public nonce scalars to filter native digests by modular intervals
before testing congruences. It avoids the naive pair scan in the specified
family. Four real 70-byte signatures found by the join pass
[Core consensus and policy](../../research/covenant-2026-09-17/continuation/r8_batch_core.md).
These are small-work native fixtures, not a 55-byte search or a completed
Binohash collision analysis. Full expected work and mandatory nonce/output
binding remain open; actual bucket operations and offline memory must be
included, not just digest samples.

The [R9 recovery-set theorem](../../research/covenant-2026-09-17/continuation/r9_recovery_audit.md)
shows that three distinct group keys verifying one shared ECDSA signature in
each of two contexts force the digest scalars equal, for all r and s. It
removes the earlier second-x exception through complete curve-specific
polynomial certificates. Its variable-signature
[Core boundary fixtures](../../research/covenant-2026-09-17/continuation/r9_recovery_core.md)
exercise a 75-byte/47-opcode same-context layout. This improves the native
equality interface; it still needs a mandatory reference computation and
does not make hash bytes readable to ordinary Script arithmetic.

The [R10 same-input analysis](../../research/covenant-2026-09-17/continuation/r10_reference_interface.md)
confirms that a legacy SINGLE-bug signature and a separate ALL signature can
coexist on one locked input. The bug's ECDSA scalar is `2^248`. Three common
keys for equal numerical signatures force the ALL digest to this full
target; different signatures need an additional nonce-point relation.
The [143-opcode packed-seed candidate](../../research/covenant-2026-09-17/continuation/r10_parameter_frontier.md)
binds an exact small affine function, but its function variables are not yet
bound to native transaction data. Both are host-only research results,
`locally-reproduced` and `unclassified`, not complete transaction introspection.

[R11's endomorphism lattice](../../research/covenant-2026-09-17/continuation/r11_endomorphism.md)
constructs free SINGLE/ALL signature pairs after the actual ALL digest is
known, using a known relation between nonce points rather than their
individual logarithms. Three recomputed witnesses for different outputs of
the same funded outpoint pass [Core consensus and policy](../../research/covenant-2026-09-17/continuation/r11_endomorphism_core.md);
three negative cases fail. The 44-byte/27-opcode interface still has no
hash-root reference or exact-output asymmetry. A separate
[literal recovery-table lookup](../../research/covenant-2026-09-17/continuation/r11_lookup_reference.md)
does bind native messages to rows, but its table construction remains
circular through the funding txid even after removing the table from scriptCode.

[R12](../../research/covenant-2026-09-17/continuation/r12_live_reference.md)
hashes the actual full-length signature and binds that hash in a 55-byte,
35-opcode raw predicate. Its large public scalar family defers curve work
until after hash filtering, but the hash has no readable intended-output
reference and changing the scalar also changes the authenticated signature.
This host-only result does not increase L for a fixed root.

The [R13/R14 orbit investigation](../../research/covenant-2026-09-17/continuation/r13_orbit_query.md)
isolates another useful host identity, `x0+x1+x2=h*p`, from the native
predicate needed to authenticate it. The supplied h is free in the tested
six-CHECKSIG layout. When all three r fit hash-sized DER signatures,
[complete enumeration](../../research/covenant-2026-09-17/continuation/r14_orbit_observable.md)
leaves only one coordinate orbit and a fixed h=2. Full-length variants are
outside that enumeration; two proposed denser key graphs have
[separate algebraic obstructions](../../research/covenant-2026-09-17/continuation/r14_orbit_binding.md).

Moving the ECDSA table directly into tapscript is
[demonstrably insufficient under Core](../../research/covenant-2026-09-17/continuation/r13_table_commitment.md):
33-byte keys trigger unknown-key behavior rather than ECDSA verification.
Moving its commitment into earlier mandatory SegWit stages preserves the
[funding-dependency cycle](../../research/covenant-2026-09-17/continuation/r14_table_chronology.md).
Neither result establishes a generic lower bound for another verifier or
for a fully charged simultaneous-construction algorithm.

For three common recovery keys across different signatures,
[R15](../../research/covenant-2026-09-17/continuation/r15_three_common_keys.md)
reduces the unmatched antipodal-pair case to a quartic for each fixed
public affine translation. Exhaustive small curves reproduce nonzero-offset
matches. This is a host candidate test, not an executed native query or
a complete reference evaluator.

[R16](../../research/covenant-2026-09-17/continuation/r16_three_key_support.md)
strengthens this to an exact digest-support statement: at most five pair
centers times `p-n-1` possible target r values for each fixed alpha. Its
query bound excludes a practical search below `2^64` only within the
stated independent-answer model, not arbitrary correlated constructions.
The [native translation equation](../../research/covenant-2026-09-17/continuation/r16_native_translation.md)
is `rj*(si*V-C*G)=-ri*z_ALL*G`. Small-curve positive examples use actual
transaction hashes, but neither their logarithm table nor their projected
source signature supplies the missing Bitcoin construction. Both results
are `locally-reproduced`, `unclassified`.

[R17](../../research/covenant-2026-09-17/continuation/r17_shared_source.md)
makes the shared-answer case explicit using the inner SHA256 digest of the
actual legacy preimage as a witness item. This avoids an independent hash
match for honest generation; it does not authenticate that provenance.
The [raw-DER diagonal](../../research/covenant-2026-09-17/continuation/r17_correlated_diagonal.md)
has a conditional whole-s family and a separate necessary third-key map.
No Bitcoin witness or required-output advantage is established. These are
`locally-reproduced`, `unclassified` host results.

[R18's complete coordinate elimination](../../research/covenant-2026-09-17/continuation/r18_endomorphism_resultant.md)
rules out all nonzero translations with slopes `+/-lambda^k` for the
three-recovery-root interface. Its independent resultant/Frobenius audit
does not extend that conclusion to arbitrary scalars. The
[reverse diagonal algorithms](../../research/covenant-2026-09-17/continuation/r18_diagonal_solver.md)
make another necessary condition executable but produce no valid candidate.
Separately, the [actual-input preimage lemma](../../research/covenant-2026-09-17/continuation/r18_mandatory_reference.md)
excludes free exact-preimage reuse across distinct input executions within
either ECDSA hashing family. None of these host results supplies the missing
mandatory reference or changes the deployment class from `unclassified`.

[R19](../../research/covenant-2026-09-17/continuation/r19_even_slopes.md)
extends the exact slope exclusions to `+/-2*lambda^k` and their inverses,
including zero translations and exceptional denominators. General slopes
remain open. The [new BCH comparison](../../research/covenant-2026-09-17/continuation/r19_reference_sources.md)
pinpoints another unresolved interface: its mandatory verifier authenticates
all consumed locking scripts and reads common transcript bytes. Those
operations rely on BCH introspection/CAT/SPLIT; importing its proof
arithmetic does not supply that enforcement on BTC.

[R20](../../research/covenant-2026-09-17/continuation/r20_taproot_reference_core.md)
reproduces the missing BTC connection on funded Core transactions: the same
DEFAULT signature accepts two different auxiliary ECDSA rows under the
same actually executed P2SH program. Both are `policy-validated`, evidence
`differentially-validated`. Separate stale/fresh-signature controls show
that retained signing authority can also replace or omit the helper.
Forced execution and semantic data equality remain separate dependencies.
The [full functional-signature source audit](../../research/covenant-2026-09-17/continuation/r20_functional_signature_spec.md)
finds an explicit unrestricted master signing key in the examined compiler;
its recipient restrictions do not enforce this creator-retained-state
covenant. This source result is `inspected`, composition `unclassified`.

[R21's canonical interface](../../research/covenant-2026-09-17/continuation/r21_canonical_affine.md)
reuses the already unique unordered ECDSA recovery pair. Uniqueness removes
arbitrary auxiliary-row choice, but does not transfer that pair into the
main input's stack or bind a main Schnorr key to it. For a fixed affine
aggregate `uR+vG`, swapping the pair preserves its finite x-only key when
u=0 **or** v=0. The fixed-coefficient alternatives yield a public signing
scalar or, for an asymmetric aggregate invariant at two distinct digests,
a digest-independent key. The nonlinear function `H(P)P+H(Q)Q` avoids that
classification; its native representation binding and honest signer remain
missing. Computing its scalar would expose the nonce logarithm when the
R coefficient is nonzero; a single signature is not claimed to do so.

For that nonlinear aggregate's cancellation branch, the
[cost analysis](../../research/covenant-2026-09-17/continuation/r21_hash_weight_cost.md)
and [independent audit](../../research/covenant-2026-09-17/continuation/r21_hash_weight_audit.md)
give `2Q*pmax` for one source fixed before every point-hash query. Adaptive
source selection instead uses the general `binom(Q,2)*pmax` collision
bound, capped at one. Setup, discarded trials and both endpoint evaluations
must count, including verification of a final returned candidate. These
ideal-oracle bounds cover equal full hash weights, not every nonlinear
interface or signing algorithm.

The [R21 orbit interface](../../research/covenant-2026-09-17/continuation/r21_orbit_interface.md)
also separates an algebraic relation from its native enforcement. Its
shared-key nonce-log extractor assumes the claimed orbit. Without that
extraction, connected antipodal-pair graphs collapse to one common pair;
non-antipodal short-signature branches are outside the lemma. In the
common-pair one-short/two-long case, equal long-signature digests cannot
complete an orbit, and differing digests have at most about 2^192 ordered
target pairs. Probability estimates require the stated independent-digest
model, which is not established for arbitrary native contexts.

These R21 controls are `locally-reproduced`, the general derivations
`inspected`, and deployment `unclassified`; they include no new Core
execution or complete covenant. The next dependency to implement is a
mandatory native binding from the auxiliary pair or nonce relation to the
main reference, with an honest signer, complete funding bytes and total-work
accounting under retained creator state. The explicit acceptance criteria
remain in [OP-021](../open-problems.md#op-021--secretless-exact-output-covenant-under-264-work).

R22 adds a native building block to this dependency chain. The
[two-context SINGLE guard](../../research/covenant-2026-09-17/continuation/r22_single_guard.md)
checks the same greater-than-57-byte ECDSA signature under two distinct
canonical compressed keys in two CODESEPARATOR contexts. The length bound
forces antipodal recovery; equal key pairs then force equal digest
scalars. Since the ordinary processed preimages differ, acceptance means
the out-of-range SINGLE constant C or a collision of distinct native
hashes modulo n, including hashes differing by n. It admits all eight
effective SINGLE flags and does not commit outputs.

The complete guard redeem script is 49 bytes, executes 32 non-push opcodes
and four native ECDSA checks, and has three non-hint entry items and a
combined stack peak of six. It has zero hint items per invocation and
complete fixture; all three entry items coexist. Its separate helper
input has one non-hint witness item on its own stack. Full P2SH, scriptSig
and transaction metrics are in the linked report. All
[ten Core cases](../../research/covenant-2026-09-17/continuation/r22_single_guard_core.json)
match expectations: four positive (`differentially-validated` /
`consensus-validated`) and six negative (`differentially-validated` /
`consensus-incompatible`). The unchanged witness passes with a changed
recipient. Default policy rejects legacy CODESEPARATOR, so this is
consensus-only evidence. The general reduced-hash argument is `inspected`.

This supplies the actual-C premise for long edges in the
[native path interface](../../research/covenant-2026-09-17/continuation/r22_native_relation.md).
For a fixed ALL recovery pair `K±=±(s/r)R-(z/r)G`, a valid antipodal C path
between its endpoints requires `z/r=C*S_m` when m is odd and extracts
`log_G(R)=C*r*S_m/s` when m is even, with
`S_m=sum((-1)^(m-i)/r_i)` and an oriented R. These necessary equations
still require valid nonce-coordinate/signature witnesses. They neither
order the pair under odd-path reversal nor establish an output reference.
Composition must revalidate the guard's entry shape and the actual
post-FindAndDelete scriptCodes; the tested isolated guard is not already
a graph implementation.

The separate [Taproot edge interface](../../research/covenant-2026-09-17/continuation/r22_taptweak_interface.md)
constructs a public ECDSA pair from a real opening. With even-y internal I,
tree root M, valid native tweak t and `O=I+tG`, choose public `a!=0` and set
`R=(I+(t/2)G)/a`, `r=x(R) mod n`, `s=a*r mod n`, `z*=t*r/2 mod n`.
All 64 host cases give the complete pair `{I,-O}` after checking finite
distinct keys and exactly two nonce roots. They are
`locally-reproduced` / `unclassified` manufactured-digest controls, not
native spend witnesses. The missing equation remains
`z_native(T,input,scriptCode,flag)=(t/2)*(x((I+(t/2)G)/a) mod n) mod n`.
The native control block authenticates its own endpoints, not witness
copies consumed by another input; compulsory endpoint binding is still
needed. Knowledge of I's scalar also permits an unrestricted key-path
spend. The constructive next steps are a guarded C graph with actual
funded signatures and an output reference, or this TapTweak equation plus
endpoint binding, followed in either case by an honest signer and a
retained-state output work advantage within the complete resource bounds.
