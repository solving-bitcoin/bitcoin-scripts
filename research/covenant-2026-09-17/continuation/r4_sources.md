# Round 4: newly found primary sources

Question: do these sources supply a compulsory native transaction binding plus
a complete verifier for exact outputs, with honest total work below `2^64` and
security even when the creator retains every setup secret?

Result: none supplies that construction. They add useful implementation leads,
and one corrects the apparent strength of an advertised end-to-end test. This
is source inspection, not a local reproduction or a proof of impossibility.

## Immutable source identities

Inspected 2026-09-17:

- Barbacovi and Larraia, [Enforcing arbitrary constraints on Bitcoin
  transactions](https://eprint.iacr.org/2025/912.pdf), ePrint 2025/912, received
  2025-05-21 and approved 2025-05-23. Download SHA-256:
  `fd1e76e87307d95bf28ff5be32ef243516addad15c0a540a68f051c7d0c4b669`.
  The archive version-list endpoint did not resolve; this hash pins the actual
  13-page PDF read, without inventing a version number.
- [AppliedPQC/bitcoin-stark-verifier](https://github.com/AppliedPQC/bitcoin-stark-verifier/tree/3d6a2d37f48456808d2b25dab3b31b94b768c838),
  commit `3d6a2d37f48456808d2b25dab3b31b94b768c838`, dated 2026-08-10.
- [bitlayer-org/tap-stark](https://github.com/bitlayer-org/tap-stark/tree/781a6349c7b658d3475dba235e12d2508d7e7a0f),
  commit `781a6349c7b658d3475dba235e12d2508d7e7a0f`, dated 2024-12-12.

Both repositories were cloned read-only into `/tmp` for inspection. No remote
tests were executed, no Bitcoin transaction was broadcast, and no repository
primitive or metric snapshot was changed. Local catalog searches `covenant`
and `stark` returned no records; that is a coverage observation only.

## The ePrint paper: an explicit BSV construction

Section 2.2, footnote 7 explicitly restricts its implementation to BSV, with
large-number arithmetic and string manipulation. Its useful protocol structure
is to put an integrity tag into the SNARK public statement, prove privately
that it commits to the allowed transaction, and verify that same tag natively.
Section 3.6 instantiates the tag as the sighash. The script constructs an ECDSA
signature using public constants `d=k=1`, then checks it against the actual
transaction and generator public key. A CODESEPARATOR shortens the scriptCode
that the circuit must hash. The SNARK verifier is Groth16.

This is a concrete articulation of the desired two-part verification relation,
but the tag-to-signature conversion is the missing operation for the present
BTC search. It requires operations BSV provides; its script and Groth16 budget
are not established under BTC's limits. Nor does the paper establish security
when the SNARK setup creator retains all trapdoor state. Evidence `inspected`;
deployment for the proposed BTC composition `unclassified`. These findings do
not establish a new BTC-native encoding construction.

## AppliedPQC: algebraic hashing is real, full native binding is absent

The concrete no-CAT representation is useful: eight KoalaBear field elements
form a digest; two digests become the sixteen inputs to a Poseidon2 permutation.
Merkle compression therefore needs arithmetic on separate stack items, without
concatenating byte strings. The source includes transcript squeezing, sumcheck,
query opening, multilinear evaluation and the final weighted identity. It
does not give a conversion from a natively checked ECDSA/Schnorr byte string to
the same authenticated field-element statement. Algebraic hashing answers a
different boundary question from native transaction binding.

The [budget and chunk implementation](https://github.com/AppliedPQC/bitcoin-stark-verifier/blob/3d6a2d37f48456808d2b25dab3b31b94b768c838/poseidon2/src/disprove.rs)
makes the intended deployment concrete: publish intermediate states and permit
a challenger to execute a bad transition, not every transition. The published
example verifier has roughly 1.24 GB of script. A permutation is reported as
572,228 bytes. These whole-verifier sizes exceed even the 4,000,000-WU block
budget, so the full examples are `consensus-incompatible`. Fragment execution
cannot change this classification.

### What “end to end” actually tests

Read
[`whir/tests/end_to_end.rs`](https://github.com/AppliedPQC/bitcoin-stark-verifier/blob/3d6a2d37f48456808d2b25dab3b31b94b768c838/whir/tests/end_to_end.rs#L451)
before treating the README as complete verifier evidence.
`full_proof_verifies_as_one_script` sets `SECURITY_LEVEL=1`, obtains one query,
and generates a bespoke script. It never calls `verifier::verify_and_close`.
The queried root, leaf and path index are inserted by the host; `state0` is a
custom deterministic state rather than the prover's complete transcript; the
starting claim is one. The host computes

```
claimed = sumcheck_claim_after_custom_transcript * f(custom_point)
```

and supplies `claimed` to the generated equality check. Perturbation tests
retain the previously computed target. This is useful composition evidence for
pieces driven by real proof data, but does not establish complete, sound
verification of the native Plonky3 statement against hostile witness inputs.
The existence of a separately implemented `verify_and_close` is not evidence
that this end-to-end test exercised it. The source's own review additionally
discloses differences in batching and initial-constraint handling.

The default tests call the Wildlife Sanctuary executor, whose stack limit is
disabled according to the repository's own alternate-executor test. Consequently
their execution deployment class is `research-unlimited`. The separate
[`poseidon2/tests/bitvm_executor.rs`](https://github.com/AppliedPQC/bitcoin-stark-verifier/blob/3d6a2d37f48456808d2b25dab3b31b94b768c838/poseidon2/tests/bitvm_executor.rs)
enables the stack limit in Tapscript for field/permutation vectors, with a dummy
empty transaction and no witness items. That does not establish full-transaction
consensus validity, full-verifier stack bounds, or policy validity.

Dependency pins in its Cargo.lock are compiler `2f2510ab9e616eaae5b0db807d13c40eae6964a0`,
Wildlife Sanctuary executor `fe203d2ae6c80e7f5a2dde5f852d9a98c4baa296`,
BitVM executor `ba96bc2bd76774c9d1b011461cb79d983c2c43a1`, and Plonky3
`3f8be41aaa578ef5e2a027004698e678e9e74d5b`. All numerical costs here are
`reported`; source-path findings are `inspected`. No costs were recomputed with
Bitcoin Lab's centralized compilation policy.

### The exact state-commitment boundary

[`winternitz.rs`](https://github.com/AppliedPQC/bitcoin-stark-verifier/blob/3d6a2d37f48456808d2b25dab3b31b94b768c838/poseidon2/src/winternitz.rs)
uses sixteen field values, eight base-16 digits per value, and three checksum
digits: 131 chains per state. Each chain supplies a hash-chain value and a digit,
so there are **262 witness items per state, 524 for both endpoints**. They
coexist at entry. The endpoint pair has 262 hash-chain signature elements and
262 digit elements; if auxiliary authentication data are called hints, all 524
are such items at the chunk boundary, not 262. The older comment in
`round_committed` claiming 262 for the pair contradicts the implementation and
updated README. Arithmetic adds no separate witness hints in this boundary.

The reported 22-round chunk script is 395,916 bytes. No complete serialized
witness, transaction, executed opcode count or combined stack peak was locally
measured, and script length below 400,000 alone does not prove relay acceptance.
In fact, its standard-policy budget claim fails even a lower bound for the
documented honest witness: the 262 twenty-byte chain values need at least
`262 * 21` serialized bytes, and the 262 digits need at least `262 * 1` bytes
(even pretending every digit is empty). Thus script plus these items already
costs `395916 + 5764 = 401680` WU, before witness count, script length prefix,
control block, or transaction overhead. `max_chunk_len` compares the script's
`.len()` alone with its argument; it does not price this witness. This is a
source-derived lower-bound calculation, not a local transaction measurement.
The chunk's input and output keys are compiled into its script; the first decoded
state is parked on the altstack while the second signature is checked. The
complete stack bound must include all 524 entry items, decoded states, and
Winternitz/arithmetic temporaries. Thus 524 is an entry count, not the peak.

For retained creator state, every secret chain start permits signing every
state. WOTS here authenticates a prover's assertion; it does not make that
assertion mathematically true. A mandatory challenge/response transaction
protocol is needed to turn a false trace into a losing execution. None of this
source supplies the requested compulsory successful whole-verifier check on
the same covenant spend. Honest setup under `2^64` cannot cure that binding gap.

## TapSTARK: real Taptree rows, with explicit external composition

The
[`basic/src/tcs/mod.rs`](https://github.com/bitlayer-org/tap-stark/blob/781a6349c7b658d3475dba235e12d2508d7e7a0f/basic/src/tcs/mod.rs)
leaf generator hardcodes the selected row index and row values and checks them
against bit-commitment openings. This is stronger than a freely supplied row:
executing that committed leaf validates that row. `commit_poly_with_query_times`
builds a separate tree for every query. The host `verify_proof` checks inclusion
and executes the leaf as two separate operations. It does not implement native
on-chain verification of an arbitrary witness-supplied root inside another
locking script. Types explicitly carry `SecretGen` and `BCommitWithSecret`.

The advertised architecture is BitVM2 plus Taptree commitments. Its README
reports multi-megabyte Fibonacci verifier totals and a 129.44-MB recursive-RISC0
estimate. These are unsuitable as single full-verifier BTC spends; fragments
and dispute protocols require their own deployment assessment. Their reported
intermediate `u32` counts are not explicit complete-witness item counts or stack
peaks. No such counts were inferred here.

The useful lead is native authentication of one committed row per query tree.
The remaining acceptance criterion is precise: show a transaction graph which
compulsorily executes every required root/row/transcript consistency check and
the native exact-output binding, without trusting any retained commitment
secret or allowing the spender to replace/omit a verifier input. These sources
do not meet that criterion.
