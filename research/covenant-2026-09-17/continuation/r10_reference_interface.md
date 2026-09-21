# R10: constant-message and output-committing checks on the same input

Date: 2026-09-17. Question: can the universal three-key equality primitive
supply the missing mandatory reference context? Comparison objective: use
native ECDSA checks to connect a readable proof parameter to the actual
output-committing digest without an optional external verifier input.

**A SINGLE-bug check and a separate ALL check can coexist on the same locked
input.** Excluding this arrangement merely because SINGLE omits outputs would
be incorrect. The remaining obligation is the relation between their
signatures and keys. No complete reference evaluator or covenant is supplied.

Evidence: `locally-reproduced`. Deployment: `unclassified`. The reproduction
uses host serialization and secp256k1 equations on synthetic transactions.
It does not execute Script, mine a hash-derived signature, or claim a Core
result. Its raw scripts are boundary layouts, not policy-compiled repository
primitives. There are no changes to library code or field-arithmetic tests.

## 1. A constant native reference needs no external verifier

Let the locked input have index i and let the transaction have at most i
outputs. A legacy signature with `flag & 31 == 3` then uses digest bytes
`01` followed by 31 zero bytes. The ECDSA scalar is **C=2^248**, not 1.
A separate signature ending in `01` on that same input still commits every
output. The ordinary preceding inputs need to exist and be spendable, but
none has to execute an externally trusted reference computation.

The four deterministic output variants in the reproduction keep the SINGLE
digest constant and change the ALL digest. A second check tests all 256 flag
bytes against two different scriptCode suffixes: only the eight SINGLE flags
yield equal digest bytes in these fixtures.

More generally, require one shared signature alpha under three distinct
canonical compressed keys before and after CODESEPARATOR. The
[R9 exact theorem](r9_recovery_audit.md) makes the two digest **scalars** equal.
Out-of-range SINGLE supplies that equality deterministically. Other flags
would have to meet actual scalar equality; the predicate is not an exact
syntactic SINGLE-flag decoder. Its complete raw layout costs 76 bytes and
48 counted opcodes, with 4 entry data items (alpha plus three keys), 0 hints,
and combined main-plus-alt-stack peak 7. A proof-to-alpha hash computation
and any readable parameter checks would add their own costs.

In the constant case, CHECKSIG authenticates the recovery relation

```
P = (s_alpha R_alpha - C G) / r_alpha.
```

This is a useful native reference to a public function of alpha. It does not
make arbitrary arithmetic on alpha or its preimage readable in Script.

## 2. Explicitly equal numerical signatures give a full digest target

The new 123-byte/41-opcode raw layout embeds two literal signatures:
`DER(2,1)||03` and `DER(2,1)||01`. It checks both under three distinct
compressed keys. These are literal flag bytes, so no unimplemented signature
splitting or flag replacement is assumed. It consumes 3 key data items,
0 hints, peaks at 6 combined stack items, and leaves one truth value.
There is no complete spending transaction, so serialized scriptSig/witness
measurements are inapplicable rather than measured zero.

In the SINGLE-bug case the universal theorem forces `z_ALL=C mod n`.
Because `C+n >= 2^256`, precisely one 256-bit digest represents this scalar.
Thus a uniform fresh ALL digest hits it with probability `2^-256`; this
estimate concerns the literal target family, not every possible reference
construction. The four actual synthetic ALL digests do not meet it. Three
keys recovered at C verify the SINGLE checks and fail every ALL check in
these fixtures. The serializer accounts separately for signature-specific
FindAndDelete in the two literal contexts.

Changing a hash-derived alpha's trailing flag is still not supplied by this
layout. Two unconstrained witness signatures cannot be assumed to have equal
numerical `(r,s)` merely because their flags have different roles.

## 3. Different signatures: an exact constructive pair relation

Suppose alpha and beta each have exactly two nonce recovery roots, and both
verify under the same two distinct keys P,Q. Their verification-key sets are

```
{ -C/r_alpha G +/- (s_alpha/r_alpha) R_alpha }
{ -z/r_beta G +/- (s_beta/r_beta) R_beta }.
```

Taking their sums and differences gives the necessary and sufficient pair
conditions

```
z/r_beta = C/r_alpha                         (mod n)
(s_beta/r_beta) R_beta = +/- (s_alpha/r_alpha) R_alpha.
```

This is constructive: choose `R_beta=t R_alpha`, take
`s_beta=r_beta*s_alpha/(r_alpha*t)` up to sign, and the corresponding target
is `z=(r_beta/r_alpha)C`. Sixteen deterministic full-size secp256k1 vectors
verify both signatures under both keys; changing the target by one breaks
the double acceptance. All nonce x coordinates in these vectors exceed
`p-n`, so a hidden `r+n` branch is excluded explicitly.

This does not yet cheaply fit an actual transaction. If alpha and an actual
ALL scalar z are fixed, the required x coordinate is
`r_beta=(z/C)r_alpha`. Lifting that x coordinate is insufficient to compute
the required scalar ratio between its nonce point and R_alpha. Conversely,
choosing the known ratio t first fixes a target z which the actual ALL digest
must match. No general work lower bound for every joint search is inferred.

Four-root recovery sets can select nonsymmetric key pairs, so their centers
need not be the simple `-z/r G`. The separate
[parallel-cycle analysis](r10_parallel_cycles.md) retains those extra pair
states; the two-root equations here must not be applied to them silently.

## Reproduction and source

```
python3 research/covenant-2026-09-17/continuation/r10_reference_interface.py
```

The [JSON](r10_reference_interface.json) records all flag cases, exact raw
scripts and scriptCodes, digest scalars, keys and scaling vectors. The
independent audit in [the parallel-cycle reproduction](r10_parallel_cycles.py)
reconstructs all 256 flag cases, four output variants, the two 93-byte
signature-specific scriptCodes, the 123-byte/41-opcode literal stack layout
at its synthetic target, and all sixteen scaling vectors. It found no
critical discrepancies; this audit shares the existing EC arithmetic helper
and is not an independent Bitcoin Core execution. The
authoritative legacy semantics remain Bitcoin Core
[`49faec4f87f5cd19c88db01a82e5c68b087c8227`, interpreter.cpp](https://raw.githubusercontent.com/bitcoin/bitcoin/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).
The useful next step is an actual readable-parameter-to-ALL relation through
this same-input interface, including all recovery branches and full search
cost. Merely repeating the literal digest target is not that step.
