# R9: use a proof hash directly as a Schnorr public key

Date: 2026-09-17. Question: can Tapscript consume `SHA256(proof)` directly as
a 32-byte x-only key, removing DER mining while obtaining a mandatory
reference check and honest total work below `2^64`?

**The native conversion and an acyclic funding order work. A cheap signing
solver with an output-specific advantage has not been found.** This is a
real change of primitive: roughly half of the hash roots lift to public
keys, and a short native fragment forces 64-byte DEFAULT signatures. But a
liftable hash root normally has an unknown discrete logarithm. The known-log
and known-nonce solvers considered below disclose a reusable signing scalar;
the unknown-log affine-nonce candidate requires a full challenge condition.
These are scoped results, not a universal lower bound for all ways to use
native Schnorr equations in a reference verifier.

Host experiments are `locally-reproduced`; deployment is `unclassified`.
The raw layout and resource counts are `inspected`. No successful full-size
signature under any of the actual SHA256-derived keys was generated, and
no Bitcoin Core or repository Script interpreter was run. Real-curve
equations, a conditional known-key replay check, and a tiny-curve complete
solver are explicitly separated in the results. No Rust or field-arithmetic
tests were run.

## A concrete native fragment, with DEFAULT enforced

For entry stack `[sigma, proof]`, the raw Tapscript leaf is

```
OP_SWAP OP_SIZE <64> OP_EQUALVERIFY OP_SWAP OP_SHA256 OP_CHECKSIG
```

Hex: `7c820140887ca8ac`.

The size test applies to the signature, and the hash output becomes the
native public key. Therefore it cannot use the successful-check behavior
reserved for unknown public-key lengths. An invalid x coordinate fails
Schnorr verification; it does not produce a usable empty success bit. The
exact 64-byte signature selects DEFAULT and excludes explicit NONE, SINGLE
and ANYONECANPAY encodings. These semantics follow
[BIP342 at commit 24e96e870fffaa257b465ce1f0370c14aac588e8](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0342.mediawiki).

Raw boundary counts, without repository compilation:

| Boundary | Count |
| --- | ---: |
| Leaf bytes | 8 |
| Non-push opcodes | 6 |
| Entry data items | 2 |
| Additional hint items | 0 |
| Combined main-plus-alt-stack peak | 4 |
| Nonempty signature budget consumed | 50 |
| Complete witness items, one leaf and 33-byte control block | 4 |
| Serialized witness for proof length L <= 252 | 110 + L bytes |

Both data items coexist at entry, and the altstack is unused. The fragment
consumes both inputs and leaves the native signature result. The proof item
still obeys the 520-byte element limit; the displayed witness formula changes
at CompactSize boundaries. These are layout/serialization counts, not a
consensus or policy verdict on a successful transaction. The sample has no
complete successful witness.

The experiment hashes 512 deterministic proof candidates. **242 roots lift
to even secp256k1 points; 270 do not.** This confirms that the DER format gate
has disappeared, not that these keys can be signed for. None of their
discrete logarithms is known by the experiment.

## The witness-key funding order is genuinely acyclic

Use a fixed NUMS internal key and this single leaf to commit the protected
funding output. Then:

1. Fix the actual funding output, transaction and spending outpoint.
2. Choose the prescribed spending outputs and calculate the native
   BIP341/342 message m.
3. Choose proof, compute `P=lift_x(SHA256(proof))`, and attempt a signature
   under P on m.

Changing proof or its derived key does **not** change the funded scriptPubKey
or this leaf. It changes the BIP340 challenge, which includes P, but not the
already fixed BIP341 message m. Thus the base proposal does not have the
key-in-funding loop from the old TapTweak hybrid. The experiment constructs
the actual DEFAULT sighash preimages for two output lists sharing a funded
program and outpoint; only the funding ancestor is synthetic. All eight
sampled proof keys use that same fixed context.

If a later proposal embeds a proof-specific key or root into the leaf, that
changes this dependency graph. If it leaves proof as witness data, its
mandatory reference computation and connection to the native message still
need to be supplied. The eight-byte leaf currently proves authorization under
the proof-derived key, not correctness of an output reference computation.

## Known-log matching gives a signing algorithm, followed by retained-key replay

One concrete strategy generates known public scalars d_j and their even
x-only keys, and separately hashes candidate proofs until

```
SHA256(proof_i) = x(d_j*G).
```

Once such a match is found, ordinary Schnorr signing gives a valid witness.
For M distinct known-key x coordinates and Q fresh ideal hash queries, the
expected match count is `M*Q/2^256`. Charging both tables, even with EC work,
memory and proof generation free, `M+Q <= 2^64` gives at most `2^−130`
expected matches. The usual balanced strategy needs about `2^128` entries
per side for an order-one expectation. This is an independent matching
strategy estimate, not a lower bound for all adaptive solvers.

Another actual algorithm is to lift a proof hash and solve its discrete log
with baby-step/giant-step, then sign. The generic algorithm has square-root
group-order work and table size, roughly `2^128` for secp256k1 before other
costs. This is a description of that algorithm, not an unconditional lower
bound. The separate small-curve fixture implements it fully: over F211,
order 199, the first adapted hash key is `(142,206)`. Fifteen baby entries
and three giant lookups recover scalar 40, after which **the same proof
accepts signatures for both output lists**. The adapter reduces SHA256 to
the tiny coordinate field; its signatures are not Bitcoin encodings or a
full-size Bitcoin reproduction.

More importantly, a successful known-log method does not make a covenant:
the creator keeps d_j, reuses exactly the same proof/root, and signs a fresh
DEFAULT signature for a different output list. DEFAULT commits each
signature to its outputs, but does not prohibit signing another message.
Even a pure check that the unchanged proof is internally valid is insufficient
unless that check also authenticates the actual native message.

This observation also applies when the signer claims not to retain the key
but knows its nonce scalar k. From an accepted signature under P=dG,

```
s = k + e*d mod n,       e = H_BIP0340/challenge(x(R)||x(P)||m) mod n,
```

one obtains

```
d = (s−k)/e mod n              when e != 0.
```

Here k is the scalar of the normalized even nonce R, not an unadjusted
pre-normalization scalar. The challenge-zero exception is a separate rare
event, not a general signing algorithm.

The real-curve fixture verifies this extraction for four explicit retained
public scalars and both actual DEFAULT messages: **eight BIP340 host
signature checks**. These keys are not claimed to be known hash images, so
those checks do not constitute successful witnesses for the full hash-key
leaf. They reproduce the conditional algebra: if the known-log/known-nonce
step succeeds for a hash root, keeping the resulting scalar permits the
output change without repeating the hash search.

## Unknown-log affine nonces: a concrete cancellation candidate

For a real hash-derived point P with unknown logarithm, choose known a,b and
construct a nonce point

```
R0 = a*G + b*P.
R  = rho*R0,   rho in {+1,−1}, chosen so R has even y.
```

The native verification equation becomes

```
s*G = R + e*P = rho*a*G + (rho*b+e)*P.
```

There is a public cancellation witness `s=rho*a` precisely when

```
e = −rho*b mod n.
```

The coefficient b may vary freely between attempts; it is not restricted to
the previous TapTweak hybrid's targets ±1. Nonetheless, once a,b,proof,m and
the even nonce R have been fixed, the target must be met by the actual
challenge hashing R, P and m. In a model with a fresh independent challenge
query after those choices, any target scalar has at most two 256-bit hash
representations, giving success at most `2/2^256` per attempt and at most
`2^−191` in `2^64` attempts. Point operations, proof generation, funding and
verification are uncharged in that favorable count.

The experiment tries six a,b pairs under each of eight genuine SHA256-derived
keys. All **48 artificial target-challenge equations** hold; all 48 actual
BIP340 challenges reject. It includes b=0, a=0, and both parity signs. No
artificial challenge is represented as an accepted Bitcoin signature.

Choosing b after seeing e must also preserve the nonce already queried. A
different representation of the same R0,

```
a*G+b*P = a'*G+b'*P,       b != b',
```

would itself disclose `d=(a'−a)/(b−b')`. Finding such a representation is
not a free reassignment of coefficients. This explains the obligation of
that adaptive variant; it does not exclude every other adaptive or nonlinear
use of the point/hash equations.

An adaptor pre-signature has the same missing scalar in another form. For
known signing key Q=dG and nonce K=kG, adapting by P=tG gives even nonce
`R=rho*(K+P)`. The public pre-response is `s_hat=rho*k+e*d`, whereas a valid
ordinary response is `s=s_hat+rho*t`. Native CHECKSIG does not validate the
incomplete pre-response as an adaptor object. Completing it requires t or
another actual relation; t is precisely the unknown root-key logarithm in
this candidate. The earlier affine cancellation equation shows what is
required when the unknown point is shifted into the native checking key.

## Another native equation does not automatically supply the logarithm

For example, reusing one complete Schnorr signature `(R,s)` under the hash
key P and a known key Q=qG gives

```
sG = R + e_P*P = R + e_Q*qG.
```

If `e_P != 0`, any accepted pair exposes
`d=e_Q*q/e_P mod n`. The challenges may come from the same or different
native messages; the equation is unchanged. Thus a proposed public solver
using this additional check must account for actually obtaining a logarithm
of the hash-derived key. Once obtained, it is retained state, rather than a
one-time authorization property. This conditional implication is algebraic;
no successful full-size pair for the sampled hash roots is claimed.

## Result and useful next criterion

The hash-as-key primitive removes the DER work and permits post-funding proof
selection while enforcing DEFAULT in eight raw bytes. That makes it a useful
native interface to investigate. The supplied solvers either need much more
than `2^64` work in their stated models or reveal a reusable key; the short
leaf still lacks a mandatory relation between proof meaning and actual
outputs.

A successful extension must give an explicit signing/verification algorithm
that uses a real SHA256-derived key, count all root and challenge searches,
and show why the retained transcript cannot sign disallowed outputs. If it
uses a known nonce, it must account for the exact extraction formula above.
If it uses an adaptor or another unknown-log nonce, it must show how the
ordinary native Schnorr check accepts the complete response. A valid point
encoding alone is not a signing witness or a reference proof.

Schnorr equations and encoding follow
[BIP340 at the immutable BIP commit](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0340.mediawiki).
The candidate, extraction observations and scoped cost models are local
derivations.

Reproduce: `python3 research/covenant-2026-09-17/continuation/r9_hash_xonly.py`.
