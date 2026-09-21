# R7: solving the variable-DER digest/signature equation

Date: 2026-09-17. Question: can free r and s in the R6 affine correlation give
a concrete honest solver below `2^64`, including its match to an actual
output-specific native transaction hash?

**No complete covenant is obtained.** The fixed-key equation has an exact
enumeration algorithm, and all 32,512 candidates with a one-byte s and every
flag have been checked. They contain no solution. The especially useful
short-r nonce `G/2` and its negative are excluded for this equation by an exact
integer interval argument, covering every allowed s and all 256 flags.
Allowing the key to vary does give explicit valid 32-byte DER signatures that
are their own numerical message digests. Those are synthetic digest targets;
no actual transaction hash or hash preimage equals them. The distinction
between generating such a target and matching the native transaction is the
remaining obstacle in this family.

Evidence for the companion experiment is `locally-reproduced`; deployment is
`unclassified`. The probability calculations below are labeled models. There
is no new Bitcoin locking script or complete transaction witness, so script
bytes, witness bytes, entry items, hint items, stack peak and executed opcodes
are not measured. No repository Script interpreter, Bitcoin Core, Rust tests,
or field-arithmetic tests were used. The two transaction serializations below
have an explicitly synthetic common funding outpoint.

## Exact domains and a forward solver

For a positive integer, the values having exactly l minimally encoded DER
bytes form the contiguous interval

```
I_1 = [1, 127]
I_l = [2^(8l−9), 2^(8l−1)−1]  for l >= 2.
```

This includes both the necessary leading-zero encodings and the encodings
whose first byte is already positive. It excludes zero, which can pass a DER
syntax gate but cannot be a valid ECDSA r or s.

For a fixed total size b, lengths `l_r+l_s=b−7`, and final flag f, write

```
alpha = DER(r,s,f)
z = int_big_endian(alpha) = C0 + A*r + 256*s
A = 2^(8*(l_s+3)),       0 < C0 < n.
```

The key `P=−A*G` makes verification equivalent to

```
R_s = (256 + C0/s)*G,
r = x(R_s) mod n in I_(l_r),       s in I_(l_s).
```

An actual forward algorithm is therefore:

1. Enumerate admissible positive s.
2. Compute its modular inverse, then R_s. Reject infinity.
3. Reduce the actual x coordinate modulo n and check the exact r interval.
4. Serialize alpha, checking its intended DER lengths and flag, and verify
   the resulting identity independently.

This obtains candidate r from s; it does not treat them as independent knobs
after the curve equation is imposed. It also includes the `x=r+n` branch
automatically whenever the computed x is at least n. In a reverse algorithm,
enumerating r requires lifting both x=r and x=r+n when the latter is below
the field modulus, and retaining both point signs. There can be zero, two,
or four recovery points; discarding the second x branch is unsound in general.

For a fixed s and length layout, increasing the flag by one increments C0 by
one, and thus increments R by `(1/s)*G`. The experiment exploits this exact
relation to check all flags using point additions. It exhausts all 127
one-byte s values and all 256 flags for a 32-byte alpha with 24-byte r:
**32,512 points, zero valid identities**. This is a small complete slice,
not an exhaustive search over every layout. Twenty-four additional real
secp256k1 cases check the affine identity for four layouts and six flags.

The reverse equation is

```
s * (R−256G) = C0*G.
```

For each chosen short-x point R, a bounded discrete-log algorithm can search
the allowed s interval. However, the base `R−256G` changes with r. A table of
baby steps for one base is not automatically a table for all other bases.
Conversely, enumerating s maps it through modular inversion; the resulting
nonce scalars do not form an interval to which a usual interval-log estimate
can simply be applied. These formulations identify possible algorithmic
targets; they do not establish a fast joint interval solver or an
impossibility result. Batch inversion and reuse across flags reduce
arithmetic overhead, but do not demonstrate a favorable search exponent.

## The finite s domain cannot be omitted from cost estimates

In an explicit heuristic model where the nonce x coordinate modulo n has
uniform marginals, the expected number of identities in one fixed
layout/flag is

```
|I_r| * |I_s| / n.
```

For the interior 32-byte layouts this is about `2^−58`, since the two integer
lengths sum to only 25 bytes. Thus “search for a short r with probability
approximately `2^(8*l_r−257)`” needs the additional check that enough distinct
admissible s values exist. This model typically predicts that the whole
fixed-layout domain contains no solution, rather than predicting an
unbounded series of independent retries until success.

Summing the exact nonzero-r/nonzero-s DER counts over all 24 layouts and all
256 flags yields approximately **`2^−45.426802` expected identities** in this
model. This uses a different fixed public key for each s-length layout. The
similarity to the SHA256-to-DER syntax probability is numerical; this is a
count of potential valid digest/signature identities under constrained keys,
not a new hash-to-DER success probability. The small difference from the old
`780555/2^65` gate count comes from excluding zero r and s.

For completeness the program also counts 20-byte layouts, giving about
`2^−142.427274` expected identities relative to the full 256-bit curve order.
A 20-byte alpha is not byte-equal to a 32-byte native transaction digest.
Interpreting it as the same scalar requires the corresponding leading-zero
condition on that native digest in addition to any other binding requirement.

**These are heuristic equidistribution estimates, not secp256k1 lower bounds
or proofs that the full fixed-key family contains no solution.** The scalar
map `s -> 256+C0/s` is deterministic and structured. Its actual distribution
on the curve could matter. No independence between all sampled points has
been established, and a solver using additional correlations is not excluded.

## Exact rejection of the known short-r nonce G/2

The nonce `k=1/2 mod n` has

```
r = 0x3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63.
```

It has 21 DER bytes. A 32-byte alpha therefore requires a four-byte s, with
`2^23 <= s <= 2^31−1`. For this specific r, `r+n >= p`, so the only nonce
points are `G/2` and `−G/2`; no alternate x=r+n branch remains.

The fixed-key relation for these two signs gives, respectively,

```
2*C0 + 511*s = 0 mod n
2*C0 + 513*s = 0 mod n.
```

For every flag from 0 through 255 and every s in that full interval, the
left-hand side lies strictly between zero and n. The executable checks all
512 flag/sign interval endpoints, which suffices because the expression is
linear and increasing in s. Therefore neither nonce can be a solution in
this fixed-key family. This is an exact scoped exclusion, independent of
the equidistribution model. It does not exclude other nonce points.

## Free keys really do produce identities, but not native hash preimages

With a known short-r nonce k and a freely selected key, choose any admissible
s and set

```
alpha = DER(r,s,f),       z = int(alpha)
d = (s*k−z)/r mod n,     P=d*G.
```

The signature verifies algebraically on its own numerical digest. This is
also the solution of the more general affine equation with a key offset
`P=−(A+B)G`, where B is chosen after r and s. One concrete ALL example is

```
alpha = 301d02153b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6302040080000101
P     = 02c7bddd69694bba52ac7efe04c8bdb9f9b1136d5b8b3240ce5ac0a548248576f3
```

The experiment verifies six such identities, including NONE, SINGLE and
nonstandard flag bytes. These are **not mined hash outputs**. Knowing an
alpha/key pair gives no preimage T with `H_native(T)=alpha`.

A direct target-table strategy first creates M such targets, then hashes N
concrete intended transactions and looks for a match. In a fresh ideal
256-bit native-hash model, its expected match count is at most

```
M*N/2^256.
```

Even granting one unit for creating a target and one for a native query,
and charging nothing for EC work, storage, funding or proof verification,
`M+N <= 2^64` gives at most `2^−130`. This is a bound for the specified
preselected-target strategy. It is not a lower bound for all algorithms in
which targets depend adaptively on native hashes.

Plain ECDSA verification under a fixed alpha/key pair also admits other
message scalars: each possible nonce point R_j gives a target
`z_j*G=s*R_j−r*P`. A matching proof must not equate this with unique digest
equality. Even granting all four nonce points and up to two 256-bit hash
representations for each scalar for free, the corresponding target-table
upper bound only rises to `2^−127` at the same total query budget. For the
specific G/2 example there are two nonce points, and their message scalars
can both be computed because their discrete logarithms are known.

That adaptive alternative has to preserve its claimed predicate. The fixture
takes two actual legacy ALL preimages with the same synthetic funding
outpoint and different output scripts. For each native digest z', recovery
produces a key

```
P(z') = (s*R−z'*G)/r
```

under which the same 32-byte alpha is valid. Both verify. Neither native
digest equals alpha. The original fixed self-digest key rejects both.
Consequently, native signature verification under a newly recovered witness
key does not implement the missing equality `alpha=H_native(T)`.

The funding order distinguishes the two cases:

- With an unconstrained witness key, it can be recovered after the concrete
  funding outpoint and outputs are fixed. The fixture works for either
  output list, and the exact output reference is still absent.
- If the key is committed in the funded locking script, choosing that key
  changes the funding transaction and hence the spending sighash. The
  convenient choice of key after computing the final digest no longer
  applies without another fixed-point construction. Merely allowing the
  depositor to inspect funding before broadcast does not erase that hash
  dependency.

All 256 flags matter to a consensus-level construction. An honest choice of
ALL is not an on-chain exclusion of NONE or incomplete SINGLE. The numerical
affine relation does not itself expose or validate the flag as a Script
number, and changing the final byte changes both C0 and the actual native
sighash mode. The tests therefore do not restrict their algebra to only the
honest flag. For an intended output-specific target-table search one may
grant an enforced ALL mode; its full native hash-matching cost still remains.

## What remains constructive

The fixed-key family now has a precise finite-domain solver, an exact
exclusion of both known G/2 branches, and a reproducible small-domain scan.
The free-key family has concrete valid self-digest targets. A next extension
would have to add an actual relation between a supported native preimage and
these target blobs, with an authenticated output reference, while retaining
enough independent choices after the final funding outpoint is fixed. A list
of algebraically valid target digests alone does not supply that relation.

The ECDSA verification and key-recovery equations follow
[SEC 1 v2.0, 21 May 2009, §§4.1.4–4.1.7](https://www.secg.org/sec1-v2.pdf).
All interval, DER-layout, solver and cost deductions in this note are local
derivations, rather than claims made by that standard.

Reproduce:
`python3 research/covenant-2026-09-17/continuation/r7_variable_der.py`.
