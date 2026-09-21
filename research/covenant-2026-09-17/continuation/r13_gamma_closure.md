# R13: closing the live signature hash onto one or two existing keys

Date: 2026-09-17. Question: can `gamma=SHA256(alpha_s)` use the existing
R11/R12 key P_s, or both P_s and Q_s, instead of R12's freely recovered K?
The attempted extension is a known endomorphism plus a public point offset.
All short-r recovery branches are included.

**The public offset constructs ordinary same-key signatures after an actual
digest, but does not close their hash relation.** Two shared keys impose a
stronger exact restriction: a nonzero common offset can work only through
the mixed `rho`/`rho+n` recovery branch. The R11 lattice can move its short
coordinate restriction onto gamma, with the same finite target-support
bound. Gamma's s is then an additional hash-derived constraint.

A new finite-domain observation distinguishes the R12 sampler from this
closure: for one fixed native scalar family, each candidate gamma has at
most four matching s values. In the stated ideal SHA256 model, even
enumerating **every** s in that family gives at most `4*p_DER`, approximately
`2^-43.426`, expected hash-closed hits. This is a fixed-family statement,
not a lower bound for arbitrarily adapted families or all covenants.

Evidence: `locally-reproduced`; deployment `unclassified`. The 16 full-size
offset vectors use actual native ALL serializations and public secp256k1
equations, but none satisfies `gamma=SHA256(alpha)`. Six short-gamma vectors
have manufactured scalar digests. No valid hash-closed Bitcoin script,
funded transaction, Core result, rare DER search, field-library test or
primitive metric is supplied. Reproduction and data:
[`r13_gamma_closure.py`](r13_gamma_closure.py),
[`r13_gamma_closure.json`](r13_gamma_closure.json).

## 1. Exact conditions covering all recovery branches

Fix an R11 native family before the fresh alpha-hash queries. With group
order n and SINGLE-bug scalar C, let

```
r = x(R) mod n != 0,
alpha_s = DER(r,s) || 03,
P_s = ( sR - CG)/r,
Q_s = (-sR - CG)/r.
```

Use `1<=s<=floor(n/2)` and exclude infinity keys. The earlier alpha checks
then pass. Existing R11 beta checks, if retained, impose further conditions;
everything below about gamma is still necessary. When gamma replaces beta,
the same two-key equations are the complete native two-signature interface.
No replacement is implicitly claimed to preserve an additional R11 beta.

Suppose the **actual** SHA256 output parses as a nonzero signature
`gamma=(rho,tau,f)`. Let g be its actual flag-selected native digest. Define

```
a = rho*s/(r*tau) mod n,
b = (g-rho*C/r)/tau mod n.
```

Its verification points under the two existing keys are exactly

```
W_+ =  aR + bG,
W_- = -aR + bG.                                      (1)
```

Let `V(rho)` contain every point whose field x-coordinate is rho or rho+n,
where the coordinate is below p and lifts to the curve. Include both signs.
There are zero, two, or four such points. A gamma check under P_s succeeds
exactly when `W_+` belongs to V(rho). Both checks succeed exactly when there
are distinct ordered `U,V in V(rho)` with

```
tau*(U+V) = 2*(g-rho*C/r)*G,
tau*(U-V) = 2*rho*s/r*R.                             (2)
```

These are public group equalities, not equations in assumed independent
formal generators. They require no knowledge of the logarithm of R.
Nonzero rho, tau and distinct original keys ensure `U!=V`.
The recovery implementation's r+n and parity branches are explicit in
[libsecp256k1 v0.6.0](https://github.com/bitcoin-core/secp256k1/blob/v0.6.0/src/modules/recovery/main_impl.h).

If `U=-V`, equation (2) forces

```
rho = g*r/C mod n.                                   (3)
```

Otherwise U and V cannot have the same x-coordinate: over this curve two
distinct points with the same x are negatives. They must therefore use
different integer representatives rho and rho+n. Necessarily

```
1 <= rho < Delta = p-n,
both rho and rho+n lift,
x(U)-x(V) = ±n.                                     (4)
```

For each rho with four roots, there are four ordered antipodal pairs and
eight ordered mixed pairs. Thus (2) includes the complete finite branch
set rather than discarding the short-r exception. The mixed case does not
generally obey (3).

## 2. Concrete public-offset construction for one key

Try public nonzero t and public offset d with

```
W = tR+dG.
```

A sufficient coefficient-matching construction of (1) is

```
tau*t = rho*s/r,
tau*d = g-rho*C/r.                                   (5)
```

The full group equation is weaker than separately setting these two
coefficients, because R is a group multiple of G. Equation (5) describes
the concrete public construction attempted here, not all possible solutions.

For `d!=0`, choose rho and any of its recovery roots W, then set

```
R = t^-1*(W-dG),          r = x(R) mod n,
tau = (g-rho*C/r)/d,
s = r*tau*t/rho.                                    (6)
```

Reject infinities and zero scalars. This produces alpha at C and gamma at
the already supplied g under exactly the same P_s, without a logarithm of
W or R. LOW_S normalization changes recovery signs as usual. If both alpha
and gamma are normalized, R, W, t and d can be sign-adjusted consistently;
the executable records raw algebraic scalars and verifies the final encoded
LOW_S signatures independently with the host ECDSA equations.

The finite test uses:

- Two native ALL digests with different output recipients and the same
  synthetic prevouts.
- `rho=2`, **all four** recovery roots including x=n+2.
- `t=lambda`, `d in {1,17}`.

All 16 resulting alpha/gamma pairs pass their two native equations under P.
Their gammas fail under Q, and the directly computed W_- has a different
reduced x-coordinate. Alpha has 71–72 bytes; every gamma has **40 bytes**.
Consequently none equals the 32-byte SHA256(alpha). The digest computation
uses the proposed six-byte same-key hash script as its real scriptCode;
the host does not pretend that its separately constructed 40-byte gamma
is the hash that this script would execute.

This construction also does **not** guarantee the original R11 additional
beta relation `x(phi(R))/r=z/C`. Retaining that beta adds the relation as
another necessary check. The one-key offset vectors are a constructive
relaxation, not an extension that silently inherits all earlier checks.

Finite search choices must be charged. One concrete family selects t from
the six signed endomorphisms, a declared finite set D of nonzero offsets,
rho from `1..2^191-1`, and at most four roots per rho. There are at most
`6*|D|*4*(2^191-1)` root/offset candidates before curve and encoding filters.
No enumeration of that large family is claimed. Each offset construction
needs its public group operations; treating every offset as free would hide
the preparation cost. Setting t and d after seeing the hash merely returns
to equation (1), with no new solver.

For exact 32-byte gamma, the positive minimal DER integer lengths must
satisfy `ell_rho+ell_tau=25`. Even choosing rho=2 requires its LOW_S tau
to lie in the exact interval `2^183 <= tau <= 2^191-1`. Equation (6) supplies
a generic full-width tau, not this interval and not its hash preimage.
Enforcing those properties remains part of the construction.

## 3. Two keys and a nonzero common offset

Suppose the attempted verification points are

```
W_+ =  tR+dG,
W_- = -tR+dG.
```

If their integer x-coordinates are equal, then `W_-=W_+` would give
`2tR=0`, impossible for nonzero t,R. The remaining possibility
`W_-=-W_+` gives `2dG=0`, hence `d=0 mod n`.
Therefore every nonzero d that works for **both** keys must have

```
x(W_+)-x(W_-) = ±n,
rho < p-n,
both short-r recovery x coordinates present.         (7)
```

This leaves a real branch; it is not an impossibility argument. On the
independent toy curve `p=211,n=199`, exhaustive enumeration of 39,402
nonzero-t/offset pairs finds 196 zero-offset antipodal cases and 16
nonzero-offset cases. Every nonzero case is mixed, exactly as (7) requires.
For the fixed toy gamma family in the next section, all four two-key
incidences also use mixed roots; examples are stored in JSON.

For a prescribed finite d set, (5), (7), the curve lifts and the actual hash
equality are all required. The offset itself is a witness-construction
parameter, not an on-chain proof that these checks pass.

## 4. Moving the lattice strip from alpha to gamma

At d=0, take `R_gamma=phi^j(R_alpha)=tR_alpha` and desired `u=g/C`.
The native two-key equation is

```
rho/r = u mod n,
rho = x(phi^j(R_alpha)) mod n.
```

The R11 lattice can restrict gamma's x-coordinate instead of alpha's:
solve the inverse ratio `1/u` with short first coordinate, then swap the
two returned points and invert the known multiplier t. The executable uses
exactly that existing integer-lattice solver.

For `Rmax=2^191-1`, gamma's possible x coordinates occupy

```
[1,Rmax] union [n+1,n+min(Rmax,p-n-1)].
```

Each such x and each of the two nonidentity endomorphisms determines at
most one u. The target support is therefore still at most

```
S = 2*(Rmax+min(Rmax,p-n-1)).
```

For an independent uniform scalar this gives support probability at most
`S/n`, approximately `2^-64`; for a uniform 256-bit digest reduced mod n,
the exact conservative bound is
`(S+min(S,2^256-n))/2^256`. Swapping the two coordinates does not enlarge
this support. Zero targets are rejected. This bound is for the stated
endomorphism catalogue, not the arbitrary-offset or general-curve family.

Six planted vectors move a 191-bit coordinate to gamma, make gamma exactly
32 bytes, and satisfy all four native ECDSA equations at manufactured g.
Their `SHA256(alpha)` values are different from gamma. Sixty-four actual
ALL digests using the full 54-byte two-key hash script yield no short-gamma
coordinate within the solver's existing explicit cap. This sample and cap
are not a proof of nonexistence for those digests.

Even if the coordinate search succeeds, fixed r,R,t and native g now require

```
rho = g*r/C,
tau_s = min(rho*s/(r*t) mod n, -rho*s/(r*t) mod n),
SHA256(DER(r,s)||03) = DER(rho,tau_s)||01.             (8)
```

The right side must have length 32. Equation (8) is an actual constrained
hash fixed-point relation. Mining a hash which merely looks like DER does
not enforce its predetermined rho or its linked tau. Conversely choosing
s from a hash-derived tau changes alpha and therefore changes the hash.
Both hash-derived scalars must be satisfied together.

## 5. Exact finite-family incidence count for the live hash

Here is a separate limitation that also covers non-endomorphism recovery
roots and all short-r branches. Keep the transaction, native digest
function, R and r fixed **before** querying fresh `SHA256(alpha_s)` values.
Let S_s be any subset of the canonical LOW_S scalar domain with valid keys.
For each s, let A_s be the set of all 32-byte strings that are accepted
as gamma under the existing P_s in that fixed transaction.

For any fixed candidate gamma=(rho,tau,f), its native digest g_f is fixed.
It has at most four recovered keys

```
K_W = (tau*W-g_f*G)/rho,       W in V(rho).
```

But `s -> P_s=(sR-CG)/r` is injective. Each K_W can therefore correspond to
at most one s. Some keys are infinity or outside the chosen scalar domain;
that only reduces the count. Thus, writing D32 for the set of strict DER
32-byte strings including their flag,

```
sum_s |A_s| <= 4*|D32|.                              (9)
```

Allowing g to depend on the hash-derived flag does not invalidate (9): once
the complete gamma is fixed, that flag and g are fixed too. Zero-scalar and
policy-invalid strings may be left inside D32 for this upper bound.

In the ideal fresh SHA256 model, all fixed alpha_s inputs have uniform
256-bit hash outputs. If X counts actual closed pairs over the **entire**
selected s domain, linearity of expectation gives

```
E[X] = sum_s |A_s|/2^256
     <= 4*|D32|/2^256
     <= 4*(780555/2^65)
     = 780555/2^63
     = approximately 2^-43.42586.

Pr[X>=1] <= E[X].                                    (10)
```

For just the literal ALL flag the syntactic counting bound can be divided
by 256. Requiring the same gamma under Q_s as well only reduces A_s. This
is why R12's nearly n/2 alpha choices do not create an almost-certain
same-key hash solution: after closure, candidate gammas have small
**in-degree**, even though there are many alpha inputs.

The statement does not assume the discrete-log inverse s is efficiently
computable. It is a count. It is not an estimate of the work of a solver,
nor a claim about arbitrary hash-dependent selection of R,r,transaction
or other family parameters. For a preselected finite collection of F
families a union bound gives `4F*p_DER`; preparation and inspection of those
families must still be counted. Adaptively fitting a different family to
already observed hashes requires another argument.

There is a stronger count for the mixed two-key branch at one fixed flag.
For each `rho<Delta`, at most eight ordered mixed pairs U,V exist. Since
`U+V!=0`, the first equation in (2) determines at most one tau modulo n for
that pair, and the second determines at most one s. Therefore

```
E[X_mixed at a fixed flag] <= 8*(Delta-1)/2^256
                          = approximately 2^-124.65430.             (11)
```

This does not include the antipodal branch, which must be treated with
(3). If its forced rho exceeds Rmax, that branch contributes zero. Several
accepted flags require summing their branch bounds; no ALL-only flag
enforcement is silently assumed here.

The deterministic toy exhaustively checks all 3,069 `(rho,tau)` values in
its declared alphabet against 98 valid scalar values: **300,762** direct
membership comparisons. Recovering keys and inverting the scalar orbit
agrees exactly with direct ECDSA evaluation. The largest in-degree is four.
There are 1,560 one-key incidences and four two-key incidences, all of the
latter mixed. With the separately declared ideal toy hash alphabet of
`2^20` outputs, exact independent-oracle probabilities and expectations are

| Fixed toy family | Expected closed hits | Probability of at least one |
| --- | ---: | ---: |
| One key | `195/131072` | 0.0014866370892 |
| Two keys | `1/262144` | 0.00000381469181 |

The probabilities use the exact product `1-product_s(1-|A_s|/2^20)`;
expectation is not substituted for probability. The toy alphabet is
expressly not Bitcoin DER or a proposed truncation opcode.

## 6. Raw candidate layouts and remaining scope

For a single shared key, the complete stack-consuming candidate is

```
# Entry alpha P
2DUP CHECKSIGVERIFY
SWAP SHA256 SWAP CHECKSIG
```

For two keys, the candidate starts with `[alpha,P,Q]`, checks exact entry
depth, computes gamma from a copy of alpha, reorders to `[alpha,gamma,P,Q]`,
then executes the existing R11 guarded four-check layout. The prefix is
`DEPTH 3 EQUALVERIFY 2 PICK SHA256 2 ROLL 2 ROLL`.

| Unmined raw complete layout | One shared key | Two shared keys |
| --- | ---: | ---: |
| Script bytes | 6 | 54 |
| Static non-push opcodes | 6 | 33 |
| Native checks if successful | 2 | 4 |
| Entry data items | 2 | 3 |
| Auxiliary hints | 0 | 0 |
| Structural combined stack peak | 4 | 7 |

No valid hash-closed witness executes either layout here. These are raw
structural counts, not compiled library metrics or measured consensus
execution. All entry operands coexist; no hints or secondary tables are
hidden. The single-copy layouts fit the numeric stack bound. Serialized
scriptSig, witness and complete-transaction weights are not reported because
there is no complete valid candidate. No repeated composition is measured.
Both fragments would consume their declared data and leave one truth value;
the two-key layout also enforces distinct 33-byte keys. Neither extracts
SIGHASH flags or an output reference. Signature parsing is governed by
[Bitcoin Core v29.0](https://github.com/bitcoin/bitcoin/blob/v29.0/src/script/interpreter.cpp).

The construction attempt therefore produces an exact one-key public-offset
solver for **unhashed** signatures and a complete classification of the
two-key offset branch, but no cheap hash closure or output asymmetry.
The next constructive criterion is a way to choose genuinely new native
families after funding that satisfies both components of gamma's actual
hash relation and a mandatory intended-output reference, with finite search,
setup and audit costs included. Merely transferring the short strip or
varying s inside one fixed family does not meet that criterion.

Run `python3 research/covenant-2026-09-17/continuation/r13_gamma_closure.py`.
All inputs and finite ranges are deterministic. The script reuses the R11
integer-lattice and host curve helpers; its toy enumerations are separate
finite checks. No library source or primitive measurement is changed.
