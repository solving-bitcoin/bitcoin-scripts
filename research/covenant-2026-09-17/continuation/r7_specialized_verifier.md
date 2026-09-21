# R7: one-round univariate lookup, authenticated quotient, and public group fallback

Date: 2026-09-17. Question: can the reusable reference sighash evaluation be
reduced to one polynomial identity, replacing R6's 77 sumcheck rounds while
fitting 201 legacy opcodes and the retained-state creator model?

The concrete quotient identity does remove all those rounds. It does not
produce a covenant: explicit readable coefficient authentication exceeds the
opcode budget even for a small example, while the examined constant-size
group replacement is freely forgeable if its evaluation scalar is public or
retained. A further useful result is exact: a false, fully precommitted
quotient can select **any desired N−1 challenge points** at which to pass.
This exposes the relevant challenge fibers rather than importing uniform
Fiat–Shamir soundness into Binohash/QSB.

Evidence: `locally-reproduced`. Deployment: `unclassified`. The executable is
a deterministic host polynomial/group experiment. No Bitcoin Core execution,
pairing implementation, complete Script verifier, rare-event mining, or
repository field-arithmetic test is claimed. No repository primitives changed.

## 1. Concrete protocol and final authentication

Encode the selected reference input `(v,D)` as a distinct prime-field point x. Let
the permitted input domain have N elements. For one field coordinate of the
reference sighash or recovery relation, interpolate the exact table as
`F(X)`, of degree at most N−1. For a correct claimed output y, the prover forms

```
Q(X) = (F(X) − y) / (X − x),       deg Q <= N−2.
```

The one-round transcript is:

1. Fix the true reference polynomial F and authenticate its coefficients to
   the verifier. The target outputs `O*`, the domain-to-x map, and the field
   are fixed parts of the statement.
2. Fix x and claimed y. Commit to all coefficients of Q **before** deriving
   the challenge r. Enforce `deg Q <= N−2` by a fixed coefficient count.
3. Derive r, with `r != x`. Authenticate F's and Q's coefficients and evaluate
   both by Horner's method. The final verifier performs
   `F(r) − y == (r − x) * Q(r)`.

The final values are computed from the authenticated coefficients; there is
no residual unbound oracle. The expensive direct instantiation uses the R6
mixed-hash parameter root for these coefficients. Each field element has a
fixed bit encoding, the path retains normalized bits, reconstruction enforces
the field range, and arithmetic uses those exact reconstructed values.
This is an explicit authentication interface, not a succinct implementation.

For costs below, authentication and evaluation of F are optimistically free;
we count only direct Q coefficient authentication. This relaxation is stated
to obtain a lower cost for this **chosen implementation**, not to assume an
external honest oracle in a covenant. The host test actually computes F(r)
and Q(r) from the fixed exact coefficient arrays.

The native transaction would still have to enforce all of: the true `(v,D)`
mapping, challenge chronology, alpha's output-binding sighash mode, the native
recovery relation, and equality of the relevant reference and native values.
These obligations are not implemented by the polynomial identity. Their cost
cannot be inferred from the host tests.

## 2. Exact false-opening construction with full coefficient authentication

Fix a false y with `F(x) != y`, and fix any N−1 distinct field points
`S = {s_1,...,s_(N−1)}` that exclude x. Construct

```
E(X) = c * product_(s in S) (X − s),
c = (F(x) − y) / product_(s in S) (x − s),
Q_bad(X) = (F(X) − y − E(X)) / (X − x).
```

The numerator vanishes at x, so Q_bad is a genuine polynomial of degree at
most N−2. It can be fully committed before r is known. The verifier accepts
exactly when `E(r)=0`, hence exactly at the selected points S. This succeeds
despite correct F evaluation and authentic Q openings. It is ordinary
polynomial identity error, not an attack on coefficient commitments.

The deterministic fixture uses F257, 16 domain-separated SHA256-derived rows,
and their degree-15 interpolant. It verifies all **4,112** honest x/r pairs
(including r=x for the identity check). For a false query at x=7 it commits a
degree-14 Q_bad targeting S={16,...,30}. Exactly **15 of the 256** eligible
challenges accept, and the accepted set equals S.

If Q(r) is instead supplied without any polynomial authentication, the prover
sets `Q(r)=(F(r)−y)/(r−x)` after seeing r. All **4,096** false toy x/r cases
with r!=x then pass. The authenticated and unbound cases use the same fixed
true reference F, so the experiment isolates the missing final binding.

For independent uniform r over the field minus x, the fixed-false-claim error
is at most `(N−1)/(p−1)`, and the construction attains it. More generally it
can target the N−1 points with the greatest challenge probability. For a
deterministic mapping `r=q(D)`, it can target the union of any N−1 chosen
fibers `q^{-1}(s)`. Native pinning and subset search must charge the cost of
selecting D from that union. Neither the uniform bound nor these toy counts
are a lower bound on Binohash/QSB adversarial work. If the entire available
challenge support has at most N−1 points and excludes x, a false quotient can
target the complete support.

## 3. Direct readable coefficients are quantified, not a free oracle

R6's specific n-bit root fragment costs `3+8n` static counted opcodes and
`5+10n` raw bytes. Q needs N−1 coefficients. With b-bit field encodings,
`n=b*(N−1)`. Counting **only** that root:

| Domain | Field-encoding bits | Q coefficients | Selector bits | Counted ops |
| --- | ---: | ---: | ---: | ---: |
| Toy N=16 | 9 | 15 | 135 | 1,083 |
| Nonce-only N=2^32 | at least 33 | 2^32−1 | 141,733,920,735 | 1,133,871,365,883 |
| Product N=2^77 | at least 78 | 2^77−1 | 78(2^77−1) | 3+624(2^77−1) |

The toy Q authentication alone is 1,355 raw bytes, 136 entry data items,
**zero auxiliary hint items**, and combined main-plus-alt-stack peak 138.
All 135 selector bits and one 33-byte seed coexist at entry. These figures
exclude input pushes, coefficient reconstruction, range checks, field
arithmetic, F authentication, native predicates, cleanup and the final
locking-script predicate. They describe the R6 fragment, not a complete
locking script or serialized transaction. The large configurations also
violate the 1,000-item stack limit at entry. JSON records their exact integers.

For the prime-field encoding used here, injectively encoding the nonce-only
2^32-point domain already needs a prime larger than that domain; a positive
four-byte ScriptNum field does not have enough points. A binary extension
field of exactly 2^32 elements can encode that domain, but the false quotient
can then target every eligible challenge, so injection alone does not help.
For a target ordinary uniform-challenge error `2^-lambda`, this
protocol requires `p−1 >= (N−1)*2^lambda`, before any native challenge-selection
analysis. This does not impose a new security target on the user's request;
lambda is an explicit parameter. Multi-limb or extension fields are possible,
but their multiplication is extra work and the direct coefficient count stays.

Materializing the full product interpolant also evaluates at least 2^77 table
entries, beyond the honest setup budget. A nonce-only 2^32 table could fit the
work budget in principle; its direct verifier above still does not. Compact
circuit representations are expressly outside this explicit-table cost, and
are not ruled out by it.

## 4. The examined constant-size group replacement is not secretless binding

A tempting replacement is to commit as `C=[F(tau)]G` and prove y at x by
`W=[Q(tau)]G`. The corresponding group identity is

```
C − [y]G = [tau−x] W.
```

The polynomial-commitment construction in Kate, Zaverucha and Goldberg,
[December 1, 2010 extended paper, §3.2](https://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf),
uses powers of an authority-generated scalar and a bilinear pairing to verify
the related hidden-scalar identity. Its public parameters grow with the
supported degree. Existing Bitcoin signature opcodes do not provide that
pairing verifier.

Even granting an implementation of the group identity, making tau public to
avoid trusted secret retention makes every false evaluation easy. For any
claimed y and `x != tau`, compute

```
W_bad = [(tau−x)^−1] (C − [y]G).
```

This uses only the public commitment point C and public scalars; the creator
does not need to know C's discrete logarithm. It also works if tau was
initially sampled in setup and the creator merely kept it. Checking one true
opening before funding does not prevent computing a different opening later.

The host script reproduces **12 false openings on secp256k1**, across four
query points and three wrong output values per point. Every forged point
satisfies the exact group identity against the same C. This is not a pairing
test and not a native ECDSA Script test. It demonstrates the retained-scalar
failure algebraically on the relevant curve. Secretless transparent
commitments using different assumptions are not excluded by this example.

## 5. Funding and reuse obligations remain explicit

The exact table includes the actual funding outpoint in each reference
sighash. Embedding its commitment in that funding's script creates the
dependency `funding txid -> F -> commitment/script -> funding txid`. Supplying
a pre-audited complete intended spend does not by itself solve that equation.
One can instead describe a universal function taking the outpoint as input,
but the explicit full table then gains that input dimension; a compressed
evaluation proof would be a different construction.

Furthermore Q changes with `(x,y)`. Recomputing a signature root for each Q
cannot be counted as a reusable root supporting 2^32 variants. A separate
authenticated post-root quotient must be committed before the native query
that tests it, and that transcript has to be charged under the R5 chronology.
This report has not introduced a shortcut around either requirement.

The constructive interface exposed here is narrow: authenticate evaluations
of a high-degree exact reference function and a query-dependent quotient,
with genuine before-query binding, without enumerating their coefficients or
depending on a retained setup scalar. Native group identities with a public
evaluation point cannot supply that binding. No complete covenant is claimed.

Reproduce with `python3 research/covenant-2026-09-17/continuation/r7_specialized_verifier.py`.
