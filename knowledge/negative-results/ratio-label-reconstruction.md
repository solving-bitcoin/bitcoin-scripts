# Ratios of public affine point forms do not compress linear scalar openings

Question: can a label `ell = log_B(A) = a(x)/b(x)` bridge a high-rate subset
opening to fixed hidden verifier labels more cheaply than linear sharing?
Here A and B are public affine combinations of setup points X_i=x_i*G;
their coefficient vectors, including scalar constants, are public and fixed.
The native openings disclose only known linear forms `M*x = y`.

This is a boundary for that particular ratio-label interface. It is not an
impossibility result for nonlinear garbling or point locks in general.

## Exact reconstruction boundary

Work over an odd prime field. Write the affine fiber of the disclosed
scalars as `x = u + K*z`, where columns of K span ker(M). On that fiber,

```
a(x) = a0 + alpha*z
b(x) = b0 + beta*z.
```

Require b(x) nonzero for a valid logarithm base. There are four cases:

1. The entire denominator restriction is zero: the base is invalid.
2. Both residual vectors alpha and beta vanish: the openings determine both
   scalar forms, hence their ratio whenever b0 is nonzero.
3. The two restricted affine forms are proportional: the ratio is constant.
   Outside case 2, beta must have a nonzero entry. The constant lambda is
   therefore a ratio of public coefficients alpha_j/beta_j. Anyone can check
   `A = lambda*B` using the setup points before any opening.
4. Otherwise there are two points on the scalar fiber, with nonzero
   denominators, giving different ratios.

For completeness of case 4, a constant ratio lambda on the valid domain
would make the affine form a-lambda*b vanish there. If b is nonconstant,
that domain has `(q-1)*q^(k-1)` points in a k-dimensional fiber, more than
the `q^(k-1)` zeros of a nonzero affine form for q>2. If b is a nonzero
constant, the domain is the whole fiber. Thus a-lambda*b must be identically
zero, which is exactly case 3 or case 2. Zero-dimensional fibers fall in
case 1 or 2. The odd-field qualification matters: over F2 a nonconstant
denominator leaves only one of its two scalar values.

The tempting exception `a=x, b=y, opening x-y=0` is real: neither scalar is
known, but their ratio is one. It supplies no hidden label because its public
points already satisfy X=Y. An opening x-y=c with nonzero c does not have
that property. The implementation explicitly tests both cases.

Consequently a fixed ratio label that remains hidden must require both
linear coefficient forms in the disclosed row span. Affine constants are
already public. A vector of such labels requires the span of all its
nonpublic numerator and denominator forms. Under this model, the
[full-subset classification boundary](linear-subset-classification.md)
therefore also applies after replacing each ratio label by that required
subspace. A constant denominator recovers the old scalar interface; a ratio
of two independent inventory coordinates requires both openings. For 5-of-54
selection the latter is available in only C(52,3)=22,100 of 3,162,510 subsets.

## Public point commitments and a discrete-log reduction

Two different scalar assignments usually have different public points.
The fiber argument alone is therefore not an information-theoretic hiding
proof for a published setup. The following separate reduction addresses
the computational question for the stated point metadata.

Given a challenge X=z*G with unknown z, choose known vectors u,h with
M*h=0, and construct every setup point as

```
X_i = u_i*G + h_i*X.
```

All disclosed scalars M*u are known. The reduction also constructs every
allowed public affine point combination without knowing z. Write

```
A = a0*G + alpha*X
B = b0*G + beta*X
Delta = alpha*b0 - beta*a0.
```

For Delta nonzero and B finite, any correct returned label ell with A=ell*B
reveals the challenge scalar exactly:

```
z = (a0 - ell*b0) / (ell*beta - alpha) mod n.
```

The divisor cannot vanish: otherwise the valid point equation would force
Delta=0. The reference embedding accepts X as a point, never its scalar;
the test oracle separately knows z to check extraction.

For independently uniform hidden setup scalars and fixed public forms, a
direction with a nonconstant ratio has a nonzero affine determinant as a
function of u. Sampling u until Delta!=0 removes at most a 1/n fraction.
Translation by h*z preserves Delta, so the embedded scalar vector has the
uniform distribution on that allowed set. A zero denominator is a further
at-most-1/n exception. This explains the usual DLP-hardness interpretation
for this family; it is not a bound for every malicious or constrained native
setup distribution, adaptive choice of coefficients, or added secret-derived
metadata. No numerical whole-protocol security level is claimed.

## Scope and evidence

Known point pairs do support inversion by swapping endpoints, and chaining
`(P,Q),(Q,R)` multiplies their relative logarithms. Those identities do not
provide the unknown scalar labels from the fixed-G linear openings. A native
operation that directly opens a relative logarithm would be a different
interface and is not ruled out here.

Nonlinear secret-derived point metadata, ciphertexts, secret-dependent
coefficient tables, different allowed setup distributions and other native
openings are outside this result. It does not establish extraction for the
current 98,323-vB transaction candidate or solve its public garbling check.

Evidence: **inspected** proof and **locally-reproduced** exact tests.
The [reference and report](../../research/pointlocks-2026-09-17/ratio-labels.md)
cover 654,476 exhaustive small-field cases and twelve secp256k1 challenge
embeddings. Deployment: **unclassified**. No script, witness, hint count,
stack peak, opcode budget, transaction, Core result or setup timing is added.
