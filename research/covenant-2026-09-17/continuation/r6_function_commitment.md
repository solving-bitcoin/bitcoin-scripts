# R6: a readable parameter commitment and an explicit sumcheck lookup attempt

Date: 2026-09-17. Question: can one native root signature bind a reusable
reference function for at least `2^32` transaction choices and roughly `2^45`
digest-subset choices, without materializing their product table, while a
mandatory legacy verifier fits 201 counted opcodes?

No complete function commitment is constructed. Two concrete results narrow
the interface: mixed-hash paths can commit readable short parameters directly
into a signature root, and an explicit sumcheck lookup reduces the requested
lookup to an authenticated **off-Boolean-cube function evaluation**. The latter
is an additional requirement, not supplied by an ordinary table membership
opening. The straightforward 77-variable verifier also exceeds 201 operations
even under very generous arithmetic accounting.

Evidence is `locally-reproduced` for the host tests and raw-fragment model;
deployment is `unclassified`. There was no Bitcoin Core run, no repository
script compilation, no rare DER root mined, and no full transaction. The
raw bytecode below is deliberately an unoptimized boundary vector rather
than a policy-produced primitive metric. No field-library tests ran.

## 1. Exact requested interface

Let `v` select a real transaction with fixed funding outpoint and ordered
outputs `O*`, and let `D` select the deleted signatures/context. An initial
commitment must support

```
OpenEval(C, v, D, z, evaluation_proof) = true
    implies z = LegacySignatureHash(T_v, scriptCode_D, flag).
```

After `alpha` is derived from the committed description, a separate mandatory
relation must also establish

```
r(alpha) P_ref + z G = s(alpha) R(alpha).
```

The reference output must be linked to the actual native `P`, not just named
by another witness item. A compressed program for the sighash function is a
possible representation of C; an evaluation argument is still required.
This note grants readable `v,D,z`, proper flags and native challenge generation
when inspecting the evaluation argument. It does not silently implement them.

The function need not be an explicit product table. A fixed arithmetic circuit
can represent its program compactly. The unfinished part is a Script verifier
that authenticates an input-dependent execution of that program and the later
alpha-dependent curve relation.

## 2. A short parameter root that Script really can read

For a 33-byte public seed u and n semantic bits b, define

```
state = u
for bit in b:
    state = SHA256(state) if bit else RIPEMD160(state)
alpha = SHA256(state)
```

The fixed n-step program starts with the reversed selector items below u:

```
SIZE 33 EQUALVERIFY
repeat n times:
    SWAP
    IF SHA256 1 TOALTSTACK
    ELSE RIPEMD160 0 TOALTSTACK
    ENDIF
SHA256
```

Afterwards alpha is on the main stack and all normalized bits remain on the
alt stack, in execution order. They can be consumed by later arithmetic. Alpha
can therefore be used directly as the actual signature; it need not be a hash
of an opaque serialized proof with separately unbound coefficient items. This
is an implementable alternative root representation, not a claim that alpha
is already a valid signature.

The 33-byte seed is separated by length from the 20/32-byte intermediate hash
states. It avoids the elementary substitution of a pre-hashed internal state
for a root in this fixed program. Collision binding for arbitrary adversarial
mixed-hash searches still needs an explicit model and proof; no general
binding theorem for this construction is claimed here. Mining alpha, checking
its flag and recovery possibilities, and the native pin are all additional
costs.

The Script commits each selector's **truth value**, not its original byte
encoding. The branch pushes canonical 0/1 itself, so legacy noncanonical true
and negative-zero encodings do not change the bits presented to arithmetic.
The fixture tests three such encodings explicitly.

The measured boundary is `fragment-only:` input pushes and any native
signature check, pin, output comparison, arithmetic reconstruction, cleanup and
terminal predicate excluded. It retains the bits deliberately. All n bit
operands and the seed coexist at entry; there are **zero auxiliary hint
items**, n+1 data items, and combined main-plus-alt-stack peak n+3. Model
measurements are:

| Parameter bits | Raw fragment bytes | Static counted ops | Executed counted ops incl. control | Data items | Peak |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 15 | 11 | 9 | 2 | 4 |
| 3 | 35 | 27 | 21 | 4 | 6 |
| 8 | 85 | 67 | 51 | 9 | 11 |
| 15 | 155 | 123 | 93 | 16 | 18 |

Input push encodings use n+34 bytes for the canonical fixture inputs. A
witness-style serialization of the item vector uses `35+n+number_of_ones`
bytes; this is only a serialization comparison, not an actual SegWit witness
or complete legacy scriptSig. The JSON records each measured vector. No
whole-transaction weight is asserted.

This root can bind, for example, the three 5-bit encodings of a quadratic over
F17 in 123 static opcodes before their numeric reconstruction. It freezes
those three coefficients. A fixed universal-program description can also be
bound this way if short enough. It does **not** turn arbitrary later trace
coefficients into committed values. A three-coefficient polynomial over a
31-bit field would already use 93 bit positions and 747 static opcodes in this
particular representation. These are family-specific costs, not lower bounds
on other commitments.

## 3. The concrete algebraic lookup reduction

For `k=32+45=77` input bits, let f be one field coordinate of the reference
function, and let `f_tilde` be its multilinear extension. For a selected Boolean
argument x define

```
eq_x(X) = product_i (X_i if x_i=1 else 1-X_i)
g_x(X)  = eq_x(X) * f_tilde(X)
f(x)    = sum_{X in {0,1}^k} g_x(X).
```

Every variable of g has degree at most two. The standard sumcheck recurrence
lets the prover send a quadratic `a_i+b_i X+c_i X^2` in each of k rounds. The
verifier checks that its values at 0 and 1 sum to the previous claim and uses
the challenge r_i to update that claim. At the end it checks

```
last_claim = eq_x(r) * f_tilde(r).
```

This is a concrete evaluation protocol, but it concludes at `f_tilde(r)` for a
typically non-Boolean point r. A table membership opening for `f(v,D)` on
Boolean inputs does not establish that final value. Replacing it with another
sumcheck without a base evaluator merely moves the obligation. A polynomial
commitment evaluation opening or a complete circuit/GKR verification would
provide an appropriate interface, if implemented.

This is the standard sumcheck/GKR distinction described in Thaler's
[July 18, 2023 manuscript](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf),
sections 3.5, 4.1, 4.6 and 7.3. Circuit-specific implementations can avoid
enumerating a giant truth table; see also the primary paper
[Time-Optimal Interactive Proofs for Circuit Evaluation, v1](https://arxiv.org/abs/1304.3812v1).
Neither source supplies the required Bitcoin Script byte linkage or the
prover-selected QSB challenge analysis.

## 4. A reproduced omission, with the true function kept fixed

The fixture uses F17 and a deterministic hash-defined function on five Boolean
inputs. It constructs 96 honest five-round lookup proofs and rejects the same
transcripts when the claimed row value is changed. This checks the reduction,
not a Bitcoin sighash implementation.

A smaller three-input fixture fixes the true function and a false claimed
value. It sets every round polynomial to the constant `previous_claim/2`.
These polynomials satisfy all round consistency checks before the challenge
is known. If the final oracle value is not authenticated, after the challenge
vector r it supplies

```
fake_f_tilde(r) = claimed_value / (2^k * eq_x(r)).
```

For every challenge vector in `(F17 minus {0,1})^3`, the denominator is nonzero.
All **3,375 of 3,375** false transcripts accept with that unbound final value.
With the same forged round polynomials and the **actual** final function
evaluation, only **191 of 3,375** accept. Occasional acceptance is expected for
a small-field probabilistic protocol; this experiment does not claim that
sumcheck has zero soundness error. It isolates the exact missing authenticated
interface, even when the universal function is fixed and known.

The non-Boolean challenge domain is an explicit toy choice, not a proposed
QSB sampler. Ordinary uniform-challenge soundness cannot be imported into
QSB; the native restriction/search accounting from R4/R5 remains necessary.

## 5. An optimistic, already excessive verifier for this reduction

For each quadratic, checking `2a+b+c=previous_claim` uses three additions and
one equality. Evaluating `a+r*(b+r*c)` uses two multiplications and two
additions. This straightforward recurrence therefore uses eight field
operations/comparisons per round, or **616 for 77 rounds**. This counts a full
field addition, multiplication or equality as one operation and grants stack
routing, modular reductions, range checks, challenges, commitment checks and
the final oracle evaluation for free.

616 is an explicit optimistic cost of this implementation, not a universal
opcode lower bound. Existing Bitcoin Script has no native multiplication;
lookup-based multiplication does not erase the other obligations. The
straightforward protocol already fails the 201-opcode objective before any
native pin or root computation. One-round univariate reductions, batched
checks, specialized circuit structure and different functional commitments
are not excluded by this count.

The transcript contains 231 coefficient field elements for the 77-round
version. A literal witness would have 231 coefficient data items, with any
opening proofs and arithmetic hints additional; they all coexist at entry.
No exact full-witness bytes, hint count or stack peak is claimed because no
full verifier has been implemented. The fragment measurements above must not
be substituted for those missing whole-protocol metrics.

## 6. What remains constructive

The result improves the root interface: readable short parameters can feed an
actual alpha signature through native hash paths. It also makes the universal
evaluation obligation precise: authenticate an off-cube reference evaluation
or implement an equivalent circuit verifier, while binding the post-root
input-dependent proof messages to the native query chronology. Finally the
alpha-dependent EC recovery still needs mandatory verification.

No product table is declared necessary, and no claim is made that every
function commitment exceeds the budget. The next promising change would need
to reduce the **specific evaluator**, not merely rename its final oracle as a
commitment opening. Reproduce the new host tests with
`python3 research/covenant-2026-09-17/continuation/r6_function_commitment.py`.
