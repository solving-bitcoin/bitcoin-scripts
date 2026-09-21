# R18: two exact reverse generators for the exceptional diagonal predicate

Question: can the first R17 condition
`rho=r*(D+A*r)/C mod n`, with both r and rho below Delta=p-n, be solved
constructively without extending the earlier forward scan of small r?
Here `C=2^248`, `A=2^(8*(ns+3))`, and D is the actual fixed 32-byte DER
layout contribution, including a flag selecting the constant SINGLE case.

Two exact alternative parameterizations are implemented: a quadratic solve
for a chosen rho and a unique inverse modulo `2^248` for a chosen integer
quotient. They are complete finite-domain generators, but neither supplies
a proven total cost below `2^64` or a positive full-size candidate.

Evidence: `locally-reproduced`; deployment: `unclassified`.
[Python](r18_diagonal_solver.py) and [JSON](r18_diagonal_solver.json) contain
the exact domains, reproducible arithmetic checks and bounded certificates.
The original subagent stopped with a generic tool-reported cybersecurity
error after saving the Python file. Root inspected and executed that file
and completed this report. No specific triggering passage was provided.
This is public host arithmetic, with no Script, witness, Core execution or
library field test. Script/witness/hint/stack measurements do not apply.

## Quadratic inversion for a chosen target coordinate

Fix a layout, flag and target rho. Then every possible source r solves

```
A*r^2 + D*r - C*rho = 0 mod n,
r = (-D +/- sqrt(D^2+4*A*C*rho))/(2*A) mod n.
```

A is nonzero modulo the prime group order. Thus there are at most two
solutions, and modular square-root extraction returns all of them. The
implementation uses Tonelli-Shanks: n is 1 modulo 4, `v2(n-1)=6`, and 5
is the selected quadratic nonresidue. Each root is substituted back into
the original equation. No source-point logarithm or root-distribution
assumption is needed for this enumeration.

After solving, require that r lies in the exact canonical DER interval
for its declared byte width and below Delta. Next both r and rho need
the two valid x lifts. Only then does R17's midpoint relation become
relevant. A root outside its declared width cannot be reinterpreted using
a different layout's D and A without solving that other equation.

The bounded certificate solves all 17 possible r-width layouts, all eight
flags `3+32*j`, and rho=1..256: **34,816 quadratics**, yielding 34,618
mod-n roots in 17,309 nonempty cases. None lies in its required source
interval. Consequently this excludes the exceptional family for every
valid source r when rho is in 1..256 and the listed flags are used. It is
not a larger forward-r sample and not an exclusion for larger rho.
Sixty of the tested target rho values have all four curve roots; the
certificate deliberately also includes the others as a favorable superset.
The ordered root transcript is hashed in the JSON.

The eight flags form the consensus-oriented constant-context superset;
not all meet standard relay flag rules. Restricting the flag set can only
remove candidates. Source s does not enter this exceptional condition.

## Unique inverse for a chosen integer quotient

Write the original congruence as an integer equality

```
C*rho = r*(D+A*r) + k*n.
```

For a declared source interval `[lo,hi]`, every permitted solution has

```
ceil((C-hi*(D+A*hi))/n) <= k
k <= floor((C*(Delta-1)-lo*(D+A*lo))/n).
```

These bounds use the monotonicity of the positive integer polynomial in r.
They may include extra quotients but omit none. Set `E=2^256-n`. Since
`n=-E mod C`, the equality implies

```
A*r^2+D*r = E*k mod 2^248.
```

A is even and each allowed flag makes D odd. The derivative `2*A*r+D`
is therefore always odd. Each root modulo `2^j` has exactly one lift
modulo `2^(j+1)`, starting from the unique parity solution. Equivalently,
the polynomial permutes the residues modulo `2^248`. Newton lifting with
precision doubling computes the unique residue r for each k.

Every allowed source r is less than Delta, hence less than C. It must
equal that unique residue as an ordinary integer. After checking its
declared interval, compute rho from the full integer equality and test
`1<=rho<Delta`. This describes a complete generator across the stated
quotient domain, not just a necessary modular test.

The fixture checks 408 sampled full-size quotients and independently maps
272 source interval endpoints forward and back; all inversions agree.
The 408 samples yield no valid first-predicate pair. Those samples are
explicitly not a complete quotient-domain enumeration.

## Exact domain sizes and what they do not establish

Across the 136 layout/flag rows, the complete unfiltered domain sizes are:

| Generator | Exact domain size, log2 | Per-candidate operation |
|---|---:|---|
| Forward source r | 131.3457021 | Modular quadratic evaluation |
| Reverse target rho | 135.4331650 | Modular square-root solve, at most two roots |
| Integer quotient k | 129.3705828 | Unique inverse modulo `2^248` and interval tests |

The exact integer endpoints and sums are recorded in the JSON. These are
sizes of complete enumeration domains before four-lift filtering, not
expected work, measured curve-operation costs, or lower bounds for another
algorithm. Early stopping, useful root density and a sublinear interval
method have not been proved. In particular, comparing these exponents as
though all three candidate operations had equal cost would be unjustified.

The arithmetic routines additionally pass exhaustive tests for all 76
square-root residues across four small primes, all 4,624 quadratic
configurations modulo 17, and 6,144 inverse configurations modulo 256.
These verify the arithmetic algorithms; they are not positive Bitcoin
signatures or hash projections.

## Remaining task

The reverse generators make the first scalar filter executable in two
ways; they do not solve it cheaply. Even a first-predicate hit would still
need four source roots, four target roots, R17's public midpoint equation,
a computable third-key map q, an actual raw-DER native hash hit and
mandatory exact-output enforcement. No such candidate was obtained.

A further method must exploit actual interval or algebraic structure to
reduce total work, rather than merely increasing these complete-domain
scans or assuming that modular roots are uniformly distributed. The
separate [endomorphism-slope certificate](r18_endomorphism_resultant.md)
also prevents closing q by any of the six endomorphism scalar choices.

Reproduce: `python3 research/covenant-2026-09-17/continuation/r18_diagonal_solver.py`.
