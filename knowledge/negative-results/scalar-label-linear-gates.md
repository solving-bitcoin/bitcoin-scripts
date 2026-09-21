# A single-scalar linear AND cannot preserve both input labels and output authenticity

This strengthens the [specific scalar AND counterexample](public-algebraic-gate-labels.md)
within an explicit linear model. It does not exclude vector labels,
nonlinear encryption, extra authentication interfaces or all algebraic
constructions.

Work over any field. Every input label is one scalar linear form in a hidden
setup vector; recovery uses public affine combinations of disclosed forms.
Quotient out the span of all publicly disclosed scalar information, including
constants. A public point commitment does not itself disclose its scalar.
Write the four input forms as a=L0, b=L1, c=R0, d=R1.

The complete-label requirement means that, for every selected pair, neither
opposite input form is in its scalar-linear span. Otherwise replacing that
wire yields the full labels of another input. In particular:

```
d is not in span(a,c),
a is not in span(b,c).
```

Correct AND evaluation requires its zero-output form z to satisfy

```
z in span(a,c) intersect span(a,d) intersect span(b,c).
```

The privacy conditions imply that a is nonzero, that c is not proportional
to a, and that d lies outside span(a,c). The first two spans therefore
intersect exactly in span(a). But a lies outside span(b,c), so intersecting
with the third span leaves only zero. Hence z is public in the original
affine model. The 11 opening can then obtain the opposite output label,
contradicting output authenticity.

Thus both requirements cannot hold for this one-scalar, scalar-linear gate
interface. Altering public coefficients, correlated masks or known affine
offsets does not evade the proof as long as this model still applies.
This is not a theorem about arbitrary non-linear scalar functions, proof
systems, point encodings, vector keys or a different whole-protocol interface.

The [vector-label follow-up](../../research/pointlocks-2026-09-17/vector-label-gates.md)
constructively escapes the premise: two scalars per input label support
public point-only checking for every binary truth table, while the complete
alternative labels and opposite output remain outside the disclosed span.
A discrete-log embedding gives the corresponding single-gate computational
argument. It requires four selected scalars per gate; a direct legacy wrapper
for one layer on 2,048 bits has a 241,664-vB signature-push floor, excluding
all other costs. Public point equations for packing two coordinates into one
scalar do not establish the needed integer ranges; a separate control
reproduces that failure.

Evidence: **inspected** proof and **locally-reproduced** controls. Deployment:
**unclassified**. Exhaustive F_2^3/F_3^3 screens corroborate the scalar boundary,
and nine tests cover the vector construction and malformed cases. No new
native script, witness, hint count, stack peak, transaction or setup benchmark
is claimed. The original publication goal remains open.

The [shared-coordinate follow-up](../../research/pointlocks-2026-09-17/shared-vector-gates.md)
reaches three distinct openings per gate and proves that rank three is the
minimum worst case for arbitrary vector inputs in the same linear model.
It also proves the separate [full-subset classification bound](linear-subset-classification.md),
including correlations; neither result excludes nonlinear garbling.
