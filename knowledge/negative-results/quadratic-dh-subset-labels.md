# The independent-coordinate quadratic DH interface stops at three missing scalars

The [DH quartet selector](../../research/pointlocks-2026-09-17/dh-quartet-labels.md)
is a positive departure from scalar-linear labels: one of four scalar
openings provides two secret point-valued labels. This page limits a direct
high-rate extension, not all group-valued garbling or the publication goal.

The later [correlated extension](correlated-quadratic-subset-labels.md)
proves the same necessary boundary for public linear candidate correlations
that preserve full t-subset scalar privacy. Its degree argument is separate
from the independent-coordinate graph proof below.

## Model and four-missing obstruction

There are N independent hidden scalars x_i and public X_i=x_iG. An accepted
view discloses an arbitrary t-subset S of scalars. Public metadata contains
no additional secret-derived quadratic point values. A label is a fixed
nonempty vector of DH products x_i*x_j*G for distinct indices i,j.

Represent a label by its edge set E. The evaluator can compute its whole
vector precisely when S meets every edge. If an edge has neither endpoint
opened, its point is a CDH value of two undisclosed independent scalars. The
formal access calculation assumes group operations with known scalars; the
CDH interpretation is computational, not information-theoretic.

Suppose every t-subset must yield exactly one of two fixed hidden labels
with nonempty edge sets E0,E1. Pick any e0 in E0 and e1 in E1. Their union
has at most four vertices. If N-t>=4, choose a missing set K of size N-t
containing that union, and open its complement. Neither output vector is
available, contradicting total evaluation. This includes arbitrary vector
widths and choices of the binary classifier.

The same formal obstruction covers fixed quadratic polynomial point labels
with known coefficients: choose a nonzero quadratic monomial from each
nonpublic label and leave all of their variables unopened. Neither restricted
polynomial is affine in the remaining unknowns. Linear terms are already
public points. This extension excludes extra quadratic metadata and is not a
claim about arbitrary nonlinear evaluation algorithms or constrained setup
distributions.

For 5-of-54, 49 coordinates remain unopened, far beyond this interface's
boundary. This does not rule out correlated candidates, hidden nonlinear
metadata, different admissible selection families or different native locks.

## Three missing coordinates are achievable

Partition the N vertices into A,B, with each side of size at least two. Let
the first label contain every DH edge within A, and the second every DH edge
within B. For any three missing vertices, exactly one side contains at least
two. Its label has a missing DH component; the other label is wholly
computable. Hence this is a total nonconstant binary classifier for all
(N-3)-subsets, with CDH protection of the opposite full vector under honest
independent input generation.

At N=4, each side has two vertices. Two different balanced partitions give
the two-bit quartet selector. The implementation also supports publicly
correlated quartet inputs; that variant is outside this independent-coordinate
graph theorem and has a separate square-CDH argument.

The exact graph screens give the following counts of distinct unordered pairs
of complementary, nonconstant access masks. Multiple different edge vectors
can implement the same mask and are not counted twice.

| N | t | Missing | Nonempty edge vectors examined | Complementary access pairs |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 0 | 4 | 63 | 0 |
| 4 | 1 | 3 | 63 | 3 |
| 5 | 1 | 4 | 1,023 | 0 |
| 5 | 2 | 3 | 1,023 | 10 |
| 6 | 2 | 4 | 32,767 | 0 |
| 6 | 3 | 3 | 32,767 | 25 |

## Setup and composition remain separate

The independent quartet's shape checker accepts x3=x0*x1/x2, even with
distinct nonzero input points; two complete message-label vectors then
coincide. The correlated profile's extra public checks reject all exact
output equalities, but do not certify entropy or verify garbling ciphertexts.
These distinctions are exercised by separate controls in the reference.

Point values also cannot be silently substituted for scalar labels at the
next gate. The subsequent [native quartet wrapper](explicit-dh-quartet-tables.md)
supplies small scalar openings but exceeds the full-message budget with its
explicit tables. Public binding of garbling, full transaction construction
and complete setup timing remain unresolved.

Evidence: **inspected** proofs and **locally-reproduced** finite screens in
the [report](../../research/pointlocks-2026-09-17/dh-quartet-label.json).
Deployment: **unclassified**. No new Script, witness/hint/stack/opcode metric,
Bitcoin transaction, Core result or setup benchmark is claimed.
