# Shared coordinates reduce the algebraic gate opening to three scalars

Question: can shared label coordinates reduce native scalar delivery while
retaining public checking and access to only one complete message's labels?
The comparison counts independent scalar openings, not only offchain storage.

**Three scalars suffice, down from four, and attain the minimum worst-case
rank for this scalar-linear AND interface.** The public check needs no ZKP.
Its direct legacy delivery still exceeds the publication budget. A separate
theorem excludes a linear extension to all 5-of-54 choices, including public
linear correlations among their scalar labels.

[Implementation](shared_vector_gate_probe.py),
[report and hashes](shared-vector-gate.json),
[previous construction](vector-label-gates.md),
[subset-classification proof](../../knowledge/negative-results/linear-subset-classification.md).

## One missing scalar identifies the message

Choose independent secret scalars x00,x01,x10,x11 and publish their secp256k1
generator multiples. Use these input labels:

| Wire value | Scalar vector |
| --- | --- |
| L0 | (x10,x11) |
| L1 | (x00,x01) |
| R0 | (x01,x11) |
| R1 | (x00,x10) |

Input (a,b) needs exactly the three distinct scalars other than x_ab. Shared
coordinates need only be opened once. For AND the output labels are

```
c0 = x11
c1 = x00+x01+x10 mod n.
```

Every zero input supplies x11; 11 supplies all three summands of c1. Public
point equations check both output commitments. The caller supplies the
intended function, and openings are checked against their prebound points.

For N independent coordinates and any nonconstant binary function f of the
missing index, the same construction uses

```
c_b = sum_{j: f(j) != b} x_j mod n.
```

Opening every coordinate except x_i reconstructs c_f(i). The opposite label
contains x_i with coefficient one; any different complete opening also
requires x_i. Recovering either therefore solves log(X_i). A DLP reduction
given X_i can choose every other scalar and compute both output points. This
is a one-opening argument with independent honest secrets; guessing an
adaptively chosen index costs the finite N factor. No whole-protocol security
level follows from it.

The public equations bind reconstruction even when the creator retains all
secrets or supplies a different algebraically consistent setup. They do not
certify entropy or stop deliberate extra disclosure. Infinity, duplicate
candidate points, equal output points and noncanonical openings are rejected.
The reference seeds are public test data.

## Three is optimal for the linear one-gate interface

Let U0,U1,V0,V1 be the subspaces of scalar forms carried by arbitrary vector
input labels, after quotienting out public scalar information. Suppose every
selected pair has rank at most two and cannot derive the opposite full label.
If one U has dimension two, both V alternatives must lie inside it; an
opening containing U then exposes both V labels. The same applies to V.
Zero-dimensional labels also violate the input restriction.

All four spaces must therefore have dimension one. The
[single-scalar AND proof](../../knowledge/negative-results/scalar-label-linear-gates.md)
forces a public zero-output label, defeating protection of the opposite
output after 11. Thus at least one input requires rank three. The shared
construction reaches three for every input. This is a linear-recovery bound
with both output labels protected, not a bound on arbitrary garbling.

## Cost and the high-rate pool boundary

The gate has four hidden dimensions, three scalar openings (96 raw bytes),
and six public point slots (198 compressed bytes before deduplication and
framing). For AND one output point duplicates an inventory point. These
host-side counts are not Bitcoin witness measurements.

One layer of 1,024 **independent** gates on 2,048 bits needs 3,072 direct
scalar openings. Granting efficient guarded legacy locks and 58-byte
signatures, their pushes alone cost `3072*59 = 181,248 vB`: 25% below the
previous 241,664-vB interface, but still too large before every other cost.
Cross-gate correlations and different native mechanisms are outside that
numerical bound. No arbitrary-target native wrapper is supplied here.

Literal componentwise composition still doubles label width per gate on a
path. This is a property of this simple construction, not a lower bound on
advanced gate-evaluation secret sharing.

The [new theorem](../../knowledge/negative-results/linear-subset-classification.md)
permits known linear correlations and vector output labels. If every
t-subset is admissible and reveals no extra candidate scalar, a linear
decoder cannot always provide exactly one of two fixed hidden labels when
N>=t+2. The N=t+1 complement construction is a tight boundary.

A separate bound covers just one protected output. In the current 5-of-54
alphabet of 3,162,510 subsets, a nonpublic fixed linear scalar label is
recoverable from at most 292,825 choices (5/54). If its form is not
proportional to an inventory form, at most 158,125 choices can recover it,
below 5%. These bounds allow correlations preserving subset privacy.

Changing one pool's subset really changes the current decoded message:
B=3,162,510 has 2-adic valuation one. For nonzero rank difference |d|<B and
pool index i<=94, the valuation of d*B^i is at most 115, below 2048. Such a
change cannot vanish modulo 2^2048. Multi-pool aliases still exist.

The existing PRF-encrypted complement and garbled mixed-radix decoder are
nonlinear and outside these bounds. Their honest measurements are unchanged;
public setup binding remains unresolved.

## Evidence

Ten tests pass: 56 curve evaluations of all 14 nonconstant binary gates,
14 openings of three larger complement lookups, twelve alternative-message
rank checks, altered commitments, wrong-function rejection and malformed
openings. A 50,625-case coordinate-subspace screen corroborates the rank-two
boundary. Support enumeration covers 21 (N,t) configurations through N=7.

Correlated Vandermonde examples examine 437 projective target directions and
all relevant subsets over F5/F7; no two hidden labels cover their full
alphabets. Another 480 cases construct the missing subset from the general
proof. The current decoder parameters are read from its pinned report.
These finite checks corroborate, rather than replace, the proofs.

Evidence: **locally-reproduced** tests and **inspected** proofs. Deployment:
**unclassified**. No script, witness, hints, stack peak, opcode budget,
transaction, Core execution or setup benchmark is produced; those metrics
are not applicable, not zero. Existing native artifacts and APIs are unchanged.

A next construction needs publicly bound nonlinear decoding, a different
authenticated message interface, or a cheaper suitable native disclosure.
Additional linear sharing of the full 5-of-54 alphabet does not supply the
missing binary-label bridge.

The [ratio-label follow-up](ratio-labels.md) tests replacing those linear
outputs by relative logarithms. Fixed public affine endpoint forms require
the same disclosed span, apart from publicly recognizable constant labels;
different native openings and nonlinear metadata are outside that extension.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/shared_vector_gate_probe.py -v
```
