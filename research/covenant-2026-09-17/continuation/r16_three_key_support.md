# R16: five pair centers bound the native digest support of three common keys

Question: can R15's general affine three-key interface, including every
nonzero translation, cheaply connect a hash-derived signature under the
constant SINGLE-bug digest to a different signature under native ALL?

For **each fixed valid alpha under a fixed constant C**, the possible second
digest scalars have support at most `5*(p-n-1)`, even allowing arbitrary
second signatures and every affine map. This is an exact geometric support
bound, not an assumption that the map is an endomorphism or that the nonce
logarithms are hard to compute.

In the separately stated model of fresh independent source-hash and native
digest answers, at most `2^64` total queries have success probability at
most approximately `2^-44.08044`. This includes adaptively dividing the
query budget between the two domains. It does **not** apply unchanged to
shared answers such as alpha equal to the actual native digest, or to every
correlated hash construction. No general covenant impossibility is claimed.

Evidence: `locally-reproduced`; deployment: `unclassified`.
[Python](r16_three_key_support.py) and [JSON](r16_three_key_support.json)
record exact rational counts and 594,285 exhaustive small-curve signature-set
comparisons. A second agent independently checked the five-center argument,
infinity/zero-center cases and native-hash bias. There is no new Bitcoin
script, hint/witness interface, Core execution, or complete covenant.

## Five centers suffice, without computing their logarithms

Let alpha have fixed nonzero numerical scalars `(r,s)` and verify at constant
digest C. Its recoverable group keys are

```
K_R = (sR-CG)/r,
R in V(r),
V(r) = {points at x=r or x=r+n, with both signs, where lifts exist}.
```

Only finite keys count. Three distinct common group keys require four nonce
roots, so `1<=r<Delta=p-n`. Write the full set as `{A,-A,B,-B}`. The six
unordered pairs of potential keys have only five different sums:

```
-2C/r * G                                  (two antipodal source pairs),
(s*(epsilon*A+eta*B)-2C*G)/r                (four mixed pairs).
```

The four mixed point sums are distinct from each other and from zero since
`A!=±B` and the group has odd prime order. Removing an infinity key only
removes available pairs; it cannot add a center.

Now let a second valid signature `(rho,tau)` verify for native scalar z under
any three of the finite alpha keys. Its three distinct verification points
also require a four-root recovery set, hence `1<=rho<Delta`. Among these
three points is an antipodal pair U,-U. For its corresponding keys Ki,Kj,

```
rho*(Ki+Kj)+2zG = O.
```

Define the group point `Tij=-(Ki+Kj)/2`. Abstractly write `Tij=tij*G`.
No algorithm is assumed to know tij. The equation nevertheless proves

```
z = tij*rho mod n,
1<=rho<Delta,
tij belongs to a fixed set of at most five scalars.
```

Each scalar contributes at most Delta-1 possible residues, so the union has
size at most `M=5*(Delta-1)`. A zero center contributes only z=0, regardless
of rho, and is included by this upper bound. A source signature with only
two recovery roots cannot supply the three common keys in the first place.
The result covers arbitrary second s values, arbitrary three-key subsets,
matched or mismatched antipodal pairs, and arbitrary affine parameters a,b.
It is necessary, not sufficient: not every value in this envelope admits a
valid second signature.

For the mixed pair, R15's `V=(A+B)/2=vG` gives the same center explicitly as
`t=(C-sv)/r`. Thus its native equation is

```
z = rho*(C-sv)/r,
v = (C-z*r/rho)/s.
```

The quartic still tests whether a proposed known v actually corresponds to
the required pair. This support argument does not provide those logarithms
or solve that test after a real digest is known.

## Exact 32-byte source-format mass

A positive canonical DER integer of byte length k occupies

```
[1,127]                                       if k=1,
[2^(8k-9), 2^(8k-1)-1]                        if k>=2.
```

For a 32-byte signature including its sighash flag, `nr+ns=25`. Intersect
the r interval with `[1,Delta-1]`, use the full positive s interval, and
sum over nr=1..24. Granting all 256 flags gives

```
p_source =
88519191233640796298980838791020172182854025 /
6277101735386680763835789423207666416102355444464034512896
           ≈ 2^-46.01110165.
```

This deliberately overcounts curve-nonliftable r and flags not selecting C.
It is therefore an upper bound on suitable source-hash answers. No uniform
distribution of curve residues is assumed. The JSON records each nonempty
DER-length row and its exact integer count.

As a consistency check, omitting the r<Delta restriction gives
`780045/2^65` for positive r and s. The earlier `780555/2^65` counted strict
DER syntax including zero scalars; it remains a valid upper bound and was
not an incorrect probability for that broader syntax-only predicate.

## Native digest reduction and adaptive query budgets

A uniform 256-bit native hash reduced modulo n is slightly biased. With
E=`2^256-n`, exactly E residues have two possible hash encodings. For any
support set of size at most M,

```
p_native <= (M+min(M,E))/2^256 ≈ 2^-125.06933535.
```

This bound is valid regardless of the locations of the five arithmetic
progressions. It does not silently replace the native hash distribution by
a uniform scalar modulo n.

Use two independent fresh answer tapes, one for candidate source hashes,
one for native digest queries. Both setup and online queries count. For
fixed source index i and native index j, the preceding bound gives

```
Pr[that pair can share three keys] <= p_source*p_native.
```

If a run adaptively spends at most Q queries in total and uses that pair,
then i+j<=Q. There are `Q*(Q-1)/2` such index pairs. Consequently

```
Pr[any suitable pair] <= Q*(Q-1)/2 * p_source*p_native.
```

This is the answer-tape argument already separately checked in
[R11's adaptive allocation analysis](r11_endomorphism_root_cost.md). The
fixed-cap `Q²/4` factor is not substituted for an adaptive total budget.
At Q=`2^64` the bound is approximately `2^-44.080437`. Requiring even 50%
success needs Q approximately at least `2^85.5402` according to this necessary
condition. That is a query-model statement, not a benchmark or a complete
expected-work theorem. Curve arithmetic, memory, funding consistency and
native enforcement costs have been optimistically ignored.

Queries for different sighash flags or transaction templates are included
as native digest queries; such choices are not free extra trials. Choosing
the query inputs adaptively is permitted, but the two fresh answer tapes
remain an explicit modeling assumption. A shared answer, an equality like
alpha=z, or another algebraically correlated reuse of actual hash results
must be analyzed separately. Likewise the bound does not cover the free,
unhashed alpha witnesses constructed by R11.

## Complete small-curve verification and remaining task

For p=43/order31 and p=211/order199, the implementation enumerates every
native scalar z, every four-root target r and every LOW_S target s for each
listed source alpha. Recovery-key intersections of size at least three are
compared directly against the five-center support envelope. The tests make
3,255 and 591,030 comparisons respectively, with all expectations satisfied.
The selected source scalars deliberately include infinity-key exclusions
and zero centers, in addition to ordinary and boundary LOW_S values. Target
two-root signatures are omitted only because three common keys are impossible
for them. No Bitcoin-sized exhaustive enumeration is claimed.

The useful next construction must exploit a concrete correlation outside
the independent-answer model, or use a different native/reference interface.
For a correlated candidate, supply actual serialized hash inputs, show how
Script enforces the needed relations, and count the joint search without
granting a source signature whose exact hash bytes have not been obtained.
Changing only the proposed affine translation no longer escapes this
five-center support result.
