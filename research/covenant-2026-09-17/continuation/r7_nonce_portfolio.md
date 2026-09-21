# R7: different-nonce portfolios and native length constraints

Date: 2026-09-17. Question: can preprocessing many public known nonces replace
the special G/2 nonce, or supply a stronger transaction fingerprint, while
keeping total honest work below `2^64` and legacy execution below 201 opcodes?
The comparison includes nonce discovery, message search, and checking the
portfolio. The creator retains all nonce scalars and signing scalars.

**Different nonce multipliers escape the previous common-slope partition
argument.** They can produce substantially more length-answer patterns.
However, a length check does not enforce the selected nonce. A portfolio
also does not by itself distinguish allowed from forbidden outputs. A
single fixed-r-length portfolio has an unfavorable exact setup/search tradeoff
in the stated ideal model. Mixed-r-length portfolios need a separate analysis;
they are not ruled out by that tradeoff.

## Different slopes really change the scalar partition

For known nonce `k_j`, nonce coordinate `r_j=x(k_j G) mod n`, and public
signing scalar `d_j`, write

```
s_j(z) = k_j^-1 * (z + r_j*d_j) mod n
low_s_j(z) = min(s_j(z), n-s_j(z)).
```

Thus the exact DER width is an interval predicate after a modular affine
permutation. If the slopes are different, one cannot first change variables
to one common `t=2z` and then apply the old bound on translated endpoints.
For a positive integer slope `lambda`, a single interval can pull back to
as many as `lambda` intervals on the integer representatives `0..n-1`.
Multiplication by a large modular scalar can consequently fragment it
extensively. This is a real difference from merely varying public-key offsets.

The deterministic experiment exhausts all 509 digests of a small prime-order
scalar model, using eight checks and fixed offsets. Invalid zero scalars are
recorded as their own answer, not quietly accepted as signatures.

| Slopes | Complete answer vectors | Entropy in bits |
| --- | ---: | ---: |
| eight copies of 2 | 24 | 4.022 |
| 2,3,5,7,11,13,17,19 | 120 | 6.626 |
| 1,257,409,123,163,245,301,501 | 238 | 7.715 |

These are exact host counts, not secp256k1 measurements, an independent-bit
claim, or an executable nonce-enforcement primitive. The toy order was chosen
so its DER boundary has appreciable probability; ordinary secp256k1 low-S
widths are strongly biased toward 32 bytes. Increasing support size does not
make their real-world entropy one bit per check.

## Exact single-stratum preprocessing/search model

A complete ECDSA signature item has `a+b+7` bytes when r and s require a and b
DER integer bytes. For a 55-byte item, `a+b=48`. This cost model uses the
LOW_S signing strategy throughout; it is not an enumeration of additional
high-S strategies that legacy consensus may accept.

Let `[A_a,B_a)` be the positive integers of DER width a, clipped at n, and
`[A_b,B_b)` the s-width interval, clipped at `(n+1)/2`. For width w above 1,
its un-clipped endpoints are `2^(8w-9)` and `2^(8w-1)`. Define

```
u_a = (B_a-A_a)/(n-1)
v_b = 2*(B_b-A_b)/n.
```

Here `v_b` is the exact success probability for a uniform scalar digest z:
every nonzero k induces a permutation. `u_a` is exact **only in the explicit
ideal uniform-r model**. Actual secp256k1 x-coordinates are curve points, not
all uniformly distributed integers; interpreting `1/u_a` as point-search
work is a heuristic. Uniform 256-bit digest reduction has the additional
small `2^256-n` residue multiplicity, which this scalar-domain model excludes.

Suppose the setup collects M nonce points all from one a-stratum. Its expected
sampling cost is `M/u_a` in that model. For any fixed collection of slopes and
offsets, the union of their message acceptance sets has measure at most `M*v_b`.
Even granting free classification of a digest against the entire collection,
the corresponding setup-plus-digest expected cost is at least

```
C(M) >= M/u_a + 1/(M*v_b).
```

This bound needs no independence between the M length predicates. It grants
each sampled point unit cost, ignores audit and memory, and omits every
portfolio lookup operation, so it is optimistic. Away from clipped widths,
`u_a*v_b` is almost `2^-129.011293` for every split a+b=48. Relaxing M to a
positive real yields `2/sqrt(u_a*v_b)`, about `2^65.505647`. Integer M≥1 is
checked exactly in the program.

| r width a | s width b | Best integer M for this bound | Bound, log2 work |
| --- | --- | ---: | ---: |
| 21 | 27 | 1 | 89.00565 |
| 24 | 24 | 1 | 65.59061 |
| 25 | 23 | 181 | 65.50565 |
| 26 | 22 | 46,341 | 65.50565 |
| 31 | 17 | 50,952,413,380,206,181 | 65.50565 |

The pre-existing public point G/2 is an exception to *paying generic discovery
cost*. Its 21-byte r is already known with its scalar, so its setup is tiny;
the R6 message strategy still costs approximately `2^40.00565` queries. The
table does not charge rediscovery of that supplied point. It explains why a
generic new collection with one chosen r width does not match its advantage.

For M comparable independent events with `M*v_b << 1`, a straightforward scan
uses approximately `1/(M*v_b)` fresh hashes but approximately `1/v_b` scalar
predicate tests: each rejected digest must be tested against M nonces.
Reducing the number of hashes is not the same as reducing total work.

## Mixed widths: a separate batch-incidence problem remains

One point-generation pass samples all r widths. Therefore it would be wrong
to apply the preceding one-stratum bound unchanged to a portfolio retaining
several widths. In the ideal model the summed per-pair probability for exact
55 bytes under this LOW_S strategy is

```
F = sum over a=16..33 of u_a * v_(48-a)
  ≈ 2^-124.923498.
```

This is only a pair-mass calculation. Rare r strata cluster many successes
on the same rare row, and the actual tests `s=(z+rd)/k` share z. A simple
`R*Q*F` expectation must not be relabeled an actual probability of success.

To make that distinction explicit, the artifact also evaluates a surrogate
with R independent nonce rows and Q independent Bernoulli cells conditional
on each row's r width. Its exact formula is

```
U(Q) = sum_a u_a * (1-(1-v_(48-a))^Q)
Pr[at least one hit] = 1-(1-U(Q))^R.
```

An exhaustive 1,024-outcome small model confirms that formula for its stated
independence assumptions. With equal R and Q and counting *only samples*,
the large surrogate gives probability 0.515 at total `2^63.7` samples, or
0.664 at `2^64`. This is not a sub-`2^64` signing algorithm: the naive pair
scan at the former setting performs `2^125.4` modular tests, and the required
row independence has not been transferred to the real modular equations.

The constructive remaining algorithmic question is a batch modular-incidence
query: find a pair `(k,z)` from large explicit sets satisfying
`DERlen(r(k)) + DERlen(low((z+r(k)d)/k)) = 48`, while including point
generation, indexing, lookup, memory handling, and audit in total work.
Arithmetic-progression membership for one k is cheap; no data structure
handling this mixed collection at the sample-only cost is supplied here.
This question concerns improved public signing work, and would still need a
separate mandatory output-reference construction to become a covenant.

## Native enforcement and retaining-creator replay

The complete raw check

```
OP_SIZE <70> OP_EQUALVERIFY <G> OP_CHECKSIG
```

validates a 70-byte signature under the public signing scalar d=1. It neither
extracts r nor verifies that a nonce chosen from an external table was used.
An index selecting a precommitted *public key* would bind the key, but would
still not establish which nonce signed under it. A supplied copy of r or k
must be authenticated to the actual signature before the different-slope
fingerprint above can be used as a deterministic reference.

The host fixture takes 4,057 incremental public point additions to find eight
distinct 31-byte-r nonces. For each of two different output scripts sharing
one synthetic fixed funding outpoint and one fixed locking script, it
constructs **two different-r 70-byte ALL signatures** from that portfolio.
All four actual secp256k1 verification equations hold. This demonstrates both
nonce ambiguity for a fixed message and public replay after changing the
outputs. It is not a claim about the distribution of a large mined portfolio.

Funding order is explicit: public d and the complete check are fixed, then
the synthetic outpoint, then the two distinct output lists and their native
legacy ALL preimages. Nonces remain witness choices and require no locking
script change. The retaining creator has exactly the same signing procedure
for each output list. This particular script also does not constrain the
signature's sighash byte; choosing ALL in the fixture is not a native ALL
guard. NONE and partial SINGLE remain a separate binding obligation.

`complete-leaf:` raw script serialization is 39 bytes with three non-push
operations; one signature data item, **zero auxiliary hint items**, combined
main-plus-alt peak **3** by inspection, with empty altstack. Each synthetic
P2SH scriptSig is 111 bytes containing signature and redeem-script pushes;
serialized witness bytes are zero. Each complete synthetic one-input,
one-output transaction is 772 WU. These are raw host boundary fixtures, not
policy-compiled library metrics, and no Core validation is claimed. There is
no batch of signatures or hidden entry hint stack in this check.

## Evidence and next acceptance test

Evidence: `locally-reproduced`; deployment: `unclassified`. The experiment
does not call the repository's tapscript executor or disable consensus limits.
No field-library tests, primitive metrics, or external experiments were run.

Reproduce:
`python3 research/covenant-2026-09-17/continuation/r7_nonce_portfolio.py`.
The [JSON](r7_nonce_portfolio.json) records the full exact fractions, all
18 width splits, toy counts, nonce table, raw scripts and synthetic spends.

The ECDSA verification and DER conventions follow the pinned
[Bitcoin Core 30.3 interpreter](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).
The special-point baseline and scope of its four digest intervals are in
[R6](r6_length_puzzle.md); the old translated-key argument and its explicit
same-slope scope are in the [second pass](../second_pass_legacy.md).

A successful next construction must either authenticate the selected nonce
inside the complete native check, or formulate a predicate sound under *all*
nonce choices. It must then show why the allowed output reference gives an
advantage that retained nonce tables cannot reproduce for another output.
More answer patterns or fewer distinct digest hashes alone do not meet those
criteria.
