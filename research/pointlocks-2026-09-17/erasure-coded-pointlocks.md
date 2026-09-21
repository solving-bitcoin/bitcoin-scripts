# Erasure coding does not yet close the point-label gap

This bounded review asks whether a practical cap-60 small-r publication can
tolerate accepted signatures with `r != r0`, instead of requiring every
signature to reveal its selected target scalar. Such signatures are publicly
detectable erasures for the known-nonce extractor. **No complete construction
meeting the stated requirements was established.** This is not a general
impossibility result for erasure-coded point locks.

An erasure is a missing *private label scalar*, not a missing proof bit. The
selected public key or authenticated table index already identifies the
published symbol. Ordinary error correction of those public symbols does not
recover independently chosen garbled labels. A protocol needs both enough
surviving secret labels for the garbled verifier and a reason every accepted
selection has that property.

Per-label threshold sharing alone does not improve on repetition: a k-of-n
sharing fails after n-k+1 erasures, whereas repetition is the k=1 case. Nor
does the number of erasures establish their computational cost. In particular,
unconstrained sighash modes can give the spender separately variable digest
fields. A distance argument cannot silently replace the missing joint-work
argument identified in the [repeated-check review](repeated-cap60-sizing.md).

## A concrete algebraic encoding, with explicit missing enforcement

An actual algebraic bridge can be written over the prime-order scalar field.
For binary message coordinates b_i, let independent secret masks A_i and a
shared nonzero secret Delta define selected labels

```
u_i = A_i + b_i*Delta.
```

The two public label points for coordinate i are A_i*G and
(A_i+Delta)*G. An integer/field-linear encoder with matrix M produces

```
x_j = sum_i M[j,i]*u_i
    = sum_i M[j,i]*A_i + v_j*Delta,
v_j = sum_i M[j,i]*b_i.
```

For each possible v_j, setup can publish the corresponding point using only
public point addition and multiplication. This relation can be checked
publicly without a ZKP. Correct selected shares can reconstruct the selected
u_i values using a suitable linear decoder. Recovering those selected values
does **not** by itself reveal Delta: the independent A_i masks remain unknown.

However, each accepted share must select the v_j corresponding to the same
binary message b. A collection of independently accepted point-table choices
does not enforce this. A wrong tuple may interpolate field values that are
neither of the original wire's two valid label scalars. The construction needs
on-chain code-membership enforcement, or a complete protocol argument covering
*every* accepted tuple. Merely declaring wrong tuples invalid after funds have
been consumed supplies neither guarantee. No implementation of that bridge is
assumed here. Small local arithmetic checks may be possible; consistency across
all transaction inputs and compatibility with the garbled verifier still have
to be demonstrated.

Dense binary XOR parity does not automatically make the elliptic-curve label
alphabet binary. Replacing v_j by its parity introduces an unknown carry term
`-2*floor(v_j/2)*Delta` into the scalar equations. If surviving equations for
(u_1,...,u_k,Delta) have augmented rank k+1, their solution reveals Delta and
then both labels for each recovered wire. That is a conditional rank statement,
not a claim that all linear encodings disclose Delta. A construction whose
augmented matrix avoids that exposure still must demonstrate the required
selected-label recovery for every permitted message and erasure pattern.

## Scoped cost bound for a full-field linear decoder

The following numerical screen applies only under all these assumptions:

- The decoder must recover k independent field-valued selected label scalars
  u_i. Independent masks A_i are sufficient for this condition. The later
  [binary-label rank argument](binary-linear-label-rank.md) shows that it is
  also necessary for the direct scalar-linear interface when all binary
  messages are admissible and those labels completely authenticate the
  message: a dependence enables an unauthorized single-bit change. The
  message coordinates being binary do not remove those secret dimensions.
- The n shares are field-linear in u, with generator matrix of full column
  rank k and minimum Hamming distance d. Thus n >= k. This is **not** a bound
  on binary-domain detecting matrices: fewer integer observations can identify
  k public bits without recovering k independent secret masks.
- A row with w nonzero coefficients uses the full binary-message alphabet of
  possible sums. Over the large prime field, its sumset has at least w+1
  values. Each corresponding point is separately authenticated as a table
  entry. This explicitly excludes a new compact authentication primitive or
  table sharing that removes those entries.
- One share opening supplies one optimistically 60-byte signature; a hashed
  table also needs its 33-byte public key. Every counted byte receives the
  full witness discount. All opcodes, indices and transaction framing are
  omitted. Any code-membership checks are granted for free.

The minimum distance is at most each column's nonzero count, by applying the
encoder to a coordinate basis vector. Consequently the sum of row weights is
at least k*d. The row-alphabet bound follows by repeatedly adding a nonzero
coefficient: the sumset becomes `S union (S+a)`, which grows by at least one
unless S is already the whole prime field, because translation by nonzero a
has one full-field orbit. Writing W for the row-weight sum, the direct-key representation needs at
least `34*(W+n)+61*n` witness bytes. The hashed representation needs at least
`21*(W+n)+95*n` witness bytes. Here 34 and 21 include key/table push bytes,
and 61/95 include the signature and optional supplied-key item lengths.

Using W >= k*d and n >= k gives the optimistic bounds

```
embedded keys: k*(8.5*d + 23.75) vbytes
hashed keys:   k*(5.25*d + 29)   vbytes.
```

For k=2,048 independent binary-wire labels, embedded keys already cost at
least **100,864 vbytes at distance 3**; hashed keys cost at least **102,400
vbytes at distance 4**. These exclude every execution and transaction cost.
Repeated identical rows cannot receive independent bad-opening-work credit:
a signature for the same key and actual digest can be reused.

These bounds do not address an encoder with fewer independent secret masks,
a different label alphabet, nonlinear recovery, compact authentication, or a
garbled-verifier design that needs fewer recovered scalars. Such a change
requires its own public binding, extraction, message consistency and size
arguments. No such complete substitute is supplied by calling the current
missing scalars erasures.

Evidence: **inspected** mathematical analysis. Deployment class:
**unclassified**. No code, tests, native execution, benchmark or computational
hardness amplification is claimed in this note.
