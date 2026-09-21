# The scalar interface of the local DDH compression has rank one

Question: can another linear sharing or public algebraic check connect the
[DDH batch-select prototype](ddh-batch-select.md) to separately opened point
locks without the common-shift failure? For this ciphertext layout, **every
additional nonredundant scalar-linear disclosure of its key vector gives an
explicit two-label recovery**. This extends the earlier common-shift example
to arbitrary known linear coefficients. It does not exclude nonlinear
constructions or supply a native Bitcoin aggregate lock.

[Independent Python reproduction](ddh_linear_leakage_probe.py),
[exact results and provenance](ddh-linear-leakage.json).

## Precise disclosure model

Write the hidden key vector as `K=(k0,k1,...,kb)` over the secp256k1 scalar
field. A valid opening for bit vector y releases

```
c_y = (1,y1,...,yb),          k = <c_y,K>.
```

The public matrix and offsets are the existing construction's

```
B_i = L_i^0 + k0 R_i
D_ij = k_j R_i                              (i != j)
D_ii = k_i R_i + L_i^1 - L_i^0.
```

Suppose the wrapper additionally requires revealing `ell=<a,K>` for a known
coefficient vector a. A known constant in an affine disclosure can be
subtracted first. We do not assume that these coefficients are small or
nonnegative. Nor does the calculation require an honest recipient's knowledge
of any row randomizer, hidden key coefficient or unopened label.

If `a` is not a scalar multiple of `c_y`, some row i satisfies

```
d = a_i - a_0*y_i != 0 mod n.
```

From the public off-diagonal cells and the two disclosed scalars, compute

```
U = k R_i   - sum_(j != i) y_j D_ij = k0 R_i + y_i k_i R_i
V = ell R_i - sum_(j != i) a_j D_ij = a0 k0 R_i + a_i k_i R_i

M_i = (V-a0 U)/d = k_i R_i
M_0 = U-y_i M_i  = k0 R_i

L_i^0 = B_i-M_0
L_i^1 = L_i^0 + D_ii-M_i.
```

Canonical decoding yields both binary labels. Under the prototype's common
free-XOR offset, their XOR is Delta, so every delivered input label can be
flipped. This recovers a complete alternate input-label vector. Even without
free-XOR, the two labels at row i are exposed; the global propagation would
then need a separate argument.

Conversely, `a=a0*c_y` gives `ell=a0*k`: the disclosure is already computable
from the valid opening and supplies no additional information. Thus, within
the specified scalar-linear disclosure model, the allowed coefficient space
is exactly the one-dimensional span of c_y. This is a statement about added
information, **not a full security proof for the aggregate-only encoding**.
Two or more disclosures do not help if their span stays in that line; if one
lies outside it, the displayed recovery applies immediately.

## Consequences for native composition and setup checking

- If a Bitcoin wrapper reveals several linear shares of K from which the
  aggregate k is reconstructed, those shares must all be redundant multiples
  of k to avoid this recovery. Merely choosing more elaborate public weights
  instead of the previous common shift does not repair that interface.
- Any fixed, nonzero scalar-linear setup disclosure is nonproportional to
  c_y for at least one future message y. In fact the spans of `(1,0,...,0)`
  and `(1,1,0,...,0)` already intersect only at zero. Such a disclosure cannot
  be assumed harmless for every future message.
- This does not cover a response containing fresh hidden blinding variables,
  nonlinear disclosures, an entirely different ciphertext structure, or an
  independently specified proof protocol. It is not a general prohibition on
  publicly verifiable encryption or algebraic setup.

The attack concerns information the proposed wrapper itself would disclose,
even with honest setup. It does not rely on a malicious creator gratuitously
publishing secrets it already possesses.

## Public affine relations between rows are also unsafe

The previous relative-randomizer test was a special case. Suppose public
coefficients give a relation

```
R_i = gamma G + sum_(j != i) beta_j R_j.
```

Since `K_i=k_i G` and the off-diagonal `D_ji=k_i R_j` are public,

```
k_i R_i = gamma K_i + sum_(j != i) beta_j D_ji.
```

Subtracting this mask from D_ii exposes `L_i^1-L_i^0`. One legitimate label
at row i then yields the other. Free-XOR propagates this to every alternative.
Consequently, deriving many rows from one or a few bases using published
affine coefficients is not a safe way to compress or certify this table.
Requiring pairwise distinct row points alone does not exclude this case.

There is a useful, narrower constructive distinction: a public seed can
derive row points directly by hashing x-coordinates and lifting them to the
curve. It need not derive and publish scalars `r_i=H(seed,i)` followed by
`R_i=r_i G`. The new reproduction uses the former method for its honest
profile and never generates their discrete logarithms. Its fixed derivation
can be checked publicly without exposing the scalar masks. This addresses
row-parameter reproducibility only; it does **not** verify `D_ij=k_j R_i`,
bind the encrypted labels, or prove the hardness of the resulting points.

## Reproduced boundaries

The independent program uses the existing Python curve helper rather than
the Rust/libsecp256k1 point operations in the earlier probe. It implements the
same reversible128-bit label embedding and uses new domain-separated public
fixtures. All arithmetic is exact.

- 5,000 coefficient cases exhaust all four-coordinate vectors over F5 for
  all eight three-bit messages. The determinant criterion equals the
  nonproportionality criterion in every case. This finite-field regression is
  separate from the general proof above and the secp256k1 calculations.
- 47 actual secp256k1 extra-disclosure cases recover all alternative labels,
  covering unit-vector disclosures, dense coefficients and negative residues
  over every three-bit message.
- 33 proportional controls take the redundant-disclosure branch and produce
  no result from this extractor; this is not empirical evidence of universal
  privacy. Eight incorrect disclosed values fail the public label checks.
- A deliberately structured profile with `R2=7G+3R0+5R1` exposes all alternate
  labels for all eight messages. This profile is outside the fixed independent
  hash-and-lift row derivation and illustrates an unsafe replacement for it.

The attack functions receive only the public table, declared disclosures and
one valid opening. Hidden fixture labels are consulted only afterwards as
expected results. The report pins this program, its curve helper and the
existing Rust DDH source. Prior benchmark sources and measurements remain
unchanged. No new timing is a claimed setup benchmark.

Evidence: **inspected** universal algebra and **locally-reproduced** exact
coefficient/curve cases. Deployment: **unclassified**. No Bitcoin Script,
transaction, native signature predicate or public ciphertext verification is
provided. Script/witness bytes, hints, stack peaks, opcode counts and native
validation budgets are not applicable to this offchain experiment.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/ddh_linear_leakage_probe.py
```

The next acceptance criterion is sharper: a native connection to this exact
batch-select layout must enforce and reveal its message-dependent aggregate
without disclosing another independent scalar-linear function of K. It must
also retain the missing public ciphertext/label binding. No existing native
candidate in this repository meets both conditions, and the original goal
remains open.

The [masked-audit follow-up](ddh-masked-audit.md) covers one previously
excluded fresh-blinding case: publishing `z=h+<a,K>` and the corresponding
`hR_i` exposes `<a,K>R_i`, which suffices for the same recovery when
`a_i-a0*y_i != 0`. It also reproduces a false-table certificate when the
challenge is fixed before mask commitments. These are scoped failures, not
an exclusion of all hidden masks or a counterexample to proper DLEQ proofs.
