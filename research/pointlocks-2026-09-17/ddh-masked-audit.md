# Masked audit boundaries for the DDH label table

Question: can fresh scalar masks repair the public setup check of the
[DDH batch-select candidate](ddh-batch-select.md), while preserving its
aggregate-only label access? The comparison objective is a publicly checkable
algebraic setup without adding a proof protocol or revealing alternative
labels. Two specific shortcuts fail. This is not an impossibility result for
all masked protocols.

[Executable reproduction](ddh_masked_audit_probe.py) and
[exact results with source hashes](ddh-masked-audit.json).

## A row action can disclose labels without disclosing its scalar

Keep the previous notation: `K=(k0,...,kb)`, independent public row points
`R_i`, and the table

```
B_i  = L_i^0 + k0 R_i
D_ij = k_j R_i                         (j != i)
D_ii = k_i R_i + L_i^1 - L_i^0.
```

A valid publication of y reveals `k=k0+sum_j y_j*k_j` and the selected
labels. Suppose additional setup data exposes only the group element
`A_i=<a,K> R_i`, for public coefficients a. The observer does not need the
scalar `<a,K>`. It computes

```
U = k R_i - sum_(j != i) y_j D_ij = k0 R_i + y_i k_i R_i
V = A_i   - sum_(j != i) a_j D_ij = a0 k0 R_i + a_i k_i R_i
d = a_i - a0*y_i.
```

When `d != 0 mod n`, both masks and both labels follow:

```
M_i = (V-a0 U)/d = k_i R_i
M_0 = U-y_i M_i  = k0 R_i
L_i^0 = B_i-M_0
L_i^1 = L_i^0+D_ii-M_i.
```

The prototype's canonical label decoder and precommitted hashes verify these
labels. Their XOR discloses its common free-XOR offset, which flips every
delivered label. Without that common offset, the demonstrated consequence
is the pair at row i, not automatic propagation to every other row.

If `d=0`, the action is already computable from the legitimate opening and
off-diagonal cells. A fixed setup action is redundant for *every* future
message only if `a0=a_i=0`, since both `y_i=0` and `y_i=1` must be supported.
In that case it was already computable from the off-diagonal table alone.
This is a characterization of this specified row-action interface, not a
complete privacy theorem.

For example, exposing a freshly masked response `z=h+<a,K>`, together with
`H=hG` and `V_i=hR_i`, permits the public check
`zG=H+sum_j a_j K_j`. But it also reveals `A_i=zR_i-V_i`, so hiding h and
the unmasked scalar does not prevent the recovery above. The condition that
the corresponding row action is exposed or derivable matters; a hidden
scalar mask by itself is not claimed unsafe.

## Unbound mask points do not certify the DH table

Consider an off-diagonal column claim `D_ij=k_j R_i` with public `K_j=k_jG`.
A proposed plain algebraic certificate supplies z, H and V_i and checks

```
zG   = H   + c K_j
zR_i = V_i + c D_ij                    (i != j).
```

If c is fixed by the statement before H and V_i are chosen, anyone can pick
z and define `H=zG-cK_j`, `V_i=zR_i-cD_ij`. These equations pass even when
the claimed table is false. Including the table in the hash defining c does
not fix this ordering. The missing condition is that every V_i uses the
same scalar h as H.

This is **not** a counterexample to a proper Schnorr, DLEQ or Fiat–Shamir
proof. A challenge that also binds proof commitments has a different
analysis. Such a proof has not been implemented here and would require
revisiting the explicit no-ZKP constraint.

The two results must also be kept distinct. For a column j check with
`a=c*e_j`, an off-diagonal row i has `a0=a_i=0`; the row-action recovery
above is redundant there. It does not imply that a correctly designed
off-diagonal DLEQ proof leaks diagonal labels. The counterfeit certificate
fails because its mask relations are not established, not because every
possible proof of those relations must leak.

## Reproduction and scope

Three focused deterministic tests pass:

- Exhaustive F5 regression: 15,000 coefficient/message/row cases, 12,000
  nonzero determinants, and 75 row/coefficient choices redundant for all
  eight messages. The general argument is algebraic, independent of this
  small-field regression.
- Actual secp256k1 arithmetic: 80 recoveries of all alternative labels,
  64 redundant-row controls and 80 wrong-mask-action rejections. Coefficients
  cover unit vectors, dense combinations and negative residues. Receiver
  functions receive neither h nor the hidden key vector.
- An honest certificate passes. Changing one off-diagonal cell by G leaves
  the public keys, row bases, offsets and label hashes unchanged. A certificate
  derived from public data alone still passes, but four of the eight valid
  aggregate openings fail the original label checks. Three separately
  malformed certificates are rejected. Hidden fixture keys are used only
  to confirm the false table relation and produce expected valid openings.

Run only this probe:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/ddh_masked_audit_probe.py -v
```

Evidence: **inspected** algebra and **locally-reproduced** coefficient and
curve regressions. Deployment: **unclassified**. This experiment operates on
offchain group objects; it provides no Bitcoin Script, transaction, native
aggregate lock, public setup verifier or setup benchmark. Script bytes,
serialized witness bytes, hint items, entry items, combined stack peak,
opcode counts and native budgets are not applicable, rather than zero.
The earlier DDH benchmark sources and results are unchanged.

An acceptable next construction must supply a concrete public check whose
relations cannot be absorbed into freely chosen mask points, and whose
disclosures remain harmless after every permitted future aggregate opening.
It must independently supply native aggregate-only extraction. Neither gate
is closed by this experiment.
