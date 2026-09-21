# NR-067: Separate point-lock shares defeat the common-shift DDH batch-select wrapper

The [DDH batch-select probe](../../research/pointlocks-2026-09-17/ddh-batch-select.md)
delivers an honest full vector of garbled labels from a scalar aggregate key.
Replacing that aggregate-only interface with separately revealed t-of-n point
scalars, using `x_i=k_i+a` and `k0=t*a`, is unsafe for t>=2 under the tested
common-offset label interface.

Two selected openings give `d=x_i-x_j=k_i-k_j`. The public off-diagonal cell
`D_ij=k_j R_i` then gives `k_i R_i=D_ij+d R_i`. Subtracting it from diagonal
`D_ii` reveals `L_i^1-L_i^0`. The honest selected label supplies one endpoint,
so the other label is decoded too. Their XOR exposes the common free-XOR
offset and flips every input label. The full calculation succeeds for all70
four-subsets of an eight-candidate pool with honestly generated tables and
valid public point equations. No discrete-log or hash search is needed.

For1<=t<n the common shift is necessary in this simple additive wrapper:
exchanging one member between two t-subsets forces `x_i-k_i` to be constant.
The result does not exclude t=1, nonlinear wrappers, or native constructions
that disclose only the aggregate. It is not an attack on the published
aggregate-only encoding.

Two other attempted public checks also fail: releasing row randomizers reveals
both labels directly; releasing their ratios lets off-diagonal cells reveal
the diagonal masks after opening. A changed ciphertext cell additionally
passes point/shape checks while preventing one valid aggregate opening from
delivering the intended label. An audit with all secrets is not public setup
verification.

Evidence: **locally-reproduced** eight focused Rust tests and **inspected**
wrapper algebra. Deployment: **unclassified**. No Bitcoin Script or native
transaction is generated. Offchain payload bytes and timing are not onchain
vbyte or full setup measurements. Source, exact commands and benchmark
provenance are linked from the research note.

OP-017 remains open: supply native aggregate-only extraction and public
ciphertext/label binding, or a compression whose security explicitly permits
the extra constituent scalar revelations.

## General scalar-linear interface restriction

The [follow-up proof and independent curve reproduction](../../research/pointlocks-2026-09-17/ddh-linear-leakage.md)
extend the common-shift failure. Given the intended aggregate `k=<c_y,K>`,
every additional known-coefficient disclosure `ell=<a,K>` with `a` outside
`span(c_y)` exposes both labels at a row with `a_i-a0*y_i != 0`. Two public
linear combinations isolate the masks `k_i R_i` and `k0 R_i`. Free-XOR then
reveals every alternative label. Coefficients within that span disclose only
values already computable from k; this is not a complete privacy theorem.

The new program verifies47 secp256k1 recoveries,33 proportional controls,
eight incorrect-disclosure rejections and5,000 small-field coefficient cases.
It also reproduces eight recoveries using the public affine row relation
`R2=7G+3R0+5R1`, without disclosing the underlying row logarithms. This rules
out more general public affine row-compression descriptors, not merely known
ratios. Public hash-and-lift row derivation is a valid way to avoid publishing
those logarithms, but does not validate the encrypted cells.

Evidence: **inspected** algebra and **locally-reproduced** regressions;
deployment remains **unclassified**. The restriction applies to this local
ciphertext layout and the stated linear disclosures. It excludes neither
nonlinear interfaces nor a native aggregate-only construction.

## Fresh masks and public group actions

The [masked-audit follow-up](../../research/pointlocks-2026-09-17/ddh-masked-audit.md)
requires only `A_i=<a,K>R_i`, not disclosure of `<a,K>` itself. The determinant
`a_i-a0*y_i` again isolates both row masks when nonzero. A response
`z=h+<a,K>` with public `hR_i` supplies that action by subtraction. The
reproduction has 80 secp256k1 alternative-label recoveries, 64 redundant
controls and 80 incorrect-action rejections.

The same program shows why unbound mask points cannot certify a column:
for a statement-only challenge c, selecting z first and defining
`H=zG-cK_j`, `V_i=zR_i-cD_ij` makes both verification equations pass even
for a false table. Four of eight otherwise valid openings then fail the
original label checks. This concerns a challenge fixed before commitments;
it is not a failure of proper Schnorr/DLEQ/Fiat–Shamir proofs. In particular,
correct off-diagonal column actions are redundant in the first calculation.

Evidence: **inspected** algebra and **locally-reproduced** three deterministic
tests, including 15,000 finite-field cases. Deployment: **unclassified**.
No native code, complete transaction or setup benchmark is supplied.
