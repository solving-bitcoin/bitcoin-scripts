# Argo MAC and Duty-Free Bits: the input interface still matters

Question: can recent arithmetic garbling replace the expensive Boolean
translation behind the point-lock publication candidates? The objective is
to reduce complete setup work while retaining authenticated future inputs,
public setup checking and scalar extraction. These sources provide useful
translation machinery, but the inspected interfaces do not supply the
missing native publication or public setup check.

[Pinned sources, inspected-file hashes and test results](arithmetic-garbling-interface.json).

## Argo MAC

[Argo MAC](https://eprint.iacr.org/2026/049), by Liam Eagen and Ying Tong Lai,
translates encoded coordinate bits into homomorphic elliptic-curve MACs.
Section 1.1 starts from input encodings whose validity Bitcoin can already
check. Sections 3.2–3.3 handle invalid inputs and exceptional curve formulas;
these guards must survive composition. They do not provide a public check
of arbitrary maliciously generated garbling tables.

Section 4 reports single-threaded Apple M4/24-GB garbling times of 45, 72
and 23 ms for its three BN254 group/MAC profiles, with 7.1, 13.9 and 3.6 MB
tables. Its roughly 25-MB full Groth16-verifier size is a preliminary estimate.
These are **reported** component results, not reproduced complete point-lock
setup measurements. The paper explicitly leaves the pairing-based verifier
construction to subsequent work.

The inspected 14-page PDF is dated January 18, 2026; ePrint metadata lists a
January 19 revision. The official PDF endpoint returned HTTP 403, so the
author-written paper was read through a
[pinned public mirror](https://github.com/zk-coins/research/blob/0534c7236fd612705c8a3fbe1d60de22a9acb768/argo-mac-paper.pdf).
Its SHA256 is recorded in the manifest. No Argo implementation was executed.

## Duty-Free Bits

The official [Duty-Free Bits abstract](https://eprint.iacr.org/2026/476)
describes a transformation from Yao-style input labels to affine arithmetic
encodings, improving communication for BABE and Argo MAC. Its noninteractive
VOLE/OT application still assumes base OTs. This review inspected that
abstract and metadata, not the unavailable full PDF; it does not claim a
review of every theorem in the paper.

The authors' [implementation](https://github.com/alpenlabs/duty-free-bits/tree/594fb4de28fac1f76a93cf9a10cee7a0262b0a52)
was inspected at commit `594fb4de28fac1f76a93cf9a10cee7a0262b0a52`.
Its [`pgs.rs`](https://github.com/alpenlabs/duty-free-bits/blob/594fb4de28fac1f76a93cf9a10cee7a0262b0a52/src/pgs.rs)
has an actual separated interface:

| Procedure | Inputs and result | Composition consequence |
|---|---|---|
| `garble` / `garble_from_seed` | Affine coefficients and coins produce a public `Program` and private `EncodingInfo` | Setup can precede the choice of message. |
| `encode` | Private encoding information and message bits produce one label per bit | This procedure does not enforce Bitcoin authorization or extract a point scalar. |
| `eval` | Program, selected labels and clear message bits produce affine-map residues | The evaluator has a separate API; it does not receive the encoding key. |

The private encoding information contains all bit masks and the common
offset. Supplying it to the receiver would defeat restricted label access.
At this revision, `InputLabels` has private fields and is produced by
`encode`; importing independently supplied point-lock outputs would require
an explicit, justified adapter.

Two accounting/correctness details affect any integration. `program_bits()`
excludes output decoding masks; `mask_bits()` records them separately. Both
belong in complete offchain communication. Also, the API returns CRT
residues of an integer affine expression, not automatically a hidden-quotient
encoding modulo the caller's target prime. Its documentation assigns the
necessary offset smudging and final reduction to the caller. Raw coefficient
residues are therefore not a drop-in cryptographic encoding for our use.

The combined `affine::build_s_aff` driver generates labels internally while
running both parties. Its timings cannot establish input authentication.
Conversely, the separate `pgs::eval` is a useful integration boundary and
should not be confused with that combined driver.

## Executed checks and acceptance criterion

In the unchanged upstream checkout, both focused commands passed:

```sh
cargo test --locked --offline --lib tests::test_s_aff_edge_regimes -- --exact
cargo test --locked --offline --lib pgs::tests::test_pgs_split_matches_oracle -- --exact
```

Each ran one test with 105 filtered out. The second covers input widths
8, 33, 64 and 256 against a direct modular-arithmetic oracle. These upstream
tests use runtime randomness, not recorded deterministic seeds. The result
is **locally-reproduced** upstream correctness evidence, not a deterministic
new fixture, a setup benchmark, a malicious-table audit or a privacy proof.
No dependencies were added to Bitcoin Lab's Cargo manifest or lockfile.

Evidence is **inspected** for the implementation/interface analysis and
**reported** for publication performance claims; deployment is
**unclassified**. No Bitcoin Script or transaction is produced. Script and
witness bytes, hint and entry items, combined stack peak, opcode/validation
budgets and onchain vbytes are not applicable to these offchain tests.

A useful next integration must specify how each accepted Bitcoin publication
produces exactly the labels required by this separated evaluator, how their
relationship to the prebound verifier is publicly checked under malicious
setup, and how all setup work is counted. It must preserve every future
2048-bit message and prevent unintended alternative labels. Faster affine
garbling alone does not establish those properties.

The [public scalar-AND follow-up](public-algebraic-gate.md) tests a different
privacy-free formula-garbling route. Although the local gate's point equations
are publicly checkable, its input labels permit an alternative message.
That example concerns the specified scalar AND adaptation, not Argo MAC or
Duty-Free Bits, and records why output authenticity alone is insufficient
for the active goal's input interface.
