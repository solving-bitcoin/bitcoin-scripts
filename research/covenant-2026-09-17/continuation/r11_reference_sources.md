# R11: source audit of the missing message-bound reference

Date: 2026-09-17. Question: does a follow-up to Binohash, QSB, ColliderScript,
or ColliderVM supply a public, secretless conversion from the intended-output
predicate to a native transaction signature? The comparison is with the
same-input SINGLE/ALL interface in [R10](r10_reference_interface.md), including
all setup work and a creator retaining every intermediate value.

**No new source supplies that conversion.** The concrete new lead is
**Bitcoin PIPEs v2** (2026), reached through ColliderVM's reference to the
original PIPE. Its public witness-signature interface has an exact mismatch:
one valid witness authorizes every message. This remains true even if setup
is ideal, its proof is valid, and no setup key was retained.

Evidence: source claims `reported`; equations and source-interface audit
`inspected`. Deployment: `unclassified`. No Script was generated or executed,
no rare event was mined, and no new consensus claim is made. Locking bytes,
witness bytes, hint-item counts, stack peaks, and opcode metrics are not
applicable to this paper audit. No library or field-arithmetic tests ran.

## 1. The overlooked follow-up: PIPEs v2

The authors' [PIPEs v2 paper](https://www.allocinit.xyz/uploads/pipesv2.pdf),
§§1.1, 3–4, defines setup for a statement `x`, public verification of the
setup, and `WSign(wout,w,m)`. Setup encrypts a Schnorr secret key under `x`;
signing decrypts that key with a witness satisfying `R(x,w)` and signs `m`.
Definition 3.2 requires correctness for **all messages** for such a witness.
Section 1.1 and its footnote 2 explicitly disclaim a binding between the
on-chain transaction and an intended template. The setup proof certifies
encryption/key consistency. It does not impose an output predicate on `m`.

This is not a newly discovered attack on the paper's stated binary
authorization functionality. It is a precise reason that the advertised
signature primitive cannot fill our stronger interface. The authors also
explain the distinction in their [12 February 2026 announcement, “Covenant
Semantics”](https://delvingbitcoin.org/t/bitcoin-pipes-v2/2249): successful
authorization releases unrestricted signing capability. Their 14 February
reply distinguishes this from the earlier functional-encryption design.

### Exact substitution test

Grant perfect setup and even free, mandatory setup validation. Let `x`
contain the intended outputs `O*` and all desired funding parameters. Let
`w_good` establish the full desired off-chain statement, including any
computation of an intended transaction's digest. For any otherwise-valid
transaction `T_bad` with different outputs, execute

```
m_bad     = BitcoinSignatureMessage(T_bad)
sigma_bad = WSign(wout, w_good, m_bad)
```

The relation test still receives `(x,w_good)`, so it accepts. Correctness
then supplies a native signature on `m_bad`. In the concrete construction,
one can equivalently decrypt once and sign `m_bad` directly.

For this substitution, bad preparation costs one valid-witness computation,
one decryption, and one ordinary signature: the same types of operations as
an honest authorized spend. There is no second preimage, native puzzle
repetition, or statistical work gap. Putting a hash of `T_good` into `x`
changes which witness must be produced; it does not change the freely supplied
argument `m_bad`. A new ciphertext for each desired message has the same
problem while its plaintext is the unrestricted signing key.

The required interface is instead a constrained signing function

```
F(x,m,w) = Sign(sk,m) if R(x,m,w), otherwise failure,
```

with security against a party that possesses valid witnesses for permitted
messages, and without exposing `sk`. Merely adding an `m` equality test to
the public WSign wrapper is insufficient: its caller can run WE.Dec and the
ordinary signer separately. This argument does not assume retained HORS
labels, an optional verifier input, or a deleted-key transaction graph.

## 2. New WE implementation work does not change the interface

PIPEs v2 §5.3.1 reports a modeled verifier with about 14,083 variables and
14,371 multiplication constraints, giving an estimated 338 TB ciphertext.
It explicitly distinguishes the model from a complete implementation and
describes security as heuristic. The related [AADP paper, ePrint
2026/175](https://eprint.iacr.org/2026/175), revised 10 May 2026, reports
hundreds of terabytes at 100-bit security. I inspected its metadata and
abstract; its revised PDF could not be fetched, so I do not claim to have
audited that construction or revision.

Neither a storage estimate nor a cloud-dollar estimate establishes honest
total work in the repository's cost model. More importantly, **even granting
WE setup and decryption below `2^64` leaves the substitution above intact**.
Faster witness encryption alone cannot supply message restriction.

## 3. The four requested construction families, revisited

| Source, exact inspected version | Interface actually supplied | Consequence for R10 |
| --- | --- | --- |
| [Binohash](https://robinlinus.com/binohash.pdf), PDF SHA-256 `1be2b63034a86db1f9f4a35c7963248d307583723079ff25284a9fc4affee94a` | A transaction-bound, prover-selected readable subset digest. Appendix D's polyglot optimization makes a 20-byte hash output also a dummy DER signature; it reports about `180*2^46 = 2^53.49` hash evaluations for preparation. | The polyglot prepares admissible dummy signatures. It does not evaluate the intended-output reference or constrain the actual ALL digest to that reference. This conclusion does not rely on whether the preimages are secret. |
| [QSB source](https://raw.githubusercontent.com/avihu28/Quantum-Safe-Bitcoin-Transactions/2c9172051d5c150ef0a994ca6b988a08a3ef9e85/paper/QSB.tex), commit `2c9172051d5c150ef0a994ca6b988a08a3ef9e85` | A hardcoded ALL signature, transaction-dependent ECDSA key recovery, and a hash-to-DER puzzle; separate transaction pinning precedes two digest rounds. | This authenticates a native context and enables readable choices. No computation equating those choices to the designated outputs is added. The nontrivial pinning analysis remains [R4](r4_succinct_reference.md); no ordinary Fiat–Shamir or fixed-query shortcut is inferred here. |
| [ColliderScript](https://eprint.iacr.org/2024/1802), 15 November 2024 revision | The explicit Big/Small representation bridge uses equality of 160-bit native hashes. | Substituting a QSB-readable subset for one side still requires checking the relation between that subset and the intended signature/transaction. Keeping the actual 160-bit bridge retains its search equation; changing its representations requires a new proof. See [the scoped ideal-oracle bound](../bridge_alternatives.md). |
| [ColliderVM](https://eprint.iacr.org/2025/591), 10 April 2025 revision | Collision-based persistence of computation inputs across verifier fragments; the paper distinguishes data persistence from the separate mechanism fixing the computation flow. | Smaller persistence costs do not provide the missing parameter-to-native-ALL-signature evaluator. This is an interface observation, not a repetition of its setup-key attack. |

The current Binohash PDF still prints the SINGLE-bug scalar as `1`; R10
correctly uses `C=2^248`. QSB's repository history includes the corresponding
SINGLE constant correction. A paper's compact notation should not replace
the pinned Core byte-order semantics in the R10 construction. No complete
new Binohash or QSB security audit is claimed here.

## 4. What would change the conclusion

A useful follow-up must instantiate either (a) the constrained signing
function above, secure against its creator retaining setup state, or (b) a
native relation that connects a readable proof parameter to the actual ALL
message and a mandatory intended-output reference. Its full setup and
honest search must be counted. The same-input SINGLE constant, hash-to-DER
syntax, collision-based persistence, and witness-gated key release each
provide useful parts, but the inspected papers do not compose them into
that relation.

This is a bounded source result, not an impossibility theorem for Bitcoin
covenants, functional encryption, or a future message-bound construction.

## Provenance

The [source manifest](r11_reference_sources.json) records URLs, inspected
versions, byte hashes where available, and fetch limitations. The PIPE PDF
was obtained from the authors' site because IACR returned HTTP 403. Its
embedded creation/modification timestamp is `20260205104401+01'00'`, and its
22-page file is pinned by SHA-256; byte identity with IACR was not verified.
The IACR landing page records receipt on 5 February 2026 and approval on
6 February. PDF metadata is provenance, not proof of a publication date.
