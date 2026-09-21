# R20: functional signatures, retained signing state, and native encodings

Date: 2026-09-17. Question: can newer primary work replace the mandatory
output-reference computation, or reduce a Big/Small representation bridge
below `2^64` total honest work when the creator retains all setup state?

**No complete candidate was established.** Three 2026 papers are new to this
research's source notes. A concrete source inspection resolves one tempting
connection: functional adaptor signatures provide a message-specific fair
exchange, but their inspected implementation retains the ordinary payment
signing key. Its Python signature encoding is also not native BIP340.

Evidence: the implementation findings and the later full-specification audit
of ePrint 2026/1346 are `inspected`; the other paper abstract claims are
`reported`. Deployment of any proposed BTC composition remains
`unclassified`. No source programs, Script interpreters, or field tests ran.
No script-size, witness/hint-item, stack-peak, opcode, weight, or computational
cost measurement is claimed.

## Functional adaptor signatures for general functions

[New Constructions of Functional Adaptor Signatures: Broader Functions and
Improved Efficiency](https://eprint.iacr.org/2026/1124), Vanjani, Greiner,
Thyagarajan and Soni, lists a **2026-09-10 revision**, first received
2026-06-01. Its abstract describes homomorphic-encryption-based functional
fair exchange supporting general functions. A buyer learns the function's
output in exchange for a signed payment. This differs from the unrestricted
witness-gated key release examined in R11: the adaptor completion concerns
a particular pre-signed message. The distinction is useful, but alone does
not restrict someone possessing the payment signing key.

The [authors' implementation](https://github.com/nikhilvanjani/fas-from-he-impl/tree/f59875bbf739280e6fdb460232e3cef00b604f25)
was inspected at commit `f59875bbf739280e6fdb460232e3cef00b604f25`, dated
2025-12-22T21:43:42+05:30. The code predates the latest paper revision; this
audit does not claim correspondence with every change in that revision.
Read-only checkout: `/private/tmp/r20-fas-from-he-source`.

In
[`fas_fpresign2`](https://github.com/nikhilvanjani/fas-from-he-impl/blob/f59875bbf739280e6fdb460232e3cef00b604f25/fas-from-fhe-polynomial.py#L620),
the buyer supplies `seckey` and `msg` to the ordinary adaptor pre-signing
routine. Completion uses the seller's ElGamal secret; extraction recovers
that secret to decrypt the selected function value. The native payment
secret and the seller's encryption secret have distinct roles.

For the present retained-state model, even grant a correct native BIP340
port and give the creator the buyer's setup state, including `seckey`.
It can run ordinary signing on the actual digest of a different-output
transaction. No functional evaluation, adaptor
completion, or ciphertext opening is necessary. This is a mismatch with our
target model, not a failure of fair exchange between the paper's distinct
parties. Giving the payment key to an independent honest signer instead
changes the requested assumptions. Nothing inspected constructs the needed
message-restricted signing authority without that retained ordinary key.

There is also an exact encoding boundary. The inspected
[`schnorr.py`](https://github.com/nikhilvanjani/fas-from-he-impl/blob/f59875bbf739280e6fdb460232e3cef00b604f25/schnorr.py#L22)
serializes full points: verification expects a 64-byte public key and a
96-byte signature. The signing code hashes the full point encodings, and
the BIP340 parity-normalization lines are commented out. Merely dropping y
coordinates would therefore change the challenge. A BIP340-compatible port
would require adapting the actual signature/adaptor algorithms and their
analysis. These Python artifacts are not native Bitcoin signature vectors.
[BIP340](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0340.mediawiki)
specifies x-only 32-byte keys, 64-byte signatures, and the corresponding
challenge/parity rules. This encoding observation does not claim the general
FAS technique cannot be ported.

## Almost-scriptless adaptors: full specification now inspected

[Almost Scriptless Adaptor Signatures from any Signature Scheme](https://eprint.iacr.org/2026/1346),
Giunta and Hostakova, was received 2026-06-30 and approved 2026-07-02.
The functional-signature compiler uses iO in the CRS model or witness
encryption and garbling, with additional considerations for key-correctness
proofs. Its relaxation signs `m || r`, adding randomness to the original
message. The PDF initially failed to download, but a later ordinary direct
GET succeeded. The [full-specification audit](r20_functional_signature_spec.md)
records the inspected PDF's hash, date, exact algorithms, and evidence scope.

Figures 8, 9, 11, and 13 explicitly retain the unrestricted base signing key
in the master setup. The functional-key unforgeability game withholds that
key from its adversary. Therefore a creator retaining it can sign an
alternative transaction directly; the derived functional key does not
constrain that creator. This resolves the previously open setup question
for the paper's actual constructions.

The authors explicitly suggest Bitcoin `OP_RETURN` metadata. A transaction
wrapper that performs existing Bitcoin serialization and sighash internally
could be a route to native-compatible adaptor signatures; this audit does
not exclude that application. Simply signing `TapSighash(T) || r`, however,
is not native verification of `T`, whose digest is prescribed by
[BIP341](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0341.mediawiki).
An exact wrapper and its assumptions still need specification. Neither
message interpretation fixes the retained-master-key issue, and no concrete
sub-`2^64` setup, proof and evaluation cost is established here.

## WOTS-to-Lamport translation: different missing boundary

[Non-Interactive Translation of Winternitz Signatures to Lamport Signatures
via Secret Sharing](https://eprint.iacr.org/2026/1684), Sergeevitch, Staniec,
Tse, Vanjani and Woll, was received 2026-08-13 and approved 2026-08-15.
The abstract describes a translation from compact WOTS commitments to
orthogonal garbled-circuit input labels using secret sharing and checksum
structure. It reports smaller dispute transactions for BABE. This is new
to these source notes, rather than a newly invented construction here.

The described privacy guarantee concerns an evaluator learning permitted
labels without learning mutually exclusive ones. Our creator retains the
garbler's state and all labels, so that evaluator guarantee cannot be
substituted for a compulsory mathematical check. Even granting a perfect
translator, a covenant candidate still needs the native actual-transaction
digest bound to the permitted-output computation and must force execution
of its checks. No such replacement is established by the inspected
abstract. The PDF was unavailable, so no full protocol audit is claimed.

## Scope and next falsifiable result

The existing STATE, primary-source registry, R19 source report, and current
point-lock algebra/Core report were read first. The point-lock work is
unchanged. Its extraction of a scalar from a published signature does not
give Script arithmetic access to that scalar or enforce a different
transaction's outputs; no new such connection was found here.

Searches covered new Bitcoin covenant/equivalence-bridge work, constrained
and functional signatures, adaptor signatures, and restricted short-input
hash-collision work. Previously reviewed ColliderScript, ColliderVM,
Binohash, QSB, PIPEs and R19 BCH material were not reclassified. Searches
did not locate a new restricted-hash bridge with the required cost/model;
this is not an impossibility result or proof of complete literature coverage.

All three ePrint landing pages were read. Full PDFs for 1124 and 1684 remain
uninspected after failed fetches. The initial 1346 fetch failures were
superseded by a successful official PDF download and full-specification
inspection, recorded with a byte hash in the linked audit. Revision dates
for 1124 and 1684 identify metadata, not inspected immutable PDF bytes.
The Git commit above pins the code findings independently.

A useful next source result is a full specification of restricted native
signing whose setup creator cannot use retained state to sign outside the
permitted message set. A useful implementation result is an exact current
Bitcoin transaction plus mandatory reference verifier. Neither a general
functional-computation claim nor a non-native signature benchmark meets
those criteria.
