# R20: full specification audit of almost-scriptless adaptors

Date: 2026-09-17. Question: does ePrint 2026/1346 provide native Bitcoin
signing restricted to an output predicate even when its setup creator retains
all keys and randomness?

**The inspected construction does not meet that retained-state requirement.**
Its key generation explicitly returns the unrestricted base signing key.
Functional keys constrain a recipient who lacks that master key. They do not
constrain the party that generated them and retained it.

This resolves the setup question left open in
[the earlier R20 source note](r20_reference_sources.md). It does not establish
an impossibility for other functional-signature constructions or settle the
overall covenant problem.

Evidence: `inspected`. Deployment of a proposed BTC composition:
`unclassified`. No construction, signature program, Script interpreter, or
field tests were executed. There are no script bytes, witness or hint items,
stack peaks, opcodes, transaction weights, or concrete work measurements to
report from this source inspection.

## Source identity and inspection boundary

Emanuele Giunta and Kristina Hostakova,
[Almost Scriptless Adaptor Signatures from any Signature Scheme](https://eprint.iacr.org/2026/1346),
44-page [full PDF](https://eprint.iacr.org/2026/1346.pdf).
Landing-page history: received 2026-06-30, approved 2026-07-02.
The downloaded PDF's creation and modification metadata both read
`20260630114211+02'00'`. The inspected bytes have SHA-256:

```text
194906ef1974c48fd469c77515b4c25d639118f27ddcb108564979e1a02a637f
```

Read-only local copy: `/private/tmp/r20-giunta-hostakova-1346.pdf`.
The earlier web fetch failures did not indicate permanent unavailability:
an ordinary direct HTTP GET of the official PDF succeeded during this pass.
Text was extracted with `pypdf`. Figures 8, 9, and 11 were also rendered and
visually inspected to check the multi-column algorithm ordering. Relevant
sections inspected: introduction and technical overview; definitions 10-14;
Section 4's compiler; Sections 5.1-5.3's concrete constructions and limitations;
and Appendix B.2's bilinear-GGM replacement. This is a targeted specification
audit, not an independent proof verification of every theorem.

## The retained master key is explicit

Definition 10 and Figure 6, pages 15-16, separate master signing from
functional signing. `FS.mskSetup` creates `(vk, sk)`;
`FS.mskSign(sk, m)` signs an arbitrary message using the master key.
`FS.KeyGen(crs, sk, p)` derives a key `sk_p` for a predicate. The unforgeability
experiment gives its adversary `crs`, `vk`, derived functional keys, and a
signing oracle. It does not give that adversary `sk`.

The adaptor compiler makes this distinction concrete in Figure 8, page 20:

```text
AS.Gen:       (vk, sk) <- FS.mskSetup; return (vk, sk)
AS.Sign:      sample r; sigma <- FS.mskSign(sk, m || r)
AS.pSign:     derive sk_p from sk and prove its correct derivation
AS.Adapt:     set r = w XOR rho; use sk_p to sign m || r
```

The public correctness proof for a pre-signature certifies how a restricted
key was derived. It does not certify absence or deletion of the original key.

Both realizations preserve the ordinary signing key:

- Figure 9, page 23: `FS.mskSetup` calls `S.Gen` and returns its keypair.
  The derived key is an obfuscation of a circuit containing `sk`, signing only
  when its predicate accepts.
- Figure 11, page 26: `FS.mskSetup` again calls `S.Gen`. Key derivation garbles
  the ordinary signing circuit with `sk` fixed inside it; witness encryption
  controls which input labels the receiver can obtain.
- Figure 13, page 37: the bilinear-GGM replacement retains the same base
  key-generation structure.

**Inference for this research model:** if the covenant creator is that
key-generating signer and keeps `sk`, then for any alternative transaction
`T'` allowed by the otherwise ordinary signature lock, it computes
`S.Sign(sk, message(T'))` directly. With a native BIP340 instantiation,
`message(T')` is the actual Bitcoin signature digest. It need not evaluate the
functional key, supply a predicate witness, open witness ciphertexts, or use
the adaptor interface. This already defeats the proposed restriction;
retaining all garbling labels only gives additional unrestricted setup state.
This observation is consistent with the paper's stated recipient security.

Function privacy must not be confused with retained-key unforgeability:
the privacy definition can reveal the master key while comparing two ways of
producing a signature for the same message. That experiment does not claim
that the revealed key loses its ordinary signing authority.

## Exact native message boundary

Figure 8 verifies the extended message `m || r` using the base verifier.
Theorem 2, page 21, formalizes a translator moving `r` from the adaptor
signature into the base message. This is not an additional predicate check
performed by the base signature verifier.

The authors explicitly suggest transaction metadata, including Bitcoin
`OP_RETURN`, on page 4 and footnotes 1-2. Therefore the source should not be
described as ruling out Bitcoin applications. There are two distinct
instantiation questions:

1. If `S` is BIP340 on a supplied message, signing
   `TapSighash(T) || r` does not produce the signature Bitcoin expects for
   `T`. Bitcoin's application supplies its prescribed digest, without that
   appended suffix. Appending an `OP_RETURN` output changes the transaction
   being hashed; it does not append bytes after the digest.
2. One could instead define the base scheme over a canonical transaction
   representation, with Bitcoin serialization and signature hashing inside
   `S.Sign` and `S.Vfy`. A functional signing circuit could then incorporate
   that wrapper and sign the transaction containing metadata through ordinary
   BIP340. This is a plausible direction for an adaptor application without
   changing consensus verification, not a demonstrated exact BTC
   instantiation in the inspected sections. It needs a precise message
   domain, input/prevout context, sighash mode, metadata encoding, and a
   proof that the required base-signature and predicate assumptions apply.

The distinction follows from the pinned
[BIP341 signature-validation specification](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0341.mediawiki#signature-validation-rules)
and
[BIP340 verification specification](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0340.mediawiki#verification).
Neither interpretation removes the master-key bypass above. For an exact-output
covenant, any added metadata output would additionally belong to the output
amount/order/scriptPubKey specification being enforced.

## Additional limits relevant to candidate selection

The concrete constructions support predicates with a unique satisfying
input. Section 5.1, Remark 4, allows polynomially many only with extra
extraction and size requirements. An arbitrary predicate saying that a
transaction pays specified outputs can have many satisfying transaction
encodings; it cannot silently inherit the unique-input theorem.

Section 5.3, pages 29-30, also states that the raw ROM construction of Section
5.2 does not directly supply the key-correctness proof needed by the adaptor
compiler. The authors discuss additional modeling assumptions and an
alternative bilinear-GGM construction. Treating the abstract's witness
encryption route as a complete directly implementable pipeline would omit
this interface.

Page 5 frames the work as a feasibility result and disclaims efficiency
competitive with signature-specific adaptors. No concrete sub-`2^64`
setup/audit/signing cost or exact Bitcoin transaction is established here.

For the covenant search, this paper supplies a verified example of a
restricted native-compatible signing *interface*, subject to an exact
transaction instantiation. It supplies no mechanism forcing its creator to
use that interface after retaining the unrestricted signing key. A new
proposal would have to close that separate setup condition before its
functional evaluation machinery becomes a covenant candidate.
