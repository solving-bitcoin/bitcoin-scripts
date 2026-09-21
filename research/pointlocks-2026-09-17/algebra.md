# Two-check point-lock candidate: independent algebra review

Date: 2026-09-17. Question: can the recovery-point geometry used in the
covenant experiments simplify the existing three-check point lock while
retaining public extraction of the target scalar?

The two-check predicate has an exact and useful invariant. It does **not**
give unconditional extraction for every mathematically valid ECDSA digest.
Calling it a computational point lock additionally requires a stated
assumption about actual native transaction hashes. In particular, the
known-nonce matching assumption below does not by itself cover every
adversarially chosen target point.

Evidence for the written derivation is `inspected`. The explicit synthetic
arithmetic vector below was `locally-reproduced` with the repository's
Python secp256k1 helpers. Deployment of that vector is `unclassified`: its
digest is deliberately manufactured, and it is not a Bitcoin transaction
or a Bitcoin Core result. Script execution and compiler measurements are
separate obligations of the implementation.

## Parameters and predicate

All scalar equations are modulo the prime secp256k1 group order `n`.
Coordinate comparisons use ordinary integers in `[0,p-1]`. Let

```text
C  = 2^248,
k0 = 2^-1 mod n,
R0 = k0*G,
r0 = x(R0) = 0x3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63,
c  = -2*C/r0 mod n,
T  = t*G,
Q  = c*G - T.
```

Here `r0 > p-n`, and `r0 < n`. Reject `Q=infinity` and `Q=T`.
The script derived only from the compressed public point `T` is

```text
OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
OP_DUP <T> OP_CHECKSIGVERIFY
<Q> OP_CHECKSIG
```

This raw serialization is 76 bytes: five guard bytes, one `OP_DUP`, two
34-byte compressed-key pushes, and two signature-check opcodes. It uses
one complete signature data item, zero auxiliary hint items, and no alt
stack. The combined stack peak by inspection is three items. Success
leaves one truthy item. These counts describe the complete bare revelation
predicate; they exclude authorization/refund branches, P2SH wrapping,
transaction serialization, and input pushes. Legacy execution has no
witness serialization. The policy-produced implementation must establish
its own final byte measurement.

Both checks use the same signature item and the same legacy `scriptCode`.
There is no separator. Under current strict-DER consensus rules a valid
signature item has length at most 73 bytes. Every accepted signature push
therefore starts with a direct-push opcode in `[58,73]`; no instruction
boundary of this script has such an opcode. The two embedded public-key
pushes use opcode 33. Thus legacy `FindAndDelete` cannot delete an accepted
signature item from this script. The keys remain inside the native
`scriptCode` hash input.

## Exact acceptance invariant

Let an accepted signature encode nonzero scalars `(r,s)`. Write `z` for
the actual 32-byte native digest interpreted big-endian and reduced
modulo `n`. The two ECDSA verifications reconstruct

```text
RT = (z*G + r*T)/s,
RQ = (z*G + r*Q)/s.
```

Both are finite, and both x coordinates reduce to `r` modulo `n`.

If `r+n < p`, then `r < p-n`, so its positive DER integer takes at most
17 bytes. Even allowing a 33-byte positive DER `s`, the entire signature
item including its sighash byte would take at most `7+17+33=57` bytes.
The size guard rejects it. Consequently each accepted `r` has at most
the single field-coordinate lift `x=r`, and the nonce points are equal
or opposite.

They cannot be equal: subtracting their definitions would give
`r*(T-Q)=infinity`, contradicting `r != 0` and `T != Q`. They are
therefore opposite. Adding gives

```text
RT + RQ = (2*z*G + r*(T+Q))/s
        = (2*z + r*c)*G/s
        = infinity.
```

The group has prime odd order, so

```text
2*z + r*c = 0,
r = r0*z/C mod n.                         (1)
```

This conclusion is exact. In particular, an accepted signature cannot
have `z=0`, because (1) would require `r=0`. No nonce-logarithm knowledge,
hash-randomness assumption, endomorphism assumption, or curve-root search
estimate is used in this proof.

## Honest spend, extraction, and exceptional targets

An honest spender places the legacy input at an index with no
corresponding output and uses SIGHASH_SINGLE. Its actual native digest
then has internal bytes `01 00...00`, hence `z=C`. Equation (1) forces
`r=r0`, so `RT` is `R0` or `-R0`. The public extractor tries

```text
t_candidate = (s*(+/-k0)-C)/r0 mod n
```

and returns the candidate whose public point is `T`.
The extractor must calculate the actual native digest from the actual
transaction; a witness-supplied alleged digest is insufficient. It may
perform this extraction whenever the actual reduced digest equals `C`,
even if that value occurred outside the historical bug path. In fact
`C+n > 2^256`, so `C` has only one 256-bit representative.

The honest signature is

```text
s_raw = (C+r0*t)/k0 mod n.
```

Normalize to low-S when its encoding passes the guard. If that encoding
is too short, use `n-s_low`; the 33-byte high-S integer produces a
61-byte complete signature with the 21-byte `r0`. That fallback is
legacy-consensus compatible but violates LOW_S relay policy. The usual
low-S signature is at most 60 bytes. Policy acceptance of a representative
low-S transaction must not be described as policy completeness for all
targets.

The two rejected points have known public discrete logs:

* `Q=infinity` occurs at `T=c*G`; there is no valid companion key.
* `Q=T` occurs at `T=(c/2)*G=-(C/r0)*G`; the honest numerator is zero,
  and the proof that the nonce points differ also fails.

These exclusions are detectable from `T` alone. They are not an unknown
secret setup requirement. The script supplies revelation only, not
independent payment authorization.

## Synthetic ordinary-digest vector: what algebra does not prove

Choose public fixture scalars `t=7`, `k=3`. Set

```text
r = x(k*G) mod n,
z = C*r/r0 mod n,
s = (z+r*t)/k mod n.
```

The resulting low-S vector is

```text
r = f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
s = 4f633ed2107778e8fc75442db3ec140c8f73478351cbfc2f53b4520570716e1a
z = 1dd5f66b30f91548f4f19fdf4f76fcfa1a168a0b790a8220cffd95d308785105
```

The complete 72-byte signature item is

```text
3045022100f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f902204f633ed2107778e8fc75442db3ec140c8f73478351cbfc2f53b4520570716e1a01
```

It passes both ECDSA equations and the size predicate for this supplied
digest, but `z != C`, `r != r0`, and neither G/2-based extraction candidate
matches `T`. This disproves any claim that the two ECDSA equations alone
force the known nonce. It does **not** give a transaction with this
digest, an efficient native bypass, or a proof that no other extractor
exists. The fixture's `t` and `k` are intentionally public.

Reproduction without creating additional files:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 - <<'PY'
import sys
sys.path.insert(0, 'research/covenant-2026-09-17')
from legacy_same_signature_counterexample import N, P, mul, verify, signature_integer
C = 1 << 248
k0 = pow(2, -1, N)
r0 = mul(k0)[0] % N
c = -2*C*pow(r0, -1, N) % N
t, k = 7, 3
T, Q = mul(t), mul((c-t) % N)
r = mul(k)[0] % N
z = C*r*pow(r0, -1, N) % N
s = (z+r*t)*pow(k, -1, N) % N
s = min(s, N-s)
body = signature_integer(r) + signature_integer(s)
sig = b'\x30' + bytes([len(body)]) + body + b'\x01'
assert r > P-N and r != r0 and z != C and len(sig) == 72
assert verify(z, r, s, T)[0] and verify(z, r, s, Q)[0]
assert all(mul((s*e*k0-z)*pow(r, -1, N) % N) != T for e in (-1, 1))
print('synthetic vector verified; no actual native transaction supplied')
PY
```

## Additional assumption and target-selection scope

For a spender that knows `t`, every accepted ordinary transcript exposes
to that spender a nonce scalar

```text
k = (z+r*t)/s mod n,
x(k*G) mod n = r0*z/C mod n.               (2)
```

It is nonzero because the reconstructed nonce is finite. The relevant
additional assumption is hardness of finding this match using an
**actual native legacy transaction digest** and a known nonce scalar,
with the public target and companion key embedded in the applicable
script and with the actual funding dependencies respected. Choosing an
arbitrary `z`, as the vector above does, is outside this game.

Two quantifiers must be kept separate:

1. **Known-scalar target game.** The adversary knows `t`, or a reduction
   is given it. A valid ordinary spend then yields a known `k` by (2).
   Known-nonce matching resistance is sufficient to rule out that bad
   branch in this game. Knowing `t` does not make the matching task
   disappear: it only lets a found match be turned into the required
   signature.
2. **Arbitrary point-only target game.** The adversary may select `T`
   without knowing its discrete log, or receive an external `T` for
   which no party supplies that log to the reduction. A valid signature
   yields the point `RT`, not the scalar `k`. The inference that the
   adversary knows `k` is invalid in this game. A proof of knowledge at
   setup would change the advertised point-only interface.

For the second game the presently sufficient assumption is stronger:
computational resistance to constructing any valid ordinary two-check
native transcript, allowing adversarial target selection and all
retained setup state. That is a construction-specific native-transcript
assumption, not a consequence proved here from the known-nonce game.
Closing this gap is necessary before claiming the same arbitrary-target
extraction guarantee as the three-check design.

Native hashing includes `T,Q` in `scriptCode`, and normal funding also
commits to the locking script. Recovering a convenient target point
after freely selecting a digest therefore does not produce an actual
native transcript. Conversely, this dependency observation is not a
proof of hardness and must not replace one.

## What the approximately 128-bit estimate means

For a fixed set of `qK` known nonce coordinates and `qH` independent
uniform 256-bit native-hash answers, each nonce fixes one reduced digest
through (2). A reduced scalar has at most two 256-bit representatives, so
the union bound is at most

```text
Pr[one match] <= min(1, 2*qH*qK / 2^256).
```

Independent-list birthday searching consequently has a cost scale near
`2^128`, subject to usable transaction variation, point-generation,
storage, and verification costs. This is a **model estimate**, not an
established attack lower bound. It does not cover an arbitrary adaptive
algorithm choosing nonce scalars from previous hash answers, possible
special structure of the deterministic secp256k1 coordinate map, or
unknown-log target selection. No ECDLP reduction or generic-group lower
bound for the complete native construction is supplied here.

## Relation to existing cryptographic notions

Ordinary ECDSA unforgeability does not directly settle the known-scalar
game: that adversary already has the signing key. It also does not
automatically cover adversarial selection of the verification key.
Hash collision resistance alone concerns equality of hashes and does
not assert hardness of the coordinate/hash relation (2).

The closest descriptive notion is resistance for one specified
input/output correlation. Canetti, Goldreich, and Halevi define
correlation intractability relative to relations and distinguish
relations that are evasive even for a random oracle. Their general
results are not a theorem that SHA-256 or this particular relation has
the required property. See [The Random Oracle Methodology, Revisited,
arXiv:cs/0010019v1, sections 3.1 and 5.3](https://arxiv.org/pdf/cs/0010019v1).

Here the nonce scalar or signature is an additional witness that need
not occur in the hashed preimage. Merely naming correlation
intractability does not remove that witness or prove the relevant
relation evasive. An assumption stated directly as the actual native
game above is more precise than claiming a standard instantiated
correlation-intractability theorem. Likewise, an extractable-signature
or knowledge assumption would be an additional assumption or protocol
component; ordinary signature verification is not evidence of scalar
knowledge.

## Comparison with the 79-byte construction and R9/R18

The existing [three-check implementation](../../src/signatures/pointlocks/three_check/README.md)
uses one signature, two `scriptCode` views, a five-item stack peak, and
the same size guard. If its two target-key digest scalars differ, the
two nonce points must be opposite and the public transcript directly
gives `t=-(zA+zB)/(2r)`. Equal ordinary digest scalars are instead the
stated related-scriptCode hash-collision exception. The SINGLE-constant
case uses the companion key to force `r=r0` as above.

Removing the extra target check and separator saves three script bytes
and reduces the stack peak. It also removes the executed-CODESEPARATOR
policy obstacle for a P2SH realization. It changes the extraction
assumption substantially: all ordinary matching transcripts now need
the extra hardness treatment, even though no hash collision is present.
The rare high-S policy-completeness exception remains.

[R9](../covenant-2026-09-17/continuation/r9_recovery_audit.md)
proves equal digests for one signature shared by three distinct group
keys in both contexts, including four-root cases. That cannot simply
replace the guard or add a third honest key here: `r0 > p-n`, so the
honest G/2 signature has only two possible nonce points and hence only
two recovery public keys in one digest context.

[R18](../covenant-2026-09-17/continuation/r18_endomorphism_resultant.md)
excludes nonzero affine translations of three recovery roots for six
endomorphism slopes. The present acceptance proof uses only two roots
in one context. R18 does not force their scalar discrete logarithms to
be known and does not prove ordinary native-hash matching hard. Its
role here is to prevent importing an unjustified three-root shortcut,
not to supply the missing cryptographic reduction.

The resulting status is therefore a compact conditional point-lock
candidate with an exact constant-digest extractor, not an unqualified
replacement for the three-check revelation guarantee.
