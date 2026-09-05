# Point locks

A point lock is the discrete-log analogue of a hash lock. Its public instance
is a secp256k1 point `T = tG`; a successful spend publishes enough signature
material for an observer to recover `t`. The catalog currently records three
constructions with different setup and security boundaries.

## Comparison objective

Compare the on-chain predicate, setup interaction, extraction relation, and
security assumptions for a single point revelation. Locking-script and witness
figures include only the point-lock success branch, not timeout/refund branches,
Taproot control blocks, P2SH wrappers, or complete transactions.

| Construction | Setup | On-chain primitive | Principal drawback |
| --- | --- | --- | --- |
| Schnorr adaptor signature | Interactive; counterparty creates and verifies an encrypted signature | Ordinary tapscript BIP340 `OP_CHECKSIG` | Requires a valid adaptor transcript before funding |
| ECDSA `G/2` small-R | Non-interactive after publishing `T` | Signature length plus legacy ECDSA `OP_CHECKSIG` | Only roughly 80-bit conservative security |
| Three-check ECDSA | Non-interactive; constructed from `T` alone | One signature, two legacy `scriptCode` views, and related keys `T,Q` | Non-standard legacy-only construction; reduced-sighash collision assumption |
| Committed ECDSA | Non-interactive on chain; spender proves the commitment relation off chain during setup | SHA-256 equality plus legacy ECDSA `OP_CHECKSIG` | Requires an off-chain ZK proof and the legacy SIGHASH_SINGLE bug |

## Schnorr adaptor signature

The counterparty produces a Schnorr adaptor signature encrypted to `T` and the
prospective spender verifies it before accepting the contract. Completing the
adaptor signature with `t` yields an ordinary BIP340 signature. Comparing the
completed signature with the previously validated adaptor transcript extracts
`t` (with the convention-specific sign handling required by BIP340).

The blockchain sees only the ordinary x-only public key and `OP_CHECKSIG`; the
point lock is enforced by the off-chain transcript. This is the smallest and
strongest construction here under standard discrete-log and adaptor-signature
assumptions, but setup is interactive: without the counterparty-created
adaptor signature there is no later extraction guarantee. No adaptor library
is added locally because Script contains no adaptor-specific predicate.

## ECDSA with the `G/2` nonce

The spender signs under `T = tG` using nonce scalar
`k = 2^-1 mod n`. The public nonce `R = G/2` has

```text
x(R) = 0x3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63,
```

which is only 21 bytes as a positive DER integer. A low-S Bitcoin signature is
therefore at most `7 + 21 + 32 = 60` bytes including the sighash byte. Script
requires a signature no longer than 60 bytes and verifies it under `T`:

```text
OP_SIZE 60 OP_LESSTHANOREQUAL OP_VERIFY <T> OP_CHECKSIG
```

Given the published transaction digest `z`, extraction tries the two ECDSA
nonce signs and selects the scalar whose public key is `T`:

```text
t = (s*(+/- 2^-1) - z) * r^-1 mod n.
```

Measured facts: the policy-compiled complete predicate is 40 bytes; the
deterministic representative signature is 60 bytes and its serialized
one-item witness is 62 bytes; local tests reproduce signing, extraction, and
legacy ECDSA verification. The `G/2` x-coordinate and DER accounting match the
Binohash paper.

Security inference: Script constrains total encoding length, not the exact
nonce. The Binohash paper estimates about 97 bits to find a smaller comparable
R-value. A conservative point-lock estimate is roughly 80 bits after allowing
alternate `r`/`s` length allocations and generic attacks. That conservative
bound has not been reproduced locally and remains an open analysis item.

## Three-check ECDSA from `T` alone

This construction removes the small-R search assumption, signature
commitment, and setup proof. Let `k0=1/2 mod n`, `r0=x(G/2)`, and let `z0=2^248`
be the ECDSA interpretation of the legacy out-of-range SIGHASH_SINGLE digest.
From the public target derive

```text
Q = -(2*z0/r0)G - T.
```

Reject the publicly detectable cases `Q=infinity` and `Q=T`. The lock is:

```text
OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
OP_DUP <T>
OP_2DUP OP_CHECKSIGVERIFY
OP_CODESEPARATOR
OP_CHECKSIGVERIFY
<Q> OP_CHECKSIG
```

The first two checks verify the same signature under `T` using full and suffix
legacy `scriptCode` views. The third verifies it under `Q` using the suffix
view. The policy-produced predicate is 79 bytes, consumes one signature item,
uses zero witness hints, and has a five-item combined-stack peak.

For digests `zA,zB`, the target checks reconstruct nonce points

```text
RA = s^-1(zA*G + r*T),  RB = s^-1(zB*G + r*T).
```

The strict `length > 57` guard excludes every `r` for which the alternative
field coordinate `r+n` can exist. Consequently `RA=+/-RB`. The opposite case
reveals `t=-(zA+zB)/(2r) mod n`; the equal case requires `zA=zB mod n`, which
is the stated related-scriptCode reduced-sighash collision exception. This
does not rely on an attacker being unable to find an x-coordinate shorter than
`x(G/2)`.

For an honest spend, place the input at an index without a corresponding
output and sign with SIGHASH_SINGLE and nonce `k0`. All checks then use `z0`.
The `T,Q` checks force `r=r0`, and trying both nonce signs extracts `t`. A low-S
signature is at most 60 bytes. If its DER integer is too short for the guard,
the equivalent high-S encoding is 61 bytes and restores consensus-level
completeness, at the cost of an additional policy violation.

The Rust implementation and detailed compatibility matrix are in
[`src/signatures/pointlocks/three_check/`](../../src/signatures/pointlocks/three_check/).
Its deterministic tests reproduce the script, companion relation, intended
legacy execution, both extraction branches, DER boundary, high-S fallback,
and exceptional targets. Execution remains `unclassified`: the complete
non-standard transaction has not been run through a pinned Bitcoin Core.

## Committed ECDSA over the SIGHASH_SINGLE bug

Let `P = xG` be an ECDSA verification key whose scalar `x` is public protocol
data. The spender creates a low-S SIGHASH_SINGLE signature using nonce point
`R = +/-T`, then commits to the complete Script signature item:

```text
h = SHA256(DER(r,s) || 0x03).
```

The lock is:

```text
OP_DUP OP_SHA256 <h> OP_EQUALVERIFY <P> OP_CHECKSIG
```

It must execute in a legacy input whose input index has no corresponding
output. The historical SIGHASH_SINGLE bug then supplies the fixed digest
conventionally displayed as `000...001`. Once the committed signature appears,
an observer computes the nonce scalar and corrects its sign against `T`:

```text
t = +/-(z + r*x) * s^-1 mod n.
```

At the byte interface used by Bitcoin Core and libsecp256k1, the internal
`uint256(1)` buffer is `01 00...00`; ECDSA interprets those 32 bytes as a
big-endian integer. The local helper therefore uses `z = 2^248`, not the
human-display integer `1`. Protocol implementations must follow the actual
digest bytes rather than transcribing the displayed hash as an integer.

During contract setup the spender must give the counterparty an off-chain
zero-knowledge proof that the SHA-256 preimage contains `x(T) mod n` in the DER
`r` field and ends in `0x03`. The proof need not establish curve membership or
ECDSA validity: the public target point is already parsed off chain, and the
on-chain `OP_CHECKSIG` checks the signature. RISC Zero, SP1, and Flock are
possible proving backends, but this repository intentionally does not pull one
in as a dependency.

Measured facts: the complete predicate is 71 bytes; the deterministic
representative signature is 71 bytes and its serialized one-item witness is 73
bytes. Tests reproduce the bug-context signature, exact SHA-256 commitment,
legacy ECDSA validation, extraction, and rejection of substituted signatures,
wrong points, and wrong sighash flags.

## Compatibility

The small-R lock is meaningful in bare legacy, P2SH, and P2WSH scripts because
extraction can use the actual public transaction digest. The committed lock is
limited to bare legacy or P2SH: BIP143 SegWit v0 does not reproduce the
SIGHASH_SINGLE constant-digest bug. The three-check lock is likewise limited
to bare legacy or P2SH and is non-standard in both forms: bare arbitrary
outputs are not standard templates, while executed `OP_CODESEPARATOR` violates
`CONST_SCRIPTCODE` policy. It is incompatible with P2WSH because BIP143 fixes
the required bug. All ECDSA locks are incompatible with tapscript, where
`OP_CHECKSIG` uses BIP340 and 33-byte keys have unknown-key semantics. The
Schnorr adaptor construction is the tapscript alternative.

The local legacy tests use the pinned `bitcoin-scriptexec` interpreter rather
than Bitcoin Core and do not establish relay policy. In the small-R success
test, semantic NOP padding works around a pinned-interpreter FindAndDelete
underflow for scriptCode shorter than the signature; the measured 40-byte
predicate itself is not padded.

## References and status

- Binohash sections 2.1.1-2.1.4 specify ECDSA DER sizing and the 21-byte
  `G/2` x-coordinate; section 2.4.3 specifies the legacy SIGHASH_SINGLE bug.
- BIP340 and BIP342 specify the completed Schnorr signature and tapscript
  verification boundary.
- Fournier's one-time verifiably encrypted signature paper describes adaptor
  signature creation, adaptation, and extraction.

The three ECDSA implementations are `locally-reproduced` with `unclassified`
deployment. The Schnorr adaptor construction is `reported` and unimplemented
locally. None is claimed `policy-validated`.
