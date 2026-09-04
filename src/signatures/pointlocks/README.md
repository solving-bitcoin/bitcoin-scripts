# ECDSA point locks

A point lock has a public point `T = tG` and makes a successful spend reveal
its discrete logarithm `t`, analogously to a hash lock revealing a preimage.
This module implements two ECDSA constructions. Schnorr adaptor signatures are
covered in the knowledge page because their meaningful construction and
verification happen between counterparties off chain.

## Parameters

- `T = tG`: the point whose scalar is to be revealed; no default.
- Small-R lock key: `T` itself is the ECDSA verification key.
- Small-R nonce: `G/2`, whose x-coordinate is the 21-byte integer
  `3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63`.
- Small-R maximum signature-item length: 60 bytes, including the sighash byte.
- Committed lock signing key: `P = xG`, with both `P` and `x` public.
- Committed lock digest: `SHA256(DER(r,s) || 0x03)`; no default.
- Committed lock transaction: legacy SIGHASH_SINGLE at an input index with no
  corresponding output, so the historical constant digest is used.

## Script metrics

The scripts are complete terminal predicates. Locking-script sizes include the
compressed public key and terminal `OP_CHECKSIG`. Witness sizes are consensus
serializations of a one-item vector and depend on the concrete `s` encoding.

| Configuration | Locking script | Representative unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| `G/2` small-R lock | <!-- metric:pointlock_small_r_script -->40<!-- /metric:pointlock_small_r_script --> bytes | <!-- metric:pointlock_small_r_witness -->62<!-- /metric:pointlock_small_r_witness --> bytes | 3 |
| Committed signature lock | <!-- metric:pointlock_committed_script -->71<!-- /metric:pointlock_committed_script --> bytes | <!-- metric:pointlock_committed_witness -->73<!-- /metric:pointlock_committed_witness --> bytes | 3 |

The first script is:

```text
OP_SIZE 60 OP_LESSTHANOREQUAL OP_VERIFY <T> OP_CHECKSIG
```

The committed script is:

```text
OP_DUP OP_SHA256 <SHA256(DER(r,s) || 0x03)> OP_EQUALVERIFY <P> OP_CHECKSIG
```

## Security

For the small-R construction, a low-S signature made with nonce scalar
`k = 1/2 mod n` has a signature item of at most 60 bytes. Once `(r,s)` and the
transaction digest `z` are public, either

```text
t = (s*k - z) / r mod n
```

or the corresponding value for `-k` matches `T`; the sign ambiguity comes from
low-S normalization. The Script does not prove that the nonce is `G/2`. It
only bounds the total DER size. Security therefore rests on the work required
to forge another valid signature within that size bound. The Binohash analysis
records a 21-byte `x(G/2)` and about 97 bits to find a smaller comparable
R-value; a conservative protocol estimate is roughly 80 bits once alternate
`r`/`s` length tradeoffs and generic attacks are admitted. This repository has
not reproduced either work factor.

For the committed construction, let the committed signature use nonce point
`R = +/-T`. With public signing scalar `x` and the fixed bug digest, revealing
the signature gives

```text
t = +/-(z + r*x) / s mod n.
```

Binding rests on SHA-256 second-preimage resistance, ECDSA verification, and
the soundness of the off-chain setup proof. The signing scalar `x` is not an
authorization secret. Reuse that treats it as one would let anyone sign; the
hash commitment is the actual spend authorization.

The bigint helpers in this module are deterministic research utilities and
are not constant-time. They must not handle production secrets.

## Script compatibility and standardness

- Bare legacy Script: both opcode sequences are consensus-compatible, but bare
  outputs are generally non-standard relay templates.
- P2SH: both redeem scripts fit the 520-byte element limit. Standard relay has
  not been reproduced here.
- P2WSH: the small-R construction remains meaningful with the BIP143 digest.
  The committed construction does not: SegWit v0 intentionally does not return
  the legacy SIGHASH_SINGLE bug digest.
- Tapscript: incompatible. Tapscript `OP_CHECKSIG` uses BIP340 Schnorr, and a
  33-byte key has unknown-key semantics rather than legacy ECDSA semantics.

See [`docs/script-types.md`](../../../docs/script-types.md) and
[`docs/standardness.md`](../../../docs/standardness.md).

## Witness and hints

Each script consumes exactly one signature item. Small-R accepts any defined
ECDSA sighash type whose actual transaction digest is supplied to extraction.
Committed ECDSA requires the byte-exact item `DER(r,s) || 0x03`; the final byte
is inside the SHA-256 commitment and selects SIGHASH_SINGLE.

Committed setup additionally requires an off-chain zero-knowledge proof that
the SHA-256 preimage contains the target point's x-coordinate in the DER `r`
field. On-chain DER parsing and `OP_CHECKSIG` establish signature validity, so
the proof need not establish curve membership or duplicate ECDSA verification.
A RISC Zero, SP1, or Flock circuit is an integration choice, not a dependency
of this module.

## Stack contract

For both scripts:

```text
... signature -> ... true
```

On a clean one-item witness, success leaves exactly one truthy item. The
altstack is unused and the peak is three main-stack items.

## Operational notes

Tests cover the 21-byte `G/2` constant, deterministic signing, both extraction
relations, byte-exact commitment enforcement, ordinary-signature rejection,
wrong targets, and wrong sighash flags. Legacy execution uses the pinned
`bitcoin-scriptexec` ECDSA path. The short-R success test appends semantic NOPs
because that pinned interpreter has an unsigned-underflow bug in legacy
FindAndDelete when `scriptCode` is shorter than the signature; the unpadded
script bytes are measured separately.

No zkVM verifier dependency is included. No implementation of adaptor-signature
nonce exchange, transcript validation, or encrypted-signature verification is
included.
