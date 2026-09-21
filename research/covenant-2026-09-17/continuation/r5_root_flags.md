# R5: native flag enforcement for a hash-derived ECDSA commitment

Date: 2026-09-17. Question: can `alpha=SHA256(proof)` be required by existing
Bitcoin opcodes to sign **every output**, while its DER `(r,s)` remain free
commitment data? Comparison objective: a native flag gate whose honest cost
is not an additional full-scalar/point coincidence and whose complete Script
can coexist with the commitment and digest construction.

**No complete ALL-output gate was found.** There is a small native guard
against the legacy out-of-range SINGLE constant, but it does not reject NONE
or in-range SINGLE. Requiring a fixed ALL signature under the same key adds a
specific group equation, not just a trailing-byte restriction. These are
narrow statements about the tested mechanisms, not an impossibility proof for
all existing-opcode constructions.

Mathematical analysis is `inspected`; the deterministic host reproduction is
`locally-reproduced`; deployment is `unclassified`. No Script executor or Core
was used in this file's reproduction. The raw candidate byte counts below
are inspected boundary vectors, not optimized repository primitive metrics.
No library code or tests were changed and no field-arithmetic tests ran.

## 1. Only 16 of the 256 consensus flag bytes fail to commit every output

For legacy ECDSA, the low five bits select the output behavior:

- `flag & 31 == 2`: NONE, 8 possible complete flag bytes;
- `flag & 31 == 3`: SINGLE, 8 possible complete flag bytes;
- all other values: ALL-like output serialization, 240 possible bytes.

ANYONECANPAY changes input commitment, not this output rule. Every ordinary
preimage still ends with the entire flag encoded as a four-byte integer, so
ALL-like bytes do not produce the same digest as `0x01`. `STRICTENC`'s narrower
six-flag rule is a policy restriction for this legacy use, not a flag rule the
locking script can demand by invoking a new opcode.

Consequently, honest rejection sampling of a uniformly distributed root's
flag for full-output commitment adds a factor `16/15`, about `0.0931` bits,
not a factor 256. This observation **does not enforce that sampling rule**
against a creator: a NONE root retains its output-independent native meaning.
For policy-defined full-output signatures only `0x01` and `0x81` remain, but
the already investigated hash-to-DER constructions use nonstandard checks.

The pinned semantics are Bitcoin Core
[`49faec4f87f5cd19c88db01a82e5c68b087c8227`, interpreter.cpp](https://raw.githubusercontent.com/bitcoin/bitcoin/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp),
particularly `CTransactionSignatureSerializer`, `SignatureHash`,
`IsDefinedHashtypeSignature`, and `EvalChecksigPreTapscript`.

## 2. A five-opcode guard rejects exactly the SINGLE-bug equality

Starting with `alpha P`, consider the raw fragment

```
OP_2DUP OP_CHECKSIGVERIFY OP_CODESEPARATOR OP_CHECKSIG OP_NOT
```

Hex `6eadabac91`; 5 bytes, 5 counted opcodes. The first check sees effective
scriptCode `6eadac91`; the second sees `ac91`. Let their native digests be
`z0,z1`. The predicate is

```
ECDSA(alpha,P,z0) AND NOT ECDSA(alpha,P,z1).
```

When `flag & 31 == 3` and input index is at least the output count, both checks
use the legacy constant digest, whose bytes are `01` followed by 31 zero
bytes and whose ECDSA scalar is `2^248`. A first successful check then forces
the second to succeed, so the guard rejects. This conclusion holds for all
recovery branches, keys, and nonempty signatures, without a random-oracle
assumption.

Outside that bug case, both NONE and ALL continue hashing their different
scriptCodes. The different contexts generally give different scalars, so the
second check normally fails under a key recovered for the first, regardless
of whether outputs were included. It is not sufficient to reject one famous
constant-digest case and infer that the surviving flags bind all outputs.

The reproduction evaluates actual curve equations for all 256 flag bytes at
two input indices in a two-input, one-output synthetic transaction. It uses
DER `(r,s)=(1,1)` with each flag; **these 512 synthetic signatures are not
claimed to be hashes of known preimages**:

| Case | Accepted | Rejected | NONE flags accepted |
|---|---:|---:|---:|
| input 0, one output | 256 | 0 | 8 |
| input 1, one output | 248 | exactly the 8 SINGLE flags | 8 |

The fragment requires exactly 2 entry data items, 0 hint items, and has an
inspected combined main-plus-alt-stack peak of 4. No hints coexist with its
inputs, and it leaves one boolean, suitable as a terminal predicate. Standard
relay flags reject its nonempty failed CHECKSIG (`NULLFAIL`) and legacy
CODESEPARATOR use; no policy acceptance is claimed.

## 3. The actual public hash root also bypasses that guard under NONE

With entry stack `proof P`, prepend

```
OP_SWAP OP_SHA256 OP_SWAP
```

The complete raw wrapper is `7ca87c6eadabac91`, 8 bytes and 8 counted opcodes;
its two effective scriptCodes are `7ca87c6eadac91` and `ac91`. It still has
2 entry data items, 0 hints, and inspected combined peak 4. It hashes the
preimage inside the candidate script, so this is more specific than simply
assuming an unconstrained signature.

The existing public 16-byte preimage

```
00000000000000000200a8013bbb8678
```

has SHA256

```
301d020a7993dad81d0e10285a7e020f682a7033db72199360c2dc3599f2d302
```

Its flag is NONE `0x02`, `r=574133785192103850564222`, and
`s=540859624094206118082341328620483283`. Recovery must include `x=r+n`:
`x=r` is not on secp256k1, but `x=r+n` is. This branch is especially relevant
for a short-DER root; the usual near-uniform-256-bit-r heuristic must not
silently discard it.

Recover P against the first wrapper digest using that nonce point. The same
preimage and same P pass the first check and fail the second for each of:

- one intended output;
- two outputs with different amounts, scripts, and output count.

Both corresponding native digest pairs are byte-for-byte identical, since
NONE removes outputs before hashing. The JSON records the exact public key
and digests. This is a deterministic host counterexample to **this guard's
claimed all-output enforcement**, not a claimed execution of the full
commitment-plus-proof protocol. There is no serialized full transaction, so
scriptSig/witness byte metrics are inapplicable rather than zero.

## 4. Why a fixed ALL companion is a group constraint

Let a fixed companion be

```
beta = DER(r0=1,s0=1) || 0x01.
```

Its two possible verification nonce points are `+R0,-R0`, with `x(R0)=1`;
`x=n+1` does not lift. Write the selected nonce as `R0` for either sign. If
beta verifies under P at native ALL scalar `z_A`, then

```
P = R0 - z_A G.
```

If variable alpha `(r,s,flag)` also verifies under that same P at native
scalar `z_f`, for some nonce point `R_alpha` with `x mod n = r`, then

```
s R_alpha - r R0 = (z_f - r z_A) G.                    (1)
```

Equation (1) covers either branch of beta and every `r` or `r+n` branch of
alpha. Checking both signatures implements that point relation. Merely
choosing alpha's flag to be `0x01` does not make it an identity: even if the
scriptCodes and trailing flag match so that `z_f=z_A`, it becomes

```
s R_alpha - r R0 = (1-r) z_A G.
```

For arbitrary proof-derived `(r,s)`, the left side is an independent point
expression. If `r=1` and the nonce branch is the same, it reduces to `s=1`;
with the opposite branch, to `s=-1 mod n`. The exact-copy case passes but its
signature is 9 bytes. Neither this nor the negative-s case is a 20-/32-byte
native hash output with that fixed `(r,s)` choice. An arbitrary 32-byte root
cannot be treated as the same numerical signature with only an unchecked
flag appended.

The reproduction uses the known root's numerical `(r,s)` with 8 synthetic
flag variants. It verifies the exact residual equation for each and confirms
that every corresponding fixed-ALL companion fails, including the variant
whose flag is `0x01`. Only the unmodified NONE variant has a known hash
preimage. A separate exact `(1,1,0x01)` case passes, confirming that the test
does not simply reject every pair.

This experiment does not establish a universal search lower bound. A future
construction could deliberately find roots satisfying (1), use a different
fixed companion, or enforce some alternative relation. It must account for
that group constraint as work; the fact that both signatures say ALL is not
an honest-side shortcut for arbitrary commitment roots.

## 5. Scope of the remaining gap

A genuine construction still needs either an affordable existing-opcode
filter excluding all NONE/incomplete-SINGLE witnesses, or an additional
mandatory output-binding relation that remains valid even when alpha uses
such a flag. Ordinary local stack manipulation, `OP_SIZE`, or a second
CODESEPARATOR context does not supply the missing filter in these candidates.
The already established preimage-equivalence study covers a broader family
of exact context equalities; the present experiment specifically adds the
negative second-check guard and tests the actual public hash root.

Run:

```
python3 research/covenant-2026-09-17/continuation/r5_root_flags.py
```

The script deterministically writes `r5_root_flags.json`. No RNG, network,
wallet, funds, or external transaction is involved.
