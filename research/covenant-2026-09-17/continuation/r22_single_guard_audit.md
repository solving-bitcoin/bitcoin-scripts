# R22 independent audit: variable-signature SINGLE-bug guard

The guard's scoped claim is sound: an accepting ordinary legacy context
would give two distinct preimages whose double-SHA256 digests agree modulo
the secp256k1 order n. In the absence of that collision, acceptance requires
the out-of-range SINGLE branch. It supplies a constant-context signature
check, not output binding or a complete covenant.

This audit inspected [the generator](r22_single_guard.py) and
[Core companion](r22_single_guard_core.py), independently decoded the raw
opcodes, traced symbolic stack values, and independently parsed all ten
saved transaction serializations and their two native preimages. It did
not import the generator's stack model or transaction serializer for those
checks and did not rerun Core. The byte/stack/serialization checks are
`locally-reproduced`; the general proof is `inspected`. Core evidence is
the existing [saved record](r22_single_guard_core.json), whose positive
spends are `differentially-validated` / `consensus-validated`, not
`policy-validated`.

## Exact stack and byte boundary

The audited 49-byte raw redeem script is

```
745388820121887c820121887c6e8791695279820139a0697552795279ad52795179adab52795279ad52795179ad6d7551
```

The first 25 bytes require exactly three entry items, check both key lengths
as 33, check their byte inequality, and check beta's length above 57.
The guard restores the original stack `beta P Q`. Each ten-byte pair block
is `2 PICK 2 PICK CHECKSIGVERIFY 2 PICK 1 PICK CHECKSIGVERIFY`.
Its two calls consume copies of `beta P` and `beta Q`, respectively, and
restore `beta P Q`. The second pair block does the same. Final
`2DROP DROP 1` leaves exactly one true item.

Zero-based CHECKSIGVERIFY offsets are 29, 34, 40 and 45. The only
CODESEPARATOR is at offset 35; its following suffix begins at 36.
The processed context lengths are therefore 48 and 13 bytes. No instruction
boundary has a direct-push opcode in the interval 58 through 73. Hence no
accepted beta push can occur in either suffix: FindAndDelete is inert for
every accepted beta, not just the sampled signature rows. More directly,
its serialized push has at least 59 bytes, exceeding the entire 49-byte
script. The first suffix contains the entire second suffix and an
additional 35 bytes.

The independent symbolic trace confirms 32 executed non-push opcodes,
four signature checks, three data items and zero hint items at redeem
entry, and a combined main-plus-alt-stack peak of six. The altstack is
empty. Depth, size and comparison operands here are small positive
ScriptNums; no witness-supplied integer or sign encoding is interpreted.
The host model is specific to this layout, not a general Script interpreter.

## Pair uniqueness and the exact hash exception

For an accepted ECDSA signature, r and s lie in `[1,n-1]`. Put
`Delta=p-n`. An additional coordinate `r+n<p` requires `r<Delta`.
Such an r takes at most 17 positive DER integer bytes; s takes at most
33, including a high-S sign-padding byte. Its entire signature including
the flag therefore has length at most `7+17+33=57`. The guard excludes
that case, leaving only the two nonce points `R,-R` at x=r.

Successful checks of 33-byte keys establish valid compressed points. In
that format distinct bytes represent distinct points. In either context
the two reconstructed nonce points cannot be equal, because their
difference is `(r/s)*(P-Q)`. They are therefore opposite, and

```
2*z_j*G + r*(P+Q) = infinity.
```

Subtracting the two context equations forces `z0=z1 mod n` without any
nonce-logarithm assumption. Normalizing high-S only negates both nonce
points and leaves this conclusion unchanged. The new ten-case Core record
does not itself include a high-S positive; the length argument includes it.

For the same actual input and beta, both contexts have the same flag and
the same input/output counts. The constant branch is shared exactly for
flags `03,23,43,63,83,a3,c3,e3` when `input_index>=output_count`.
Otherwise the two different processed script lengths appear in their
ordinary preimages, including NONE, ANYONECANPAY and undefined flag modes.
The same preimage cannot result. No assumption of independent native hash
contexts is needed for this byte-level conclusion.

For raw 256-bit integers H0,H1, equality modulo n means
`H0=H1` or `H0-H1=+/-n`, since `2n>2^256`. In the latter case the smaller
integer is below `E=2^256-n`. Thus “bitwise hash collision” alone would be
too narrow. This audit establishes the exact conditional implication,
not a numerical lower bound for arbitrary correlated hash searches.

## Saved Core cases and independently checked serialization

All four saved positives and six negatives match their declared Core
outcomes. Positives include a changed recipient with identical guard data,
ANYONECANPAY, and an undefined upper-bit SINGLE flag. Negatives cover ALL,
NONE, in-range SINGLE, duplicate keys, a short valid signature and an
uncompressed key. The two recipient variants spend the same funded outpoint.

The independent parser recomputed all ten txids, wtxids, stripped/total
sizes, weights, scriptSig pushes, witness vectors and actual native
preimages/digests. It also checked the funding P2SH commitment. Each positive
has a 23-byte locking script, 190-byte scriptSig (four pushes including the
redeem script), 313 stripped bytes, 319 total bytes and 1,258 WU.
The helper P2WSH input has one `OP_TRUE` witness item, serialized in three
bytes; the locked input has zero witness items, serialized as one empty-vector
count byte. Together these are four witness bytes plus two marker/flag bytes.
There are zero hints across both inputs. P2SH's outer peak is five and adds
two non-push operations; the redeem peak of six includes all three data items.
These are raw boundary measurements, not repository compiler metrics.

Default policy rejects the positives for CODESEPARATOR or, in the undefined
flag case, the earlier hashtype check. The output-change positive confirms
that the new native guard does not establish a covenant.

## Pinned primary semantics

All references below use Bitcoin Core commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227` (30.3), matching the saved binary
provenance. Local source files were not located; the immutable upstream
source was inspected directly.

- [Strict DER sizes and encodings, interpreter.cpp lines 101-160](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L101-L160).
- [FindAndDelete and pre-tapscript CHECKSIG, lines 213-321](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L213-L321).
- [CODESEPARATOR suffix selection, lines 972-1002](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L972-L1002).
- [Legacy serialization, lines 1154-1239](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L1154-L1239).
- [SINGLE constant and signature hashing, lines 1475-1578](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L1475-L1578).
- [Hashtype policy, lines 177-201](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L177-L201), and [legacy CODESEPARATOR policy, lines 440-442](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L440-L442).
- [CPubKey::Verify in pubkey.cpp](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/pubkey.cpp) performs full point parsing and high-S normalization before verification.
