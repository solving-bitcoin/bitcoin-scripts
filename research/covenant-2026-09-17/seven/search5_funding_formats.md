# Search 5: cross-format equality and funding chronology

Question: can identical native hash preimages, or a funding transaction used as
a hash reference, enforce exact prescribed outputs with retained creator state
and honest total work below `2^64`? The objective includes setup and verification.

**Result:** the explicit legacy/BIP143 equal-preimage candidate has an earlier,
output-independent 256-bit self-dependent hash condition. In an ideal HASH256
model it cannot supply the requested inexpensive honest construction. This is
a narrow result about exact byte overlap, not an impossibility theorem for
native digest relations or existing-opcode covenants. Funding chronology and
an auxiliary input do not supply the missing authenticated context here.

## Solving the first cross-format constraints

Use the same actual spending transaction T, with m nonempty inputs, and any
legacy context i and witness-v0 context j. Let u_k be the 36 serialized bytes
of its kth outpoint. Different full signature flag bytes cannot produce equal
ordinary preimages: the last four bytes encode that flag. Thus equality forces
the same full flag h, including ANYONECANPAY. Exclude legacy's out-of-range
SINGLE constant, for which there is no ordinary serialized preimage.

The candidate from search 2 is

```
M_legacy(T,i,Ca,h) = M_143(T,j,Cb,amount_j,h).
```

Both start with the same four-byte transaction version. Immediately after it:

```
legacy: CompactSize(k) || first_selected_outpoint || ...
BIP143: hashPrevouts || ...
```

If h has ANYONECANPAY, k=1 but hashPrevouts is 32 zero bytes. The first byte
is therefore `01` versus `00`: equality is impossible.

Otherwise k=m and the first selected outpoint is u_0, regardless of which
input's script is running. Set

```
X = u_0 || ... || u_(m-1)
c = CompactSize(m)
d = len(c).
```

Every solution must satisfy the exact 32-byte equation

```
H256(X) = c || X[0 : 32-d].                 (1)
```

This appears before either scriptCode or any output. It holds for ALL, NONE,
ordinary SINGLE and undefined base flag values alike. For m<253 the last 31
bytes of the target are a prefix of the first actual funding txid; at m=253
the prefix is 29 bytes and the three count bytes remain prescribed. These
are always **32 prescribed bytes in total**, not merely 31 or 29 bytes.

Equation (1) explains why choosing a funding txid from an already computed
hash is not a direct solution: changing that txid changes X itself. A prefix
assignment creates the new input whose hash still has to satisfy (1).

In an ideal model where HASH256 is a random function, each fresh query X fixes
its own unique m=length(X)/36 and hence its entire target before its random
output is returned. Its success probability is exactly `2^-256`. Adaptively
choosing later inputs does not change this per-query probability. A union bound
for Q fresh eligible queries gives `Pr[solution] <= Q/2^256`; at `Q=2^64`
this is `2^-192`. Counting funding hash queries as well only increases Q.
This is a model bound, not a measured runtime or a cryptanalytic claim about
SHA256. The argument deliberately does not address two distinct preimages
whose digests agree, agree modulo the group order, or satisfy another relation.

The new r=s=1 complete-recovery-key gadget from search 3 enforces scalar digest
equality when both contexts and common keys are actually enforced. It does not
remove (1) from a construction that tries to achieve that equality through
identical legacy/BIP143 preimages. No second-format suffix layout or prescribed
output can repair an unsatisfied prefix.

The serialization rules were inspected against [Bitcoin Core 30.3,
interpreter.cpp](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp)
and the [BIP143 specification](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki).
The immutable Core commit is `49faec4f87f5cd19c88db01a82e5c68b087c8227`;
BIP143 was consulted on 2026-09-17. Equation (1) and its model bound are our
derivations, not claims attributed to those sources.

## Can a transaction serialization be the native preimage?

For ordinary legacy semantics the preimage has the form

```
M_legacy = SerializeStripped(transformed_T) || LE32(h).
```

The transformed transaction has canonically serialized input and output
vectors. Its output values need not be consensus-valid, as in SINGLE's null
outputs, but their byte format still has a unique parse. A stripped transaction
parser reaches its locktime and ends **four bytes before** the end of M.
Consequently no complete canonical stripped funding transaction serialization
can equal M. The four flag bytes cannot be silently reinterpreted as the
transaction's locktime: its preceding counts already fixed that boundary.
This is an exact-format rejection, stronger than a work estimate. Comparing
hashes of these different byte strings would instead require another bridge.

BIP143 does not share this canonical transaction prefix, so the same proof
does not apply. A proposed equality `SerializeStripped(F)=M_143(T)` needs a
complete overlapping parse and an authenticated relationship between F and T.
If T spends an output of F, then M_143 contains an actual outpoint referencing
`H256(SerializeStripped(F))`; ANYONECANPAY still retains its current outpoint.
Selecting F after T therefore does not remove its self-dependent funding
equation. No concrete parse plus inexpensive funding solution was found.
This remains a candidate constraint, not a claimed general work lower bound.

## Auxiliary inputs and chronology

Putting two verifier outputs in one funding transaction supplies both coins,
but does not make spending one require spending the other. A count/index
condition can require some additional input while leaving its outpoint and
program attacker-selectable, as the executed second-pass SINGLE-bug cases
already show. Likewise, separately supplied keys in two inputs are not common
keys merely because both scripts ask for keys of the same format. An enforced
common-key commitment or another authenticated link is still necessary.

The direct hardcoding attempt has the concrete dependency

```
common keys K -> funded verifier scripts -> funding txid u
             -> native digests of spend(u,O*) -> recovered common keys K.
```

CODESEPARATOR can omit constants from a scriptCode but not remove their
commitment through u. Segwit funding leaves its witness outside its txid but
keeps funded output scripts and amounts inside it. Consequently changing a
funded P2WSH/Taproot script or its commitment changes u. Moving variable data
only into an uncommitted funding witness removes this txid dependency, but
then the future input has no demonstrated native way to authenticate that
data as its common-key/output reference.

Constructing an auxiliary coin after the protected coin permits a forward
reference from the auxiliary script to the protected outpoint. It does not
give the protected coin the missing reverse requirement to consume that
specific auxiliary coin. Retained keys can authorize a different auxiliary
history unless a covenant or an independently demonstrated public predicate
already prevents it. Coinbase funding adds neither a reverse reference nor
a signature mode omitting the currently spent outpoint. No chronology-based
shortcut was found; all funding preparation belongs in honest total work.

## Reproduction and scope

Run `python3 research/covenant-2026-09-17/seven/search5_funding_formats.py`.
The [fixture](search5_funding_formats.py) checks all 256 full flag bytes at two
input positions for input counts 1, 2, 252, 253 and 1000. It verifies the ACP
contradiction, derives the non-ACP target directly from serialized bytes, and
parses every ordinary legacy preimage to show the four-byte trailer.
The exact counts are in the [report](search5_funding_formats.json).

Evidence is `locally-reproduced` for these host fixtures and `inspected` for
the source/algebra argument. Deployment is `unclassified`. There is no Script
execution, no locally mined hash puzzle, and no complete covenant. No repository
tapscript executor or disabled consensus checks are used. Host fixtures have
0 hint items and 0 witness bytes; locking-script size, combined stack peak,
executed opcodes and complete transaction weight are inapplicable, not zero.
No primitive code/metrics changed and no field-arithmetic tests were run.

Falsifiable next criterion: exhibit either a non-identical-preimage digest
relation that is efficiently satisfied only for the prescribed outputs, or
a BIP143/funding-transaction overlap with an explicit acyclic funded instance,
enforced auxiliary verifier, complete witness, and honest total work below
`2^64`. The creator must retain all setup state in the bad-output analysis.
