# Taproot's native group equation: an ECDSA/Schnorr hybrid

Question (2026-09-17): can control-block validation authenticate the missing
arithmetic reference data or complete a secretless exact-output covenant,
with retained creator state and honest **total** work below `2^64`?

Result: the native group equation is real, but the concrete hybrid below
reduces its unknown-point cancellation to a prescribed Schnorr challenge.
It provides neither an inexpensive honest construction nor a demonstrated
advantage for prescribed outputs. This is a bounded negative result, not an
impossibility theorem.

## What consensus authenticates

Let `P` be the even lift of the control block's internal-key bytes. For leaf
`L`, consensus hashes its version, canonical length, and exact script bytes;
it then folds each sibling using sorted TapBranch hashing to obtain `M`.
It computes `t=H_TapTweak(x(P)||M)`, rejects `t>=n`, and checks
`Q=P+tG` against the funded x-only output key and control parity bit. Script
execution receives neither the control block nor the script as stack data.
These statements follow [BIP341, script-path validation](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#script-validation-rules).

Thus the relation authenticates a *funded leaf*, not a second freely supplied
copy of `P`, `M`, `t`, or the control bytes. An arithmetic proof can receive
copies as ordinary witness items, but this check supplies no equality between
those copies and the consensus-consumed values. Embedding their expected
values in a leaf makes them constants and changes its commitment; it does
not create an introspection operation. The raw script and its arithmetic
encoding also need an actual enforced relation if both are variable.

There is useful mandatory execution here: a correctly generated output with
an unknown-log internal key and only the intended spending leaf forces that
leaf, subject to the usual cryptographic assumptions. It does not make an
unrelated legacy coin require this Taproot input. Moving the protected value
to Taproot fixes that particular optional-verifier problem but loses native
ECDSA/DER gates: current tapscript signature checks use Schnorr. [BIP342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)

Sorted hashing makes swapping two sibling operands the *same* branch; it
does not encode a directional witness bit or a linear relation between hash
scalars. The parity bit is fixed by `Q`; it is not free search entropy.
Unknown leaf versions and OP_SUCCESS paths cannot be admitted as verifier
alternatives. A sound funding audit must examine the complete chosen tree.

## Concrete hybrid: cancel the ECDSA nonce through the Taproot tweak

Grant the candidate more native links than a script currently demonstrates:
the ECDSA recovery key is the control internal key up to its mandated parity,
and the Schnorr key is the actual tweaked output key. Failure even under this
grant identifies a separate algebraic obstruction.

Fix the public unknown-log even nonce point `R=lift_x(1)` and ECDSA signature
`r=s_E=1`. For an actual native legacy digest scalar `z`, choose recovery sign
`sigma` and let

```
A = sigma*R - zG
P = delta*A                         delta in {+1,-1}, P even
t = H_TapTweak(x(P)||M)
Q = P+tG
Qbar = epsilon*Q                    epsilon in {+1,-1}, Qbar even.
```

Try Schnorr nonce `R`, key `Qbar`, and scalar `s_B`. Native verification uses
`e=H_BIP0340/challenge(x(R)||x(Qbar)||m) mod n` and requires

```
s_B G = R + e*Qbar
      = (1+e*epsilon*delta*sigma)R
        + e*epsilon*(t-delta*z)G.
```

The direct public construction cancels the unknown-log point only if

```
e = -epsilon*delta*sigma mod n
s_B = sigma*z - delta*sigma*t mod n.
```

This is the attempted hybrid: the tweak supplies the missing scalar term,
and native ECDSA supplies a point with a known digest coefficient. The exact
equation works. Native Schnorr also hashes the nonce, key, and transaction
message, so the challenge is not selectable by an arithmetic witness.
For fixed parity signs the target is `+1` or `-1`, not a permissive 64-bit
predicate. The 16 deterministic host cases cover all four `(delta,epsilon)`
pairs: every artificial target-challenge equation passes and every actual
challenge rejects. [BIP340 verification](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#verification)

For general fixed `r`, nonce sign, and ECDSA `s_E=1`, the same derivation gives
`e=-r*epsilon*delta*sigma` and
`s_B=sigma*z-r*delta*sigma*t`. Allowing variable `r` makes the target depend
on the nonce x coordinate; it does not remove that coordinate from the
challenge input. No efficient solver or output-specific advantage follows.
If a public algorithm could solve the leftover nonzero coefficient of this
fixed `R` by supplying `s_B`, the resulting scalar equation exposes its
discrete logarithm; coefficient cancellation is the direct escape examined.

In a random-oracle estimate with fixed `r=1`, accepting either target gives
probability at most `3/2^256` per fresh 256-bit challenge hash: reduction modulo
`n` has two preimages for `1` and one for `n-1`. Thus `2^64` fresh queries give
an upper bound `3*2^-192` for this target-search strategy. This is an ideal-model
bound for this restricted strategy, not a universal covenant work bound.
Actual signs determine just one target; using both is conservative. Choosing
metadata with good outputs and with bad outputs supplies the same target
search, before charging funding, hashing, point operations, and audit work.

## Retained-state bypass and funding dependencies

Making `P=dG` with creator-known `d` makes the tweaked key scalar known:
`q=epsilon*(d+t) mod n`. The creator can sign any otherwise valid spend via
the key path, which does not run a leaf. No deletion assumption may hide this
state. The fixture uses the explicitly public scalar 7 and a committed
OP_RETURN leaf; it signs two different synthetic messages under that same
output key. This illustrates the bypass algebra, not a complete transaction
or consensus test. A NUMS `P` or `H+dG` with unknown-log `H` removes this easy
bypass but does not solve the challenge condition above. [BIP341, constructing outputs](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs)

The hybrid also has a funding loop even before the challenge condition:

```
z -> recovered A -> normalized P -> t and Q -> funding scriptPubKey
  -> funding transaction F -> txid(F) -> spend outpoint -> z.
```

If the Schnorr message comes from spending this Taproot output, it commits
to that output's scriptPubKey and outpoint, including under ANYONECANPAY;
without ANYONECANPAY it also commits to the other spent programs. Hence
choosing `P` or the leaf after calculating `z` or the Schnorr message changes
the object that was signed. CODESEPARATOR can change the leaf signature
context but cannot remove the funding outpoint or current scriptPubKey.
Leaves embedding `P`, `Q`, a reference digest, or their limb encodings add
their own commitment edges. They do not break this dependency cycle.

Placing the legacy and Taproot checks in separate inputs also needs a proven
mandatory dependency and common-data binding. Choosing the Taproot output
after the legacy protected output only gives a forward reference. Without a
reverse requirement, replacing or omitting that input remains possible as in
the prior search's explicit replacement algorithm. Funding both together
changes neither condition. Funding transaction witness data may be mutable
without changing txid, but it does not choose the already committed output
key/tree and no new authenticated read of that witness was found.

Trying a prescribed known-log `Q` and defining `P=Q-tG` instead moves the
problem to `t=H_TapTweak(x(P)||M)` and internal parity consistency. It is not
an acyclic tweak construction; even if solved, knowledge of `log_G(Q)` gives
the unrestricted key path. Letting arbitrary witness `P/M` vary at a fixed
unknown-log `Q` must produce another valid opening, not an unconstrained
native group oracle.

## Reproduction, evidence, and next criterion

Run `python3 research/covenant-2026-09-17/continuation/r4_taproot.py`.
Results: [r4_taproot.json](r4_taproot.json). Host point-equation fixtures are
`locally-reproduced`; consensus-source and construction arguments are
`inspected`. Deployment is `unclassified`. No Script interpreter, disabled
consensus check, rare witness mining, wallet, real coin, or field test is
used. Fixture messages are synthetic digest bytes, not actual sighashes.
Script bytes, serialized witness bytes, hint items, combined stack peak,
opcodes, and validation budget are **not measured** because this is a host
algebra experiment with no proposed executable leaf. No resource-compliant
bridge is claimed, and no primitive or metric baseline changed.

BIP340/341/342 master documents were retrieved on 2026-09-17. An immutable
BIP pin was not obtained in this bounded run. Cross-check source is
[Bitcoin Core 30.3 interpreter.cpp](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp),
commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`.
All hybrid equations and work estimates above are our derivations.

Falsifiable next criterion: give a complete existing-opcode leaf whose
arithmetic reference values are authenticated to the *consensus-consumed*
Taproot relation, with an explicit acyclic funding algorithm and an
unknown-log output key, and demonstrate that native signature satisfaction
is cheaper for the specified outputs after counting all setup. A stack copy
of the control block, an artificial Schnorr challenge, or an optional second
input does not meet that criterion.
