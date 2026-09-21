# Witness-discount algebra search

Question: can a noninteractive, purely algebraic point-label setup support an
arbitrary future 256-byte publication below 100,000 combined creation and
spending vbytes by moving scalar revelations into SegWit witnesses?

This note records `inspected` algebra and specification checks. Deployment
class: `unclassified`. It contains no executable construction or measured
transaction, and establishes no general impossibility result.

## The sum-key equation leaves an honest-opening obligation

For fixed `T=P+Q=tG`, an accepted sum-key signature satisfies

```text
r = -2z/t mod n.
```

In the common-G construction, honest signing additionally needs a known scalar
`k` with `x(kG) mod n = r`. Knowing `t` and the eventual native digest `z` does
not provide that scalar. The legacy constant digest permits choosing `k`
first and generating `t`; replacing the wrapper with P2WSH does not preserve
this setup order.

BIP143 includes the current input's outpoint for every sighash flag. Removing
candidate keys from the scriptCode prefix using CODESEPARATOR does not remove
the funding transaction ID. That ID commits to the funded witness program.
Moving funding through another transaction merely moves this dependency to
the transaction that actually creates the point-lock output. Out-of-range
SINGLE uses a zero `hashOutputs` field and still hashes the ordinary preimage;
it does not reproduce the legacy constant.

## Dynamic ECDSA recovery keys do not yet repair setup

Fix a public signature `(r0,s0)` and select one possible nonce point `R0`.
Its recovered verification key for native digest `z` is

```text
P(z) = A - b*z*G
A = (s0/r0) R0
b = 1/r0.
```

This key can be computed using public group operations, without knowing the
discrete logarithm of `R0`. A fixed-signature ECDSA check could therefore
authenticate such a dynamically supplied key.

Composing it with a sum-key check against fixed `Q`, however, requires

```text
A+Q = uG
r1 = -2z / (u-b*z).
```

For a fixed nonzero `u`, this again specifies a nonce x-coordinate with no
known nonce scalar. The special cancellation `u=0` makes `r1=2/b` independent
of `z`, but also makes the supposed locked target `A+Q` infinity. Two dynamic
recovery keys give the same expression with the corresponding sums of `A`
and `b`. This rules out that simple composition, not every construction using
dynamic keys.

The [dual-anchor native follow-up](dual-anchor-sum-collapse.md) now tests a
related attempted repair: anchor both dynamic keys to +/-T, then apply the
exact long-signature sum-key predicate. Its common-digest branch admits a
publicly computable 72-byte high-S opening with no target scalar. Core accepts
it under consensus. The sum-key theorem extracts the already public dynamic
key sum, not log(T); changing which point is called the target is essential.

## Taproot tweak as a candidate point lock

A tempting generated-label construction chooses an externally fixed NUMS
internal point `P`, a hidden script-tree root `m`, and

```text
t = H_TapTweak(x(P) || m)
T = tG
Q = P+T.
```

With the ordinary Taproot range and parity conditions, a script-path spend
reveals the control block and script needed to recompute `m`, hence `t`.
For honestly generated `T` with its scalar known to the holder, knowing the
output key's scalar would imply knowing the NUMS point's scalar.

The public equation `Q=P+T` is nevertheless **insufficient for malicious setup**.
The holder can instead choose an ordinary known-secret output key `Q=qG` and
advertise `T=Q-P`. The equation passes, while a key-path spend reveals no
scalar of `T`. The holder need not possess a valid hidden tree or know `log(T)`.
An externally fixed NUMS `P` does not rule out this alternate setup order.
Certifying the holder's knowledge of `log(T)` or the correct hidden tweak
preimage would require an additional mechanism; this note does not treat a
proof of knowledge as permitted by the ZKP-free requirement.

Even under honest setup, all leaves of one ordinary Taproot tree reveal the
same root `m`, and therefore the same scalar `t`. They do not implement one
independent label per leaf. Sibling hashes in a control block are not
automatically authenticated scalar openings of independently advertised
points. Constructing alternative internal-key/root representations of one
output requires satisfying the hash-dependent tweak relation for each;
ordinary public point addition does not supply those representations.

One output per candidate is also too expensive for the target in the simple
subset model. Ignoring transaction headers and using favorable costs of 43
vbytes per created P2TR output and 58 vbytes per selected spend gives

```text
cost >= 43*N + 58*T
information <= N*H2(T/N).
```

Minimizing the ratio gives approximately 138,773 vbytes for 2,048 bits before
the omitted costs. This is a restricted-family estimate, not a bound on all
Taproot protocols.

## Remaining falsifiable direction

A successful witness construction must give an efficiently generated,
publicly algebraically verifiable setup in which every permitted spending
path extracts one of the intended precommitted point scalars. It must
demonstrate honest openings after the actual funding outpoints are fixed,
exclude an ordinary signing escape path, and provide fully serialized
creation-plus-spending transactions below 100,000 vbytes. No candidate in
this note meets those conditions.

Primary specifications, inspected 2026-09-17:

- [BIP143, witness-v0 digest](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)
- [BIP341, Taproot key and script paths](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP342, tapscript signature semantics](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)

Relevant implementation pin for later differential checks: Bitcoin Core 30.3,
`49faec4f87f5cd19c88db01a82e5c68b087c8227`. No Core test was run for this
algebra-only note. No script metrics or hint counts are claimed.
