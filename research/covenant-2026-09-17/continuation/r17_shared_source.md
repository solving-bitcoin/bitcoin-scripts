# R17: an actual shared hash answer is available without a second preimage search

Question: is R16's excluded shared-answer case `alpha=z_ALL` compatible
with actual Bitcoin hash inputs, or does it already require another hard
hash match? Comparison objective: isolate the cost of obtaining the shared
answer from the remaining signature geometry and output binding.

The shared answer is available directly. Let M be the actual serialized
legacy ALL preimage, including the concrete funding outpoint and scriptCode.
Set `u=SHA256(M)`. Then a Script `OP_SHA256` on witness item u produces

```
alpha = SHA256(u) = HASH256(M) = actual ALL digest bytes.
```

The spender can compute u after funding without changing the locking script
or funding txid. There is no additional source preimage search. Alternatively,
`OP_HASH256` on M gives the same equality if M fits the 520-byte item limit.
This is an honest witness-generation equality, **not a native check that u
or M has that provenance**. It does not give an accepted ECDSA witness or an
intended-output advantage by itself. In particular, one must not multiply
two independent hash-hit probabilities for this deliberately shared answer.

Evidence: `locally-reproduced`; deployment: `unclassified`.
[Python](r17_shared_source.py) and [JSON](r17_shared_source.json) reproduce
eight exact serialized transaction-preimage/hash identities and eight
source-mutation checks. No projected scalars or manufactured hash outputs
are used. None of these eight hashes is a valid positive 32-byte DER
signature. No six-CHECKSIG replay or Bitcoin Core execution is claimed.

## Concrete source routing and chronology

Using [R16's five-item three-key layout](r16_native_translation.md), enter
the candidate script with `beta K1 K2 K3 u` and prepend

```
OP_SHA256 4 OP_ROLL 4 OP_ROLL 4 OP_ROLL 4 OP_ROLL
```

The prefix leaves `alpha beta K1 K2 K3`, exactly the operand order required
by the existing six-check body. Replacing SHA256 with HASH256 selects the
full-preimage route. The prefix is 9 bytes and five non-push opcodes; its
measured stack peak is six. The complete candidate is 88 bytes and 55
static non-push opcodes, with five entry data items and zero incremental
hint items. All five coexist at entry. Including the R16 body, its structural
combined main-plus-alt-stack peak is eight; the alt stack is unused. This
is a raw boundary layout, not a policy-compiled library metric or evidence
that the candidate's signature checks can be satisfied.

Each mode fixes its script first and forms one synthetic funding transaction
with two outputs: an OP_TRUE helper and the P2SH candidate. All four child
variants for that mode consume the same two funding outpoints; the candidate
is input index 1 and the child has one output, so the intended source flag
03 would have the constant SINGLE-bug context C. The target flag is ALL.
The variants change the recipient, amount or locktime separately. Their
actual ALL preimages include the candidate script and produce four distinct
hashes. The funding is not regenerated for those variants.
These are intended witness flag choices; the body alone does not force
alpha's flag to 03 or beta's flag to 01. An eventual construction must also
handle every other flag that its predicate accepts.

The resulting raw hash is not pushed into scriptCode, so the proposed
32-byte source signature has no signature-specific FindAndDelete occurrence.
The actual eight vectors are only hash/routing witnesses: beta and the
three valid keys are not supplied. There is consequently no complete
scriptSig or spending-transaction weight measurement. These legacy shapes
have no witness serialization. The synthetic funding is not a mined UTXO.

## What this establishes and what remains

For the SHA256 source, the source operand is only 32 bytes. Its construction
works even when M itself exceeds a stack element. For the HASH256 source,
the supplied vectors explicitly check that the complete M is at most 520
bytes. Both routes preserve the concrete funding outpoint and need only
ordinary public hash evaluations after choosing the child transaction.

The useful remaining mathematical question is therefore the diagonal one:
which raw DER hashes alpha, considered simultaneously as scalar
`z=int(alpha)`, admit the three common keys at C and z? R16's exact
five-center relation still applies for each fixed alpha; its *independent*
two-answer probability multiplication does not apply to this shared answer.
The [diagonal calculation](r17_correlated_diagonal.md) addresses that relation
without granting control over the output of HASH256.

Even a favorable diagonal family would still need a mandatory relation to
the allowed outputs. This bare candidate permits choosing the hash-source
operand freely, and the same shared-answer construction is available for
different recipients and amounts. The eight identities show that availability;
they are not two accepted spends or a proof of equal search complexity.
Committing an output-specific source/reference requires a new enforcement
and funding-dependency analysis, with every setup and audit cost counted.

Reproduce with `python3 research/covenant-2026-09-17/continuation/r17_shared_source.py`.
