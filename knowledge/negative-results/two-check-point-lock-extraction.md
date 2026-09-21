# Two-check ECDSA does not establish unconditional point extraction

Date: 2026-09-17. Evidence: `locally-reproduced` for the synthetic arithmetic
counterexample and local implementation tests; deployment: `unclassified`.
This result identifies an extraction boundary, not a discovered native
transaction bypass or a universal impossibility theorem.

The [76-byte candidate](../../src/signatures/pointlocks/two_check/README.md)
uses one signature under `T` and `Q=-(2*C/r0)G-T`, where `C=2^248` and
`r0=x(G/2)`. Its `length>57` check excludes every second x-coordinate `r+n`.
Distinct keys then reconstruct opposite nonce points, proving

```text
r = r0*z/C mod n.
```

On the constant-digest branch `z=C`, the public G/2 extractor works. The
equations do not force `z=C` or a known nonce for arbitrary supplied digests.

Choose `t=7`, `k=3`, `r=x(kG) mod n`,
`z=C*r/r0 mod n`, and `s=(z+r*t)/k mod n`. The complete low-S signature is
72 bytes, passes the size guard and both ECDSA equations for that supplied
digest, and has `z!=C` and `r!=r0`. Neither G/2 extraction candidate matches
`T`. Full scalar values and a deterministic reproduction are in the
[independent algebra review](../../research/pointlocks-2026-09-17/algebra.md).
The digest is manufactured: no serialized Bitcoin transaction hashing to it
has been supplied. The deliberately public fixture scalars also do not prove
that no other extraction algorithm could exist.

The API represents the distinction explicitly. `extract` checks both ECDSA
equations before returning `NonConstantDigest` for this valid algebraic case.
That error is not reported as a signature failure.

If an adversary knows `t`, an ordinary native spend would provide it with
`k=(z+r*t)/s` and hence a native-hash/known-nonce coordinate match. Independent
lists suggest a work scale near `2^128`; this is neither a general adaptive
lower bound nor a reduction from ECDLP. For a point selected without knowledge
of its scalar, a valid signature reveals the nonce point but need not reveal
its scalar. The known-nonce assumption therefore does not cover the full
arbitrary-target interface. A stronger actual-native-transcript resistance
assumption or a new proof is necessary.

The retained 79-byte three-check design uses a second target-key `scriptCode`
view. Different digest scalars directly reveal `t` through opposite nonces;
equal ordinary digest scalars are its stated collision exception. Dropping
that check changes the assumption, even though it improves size, stack use,
and the P2SH CODESEPARATOR policy boundary. The covenant R9/R18 three-root
results do not repair this two-root extraction gap.

Metrics for the new complete predicate are 76 locking bytes, one signature
data item, zero hint items, a three-item combined stack peak, and six executed
non-push opcodes. The representative 60-byte signature yields 61-byte bare or
139-byte P2SH scriptSig serialization; the latter has two pushes including
the redeem script. The legacy input has no witness. The synthetic example's
72-byte signature is not a complete transaction measurement. See
[OP-017](../open-problems.md#op-017--point-lock-security-and-deployment-validation).


The [HASH160-committed extension](../../src/signatures/pointlocks/committed_two_check/README.md)
adds a constraint absent from the supplied-digest example: the signature's
hash remains in its own ordinary scriptCode. This negative result does not
supply a native-transaction attack satisfying that additional commitment.
The full committed construction's hardness argument remains open under OP-017.

## Two full-pool CHECKMULTISIG calls do not preserve pair binding

Replacing selected-pair checks by independent `t-of-n` multisigs over all
`T_i` keys and all `Q_i` keys permits different matching indices. A concrete
counterexample already exists for n=2, t=1 on the SINGLE constant C.
Let `K=-(2C/r0)G`. Choose a nonce scalar k, `r=x(kG) != r0`, and a valid
signature `(r,s)` with length greater than 57. Its recovered keys are
`A=(sk-C)/r*G` and `B=(-sk-C)/r*G`. Set:

```text
T0=A     Q0=K-A
T1=K-B   Q1=B
```

Both intended pairs satisfy `T_i+Q_i=K`. The signature nevertheless passes the
T-list through T0 and the Q-list through Q1. A HASH160 commitment to that exact
signature does not prevent this constant-digest mismatch. The known-G/2
extractor fails; the spender's nonce need not be disclosed.

[Deterministic vector generator](../../examples/pointlock_multisig_cross_pair.rs)
checks the ECDSA equations and extractor failure with public test scalars.
It emits an exact script and unlocking stack for independent Core validation.
The pinned local interpreter cannot execute CHECKMULTISIG, so no local Script
success is inferred from that interpreter. See the
[Core harness](../../research/pointlocks-2026-09-17/multisig_core_check.py)
for complete funded transaction validation. The
[Core report](../../research/pointlocks-2026-09-17/multisig_core_check.json) confirms
that the 177-byte counterexample is accepted under both consensus and default
relay policy on the pinned Core 30.3 revision. This is an accepted transaction
for an unsound replacement predicate, not a failure of the original paired checks.

Using exact selected-key lists (t-of-t twice, or paired duplicate signatures
in one 2t-of-2t multisig) preserves positional correspondence. This fixes the
pairing problem but adds dummy/count/stack-arrangement overhead; it does not
reduce the 2t ECDSA verifications or the candidate-table commitments.
