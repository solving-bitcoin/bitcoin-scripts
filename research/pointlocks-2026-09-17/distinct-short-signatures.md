# Byte-distinct short signatures need not add extraction equations

Question: can several pairwise-distinct exact-60-byte signatures under one
committed key replace the separate scriptCode contexts in a compact point
lock? Byte inequality alone does not establish that amplification. The native
counterexample below concerns **legacy SIGHASH_SINGLE's constant digest**.
It does not break the anchored P2WSH candidate or the exact two-key sum lock.

## Algebraic construction

Write n for the secp256k1 group order, p for its field prime, and C=2^248
for the scalar represented by the legacy constant digest `01 00 ... 00`.
Hash the domain `bitcoin-lab/distinct-exact60/single-constant/v1`, take its
first20 bytes as an unsigned big-endian integer, add2^160, and increment
until x lifts to a curve point R. Choose the smaller of the two field y values.
This deterministic fixture lifts at counter0. Its scalar is never generated.
Set

    r = x(R),  s = floor(n/2),  Q = r^-1 (sR - CG).

Commit to Q in the script before funding. Then `(r,s)` verifies at C under Q
with nonce point R; `(r,n-s)` verifies with nonce point -R. In this fixture r
has a21-byte positive DER encoding. Both s and n-s have32-byte encodings:
both are below2^255 despite being on opposite sides of n/2. Consequently both
signatures have exactly7+21+32=60 bytes including their sighash byte. Exact60
does **not** enforce low-S.

Each of these eight raw sighash bytes enters the out-of-range SINGLE branch:

    03 23 43 63 83 a3 c3 e3

For an input index at least the output count, all return the same constant C,
before hashing the otherwise different raw flag. The two s values and eight
flags therefore give16 distinct signature byte strings, with one r, one
digest, and the same committed key Q. All are derived from public data.

This is not merely a failure of our current extraction implementation. If
q=log_G(Q) could be extracted, the nonce-point scalar would follow as

    log_G(R) = (r*q+C)/s mod n.

Conversely, knowing log_G(R) gives q. Thus extraction here is equivalent to
solving the discrete logarithm of the transparently lifted R. The other15
encodings add no secret information. This is a reduction for this fixture,
not a proof that every possible discrete-log algorithm is expensive.

For fixed Q,C,r with r>p-n, there are at most two verifying s values: the
nonce points have x=r, so they are opposite points. Including the eight
constant-digest flags gives at most16 such encodings for this fixed r.
An exact60 signature necessarily has r>p-n: its DER integer lengths sum
to53, s needs at most33 bytes, and a20-byte positive DER integer is at least
2^151, above p-n. Requiring17 distinct encodings would therefore force at
least two r values on this branch, **not** prove scalar extraction from them.

## Native predicate and controls

[Generator](../../examples/pointlock_distinct_signature_probe.rs),
[runner](distinct_signature_core_check.py),
[complete report and transaction hex](distinct-signature-core-check.json).

The policy-compiled multiple-signature predicate first compares **every pair** of supplied
signature byte strings, rejects equality, then checks exact60 and ECDSA
validity under Q for each. It contains no CODESEPARATOR. Q is fixed in the
redeem script; neither Q nor the native digests are supplied as trusted hints.
All positive checks use actual funded native transaction digests.
The single-signature control compiles the repository's unchanged
`g_half_point_lock` implementation: its40-byte max60 predicate also accepts
the fixture. Neither predicate requires the nonce to be G/2.

Seven positive spends pass Bitcoin Core30.3 block validation and are mined:

| Case | Distinct signatures | Policy accepted | Redeem bytes | scriptSig bytes | Spend vB | Peak main+alt | Executed non-push ops |
|---|---:|---|---:|---:|---:|---:|---:|
| Existing max60 predicate, low-S |1|yes|40|102|239|3|4|
| Existing max60 predicate, high-S |1|no|40|102|239|3|4|
| Low-S, flags03 and83 |2|yes|58|181|318|4|18|
| Both s signs, flag03 |2|no|58|181|318|4|18|
| Both signs, three flags |6|no|180|548|687|8|112|
| Low-S, all eight flags |8|no|283|774|913|10|189|
| High-S, all eight flags |8|no|283|774|913|10|189|

The last two are competing spends of the **same funded output**, together
covering all16 encodings. No single16-signature all-pairs predicate is claimed.
High-S and undefined flags cause the listed policy rejections. The two ordinary
low-S flags already provide a policy-accepted example of byte distinctness
without an extra equation. Every positive transcript returns `None` from the
existing known-G/2/repeated-nonce extractor, consistent with the reduction.

Five controls fail both policy and block validation: a nonadjacent duplicate,
a changed s scalar, a59-byte signature, replacing SINGLE with ALL, and adding
an output so that SINGLE no longer takes the constant branch. The all-pairs
test therefore executes; the predicate does not merely ignore its operands.

There are **zero hint items** in every invocation and across the whole
diagnostic. Complete redeem-entry data counts are1,2,6,8 signature items;
scriptSig push counts including the redeem script are2,3,7,9. Every operand
coexists at entry. The table's peaks include main and alt stacks and temporary
pushes; they come from an independent trace of the final compiled bytecode,
not instrumented Core. The maximum10 is well below the1,000-item bound. No
stack-unlimited or tapscript execution helper supplies the native verdicts.

These are P2SH operands in scriptSig, not discounted witness data. Each complete
spend also has a test-only OP_TRUE P2WSH helper input. The serialized witness
vectors total4 bytes:3 for that helper and1 for the legacy input's empty
witness vector, plus the transaction's separate2-byte marker/flag. The test
funding transaction is267 vB and creates the helper, four diagnostic P2SH
outputs, and change. This is a counterexample fixture, **not** a256-byte
publication profile, and its helper is not production authorization.

Evidence: **differentially-validated** for the public curve equations,
independent bytecode trace, transaction serialization, and Core execution.
Positive case set: **consensus-validated**; the two policy-accepted cases have a
**policy-validated** `testmempoolaccept` result. The failure controls are
**consensus-incompatible**. These labels describe those specific transactions,
not point-lock soundness or BitVM3 deployment.

Core commit:49faec4f87f5cd19c88db01a82e5c68b087c8227. Centralized compiler
commit:124b561ed75ac3ec4c6ad99207d8dcdd3bc67180. Source hashes, final scripts,
funding and spending hex, node options and exact rejection reasons are in the
report. Every Core run uses a fresh temporary regtest datadir with wallets
and external networking disabled. Reproduce only this focused experiment:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/distinct_signature_core_check.py
```

`--algebra-only` runs the16-encoding construction and twelve predicate controls
without Core and makes no new native-validation claim. Setup timing and
garbled-verifier integration are not measured by this diagnostic.

## Consequence for the search

Counting different signature bytes cannot replace analysis of the actual
nonce points and reduced digests. BIP143 does not have the legacy constant
branch, so this counterexample cannot be transplanted into the anchored
P2WSH construction by assigning C to a synthetic digest. Conversely, proving
distinct native digests is still not enough when signatures use independently
unknown nonces. A replacement must establish extraction across all accepted
encodings, rather than treating byte inequality as independence.
