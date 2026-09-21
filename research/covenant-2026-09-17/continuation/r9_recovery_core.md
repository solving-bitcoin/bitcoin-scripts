# R9: Core checks of the three-common-key native relation

Date: 2026-09-17. Question: does the variable-signature layout actually retain
one signature, require three distinct canonical keys, and perform both sets
of native checks with the intended stack and scriptCode semantics?

**All eight expectations passed.** Four positive spends pass Bitcoin Core
consensus and default policy; four negative spends fail consensus and policy.
The positives deliberately repeat the same context. No distinct-context hash
collision, reference evaluator, rare-event witness or covenant is claimed.

Evidence: `differentially-validated`; positive deployment: `policy-validated`.
Bitcoin Core 30.3, immutable commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`, using the existing verified archive
and binary pins. The node runs an isolated temporary regtest chain without
wallet or network peers. All transactions, flags and results are retained
in [the JSON](r9_recovery_core.json).

## Native interface exercised

The [generator](r9_four_roots.py) accepts entry items, bottom to top:

```
sigma, Q0, Q1, Q2
```

It requires each key to have 33 bytes, checks all three pairwise inequalities,
and checks copies of the exact same sigma under each original key twice.
Successful ECDSA verification plus that length check supplies canonical
compressed points, so different encodings mean different group keys. The
original four items remain until final cleanup. No signature r or s is
extracted or supplied as an independently trusted hint.

With no CODESEPARATOR the complete raw layout is 75 bytes and executes 47
non-push operations. A CODESEPARATOR between the two groups makes it 76 bytes
and 48 counted operations. The latter creates different actual scriptCode
contexts and is used for the corresponding negative fixture.

The [exact curve proof](r9_recovery_audit.md) establishes that three distinct
common keys for any shared valid ECDSA signature force equality of the two
digest scalars modulo n. It separately excludes every possible four-root
translation exception. The four positive transactions test execution of the
layout; they are not themselves an exhaustive proof over all signatures.

## Positive and negative cases

The funding transaction creates five ordinary P2SH outputs and one output
containing the CODESEPARATOR variant. All scripts are fixed before deriving
their actual spending digests. Public point recovery then provides the
witness keys; no nonce or signing-key discrete logarithm is needed.

Four positives use `(r,s)=(2,1),(4,2),(6,17),(16,129)`. Each r has both
field-coordinate lifts r and r+n. The cases omit a different one of the
four possible nonce roots, covering all four choices of three keys. Their
signatures all use the explicit ALL flag. Signature size is nine bytes in
the first three and ten bytes in the final case.

The ordinary fifth funded output supplies these negatives:

- Two key inputs are identical: pairwise inequality rejects.
- One valid key uses its 65-byte uncompressed encoding: length check rejects.
- Change the signature s without changing the recovered keys: native
  CHECKSIGVERIFY rejects under consensus; default policy reports NULLFAIL.

The sixth output separates the groups with CODESEPARATOR. Its keys verify
the first actual digest, but the second actual digest differs, and consensus
rejects CHECKSIGVERIFY. Policy rejects the legacy CODESEPARATOR separately.
The policy error is therefore not presented as a second test of the digest
relation. Both actual sighashes are recorded in the JSON.

Each positive uses a distinct funded outpoint. The mempool is empty before
every `testmempoolaccept` and direct `generateblock` check; no invalidation,
replacement-fee interaction or restart affects these verdicts.

## Resources and scope

`complete-leaf:` 75 raw script bytes for positives; **four entry data items**
(one signature and three keys); **zero hint items**; combined main-plus-alt-
stack peak **7** by inspection; 47 executed non-push operations. Altstack is
empty throughout. All four input data items coexist at entry. The P2SH
wrapper separately contributes two opcodes and a 23-byte funding script.

`complete-transaction:` one P2SH input, one 990,000-satoshi P2WPKH output and
a 10,000-satoshi fee. The first three positive scriptSigs are **188 bytes**,
with five pushes including the redeem script; their transactions are
**1,080 WU**. The final larger signature gives **189 scriptSig bytes** and
**1,084 WU**. Serialized witness bytes are **0**. Funding weight is excluded.
The rejected CODESEPARATOR case has a 190-byte scriptSig and 1,088 WU.

These are raw consensus-boundary vectors, not policy-compiled repository
primitives. No default tapscript executor or disabled consensus checks were
used. No field-library tests or primitive metrics were changed.

This layout does not enforce the variable signature's flag, nor does it
provide a context containing an independently checked intended output list.
DEFAULT enforcement from the separate Schnorr experiment cannot be imported
into this ECDSA script. The theorem concerns native digest scalars, not an
unrestricted witness claim about what their bytes ought to be.

Reproduce with `python3 research/covenant-2026-09-17/continuation/r9_recovery_core.py`.
