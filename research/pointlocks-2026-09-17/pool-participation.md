# Pool authorization does not enforce a complete publication

Question: does the existing 98,323-vB round-major candidate force all 95
funded pools to participate when its creator retains the signing secrets?
The comparison keeps every pool script, point and commitment unchanged and
varies only the spending transaction and its correctly regenerated witnesses.

**No.** Bitcoin Core accepts an individual first, middle or last pool without
the helper, and also accepts the helper with only the middle pool. Each such
spend opens five selected points while 94 pool outputs remain unspent.
This makes the previously documented participation gap concrete for the
current full instance. It is not a counterexample to individual scalar
extraction and does not demonstrate theft in a complete BitVM3 protocol.

Artifacts: [generator](../../examples/pointlock_pool_participation_probe.rs),
[native harness](pool_participation_core_check.py),
[full transactions and results](pool-participation-core-check.json).
The source instance is the existing
[round-major publication](round-major-publication.md), whose manifest hash
is checked against its earlier native report before running the experiment.

## Same funded instance, different input sets

The generator imports the original policy-compiled script bytes. It does not
replace scripts, regenerate labels or change the funded output set. A fresh
test grant funds the same first P2TR helper and all 95 P2WSH pool outputs.
Only this grant's outpoint and its funding signature change. The grant is the
documented external starting coin, not a free protocol transaction.

The deterministic creator retains the public test scalars recorded in the
original fixture, as the goal's model permits. For each chosen input set it
recomputes the actual BIP143 anchor digest, the dynamic verification keys,
six short signatures per label and the mandatory ALL authorization. The
helper, when included, receives a fresh default Schnorr signature. All inputs
refer to the same confirmed funding transaction.

| Spend | Pool inputs | Helper | Spend vB | Default policy and mined consensus |
| --- | ---: | --- | ---: | --- |
| Full control | 95 | Yes | 94,127 | Accept |
| First pool alone | 1 | No | 1,043 | Accept |
| Middle pool alone | 1 | No | 1,044 | Accept |
| Last pool alone | 1 | No | 1,044 | Accept |
| Helper and middle pool | 1 | Yes | 1,101 | Accept |

The funding transaction costs 4,196 vB. The full control therefore reproduces
98,323 total vB, including all creation and consumption. The smaller rows do
not publish a complete 256-byte message and are not competing cost results.
After mining each partial spend, `gettxout` confirms exactly 94 unspent pool
outputs and the expected helper state. Each accepted block is invalidated
before checking another conflicting spend; policy checks happen beforehand.

Three malformed controls fail both policy and consensus:

- Reuse the full transaction's entire first-pool witness in the partial spend.
- Use a fresh partial opening with the stale full-spend authorization.
- Use the stale full-spend opening with fresh partial-spend authorization.

Thus transaction commitments work: retaining an old signature while changing
its committed transaction does not pass. They do not force an authorizer
who retains its secret to sign only the original complete input set.

## Extraction and resource boundary

An independent Python decoder reads each accepted partial transaction's
actual witness and recomputes its digests. For each partial it verifies 36
ECDSA equations (one authorization, five anchors, thirty short checks),
recovers the five selected scalars using the fixture's known nonce and checks
their advertised points. Only afterward are the answers compared with the
retained fixture scalars. This verifies the intended partial openings; it is
not an all-nonce extraction proof. No complete-message decoder runs on them.

Every exercised pool retains a 1,503-byte script and 201 static non-push
opcodes. There are exactly five index hints, 46 entry data items and 47
complete witness items per pool, serialized as 3,794 or 3,795 bytes. All five
hints coexist at entry. The independent combined main/alt-stack height trace
peaks at 100, including temporary pushes; it is not Core instrumentation.
There are 475 hints, 4,370 entry items and 4,465 complete pool-witness items in
the full control, distributed over 95 independent stacks. The P2TR helper
adds one signature witness item when present; it supplies no hints.

Core 30.3, commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`, runs on disposable
regtest with networking and wallets disabled. Evidence:
**differentially-validated**; deployment of the positive transaction cases:
**policy-validated**. Complete-protocol deployment remains **unclassified**.
No tapscript research executor or disabled stack checks are used. This
experiment adds no setup benchmark and leaves all previous timing boundaries
unchanged. The report records source, generator-binary and Core identities.

## Requirement for a repair

A standalone claim that any accepted pool spend is a complete publication
fails this experiment. A complete protocol can instead distinguish a partial
spend from successful publication, but must demonstrate that distinction in
its actual transaction and challenge/refund graph. Merely rejecting partial
data in an offchain decoder does not enforce a payout condition.

A repair must show that every successful application path makes all needed
labels available, or that partial spending can only cause an explicitly safe
abort. Count every additional output and transaction, and test it against
retained creator secrets and newly signed partial spends. The current ALL
authorization and optional helper alone do not meet that criterion. No
general impossibility result for such a repair is claimed.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/pool_participation_core_check.py
```
