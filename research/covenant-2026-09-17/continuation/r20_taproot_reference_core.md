# R20: funded Core validation of the auxiliary-input binding gap

Date: 2026-09-17. Question: does the host distinction between committed input
programs and shared witness data survive actual Bitcoin execution?

**Yes. Two different valid auxiliary ECDSA rows spend the same funded inputs
with exactly the same Taproot DEFAULT signature. Both pass consensus and
the pinned node's relay policy.** A separate retained-key signer can also
replace or omit the auxiliary program by generating a fresh signature.
This verifies the bounded counterexample in [the host report](r20_taproot_reference.md),
not a covenant construction or a general impossibility result.

Evidence: `differentially-validated`. Deployment of the two row variants:
`policy-validated`. The OP_TRUE replacement is `consensus-validated` and
nonstandard; negative controls are `consensus-incompatible` complete spends.
The scripts are raw consensus-boundary vectors, not generated library
primitives or compiler-policy metric updates.

## Exact execution boundary

[Harness](r20_taproot_reference_core.py) and [complete results](r20_taproot_reference_core.json).
Bitcoin Core 30.3 at `49faec4f87f5cd19c88db01a82e5c68b087c8227` was extracted
from the repository's checksum-pinned archive. The JSON records the archive
and binary SHA256 hashes and Core version. A fresh private regtest datadir
used `disablewallet`, `networkactive=0`, `connect=0`, `listen=0`, and
`acceptnonstdtxn=0`. No existing node, wallet, peer or actual funds were used.

The chain matured an OP_TRUE witness-script coinbase and funded these
outputs: 900,000 sats to the NUMS-internal-key Taproot leaf, 50,000 to the
P2SH checker, 50,000 to a separate OP_TRUE replacement, and change. The
funding fee was 10,000 sats. The two primary spends pay 940,000 sats and
thus also have a 10,000-sat fee. Both spend exactly funding outputs 0 and 1.

Core's decoder independently agrees with every host txid, wtxid and weight.
All policy checks ran before any conflicting transaction was mined. Each
positive consensus check connected the actual transaction in a block;
that validation block was invalidated before the next comparison. The
funding transaction stayed connected. Consequently the two positive rows
are alternatives for exactly the same funded outpoints, not separately
funded examples.

| Complete spend | Consensus | Policy | Bytes | Weight |
|---|---|---|---:|---:|
| Matching main/auxiliary alpha | accepts | accepts | 406 | 1,147 |
| Different auxiliary alpha; identical main DEFAULT signature | accepts | accepts | 406 | 1,147 |
| Different main claim | rejects | rejects | 406 | 1,147 |
| Different auxiliary alpha with old auxiliary keys | rejects | rejects | 406 | 1,147 |
| OP_TRUE replacement, original DEFAULT signature | rejects | nonstandard input | 282 | 651 |
| OP_TRUE replacement, fresh signature from public leaf key | accepts | nonstandard input | 282 | 651 |
| Auxiliary omitted, original DEFAULT signature | rejects | rejects | 240 | 486 |
| Auxiliary omitted, fresh signature from public leaf key | accepts | accepts | 240 | 486 |

Omission requires reducing the output from 940,000 to 890,000 sats because
only the 900,000-sat main input remains. This is explicitly an altered-output
case, still with a 10,000-sat fee. The OP_TRUE replacement keeps the original
940,000-sat output. Policy rejects both OP_TRUE variants for their nonstandard
input before distinguishing their Schnorr results; consensus independently
rejects the stale signature and accepts the fresh one. The other negative
controls fail the intended comparison or signature checks.

## Measured resources and hints

Boundary: `complete-transaction:` input pushes, output, scripts and complete
witness serialization included. The successful P2SH/Taproot variants have:

- Main locking program 34 bytes; leaf 45 bytes; control block 33 bytes.
  Two data operands and **zero hints** at leaf entry, four complete witness
  items, 156 serialized witness bytes. Two executed non-push opcodes,
  combined main-plus-alt-stack peak 3 by inspection. Validation budget
  206 available, 50 consumed by one nonempty Schnorr signature.
- Auxiliary locking program 23 bytes; redeemScript 11 bytes; scriptSig
  124 bytes containing five pushes. Four data operands and **zero hints**
  at redeem entry. Redeem-only peak 5 and nine executed non-push opcodes;
  including the P2SH wrapper, input-wide peak 6 and eleven non-push opcodes.
  Its empty witness has zero items and a one-byte vector serialization.
- Six data operands and **zero total hints** across the two separate input
  executions. Each input's data coexist at its own script-entry boundary;
  stacks do not carry over between inputs. Their peaks must not be added.
  Both are below the 1,000-item limit. Complete witness serialization is
  157 bytes plus the two transaction marker/flag bytes. The base transaction
  is 247 bytes, so weight is `4*247+157+2=1147`.

Core supplies complete execution verdicts and transaction weights, not a
stack-peak trace. The peak/opcode/resource breakdown is from the explicit
bytecode and the host replay, with that boundary stated separately. An
initial metadata-only peak of 5 was corrected to 6 for the entire P2SH input;
the redeem fragment remains peak 5. No transaction or Core verdict changed.

## What the result requires from a new candidate

The first two rows already grant actual execution of the intended helper.
They show that its accepted data can differ from the main leaf's data,
because DEFAULT does not hash another input's unlocking fields. The
replacement/omission rows separately show why a retained signing key can
authorize a different committed input set. The internal key is NUMS;
neither result invokes an alternative key path.

A candidate may still succeed if every valid auxiliary witness proves the
same canonical function of the actual transaction, or another enforced
relation binds its accepted values. Such a proof has not been supplied.
Likewise, restricting authorization for the main DEFAULT signature is a
separate construction problem. Native commitment to fields alone does not
restrict a signer that can authorize fresh messages.

Reproduce with:

```sh
python3 research/covenant-2026-09-17/continuation/r20_taproot_reference_core.py
```

Local RPC socket binding needs permission outside the restricted network
sandbox; the run itself remains isolated regtest. All eight expectations
passed. No field-library tests or repository primitive metrics were changed.
