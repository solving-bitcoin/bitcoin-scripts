# Destructive lookup for point-lock subsets

The objective is to minimize the combined serialized funding and assertion
transactions for publishing a recoverable 256-byte value. Redeem-script size
alone is not the objective. This experiment retains the HASH160 signature
commitment, the two related public keys, and the signature-length guard of
[the committed point lock](../../src/signatures/pointlocks/committed_two_check/README.md).
It introduces no ZKP or interactive setup.

## Construction

A shared table holds one row per candidate:

```
HASH160(T_i), HASH160(Q_i), HASH160(sigma_i)
```

Each opening contains the signature, its two public keys, and a lookup hint.
`OP_ROLL` removes the selected three commitments from the table. Consequently,
a subsequent opening cannot select that physical row again. This removes the
previous-index state and ascending-index checks of the earlier subset probe.
The verifier authenticates all three openings, checks signature length `>57`,
and executes both ECDSA checks. The remaining rows are discarded and the
complete redeem script leaves one true item.

The table remains in the redeem script. It is not moved into uncommitted
unlocking data. Before building the script, every candidate must satisfy the
original public relation `T_i + Q_i = -(2C/r0)G`, with the exceptional cases
excluded. Independent candidate secrets remain a protocol assumption: in
particular, simply using one candidate's companion as another candidate would
not give an independent reveal choice.

Two further representation changes reduce the script:

1. Move the incoming openings to the alt stack before pushing the table, then
   retrieve each opening with four `OP_FROMALTSTACK`s. This avoids repeated
   large-depth `OP_ROLL` instructions to fetch the opening itself.
2. Supply the table depth directly instead of a row number requiring a
   multiplication by three. The depth is explicitly range-checked so it can
   address only the committed table, never the remaining unlocking data.

The second change uses hash binding to authenticate row alignment. A signature
has at least 58 bytes, while a committed compressed key has 33. A signature
cannot open a key-hash slot without a cross-format HASH160 collision/second
preimage. This is a cryptographic condition, not an unconditional ScriptNum
alignment proof. The alternative with an explicit integer row index retains
structural alignment and is measured separately. With embedded full keys, a
20-byte computed hash cannot equal a 33-byte key slot even before invoking a
hash assumption.

Removal does not require a particular selection order. The message decoder
uses the selected set; permutations do not contribute additional authenticated
message bits.

## Fixed-cardinality measurements

All sizes are policy-compiled complete redeem scripts. Signature fixtures are
60 bytes including the sighash byte. ScriptSig includes minimal data pushes,
selector pushes, and the final redeem-script push, but excludes its CompactSize
length and the 40 other non-witness input bytes.

| Layout | Selection | Redeem bytes | Maximum scriptSig bytes | Static non-push ops | Sigops | Combined stack peak |
|---|---:|---:|---:|---:|---:|---:|
| Three hashes, explicit row index, alt-staged | 2 of 6 | 487 | 750 | 94 | 4 | 29 |
| Three hashes, direct depth, alt-staged | 2 of 6 | 474 | 738 | 82 | 4 | 29 |
| Three hashes, direct depth, alt-staged | 3 of 6 | 517 | 911 | 119 | 6 | 33 |
| Two full keys plus signature hash, direct depth | 2 of 5 | 517 | 644 | 59 | 4 | 22 |

A hashed-key opening has one mandatory lookup-hint item and three data items:
one signature and two keys. Thus 2-of-6 uses **2 hints and 8 complete input
items**, and 3-of-6 uses **3 hints and 12 input items**. The embedded-key 2-of-5
variant uses **2 hints and 4 input items**. All items coexist at script entry;
the stated peak includes the main and alt stacks. No primitive uses witness
serialization: these are legacy scriptSig inputs. In a mixed SegWit
transaction each legacy input has a serialized empty witness vector of one
byte; that framing belongs in the transaction calculation.

A direct depth above 16 takes two scriptSig bytes rather than one. Accordingly,
the table reports the maximum across subsets. Selecting a different order can
sometimes save the extra byte; it cannot create an extra authenticated choice.

## Variable-cardinality pools

Allowing one, two, or three selections from a five-candidate table fits in a
**467-byte redeem script**. The first opening is mandatory. An optional opening
has depth zero when omitted; its four unlocking items are empty. The script
then discards that frame and an unused three-item table row. This preserves the
physical table length expected by subsequent rounds. The canonical encoder
puts actual openings first and omitted frames last. Other accepted orders are
interpreted by simulating the same destructive table operations and extracting
the set of actually verified candidates.

| Pool | Redeem bytes | scriptSig with 1 / 2 / 3 / 4 selections | Static non-push ops | Static sigops | Combined stack peak |
|---|---:|---:|---:|---:|---:|
| 1–2 of 6 | 482 | 620 / 746 / — / — | 90 | 4 | 29 |
| 1–3 of 5 | 467 | 608 / 734 / 860 / — | 133 | 6 | 30 |
| 1–4 of 5 | 518 | 663 / 789 / 915 / 1,041 | 178 | 8 | 34 |

The 1–3-of-5 scriptSig size is exactly `482 + 126*t` for the deterministic
60-byte signature fixtures and `t` actual selections. It always takes **3
lookup-hint items and 12 total entry items**, including the empty padding. The
1–4-of-5 variant always takes **4 hints and 16 total entry items**. The 1–2-of-6
variant takes **2 hints and 8 entry items**; its maximum includes the longer
initial depth hint. Static opcode counts include skipped branch instructions;
executed non-push counts were not instrumented. Each actual selection executes
two CHECKSIGs.

Variable subsets alone are not a secure message encoding: after observing a
larger subset, anyone could publish one of its nonempty subsets. The proposed
encoding therefore restricts the **total number of verified reveals across all
pools** to a fixed value. Distinct accepted messages then form an antichain:
a different accepted selection cannot be a strict subset of the observed
selection. The protocol's acceptance logic must enforce that global count;
these individual redeem scripts do not enforce it. Moreover, decoder rejection
alone is insufficient for funded publication: a third party can erase optional
openings, produce a valid lower-weight spend, and leave the P2TR helper's
signature unchanged. That consumes the publication outputs without delivering
an accepted full message. Consequently the variable pool is a conditional
research construction, **not the standalone publication result**. The final
full-transaction experiment uses fixed per-pool thresholds. See
[the exact encoding and transaction-cost experiment](encoding-optimization.md).

## Reproduction and limits

Run only this focused experiment:

```sh
cargo run --locked --example pointlock_lookup_probe
```

[Source](../../examples/pointlock_lookup_probe.rs) compiles through
`ScriptCompilation::compile_with_policy()`. It covers `n=2..7`, fixed
`t=1..3`, both key representations, direct-depth versus integer-row hints, and
both input-staging layouts. Variable pools cover `n=3..6`, maximum count two
through four. Fitting fixed and variable configurations execute all canonical
subsets in a Legacy context. Fixed configurations also accept reversed
selection order. Negative cases include incorrect signatures, incorrect keys,
repeated openings, invalid depths, and empty variable subsets.

Evidence: **locally-reproduced**. Deployment class: **unclassified** pending
independent full-transaction validation for each exact compiled configuration.
The local interpreter is `bitcoin-scriptexec`
`702544c9a045ac4fc14846da6da6559e2b7cd9d1`, with `ExecCtx::Legacy` and
`Options::default()`; the compiler is `bitcoin-script`
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`. Both identities are emitted from the
embedded Cargo.lock provenance helper. No shared tapscript execution helper or
disabled stack-limit mode is used. The synthetic transaction has input index
one and one output, selecting the native legacy SINGLE constant. Transaction
wrapping, relay policy, and all-other-digest extraction are separate questions.

The generator writes exact [fixed-pool vectors](lookup-vectors.json) and
[variable-pool vectors](lookup-variable-vectors.json) for independent validation.
The ordinary-digest security question of the underlying committed point lock
is unchanged. These measurements establish byte savings and local execution;
they do not close that open argument or prove global optimality.
