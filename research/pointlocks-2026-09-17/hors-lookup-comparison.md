# Binohash lookup tables applied to Sum-Key publication

Question: can Binohash's HORS table layout reduce creation plus spending for
an arbitrary 256-byte point-lock publication, with purely algebraic setup?

**Lookup tables help, and the existing Sum-Key scheme already uses them.**
The follow-up also found that the old bare scan unnecessarily stopped at seven
selections: ten fit its 201-opcode budget. The best uniform-pool configuration
in the new scan has a **153,125-vB canonical maximum size estimate**.

## Source comparison

[Binohash](https://robinlinus.com/binohash.pdf), section 6.4 and Appendix B,
uses a hash-commitment table and destructive `OP_ROLL` selection. Appendix B
also selects public dummy signatures from a second table and moves witness
operands directly from below the tables. Its dummy signatures support legacy
FindAndDelete; they are not secret point-lock openings.

The inspected 33-page PDF has SHA256
`1be2b63034a86db1f9f4a35c7963248d307583723079ff25284a9fc4affee94a`.
The local [HORS helper](../../src/signatures/hors/mod.rs) instead uses
non-destructive `OP_PICK` and accepts caller-supplied indices without enforcing
distinctness. It is an explicit hash-opening helper, not a replacement for
the fixed-cardinality point-lock verifier.

Our existing table contains `HASH160(P_i)`, selected destructively. Each
opening supplies a signature, compressed key and depth hint, authenticates
the key hash, checks signature length greater than 57, and verifies the same
signature under P_i and G. Thus the public transcript yields
`log_G(P_i+G) = -2z/r_i`. Publishing the point-lock signatures in a public
lookup table would publish those scalars before spending. Storing ordinary
HORS hash preimages instead would require an additional proven link to the
committed curve points, which this lookup optimization does not supply.

## Reproduced comparison

The [probe](../../examples/pointlock_hors_lookup_probe.rs) compares the existing
altstack-staged records with direct access to records below the table. The
latter reverses frame order and uses three constant-depth `OP_ROLL`s per
selection. It preserves strict index range checks and destructive selection;
it does not copy the paper's index-clamping convention.

| Layout | Pools | Locking script per pool | Maximum scriptSig per pool | Non-push opcodes per pool | Funding | Spending | Combined |
|---|---:|---:|---:|---:|---:|---:|---:|
| Existing validated 7-of-48 | 79 | 1,232 B | 756 B | 140 | 98,308 vB | 63,252 vB | 161,560 vB |
| Staged 10-of-57 | 58 | 1,502 B | 1,080 B | 200 | 87,865 vB | 65,260 vB | **153,125 vB** |
| Direct 11-of-64 | 52 | 1,709 B | 1,188 B | 187 | 89,551 vB | 64,136 vB | 153,687 vB |

The last two rows are complete serialization **estimates**, using repeated
pool fixtures and placeholder helper signatures. Their individual scripts
pass the local legacy interpreter, but no complete independently generated
publication, native Core run, or setup-time benchmark is claimed for these
rows. The first row is the previously Core-validated maximum; its sequential
message fixture is 161,382 vB. Compare maxima: the new staged estimate saves
8,435 vB (5.22%). The direct variant saves opcodes but its depth constants cost
extra bytes, so it loses to the better staged configuration in this scan.

The scan covers every integer n from max(16,t+1) through 100, and t from 1
through 12, discarding scripts above 201 non-push opcodes or 10,000 bytes.
This is not a global optimum over all layouts or mixed pools. Exactly
`C(57,10)^58 >= 2^2048`, while 57 pools are insufficient. Its 3,306 candidate
points supply 580 openings. The direct configuration has 3,328 candidates
and 572 openings. Setup uses the same candidate-generation procedure, with
no new grinding mechanism or ZKP; its complete timing remains unmeasured.

The serialized transactions start from one existing P2TR UTXO. Funding creates
a first P2TR helper output and every bare pool output; spending consumes all
of them and creates one P2TR output. Costs include both scripts, outpoints,
sequences, output amounts, every CompactSize prefix, 64-byte helper signatures,
empty legacy witness vectors, marker/flag bytes and separate vbyte rounding.
All point-lock signatures are exactly 71 bytes including the sighash byte.
Initial UTXO creation, change, refunds and additional authorization are excluded.

| Layout | Mandatory hints per input / total | Complete entry data per input / total | Measured combined stack peak | Serialized witness vectors, both transactions |
|---|---:|---:|---:|---:|
| Staged 10-of-57 | 10 / 580 | 30 / 1,740 | 91 | 190 B |
| Direct 11-of-64 | 11 / 572 | 33 / 1,716 | 101 | 184 B |

All opening operands and hints coexist at script entry; staged records move
to the altstack, included in the peak. Different inputs have separate stacks.
Bare inputs have zero witness items; the totals include their empty-vector
bytes and both helper witnesses, excluding the four marker/flag bytes.
Unused table entries remain at termination, as bare consensus permits.

Evidence: `locally-reproduced`; deployment: `unclassified` for the new rows.
Execution uses `ExecCtx::Legacy`, default options and enabled stack limits,
not the shared tapscript helper. Compiler:
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`; interpreter:
`702544c9a045ac4fc14846da6da6559e2b7cd9d1`. All scripts compile through repository
policy with optimization enabled. Tests cover every 3-of-6 subset in two
orders, malformed/short signatures, wrong keys, invalid/oversized hints,
missing frames, duplicate openings, large-pool ordering and opcode boundaries.

```sh
cargo test --locked --example pointlock_hors_lookup_probe
cargo run --locked --example pointlock_hors_lookup_probe
```

[Saved measurements](hors-lookup-comparison.json).

The subsequent [table-first selector](clamped-lookup.md) uses 16 operations
per opening, with a mixed **151,176-vB** maximum estimate. Its constituent
pools pass 78 Core controls; full mixed publication validation is still pending.

## What remains below 100,000 vB

These changes retain the explicit independent-key representation. Its
[existing bound](sub100-lookup.md) is 119,403.84 vB with 71-byte signatures,
even before verification code, selectors and transaction framing. Even
granting ideal 58-byte signatures leaves 111,573.86 vB. Lookup scheduling alone
therefore cannot meet the goal within this family. A smaller authenticated
point representation, a different opening primitive or a sound witness-
discounted construction is still needed. Full native validation of the
153,125-vB candidate remains a separate, falsifiable next step.
