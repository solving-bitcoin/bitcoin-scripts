# Selecting the table entry before loading the opening

Question: can the existing independent Sum-Key table use fewer operations and
bytes, counting both output creation and spending, without extra setup work?

The [prototype](../../examples/pointlock_clamped_lookup_probe.rs) moves table
selection ahead of the public key and signature. The best uniform-pool scan
gives **151,385 vB**; mixing ten 12-of-67 pools with 38 12-of-68 pools gives
**151,176 vB**. These are maximum canonical serialization estimates with 71-byte
signature items, not a complete independently generated publication test.

## Lookup invariant

At selection time, only committed hashes are above the shared G key. With m
hashes remaining, use:

```text
<hint> <m-1> OP_MIN OP_ROLL
```

`MIN` caps a nonnegative hint at m-1. Negative values fail in `ROLL`; numeric
operands longer than four bytes fail in `MIN`. Thus selection cannot reach G,
unprocessed witness data, or a previously consumed hash. Next load the key,
authenticate its HASH160 against the removed entry, load the signature, apply
the length guard, and check the same signature under G and the selected key.

High hints are accepted aliases for the bottom remaining table entry. Decode
the authenticated selected keys into their original indices and sort them;
the raw hint values and selection order are not message bits. Canonical
publication uses only hints from zero through m-1. Altering an alias cannot
change the decoded message without changing the authenticated selected key.
Each successful round removes one distinct table entry. Setup must continue
to reject duplicate keys/hashes and degenerate sum points.

Direct access now uses 16 non-push operations per opening, versus 17 in the
previous direct variant and 20 in the previous staged variant. Twelve
openings use 192 operations; thirteen use 208 and fail the legacy 201 limit.
The new staged version uses 19 per opening and fits ten. This is a change to
record order and accepted index representation; the source retains the size
guard, both ECDSA checks and a terminal true value. Compiler policy supplies
routine local rewrites.

## Cost accounting

| Layout | Pools | Canonical maximum funding + spending |
|---|---:|---:|
| Previous staged 10-of-57 | 58 | 153,125 vB |
| Table-first staged 10-of-57 | 58 | 151,965 vB |
| Table-first direct 12-of-62 | 50 | 151,385 vB |
| Table-first direct 12-of-67 / 12-of-68 | 10 / 38 | **151,176 vB** |

The mixed layout has 3,254 independent candidate positions and 576 openings.
Its capacity is checked with exact integers:

```text
C(67,12)^10 * C(68,12)^38 >= 2^2048
```

Per pool: 1,778 or 1,799 locking-script bytes, at most 1,296 scriptSig bytes,
192 static/executed non-push operations for a successful straight-line run,
24 ECDSA checks, 12 mandatory index-hint items and 36 complete entry data
items. The locally measured combined main-plus-alt peak is 105 or 106.
All data/hints coexist at entry; direct access uses no altstack. Across
48 separately executed inputs there are **576 hints and 1,728 data items**;
these do not coexist on a single stack. Canonical hint pushes cost one or two
bytes each, at most 24 bytes per pool and 1,152 bytes across all 48 pools.
Accepted noncanonical upper aliases can use longer pushes; the size maximum
here describes the canonical publisher, not every consensus-accepted spend.

| Transaction | Maximum virtual bytes |
|---|---:|
| Funding | 86,781 |
| Spending | 64,395 |
| Combined | **151,176** |

Both full serialization shapes include an existing P2TR funding input, a
first P2TR helper output, creation and consumption of every bare pool output,
one final P2TR output, 64-byte helper signatures, all CompactSize prefixes,
empty legacy witness vectors, marker/flag bytes and separate vbyte rounding.
The witness vectors total 180 bytes across both transactions, plus four
marker/flag bytes. Each bare input has zero witness items and contributes one
empty-vector byte beside the helper. Initial UTXO creation, change, refunds
and additional authorization are excluded. Repeated fixture pools and
placeholder helper signatures are used for sizing only; production pools
must use independent candidates. Complete setup time is unmeasured.

The mixed configuration saves 1,949 vB (1.27%) against the previous estimate.
It is not a global optimum over all mixed configurations. The uniform scan
tests n=max(16,t+1)..100, t=1..13, keeping scripts within 10,000 bytes and 201
operations. The mixed profile is separately compiled and serialized, with
its integer capacity checked. The [saved output](clamped-lookup-comparison.json)
pins the compiler, interpreter and source hashes.

## Validation boundary

Local tests enumerate all 3-of-6 subsets in two orders under both layouts.
They exercise negative/oversized hints, upper aliases, short/malformed
signatures, wrong keys, missing frames, duplicate openings and extra lower
stack data, plus larger pools and opcode boundaries. Execution uses
`ExecCtx::Legacy`, default options and enabled stack limits, not the shared
tapscript helper. All scripts use `compile_with_policy()` with optimization.

The [Core harness](clamped_lookup_core_check.py) tests the exact compiled
1-of-8, 10-of-57, 12-of-62, 12-of-67 and 12-of-68 scripts on isolated regtest.
It checks block consensus independently of standardness, and independently
verifies ECDSA equations and scalar extraction for accepted openings.
The [native report](clamped-lookup-core-check.json) passes all 78 expectations:
30 accepted spends, 48 script rejections, and 282 independently checked scalar
openings. Core is 30.3, commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`,
with its unchanged consensus rules. The exact accepted pool fixtures are
`differentially-validated`, `consensus-validated`; no relay-policy acceptance
is claimed. Peaks above are local interpreter measurements, not Core telemetry.
Whole-publication sizes remain `locally-reproduced`, `unclassified` until an
independent complete setup, funding/spending and 256-byte roundtrip are tested.

```sh
cargo test --locked --example pointlock_clamped_lookup_probe
cargo run --locked --example pointlock_clamped_lookup_probe > research/pointlocks-2026-09-17/clamped-lookup-comparison.json
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/clamped_lookup_core_check.py
```

## Limits of further compression

Offsets do not allow different choices to share the same opening. If
`T_i = U - delta_i*G` for public delta_i, disclosing u=log(U) reveals **every**
`t_i=u-delta_i`, not just a selected target. Use independent auxiliary
openings for independent choices. Public offsets can bind externally chosen
targets but do not remove the candidate table by themselves; that wrapper is
an algebraic observation and is not implemented or tested by this probe.

The [explicit-table lower bound](sub100-lookup.md) still applies. This result
does not meet the sub-100,000-vB goal, establish the full setup-time target,
or resolve participation, surplus-codeword and BitVM3 integration obligations.
