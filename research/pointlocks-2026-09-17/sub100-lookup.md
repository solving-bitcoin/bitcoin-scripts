# The sub-100,000-vbyte target and explicit point tables

The target is publication of **every possible 256-byte value**, counting both
creation of the point-lock outputs and their eventual spending, below 100,000
vbytes. Setup is noninteractive, uses no ZKP, and the historical honest-work
budget is below `2^64`. A construction must retain public algebraic binding to
the target points and resist replacement of a published message, including
removal of optional revelations.

The explicit independent-point-table family cannot reach this target merely
by improving its Script lookup or subset encoding. A lower bound already
exceeds 100,000 vbytes before accounting for any opcodes, lookup hints,
transaction framing, common verification key, or P2SH wrapper.

This is a bound for a specified representation family, **not an impossibility
claim for Bitcoin Script or point locks in general**.

## Representation-family bound

Assume each independent selectable candidate uses one of these representations:

- HASH160 of its compressed verification key appears once in a committed
  table: 20 bytes plus one push byte. A selected candidate supplies the
  33-byte key and a signature, with their push bytes.
- The compressed verification key itself appears once in the table: 33 bytes
  plus one push byte. A selected candidate supplies a signature and its push.

The current sum-lock guard accepts signature items strictly longer than 57
bytes, including the sighash flag. Grant the defender the optimistic minimum
of **58 bytes for every signature**, even though the measured honest generator
uses 71 bytes. The corresponding costs per candidate are:

| Representation | Fixed table bytes `a` | Bytes per revelation `b` |
|---|---:|---:|
| Hashed key, measured 71-byte signature | 21 | 106 |
| Hashed key, ideal 58-byte signature | 21 | 93 |
| Embedded key, measured 71-byte signature | 34 | 72 |
| Embedded key, ideal 58-byte signature | 34 | 59 |

Let a uniformly sampled 2,048-bit message select candidate `j` with probability
`p_j`. Even allowing an arbitrary globally correlated subset code, its entropy
is at most `sum H2(p_j)`, by entropy subadditivity. Its expected serialization
cost is at least `sum (a_j + b_j*p_j)`. Therefore its cost per authenticated bit
is bounded below by:

```
min over 0 < p < 1 of (a + b*p) / H2(p)
```

The inequality applies to nonuniform tables, mixed threshold sizes, global
constant-weight codes, and arbitrary mixes of the two stated key
representations: apply the minimum ratio to each coordinate separately. A
worst-case size cap also caps the uniform-message expected cost. Selection
order does not contribute independent authenticated bits, because rearranging
already revealed candidate openings requires no additional secret.

| Representation | Best density | Lower bound, bytes per bit | Lower bound for 2,048 bits |
|---|---:|---:|---:|
| Hashed key, 71-byte signature | 0.220938 | 58.302657 | **119,403.84 vB** |
| Hashed key, ideal 58-byte signature | 0.234469 | 54.479425 | **111,573.86 vB** |
| Embedded key, 71-byte signature | 0.311852 | 63.055246 | **129,137.14 vB** |
| Embedded key, ideal 58-byte signature | 0.331862 | 58.441140 | **119,687.45 vB** |

These bytes are legacy non-witness bytes, so they contribute equally many
vbytes. The bound omits every additional cost and grants signatures shorter
than our current generator produces. It consequently cannot be repaired by
better opcode scheduling, cheaper indexing, or larger pools alone.

The bound assumes separately serialized independent candidate commitments and
one opaque signature per selected candidate. A compact accumulator,
algebraically authenticated implicit candidate set, witness-discounted
construction, or different primitive can escape these assumptions. A proposed
shortcut must specify which assumption it removes.

## Bare legacy experiment

The [focused source](../../examples/pointlock_sub100_table_bound.rs) also compiles
larger bare legacy tables, allowing `n` up to 400 and thresholds up to seven.
It deliberately omits unused-table cleanup, favoring bare script's lack of a
consensus CLEANSTACK requirement. This saves operations but makes it unsuitable
for ordinary relay policy. Every byte of the locking script is still charged
to the funding output; the spending input does not repeat a redeem script.

The best sampled row was **7 of 48**:

- 1,232-byte bare locking script;
- 756-byte scriptSig, using 71-byte signatures;
- 26.13 bits per selected subset;
- 78.14 incremental creation-plus-spending bytes per bit;
- approximately **160,024 bytes** for 2,048 bits before complete transaction
  framing and rounding the number of pools.

This historical scan is a sampled comparison, not a global optimum. Its
compilation-only result is superseded for the seven-of-48 profile by the
[complete bare publication](bare-publication.md): 79 pools, **161,382 vB actual**,
**161,560 vB canonical maximum**, 553 recovered scalars and a 256-byte roundtrip.
That follow-up is `differentially-validated` and `consensus-validated`, with
default policy rejection. Each `t`-revelation input
has **t mandatory index-hint items and 3t total data items**, all present at
entry. It uses the alt stack; an analytical combined-stack upper bound is
`n+3t+5`, below 1,000 for the scanned domain. No measured peak or executed-opcode
count is claimed. There is no witness discount; witness vector framing and
whole-transaction overhead are excluded from the per-pool comparison.

Evidence: **locally-reproduced** sizes. Deployment class: **unclassified**.
The compiler is `bitcoin-script`
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`, read through embedded Cargo.lock
provenance. Every script uses `compile_with_policy()`; all scanned scripts are
below the optimizer's 32-KiB cutoff. Reproduce with:

```sh
cargo run --locked --example pointlock_sub100_table_bound
```

[Exact output](sub100-table-bound.txt) includes the numerical entropy minima,
all sampled table sizes, opcode counts, hints and input data accounting.
No unrelated primitive tests are run.

The [Binohash HORS lookup comparison](hors-lookup-comparison.md) extends the
scan to thresholds ten and eleven. It finds a **153,125-vB maximum serialization
estimate** with 58 ten-of-57 staged pools. Individual legacy scripts pass local
tests; complete native publication validation and setup timing remain pending.
This improves the sampled layout, without changing the representation bound.

## Compression approaches that do not yet provide a construction

**Grinding leading zeroes in HASH160 does not shorten its stack encoding.**
The output remains 20 bytes. Script arithmetic rejects numeric operands longer
than four bytes before interpreting their value, even if they contain many
zeroes. CAT/SUBSTR are unavailable, so storing a short suffix does not provide
a reconstruction operation. These are explicit behaviors in the pinned
[Core ScriptNum definition](https://raw.githubusercontent.com/bitcoin/bitcoin/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/script.h)
and [interpreter](https://raw.githubusercontent.com/bitcoin/bitcoin/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).

**A hash path is not an arbitrary-key Merkle accumulator.** The repository's
[binary](../../src/commitments/hash_path/README.md) and
[four-way](../../src/commitments/four_way_hash_path/README.md) paths apply chosen
sequences of hash functions to one starting value. To authenticate many
independently generated public keys against one fixed final 160-bit state,
setup would need engineered mergers or multiple preimages. A generic
160-bit birthday merger costs about `2^80`, exceeding the stated `2^64` honest
work budget. This is an estimate under the generic hash model, not a lower
bound for every possible structured construction. The binary path also has
known aliases if its initial preimage is not independently bound.

**Public affine relations between candidates do not give free independent
choices.** If `T_j=a*T_i+b*G` for publicly known scalars, one revealed scalar
immediately supplies the other. Counting these as independent subset entries
would overstate the authenticated message capacity. Native key-recovery
relations must be audited for this before claiming table compression.

**The all-digest extraction theorem does not remove SegWit setup circularity.**
For the common-generator setup, `T_i=(-2z/r_i)G` depends on the native digest
`z`. Committing to those keys inside P2WSH changes the scriptCode and therefore
that digest; the funding outpoint introduces another dependency. Fixing a
spending transaction after setup does not itself resolve this cycle.

## Remaining useful target

A successful sub-100k approach must demonstrate a smaller representation of
independent selectable points, rather than only a smaller verifier for the
current representation. A falsifiable candidate would supply one compact
commitment and an efficiently checked opening binding each selected point to
that commitment, without one separate 20- or 33-byte entry per candidate and
without a generic `2^80` setup search, while preserving extractability and
message non-erasure. No such construction was established in this probe.
