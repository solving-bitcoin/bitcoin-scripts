# Anchored recovery key with separated short-signature contexts

This is an unfinished candidate, not an established point lock. The current
user objective is less than 100,000 total on-chain vbytes for a future signed
256-byte message, with setup ideally below 100 ms; 1–2 seconds is marginally
acceptable. Off-chain storage is not an optimization constraint. Preserve the
prior noninteractive, no-setup-ZKP and point-scalar extraction requirements.
Actual honest publication is now reproduced at **96,176 total vB** on Core30.3.
Point-lock setup and public checking have a **66.23 ms median** with15 workers
on an Apple M5 Pro, but the first sample was127.57 ms. These measurements do not
include VSS/garbling integration and do not close the extraction requirement.

## Candidate

For target T=tG, choose r=x(T) with an unsigned 32-byte DER representation and
commit to a 40-byte ECDSA signature tau=(r,1,ALL). Public setup checks that tau
has this encoding and its r corresponds to T; r exceeds p-n, so recovery has
only the two opposite nonce points. A HASH160 table authenticates tau selections.

The selected tau is checked under one witness-supplied compressed key P at
the anchor's actual ALL digest z0. This binds

    P = (±T - z0*G)/r.

The same P is then used for d exact-60-byte ECDSA signatures, each checked after
a distinct executed CODESEPARATOR. Honest generation derives P's scalar from
t and z0, then signs each actual suffix digest with nonce G/2. If a signature
is shorter than60 bytes, another standard sighash mode can be tried; a complete
opening/setup-time bound remains to be measured.

If any short signature uses the known G/2 nonce, the extractor obtains P's
scalar and hence t (checking the sign against T). If two signatures under P
reuse r across distinct reduced digests, ordinary ECDSA nonce-reuse equations
also recover P's scalar, trying both nonce signs. Exact60 excludes the r+n
recovery ambiguity for the short signatures. Distinct Script suffixes give
different preimages, not a mathematical guarantee of different hash outputs.

The missing argument concerns transcripts using different unknown nonces for
all short signatures. Repetition alone is not a proof of a useful work factor.
No lower bound for malicious setup, adaptive transactions and all sighash modes
has been established. Do not describe this candidate as solving the objective.

The [full-consensus follow-up](anchored-rounds-limits.md) now verifies all256
raw sighash bytes on Core and covers uncompressed/hybrid dynamic keys in the
extractor. Only six flag values and compressed keys pass policy. The existing
six-round layout already costs111,372 vB in the bounded sizing scan. Adding
rounds therefore does not supply a demonstrated sub100k repair.
The later [typed-selector optimization](typed-selector-layout.md) reduces the
six-context estimate to 105,039 vB, still over budget, and five contexts to
94,120 vB. The new full-size rows use placeholder signatures; 24 positive and
14 negative native tests validate the smaller selection fixtures only.

A [direct-key follow-up](direct-context.md) removes the anchor and obtains
a six-context, 98,706-vB honest Core fixture. It permits staged searches across
different sighash modes because the target key stays fixed while fields are
varied. In this anchored design those ALL-committed mutations also change
p=(t-z0)/rT, so preserving a short-check digest does not preserve its signature
condition. That distinguishes the designs; it is not a security proof for this
one. See [NR-065](../../knowledge/negative-results/direct-context-staged-grinding.md).

## Serialization screen

`examples/pointlock_anchored_codesep_size_probe.rs` uses the centralized compiler
and serializes creation plus spending, including a first P2TR helper output and
input and every P2WSH pool. Its signatures and recovered keys are placeholders.
The target fixtures use public deterministic scalars, unsuitable for production.

| d | Pool | Pools | Script/pool | Witness/pool | Ops | Hints/pool | Entry/pool | Stack bound | Creation vB | Spend vB | Total vB |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
|3|5-of-48|99|1290|2594|176|5|30|84|4368|68372|72740|
|4|5-of-38|109|1125|2734|201|5|35|79|4798|79082|83880|
|5|4-of-50|115|1362|2894|195|4|32|88|5056|88029|93085|
|6|3-of-42|152|1148|2481|166|3|27|75|6647|100621|107268|

Each row's binomial product has at least2048 bits of capacity. Hints are one
destructive table index per selected label. They coexist with the other entry
data for that input; the complete witness adds one script item. For d=5 this is
460 hints and3680 entry items across115 independent executions, not one stack.
All stated stack values are analytical upper bounds, not measured Core peaks.
The d=6 spend is above the default transaction weight limit. The other rows
have not been policy-tested merely because their weights fit.

Evidence: `locally-reproduced` compilation/serialization; deployment:
`unclassified`. Output: `anchored-codesep-size.json`.

## Native reproduction status

`examples/pointlock_anchored_native_probe.rs` constructs a standalone anchor and
short-check fixture and verifies the ECDSA equations with rust-bitcoin sighashes
and libsecp256k1. The [Core differential](anchored_native_core_check.json) accepts
and mines the correct native spend and rejects a control whose digests include
the executed separator. Pinned local interpreter702544c gives the opposite
results: its SegWit-v0 CODESEPARATOR handler starts scriptCode at the separator
itself, whereas [BIP143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)
starts after it. The dependency checkout was not modified. Use Core as the native
execution authority for these scripts; this result is not from the tapscript
or stack-unlimited helper.

## Fully signed publication fixture

[Generator](../../examples/pointlock_anchored_publication_probe.rs),
[Core harness](anchored_publication_core_check.py),
[transactions](anchored-publication-transactions.json), and
[Core report](anchored_publication_core_check.json).

The actual profile is115 pools of4-of-50 labels, with five separated short
checks per selected label. Every pool starts with a mandatory ECDSA authorization
check. The funder/spender signs that authorization and both P2TR helper inputs.
Adding this authorization is included in the following sizes, unlike the
placeholder screen above.

| Transaction | Inputs | Outputs | Weight | vB |
|---|---:|---:|---:|---:|
| Create helper and115 P2WSH pools |1|116|20,224|5,056|
| Consume helper and every pool |116|1|364,479|91,120|
| Sum of individually rounded transaction vB | | |384,703|**96,176**|

The initial coin is an already existing P2TR UTXO. Regtest mining and the
test-only grant of that coin are excluded. Both actual protocol transactions,
including creation and consumption of all116 outputs, are included. The final
P2TR output is an ordinary recipient output. No optional existing protocol
transaction is credited as free space. No challenge/refund/garbling integration
is represented by this fixture. Authorization DER lengths cause small
transaction-dependent size variation;96,176 is this funded fixture's measurement.

Each pool has a1,397-byte witness script and196 charged non-push opcodes,
including25 CHECKSIGVERIFY operations. There are four index hints,33 complete
entry data items and34 complete witness items, including the witness script.
All four hints coexist with the other data at entry. The combined main/alt
stack upper bound is89. An independent exact height trace of the Core-accepted
straight-line bytecode gives **85 items**, including all entry data and push
instructions; no altstack is used. This is not an instrumented Core stack trace.
Witnesses are about3,002 bytes, varying with authorization
signature length. Across independent inputs there are460 hints and3,795 entry
data items, which never coexist on a single stack.

Core30.3, commit49faec4f87f5cd19c88db01a82e5c68b087c8227, accepted both
transactions under the recorded policy and mined them on isolated regtest with
networking and wallets disabled. Malformed authorization, a wrong recovered
key and a copied short signature at another separator context were rejected
by both policy and block validation. An independent Python BIP143 implementation
checked2,875 ECDSA equations, recovered the460 selected scalars from all2,300
short checks, and reconstructed the original256-byte payload. Evidence for
this honest fixture: **differentially-validated**; deployment class of these
transactions: **policy-validated**. This classification does not certify the
candidate's cryptographic soundness or the full BitVM3 protocol.

Each pool alphabet has C(50,4)=230,300 values. The generator uses115
least-significant-first mixed-radix digits. A focused test exhausts every pool
rank, and tests the all-zero, all-FF and ascending256-byte payloads. Thus the
encoding has capacity for every2048-bit value, not only the recorded payload.
`--payload-hex` supplies another exactly256-byte message after setup.

## Setup measurement

[Raw serial](anchored-setup-benchmark.json),
[raw parallel](anchored-setup-parallel-benchmark.json), and
[summary/provenance](anchored-setup-summary.json).

Hardware: Apple M5 Pro,15 logical CPUs,24 GiB RAM, macOS26.6.1 arm64. Rust
release build; compiler commit124b561ed75ac3ec4c6ad99207d8dcdd3bc67180.
Each sample regenerates5,750 independent deterministic test scalars and points,
performs11,578 target scalar multiplications including rejection trials,
constructs all tables, and compiles every complete script through the repository
policy. Public verification parses the points and exact tau encodings, matches
r to the target, rejects duplicate HASH160 commitments, recompiles and compares
every script, and checks its separator contexts. Parallel worker creation and
the global duplicate check are inside the timers. No lookup memory is reused.

| Run | Samples | Generation median | Public verification median | Combined median | Combined min–max |
|---|---:|---:|---:|---:|---:|
| Serial |5|292.23 ms|213.72 ms|505.93 ms|505.41–592.25 ms|
|15 workers |10|35.76 ms|30.66 ms|66.23 ms|64.57–127.57 ms|

The first parallel sample was127.57 ms. A separate freshly launched full
fixture measured119.85 ms for setup plus checking, so a blanket sub100-ms
latency claim is unsupported. The parallel generator was checked byte-for-byte
against the Core-validated serial transaction fixture. Opening generation in
that serial release fixture took220.69 ms and is reported separately from setup.

These are measurements of the point-lock instance, excluding VSS polynomials,
cut-and-choose, garbling and subset-to-circuit-label translation. Process
startup and compilation of the Rust executable are also excluded. The complete
user-goal setup boundary is therefore still unmeasured. All scalar secrets in
these programs are public deterministic fixtures, not production randomness.

## Remaining proof obligations

The [standalone extractor](anchored_extraction.py) implements and tests the
known-nonce and repeated-nonce branches, including both nonce signs, wrong
digests and the identical-digest degeneracy. The
[affine-relation extension](nonce-relation-extraction.md) now also recovers
keys from nondegenerate public nonce relations, including signed GLV orbits
with distinct r values. Unrelated nonces and zero-determinant relations remain
unresolved. The algebra fixtures deliberately assign digest values and do
not claim those values can be realized by Bitcoin hashing.

A [concrete alternative-nonce cost model](anchored-alternative-opening-cost.md)
also rules out treating five checks as an automatic security multiplier. It
does not execute an attack and is not a hardness lower bound. HASH160 setup
binding has a generic collision ceiling of about80 bits, so no128-bit claim
follows independently of the ECDSA question.

Further unresolved requirements are:

- Extraction for every consensus-accepted short signature and sighash flag,
  under malicious setup, adaptive transaction selection and multiple targets.
- A bound on honest opening retries. The generator now changes the helper's
  sequence and recomputes the complete opening if all six standard flags fail
  the exact60-byte requirement or a recovered private key is zero. It preserves
  outputs, amounts and selections and keeps the relative-locktime-disable bit
  set. There are2^31 retry values. No uniform bound for every message/native
  hash choice follows merely from the successful first-attempt fixture.
- Integration of the [total garbled decoder](total-message-decoder.md) into
  the actual verifier. The historical fixture decoder rejects surplus values
  offchain; the new garbled circuit instead supplies message labels under a
  total modulo-2^2048 rule. Neither behavior enforces mandatory pool inputs.
- Subset-to-garbled-label translation with verifiable algebraic setup, no
  alternate-label leakage, and its complete setup cost. Independent point
  scalars and recovered public message bits alone do not establish this bridge.
- Unavoidable participation of every required pool and application-level
  challenge/refund binding. A malicious authorizer can sign a different input
  set; per-pool authorization is not a covenant enforcing the complete graph.

These are acceptance criteria, not optional production hardening. The active
goal remains unsolved.

The [subset-to-label follow-up](subset-translation.md) now reproduces a real
encrypted translation of the cached 460 extracted scalars to 2,070 binary rank
labels. Its 7.63-GB full table takes 794.81 ms median to generate and 784.15 ms
to check with all secrets disclosed, plus 10.62 ms preparation. That check is
not public verification. A malicious-table test preserves valid public points
while returning wrong labels; neither its MAC nor offchain detection after
publication closes the setup requirement. These costs cover one translation
instance, excluding VSS and garbled copies, and do not alter general extraction.

The [threshold-complement bridge](complement-translation.md) now replaces that
large subset table with encrypted shares and actual per-pool garbled decoders.
It reproduces the same payload from the cached native scalars and measures
72.64 ms median for generation plus an all-secrets audit. That audit still
cannot replace public setup verification; this changes neither the point-lock
extraction status nor the full-protocol completion status.

The [total decoder follow-up](total-message-decoder.md) extends that path
through the full 2048-bit garbled message, including surplus codewords.
Generation takes 341.82 ms median; the all-secrets audit takes 348.66 ms,
with a combined median of 701.05 ms. It reuses this fixture's cached scalar
records without a new Core run or added onchain bytes. Public setup binding
and full verifier integration remain absent.

```sh
cargo test --release --locked --example pointlock_anchored_publication_probe
python3 research/pointlocks-2026-09-17/anchored_extraction.py -v
cargo run --release --locked --example pointlock_anchored_publication_probe -- --benchmark 10 --workers 15
python3 research/pointlocks-2026-09-17/anchored_setup_benchmark.py
python3 research/pointlocks-2026-09-17/anchored_publication_core_check.py
```
