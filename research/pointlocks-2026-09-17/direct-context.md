# Direct target keys with six separated signature contexts

Question: can repeated native checks fit another short-signature condition
under 100,000 total vbytes without the anchor signature and recovered key?
**Yes for honest execution: 98,706 vB, validated by Core.** But removing the
anchor removes an important coupling between sighash modes. The six checks
cannot be credited as six jointly ground conditions. This is a conditional
prototype, not a solution or a demonstrated security improvement.

## Predicate and selection

Commit directly to HASH160(T_i), rather than HASH160(tau_i). For each selected
target, verify six exact-60-byte signatures under that same target key, with
an executed CODESEPARATOR immediately before each check. The holder signs
actual native digests with nonce G/2, trying six standard flag values for the
length requirement. Mandatory owner authorization and helper signatures remain.
There are 115 four-of-50 pools, with the same 5,750 points and payload encoding
as the anchored fixture. This reuses one key per label across contexts; the
older scaled-key prototype stored a different key for each context.

For a selection with m table entries remaining, the selector is:

```text
<m> ROLL <m+1> ROLL
<m> MIN
ROLL OVER HASH160 EQUALVERIFY
```

The effective hint is explicitly min(h,m). Positive h>m aliases the bottom
remaining entry; the raw hint is not claimed canonical. Negative h fails ROLL;
more than four bytes fails MIN. At h=0, either the hash comparison fails or
a remaining 20-byte table hash becomes the verification key and fails ECDSA.
The latter case is tested with a crafted 20-byte key passing the hash check.
Successful selections remove one authenticated table entry, enforcing distinct
choices. This new candidate changes the hint mapping, not the strict index
requirements of earlier implementations. MIN saves two charged operations per
selection. All scripts still use the centralized compiler policy.

## Actual transactions and resources

[Generator](../../examples/pointlock_direct_context_publication_probe.rs),
[Core harness](direct_context_core_check.py),
[transactions](direct-context-publication-transactions.json), and
[Core report](direct_context_core_check.json).

| Transaction | Inputs | Outputs | Weight | vB |
|---|---:|---:|---:|---:|
| Create helper and 115 P2WSH pools | 1 | 116 | 20,224 | 5,056 |
| Consume helper and every pool | 116 | 1 | 374,599 | 93,650 |
| Sum of individually rounded vB | | | 394,823 | **98,706** |

The excluded regtest grant models one pre-existing P2TR coin. Every protocol
output is created and consumed; all framing, authorization and helper costs
are included. The unfunded host fixture has a different 98,704-vB size.

Each pool has a 1,405-byte script, 200 charged non-push operations, 25
CHECKSIGVERIFYs, four mandatory index hints, 33 total entry items and 34 complete
witness items. Its serialized witness is about 3,089 bytes. All four hints
coexist at entry. Across independent inputs: 460 hints and 3,795 entry items.
An independent straight-line bytecode height trace peaks at **83 combined
stack items**, with no altstack; the loose bound is 89. This is not an
instrumented Core peak or a single stack spanning all inputs.

Core 30.3 commit49faec4f87f5cd19c88db01a82e5c68b087c8227 accepts both complete
transactions under recorded relay policy and mines them on disposable regtest
with wallets and networking disabled. Seven cases fail both policy and block
validation: bad authorization, copied cross-context signature, wrong target
key, zero index, negative index, five-byte index, and the crafted zero-index
key. A 2^31-1 positive hint passes and selects the same target as hint 50.

Independent Python BIP143 and curve calculations verify 2,875 ECDSA equations,
recover 460 scalars from 2,760 short signatures, and reconstruct all 256 bytes.
Rust tests exhaust all 230,300 pool ranks, test zero/FF/ascending messages and
reject short payloads. Native execution uses Core, avoiding the known local
interpreter CODESEPARATOR bug. No tapscript/unlimited-stack helper is used.

Evidence for these honest transactions: **differentially-validated**.
Deployment: **policy-validated** for those transactions, **unclassified** for
general cryptographic/protocol completeness.

## Setup boundary

[Runner](direct_context_setup_benchmark.py),
[five samples and provenance](direct-context-setup-benchmark.json).
Apple M5 Pro, 15 logical CPUs, macOS 26.6.1 arm64, release build, 15 workers.

| Point-lock-only metric | Median | Minimum–maximum |
|---|---:|---:|
| Generation | 25.89 ms | 25.66–111.13 ms |
| Public checking | 19.50 ms | 19.10–25.39 ms |
| Combined per sample | **46.59 ms** | 45.01–130.23 ms |

The first sample takes 130.23 ms: no blanket sub-100-ms latency claim.
Generation rebuilds every point, key table and policy-compiled script.
Checking validates point encodings, duplicate hashes, rebuilt scripts and
context counts. Worker startup is included. Secrets are deterministic public
fixtures. Garbling, VSS, translation, process startup and compilation are
excluded. Funded opening generation took 230.36 ms, separately from setup.

Exact equality of all 5,750 targets and all 460 selected extraction records
with the previous anchored fixture is checked. The existing
[translation](subset-translation.md) therefore has the same label interface.
Its 1.590-s opened-table audit is still not public verification or full
garbling setup. No new full garbled-verifier evaluation is claimed.

The [threshold-complement bridge](complement-translation.md) now replaces that
large subset table with encrypted shares and actual per-pool garbled decoders.
It reproduces the same payload from the cached native scalars and measures
72.64 ms median for generation plus an all-secrets audit. That audit still
cannot replace public setup verification; this changes neither the point-lock
extraction status nor the full-protocol completion status.

The later [total message decoder](total-message-decoder.md) implements the
global garbled modulo-2^2048 stage, with 341.82-ms generation and a 348.66-ms
all-secrets audit. That run uses the anchored fixture's identical target/scalar
interface and does not rerun this direct fixture on Core. It adds no onchain
data and does not resolve staged-sighash extraction or public setup binding.

## Established extraction branches

For r=x(G/2), compute t=(s*k-z)/r mod n for k=+/-1/2 and select tG=T.
Repeated r with unequal reduced digests also gives ordinary nonce-reuse
extraction, trying both nonce signs. Exact-60-byte DER makes r too large for
the r+n recovery ambiguity. The [extractor](direct_context_extraction.py)
implements those branches and five focused algebra tests. Its new
[affine-relation fallback](nonce-relation-extraction.md) additionally covers
nondegenerate signed GLV or explicitly supplied public affine nonce relations.
Six unrelated unknown nonces remain unresolved. Its synthetic digest fixture is not a Bitcoin
counterexample. All consensus sighash choices still need analysis; HASH160's
generic malicious-setup collision ceiling is about 80 bits.

## Staged sighash search: the reason not to claim amplification

The [dependency test](direct_context_staged_sighashes.py) first matches all
24 baseline short digests for an actual funded pool. On the same script's
first six suffixes, choose ACP|NONE, ACP|NONE, ACP|SINGLE, SINGLE, ALL, ALL.

| Mutation | First two | Third | Fourth | Last two |
|---|---|---|---|---|
| Own input sequence | changes | changes | changes | changes |
| Corresponding output | unchanged | changes | changes | changes |
| Another input's outpoint | unchanged | unchanged | changes | changes |
| Noncorresponding output | unchanged | unchanged | unchanged | changes |

These are computed native hashes following
[BIP143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki).
The mutated outpoint is a dependency fixture, not a funded UTXO. A real search
needs a valid replacement ancestor, such as a helper transaction with a
varied data output, signed after choosing its txid. Own sequence plus valid
locktime choices supply more first-stage variation than sequence alone.
Later output/data fields provide larger search spaces. The malicious owner
can sign mandatory authorization after all stages; it does not force joint
grinding. The other labels can use ordinary honest G/2 openings.

The search can address groups 2,1,1,2 in order while preserving earlier
conditions. A [heuristic screen](direct-context-staged-sighashes.json) with
four raw-flag variants per class favors 25-byte r and 28-byte s, five distinct
nonce candidates per context. It estimates **2^61.91 nonce point trials**,
**2^61.69 scalar signature checks**, and stage transaction-trial exponents
55.37,27.68,27.68,55.37. These are separate units; native hashing and ancestor
costs are additional. No rare search or non-extracting native spend was run.
This is not a lower bound or a proof that every possible extractor fails.
It invalidates a six-fold joint-grinding estimate for this static-key design.

For the anchored alternative, each such ALL-committed mutation changes z0
and the checked private key p=(t-z0)/rT. Keeping a NONE/SINGLE digest fixed
then does not preserve its old signature condition. Removing tau saves bytes
but removes that coupling. This observation does not prove the anchor secure.

The [size probe](../../examples/pointlock_direct_context_size_probe.rs) screens
n=3..180, t=1..10, d=3..16 with homogeneous profiles, direct/HASH160 tables and
strict/clamped selectors. The original strict six-check best row is 101,278
vB. The clamp scan gives 98,720 vB with placeholder maximum authorizations;
actual signatures produce the 98,706-vB funded fixture. Seven checks still
cost 113,880 vB in this bounded scan. These are not global optima or proofs.

All-transcript extraction, total mixed-radix semantics, malicious translation
and garbling checks, compulsory pool participation and challenge/refund
integration remain goal requirements. The direct variant is not accepted as
a solution to these gaps.

```sh
cargo test --release --locked --example pointlock_direct_context_publication_probe
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/direct_context_core_check.py
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/direct_context_extraction.py -v
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/direct_context_setup_benchmark.py
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/direct_context_staged_sighashes.py
```
