# Fully signed six-context publication at 98,323 vB

Question: does the [round-major size estimate](round-major-contexts.md) survive
real signatures, independent target tables and complete funding/spending?
**Yes for the honest native fixture: both transactions pass Bitcoin Core
policy and are mined at 98,323 combined vB.** Independent decoding recovers
475 target scalars and the original 256-byte message. This is not a general
extraction proof or a completed BitVM3 setup.

[Rust generator](../../examples/pointlock_round_major_publication_probe.rs),
[full transactions](round-major-publication-transactions.json),
[Core/recovery harness](round_major_publication_core_check.py),
[Core report](round_major_publication_core_check.json),
[benchmark driver](round_major_setup_benchmark.py),
[benchmark samples and provenance](round-major-setup-summary.json).

## Actual complete transactions

The instance has 95 independent 5-of-54 pools: 5,130 candidate points, 475
selected scalar openings and 2,850 short ECDSA checks. Each selected point
also has its committed ALL anchor; each pool has a mandatory authorization.
The generator derives targets from domain-separated deterministic public
test seeds and checks global commitment uniqueness. These seeds are for
reproduction, not production secret generation.

| Transaction | Weight | Actual vB |
|---|---:|---:|
| Create the first P2TR helper and all 95 P2WSH outputs | 16,784 WU | 4,196 |
| Consume the helper and all 95 publication outputs; create final P2TR output | 376,505 WU | 94,127 |
| **Combined, summing separately rounded transaction vbytes** | **393,289 WU** | **98,323** |

Both transactions include real signatures, complete witness framing,
CompactSize lengths and all input/output bytes. The original 98,334-vB
estimate reserved 72 bytes for every pool authorization; the actual
authorizations have 71 or 72 bytes. No witness data or publication output is
omitted. The external regtest grant only supplies the assumed initial P2TR
coin; it is excluded from protocol costs and identified separately in the
report. Script generation uses `compile_with_policy()` and is optimized.

Every pool has a 1,503-byte script and 201 charged opcodes. There are five
index hints, 46 entry data items and 47 complete witness items per pool;
serialized witness size is 3,794 or 3,795 bytes. All five hints coexist with
the other entry data. Totals are 475 hints and 4,370 entry items across 95
independent stacks. The branch-free combined main/alt-stack height trace
peaks at 100 for every pool, including temporary pushes; this is an
independent trace, not an instrumented Core counter. The 95 complete pool
witnesses contain 4,465 items, in addition to the helper witness.

## Native verification and decoding

Bitcoin Core 30.3 at commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227` accepts funding and spending under
default policy and mines them on disposable regtest with networking and
wallets disabled. Three changed full transactions fail policy and consensus:
invalid authorization, a short signature replayed across contexts, and a
wrong recovered public key. The earlier small/full-pool suite additionally
covers 18 positives and 19 invalid selector/witness cases.

The independent Python decoder reads Core's actual decoded witnesses. It
checks each spent output, script hash, table commitment, selection depth,
authorization, actual BIP143 context and ECDSA equation. Its 3,420 equation
checks cover pool authorization, anchors and all short checks; Core also
validates the P2TR helpers. All 2,850 short signatures individually extract
their intended target scalar using the fixture's known G/2 nonce; the six
results for each label agree. It reconstructs all 475 selected points and
decodes the mixed-radix message to these 256 bytes:

```
00 01 02 ... fd fe ff
SHA256 = 40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880
```

The codec's radix is 3,162,510, and its 95-pool product exceeds 2^2048.
Four focused Rust tests cover 1,088 boundary/interior rank roundtrips,
complete-message boundaries, invalid message length, and public setup
validation. The latter overwrites all private opening caches before a
successful public check, then rejects six malformed public instances:
missing pool, missing candidate, duplicate commitment, changed anchor flag,
mismatched target, and wrong compiled script.

Evidence: **differentially-validated** native transactions and fixture
recovery; positive transaction deployment: **policy-validated**. This decoder
checks the canonical fixture encoding, not every consensus-allowed spending
form. It does not claim unknown-nonce extraction. No stack-unlimited or
tapscript execution helper is used.

## Scoped setup measurement

Host: Apple M5 Pro, 15 logical CPUs, 24 GiB RAM, macOS 26.6.1 build 25G76,
arm64. Build: release, rustc 1.98.0; compiler dependency commit
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`. Fixed instance-specific inputs
and all raw samples, commands, source hashes and executable hash are recorded
in the benchmark report. Serial and parallel generation produce byte-identical
transactions, per-pool public data and negative cases for the same funding
grant.

| Setup boundary | Serial, 3 samples, median | 15 workers, 7 samples, median |
|---|---:|---:|
| Target/table generation and policy compilation | 300.03 ms | 47.47 ms |
| Public point/anchor/table/script checks | 228.82 ms | 42.31 ms |
| Combined per-sample elapsed time | 528.85 ms | **89.63 ms** |

Parallel combined times range from 88.43 to 154.47 ms; the first sample is
154.47 ms. The serial combined range is 527.62–622.32 ms. Medians of separate
columns need not sum to the median of per-sample totals. No cold-start
sub-100-ms guarantee is claimed.

This boundary includes all 95 pools, 10,372 target-point multiplication
attempts for the fixed seed, public DER/point/commitment checks, duplicate
checks and reconstruction of all scripts. Public checking does not need the
opening scalars. No instance-specific table generation is moved outside the
timed interval. Process startup, compilation of the executable and ordinary
library build artifacts are excluded. Transaction funding and later signing
are also outside setup; the recorded native fixture took about 258.72 ms for
opening generation, with one transaction attempt and 2,856 short-signature
attempts.

**These are point-lock setup measurements, not complete-goal setup timings.**
They exclude the total garbled decoder, intended BitVM3 verifier and their
public malicious-setup checks. Evidence is **locally-reproduced** for the
timings and byte identity, with deployment **unclassified** for the complete
candidate. The prior 4-of-50 decoder timings are not measurements of this
5-of-54 instance.

The separate [95-pool decoder measurement](round-major-message-decoder.md)
now covers fresh target derivation, encrypted complement shares, per-pool
rank garbling and the total message circuit for this exact instance.
Generation takes 364.16 ms median; an audit requiring all secrets takes
367.84 ms, with a combined median of 733.29 ms. These timings overlap target
derivation above and exclude public setup verification and the full verifier.

## Remaining requirements

The complete signed transactions replace the earlier placeholders for this
honest fixture. They do not close the all-consensus extraction argument,
cross-label/adaptive nonce analysis, public garbling/translation binding or
mandatory-input binding. The total decoder now maps every complete valid
codeword modulo 2^2048 and reproduces the native payload through the actual
475-scalar translation path. The complete publicly checked setup still needs
its own benchmark and correctness argument.
The goal remains open; the required scalar-disclosure property cannot be
inferred from successful known-nonce examples.

The [participation follow-up](pool-participation.md) now checks the input-set
gap on these exact scripts and commitments. Core accepts four newly signed
one-pool variants, with or without the helper, leaving 94 pools unspent.
Three stale-signature controls fail. This does not refute the individual
openings, but a complete application must enforce full publication or show
that partial spending can only cause a safe abort.

The [cross-key graph follow-up](cross-key-nonce-extraction.md) replays these
exact transactions through a joint public-equation extractor. All 475 target
scalars recover from a rank-951 graph of 3,325 ECDSA rows; the known-G/2 branch
is not used by that helper. This changes neither transaction size nor the
fixture's existing extraction guarantee. General transcripts may have
unresolved graph components; the follow-up records that boundary explicitly.

```sh
cargo test --locked --example pointlock_round_major_publication_probe
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/round_major_publication_core_check.py
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/round_major_setup_benchmark.py
```
