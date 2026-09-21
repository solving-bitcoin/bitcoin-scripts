# Total message decoding for the native 95-pool instance

Question: can the current 5-of-54 publication feed a total 256-byte garbled
message decoder, and what does its complete translation/decoder setup cost?
The comparison includes fresh target derivation, retained encrypted shares,
rank garblings, private inter-circuit wiring and the full message garbling.
It adds no onchain bytes and assumes no instance-specific cached tables.

The honest-setup path now takes all 475 scalar openings from the
[98,323-vB native fixture](round-major-publication.md), produces 5,130 membership
labels and evaluates to its original 256-byte payload. Generation takes
**364.16 ms median**. An audit requiring every secret takes **367.84 ms median**;
the median per-run sum is **733.29 ms**. This completes the decoder adaptation,
not public malicious-setup verification or the full BitVM3 setup requirement.

Sources: [executable](../../examples/pointlock_round_major_message_probe.rs),
[five-share complement layer](../../examples/pointlock_decoders/round_major_complement.rs),
[composition](../../examples/pointlock_decoders/round_major_composed.rs),
[shared mixed-radix circuit](../../examples/pointlock_decoders/mixed_radix.rs),
[benchmark runner](round_major_message_benchmark.py),
[raw samples and provenance](round-major-message-benchmark.json).

## Total rule and actual label path

Let B=C(54,5)=3,162,510 and let r_i be the lexicographic rank of pool i's
five-element subset, independent of selection order. Define

```
m = (sum_{i=0..94} r_i * B^i) mod 2^2048.
```

Serialize m as 256 big-endian bytes. Every complete valid selection has one
result; every possible message has a canonical base-B representation because
B^95 has about 2051.301 bits of capacity. Larger codewords are aliases under
this modulo rule, not additional message bits. Missing pools are outside the
complete-input interface; see the [participation result](pool-participation.md).

Each pool uses degree-four complement polynomials and omits each sender's
diagonal encrypted share. Five selected scalars supply the selected one-labels
and enough shares for each unselected zero-label. The public opening function
receives only points, label commitments, retained ciphertexts and those five
scalars. It checks scalar/point matches and resulting label commitments. The
all-secret generator object remains separate from that evaluator view.

Each rank circuit outputs 22 rank labels and an exact-cardinality validity
label: 2,185 labels enter the global circuit. It range-checks every rank,
conjoins all validity labels, and outputs 2,048 message labels plus global
validity. A composed verifier must require validity to be true. That offchain
condition does not enforce a Bitcoin payout or mandatory inputs.

The shared decoder specializes multiplication using

```
B = 130 * (2^15 - 2^13 - 2^8 + 2^3 - 1).
```

Form 65*x with one addition, combine its shifted terms with four additions/
subtractions, then shift once. Operations truncate modulo the active power
of two; shifts rewire bits. These are offchain Boolean operations, not Bitcoin
opcodes or changes to Script compilation policy.

Garbling retains the prior free-XOR/four-row-AND BLAKE3 construction and its
correlation/PRF assumptions. Fixture seeds and scalars are public for
reproduction; production garbling secrets cannot be published. Public points
and label hashes still do not certify encrypted shares or garbled tables
against a malicious creator.

## Measurements and boundary

Apple M5 Pro, 15 logical CPUs, 24 GiB, macOS 26.6.1 build 25G76, arm64;
Rust release, rustc 1.98.0. Five samples use 15 workers for independent pools
and serial global garbling. Every sample regenerates interpolation preparation,
targets, commitments, coefficients, ciphertexts, rank garblings, private wiring
and message garbling. All 5,130 regenerated targets are compared with the
pinned native manifest inside generation. Allocations and worker startup count.

| Quantity | Result |
| --- | ---: |
| Target points / selected scalar occurrences | 5,130 / 475 |
| Encrypted complement shares | 271,890 |
| Encrypted-share payload | 4,350,240 B |
| Label commitments / compressed target points | 328,320 / 169,290 B |
| Combined per-pool garbling payload | 46,708,080 B |
| Mixed-radix AND / XOR gates | 587,025 / 2,238,322 |
| Mixed-radix garbling payload | 37,700,752 B |
| Combined listed public payload | 89,256,682 B |

Garbling payload includes four 16-byte rows per AND, constant labels and both
output-label hashes. Topology, host object overhead, private generator state
and file-format framing are excluded from this payload metric.

| Time for the complete translator and message decoder | Median | Range |
| --- | ---: | ---: |
| Translation, ranks and wiring generation | 56.34 ms | 54.83–64.29 ms |
| Mixed-radix generation | 308.22 ms | 307.47–330.99 ms |
| Combined generation | **364.16 ms** | 362.47–395.27 ms |
| Translation/rank audit with all secrets | 40.44 ms | 40.14–40.53 ms |
| Mixed-radix audit with all secrets | 327.35 ms | 326.11–353.90 ms |
| Combined all-secret audit | **367.84 ms** | 366.58–394.04 ms |
| Generation plus all-secret audit | **733.29 ms** | 729.06–789.31 ms |
| Scalar-to-rank evaluation | 85.88 ms | 85.83–85.93 ms |
| Mixed-radix evaluation | 69.93 ms | 69.53–73.23 ms |

Medians are independent; the first combined sample is 789.31 ms. Evaluation
is not setup. Public setup verification is absent and recorded as null.
Timers exclude the full BitVM3 verification circuit, extra garbling copies/
VSS, public malicious-setup checks, native scripts/transactions, reading cached
reports, process startup, compilation and disk/network delivery. Target
generation overlaps the point-lock benchmark, so their times cannot simply
be added. The 733.29 ms is not a complete-goal setup result or a demonstrated
public check within the 1–2-second allowance.

## Validation

Seven focused tests cover all 56 five-of-eight subsets, all 256 reduced
membership/cardinality patterns, first/last/spread full-pool choices, hostile
indices, wrong scalars, truncated tables and a changed used ciphertext. The
malformed table preserves public commitments and permits an unaffected
opening; the public setup-binding gap remains explicit.

The new multiplication is compared with independent integer arithmetic on
150 two-digit cases at widths 1, 2, 7, 22, 23 and 44, including wraparound.
Shared tests retain the prior radix and reduced total-decoding cases.

The full-width run checks 0, 1, 2^2048-1, 2^2048, 2^2048+1 and B^95-1.
Alias pairs produce identical actual output labels, not just equal bytes.
A rank equal to B, a false pool-validity label and a corrupted input label
are rejected. These boundary vectors use garbler-held label pairs and are
not additional native spends.

Cached native scalars pass through actual ciphertexts and all garbled stages,
recovering bytes 00,01,...,ff with SHA256
`40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880`.
The manifest hash matches its original Core report. There is no new Core run.

The shared membership guard increases n from 50 to 54, and mixed-radix
multiplication gains the new specialization. A separate
[legacy regression](round-major-decoder-legacy-regression.json) reproduces the
prior 4-of-50 circuit fingerprint, gate counts, payload sizes, native composition
and full-width boundaries exactly. Historical timing reports are not overwritten.
Their source identities remain historical. The older runner explicitly
normalizes the guard change when checking its old membership source body.

Incremental onchain script/witness bytes, hints and stack items are zero.
Bitcoin execution metrics for the offchain circuit are not applicable. The
unchanged native instance has five hints, 46 entry items and 47 complete
witness items per pool, with combined stack peak 100 from an independent
height trace. All five hints coexist at entry. Across 95 independent stacks
there are 475 hints, 4,370 entry items and 4,465 pool-witness items, plus the
helper signature. No unlimited-stack or tapscript helper is used.

Evidence: **locally-reproduced** implementation and timings, **inspected**
arithmetic coverage. Composed deployment: **unclassified**. The cached native
transaction retains separate **policy-validated** status. General extraction,
public malicious-setup binding, complete-protocol label privacy, mandatory
participation/safe abort, challenge graph and full verifier/setup cost remain open.

```sh
cargo test --release --locked --example pointlock_round_major_message_probe
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/round_major_message_benchmark.py
```
