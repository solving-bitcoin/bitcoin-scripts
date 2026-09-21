# Total garbled decoding of the 256-byte message

Question: can every complete 115-pool selection supply one well-defined
256-byte message, including the surplus codewords, through an actual garbled
circuit? The comparison objective is the complete offchain translation and
message-decoding cost, with no extra onchain data and no free precomputation.

The honest-setup implementation now composes 460 cached native scalar openings
through encrypted complement shares, membership-to-rank garblings, and a
2048-bit mixed-radix garbling. It produces the original message's 2,048 wire
labels and one validity label. Generation takes **341.82 ms median**; a separate
audit with all secrets takes **348.66 ms median**. The median of their per-run
sums is **701.05 ms**. This closes the decoder implementation gap, not public
setup verification or general point-lock extraction.

[Composition source](../../examples/pointlock_decoders/composed.rs),
[mixed-radix circuit](../../examples/pointlock_decoders/mixed_radix.rs),
[executable](../../examples/pointlock_total_message_probe.rs),
[benchmark runner](total_message_decoder_benchmark.py), and
[measurements and source hashes](total-message-decoder-benchmark.json).

This report measures the historical 115-pool, 4-of-50 profile. The separate
[95-pool adaptation](round-major-message-decoder.md) covers the current
5-of-54 native instance with its own benchmark. A full-width compatibility
run preserves this older profile's circuit fingerprint, sizes, native
composition and boundary results; historical timing samples remain unchanged.

## Total message rule

Let B = C(50,4) = 230,300. For each pool i, let r_i be the lexicographic rank
of its four-element subset, with 0 <= r_i < B. Pool zero is least significant.
Define the message as the 256-byte, big-endian encoding of

```
m = (sum_{i=0..114} r_i * B^i) mod 2^2048.
```

Every complete valid selection has exactly one result. Conversely, every
2048-bit message is representable: expand its integer in base B and pad to
115 digits. This fits because B^115 > 2^2048. The codeword space has about
2048.513 bits of capacity; those fractional extra bits are not independent
message bits. Codewords at or above 2^2048 are accepted aliases of messages
under the modulo rule. Reordering a subset's members does not change its rank.

For a correctly generated fixed garbling, two codewords with the same message
produce the same selected label on each message-output wire. The alias does
not supply the opposite label. The one-opening privacy argument still depends
on the complement translation and garbling assumptions; this arithmetic
observation is not a malicious-setup or extraction proof.

The circuit checks every rank's range and every pool's exact-cardinality
validity label. It outputs their conjunction separately. A composed verifier
must require that output to be true. Defining this function does not force a
Bitcoin transaction to consume all mandatory pool inputs: transaction-graph
binding remains a separate unresolved requirement. Offchain rejection of an
incomplete publication does not repair that requirement.

## Circuit and private wiring

The existing [complement layer](complement-translation.md) supplies 5,750
membership labels. Its 115 garbled rank decoders output 18 rank labels and
one validity label each, giving 2,185 inputs to the new circuit. During setup,
the garbler recovers each rank decoder's two output labels using its private
input-label pairs and free-XOR offset. That wiring computation is timed.
The public evaluator receives only one label per input; neither the private
pairs nor the offset are added to the public decoder object.

The circuit evaluates Horner's rule from the highest pool downward, truncating
to 2048 bits and using smaller accumulator widths while the integer bound
permits. A full-adder carry uses one AND gate:

```
majority(a,b,c) = a XOR ((a XOR b) AND (a XOR c)).
```

Constant multiplication uses

```
230300 = 4 * 7 * (2^13 + 2^5 + 1),
y = (x << 3) - x,
230300*x = ((y << 13) + (y << 5) + y) << 2.
```

Shifts only rewire bits; three additions/subtractions implement the product.
Discarding high bits is exact for the modulo rule. The implementation folds
public constants and identical/complementary wire references. These are
offchain Boolean-circuit operations, not Bitcoin opcodes or changes to the
repository's Script compilation policy.

Garbling uses the existing free-XOR/four-row-AND implementation and its stated
BLAKE3 PRF/correlation assumptions. All seeds and scalars in this reproducible
program are public deterministic fixtures. In an unopened production garbling,
the corresponding private state must stay secret. This experiment supplies no
new end-to-end security level or public algebraic check of the ciphertexts.

## Measurements

Apple M5 Pro, 15 logical CPUs, 24 GiB RAM, macOS 26.6.1 arm64; Rust release,
five samples. Fifteen workers process independent pools; the global decoder
is generated and evaluated serially. Every sample regenerates the field
inverse table, all points, labels, coefficients, ciphertexts, garblings and
private inter-circuit wiring. Allocations and worker startup are inside the
timers. There is no reused table cache.

| Quantity | Result |
|---|---:|
| Independent target points | 5,750 |
| Scalar-opening occurrences | 460 |
| Encrypted complement shares | 281,750 |
| Membership / rank-and-validity input labels | 5,750 / 2,185 |
| Message / global-validity output labels | 2,048 / 1 |
| New mixed-radix AND / XOR gates | 472,482 / 1,764,286 |
| New mixed-radix cryptographic payload | 30,370,000 bytes |
| Existing per-pool garbling payload | 35,712,560 bytes |
| Encrypted-share payload | 4,508,000 bytes |
| Input-label commitments / target points | 368,000 / 189,750 bytes |
| Combined listed public payload | 71,148,310 bytes |

Garbling payload counts four 16-byte ciphertexts per AND gate, published
constant labels and both output-label hashes. Fixed topology, host object
overhead, private generator state and file-format framing are excluded from
the payload byte metric. Unlimited offchain storage remains the assumption.

| Timing, complete 115-pool instance | Median | Minimum–maximum |
|---|---:|---:|
| Translation, rank garblings and private wiring generation | 51.68 ms | 49.93–92.71 ms |
| Mixed-radix garbling generation | 287.34 ms | 270.08–304.42 ms |
| Complete generation | **341.82 ms** | 325.72–397.13 ms |
| Translation and rank audit with all secrets | 36.36 ms | 34.06–36.97 ms |
| Mixed-radix audit with all secrets | 312.30 ms | 301.01–336.13 ms |
| Complete audit with all secrets | **348.66 ms** | 337.43–373.11 ms |
| Generation plus that audit | **701.05 ms** | 666.92–734.56 ms |
| Scalar-to-rank evaluation | 71.43 ms | 70.55–74.11 ms |
| Mixed-radix evaluation | 61.79 ms | 61.58–63.88 ms |

Medians are calculated independently; component medians need not sum to the
median total. The first combined sample takes 690.48 ms. Evaluation is not
setup. The audit rebuilds and compares all ciphertexts and garbled tables
using the generator's complete secrets. **Public setup verification is absent,
recorded as null.**

This boundary covers one translation and message-decoder instance. It excludes
the BitVM3 verification circuit, additional garbling copies/VSS, public
malicious-setup checks, native script and transaction construction, process
startup, compilation, serialization to disk and network transfer. Point
generation overlaps older point-lock setup measurements, so adding their
timings mechanically would double-count work. The old 72.64-ms complement
benchmark retains its old, narrower boundary and source hashes.

## Validation and native boundary

The composed run reads the previously Core-validated
[`anchored_publication_core_check.json`](anchored_publication_core_check.json),
checks all 460 recorded target points and scalar openings, decrypts the actual
retained complement ciphertexts, and evaluates all the garbled stages. The
final 256 bytes equal the cached native fixture's payload. The JSON pins the
native report, all changed Rust sources, runner, executable and Cargo.lock
with SHA256. At that measurement, the two older implementation bodies were
unchanged except for child-module declarations, checked against their
historical source hashes. The later 95-pool adaptation raises the shared
membership guard from 50 to 54 and adds a mixed-radix specialization. Its
[legacy regression](round-major-decoder-legacy-regression.json) reproduces
the older circuit fingerprint and all recorded non-timing results. The
historical body comparison explicitly normalizes the membership guard change.

Focused tests cover:

- All 512 reduced rank encodings for radices 6, 10 and 3, including 180 valid
  codewords, modulo wraparound, each false pool-validity flag and a corrupted
  output label.
- Twenty-five boundary pairs for the optimized radix-230,300 multiplication,
  compared with independent integer arithmetic modulo 2^19.
- All eight represented digits for power-of-two radices 2 and 4.
- The existing reduced membership test: all 256 membership inputs, including
  all 70 exact-weight-four subsets.

The full-width run additionally evaluates codewords 0, 2^2048-1, 2^2048,
2^2048+1 and B^115-1, checks their exact modulo outputs, and rejects a rank
equal to B, a false pool-validity flag and a corrupted input label. These
boundary inputs are selected using garbler-held label pairs; they are not
additional native spending transactions.

There is no new Bitcoin execution in this experiment. Incremental onchain
script bytes, witness bytes, opcodes, hint items and stack items are all zero.
For this offchain computation itself, Script size, witness serialization,
validation budget and Bitcoin stack peak are not applicable. The cached
96,176-vB anchored fixture still has four index hints, 33 entry data items and
34 complete witness items per pool input, with all four hints present at
entry. Across 115 independent inputs that is 460 hints and 3,795 entry items;
the stacks do not coexist. Its independent combined main-plus-alt-stack trace
peaks at 85 items per input. This experiment does not use the repository's
tapscript/unlimited-stack helper or strengthen the fixture's native claims.

Evidence: **locally-reproduced** for the composed decoder, tests and timings;
**inspected** for the arithmetic coverage argument. Deployment:
**unclassified** for the composed protocol. The cached transaction retains its
separate **policy-validated** classification.

## Remaining acceptance criteria

The unresolved parts are all-consensus point-lock extraction, public binding
of ciphertexts and garblings against malicious setup, one-opening privacy in
the complete protocol, compulsory pool participation, challenge-graph
integration and the full verifier/copy setup cost. The modulo circuit removes
the missing total-decoding rule from that list only under the stated complete,
valid-opening and correct-garbling conditions. It is not a sub-100,000-vB
construction satisfying the complete goal.

```sh
cargo test --release --locked --example pointlock_membership_decoder
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/total_message_decoder_benchmark.py
```
