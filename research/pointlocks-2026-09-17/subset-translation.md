# Subset openings to binary garbled input labels

Question: can the 115-pool, four-of-50 anchored candidate translate its recovered
scalars into actual binary input labels without hiding expensive table setup?
The comparison objective is full-instance generation plus checking, with
unrestricted offchain memory and the user's 100 ms / outer 1–2 s time targets.

The executable translation now works on the selected scalars in the existing
Core report. Its optimized table generation plus **opened-table** audit takes
1.590 s median on the recorded host. This is a conditional translation
component, not public setup verification and not a solution to the active goal.
General point-lock extraction, malicious garbling setup, full verifier
integration and protocol participation remain open. The later
[total decoder](total-message-decoder.md) supplies garbled message decoding
for the complement-based translation, with a separate timing boundary.

A [threshold-complement alternative](complement-translation.md) avoids one
ciphertext row per subset. It delivers membership labels through encrypted
shares with an omitted diagonal, then actually evaluates garbled per-pool rank
decoders. Its 72.64-ms generation/opened-audit measurement supersedes the need
for this large table under honest setup, but does not supply public setup
verification or full verifier integration. The historical measurements below
remain unchanged.

## Construction and exact boundary

For each pool, use the same 50 scalar/point pairs as the anchored native fixture.
There are C(50,4)=230,300 lexicographically ordered four-element subsets. A subset
S has rank r, represented by 18 bits. Each output bit has two 16-byte labels,
with independent zero labels and one common secret free-XOR offset Delta.
No zero labels or Delta are published.

Derive a 32-byte row key from a domain separator, pool identifier, the four
ordered indices and their four complete 32-byte scalars. Encrypt the 18 chosen
binary labels by XOR with a domain-separated keyed BLAKE3 XOF. This uses BLAKE3
1.8.7 as pinned by Cargo.lock. Scalars, labels and Delta in the executable are
deterministic public fixtures, not production secrets.

Two authentication variants are implemented:

- **Row MAC:** append a 16-byte domain-separated keyed MAC of the ciphertext.
  This authenticates a row to somebody who knows its scalar-derived key, but
  does not certify that its plaintext contains the intended labels.
- **Public label hashes:** publish the 256-bit BLAKE3 hash of each of the two
  labels per wire; omit row MACs. After decryption, check every plaintext label
  against the hash for the expected rank bit. This catches wrong plaintext at
  opening time. It still does not verify unopened ciphertext during setup.

The implementation caches hash states for shared one-, two- and three-candidate
prefixes. An exhaustive test checks all 230,300 derived row keys against
independently hashing each complete tuple. Whole-table digests also match the
earlier uncached implementation for all 115 pools. Caching changes neither the
encryption keys nor ciphertexts.

For correctly generated tables and independently hidden candidate scalars,
an opening of exactly four distinct candidates identifies one decryptable row.
Every other four-subset contains an unopened candidate. The intended privacy
argument models the tuple KDF/pad as random-oracle/PRF operations and relies on
the unexposed scalar's hardness given its secp256k1 point. This is a conditional
argument, not a reduction for the unresolved ECDSA lock or malicious tables.
The labels have 128-bit entropy, with multi-target losses to account for;
public label hashes do not justify a blanket 128-bit end-to-end claim. The
anchored candidate's separate HASH160 binding ceiling still applies.

## Measurements

[Implementation](../../examples/pointlock_subset_translation_probe.rs),
[benchmark runner](subset_translation_benchmark.py),
[summary with provenance](subset-translation-summary.json),
[MAC samples](subset-translation-benchmark.json), and
[label-hash samples](subset-translation-label-hash-benchmark.json).

Apple M5 Pro, 15 logical CPUs, macOS 26.6.1 arm64, Rust release profile,
15 workers, three full-instance samples per variant. Hardware identity comes
from the same-host point-lock benchmark; OS and CPU count are rechecked.
Every sample regenerates all scalar/point and binary-label fixtures, allocates
and writes all tables, retains them together in RAM, and reconstructs and
compares every row. All worker startup and allocations are inside timers.

| Metric | Row MAC | Public label hashes |
|---|---:|---:|
| Rows, all 115 pools | 26,484,500 | 26,484,500 |
| Ciphertext bytes per row | 304 | 288 |
| Total ciphertext bytes | 8,051,288,000 | 7,627,536,000 |
| Additional label-hash bytes | 0 | 132,480 |
| Scalar/point/label preparation, median | 10.73 ms | 10.62 ms |
| Table generation, median | 1,382.84 ms | 794.81 ms |
| Opened-table audit, median | 1,368.77 ms | 784.15 ms |
| Preparation + generation + audit, median | 2,762.33 ms | **1,589.58 ms** |
| Combined minimum–maximum | 2,724.26–3,584.12 ms | 1,585.22–1,656.14 ms |

The final label-hash samples run after the MAC samples in the same runner.
They are not cold-host latency measurements. The optimized table remains
roughly 7.63 decimal GB; no table bytes are omitted or replaced by estimates.
The whole-table digest for reproducibility is outside the timers. Disk writes,
network transfer, process startup, executable compilation, point-lock scripts
and public script checks, VSS, garbling and its public verification are excluded.
An opened-table audit needs every candidate scalar and both output labels; it
cannot be presented as the requested public setup check.

The benchmark covers **one set of binary inputs for one garbled computation**.
It does not silently supply many cut-and-choose copies for the same price.
Independent copies of this explicit representation multiply its ciphertext
storage by the number of copies. Sharing rows/labels across copies needs an
argument that opened copies do not reveal unopened copies' inputs.

## Connection to the existing native transcript

The runner reads the 460 extracted scalars in
`anchored_publication_core_check.json`, checks their 460 target points, opens
the corresponding retained rows and matches all **2,070 binary input labels**
to their intended rank bits. Combining the 115 rank digits reconstructs the
report's exact 256-byte message. The report hash is recorded in the summary.
This connects to a previously Core-accepted 96,176-vB honest publication.
No new Core run or actual full garbled-verifier evaluation is claimed.

The subsequent [direct-key six-context fixture](direct-context.md) has its
own Core validation at 98,706 vB. Its setup runner verifies exact equality of
all 5,750 target points and the complete 460 selected extraction records with
this translation's original fixture. Thus the same table interface applies;
this does not add a public translation check or a garbled-verifier evaluation.

The 2,070 wires represent 115 eighteen-bit radix digits, not 2,070 independent
message bits. The later [total decoder](total-message-decoder.md) implements
base-230,300 decoding modulo 2^2048 using the complement bridge's rank and
validity labels, including all surplus codewords. It does not enforce the
mandatory input set onchain. This historical explicit-row experiment still
reconstructs the integer in ordinary offchain code.

This component adds zero onchain script bytes, witness bytes, opcodes, hint
items or stack items to that fixture. The native inputs retain four hints,
33 entry data items and 34 complete witness items per pool; all four hints
coexist at entry. There are 460 hints across independent inputs. The existing
independent bytecode height trace peaks at 85 items per input, not a combined
multi-input stack. The translation uses ordinary offchain memory and does
not run under the repository's tapscript/unlimited-stack helper.

Evidence: **locally-reproduced** for translation, exact byte counts, benchmarks,
tests and linkage to cached extraction records; **inspected** for the conditional
privacy argument. Deployment: **unclassified** for the translation/protocol.
The earlier native transactions retain their separate **policy-validated**
classification; it does not transfer to the complete proposed protocol.

## Why the missing setup check is substantive

The focused test `public_points_cannot_certify_row_plaintext` preserves all
public candidate points while changing one encrypted output label. The row MAC
still verifies and the scalar openings are correct, yet the wrong verifier
label emerges. In the label-hash variant, the points and all advertised label
hashes remain fixed; decryption then rejects the malicious row. Detecting the
failure after an accepted publication is not the required guarantee of usable
labels. A setup proof/check must bind the encrypted rows to the intended
verifier labels before the protocol relies on them.

This is a counterexample to treating ordinary point validation as translation
validation, not an impossibility theorem for algebraic translation or for
cut-and-choose composition. The referenced
[Glock design](https://hackmd.io/@alpen/B1QfSSO5gg) explicitly has polynomial
share validation, opened garblings and a wide-label translation stage; omitting
those parts would change its boundary. No noninteractive replacement for the
needed setup checks is implemented here.

A tempting shortcut is also invalid: publishing every zero input label and
letting scalar openings release selected one labels in a free-XOR circuit.
Because L_i^1=L_i^0 XOR Delta, one such opening reveals Delta and all other
one labels. The small [reproduction](subset_public_zero_counterexample.py)
recovers 50 one labels from 50 public zero labels and one released one label.
This uses the common-offset relation of
[Kolesnikov–Schneider, ICALP 2008, section 3](https://encrypto.de/papers/KS08XOR.pdf).
It does not rule out other independent-label or monotone constructions.

The next useful comparison is a translation whose correctness follows from
public algebraic checks, or a complete noninteractive garbling-check protocol
with all copy/VSS/translation costs included. Faster row encryption alone
does not establish either property.

```sh
cargo test --release --locked --example pointlock_subset_translation_probe
python3 research/pointlocks-2026-09-17/subset_translation_benchmark.py
python3 research/pointlocks-2026-09-17/subset_public_zero_counterexample.py
```
