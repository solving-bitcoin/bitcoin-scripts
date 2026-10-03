# CRC-8 nibble feedback: initial experiment

Question: can a sixteen-entry feedback table plus the existing triangular
nibble XOR table beat a serial bit-register schedule for CRC-8 polynomial
`x^8+x^2+x+1` while retaining hostile-input checks, zero hints, and bounded
combined stack usage? Recurrent fixed-distance patterns in a fresh private
seed motivated a feedback experiment. Atlas/source/negative-result searches
found no recorded CRC-8 primitive; that is a coverage gap, not a novelty claim.

Use initial CRC zero, MSB-first nibbles (high nibble before low nibble of each
byte), no final reflection or xor. The first logical nibble is at the top of
the witness. Every numeric input is checked in 0..=15, at most four bytes;
numeric aliases are allowed by the local Consensus profile. Output is one
canonical numeric byte, not an eight-bit raw byte string. All N ordinary
message items coexist at entry; **zero hint items and zero hint bytes**.
CRC-8 provides no cryptographic authentication or collision resistance claim.
The caller binds message provenance, byte pairing and the expected checksum.

Hypothesis: four-bit feedback reduces code growth but its 184 resident table
items restrict all-entry message length compared with eight live CRC bits.
State `(H,L)` updates through `T(H xor d)`, where `T(i)` is the remainder of
`i*x^8` modulo the polynomial. New high nibble is `L xor high(T)` and low is
`low(T)`. Tables include sixteen paired high/low entries, the existing
136-item triangular XOR table and sixteen existing lookup offsets. The serial
baseline keeps eight bits and feeds each input bit through a linear register.
Both include numeric guards, all setup/cleanup and canonical byte packing;
leaf variants additionally compare the exact checksum and return TRUE.
Witness bytes serialize the complete item vector and prefixes, excluding
leaf/control block/annex/transaction framing. Actual compilation uses the
repository ALL<=32KiB / NONE-above policy, including each final checked leaf.

Primary polynomial/order reference: SMBus Specification v3.1, 2018-03-19,
section 6.4.1.3 (p.37),
<https://smbus.org/specs/SMBus_3_1_20180319.pdf>, PDF SHA256
`ae22a791184fdd649c3101f70c3ce238c35b08c7f5b736458e740b903d1bf386`.
Algorithm context: Linux v6.18 commit
`7d0a66e4bb9081d75c82ec4957c50034cb0ea449`,
<https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/lib/crc/crc8.c>.
The generic Linux routine permits a caller-selected initial state; its header
default/complement conventions are not substituted for this experiment's
explicit zero initialization/no-xor profile. No Linux source is copied or
executed. The host oracle computes exact polynomial remainders independently.

Threat model: hostile nibble values/encodings, every live input position,
wrong order, short inputs, caller stack corruption, transient combined depth
and terminal-check bypass. The initial private probe exhausts 4,096 state/
nibble transitions and 65,536 two-byte messages for each family, numeric
aliases, typed malformed/short inputs, deliberately bypassed compiled guards
with valid controls caught by the same typed assertion, and both caller-stack
frontiers. Qualification must later extend the shared contracts to strict
canonical siblings, output/ordering mutations, policy controls and composition.

Execution is locally-reproduced/unclassified only after the actual probe
passes. The local Consensus tapscript profile has numeric minimality off,
MINIMALIF and combined stack checks on, OP_CAT off, CLTV/CSV checks on,
synthetic empty transaction, data-only budget and no signatures. Static
non-push counts are separate from unavailable executed counts and complete
transaction-budget evidence. Production source remains unchanged during this
initial experiment; no catalog or deployment promotion is made yet.

## Initial locally reproduced observations

Both schedules pass every one of the 4,096 CRC-state/nibble transitions and
65,536 two-byte messages: 139,264 executions before the additional fixtures,
hostile inputs and caller frontiers. An independent Python bitwise recurrence
checks both output-stream digests against the Rust polynomial-division oracle,
all 32 scalar rows, witness/output serialization and locked Cargo identities.
The explicitly zero-initialized ASCII `123456789` fixture produces 244 (`f4`).
No Linux execution or Bitcoin Core comparison is claimed.

| Input | Feedback fragment / exact-CRC leaf | Serial fragment / leaf | Feedback / serial peak | Serialized fixture witness |
| --- | ---: | ---: | ---: | ---: |
| 1 nibble, experimental half-byte | 361 / 364 | 157 / 160 | 189 / 14 | 3 |
| 1 byte | 414 / 419 | 285 / 290 | 190 / 15 | 5 |
| 2 bytes | 520 / 524 | 541 / 545 | 192 / 17 | 9 |
| 9 bytes, ASCII fixture | 1,262 / 1,267 | 2,333 / 2,338 | 206 / 31 | 37 |
| 16 bytes | 2,004 / 2,009 | 4,125 / 4,130 | 220 / 45 | 63 |
| 64 bytes | 7,092 / 7,097 | 16,413 / 16,418 | 316 / 141 | 249 |
| 128 bytes | 13,876 / 13,881 | 33,565 / 33,570 | 444 / 269 | 499 |

All rows use ALL except the 128-byte serial fragment/leaf, explicitly
unoptimized NONE. Every byte uses two ordinary numeric nibble items, zero hints,
all at entry. The standalone empty case consumes no data, produces numeric zero
in one fragment byte and has a one-byte exact-check TRUE leaf after ALL; it does
not provide a true bare checksum predicate. Tables, validation, state and cleanup
are included equally in fragment costs, while leaf costs add the exact result
predicate. Small messages retain the table's startup loss.

At nonempty all-entry boundaries, the measured combined peaks are N+188 for
feedback and N+13 for serial, including future inputs and any existing caller
main/alt items. Feedback accepts 812 nibbles at peak 1,000 and rejects 813 at
1,001; serial accepts 987 at 1,000 and rejects 988 at 1,001. The odd 987-nibble
case is an experimental half-byte stream, not a complete SMBus message. Complete
byte-paired maxima are therefore 406 bytes for feedback and 493 for serial, the
latter with one remaining caller item. Feedback's accepted checked leaf is
43,349 bytes and serial's is 129,330, both explicitly unoptimized NONE. Fixture
witnesses are 1,576/1,916 bytes; maximum numeric-alias witnesses are 4,063/4,938.
Every hint count is zero. The 32-nibble caller tests observe every preserved
opaque byte at exactly 1,000 with zero or three alt items, and an extra item fails
with StackSize. These local fragment outcomes do not establish deployability.

The same typed Verify assertions detect deliberate compiled range-guard bypasses
at all four input positions after clean valid controls and clean mutant controls.
The hostile value 16 aliases a valid table query when validation is removed; the
serial decomposition clips it to 15. Aliases/negative zero pass the documented
numeric profile. Every position rejects negative/above-range inputs as Verify,
5..520-byte values as ScriptIntNumericOverflow, and 521-byte items as PushSize;
all short prefixes fail InvalidStackOperation.

A construction-time error in the private serial reference left an extra copy of
the feedback bit at each step. The retained original-step mutation reproduces
five zero output items for one zero nibble, while the corrected reference leaves
one canonical zero. The **same exact-output assertion** catches the original
step after the corrected control passes. This is a private reference regression,
not a defect or fix in existing production source. Its artifact records the
actual compiled hash, error, output digest and resource statistics. Expected
caught assertion panics appear in probe stderr; the complete probe exits zero.

Initial tested source: `0db90b9450d96a0bdf292d633fff14036bac2745`. Reproduce after source pin:

```sh
CARGO_PROFILE_DEV_OPT_LEVEL=1 cargo run --locked --example crc8_probe -- 0db90b9450d96a0bdf292d633fff14036bac2745 > /tmp/crc8-probe.json
cmp research/crc8-nibble-feedback/initial-probe.json /tmp/crc8-probe.json
python3 research/crc8-nibble-feedback/verify_probe.py
```

Debug assertions and overflow checks stay enabled. Public API design, canonical
sibling contracts, asymmetric ordering and terminal mutations, partial Policy
controls, composition, named metrics, full non-field checks and KB promotion
remain before any primitive PR. The original reproduction will be preserved.

## Qualified complete-byte primitive

The original probe, artifact and oracle above remain unchanged. The public
[`arithmetic::checksums::crc8::crc8_smbus_nibbles`](../../src/arithmetic/checksums/crc8/README.md)
uses a complete-byte count in 0..=406, zero initial state, no reflection/xor,
checked numeric nibble input, canonical numeric CRC and zero hints. Existing
helper APIs and the full base catalog are retained. Policy-produced bytecode
matches the frozen schedule at empty, small, cutoff and maximum sizes.

Integrated source revision: `1231ed087025ab136fcfe7c1f904bf898b328b48`.
[metrics.json](metrics.json) binds 136 scalar rows, four exact alias contracts
and 24 preloaded repeated configurations to final script/Tapleaf hashes,
raw sizes, separate whole-policy options, inputs/witnesses/outputs, compiler/
interpreter identities and explicit execution options. All classification is
locally-reproduced/unclassified; local Policy is only a documented subset.
Unknown executed counts and complete transaction budgets remain null.

Four exact generators are shared by measurements and the contract suite:
public numeric feedback, numeric serial register, and their canonical-input
compositions using the existing `verify_canonical_nibble`. Exhaustive two-byte
messages, long deterministic inputs, aliases, every malformed live position,
every short prefix, asymmetric ordering and every independent output are checked.
The same typed assertions catch actual compiled range/canonicality/terminal
bypasses after unchanged valid controls; the same exact-result assertion catches
ordering mutations. The retained original-step regression proves the private
serial-reference fix against its original counterexample.

Caller state is supplied as runtime opaque witness bytes, staged to the altstack
before the fragment and compared after it. This prevents compile-time constant
folding from removing the preserved state in the empty-message case. Every
caller byte is observed at exactly 1,000; one extra fails StackSize at 1,001.
The selected alt count is capped by available caller slots: the 406-byte maximum
has none, and R=45 nine-byte messages have two. Smaller configurations exercise
three alt items plus enough main caller items to reach the same boundary.

Repeated messages contain every future input and parked output. Numeric feedback
at R=2/8/25/26/45 has 36/144/450/468/810 ordinary data items, zero incremental
and total hints, and peaks 224/332/638/656/998. Witnesses serialize to
71/280/875/910/1,573 fixture bytes, and attained four-byte-alias maxima are
181/721/2,253/2,343/4,053. R=46's 828 data / zero hints fail at measured 1,001.
The component sum includes output park/restore; its whole-policy delta includes
any ALL-to-NONE transition. R=25 has fragment/leaf 31,550/31,638 with ALL;
R=26 has 32,890/32,982, both explicitly unoptimized NONE. R=45 is
56,925/57,083, also unoptimized NONE. Canonical/serial siblings have separately
measured bytes, aliases, cutoffs and resource outcomes.

Numeric witness maxima are attained by four-byte aliases of the exact fixture,
so the bound CRC remains unchanged. Canonical domain encoding caps are recorded
separately; their exact maximum under a fixed checksum is unknown and stays
null. Source artifacts and catalog rows do not silently upgrade siblings.

Reproduce:

```sh
CARGO_PROFILE_DEV_OPT_LEVEL=1 cargo run --locked --example crc8_metrics -- 1231ed087025ab136fcfe7c1f904bf898b328b48 > /tmp/crc8-metrics.json
cmp research/crc8-nibble-feedback/metrics.json /tmp/crc8-metrics.json
python3 research/crc8-nibble-feedback/verify_metrics.py
python3 research/crc8-nibble-feedback/verify_probe.py
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test crc8_contract
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test primitive_metrics crc8_smbus_metrics_are_current
python3 tools/kb.py validate
cargo fmt --all -- --check
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked -- --skip fields::
```

The artifact test regenerates the full report with those same generators,
checks every catalog configuration, and compares immutable source bytes. A
shallow CI checkout must prove that it is shallow if the source commit is
unavailable; current source hashes and complete artifact recomputation still
apply. Debug assertions and overflow checks stay enabled. The primitive is
error detection, not cryptographic authentication or a deployment claim.
[NR-081](../../knowledge/negative-results/crc8-nibble-feedback.md) and
[OP-039](../../knowledge/open-problems.md#op-039--streamed-crc-8-frontier) record
startup, stack, repeated-setup and wider-byte limitations.
