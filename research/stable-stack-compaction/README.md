# Stable stack compaction: reproducible local experiment

Question: can runtime binary selectors compact opaque payloads into a stable
subsequence and exact count with fewer routing bytes and live items than forward
selection followed by reversal? The private seed's repeated pair motifs suggested
payload/selector pairs. Catalog/source searches found no recorded arbitrary-item
stable filter; this is coverage, not global novelty. Stable filtering is known.

Hypothesis: consuming pairs backward stages selected items in reverse order on
altstack, so count-bounded restoration produces original order directly. Compare
native MINIMALIF schedules with each other, and explicitly guarded schedules
separately, under identical witness and terminal boundaries. Every witness item
is hostile; do not authenticate selector meaning or certify opaque data. Hard
constraints: 520-byte elements, 1,000 combined items including caller state,
central compilation policy and observable output checks.

## Immutable provenance and reproduction

Tested source revision: `666643cf20198f4e831e66f705a7192a216b33b2`.
Integration base: `bf9ee0bb34987a9130ad9dc13a06e18fef137296`.
The source revision pins the generator, comparison families, shared contract
suite, report producer, lockfile and compilation/execution helpers. The report
also records SHA256 for each relevant file. The subsequent documentation pin
commit changes only this revision text, report revision metadata and catalog
revision metadata. The complete delivered tree is tested after that pin.

Compiler: `rust-bitcoin-script` at
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`.
Interpreter: repaired `rust-bitcoin-scriptexec` at
`a09e87af444034698697f0a2267e755cf72f9aed`.
Exact Cargo source strings are recorded in [metrics.json](metrics.json), from
`support::provenance` and the embedded lockfile.

```sh
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test selection_contract
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test primitive_metrics stable_selection_metrics_are_current
python3 tools/kb.py validate
cargo fmt --all -- --check
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked -- --skip fields::
CARGO_PROFILE_DEV_OPT_LEVEL=1 cargo run --locked --example stable_stack_compaction_probe -- 666643cf20198f4e831e66f705a7192a216b33b2 > /tmp/stable-selection-reproduced.json
cmp research/stable-stack-compaction/metrics.json /tmp/stable-selection-reproduced.json
```

Optimized host test/dev profiles accelerate the experiment while retaining debug
assertions and overflow checks. They do not alter Script compilation policy.
No random execution inputs are used: masks, payloads and sparse patterns are
deterministic. Field arithmetic is excluded from broad runs as instructed.

## Exact measurement boundary

The report has 110 rows across backward native (public), forward native,
backward explicit and forward explicit schedules. It includes n=0/1/2/32/128
and resource frontiers; every sampled public pair count also has payload sizes 1, 80,
520, with all-drop and all-keep flags. Payload bytes are `42` repeated; flags
are exactly empty or `01`. Witness consists of `2n` ordinary data items, all
at entry, including discarded payloads. Hint items and serialized hint bytes
are exactly zero in every configuration. Item count and CompactSize lengths
are included; script/control block/annex and transaction are excluded.

Each fragment includes count initialization, flag validation under native
MINIMALIF or explicit numeric guards, selection, discard cleanup, altstack
staging and stable restoration. It excludes input pushes and terminal checks.
Each leaf checks canonical count followed by every retained raw payload, then
leaves TRUE. Reported script bytes/hash use the final policy-produced artifact;
raw bytes and options are recorded independently for fragment and leaf. ALL
applies through 32 KiB raw; NONE above that is explicitly unoptimized.

Execution is the explicit local `TapscriptProfile::Consensus`: numeric
minimality off, native MINIMALIF on, CLTV/CSV checks on, stack limit on,
experimental OP_CAT off, synthetic empty transaction and data-only budget.
Both main and alt stacks contribute to peak. No signatures execute; recorded
zero weight charged is not a complete transaction budget. Executed non-push
opcodes are unavailable: the interpreter's position counter includes pushes
and inactive instructions. Static non-push counts are separate.

Expected output is an independent host stable filter plus encoded count.
SHA256 commits to serialized Witness of the output vector, including lengths
and item count, avoiding ambiguous concatenation. Actual fragment output hash
and item count must match; leaf must be clean-success. Failed frontier rows
record typed StackSize and peak 1,001, without a correctness hash.

Catalog fragment `witness_bytes_max` covers arbitrary allowed payloads and
selectors at the same pair count. The all-retained literal-checking leaves
have a fixed successful witness, so their maximum equals that witness. Every
catalog configuration binds its row, boundary, source and compiler/interpreter
pins, final script hash, witness hash and execution options. Classification is
`locally-reproduced` / `unclassified` throughout; no complete Core/policy spend
is established by this experiment.

## Results and hostile contracts

At 32 all-retained one-byte pairs, reverse native is 496 fragment / 596 leaf
bytes, peak 65, versus matched forward 970/1,070/66. Both have 64 ordinary data
items, zero hints and 129 witness bytes. Explicit backward/forward schedules
cost 816/916/68 and 1,290/1,390/68; their guards are redundant to tapscript
MINIMALIF for this flag domain. Compare routing separately from validation.

At 499 pairs reverse/forward native fragments cost 8,339/18,800 bytes and peak
999/1,000; witness has 998 data items, zero hints and 1,999 bytes when retained.
Reverse permits exactly one caller item. Explicit guards permit 498 pairs
before reaching 1,000. The 500-pair native research baseline fails when it pushes
count above a 1,000-item entry. Empty public input peaks at 1; a single dropped
pair peaks at 3, retained at 4. Budget 4 when the flag is unknown.

A 499-pair 520-byte payload witness costs 261,978 bytes; fragment still costs
8,339 ALL, but the complete literal-checking leaf grows to 270,319 unoptimized
NONE. Its 80-byte counterpart is 50,260 NONE. Native local policy rejects
81/520-byte entry payloads even when discarded; 521 rejects consensus-profile
PushSize. Discard cleanup cannot rescue entry limits.

The shared suite covers all five families, including the existing four-limb
numeric word selector. It tests all masks through eight pairs, asymmetric
long/sparse vectors, empty/negative-zero/five-byte/520-byte raw payloads, every
hostile flag position, numeric aliases where allowed, short inputs, wrong
counts/outputs, stable-order mutations and preservation of both caller stacks
at exactly 1,000 and one beyond. Every preserved and returned item is observed
rather than optimized away by a constant cleanup.

Compiled flag-boundary normalization mutants preserve canonical valid controls
but accept malformed flags. The same typed rejection assertion catches them
with unchanged output cleanup. Count/payload binding bypasses likewise must
be detected by the same assertion. The word selector intentionally accepts
numeric truthy selectors and allowed aliases, rejecting numeric operands longer than four bytes; its production behavior is unchanged. Its documentation
clarifies the numeric boundary and lack of limb validation.

Primary semantic source: C++ draft [alg.copy], Eelis/draft
`c7015b485cc3db8efaa9dfb9ff0809c5394a4ed1`,
[source/algorithms.tex](https://github.com/Eelis/draft/blob/c7015b485cc3db8efaa9dfb9ff0809c5394a4ed1/source/algorithms.tex).
Its stable copy_if specification is semantic context only. Native exact flag
semantics come from BIP342 MINIMALIF; legacy truthy IF cannot inherit them.
See [the implementation README](../../src/support/selection/README.md),
[comparison](../../knowledge/comparisons/stack-selection.md),
[NR-078](../../knowledge/negative-results/stable-selection.md) and
[OP-036](../../knowledge/open-problems.md#op-036--stable-selection-protocol-composition).
