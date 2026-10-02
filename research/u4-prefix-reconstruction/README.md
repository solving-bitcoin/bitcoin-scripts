# Canonical modulo-16 prefix scan and inverse delta boundary

Research question: can a hostile canonical nibble vector be transformed into
all of its modulo-16 prefix sums in original order while preserving both caller
stacks, without a table or hints? The objective is lower live stack occupancy
for a sequence adapter that can reconstruct forward deltas when their initial
value is retained. Catalog, comparison, negative-result and source searches
found scalar sum and forward delta but no standalone recorded prefix scan;
this is a repository coverage result, with no global novelty claim.

Hypothesis: park runtime inputs on the altstack, pop them in original order,
retain every output with `OP_OVER OP_ADD`, and conditionally subtract 16 from a
sum in 0..30. This yields `n+3+preserved_items <= 1000` for n=1..997. Inputs are
canonical ScriptNums in 0..15; caller alt state is preserved; outputs remain
live and need terminal predicates. Every input is hostile. Initial value is
ordinary data and must be bound separately in an authenticated reconstruction.
There are zero hints per invocation and for every measured batch/composition;
all n ordinary data items coexist at entry.

## Comparable experiment

[Public scan](../../src/arithmetic/u4/prefix_sum.rs) versus the research-only
[31-entry table](baseline.rs), with the same canonical n-input/n-output
boundary. The table includes setup, deeper query indices under retained
prefixes, cleanup and ordered restoration. Both include input staging and
canonical/range checks, and exclude input pushes and terminal predicates.
The complete leaves compare every prefix against `(7*i)%16` in reverse with
`OP_EQUALVERIFY`, then `OP_TRUE`. Witness measurements serialize n canonical
sevens as the complete data-only vector, excluding the leaf/control block.
Combined main-plus-alt peak is measured on that exact runtime leaf.

| n | Conditional fragment / leaf / peak | Table fragment / leaf / peak | Data-only witness bytes |
| ---: | ---: | ---: | ---: |
| 1 | 10 / 13 / 4 | 10 / 13 / 4 | 3 |
| 2 | 31 / 36 / 5 | 79 / 84 / 36 | 5 |
| 32 | 661 / 726 / 35 | 664 / 729 / 66 | 65 |
| 128 | 2677 / 2934 / 131 | 2584 / 2841 / 162 | 257 |
| 966 | 20275 / 22208 / 969 | 20182 / 22115 / 1000 | 1935 |
| 997 | 20926 / 22921 / 1000 | unsupported | 1997 |

The table peak is n+34 for n>=2, otherwise n+3; its maximum is 966. It saves 93
bytes at n128/966 while needing 31 more items. This Pareto tradeoff is
[NR-075](../../knowledge/negative-results/u4-prefix-table-tradeoff.md).
Neither construction is a universal byte winner. Dynamic executed counts and
validation weight are unavailable; static non-push counts are serialized counts
only. Script hashes, witness hashes and exact counts are in [metrics.json](metrics.json).

## Inverse composition is a separate boundary

The existing forward encoder discards x[0] and accepts numeric encoding aliases.
The [roundtrip](baseline.rs) canonical-checks every original item, retains x[0],
encodes the n-1 deltas, routes x[0] below them, then performs the prefix scan.
The leaf compares every reconstructed item to the original vector through clean
truth. At n32, `x[i]=(7*i+floor(i/3))%16`, the integrated fragment is 1994 bytes,
leaf 2059, witness 62, with 32 data items, zero hints and a 66-item combined peak;
there are 1372 static non-push opcodes. This includes original canonical checks,
retention, encoder and routing; do not price it as the sum of isolated fragment
metrics. Exact runtime caller-state tests accept 66+934 items and reject one
extra. This arithmetic round trip does not authenticate initial state or deltas.

## Evidence, provenance and reproduction

All configurations are `locally-reproduced` / `unclassified`. Cost runs use
`execute_raw_script_with_inputs_strict`: local tapscript, stack checks enabled,
`Options::default`, synthetic empty transaction and data-only budget, no
signatures. Contract tests additionally use `TapscriptProfile::Consensus`
(minimal numeric policy disabled, CAT disabled, stack/minimal-IF checks enabled).
This is not Bitcoin Core consensus or complete relay policy validation.

Base: `bf9ee0bb34987a9130ad9dc13a06e18fef137296`. Compiler/interpreter Git
sources are obtained from the producer's embedded lockfile, respectively
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180` and
`a09e87af444034698697f0a2267e755cf72f9aed`. All measured fragments and leaves
are below the 32KiB raw cutoff and compile via centralized `CompileOptions::ALL`.
The artifact contract reconstructs every report row, hashes, serialized witness,
static counts, outputs, peaks and dependency pins. The measured implementation revision is `c1700d3c175dafab2cf8c990d2f2e0db565b5cd7`. Catalog parameters
pin that source tree; a documentation-only follow-up records this identity.
The delivered PR head identifies the exact integrated tree validated before
submission.

```sh
CARGO_PROFILE_DEV_OPT_LEVEL=1 cargo run --locked --example u4_prefix_reconstruction_probe > /tmp/u4-prefix-reproduced.json
cmp research/u4-prefix-reconstruction/metrics.json /tmp/u4-prefix-reproduced.json
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test u4_prefix_contract
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test primitive_metrics u4_prefix_sum_metrics_are_current
python3 tools/kb.py validate
python3 -m unittest discover -s tools -p 'test_*.py'
cargo fmt --all -- --check
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked -- --skip fields::
```

Host optimization retains debug assertions/overflow checking and does not alter
Script compilation policy. Shared contracts cover exhaustive n1/2/3 scan
vectors, deterministic longer vectors, typed every-position malformed/range/
canonical errors, accepted delta aliases with exact meaning, short input,
asymmetric ordering, runtime preserved stacks and exact resource frontiers.
Deliberate mutations remove actual compiled range/canonical checks and make the
same typed rejection assertion fail, with valid cleanup controls. A terminal
mutation drops all outputs, proving the output-binding rejection assertion
also detects its removal. No production bug fix or sibling semantic change is
claimed. Complete Core/policy transaction evidence remains
[OP-033](../../knowledge/open-problems.md#op-033--complete-prefix-scan-oracle).
