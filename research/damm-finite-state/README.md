# Damm finite-state checksum: initial experiment

Question: does keeping the fixed 100-entry Damm transition table resident across
runtime decimal digits beat a table-free balanced dispatch while preserving both
caller stacks and an exact bounded witness contract? The new private seed's
repeated-state and decimal motifs suggested a finite-state checksum. Catalog,
negative-result and source searches found no recorded Damm/decimal transducer;
this is a coverage gap, not novelty of the established Damm algorithm.

Hypothesis: a single table amortizes setup/cleanup after a small number of digits,
with a substantial entry-stack cost. Compare left-to-right resident lookup,
table-free balanced mapping and a first-row-specialized resident schedule using
the same numeric digit validation, stable input order and output check. Known
initial state is zero. No cryptographic security or deployment claim is made.

Inputs bottom-to-top: `digit0 ... digit[n-1]`. Every item is hostile and must be
an at-most-four-byte ScriptNum numerically in 0..=9. Numeric aliases are permitted
when the profile allows nonminimal numbers; this is distinct from native exact
binary selectors. Output is a canonical checksum digit. Both caller stacks
must be preserved. There are n ordinary data items and exactly zero hints per
invocation, all present at entry. Repeated preloaded groups share the entry
limit; no discarded or future inputs are free.

Source: CheckDigits.Net commit 734afa2d3596862ef4c3bb3ec404b512b96b8965:
https://github.com/KnowledgeForwardSolutions/CheckDigits.Net/tree/734afa2d3596862ef4c3bb3ec404b512b96b8965.
Exact upstream table, fold implementation and MIT license are preserved in
`reference/`. File SHA256:

- DammQuasigroupTable.cs: b5be157bdbc16daf91a1caf75911cc648ac108488a878909a8b1e22cd75ceaf2
- DammAlgorithm.cs: 626e5584a381c3a79d2d03f40e363d3769b830ecba0f6f7b02335b0cdb323135
- LICENSE.txt: 004a28c5066c23ebee0263565d9e66c1e40d0409d5042a9194334b41d7da132f

Its numeric fold starts at zero and performs table[state,digit] left to right.
The reference API rejects empty text and its validation wrapper requires at
least two characters; our research numeric empty-fold boundary returns zero,
so those API wrappers must not be conflated. The original 2004 dissertation
(DOI 10.17192/z2004.0516) could not be fetched because the current repository
returns an access-denied page; no exact thesis table or proof inspection is
claimed. The upstream repository is primary evidence for this implementation;
its statement of origin/error guarantees is reported until reproduced locally.

Hard constraints: central compilation policy, both-stack limit 1,000, 520-byte
entry elements, exact numeric range and observable output/caller state. Use the
explicit local Consensus tapscript profile (numeric minimality off, MINIMALIF
on, stack enforcement on, OP_CAT off, synthetic empty transaction, data-only
budget, no signatures). Local results remain locally-reproduced/unclassified;
no Core/policy class is inherited from other experiments. Static non-push counts
are separate; executed counts and complete transaction budget are unavailable.

Estimated resident peak is n+104 for positive n; dispatch should save the table
space. These are estimates pending policy-produced measurements. Probe script
bytes include table setup/cleanup, selection, input validation and output state;
exclude witness pushes and terminal checks. Leaf checks exact final digit then
returns TRUE. Witness serialization includes all n data items and prefixes,
excludes script/control block/annex/transaction. Promote only after shared typed
malformed-position/alias/mutation/order/caller-state/frontier contracts, immutable
artifact bindings, KB updates and the full required non-field test run.
Base bf9ee0bb34987a9130ad9dc13a06e18fef137296; reserve NR-079 / OP-037.

## Initial locally reproduced observations

At 32 digits with deterministic `(7*i+3)%10` numeric inputs:

| Schedule | Fragment / checked leaf bytes | Combined peak |
| --- | ---: | ---: |
| Resident 100-entry table | 766 / 769 | 136 |
| First-row dispatch warmup then resident table | 829 / 832 | 135 |
| First-row table then runtime ten-entry row tables | 5,652 / 5,655 | 42 |
| Table-free balanced dispatch | 27,809 / 27,812 | 35 |

All use ALL, the same 32 ordinary entry data items, exactly zero hints and
61 witness bytes (zero digits use empty ScriptNums). Resident setup amortizes
by two digits: 191 bytes/106 peak versus row-table 206/12. At one digit it
loses: 172/105 versus row-table 27/11 and table-free 81/4. These are measured
tradeoffs, not a universal best representation.

Resident reaches exactly 1,000 at 896 digits; warmup at 897; row-table at 990;
table-free at 997. The next digit rejects typed StackSize at first peak 1,001
in each schedule. Large row/table-free scripts use NONE above the cutoff:
990-digit row-table is 180,873 bytes unoptimized, versus 18,046 ALL for the
896-digit resident table. Do not compare unlike digit counts as a byte saving.
At the matched 128-digit boundary, resident is 2,686 bytes/232 peak versus
row-table 23,124/138 ALL and dispatch 113,731/131 explicitly unoptimized NONE.

The prototype passes 4,444 numeric vectors (all vectors through three digits
across four schedules), longer asymmetric vectors, malformed values at every
position with typed Verify/numeric-overflow/PushSize errors, allowed numeric
aliases and compiled guard-bypass mutations. Every bypass preserves valid
controls and makes the same typed Verify assertion fail, with unchanged cleanup
and a preserved zero caller item available to expose out-of-table picks. These
expected caught assertion panics appear in the standalone probe's stderr; its
process exits successfully when every mutation is detected.

The table's row/column permutations, zero diagonal and all 1,000 adjacent-pair
state relations are checked locally. An independent Python check reads the
exact preserved upstream table, verifies the Rust transcription, these
properties, each measured output and witness byte count. Original C# execution
has not been performed, and this does not claim Bitcoin Core validation.
Empty numeric folds remain distinct from the upstream string API.

Initial tested source: `75a22bdaa4ec03da1cb0c3b013f21226ff1e2fd2`. Source/dependency
pins and final artifact hashes are in `initial-probe.json`. Reproduce:

```sh
CARGO_PROFILE_DEV_OPT_LEVEL=1 cargo run --locked --example damm_finite_state_probe -- 75a22bdaa4ec03da1cb0c3b013f21226ff1e2fd2 > /tmp/damm-probe.json
cmp research/damm-finite-state/initial-probe.json /tmp/damm-probe.json
python3 research/damm-finite-state/verify_reference.py
```

A shared target directory may be used to reuse already built dependencies.
The public API, full caller main/alt frontier suite, policy probes, immutable
integrated artifact contracts, catalog/README markers and required full tests
remain to be completed before any public promotion or PR.

The preserved upstream C# files include original trailing whitespace. The
scoped .gitattributes entry retains these exact SHA256-bound bytes without
applying local whitespace cleanup to foreign source snapshots.

## Qualified public implementation

The prototype above is preserved at its original source revision. The public
[`u4_decimal_digits_to_damm`](../../src/arithmetic/u4/damm/README.md) supports
0..=896 numeric decimal digits, validates hostile numeric range, preserves both
caller stacks, and returns one canonical state. Original sibling sum APIs and
catalog evidence remain unchanged. Its initial source/probe/oracle bytes are
retained for the reproduction-before-production boundary.

Qualified source revision: `b53af2109f200fc21c1f70a28d39954ed078b139`.
[`metrics.json`](metrics.json) binds that revision, every source file affecting
the new report, compiler/interpreter identities, exact execution options and
final whole-artifact hashes. It contains 56 scalar rows, seven resident lifecycle
breakdowns and four preloaded independent compositions. The new independent
Python oracle also checks the actual Cargo dependency identities, all composed
witness hashes, output order and optimizer deltas. Full artifact/catalog
contracts recompute the report and inspect immutable source bytes when the
commit is available; a shallow CI checkout still verifies current source hashes
and recomputed artifacts and must identify itself as shallow.

The public resident loop is byte-identical to the original prototype at all
shared valid sizes. Its 32-digit fragment/leaf are 766/769 bytes with the same
61-byte fixture witness, 32 data items and exactly zero hints. Four-byte numeric
aliases are legal when numeric minimality is off; the full allowed witness
maximum is 161 bytes, not the canonical-encoding bound. Policy probes separate
MinimalData and entry-size prechecks from numeric consensus-oriented execution;
they are partial local policy evidence and never relay classification.

Two preloaded independent folds use 64 ordinary items, zero total hints,
67 serialized witness bytes and peak 168. Component sum 1,536 plus whole-policy
delta -4 gives a 1,532-byte fragment; a leaf checking both states is 1,537.
At 28 folds, 896 ordinary items and zero total hints give witness 927 bytes and
peak 1,000; component sum 21,504 plus delta -56 gives fragment 21,448 and checked
leaf 21,505. All use ALL. The 29th fold fails StackSize at 1,001. Allowed witness
maxima including numeric aliases are 321/4,483 bytes. Every future message,
parked state and caller main/alt item is counted; no shared-table API is claimed.

The shared suite covers four Damm schedules plus existing canonical modulo-16
and numeric exact sums: all short vectors, asymmetric/order vectors, typed
malformed inputs and aliases at each position, all short prefixes, exact combined
frontiers and every preserved caller byte. Compiled mutations bypass range and
canonicality guards, reverse input order, or omit terminal equality; unchanged
valid controls and the **same** typed-error or exact-output assertion catch them.
Additional composition tests bypass all 64 digit guards and shorten every prefix
of a two-message witness. Error-detection properties are checked independently
and exercised on all 100 three-digit valid codewords; 000/130 demonstrate
forgeability. No C# or Bitcoin Core execution is claimed.

Reproduce from the qualified source plus its bound report:

```sh
CARGO_PROFILE_DEV_OPT_LEVEL=1 cargo run --locked --example damm_metrics -- b53af2109f200fc21c1f70a28d39954ed078b139 > /tmp/damm-metrics.json
cmp research/damm-finite-state/metrics.json /tmp/damm-metrics.json
python3 research/damm-finite-state/verify_metrics.py
python3 research/damm-finite-state/verify_reference.py
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test damm_contract
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked --test primitive_metrics u4_damm_metrics_are_current
python3 tools/kb.py validate
cargo fmt --all -- --check
CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --locked -- --skip fields::
```

Test optimization keeps debug assertions and overflow checks. Every published
configuration remains `locally-reproduced`/`unclassified`; no deployment class
is inherited from strict stack success, a partial Policy probe or checksum
algebra. The [negative result](../../knowledge/negative-results/damm-finite-state.md)
and [OP-037](../../knowledge/open-problems.md#op-037--authenticated-decimal-transducer-composition)
record the cost and authentication boundaries.

At 32 digits the independently policy-compiled lifecycle is 100 bytes of table
setup, one byte of initial state, 613 bytes of validated queries/routing, and
52 bytes of table cleanup/state restoration. The whole optimizer delta is zero,
so these sum to the final 766-byte fragment. At 128/896 digits, query/routing
components are 2,533/17,893 bytes; setup/state/cleanup remain 100/1/52 and deltas
remain zero. Query depth encodings vary with n, so this is not a constant
per-digit charge or a shared-table API.
