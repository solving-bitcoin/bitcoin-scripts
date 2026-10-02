# Canonical u4 modulo-16 prefix scan

Question: can all prefix sums of a hostile nibble vector be retained in order
without a resident table or hints? The objective is a low-stack sequence
adapter that reconstructs forward deltas when their first value is retained.

`arithmetic::u4::prefix_sum::u4_nibbles_to_prefix_sum(n)` maps
`preserved | x[0] ... x[n-1]` to `preserved | s[0] ... s[n-1]`, with
`s[i]=sum(x[0..=i]) mod16`. All inputs are canonical ScriptNums in 0..15.
Park the inputs on the altstack, pop them in original order, and retain every
prefix using `OP_OVER OP_ADD`. Each sum is at most 30; subtract 16 once if needed.
Caller altstack state is preserved. The fragment retains n outputs and supplies
no terminal predicate. Parameter n is 1..997 with no default.

The threat model treats every witness item as hostile. Canonicality is an
explicit byte check, independent of interpreter minimal-number policy. There
are zero hint items for every configuration. All n ordinary data items coexist
at entry. This is arithmetic, with no cryptographic authentication claim.

## Measured frontier

| n | Conditional fragment / leaf | Table fragment / leaf | Serialized data witness | Hint items | Conditional / table combined peak |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 10 / 13 | 10 / 13 | 3 | 0 | 4 / 4 |
| 2 | 31 / 36 | 79 / 84 | 5 | 0 | 5 / 36 |
| 32 | 661 / 726 | 664 / 729 | 65 | 0 | 35 / 66 |
| 128 | 2677 / 2934 | 2584 / 2841 | 257 | 0 | 131 / 162 |
| 966 | 20275 / 22208 | 20182 / 22115 | 1935 | 0 | 969 / 1000 |
| 997 | 20926 / 22921 | unsupported | 1997 | 0 | 1000 / unsupported |

All rows use n canonical sevens, all present at entry. Fragment-with-memory
includes staging, input validation and all ordered outputs; table rows include
31-entry setup, query routing, cleanup and restoration. Input pushes and
terminal checks are excluded on both sides. Leaves compare each reverse prefix
with `(7*i)%16` using `OP_EQUALVERIFY`, then `OP_TRUE`; the witness serialization
is the complete data-only vector, excluding leaf/control block. The peak is
measured on that leaf; resource tests also use observable fragment outputs.
All final fragments and leaves are below the 32KiB raw optimizer cutoff and
receive `CompileOptions::ALL` via `compile_with_policy()`.

The conditional scan peaks at `n+3+preserved_items`; the table at
`n+34+preserved_items` for n>=2, or n+3 for its no-table singleton. Exact local
frontier tests accept 1000 and reject one extra item with `StackSize`, including
runtime main and alt state. The 997-output scan cannot coexist with other live
items. The table's maximum is 966. Static non-push counts at n32 are503 and492;
these are not dynamic executed counts. Dynamic counts and validation weight
remain unavailable.

Evidence is `locally-reproduced`; execution is `unclassified`. Cost runs use the
strict local tapscript helper, `Options::default` with the stack limit enabled,
a synthetic empty transaction and data-only budget. Hostile-witness/resource
contracts additionally use local `TapscriptProfile::Consensus` (minimal-number
policy off, experimental CAT off, stack and minimal-IF checks on). Neither
establishes Bitcoin Core consensus, full transaction or relay validity.
The 32-item scan's 503 non-push opcodes exceed the 201-opcode legacy/P2WSH limit.

## Comparison and inverse composition

The [scalar sum](u4-sum-mod16.md) returns one checksum (592 bytes at n32), while
this returns every prefix. The [forward delta](u4-adjacent-delta.md) discards
the initial value and accepts numeric encoding aliases. These are different
semantics and must not be ranked by fragment bytes as interchangeable operations.

The research round trip first canonical-checks every original input, retains
x[0], runs the existing delta encoder, routes `x[0] | deltas` into the scan,
and compares all reconstructed outputs. Its bytes and peak are separately
reported in [metrics.json](../../research/u4-prefix-reconstruction/metrics.json),
including canonical checks and retained/routed initial state. There are n
ordinary data items and zero hints. A protocol must bind the initial value and
each delta; numeric reconstruction alone authenticates neither original bytes
nor their source. The table saves 93 bytes at n128 while using31 more items:
[NR-075](../negative-results/u4-prefix-table-tradeoff.md) records that the
conditional form is not a universal size winner.

## Reproduction and provenance

[Research manifest](../../research/u4-prefix-reconstruction/README.md),
[implementation README](../../src/arithmetic/u4/README.md),
[contract suite](../../tests/u4_prefix_contract.rs), and
[deterministic producer](../../examples/u4_prefix_reconstruction_probe.rs)
bind the final artifacts and immutable compiler/interpreter identities.
The compiler is `124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`, interpreter
`a09e87af444034698697f0a2267e755cf72f9aed`; primary semantics/resource references
are [BIP342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki) and
[Core v30 resource rules](https://github.com/bitcoin/bitcoin/blob/d0f6d9953a15d7c7111d46dcb76ab2bb18e5dee3/src/script/interpreter.cpp).
Report pins are resolved from the binary's embedded lockfile. Remaining complete
Core/policy oracle acceptance is [OP-033](../open-problems.md#op-033--complete-prefix-scan-oracle).
